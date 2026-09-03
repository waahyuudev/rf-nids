from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.train_rf_v2 import validate_dry_run
from src.experiment_d.d3 import (
    assert_provenance_not_features,
    assert_session_separation,
    canonical_json_sha256,
    decode_int64_sequence,
    decode_index_membership,
    deterministic_cap,
    encode_int64_sequence,
    encode_index_membership,
    validate_output_contract,
)

ROOT = Path(__file__).resolve().parents[2]
SPLIT = ROOT / "reports/experiment_d/adaptation/split_manifest.json"
PLAN = ROOT / "reports/experiment_d/adaptation/rf_v2_training_plan.json"


def load_artifacts() -> tuple[dict, dict]:
    return json.loads(SPLIT.read_text()), json.loads(PLAN.read_text())


def test_d2_inputs_and_invalid_replacement_are_frozen() -> None:
    split, _ = load_artifacts()
    sources = split["adaptation"]["source_identities"]
    assert len(sources) == 9
    assert sum(x["rows"] for x in sources) == 15_914
    assert split["adaptation"]["excluded_invalid_sessions"] == ["expd-adapt-ddos-session-03"]
    assert "expd-adapt-ddos-session-04" in split["adaptation"]["selected_validation_sessions"]
    assert split["feature_count"] == 78
    assert split["leakage_checks"]["d2_leakage_audit"] == "PASS"


def test_session_level_split_and_deterministic_membership() -> None:
    split, _ = load_artifacts()
    adaptation = split["adaptation"]
    assert not set(adaptation["selected_training_sessions"]) & set(adaptation["selected_validation_sessions"])
    cicids = split["cicids2017"]
    train = decode_index_membership(cicids["training_membership"])
    control = decode_index_membership(cicids["internal_control_membership"])
    assert len(train) == sum(cicids["training_class_counts"].values())
    assert len(control) == sum(cicids["internal_control_class_counts"].values())
    assert not set(train) & set(control)


def test_membership_encoding_is_path_independent() -> None:
    one = encode_index_membership([0, 2, 9], 10)
    two = encode_index_membership([9, 0, 2], 10)
    assert one == two
    assert decode_index_membership(one).tolist() == [0, 2, 9]
    assert canonical_json_sha256({"logical_path": "data/a.csv", "membership": one}) == canonical_json_sha256({"logical_path": "data/a.csv", "membership": two})
    provenance = encode_int64_sequence([7, 11, 42])
    assert decode_int64_sequence(provenance).tolist() == [7, 11, 42]


def test_sampling_is_deterministic_and_does_not_duplicate() -> None:
    rows = [{"row_identity": f"row-{i}"} for i in range(20)]
    first = deterministic_cap(rows, 7, 42)
    second = deterministic_cap(list(reversed(rows)), 7, 42)
    assert first == second
    assert len({x["row_identity"] for x in first}) == 7


def test_provenance_and_rf_v1_outputs_are_prohibited() -> None:
    with pytest.raises(ValueError, match="provenance"):
        assert_provenance_not_features(["flow_duration", "session_id"])
    with pytest.raises(ValueError, match="RF-v1"):
        validate_output_contract([
            "models/random_forest_active.joblib",
            "models/experiment_d/random_forest_rf_v2_metadata.json",
            "models/experiment_d/training_manifest.json",
        ])


def test_duplicate_leakage_and_session_overlap_guards() -> None:
    rows = [
        {"session_id": "s1", "capture_id": "c1", "split_role": "adaptation_training_pool"},
        {"session_id": "s1", "capture_id": "c1", "split_role": "adaptation_validation"},
    ]
    with pytest.raises(ValueError, match="leakage"):
        assert_session_separation(rows)
    split, _ = load_artifacts()
    assert split["adaptation"]["duplicate_handling"]["training_rows_excluded_for_validation_feature_overlap"] > 0
    assert split["leakage_checks"]["post_handling_cross_source_overlap_count"] == 0


def test_final_test_and_experiment_c_prohibitions_fail_closed() -> None:
    split, plan = load_artifacts()
    bad = copy.deepcopy(split)
    bad["leakage_checks"]["final_test_used"] = True
    bad["content_identity"] = canonical_json_sha256({k: v for k, v in bad.items() if k != "content_identity"})
    with pytest.raises(ValueError, match="prohibited"):
        validate_dry_run(bad, plan, "D3-C")
    bad = copy.deepcopy(split)
    bad["leakage_checks"]["experiment_c_used"] = True
    bad["content_identity"] = canonical_json_sha256({k: v for k, v in bad.items() if k != "content_identity"})
    with pytest.raises(ValueError, match="prohibited"):
        validate_dry_run(bad, plan, "D3-C")


def test_dry_run_reports_frozen_counts_without_fit() -> None:
    split, plan = load_artifacts()
    result = validate_dry_run(split, plan, "D3-C")
    assert result["status"] == "DRY_RUN_VALID"
    assert result["training_performed"] is False
    assert result["model_instantiated"] is False
    assert result["adaptation_training_counts"] == {"Normal": 13, "DDoS": 1200, "PortScan": 1113}
    completed = subprocess.run(
        [sys.executable, "scripts/train_rf_v2.py", "--dry-run"], cwd=ROOT,
        text=True, capture_output=True,
    )
    assert completed.returncode == 0
    assert json.loads(completed.stdout)["planned_training_rows"] == 1_854_579
    assert ".fit(" not in (ROOT / "scripts/train_rf_v2.py").read_text()
