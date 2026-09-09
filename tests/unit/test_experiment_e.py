from __future__ import annotations

import copy
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.experiment_d.d5 import verify_frozen_manifest
from src.experiment_e.e1 import validate_e1
from src.experiment_e.config import ExperimentEConfig, load_experiment_e_config
from src.experiment_e.integrity import (
    assert_role_operation_allowed,
    load_preregistration,
    reject_experiment_d_final_test,
    validate_cross_role_identities,
    validate_feature_contract,
    validate_preregistration,
)
from src.experiment_e.paths import ExperimentEPaths
from src.ingestion.cicflowmeter_v3_adapter import MODEL_FEATURES


ROOT = Path(__file__).resolve().parents[2]
PREREG = ROOT / "data/lab/experiment_e/manifests/session_preregistration.json"


def test_e1_scaffold_and_actual_artifact_identities_pass() -> None:
    assert validate_e1(ROOT)["status"] == "PASS"


def test_experiment_e_roots_cannot_resolve_into_experiment_d(tmp_path: Path) -> None:
    ExperimentEPaths(ROOT).assert_isolated_from_experiment_d()
    (tmp_path / "data/lab/experiment_d").mkdir(parents=True)
    (tmp_path / "data/lab/experiment_e").symlink_to(tmp_path / "data/lab/experiment_d")
    aliased = ExperimentEPaths(tmp_path)
    with pytest.raises(ValueError, match="must not alias"):
        aliased.assert_isolated_from_experiment_d()


def test_experiment_d_final_test_inputs_are_rejected() -> None:
    for path in (
        ROOT / "data/lab/experiment_d/final_test/pcap/portscan/portscan-s01.pcap",
        ROOT / "reports/experiment_d/final_test/metrics.json",
    ):
        with pytest.raises(ValueError, match="forbidden"):
            reject_experiment_d_final_test(path, ROOT)


def test_same_session_cannot_belong_to_multiple_roles() -> None:
    records = [
        {"role": "adaptation", "session_id": "same"},
        {"role": "validation", "session_id": "same"},
    ]
    with pytest.raises(ValueError, match="session_id"):
        validate_cross_role_identities(records)


def test_same_pcap_or_flow_source_cannot_cross_roles() -> None:
    for field in ("pcap_sha256", "flow_source_sha256"):
        records = [
            {"role": "adaptation", field: "a" * 64},
            {"role": "final_test", field: "a" * 64},
        ]
        with pytest.raises(ValueError, match=field):
            validate_cross_role_identities(records)


def test_final_test_cannot_become_adaptation_or_selection_input() -> None:
    for operation in ("adaptation", "fitting", "model_selection", "validation"):
        with pytest.raises(ValueError, match="sealed"):
            assert_role_operation_allowed("final_test", operation)


def test_feature_contract_is_exactly_78_and_ordered() -> None:
    validate_feature_contract(MODEL_FEATURES)
    with pytest.raises(ValueError, match="78-feature"):
        validate_feature_contract(MODEL_FEATURES[:-1])
    changed = list(MODEL_FEATURES)
    changed[0], changed[1] = changed[1], changed[0]
    with pytest.raises(ValueError, match="78-feature"):
        validate_feature_contract(changed)


def test_preregistered_membership_is_locked_and_unique() -> None:
    plan = load_preregistration(PREREG)
    assert len(plan["sessions"]) == 10
    altered = copy.deepcopy(plan)
    altered["sessions"][0]["role"] = "validation"
    with pytest.raises(ValueError, match="locked E1 split"):
        validate_preregistration(altered)


def test_config_rejects_incomplete_d_final_test_prohibition() -> None:
    config = load_experiment_e_config(ROOT / "config/experiment_e.yaml")
    bad = config.model_dump()
    bad["forbidden_data_roles"] = []
    with pytest.raises(ValidationError, match="prohibitions"):
        ExperimentEConfig.model_validate(bad)


def test_topology_amendment_preserves_pending_live_verification() -> None:
    config = load_experiment_e_config(ROOT / "config/experiment_e.yaml")
    assert config.topology_amendment is not None
    assert config.topology_amendment.amendment_id == "A1"
    assert config.topology_amendment.traffic_captured_before_amendment is False
    assert config.topology_amendment.traffic_capture_authorized is False
    assert config.topology_amendment.final_test_collection_authorized is False

    bad = config.model_dump()
    bad["topology_amendment"]["expected_capture_interface_status"] = "verified"
    with pytest.raises(ValidationError, match="pending live verification"):
        ExperimentEConfig.model_validate(bad)


def test_live_preflight_records_pass_without_authorizing_capture() -> None:
    config = load_experiment_e_config(ROOT / "config/experiment_e.yaml")
    assert config.live_preflight is not None
    assert config.live_preflight.status == "PASS"
    assert config.live_preflight.recommended_capture_interface == "enp0s3"
    assert config.live_preflight.benign_target_service == "http://10.10.20.2:8080/"
    assert config.live_preflight.diagnostic_pcap_retained is False
    assert config.live_preflight.scientific_pcap_created is False
    assert "any" in config.live_preflight.rejected_capture_interfaces

    bad = config.model_dump()
    bad["live_preflight"]["recommended_capture_interface"] = "any"
    with pytest.raises(ValidationError, match="capture interface"):
        ExperimentEConfig.model_validate(bad)


def test_preregistration_keeps_original_topology_and_records_a1() -> None:
    plan = load_preregistration(PREREG)
    assert plan["topology"]["target"]["ip"] == "172.30.50.10"
    assert plan["topology"]["observer"]["interface"] == "eth0"
    amendment = plan["topology_amendments"][0]
    assert amendment["amendment_id"] == "A1"
    assert amendment["traffic_captured_before_amendment"] is False
    assert amendment["amended_topology"]["expected_generator"]["status"] == (
        "pending_live_verification"
    )
    assert amendment["amended_topology"]["expected_capture_interface"]["status"] == (
        "pending_empirical_verification"
    )


def test_existing_experiment_d_frozen_integrity_still_passes() -> None:
    result = verify_frozen_manifest(
        ROOT / "reports/experiment_d/audit/rf_v2_frozen_manifest.json",
        ROOT / "models/experiment_d/random_forest_rf_v2.joblib",
    )
    assert result["status"] == "FROZEN"
