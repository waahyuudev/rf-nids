from __future__ import annotations

import json
import inspect
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.experiment_d.d5 import canonical_identity, verify_frozen_manifest
from scripts.evaluate_experiment_d_final import integrity_gate, predict_once


ROOT = Path(__file__).resolve().parents[2]


def test_repository_rf_v2_frozen_manifest_verifies() -> None:
    verify_frozen_manifest(
        ROOT / "reports/experiment_d/audit/rf_v2_frozen_manifest.json",
        ROOT / "models/experiment_d/random_forest_rf_v2.joblib",
    )


def test_frozen_manifest_identity_rejects_tampering(tmp_path: Path) -> None:
    source = json.loads((ROOT / "reports/experiment_d/audit/rf_v2_frozen_manifest.json").read_text())
    source["frozen_at"] = datetime.now(timezone.utc).isoformat()
    path = tmp_path / "freeze.json"
    path.write_text(json.dumps(source))
    with pytest.raises(ValueError, match="identity mismatch"):
        verify_frozen_manifest(path, ROOT / "models/experiment_d/random_forest_rf_v2.joblib")


def test_evaluation_preflight_remains_model_blind_at_d6() -> None:
    source = inspect.getsource(integrity_gate)
    assert "joblib.load" not in source
    assert ".predict(" not in source
    assert "predict_proba" not in source


def test_d6_inference_calls_are_isolated_and_single() -> None:
    source = inspect.getsource(predict_once)
    assert source.count("model.predict(x)") == 1
    assert source.count("model.predict_proba(x)") == 1
