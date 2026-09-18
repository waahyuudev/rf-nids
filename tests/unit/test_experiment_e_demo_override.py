import json

import pandas as pd
import pytest

from dashboard.demo import DEMO_BANNER
from src.common.config import Settings
from src.inference.predictor import InferenceEngine


def test_no_demo_override_keeps_rf_v2_defaults(monkeypatch):
    monkeypatch.delenv("RF_NIDS_DEMO_MODEL", raising=False)
    settings = Settings.from_env()
    assert settings.demo_model_version is None
    assert str(settings.model_path).endswith("models/experiment_d/random_forest_rf_v2.joblib")


def test_valid_demo_override_loads_allowlisted_candidate(monkeypatch):
    monkeypatch.setenv("RF_NIDS_DEMO_MODEL", "rf-v3.0-candidate")
    settings = Settings.from_env()
    engine = InferenceEngine(settings.model_path, settings.model_metadata_path)
    assert settings.demo_model_version == "rf-v3.0-candidate"
    assert engine.metadata["model_version"] == "rf-v3.0-candidate"
    assert engine.model.n_features_in_ == 78


def test_invalid_demo_name_is_rejected(monkeypatch):
    monkeypatch.setenv("RF_NIDS_DEMO_MODEL", "../../arbitrary.joblib")
    with pytest.raises(ValueError, match="approved demo model"):
        Settings.from_env()


def test_demo_hash_mismatch_is_rejected(monkeypatch):
    monkeypatch.setenv("RF_NIDS_DEMO_MODEL", "rf-v3.0-candidate")
    monkeypatch.setattr("src.common.config.DEMO_MODEL_SHA256", "0" * 64)
    with pytest.raises(ValueError, match="unexpected SHA-256"):
        Settings.from_env()


def test_demo_feature_contract_mismatch_is_rejected(monkeypatch, tmp_path):
    from src.common import config
    source = config.DEMO_METADATA_PATH
    altered = json.loads(source.read_text())
    altered["feature_names"] = altered["feature_names"][:-1]
    path = tmp_path / "candidate.json"; path.write_text(json.dumps(altered))
    monkeypatch.setenv("RF_NIDS_DEMO_MODEL", "rf-v3.0-candidate")
    monkeypatch.setattr(config, "DEMO_METADATA_PATH", path)
    from src.common.hashing import sha256_file
    monkeypatch.setattr(config, "DEMO_METADATA_SHA256", sha256_file(path))
    with pytest.raises(ValueError, match="locked demo contract"):
        Settings.from_env()


def test_demo_inference_provenance_reports_candidate(monkeypatch):
    monkeypatch.setenv("RF_NIDS_DEMO_MODEL", "rf-v3.0-candidate")
    settings = Settings.from_env(); engine = InferenceEngine(settings.model_path, settings.model_metadata_path)
    row = pd.read_csv("data/lab/experiment_e/datasets/experiment_e_training_candidate.csv", nrows=1)
    output = engine.predict_one(row.drop(columns=["ground_truth_class"]).iloc[0].to_dict())
    assert output["model_version"] == "rf-v3.0-candidate"


def test_streamlit_demo_banner_is_explicit():
    assert "DEMO MODEL: rf-v3.0-candidate" in DEMO_BANNER
    assert "CANDIDATE / NOT ACTIVE" in DEMO_BANNER
    assert "Not scientifically promoted" in DEMO_BANNER
