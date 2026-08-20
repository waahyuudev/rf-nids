import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

from src.common.hashing import sha256_file
from src.inference.predictor import FeatureValidationError, InferenceEngine


@pytest.fixture
def inference_files(tmp_path: Path) -> tuple[Path, Path]:
    features = pd.DataFrame(
        {
            "feature_a": [0.0, 0.1, 10.0, 10.1, 20.0, 20.1],
            "feature_b": [0.0, 0.2, 10.0, 10.2, 20.0, 20.2],
        }
    )
    labels = np.array(["Normal", "Normal", "DDoS", "DDoS", "PortScan", "PortScan"])
    model = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", RandomForestClassifier(n_estimators=20, random_state=42)),
        ]
    ).fit(features, labels)
    model_path = tmp_path / "model.joblib"
    joblib.dump(model, model_path)
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text(
        json.dumps(
            {
                "model_version": "test-v1",
                "model_sha256": sha256_file(model_path),
                "feature_names": ["feature_a", "feature_b"],
                "extra_feature_policy": "reject",
            }
        ),
        encoding="utf-8",
    )
    return model_path, metadata_path


def test_inference_orders_features_and_returns_all_probabilities(
    inference_files: tuple[Path, Path],
) -> None:
    engine = InferenceEngine(*inference_files)
    output = engine.predict_one({"Feature B": 0.1, "Feature A": 0.0})
    assert output["prediction"] == "Normal"
    assert output["confidence"] == output["probabilities"]["Normal"]
    assert set(output["probabilities"]) == {"Normal", "DDoS", "PortScan"}
    assert sum(output["probabilities"].values()) == pytest.approx(1.0)
    assert output["model_version"] == "test-v1"


def test_inference_rejects_missing_and_extra_features(
    inference_files: tuple[Path, Path],
) -> None:
    engine = InferenceEngine(*inference_files)
    with pytest.raises(FeatureValidationError, match="Missing"):
        engine.predict_one({"feature_a": 0})
    with pytest.raises(FeatureValidationError, match="Unexpected"):
        engine.predict_one({"feature_a": 0, "feature_b": 0, "other": 1})


def test_inference_can_explicitly_ignore_extra_features(
    inference_files: tuple[Path, Path],
) -> None:
    engine = InferenceEngine(*inference_files, extra_feature_policy="ignore")
    output = engine.predict_one({"feature_a": 20, "feature_b": 20, "other": 1})
    assert output["prediction"] == "PortScan"
    assert output["ignored_features"] == ["other"]


def test_inference_batch_and_invalid_values(inference_files: tuple[Path, Path]) -> None:
    engine = InferenceEngine(*inference_files)
    outputs = engine.predict_batch(
        [
            {"feature_a": 0, "feature_b": None},
            {"feature_a": 10, "feature_b": float("inf")},
        ]
    )
    assert len(outputs) == 2
    with pytest.raises(FeatureValidationError, match="numeric"):
        engine.predict_one({"feature_a": "invalid", "feature_b": 0})

