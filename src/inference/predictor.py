"""Validated, feature-ordered inference using one loaded model instance."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

import joblib
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline

from src.common.config import PROJECT_ROOT
from src.common.hashing import sha256_file
from src.preprocessing.columns import normalize_column_name


class FeatureValidationError(ValueError):
    """Raised when inference features violate active-model metadata."""


class InferenceEngine:
    """Load the active model once and serve validated single/batch predictions."""

    def __init__(
        self,
        model_path: Path,
        metadata_path: Path,
        *,
        extra_feature_policy: Literal["reject", "ignore"] | None = None,
        verify_model_hash: bool = True,
    ) -> None:
        self.metadata = self._normalize_demo_metadata(self._load_metadata(metadata_path))
        self.feature_names = list(self.metadata["feature_names"])
        if self.metadata.get("feature_count", len(self.feature_names)) != len(self.feature_names):
            raise ValueError("Model metadata feature_count does not match feature_names")
        declared_path = self.metadata.get("model_path")
        if declared_path:
            expected_path = Path(declared_path)
            expected_path = expected_path if expected_path.is_absolute() else PROJECT_ROOT / expected_path
            if expected_path.resolve() != model_path.resolve():
                raise ValueError("Configured model path does not match runtime metadata")
        scientific_source = self.metadata.get("scientific_source")
        if scientific_source:
            source_path = Path(scientific_source["frozen_metadata_path"])
            source_path = source_path if source_path.is_absolute() else PROJECT_ROOT / source_path
            if sha256_file(source_path) != scientific_source["frozen_metadata_sha256"]:
                raise ValueError("Frozen scientific metadata SHA-256 mismatch")
            evaluation_path = Path(scientific_source["evaluation_path"])
            evaluation_path = evaluation_path if evaluation_path.is_absolute() else PROJECT_ROOT / evaluation_path
            if sha256_file(evaluation_path) != scientific_source["evaluation_sha256"]:
                raise ValueError("Scientific evaluation SHA-256 mismatch")
        configured_policy = self.metadata.get("extra_feature_policy", "reject")
        self.extra_feature_policy = extra_feature_policy or configured_policy
        if self.extra_feature_policy not in {"reject", "ignore"}:
            raise ValueError("extra_feature_policy must be 'reject' or 'ignore'")
        if verify_model_hash and self.metadata.get("model_sha256"):
            actual_hash = sha256_file(model_path)
            if actual_hash != self.metadata["model_sha256"]:
                raise ValueError("Active model SHA-256 does not match metadata")
        loaded = joblib.load(model_path)
        if not isinstance(loaded, Pipeline) and not all(hasattr(loaded, name) for name in ("predict", "predict_proba", "classes_")):
            raise ValueError("Runtime model must support predict, predict_proba, and classes_")
        self.model = loaded
        if getattr(self.model, "n_features_in_", len(self.feature_names)) != len(self.feature_names):
            raise ValueError("Model n_features_in_ does not match runtime metadata")
        model_features = list(getattr(self.model, "feature_names_in_", self.feature_names))
        if model_features != self.feature_names:
            raise ValueError("Model feature order does not match metadata")
        declared_classes = self.metadata.get("class_names")
        if declared_classes and [str(value) for value in self.model.classes_] != sorted(declared_classes):
            raise ValueError("Model classes do not match runtime metadata")

    @staticmethod
    def _normalize_demo_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
        """Translate only the allowlisted Experiment E candidate for runtime display."""
        if metadata.get("version") != "rf-v3.0-candidate":
            return metadata
        if metadata.get("status") != "CANDIDATE / NOT_ACTIVE":
            raise ValueError("RF-v3 demo metadata must remain CANDIDATE / NOT_ACTIVE")
        return {**metadata, "model_version": "rf-v3.0-candidate",
                "model_name": "RF-NIDS Random Forest — Experiment E Demo",
                "algorithm": "Random Forest", "class_names": metadata.get("classes_declared_order"),
                "parameters": metadata.get("rf_parameters"), "extra_feature_policy": "reject"}

    @staticmethod
    def _load_metadata(path: Path) -> dict[str, Any]:
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Unable to read model metadata {path}: {exc}") from exc
        if not isinstance(metadata, dict) or not isinstance(metadata.get("feature_names"), list):
            raise ValueError("Model metadata must contain a feature_names list")
        if len(metadata["feature_names"]) != len(set(metadata["feature_names"])):
            raise ValueError("Model metadata contains duplicate feature names")
        return metadata

    def _prepare_row(self, features: Mapping[str, Any]) -> tuple[pd.DataFrame, list[str]]:
        normalized: dict[str, Any] = {}
        for raw_name, value in features.items():
            name = normalize_column_name(raw_name)
            if name in normalized:
                raise FeatureValidationError(
                    f"Feature normalization produced duplicate input key: {name}"
                )
            normalized[name] = value
        required = set(self.feature_names)
        provided = set(normalized)
        missing = [name for name in self.feature_names if name not in provided]
        extra = sorted(provided - required)
        if missing:
            raise FeatureValidationError(f"Missing required features: {missing}")
        if extra and self.extra_feature_policy == "reject":
            raise FeatureValidationError(f"Unexpected features: {extra}")

        ordered: list[float] = []
        for name in self.feature_names:
            value = normalized[name]
            if value is None:
                ordered.append(np.nan)
                continue
            if isinstance(value, bool):
                raise FeatureValidationError(f"Feature '{name}' must be numeric, not boolean")
            try:
                number = float(value)
            except (TypeError, ValueError) as exc:
                raise FeatureValidationError(f"Feature '{name}' must be numeric") from exc
            ordered.append(np.nan if np.isinf(number) else number)
        frame = pd.DataFrame([ordered], columns=self.feature_names, dtype=np.float32)
        return frame, extra

    def predict_one(self, features: Mapping[str, Any]) -> dict[str, Any]:
        """Predict one row with class probabilities in classifier order."""
        frame, ignored_features = self._prepare_row(features)
        predicted = str(self.model.predict(frame)[0])
        probabilities = self.model.predict_proba(frame)[0]
        classes = [str(value) for value in self.model.classes_]
        probability_map = {
            class_name: float(probability)
            for class_name, probability in zip(classes, probabilities, strict=True)
        }
        return {
            "prediction": predicted,
            "confidence": probability_map[predicted],
            "probabilities": probability_map,
            "model_version": self.metadata["model_version"],
            "ignored_features": ignored_features,
        }

    def predict_batch(self, rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Predict a non-empty sequence while preserving input order."""
        if not rows:
            raise FeatureValidationError("Prediction batch must not be empty")
        return [self.predict_one(row) for row in rows]
