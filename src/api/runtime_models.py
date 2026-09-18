"""Fail-closed, scientifically neutral runtime model selection registry."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from src.common.config import PROJECT_ROOT
from src.common.hashing import sha256_file
from src.ingestion.cicflowmeter_v3_adapter import MODEL_FEATURES
from src.inference import InferenceEngine


class RuntimeModelVerificationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ApprovedRuntimeModel:
    model_id: str
    model_path: Path
    metadata_path: Path
    model_sha256: str
    metadata_sha256: str
    scientific_status: str
    scientific_decision: str | None = None


APPROVED_RUNTIME_MODELS = (
    ApprovedRuntimeModel(
        "rf-v2.0",
        PROJECT_ROOT / "models/experiment_d/random_forest_rf_v2.joblib",
        PROJECT_ROOT / "models/experiment_d/random_forest_rf_v2_runtime_metadata.json",
        "fb13a71a0287054d2630bf07529f113a153ba08d8f6835a605b04493408b8a31",
        "1c97466a9c987b161e516557d41e63c428d987129f39dcdeb6a735c9097443c0",
        "ACTIVE",
    ),
    ApprovedRuntimeModel(
        "rf-v3.0-candidate",
        PROJECT_ROOT / "models/experiment_e/random_forest_rf_v3_candidate.joblib",
        PROJECT_ROOT / "models/experiment_e/random_forest_rf_v3_candidate_metadata.json",
        "6b01c7b3923c1a6bd471862d011f8f5b88a31378e51d1dde082bd2e72bedef86",
        "30b6bdf2a6cb2d60e2be36d4db1e124d71504393081b229e6d94da7e70322cbc",
        "CANDIDATE / NOT_ACTIVE",
    ),
    ApprovedRuntimeModel(
        "rf-v4.0-candidate-01",
        PROJECT_ROOT / "models/experiment_f/random_forest_rf_v4_candidate_01.joblib",
        PROJECT_ROOT / "models/experiment_f/random_forest_rf_v4_candidate_01_metadata.json",
        "d5dccd339a5c67635e760d7d3760e1d006278362c6f70ea06bf20928ccdece13",
        "9f8bb215740943b326b6ec6f76e55caef4d094290ac43ed30cb7e32884a47a1a",
        "CANDIDATE / NOT_ACTIVE",
        "F4_A2_VALIDATION_FAIL",
    ),
    ApprovedRuntimeModel(
        "rf-v5-candidate-01",
        PROJECT_ROOT / "models/experiment_f/random_forest_rf_v5_candidate_01.joblib",
        PROJECT_ROOT / "models/experiment_f/random_forest_rf_v5_candidate_01_metadata.json",
        "31d7d50fa79e3400e7d357cab05c780e038bc527b746d0be6ff894828c6b8d17",
        "b9255fb4ad067611db60632e384e2cc5e8aaa2f989228cbc0e541ef421c7224e",
        "CANDIDATE / NOT_ACTIVE",
        "RF_V5_VALIDATION_FAIL",
    ),
)


class RuntimeModelRegistry:
    """Load only artifacts whose complete frozen identity verifies."""

    def __init__(self, engine_factory=InferenceEngine):
        self._models: dict[str, tuple[ApprovedRuntimeModel, InferenceEngine]] = {}
        self.excluded: dict[str, str] = {}
        for approved in APPROVED_RUNTIME_MODELS:
            try:
                self._models[approved.model_id] = (
                    approved, self._verify_and_load(approved, engine_factory)
                )
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                self.excluded[approved.model_id] = str(exc)

    @staticmethod
    def _verify_and_load(approved, engine_factory):
        if (
            not approved.model_path.is_file()
            or sha256_file(approved.model_path) != approved.model_sha256
        ):
            raise RuntimeModelVerificationError("model artifact SHA-256 mismatch or artifact missing")
        if (
            not approved.metadata_path.is_file()
            or sha256_file(approved.metadata_path) != approved.metadata_sha256
        ):
            raise RuntimeModelVerificationError("metadata SHA-256 mismatch or metadata missing")
        metadata = json.loads(approved.metadata_path.read_text(encoding="utf-8"))
        identity = (
            metadata.get("model_version")
            or metadata.get("version")
            or metadata.get("model_id")
        )
        if identity != approved.model_id or metadata.get("model_sha256") != approved.model_sha256:
            raise RuntimeModelVerificationError("metadata model identity/hash mismatch")
        if (
            metadata.get("feature_count") != len(MODEL_FEATURES)
            or metadata.get("feature_names") != list(MODEL_FEATURES)
        ):
            raise RuntimeModelVerificationError("feature identity/order mismatch")
        if approved.scientific_status != "ACTIVE" and (
            metadata.get("status") != "CANDIDATE / NOT_ACTIVE"
            or ("active" in metadata and metadata["active"] is not False)
        ):
            raise RuntimeModelVerificationError("candidate scientific status mismatch")
        engine = engine_factory(approved.model_path, approved.metadata_path)
        if engine.metadata.get("model_version") != approved.model_id:
            raise RuntimeModelVerificationError("loaded model identity mismatch")
        return engine

    def resolve(self, model_id: str):
        if model_id not in self._models:
            reason = self.excluded.get(
                model_id, "model ID is not in the approved runtime allowlist"
            )
            raise RuntimeModelVerificationError(reason)
        approved, engine = self._models[model_id]
        if (
            not approved.model_path.is_file()
            or sha256_file(approved.model_path) != approved.model_sha256
        ):
            raise RuntimeModelVerificationError("model artifact SHA-256 mismatch")
        if (
            not approved.metadata_path.is_file()
            or sha256_file(approved.metadata_path) != approved.metadata_sha256
        ):
            raise RuntimeModelVerificationError("metadata SHA-256 mismatch")
        if engine.feature_names != list(MODEL_FEATURES):
            raise RuntimeModelVerificationError("feature identity/order mismatch")
        return approved, engine

    def available(self):
        verified = []
        for model_id in self._models:
            try:
                verified.append(self.resolve(model_id))
            except (OSError, RuntimeModelVerificationError) as exc:
                self.excluded[model_id] = str(exc)
        return verified
