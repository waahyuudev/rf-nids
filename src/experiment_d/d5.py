"""Experiment D D5 freeze and final-test boundary checks (no inference)."""

from __future__ import annotations

import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path

import joblib
import sklearn

from src.experiment_d.config import load_experiment_d_config
from src.experiment_d.integrity import require_create_new, sha256_file
from src.experiment_d.manifest import ScientificManifest
from src.experiment_d.split import validate_role_exclusivity


EXPECTED_RF_V2_SHA256 = "fb13a71a0287054d2630bf07529f113a153ba08d8f6835a605b04493408b8a31"


def canonical_identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def freeze_rf_v2(root: Path, output: Path, *, frozen_at: datetime | None = None) -> dict:
    """Create the RF-v2 freeze record without loading/deserializing either model."""
    require_create_new(output)
    model = root / "models/experiment_d/random_forest_rf_v2.joblib"
    metadata_path = root / "models/experiment_d/random_forest_rf_v2_metadata.json"
    training_manifest = root / "models/experiment_d/training_manifest.json"
    plan = root / "reports/experiment_d/adaptation/rf_v2_training_plan.json"
    split = root / "reports/experiment_d/adaptation/split_manifest.json"
    comparison = root / "reports/experiment_d/adaptation/rf_v1_vs_rf_v2_internal_report.json"
    leakage = root / "reports/experiment_d/audit/d4_training_leakage_audit.json"
    crosswalk = root / "reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv"
    inputs = [model, metadata_path, training_manifest, plan, split, comparison, leakage, crosswalk]
    missing = [str(p.relative_to(root)) for p in inputs if not p.is_file()]
    if missing:
        raise ValueError(f"RF-v2 freeze inputs missing: {missing}")
    actual = sha256_file(model)
    if actual != EXPECTED_RF_V2_SHA256:
        raise ValueError(f"RF-v2 SHA-256 mismatch: {actual}")
    metadata = json.loads(metadata_path.read_text())
    plan_data = json.loads(plan.read_text())
    config = load_experiment_d_config(root / "config/experiment_d.yaml")
    if metadata.get("model_sha256") != actual:
        raise ValueError("RF-v2 metadata model hash mismatch")
    features = metadata.get("feature_names")
    if not isinstance(features, list) or len(features) != 78 or len(set(features)) != 78:
        raise ValueError("RF-v2 feature schema is not exactly 78 unique ordered features")
    if sha256_file(crosswalk) != config.adapter.crosswalk_sha256:
        raise ValueError("adapter crosswalk hash mismatch")
    payload = {
        "schema": "experiment_d_rf_v2_frozen_manifest", "schema_version": 1,
        "status": "FROZEN", "model_sha256": actual,
        "model_metadata_sha256": sha256_file(metadata_path),
        "training_manifest_sha256": sha256_file(training_manifest),
        "training_plan": {"sha256": sha256_file(plan), "identity": canonical_identity(plan_data)},
        "split_manifest": {"sha256": sha256_file(split), "identity": metadata["split_manifest_identity"]},
        "d4_internal_comparison": {"sha256": sha256_file(comparison)},
        "d4_leakage_audit": {"sha256": sha256_file(leakage)},
        "code_commit": metadata["code_commit"],
        "runtime": {"python": metadata.get("python_version", platform.python_version()),
                    "scikit_learn": metadata.get("scikit_learn_version", sklearn.__version__),
                    "joblib": metadata.get("joblib_version", joblib.__version__)},
        "feature_schema": {"count": 78, "ordered_names": features,
                           "identity": canonical_identity(features)},
        "rf_parameters": metadata["rf_parameters"],
        "preprocessing": plan_data["preprocessing"],
        "preprocessing_identity": canonical_identity(plan_data["preprocessing"]),
        "adapter": {**config.adapter.model_dump(), "crosswalk_logical_path":
                    "reports/tables/cicflowmeter_v3_78_feature_crosswalk.csv"},
        "cicflowmeter_v3": config.cicflowmeter_v3.model_dump(),
        "frozen_at": (frozen_at or datetime.now(timezone.utc)).isoformat(),
    }
    payload["frozen_identity"] = canonical_identity(payload)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return payload


def verify_final_test_isolation(adaptation: ScientificManifest, final_test: ScientificManifest) -> None:
    """Reject cross-role IDs and byte-identical artifacts."""
    validate_role_exclusivity(adaptation, final_test)


def verify_frozen_manifest(path: Path, model: Path) -> dict:
    raw = json.loads(path.read_text())
    identity = raw.pop("frozen_identity", None)
    if identity != canonical_identity(raw):
        raise ValueError("RF-v2 frozen manifest identity mismatch")
    raw["frozen_identity"] = identity
    if raw.get("model_sha256") != EXPECTED_RF_V2_SHA256 or sha256_file(model) != EXPECTED_RF_V2_SHA256:
        raise ValueError("RF-v2 frozen artifact verification failed")
    return raw
