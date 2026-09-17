import json
from dataclasses import replace

import pytest

from src.api.runtime_models import (
    APPROVED_RUNTIME_MODELS,
    RuntimeModelRegistry,
    RuntimeModelVerificationError,
)
from src.common.hashing import sha256_file


def test_repository_runtime_allowlist_verifies_all_four_models():
    registry = RuntimeModelRegistry()
    assert [item.model_id for item, _ in registry.available()] == [
        "rf-v2.0", "rf-v3.0-candidate", "rf-v4.0-candidate-01",
        "rf-v5-candidate-01",
    ]
    assert registry.excluded == {}
    rf_v5, _ = registry.resolve("rf-v5-candidate-01")
    assert rf_v5.scientific_status == "CANDIDATE / NOT_ACTIVE"
    assert rf_v5.scientific_decision == "RF_V5_VALIDATION_FAIL"
    assert rf_v5.model_sha256 == "31d7d50fa79e3400e7d357cab05c780e038bc527b746d0be6ff894828c6b8d17"
    assert rf_v5.metadata_sha256 == "b9255fb4ad067611db60632e384e2cc5e8aaa2f989228cbc0e541ef421c7224e"


def test_unknown_runtime_model_is_rejected():
    with pytest.raises(RuntimeModelVerificationError, match="allowlist"):
        RuntimeModelRegistry().resolve("rf-v6")


def test_model_hash_mismatch_fails_closed(tmp_path):
    approved = APPROVED_RUNTIME_MODELS[-1]
    model = tmp_path / "model.joblib"
    metadata = tmp_path / "metadata.json"
    model.write_bytes(approved.model_path.read_bytes() + b"tampered")
    metadata.write_bytes(approved.metadata_path.read_bytes())
    changed = replace(approved, model_path=model, metadata_path=metadata)
    with pytest.raises(RuntimeModelVerificationError, match="artifact SHA-256"):
        RuntimeModelRegistry._verify_and_load(changed, object)


def test_metadata_hash_mismatch_fails_closed(tmp_path):
    approved = APPROVED_RUNTIME_MODELS[-1]
    metadata = tmp_path / "metadata.json"
    metadata.write_bytes(approved.metadata_path.read_bytes() + b" ")
    changed = replace(approved, metadata_path=metadata)
    with pytest.raises(RuntimeModelVerificationError, match="metadata SHA-256"):
        RuntimeModelRegistry._verify_and_load(changed, object)


def test_feature_order_mismatch_fails_closed(tmp_path):
    approved = APPROVED_RUNTIME_MODELS[-1]
    metadata_value = json.loads(approved.metadata_path.read_text())
    metadata_value["feature_names"][0:2] = reversed(metadata_value["feature_names"][0:2])
    metadata = tmp_path / "metadata.json"
    metadata.write_text(json.dumps(metadata_value))
    changed = replace(
        approved, metadata_path=metadata, metadata_sha256=sha256_file(metadata)
    )
    with pytest.raises(RuntimeModelVerificationError, match="feature identity/order"):
        RuntimeModelRegistry._verify_and_load(changed, object)
