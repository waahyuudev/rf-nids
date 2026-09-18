"""Experiment E preregistration, provenance, and leakage guards."""

import hashlib
import json
from pathlib import Path

from src.experiment_d.integrity import require_create_new, sha256_file
from src.experiment_d.paths import contained
from src.ingestion.cicflowmeter_v3_adapter import MODEL_FEATURES


ROLES = ("adaptation", "validation", "final_test")
EXPECTED_SESSIONS = {
    "expe-normal-n-a1": ("Normal", "adaptation"),
    "expe-normal-n-a2": ("Normal", "adaptation"),
    "expe-normal-n-a3": ("Normal", "adaptation"),
    "expe-normal-n-v1": ("Normal", "validation"),
    "expe-normal-n-f1": ("Normal", "final_test"),
    "expe-portscan-p-a1": ("PortScan", "adaptation"),
    "expe-portscan-p-a2": ("PortScan", "adaptation"),
    "expe-portscan-p-a3": ("PortScan", "adaptation"),
    "expe-portscan-p-v1": ("PortScan", "validation"),
    "expe-portscan-p-f1": ("PortScan", "final_test"),
}
FINAL_TEST_PROHIBITED = {
    "fitting", "adaptation", "tuning", "preprocessing_fit", "feature_selection",
    "threshold_selection", "model_selection", "validation",
}


def load_preregistration(path: Path) -> dict:
    raw = json.loads(path.read_text(encoding="utf-8"))
    validate_preregistration(raw)
    return raw


def validate_preregistration(raw: dict) -> None:
    if raw.get("experiment_code") != "EXPERIMENT_E":
        raise ValueError("preregistration must belong to Experiment E")
    if (
        raw.get("split_unit") != "capture_session"
        or raw.get("row_redistribution_after_extraction") is not False
    ):
        raise ValueError("rows must remain assigned by capture session")
    sessions = raw.get("sessions", [])
    ids = [item.get("session_id") for item in sessions]
    captures = [item.get("capture_id") for item in sessions]
    if len(ids) != len(set(ids)) or len(captures) != len(set(captures)):
        raise ValueError("duplicate session or capture ID across roles")
    actual = {item["session_id"]: (item["class"], item["role"]) for item in sessions}
    if actual != EXPECTED_SESSIONS:
        raise ValueError("session membership differs from the locked E1 split")
    target = raw.get("topology", {}).get("target", {}).get("ip")
    external_allowed = raw.get("topology", {}).get("external_or_public_targets_allowed")
    if target != "172.30.50.10" or external_allowed is not False:
        raise ValueError("traffic target must remain the owned isolated lab target")
    for item in sessions:
        if item["class"] == "PortScan" and "172.30.50.10" not in item["command_config"]:
            raise ValueError("PortScan command is not restricted to the lab target")


def reject_experiment_d_final_test(path: Path, project_root: Path) -> None:
    prohibited = (
        project_root / "data/lab/experiment_d/final_test",
        project_root / "reports/experiment_d/final_test",
    )
    if any(contained(path, root) for root in prohibited):
        raise ValueError(f"Experiment D final-test data is forbidden in Experiment E: {path}")


def assert_role_operation_allowed(role: str, operation: str) -> None:
    if role not in ROLES:
        raise ValueError(f"unknown Experiment E role: {role}")
    if role == "final_test" and operation in FINAL_TEST_PROHIBITED:
        raise ValueError(f"Experiment E final-test is sealed from {operation}")


def validate_cross_role_identities(records: list[dict]) -> None:
    """Reject session, capture, PCAP, or extracted-flow identity reuse across roles."""
    for field in ("session_id", "capture_id", "pcap_sha256", "flow_source_sha256"):
        owners: dict[str, str] = {}
        for record in records:
            role, value = record.get("role"), record.get(field)
            if role not in ROLES:
                raise ValueError(f"unknown Experiment E role: {role}")
            if not value:
                continue
            previous = owners.setdefault(value, role)
            if previous != role:
                raise ValueError(f"duplicate {field} across roles: {value}")


def validate_feature_contract(feature_names: list[str] | tuple[str, ...]) -> None:
    if tuple(feature_names) != MODEL_FEATURES or len(feature_names) != 78:
        raise ValueError("incorrect Experiment E 78-feature order")


def ordered_feature_identity(feature_names: list[str] | tuple[str, ...]) -> str:
    encoded = json.dumps(list(feature_names), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_provenance(actual: dict, expected: dict) -> None:
    keys = ("commit", "source_archive_sha256", "image_digest")
    if any(actual.get(key) != expected.get(key) for key in keys):
        raise ValueError("incorrect CICFlowMeter provenance")


__all__ = ["require_create_new", "sha256_file"]
