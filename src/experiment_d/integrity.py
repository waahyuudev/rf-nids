"""Integrity and frozen-boundary helpers for Experiment D."""

from __future__ import annotations

import hashlib
from pathlib import Path

from src.common.config import PROJECT_ROOT
from src.experiment_d.paths import contained


EXPERIMENT_C_ROOTS = (
    PROJECT_ROOT / "data/lab/pcap",
    PROJECT_ROOT / "data/lab/flows/cicflowmeter-v3",
    PROJECT_ROOT / "data/pcap/experiment-c",
    PROJECT_ROOT / "data/lab/experiment_c",
    PROJECT_ROOT / "reports/experiment_c",
    PROJECT_ROOT / "reports/archive/experiment_c_v3_final_20260901",
)
EXPERIMENT_C_FILES = (
    PROJECT_ROOT / "reports/metrics/experiment_c_final.json",
    PROJECT_ROOT / "reports/metrics/experiment_c_v3_final.json",
    PROJECT_ROOT / "reports/tables/experiment_c_final_confusion_matrix.csv",
    PROJECT_ROOT / "reports/tables/experiment_c_final_class_metrics.csv",
    PROJECT_ROOT / "reports/tables/experiment_c_v3_normal_predictions_final.csv",
    PROJECT_ROOT / "reports/tables/experiment_c_v3_ddos_predictions.csv",
    PROJECT_ROOT / "reports/tables/experiment_c_v3_portscan_predictions_final.csv",
)
RF_V1_FILES = (
    PROJECT_ROOT / "models/random_forest_active.joblib",
    PROJECT_ROOT / "models/random_forest_tuned.joblib",
    PROJECT_ROOT / "models/random_forest_baseline.joblib",
    PROJECT_ROOT / "models/model_metadata.json",
)
GLOBAL_EXTRACTION_REPORT = PROJECT_ROOT / "reports/metrics/cicflowmeter_v3_extraction.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_experiment_c_path(path: Path) -> bool:
    resolved = path.resolve(strict=False)
    return resolved in {item.resolve(strict=False) for item in EXPERIMENT_C_FILES} or any(
        contained(resolved, root) for root in EXPERIMENT_C_ROOTS
    )


def reject_experiment_c_path(path: Path) -> None:
    if is_experiment_c_path(path):
        raise ValueError(f"Experiment C path is prohibited: {path}")


def reject_rf_v1_destination(path: Path) -> None:
    resolved = path.resolve(strict=False)
    if resolved in {item.resolve(strict=False) for item in RF_V1_FILES}:
        raise ValueError(f"RF-v1 destination is immutable: {path}")


def require_create_new(path: Path) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing artifact: {path}")
