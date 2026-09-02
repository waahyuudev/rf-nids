"""Experiment D lifecycle gates."""

from __future__ import annotations

from pathlib import Path

from src.experiment_d.integrity import reject_experiment_c_path, reject_rf_v1_destination
from src.experiment_d.manifest import ScientificManifest
from src.experiment_d.paths import ExperimentDPaths, require_under
from src.experiment_d.split import assert_role_allowed, validate_dataset_ready


def validate_training_request(
    manifest: ScientificManifest, output_model: Path, output_metadata: Path,
    paths: ExperimentDPaths | None = None,
) -> None:
    roots = paths or ExperimentDPaths()
    if manifest.role != "adaptation":
        raise ValueError("RF-v2 training requires an adaptation manifest")
    assert_role_allowed(manifest, "fitting")
    validate_dataset_ready(manifest)
    for output in (output_model, output_metadata):
        reject_experiment_c_path(output)
        reject_rf_v1_destination(output)
        require_under(output, roots.model_root, "RF-v2 output")


def validate_final_evaluation_manifest(manifest: ScientificManifest) -> None:
    if manifest.role != "final_test":
        raise ValueError("final evaluation requires a final_test manifest")
    if not manifest.sealed:
        raise ValueError("final_test manifest must be sealed")
    validate_dataset_ready(manifest)
