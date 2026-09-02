"""Capture-level split-role enforcement."""

from __future__ import annotations

from src.experiment_d.manifest import ScientificManifest


TRAINING_OPERATIONS = {
    "fitting", "tuning", "preprocessing_fit", "feature_selection",
    "threshold_selection", "model_selection", "summary_statistics",
}


def assert_role_allowed(manifest: ScientificManifest, operation: str) -> None:
    if manifest.role == "final_test" and operation in TRAINING_OPERATIONS:
        raise ValueError(f"final_test data is prohibited during {operation}")


def validate_role_exclusivity(
    adaptation: ScientificManifest, final_test: ScientificManifest
) -> None:
    if adaptation.role != "adaptation" or final_test.role != "final_test":
        raise ValueError("expected adaptation and final_test manifests")
    a_entries, f_entries = adaptation.entries, final_test.entries
    checks = (
        ("capture_id", {x.provenance.capture_id for x in a_entries if x.provenance.capture_id}),
        ("session_id", {x.provenance.session_id for x in a_entries if x.provenance.session_id}),
        ("content SHA-256", {x.sha256 for x in a_entries}),
    )
    for label, adaptation_values in checks:
        attribute = "sha256" if label == "content SHA-256" else None
        final_values = {
            getattr(x, attribute) if attribute else getattr(x.provenance, label)
            for x in f_entries
            if (getattr(x, attribute) if attribute else getattr(x.provenance, label))
        }
        overlap = sorted(adaptation_values & final_values)
        if overlap:
            raise ValueError(f"duplicate {label} across adaptation/final_test: {overlap}")


def validate_dataset_ready(manifest: ScientificManifest) -> None:
    for entry in manifest.entries:
        entry.provenance.require_complete()
