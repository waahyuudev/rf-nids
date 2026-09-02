from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from scripts.seal_experiment_d_final_test import seal_manifest
from scripts.verify_experiment_d_frozen_baseline import build_manifest
from src.experiment_d.config import ExperimentDConfig, load_experiment_d_config
from src.experiment_d.integrity import (
    GLOBAL_EXTRACTION_REPORT,
    reject_experiment_c_path,
    require_create_new,
    sha256_file,
)
from src.experiment_d.manifest import (
    ManifestEntry,
    Provenance,
    ScientificManifest,
    entry_from_file,
    scientific_identity,
)
from src.experiment_d.paths import ExperimentDPaths
from src.experiment_d.protocol import validate_final_evaluation_manifest, validate_training_request
from src.experiment_d.split import assert_role_allowed, validate_dataset_ready, validate_role_exclusivity


ROOT = Path(__file__).resolve().parents[2]


def provenance(role: str, class_name: str = "Normal", marker: str = "a") -> Provenance:
    start = datetime(2026, 9, 2, tzinfo=timezone.utc)
    return Provenance.model_validate({
        "experiment_code": "EXPERIMENT_D", "role": role, "class": class_name,
        "capture_id": f"capture-{marker}", "session_id": f"session-{marker}",
        "source_host": "lab-source", "target_host": "lab-target",
        "capture_started_at": start, "capture_ended_at": start + timedelta(minutes=1),
        "scenario_id": f"scenario-{marker}",
    })


def entry(role: str, marker: str, digest: str | None = None) -> ManifestEntry:
    return ManifestEntry(
        logical_path=f"{role}/pcap/normal/{marker}.pcap", size_bytes=4,
        sha256=digest or (marker[0] * 64), provenance=provenance(role, marker=marker),
    )


def test_config_loads_and_declares_complete_final_test_prohibitions() -> None:
    config = load_experiment_d_config(ROOT / "config/experiment_d.yaml")
    assert config.roles == ["adaptation", "final_test"]
    assert config.feature_count == 78
    assert "model_selection" in config.final_test_prohibited_operations
    bad = config.model_dump()
    bad["feature_count"] = 77
    with pytest.raises(ValidationError):
        ExperimentDConfig.model_validate(bad)


def test_paths_are_role_and_class_isolated() -> None:
    paths = ExperimentDPaths(ROOT)
    valid = paths.pcap_root("adaptation", "normal") / "new.pcap"
    assert paths.validate_input(valid, "adaptation", "normal") == valid.resolve()
    with pytest.raises(ValueError, match="input PCAP"):
        paths.validate_input(ROOT / "data/lab/pcap/normal-http-test.pcap", "adaptation", "normal")


def test_experiment_c_and_global_report_are_prohibited() -> None:
    with pytest.raises(ValueError, match="Experiment C"):
        reject_experiment_c_path(ROOT / "data/lab/pcap/ddos-test.pcap")
    assert GLOBAL_EXTRACTION_REPORT == ROOT / "reports/metrics/cicflowmeter_v3_extraction.json"


def test_create_new_semantics(tmp_path: Path) -> None:
    existing = tmp_path / "exists"
    existing.write_text("x")
    with pytest.raises(FileExistsError, match="overwrite"):
        require_create_new(existing)


def test_content_hash_and_manifest_identity_ignore_absolute_machine_path(tmp_path: Path) -> None:
    first = tmp_path / "one" / "capture.pcap"
    second = tmp_path / "two" / "capture.pcap"
    first.parent.mkdir(); second.parent.mkdir()
    first.write_bytes(b"same bytes")
    shutil.copyfile(first, second)
    p = provenance("adaptation")
    one = entry_from_file(first, "adaptation/pcap/normal/capture.pcap", p)
    two = entry_from_file(second, "adaptation/pcap/normal/capture.pcap", p)
    assert sha256_file(first) == sha256_file(second)
    assert scientific_identity([one]) == scientific_identity([two])


def test_roles_capture_sessions_and_hashes_are_exclusive() -> None:
    adaptation = ScientificManifest(role="adaptation", entries=[entry("adaptation", "a")])
    final = ScientificManifest(role="final_test", entries=[entry("final_test", "b")])
    validate_role_exclusivity(adaptation, final)
    for collision in ("capture_id", "session_id", "hash"):
        final_entry = entry("final_test", "b")
        if collision == "capture_id":
            final_entry.provenance.capture_id = "capture-a"
        elif collision == "session_id":
            final_entry.provenance.session_id = "session-a"
        else:
            final_entry.sha256 = "a" * 64
        with pytest.raises(ValueError, match="duplicate"):
            validate_role_exclusivity(adaptation, ScientificManifest(role="final_test", entries=[final_entry]))


def test_final_test_is_rejected_for_training_and_statistics() -> None:
    manifest = ScientificManifest(role="final_test", entries=[entry("final_test", "b")])
    with pytest.raises(ValueError, match="summary_statistics"):
        assert_role_allowed(manifest, "summary_statistics")
    with pytest.raises(ValueError, match="adaptation"):
        validate_training_request(
            manifest, ROOT / "models/experiment_d/model.joblib",
            ROOT / "models/experiment_d/metadata.json",
        )


def test_dataset_preparation_requires_complete_provenance() -> None:
    incomplete = entry("adaptation", "a")
    incomplete.provenance.session_id = None
    with pytest.raises(ValueError, match="provenance fields"):
        validate_dataset_ready(ScientificManifest(role="adaptation", entries=[incomplete]))


def test_training_outputs_cannot_target_rf_v1() -> None:
    manifest = ScientificManifest(role="adaptation", entries=[entry("adaptation", "a")])
    with pytest.raises(ValueError, match="immutable"):
        validate_training_request(
            manifest, ROOT / "models/random_forest_active.joblib",
            ROOT / "models/experiment_d/metadata.json",
        )


def test_unsealed_or_adaptation_manifest_cannot_be_final_evaluation() -> None:
    with pytest.raises(ValueError, match="sealed"):
        validate_final_evaluation_manifest(
            ScientificManifest(role="final_test", entries=[entry("final_test", "b")])
        )
    with pytest.raises(ValueError, match="final_test"):
        validate_final_evaluation_manifest(
            ScientificManifest(role="adaptation", entries=[entry("adaptation", "a")], sealed=True)
        )


def test_final_test_sealing_verifies_bytes_and_refuses_overwrite(tmp_path: Path) -> None:
    project = tmp_path / "project"
    paths = ExperimentDPaths(project)
    artifact = paths.role_root("final_test") / "pcap/normal/capture.pcap"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"pcap fixture")
    item = entry_from_file(artifact, "final_test/pcap/normal/capture.pcap", provenance("final_test"))
    source = paths.manifest_root("final_test") / "manifest.json"
    source.parent.mkdir(parents=True)
    source.write_text(json.dumps(ScientificManifest(role="final_test", entries=[item]).model_dump(mode="json", by_alias=True)))
    output = source.with_name("sealed.json")
    sealed = seal_manifest(source, output, paths)
    validate_final_evaluation_manifest(sealed)
    with pytest.raises(FileExistsError):
        seal_manifest(source, output, paths)


def test_frozen_baseline_inventory_currently_passes() -> None:
    result = build_manifest()
    assert result["status"] == "PASS"
    assert all(item["matches"] for item in result["entries"])


@pytest.mark.parametrize("script,args", [
    ("scripts/train_rf_v2.py", ["--adaptation-manifest", "data/lab/experiment_d/adaptation/manifests/future.json", "--output-model", "models/experiment_d/future.joblib", "--output-metadata", "models/experiment_d/future.json", "--dry-run"]),
    ("scripts/evaluate_experiment_d_final.py", ["--final-test-manifest", "data/lab/experiment_d/final_test/manifests/sealed.json", "--rf-v1-model", "models/random_forest_active.joblib", "--rf-v2-model", "models/experiment_d/future.joblib", "--dry-run"]),
    ("scripts/compare_rf_v1_rf_v2.py", ["--rf-v1-report", "reports/experiment_d/final_test/rf_v1.json", "--rf-v2-report", "reports/experiment_d/final_test/rf_v2.json", "--dry-run"]),
])
def test_d1_entrypoints_fail_closed_without_scientific_inputs(script: str, args: list[str]) -> None:
    completed = subprocess.run([sys.executable, script, *args], cwd=ROOT, text=True, capture_output=True)
    assert completed.returncode != 0


def test_training_guard_has_no_fit_call() -> None:
    assert ".fit(" not in (ROOT / "scripts/train_rf_v2.py").read_text(encoding="utf-8")
