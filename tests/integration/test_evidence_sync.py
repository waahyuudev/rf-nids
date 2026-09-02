import json
from pathlib import Path
import shutil

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from src.api.database import Base
from src.api.models import (
    Dataset,
    EvaluationResult,
    EvidenceSource,
    Experiment,
    ModelRecord,
)
from src.application.evidence_sync import (
    ALLOWED_PATHS,
    CANONICAL_EVIDENCE,
    CANONICAL_EXPERIMENT_C_PREDICTION_TABLES,
    EvidenceConflictError,
    EvidencePathError,
    EvidenceValidationError,
    load_document,
    sha256_bytes,
    synchronize_evidence,
)
from src.application import evidence_sync


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def evidence_root(tmp_path):
    root = tmp_path / "evidence"
    for relative in ALLOWED_PATHS:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPOSITORY_ROOT / relative, target)
    return root


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'evidence.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def _counts(db):
    return tuple(
        db.scalar(select(func.count(model.id)))
        for model in (Dataset, Experiment, EvaluationResult, EvidenceSource, ModelRecord)
    )


def test_canonical_allowlist_excludes_predictions_archives_and_templates(evidence_root):
    assert len(ALLOWED_PATHS) == 10
    assert "reports/experiment_c/experiment_manifest.json" not in ALLOWED_PATHS
    assert not any("archive" in path or "diagnostic" in path for path in ALLOWED_PATHS)
    assert not set(CANONICAL_EXPERIMENT_C_PREDICTION_TABLES) & ALLOWED_PATHS
    assert set(CANONICAL_EVIDENCE) == {
        "DATASET", "EXPERIMENT_A", "EXPERIMENT_B", "EXPERIMENT_C"
    }
    with pytest.raises(EvidencePathError):
        load_document(evidence_root, "EXPERIMENT", "X", "INVALID", "../secret.json")


def test_hash_calculation_and_invalid_structure_fail_closed(evidence_root, db):
    relative = "reports/metrics/tuned_metrics.json"
    data = (evidence_root / relative).read_bytes()
    document = load_document(
        evidence_root, "EXPERIMENT", "EXPERIMENT_A", "SELECTED_TUNED_METRICS", relative
    )
    assert document.sha256 == sha256_bytes(data)

    invalid = json.loads(data)
    invalid.pop("metrics")
    (evidence_root / relative).write_text(json.dumps(invalid), encoding="utf-8")
    with pytest.raises(EvidenceValidationError, match="missing required keys"):
        synchronize_evidence(db, root=evidence_root)
    assert _counts(db) == (0, 0, 0, 0, 0)


def test_dataset_and_all_experiments_import_exact_supported_values(evidence_root, db):
    result = synchronize_evidence(db, root=evidence_root)
    assert result.inserted == {
        "datasets": 1,
        "experiments": 3,
        "evaluation_results": 12,
        "evidence_sources": 10,
        "models": 1,
    }
    dataset = db.scalar(select(Dataset))
    assert dataset.name == "cicids2017"
    assert dataset.total_rows == 2_830_743
    assert dataset.total_features == 78
    assert dataset.label_column == "label"
    assert dataset.class_distribution == {
        "Normal": 2_273_097, "DDoS": 128_027, "PortScan": 158_930
    }

    experiments = {
        row.experiment_code: row for row in db.scalars(select(Experiment)).all()
    }
    assert set(experiments) == {"EXPERIMENT_A", "EXPERIMENT_B", "EXPERIMENT_C"}
    assert all(row.dataset_id == dataset.id for row in experiments.values())
    assert experiments["EXPERIMENT_C"].experiment_type == "EXTERNAL_VALIDATION"

    overall_c = db.scalar(
        select(EvaluationResult).where(
            EvaluationResult.experiment_id == experiments["EXPERIMENT_C"].id,
            EvaluationResult.metric_key == "OVERALL",
        )
    )
    assert overall_c.accuracy == 0.005404447594577833
    assert overall_c.macro_f1 is None
    assert overall_c.confusion_matrix["values"] == [
        [61, 0, 0], [10226, 0, 0], [1000, 0, 0]
    ]
    classes = {
        row.class_name: row
        for row in db.scalars(
            select(EvaluationResult).where(
                EvaluationResult.experiment_id == experiments["EXPERIMENT_C"].id,
                EvaluationResult.class_name.is_not(None),
            )
        )
    }
    assert classes["Normal"].true_positive == 61
    assert classes["Normal"].recall_score == 1.0
    assert classes["DDoS"].true_positive == 0
    assert classes["DDoS"].false_negative == 10226
    assert classes["DDoS"].recall_score == 0.0
    assert classes["PortScan"].false_negative == 1000
    assert classes["PortScan"].recall_score == 0.0

    model = db.scalar(select(ModelRecord).where(ModelRecord.model_version == "rf-v1.0"))
    assert model.experiment_id == experiments["EXPERIMENT_A"].id
    assert model.artifact_sha256 == (
        "73d86cb98f35c228d6e619e0f746a2b659d94deabe86d57e801c58bcf935f647"
    )
    assert model.feature_count == 78
    assert model.parameters["n_estimators"] == 200


def test_repeated_sync_is_idempotent_and_hash_conflict_preserves_snapshot(evidence_root, db):
    synchronize_evidence(db, root=evidence_root)
    before = _counts(db)
    second = synchronize_evidence(db, root=evidence_root)
    assert second.inserted == {key: 0 for key in second.inserted}
    assert _counts(db) == before

    path = evidence_root / "reports/metrics/tuned_metrics.json"
    document = json.loads(path.read_text())
    document["phase_2_test_change"] = True
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(EvidenceConflictError, match="stored=.*current="):
        synchronize_evidence(db, root=evidence_root)
    assert _counts(db) == before
    stored = db.scalar(
        select(EvidenceSource).where(EvidenceSource.evidence_role == "SELECTED_TUNED_METRICS")
    )
    assert stored.source_sha256 != sha256_bytes(path.read_bytes())


def test_dry_run_rolls_back_every_presentation_write(evidence_root, db):
    result = synchronize_evidence(db, root=evidence_root, dry_run=True)
    assert result.dry_run is True
    assert result.inserted["experiments"] == 3
    assert _counts(db) == (0, 0, 0, 0, 0)


def test_transaction_rolls_back_if_later_experiment_import_fails(
    evidence_root, db, monkeypatch
):
    def fail_after_experiment_a(*args, **kwargs):
        raise EvidenceValidationError("simulated Experiment B validation failure")

    monkeypatch.setattr(evidence_sync, "_import_b", fail_after_experiment_a)
    with pytest.raises(EvidenceValidationError, match="simulated Experiment B"):
        synchronize_evidence(db, root=evidence_root)
    assert _counts(db) == (0, 0, 0, 0, 0)
