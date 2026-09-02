"""Read-only scientific evidence synchronization into presentation tables."""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.api.models import (
    Dataset,
    EvaluationResult,
    EvidenceSource,
    Experiment,
    ModelRecord,
)
from src.api.service import metadata_metrics


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_KEY = "CICIDS2017_RF_NIDS_3_CLASS"
EXPERIMENT_CODES = ("EXPERIMENT_A", "EXPERIMENT_B", "EXPERIMENT_C")
CLASS_NAMES = ("Normal", "DDoS", "PortScan")

CANONICAL_EVIDENCE: dict[str, tuple[tuple[str, str, str, str], ...]] = {
    "DATASET": (
        ("DATASET", DATASET_KEY, "DATA_UNDERSTANDING", "reports/metrics/data_understanding.json"),
        ("MODEL", "rf-v1.0", "MODEL_METADATA", "models/model_metadata.json"),
    ),
    "EXPERIMENT_A": (
        ("EXPERIMENT", "EXPERIMENT_A", "SELECTED_TUNED_METRICS", "reports/metrics/tuned_metrics.json"),
        ("EXPERIMENT", "EXPERIMENT_A", "BASELINE_METRICS", "reports/metrics/baseline_metrics.json"),
        ("EXPERIMENT", "EXPERIMENT_A", "MODEL_COMPARISON", "reports/metrics/model_comparison.json"),
    ),
    "EXPERIMENT_B": (
        ("EXPERIMENT", "EXPERIMENT_B", "SCENARIO_METRICS", "reports/metrics/scenario_validation_metrics.json"),
        ("EXPERIMENT", "EXPERIMENT_B", "VALIDATION_COMPARISON", "reports/metrics/validation_comparison.json"),
    ),
    "EXPERIMENT_C": (
        ("EXPERIMENT", "EXPERIMENT_C", "FINAL_REPORT", "reports/metrics/experiment_c_v3_final.json"),
        ("EXPERIMENT", "EXPERIMENT_C", "FINAL_CONFUSION_MATRIX", "reports/tables/experiment_c_final_confusion_matrix.csv"),
        ("EXPERIMENT", "EXPERIMENT_C", "FINAL_CLASS_METRICS", "reports/tables/experiment_c_final_class_metrics.csv"),
    ),
}

ALLOWED_PATHS = frozenset(
    item[3] for group in CANONICAL_EVIDENCE.values() for item in group
)

CANONICAL_EXPERIMENT_C_PREDICTION_TABLES = (
    "reports/tables/experiment_c_v3_normal_predictions_final.csv",
    "reports/tables/experiment_c_v3_ddos_predictions.csv",
    "reports/tables/experiment_c_v3_portscan_predictions_final.csv",
)


class EvidenceSyncError(RuntimeError):
    """Base error for fail-closed evidence synchronization."""


class EvidencePathError(EvidenceSyncError):
    pass


class EvidenceValidationError(EvidenceSyncError):
    pass


class EvidenceConflictError(EvidenceSyncError):
    pass


@dataclass(frozen=True, slots=True)
class EvidenceDocument:
    owner_type: str
    owner_key: str
    role: str
    relative_path: str
    sha256: str
    schema_version: str | None
    content: dict[str, Any] | list[dict[str, str]]


@dataclass(slots=True)
class SyncResult:
    dry_run: bool
    inserted: dict[str, int] = field(
        default_factory=lambda: {
            "datasets": 0,
            "experiments": 0,
            "evaluation_results": 0,
            "evidence_sources": 0,
            "models": 0,
        }
    )
    unchanged: dict[str, int] = field(
        default_factory=lambda: {
            "datasets": 0,
            "experiments": 0,
            "evaluation_results": 0,
            "evidence_sources": 0,
            "models": 0,
        }
    )
    selected_experiments: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "selected_experiments": self.selected_experiments,
            "inserted": self.inserted,
            "unchanged": self.unchanged,
        }


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _required_mapping(document: dict[str, Any], keys: Iterable[str], path: str) -> None:
    missing = [key for key in keys if key not in document]
    if missing:
        raise EvidenceValidationError(f"{path} is missing required keys: {missing}")


def _resolve_allowlisted(root: Path, relative_path: str) -> Path:
    if relative_path not in ALLOWED_PATHS:
        raise EvidencePathError(f"Evidence path is not allowlisted: {relative_path}")
    root = root.resolve()
    candidate = (root / relative_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise EvidencePathError(f"Evidence path escapes repository root: {relative_path}") from exc
    if candidate != root / relative_path:
        raise EvidencePathError(f"Evidence path resolves through a symlink: {relative_path}")
    if not candidate.is_file():
        raise EvidenceValidationError(f"Canonical evidence file is missing: {relative_path}")
    return candidate


def _validate_json(path: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceValidationError(f"{path} must contain a JSON object")
    required: dict[str, tuple[str, ...]] = {
        "reports/metrics/data_understanding.json": (
            "dataset_name", "rows", "columns", "label_column", "mapped_class_distribution"
        ),
        "models/model_metadata.json": (
            "model_version", "model_sha256", "feature_names", "feature_count", "parameters"
        ),
        "reports/metrics/tuned_metrics.json": (
            "experiment_name", "metrics", "preprocessing", "warnings"
        ),
        "reports/metrics/baseline_metrics.json": ("experiment_name", "metrics"),
        "reports/metrics/model_comparison.json": ("selected", "reason", "baseline", "tuned"),
        "reports/metrics/scenario_validation_metrics.json": (
            "experiment_name", "metrics", "limitations", "preprocessing"
        ),
        "reports/metrics/validation_comparison.json": ("experiment_a", "experiment_b"),
        "reports/metrics/experiment_c_v3_final.json": (
            "status", "inference_path", "model", "normal", "ddos", "portscan",
            "confusion_matrix", "final_experiment_c_metrics", "limitations"
        ),
    }
    _required_mapping(value, required[path], path)
    return value


def _validate_csv(path: str, rows: list[dict[str, str]]) -> list[dict[str, str]]:
    if not rows:
        raise EvidenceValidationError(f"{path} must contain at least one data row")
    headers = tuple(rows[0])
    expected = {
        "reports/tables/experiment_c_final_confusion_matrix.csv": (
            "actual_class", "Predicted Normal", "Predicted DDoS", "Predicted PortScan"
        ),
        "reports/tables/experiment_c_final_class_metrics.csv": (
            "class", "precision", "recall", "f1", "support"
        ),
    }[path]
    if headers != expected:
        raise EvidenceValidationError(
            f"{path} headers differ from canonical schema: {headers}"
        )
    return rows


def load_document(
    root: Path, owner_type: str, owner_key: str, role: str, relative_path: str
) -> EvidenceDocument:
    path = _resolve_allowlisted(root, relative_path)
    data = path.read_bytes()
    try:
        if path.suffix == ".json":
            content = _validate_json(relative_path, json.loads(data.decode("utf-8")))
        elif path.suffix == ".csv":
            text = data.decode("utf-8-sig")
            content = _validate_csv(relative_path, list(csv.DictReader(io.StringIO(text))))
        else:
            raise EvidenceValidationError(f"Unsupported canonical evidence type: {relative_path}")
    except (UnicodeDecodeError, json.JSONDecodeError, csv.Error) as exc:
        raise EvidenceValidationError(f"Unable to parse {relative_path}: {exc}") from exc
    schema_version = content.get("schema_version") if isinstance(content, dict) else None
    return EvidenceDocument(
        owner_type=owner_type,
        owner_key=owner_key,
        role=role,
        relative_path=relative_path,
        sha256=sha256_bytes(data),
        schema_version=str(schema_version) if schema_version is not None else None,
        content=content,
    )


def load_canonical_documents(root: Path, experiments: Iterable[str]) -> dict[str, EvidenceDocument]:
    groups = ["DATASET", *experiments]
    documents: dict[str, EvidenceDocument] = {}
    for group in groups:
        for spec in CANONICAL_EVIDENCE[group]:
            document = load_document(root, *spec)
            documents[document.relative_path] = document
    _cross_validate(root, documents)
    return documents


def _cross_validate(root: Path, documents: dict[str, EvidenceDocument]) -> None:
    metadata = documents["models/model_metadata.json"].content
    if not isinstance(metadata, dict):
        raise EvidenceValidationError("Model metadata must be an object")
    features = metadata["feature_names"]
    if not isinstance(features, list) or len(features) != 78 or metadata["feature_count"] != 78:
        raise EvidenceValidationError("Model metadata must contain exactly 78 features")
    artifact = root / "models/random_forest_active.joblib"
    if artifact.is_file() and sha256_bytes(artifact.read_bytes()) != metadata["model_sha256"]:
        raise EvidenceValidationError("Active model hash differs from model metadata")

    c_path = "reports/metrics/experiment_c_v3_final.json"
    if c_path not in documents:
        return
    report = documents[c_path].content
    matrix_rows = documents[
        "reports/tables/experiment_c_final_confusion_matrix.csv"
    ].content
    class_rows = documents["reports/tables/experiment_c_final_class_metrics.csv"].content
    if not isinstance(report, dict) or not isinstance(matrix_rows, list) or not isinstance(class_rows, list):
        raise EvidenceValidationError("Experiment C evidence types are invalid")
    if report["status"].casefold() != "completed":
        raise EvidenceValidationError("Experiment C final report is not completed")
    inference = report["inference_path"]
    model = report["model"]
    if inference.get("database_persistence") is not False or model.get("fitting_performed") is not False:
        raise EvidenceValidationError("Experiment C must remain read-only and unfitted")
    expected_matrix = [
        [int(row["Predicted Normal"]), int(row["Predicted DDoS"]), int(row["Predicted PortScan"])]
        for row in matrix_rows
    ]
    if expected_matrix != report["confusion_matrix"]["values"]:
        raise EvidenceValidationError("Experiment C CSV/JSON confusion matrices differ")
    expected_classes = {row["class"] for row in class_rows}
    if expected_classes != set(CLASS_NAMES):
        raise EvidenceValidationError("Experiment C class metrics do not cover exactly three classes")


def _source(
    db: Session, document: EvidenceDocument, result: SyncResult, imported_at: datetime
) -> EvidenceSource:
    existing = db.scalar(
        select(EvidenceSource).where(
            EvidenceSource.owner_type == document.owner_type,
            EvidenceSource.owner_key == document.owner_key,
            EvidenceSource.evidence_role == document.role,
        )
    )
    if existing is not None:
        if existing.source_path != document.relative_path or existing.source_sha256 != document.sha256:
            raise EvidenceConflictError(
                f"Evidence conflict for {document.owner_key}/{document.role}: "
                f"stored={existing.source_sha256} current={document.sha256}"
            )
        result.unchanged["evidence_sources"] += 1
        return existing
    row = EvidenceSource(
        owner_type=document.owner_type,
        owner_key=document.owner_key,
        evidence_role=document.role,
        source_path=document.relative_path,
        source_sha256=document.sha256,
        schema_version=document.schema_version,
        imported_at=imported_at,
    )
    db.add(row)
    result.inserted["evidence_sources"] += 1
    return row


def _ensure_dataset(
    db: Session, documents: dict[str, EvidenceDocument], result: SyncResult, imported_at: datetime
) -> Dataset:
    understanding = documents["reports/metrics/data_understanding.json"]
    metadata = documents["models/model_metadata.json"]
    data = understanding.content
    model_data = metadata.content
    assert isinstance(data, dict) and isinstance(model_data, dict)
    row = db.scalar(select(Dataset).where(Dataset.source_path == understanding.relative_path))
    if row is not None:
        if row.source_sha256 != understanding.sha256:
            raise EvidenceConflictError(
                f"Dataset evidence changed: stored={row.source_sha256} current={understanding.sha256}"
            )
        result.unchanged["datasets"] += 1
        return row
    row = Dataset(
        name=str(data["dataset_name"]),
        source_path=understanding.relative_path,
        source_sha256=understanding.sha256,
        total_rows=int(data["rows"]),
        total_features=int(model_data["feature_count"]),
        label_column=str(data["label_column"]),
        class_distribution=dict(data["mapped_class_distribution"]),
        created_by_user_id=None,
    )
    db.add(row)
    db.flush()
    result.inserted["datasets"] += 1
    return row


def _notes(values: Any) -> str | None:
    if values in (None, [], {}):
        return None
    return json.dumps(values, ensure_ascii=False, sort_keys=True)


def _evaluation_rows(
    experiment: Experiment,
    metrics: dict[str, Any],
    source: EvidenceDocument,
    notes: Any,
) -> list[EvaluationResult]:
    labels = metrics.get("confusion_matrix_labels")
    matrix = metrics.get("confusion_matrix")
    overall = EvaluationResult(
        experiment_id=experiment.id,
        metric_key="OVERALL",
        class_name=None,
        accuracy=metrics.get("accuracy"),
        macro_precision=metrics.get("macro_precision"),
        macro_recall=metrics.get("macro_recall"),
        macro_f1=metrics.get("macro_f1"),
        false_positive_rate=metrics.get("false_positive_rate_normal_as_attack"),
        confusion_matrix={"labels": labels, "values": matrix} if labels and matrix else None,
        notes=_notes(notes),
        source_path=source.relative_path,
        source_sha256=source.sha256,
    )
    rows = [overall]
    report = metrics.get("classification_report", {})
    fprs = metrics.get("false_positive_rate_one_vs_rest", {})
    for name in CLASS_NAMES:
        values = report.get(name, {})
        rows.append(
            EvaluationResult(
                experiment_id=experiment.id,
                metric_key=f"CLASS:{name}",
                class_name=name,
                precision_score=values.get("precision"),
                recall_score=values.get("recall"),
                f1_score=values.get("f1-score"),
                false_positive_rate=fprs.get(name),
                notes=_notes({"support": values.get("support")}),
                source_path=source.relative_path,
                source_sha256=source.sha256,
            )
        )
    return rows


def _ensure_experiment(
    db: Session,
    *,
    code: str,
    dataset: Dataset,
    primary: EvidenceDocument,
    name: str,
    experiment_type: str,
    description: str,
    status: str,
    result: SyncResult,
    imported_at: datetime,
) -> tuple[Experiment, bool]:
    row = db.scalar(select(Experiment).where(Experiment.experiment_code == code))
    if row is not None:
        if row.source_path != primary.relative_path or row.source_sha256 != primary.sha256:
            raise EvidenceConflictError(
                f"{code} evidence changed: stored={row.source_sha256} current={primary.sha256}"
            )
        result.unchanged["experiments"] += 1
        return row, False
    row = Experiment(
        experiment_code=code,
        experiment_name=name,
        experiment_type=experiment_type,
        dataset=dataset,
        description=description,
        status=status,
        source_path=primary.relative_path,
        source_sha256=primary.sha256,
        schema_version=primary.schema_version,
        imported_at=imported_at,
    )
    db.add(row)
    db.flush()
    result.inserted["experiments"] += 1
    return row, True


def _insert_evaluations(
    db: Session, experiment: Experiment, rows: list[EvaluationResult], result: SyncResult
) -> None:
    existing = db.scalars(
        select(EvaluationResult).where(EvaluationResult.experiment_id == experiment.id)
    ).all()
    if existing:
        expected = {row.metric_key: row.source_sha256 for row in rows}
        actual = {row.metric_key: row.source_sha256 for row in existing}
        if actual != expected:
            raise EvidenceConflictError(f"Evaluation snapshot conflict for {experiment.experiment_code}")
        result.unchanged["evaluation_results"] += len(existing)
        return
    db.add_all(rows)
    result.inserted["evaluation_results"] += len(rows)


def _import_a(db: Session, dataset: Dataset, docs, result, imported_at) -> Experiment:
    primary = docs["reports/metrics/tuned_metrics.json"]
    comparison = docs["reports/metrics/model_comparison.json"].content
    data = primary.content
    assert isinstance(data, dict) and isinstance(comparison, dict)
    if comparison["selected"] != "tuned":
        raise EvidenceValidationError("Experiment A active selection is not tuned")
    experiment, created = _ensure_experiment(
        db,
        code="EXPERIMENT_A",
        dataset=dataset,
        primary=primary,
        name="Experiment A — Stratified Random Split",
        experiment_type="STRATIFIED_RANDOM_SPLIT",
        description=(
            "Selected tuned Random Forest evaluation on the stratified 80/20 split. "
            "Baseline metrics are retained as separate supporting evidence and are not merged."
        ),
        status="COMPLETED",
        result=result,
        imported_at=imported_at,
    )
    rows = _evaluation_rows(
        experiment,
        data["metrics"],
        primary,
        {"warnings": data.get("warnings"), "selection_reason": comparison.get("reason")},
    )
    _insert_evaluations(db, experiment, rows, result)
    return experiment


def _import_b(db: Session, dataset: Dataset, docs, result, imported_at) -> Experiment:
    primary = docs["reports/metrics/scenario_validation_metrics.json"]
    data = primary.content
    assert isinstance(data, dict)
    experiment, created = _ensure_experiment(
        db,
        code="EXPERIMENT_B",
        dataset=dataset,
        primary=primary,
        name=str(data["experiment_name"]),
        experiment_type="ORDERED_CONTIGUOUS_BLOCK_HOLDOUT",
        description=(
            "Scenario stress validation using ordered contiguous blocks; not production validation."
        ),
        status="COMPLETED",
        result=result,
        imported_at=imported_at,
    )
    rows = _evaluation_rows(
        experiment,
        data["metrics"],
        primary,
        {
            "limitations": data.get("limitations"),
            "strategy": data.get("preprocessing", {}).get("strategy"),
            "strategy_rationale": data.get("preprocessing", {}).get("strategy_rationale"),
        },
    )
    _insert_evaluations(db, experiment, rows, result)
    return experiment


def _import_c(db: Session, dataset: Dataset, docs, result, imported_at) -> Experiment:
    primary = docs["reports/metrics/experiment_c_v3_final.json"]
    class_source = docs["reports/tables/experiment_c_final_class_metrics.csv"]
    data = primary.content
    class_rows = class_source.content
    assert isinstance(data, dict) and isinstance(class_rows, list)
    experiment, created = _ensure_experiment(
        db,
        code="EXPERIMENT_C",
        dataset=dataset,
        primary=primary,
        name="Experiment C — External Virtual-Laboratory Validation",
        experiment_type="EXTERNAL_VALIDATION",
        description=(
            "Historical external virtual-laboratory validation. The fitted model was reused; "
            "no retraining or preprocessing refit was performed."
        ),
        status=str(data["experiment_status"]),
        result=result,
        imported_at=imported_at,
    )
    final = data["final_experiment_c_metrics"]
    confusion = data["confusion_matrix"]
    rows = [
        EvaluationResult(
            experiment_id=experiment.id,
            metric_key="OVERALL",
            class_name=None,
            accuracy=final.get("overall_flow_level_accuracy"),
            false_positive_rate=final.get(
                "experiment_c_controlled_normal_flow_level_false_positive_rate"
            ),
            confusion_matrix={
                "labels": confusion.get("actual_rows"),
                "predicted_columns": confusion.get("predicted_columns"),
                "values": confusion.get("values"),
            },
            notes=_notes(
                {
                    "source": "controlled virtual laboratory",
                    "total_evaluated_flows": final.get("total_evaluated_flows"),
                    "total_correctly_classified_flows": final.get(
                        "total_correctly_classified_flows"
                    ),
                    "fitted_pipeline_reused": data["model"].get("fitted_pipeline_reused"),
                    "fitting_performed": data["model"].get("fitting_performed"),
                    "limitations": data.get("limitations"),
                }
            ),
            source_path=primary.relative_path,
            source_sha256=primary.sha256,
        )
    ]
    scenarios = {"Normal": data["normal"], "DDoS": data["ddos"], "PortScan": data["portscan"]}
    final_recall = {
        "Normal": final.get("normal_recall"),
        "DDoS": final.get("ddos_recall"),
        "PortScan": final.get("portscan_recall"),
    }
    for values in class_rows:
        name = values["class"]
        scenario = scenarios[name]
        correct_key = {"Normal": "normal_correctly_classified", "DDoS": "ddos_to_ddos", "PortScan": "portscan_to_portscan"}[name]
        total = int(values["support"])
        correct = int(scenario[correct_key])
        rows.append(
            EvaluationResult(
                experiment_id=experiment.id,
                metric_key=f"CLASS:{name}",
                class_name=name,
                precision_score=float(values["precision"]),
                recall_score=float(values["recall"]),
                f1_score=float(values["f1"]),
                true_positive=correct,
                false_negative=total - correct,
                notes=_notes(
                    {
                        "support": total,
                        "source_recall": final_recall[name],
                        "predictions": scenario.get("predictions"),
                    }
                ),
                source_path=class_source.relative_path,
                source_sha256=class_source.sha256,
            )
        )
    _insert_evaluations(db, experiment, rows, result)
    return experiment


def _link_model(db: Session, experiment_a: Experiment, metadata_doc, result) -> None:
    metadata = metadata_doc.content
    assert isinstance(metadata, dict)
    version = str(metadata["model_version"])
    row = db.scalar(select(ModelRecord).where(ModelRecord.model_version == version))
    metrics = metadata_metrics(metadata)
    if row is None:
        row = ModelRecord(
            model_name=metadata.get("model_name", "RF-NIDS Random Forest"),
            model_version=version,
            algorithm="Random Forest",
            is_active=True,
            **metrics,
        )
        db.add(row)
        result.inserted["models"] += 1
    else:
        result.unchanged["models"] += 1
    row.experiment = experiment_a
    row.artifact_path = "models/random_forest_active.joblib"
    row.artifact_sha256 = metadata["model_sha256"]
    row.parameters = metadata["parameters"]
    row.feature_count = metadata["feature_count"]


def normalize_experiments(value: str | Iterable[str]) -> tuple[str, ...]:
    if isinstance(value, str):
        raw = [value]
    else:
        raw = list(value)
    normalized = []
    for item in raw:
        name = str(item).strip().upper()
        if name == "ALL":
            return EXPERIMENT_CODES
        if name in {"A", "B", "C"}:
            name = f"EXPERIMENT_{name}"
        if name not in EXPERIMENT_CODES:
            raise ValueError(f"Unknown experiment selection: {item}")
        if name not in normalized:
            normalized.append(name)
    return tuple(normalized)


def synchronize_evidence(
    db: Session,
    *,
    root: Path = PROJECT_ROOT,
    experiments: str | Iterable[str] = "all",
    dry_run: bool = False,
) -> SyncResult:
    selected = normalize_experiments(experiments)
    result = SyncResult(dry_run=dry_run, selected_experiments=list(selected))
    try:
        documents = load_canonical_documents(root, selected)
        imported_at = datetime.now(timezone.utc)
        for document in documents.values():
            _source(db, document, result, imported_at)
        dataset = _ensure_dataset(db, documents, result, imported_at)
        imported: dict[str, Experiment] = {}
        if "EXPERIMENT_A" in selected:
            imported["EXPERIMENT_A"] = _import_a(db, dataset, documents, result, imported_at)
            _link_model(
                db,
                imported["EXPERIMENT_A"],
                documents["models/model_metadata.json"],
                result,
            )
        if "EXPERIMENT_B" in selected:
            imported["EXPERIMENT_B"] = _import_b(db, dataset, documents, result, imported_at)
        if "EXPERIMENT_C" in selected:
            imported["EXPERIMENT_C"] = _import_c(db, dataset, documents, result, imported_at)
        db.flush()
        if dry_run:
            db.rollback()
        else:
            db.commit()
        return result
    except Exception:
        db.rollback()
        raise
