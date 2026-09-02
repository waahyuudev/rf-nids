"""Deterministic, presentation-database-only export serialization."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from io import StringIO
import json
from typing import Any


EXPORT_SCHEMA_VERSION = "1.0"
MAX_EXPORT_RECORDS = 10_000


def utc_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def export_metadata(*, user, filters: dict[str, Any], count: int) -> dict[str, Any]:
    return {
        "exported_at": utc_iso(datetime.now(timezone.utc)),
        "exported_by": {"id": user.id, "name": user.name, "email": user.email},
        "schema_version": EXPORT_SCHEMA_VERSION,
        "filters": filters,
        "record_count": count,
        "maximum_records": MAX_EXPORT_RECORDS,
    }


def json_bytes(value: Any) -> bytes:
    return (json.dumps(
        value, ensure_ascii=False, indent=2, sort_keys=True,
        default=lambda item: utc_iso(item) if isinstance(item, datetime) else str(item),
    ) + "\n").encode()


def csv_bytes(fieldnames: list[str], rows: list[dict[str, Any]]) -> bytes:
    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _csv_value(row.get(key)) for key in fieldnames})
    return output.getvalue().encode("utf-8")


def _csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return utc_iso(value)
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return value


def dataset_record(row) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "total_rows": row.total_rows,
        "total_features": row.total_features,
        "label_column": row.label_column,
        "class_distribution": row.class_distribution,
        "source_path": row.source_path,
        "source_sha256": row.source_sha256,
        "imported_at": utc_iso(row.created_at),
    }


EVALUATION_FIELDS = [
    "metric_key", "class_name", "accuracy", "precision", "recall", "f1",
    "macro_precision", "macro_recall", "macro_f1", "false_positive_rate",
    "true_positive", "true_negative", "false_positive", "false_negative",
    "source_path", "source_sha256",
]


def evaluation_record(row) -> dict[str, Any]:
    return {
        "metric_key": row.metric_key,
        "class_name": row.class_name,
        "accuracy": row.accuracy,
        "precision": row.precision_score,
        "recall": row.recall_score,
        "f1": row.f1_score,
        "macro_precision": row.macro_precision,
        "macro_recall": row.macro_recall,
        "macro_f1": row.macro_f1,
        "false_positive_rate": row.false_positive_rate,
        "true_positive": row.true_positive,
        "true_negative": row.true_negative,
        "false_positive": row.false_positive,
        "false_negative": row.false_negative,
        "confusion_matrix": row.confusion_matrix,
        "notes": row.notes,
        "source_path": row.source_path,
        "source_sha256": row.source_sha256,
    }


def confusion_matrix_rows(matrix: Any) -> tuple[list[str], list[dict[str, Any]]]:
    if not matrix:
        return [], []
    if isinstance(matrix, dict):
        labels, values = matrix.get("labels"), matrix.get("values")
    else:
        labels, values = None, matrix
    if not isinstance(values, list) or not values:
        return [], []
    if not isinstance(labels, list) or len(labels) != len(values):
        labels = [str(index) for index in range(len(values))]
    fields = ["actual_class", *[f"predicted_{label}" for label in labels]]
    rows = []
    for label, values_row in zip(labels, values, strict=True):
        rows.append({"actual_class": label, **{
            f"predicted_{predicted}": value
            for predicted, value in zip(labels, values_row, strict=True)
        }})
    return fields, rows


def prediction_record(row) -> dict[str, Any]:
    flow, model, experiment, alert = row.traffic_flow, row.model, row.experiment, row.alert
    return {
        "prediction_id": row.id,
        "prediction_time": utc_iso(row.prediction_time),
        "source_ip": flow.source_ip,
        "source_port": flow.source_port,
        "destination_ip": flow.destination_ip,
        "destination_port": flow.destination_port,
        "protocol": flow.protocol,
        "predicted_label": row.predicted_label,
        "confidence": row.confidence_score,
        "class_probabilities": row.class_probabilities,
        "model_name": model.model_name,
        "model_version": model.model_version,
        "source_type": row.source_type,
        "experiment_code": experiment.experiment_code if experiment else None,
        "alert_id": alert.id if alert else None,
        "alert_severity": alert.severity if alert else None,
        "alert_status": alert.status if alert else None,
    }


def alert_record(row) -> dict[str, Any]:
    prediction, user = row.prediction, row.acknowledged_by_user
    flow = prediction.traffic_flow
    return {
        "alert_id": row.id,
        "created_at": utc_iso(row.created_at),
        "attack_type": prediction.predicted_label,
        "severity": row.severity,
        "status": row.status,
        "confidence": prediction.confidence_score,
        "prediction_id": row.prediction_id,
        "source_ip": flow.source_ip,
        "source_port": flow.source_port,
        "destination_ip": flow.destination_ip,
        "destination_port": flow.destination_port,
        "protocol": flow.protocol,
        "acknowledged_at": utc_iso(row.acknowledged_at),
        "acknowledged_by_name": user.name if user else None,
        "acknowledged_by_email": user.email if user else None,
    }
