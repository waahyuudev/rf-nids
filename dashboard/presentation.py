"""Pure presentation mappings shared by Streamlit pages and tests."""

from __future__ import annotations

import json
from typing import Any


CLASS_ORDER = ("Normal", "DDoS", "PortScan")


def available(value: Any, fallback: str = "Not available") -> Any:
    return fallback if value is None else value


def percent(value: float | None) -> str:
    return "Not available" if value is None else f"{value:.4%}"


def dataset_view(row: dict) -> dict:
    return {
        "Dataset name": available(row.get("name")),
        "Source identity": available(row.get("source_path")),
        "Source SHA-256": available(row.get("source_sha256")),
        "Total rows": available(row.get("total_rows")),
        "Total features": available(row.get("total_features")),
        "Label column": available(row.get("label_column")),
        "Import timestamp": available(row.get("created_at")),
    }


def model_view(row: dict) -> dict:
    return {
        "Model name": available(row.get("model_name")),
        "Version": available(row.get("model_version")),
        "Algorithm": available(row.get("algorithm")),
        "Status": "Active" if row.get("is_active") else "Inactive",
        "Artifact path": available(row.get("artifact_path")),
        "Artifact SHA-256": available(row.get("artifact_sha256")),
        "Feature count": available(row.get("feature_count")),
        "Classes": ", ".join(row.get("class_labels") or []) or "Not available",
        "Linked experiment": available(row.get("experiment_name")),
    }


def split_evaluations(rows: list[dict]) -> tuple[dict | None, list[dict]]:
    overall = next((row for row in rows if row.get("metric_key") == "OVERALL"), None)
    classes = [row for row in rows if row.get("class_name")]
    order = {name: index for index, name in enumerate(CLASS_ORDER)}
    classes.sort(key=lambda row: order.get(row.get("class_name"), len(order)))
    return overall, classes


def confusion_matrix_view(value: Any) -> tuple[list[str], list[list[int]]] | None:
    if not isinstance(value, dict):
        return None
    labels, matrix = value.get("labels"), value.get("values")
    if not isinstance(labels, list) or not isinstance(matrix, list):
        return None
    if len(labels) != len(matrix) or any(not isinstance(row, list) or len(row) != len(labels) for row in matrix):
        return None
    return [str(label) for label in labels], matrix


def notes_view(value: str | None) -> Any:
    if value is None:
        return None
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return value


def comparison_rows(experiments: list[dict], evaluations: dict[int, list[dict]]) -> list[dict]:
    output = []
    for experiment in experiments:
        overall, classes = split_evaluations(evaluations.get(experiment["id"], []))
        if overall is None:
            continue
        by_class = {row["class_name"]: row for row in classes}
        output.append(
            {
                "Experiment": experiment["experiment_code"].replace("EXPERIMENT_", "Experiment "),
                "Evaluation Type": experiment.get("experiment_type"),
                "Accuracy": overall.get("accuracy"),
                "Macro F1": overall.get("macro_f1"),
                "DDoS Recall": by_class.get("DDoS", {}).get("recall_score"),
                "PortScan Recall": by_class.get("PortScan", {}).get("recall_score"),
            }
        )
    return output


def class_probability_rows(probabilities: Any) -> list[dict]:
    """Map only persisted probabilities; never infer missing class values."""
    if not isinstance(probabilities, dict):
        return []
    ordered = [name for name in CLASS_ORDER if name in probabilities]
    ordered.extend(name for name in probabilities if name not in ordered)
    return [
        {"Class": name, "Probability": probabilities[name]}
        for name in ordered
        if isinstance(probabilities[name], (int, float))
    ]


def prediction_context(row: dict) -> dict:
    source_type = row.get("source_type")
    return {
        "Source type": available(source_type),
        "Runtime context": "Runtime inference" if source_type in (None, "RUNTIME") else "Imported context",
        "Experiment": available(row.get("experiment_code")),
        "External key": available(row.get("external_key")),
    }
