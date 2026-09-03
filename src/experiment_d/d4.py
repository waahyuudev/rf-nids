"""Experiment D D4 evaluation and evidence helpers."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pandas as pd

from src.evaluation.baseline import evaluate_predictions
from src.preprocessing.labels import CLASS_NAMES


def write_json_new(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
        stream.write("\n")


def write_csv_new(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def metrics_with_predictions(y_true: pd.Series, predictions: np.ndarray, elapsed: float) -> dict[str, Any]:
    result = evaluate_predictions(y_true, predictions, prediction_time_seconds=elapsed)
    result["prediction_count_per_class"] = {
        name: int(np.sum(predictions == name)) for name in CLASS_NAMES
    }
    result["support_per_class"] = {
        name: int(np.sum(y_true.to_numpy() == name)) for name in CLASS_NAMES
    }
    return result


def confusion_rows(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    labels = metrics["confusion_matrix_labels"]
    return [
        {"ground_truth": true, **{predicted: metrics["confusion_matrix"][i][j] for j, predicted in enumerate(labels)}}
        for i, true in enumerate(labels)
    ]


def prediction_rows(
    provenance: list[dict[str, Any]], y_true: pd.Series, predictions: np.ndarray,
    probabilities: np.ndarray, model_classes: np.ndarray,
) -> list[dict[str, Any]]:
    class_positions = {str(name): index for index, name in enumerate(model_classes)}
    rows = []
    for i, source in enumerate(provenance):
        predicted = str(predictions[i])
        rows.append({
            "row_identity": source["row_identity"],
            "source_family": source["source_family"],
            "source_file": source["source_file"],
            "capture_id": source.get("capture_id", ""),
            "session_id": source.get("session_id", ""),
            "scenario_id": source.get("scenario_id", ""),
            "ground_truth": str(y_true.iloc[i]),
            "predicted_class": predicted,
            "confidence": float(probabilities[i, class_positions[predicted]]),
            **{f"probability_{name}": float(probabilities[i, class_positions[name]]) for name in CLASS_NAMES},
        })
    return rows


def apply_selection_rule(rf_v1: dict[str, Any], rf_v2: dict[str, Any]) -> dict[str, Any]:
    report = rf_v2["classification_report"]
    gates = {
        "ddos_recall_gt_zero": report["DDoS"]["recall"] > 0,
        "portscan_recall_gt_zero": report["PortScan"]["recall"] > 0,
        "normal_recall_gte_0_50": report["Normal"]["recall"] >= 0.50,
        "adaptation_macro_f1_gte_rf_v1": rf_v2["macro_f1"] >= rf_v1["macro_f1"],
    }
    return {"gates": gates, "passed": all(gates.values()), "rule_changed_after_results": False}
