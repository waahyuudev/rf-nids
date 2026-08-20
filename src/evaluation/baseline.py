"""Metrics and Matplotlib artifacts for the baseline classifier."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.pipeline import Pipeline

matplotlib.use("Agg")
from matplotlib import pyplot as plt  # noqa: E402

from src.preprocessing.labels import CLASS_NAMES


def evaluate_predictions(
    y_true: pd.Series,
    y_pred: np.ndarray,
    *,
    prediction_time_seconds: float,
) -> dict[str, Any]:
    """Calculate ordered multiclass metrics and one-vs-rest FPR."""
    labels = list(CLASS_NAMES)
    matrix = confusion_matrix(y_true, y_pred, labels=labels)
    macro = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average="macro", zero_division=0
    )
    weighted = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average="weighted", zero_division=0
    )
    false_positive_rates: dict[str, float] = {}
    for index, class_name in enumerate(labels):
        false_positives = int(matrix[:, index].sum() - matrix[index, index])
        true_negatives = int(
            matrix.sum()
            - matrix[index, :].sum()
            - matrix[:, index].sum()
            + matrix[index, index]
        )
        denominator = false_positives + true_negatives
        false_positive_rates[class_name] = false_positives / denominator if denominator else 0.0

    normal_index, ddos_index, portscan_index = 0, 1, 2
    report = classification_report(
        y_true,
        y_pred,
        labels=labels,
        target_names=labels,
        output_dict=True,
        zero_division=0,
    )
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_precision": float(macro[0]),
        "macro_recall": float(macro[1]),
        "macro_f1": float(macro[2]),
        "weighted_precision": float(weighted[0]),
        "weighted_recall": float(weighted[1]),
        "weighted_f1": float(weighted[2]),
        "classification_report": report,
        "confusion_matrix": matrix.tolist(),
        "confusion_matrix_labels": labels,
        "false_positive_rate_one_vs_rest": false_positive_rates,
        "ids_error_counts": {
            "normal_predicted_as_attack": int(matrix[normal_index, 1:].sum()),
            "ddos_predicted_as_normal": int(matrix[ddos_index, normal_index]),
            "portscan_predicted_as_normal": int(matrix[portscan_index, normal_index]),
        },
        "total_prediction_time_seconds": prediction_time_seconds,
        "average_inference_time_seconds_per_row": prediction_time_seconds / len(y_true),
    }


def save_confusion_matrix(
    metrics: dict[str, Any],
    output_path: Path,
    *,
    title: str = "Baseline Random Forest Confusion Matrix",
) -> None:
    """Save a labelled confusion matrix without Seaborn."""
    matrix = np.asarray(metrics["confusion_matrix"])
    labels = metrics["confusion_matrix_labels"]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure, axis = plt.subplots(figsize=(7, 6))
    image = axis.imshow(matrix, cmap="Blues")
    figure.colorbar(image, ax=axis)
    axis.set(
        title=title,
        xlabel="Predicted label",
        ylabel="True label",
        xticks=range(len(labels)),
        yticks=range(len(labels)),
        xticklabels=labels,
        yticklabels=labels,
    )
    threshold = matrix.max() / 2
    for row in range(len(labels)):
        for column in range(len(labels)):
            axis.text(
                column,
                row,
                f"{int(matrix[row, column]):,}",
                ha="center",
                va="center",
                color="white" if matrix[row, column] > threshold else "black",
            )
    figure.tight_layout()
    figure.savefig(output_path, dpi=160)
    plt.close(figure)


def save_feature_importance(
    pipeline: Pipeline,
    feature_names: list[str],
    *,
    csv_path: Path,
    figure_path: Path,
    title: str = "Baseline Random Forest Feature Importance",
) -> None:
    """Save all feature importances as CSV and plot the top 20."""
    importances = np.asarray(pipeline.named_steps["classifier"].feature_importances_)
    if len(importances) != len(feature_names):
        raise ValueError("Feature names do not match classifier feature importances")
    table = pd.DataFrame({"feature": feature_names, "importance": importances}).sort_values(
        "importance", ascending=False
    )
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    figure_path.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(csv_path, index=False)
    top = table.head(20).sort_values("importance")
    figure, axis = plt.subplots(figsize=(10, max(5, len(top) * 0.35)))
    axis.barh(top["feature"], top["importance"], color="#1565c0")
    axis.set(title=title, xlabel="Importance")
    figure.tight_layout()
    figure.savefig(figure_path, dpi=160)
    plt.close(figure)
