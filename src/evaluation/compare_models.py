"""Compare baseline/tuned results and publish the objectively selected active model."""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.common.config import PROJECT_ROOT
from src.common.hashing import sha256_file
from src.preprocessing.labels import CLASS_NAMES, LABEL_MAPPING


def load_json(path: Path) -> dict[str, Any]:
    """Load a JSON object with a clear validation error."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def selection_criteria(result: dict[str, Any]) -> dict[str, float]:
    """Extract ordered selection criteria from one experiment result."""
    metrics = result["metrics"]
    normal_support = float(metrics["classification_report"]["Normal"]["support"])
    normal_false_alarms = float(metrics["ids_error_counts"]["normal_predicted_as_attack"])
    return {
        "macro_f1": float(metrics["macro_f1"]),
        "ddos_recall": float(metrics["classification_report"]["DDoS"]["recall"]),
        "portscan_recall": float(metrics["classification_report"]["PortScan"]["recall"]),
        "normal_traffic_false_positive_rate": normal_false_alarms / normal_support,
        "average_inference_time_seconds_per_row": float(
            metrics["average_inference_time_seconds_per_row"]
        ),
    }


def selection_key(criteria: dict[str, float]) -> tuple[float, ...]:
    """Create the specification-ordered lexicographic comparison key."""
    return (
        criteria["macro_f1"],
        criteria["ddos_recall"],
        criteria["portscan_recall"],
        -criteria["normal_traffic_false_positive_rate"],
        -criteria["average_inference_time_seconds_per_row"],
    )


def choose_active_model(
    baseline: dict[str, Any], tuned: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    """Choose baseline or tuned without assuming tuning improved the model."""
    baseline_criteria = selection_criteria(baseline)
    tuned_criteria = selection_criteria(tuned)
    selected = (
        "tuned"
        if selection_key(tuned_criteria) > selection_key(baseline_criteria)
        else "baseline"
    )
    comparison = {
        "priority_order": [
            "macro_f1 (higher)",
            "DDoS recall (higher)",
            "PortScan recall (higher)",
            "Normal traffic false positive rate (lower)",
            "average inference time (lower)",
        ],
        "baseline": baseline_criteria,
        "tuned": tuned_criteria,
        "delta_tuned_minus_baseline": {
            key: tuned_criteria[key] - baseline_criteria[key] for key in baseline_criteria
        },
        "selected": selected,
        "reason": (
            f"{selected} has the stronger lexicographic result under the declared priority order; "
            "the tuned model was not selected automatically."
        ),
    }
    return selected, comparison


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline-metrics",
        type=Path,
        default=PROJECT_ROOT / "reports/metrics/baseline_metrics.json",
    )
    parser.add_argument(
        "--tuned-metrics",
        type=Path,
        default=PROJECT_ROOT / "reports/metrics/tuned_metrics.json",
    )
    parser.add_argument(
        "--comparison-output",
        type=Path,
        default=PROJECT_ROOT / "reports/metrics/model_comparison.json",
    )
    parser.add_argument(
        "--active-model-output",
        type=Path,
        default=PROJECT_ROOT / "models/random_forest_active.joblib",
    )
    parser.add_argument(
        "--metadata-output",
        type=Path,
        default=PROJECT_ROOT / "models/model_metadata.json",
    )
    parser.add_argument("--model-version", default="rf-v1.0")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        baseline = load_json(args.baseline_metrics)
        tuned = load_json(args.tuned_metrics)
        selected, comparison = choose_active_model(baseline, tuned)
        selected_result = tuned if selected == "tuned" else baseline
        selected_model_path = Path(selected_result["model_path"])
        if not selected_model_path.is_file():
            raise ValueError(f"Selected model does not exist: {selected_model_path}")
        baseline_features = baseline["preprocessing"]["feature_names"]
        tuned_features = tuned["preprocessing"]["feature_names"]
        if baseline_features != tuned_features:
            raise ValueError("Baseline and tuned feature order differs")
    except (KeyError, TypeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc

    args.active_model_output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(selected_model_path, args.active_model_output)
    active_sha256 = sha256_file(args.active_model_output)
    comparison.update(
        {
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "baseline_metrics": baseline["metrics"],
            "tuned_metrics": tuned["metrics"],
        }
    )
    args.comparison_output.parent.mkdir(parents=True, exist_ok=True)
    args.comparison_output.write_text(json.dumps(comparison, indent=2), encoding="utf-8")

    parameters = (
        tuned["effective_classifier_parameters"]
        if selected == "tuned"
        else baseline["model_parameters"]
    )
    metadata = {
        "model_name": "RF-NIDS Random Forest",
        "model_version": args.model_version,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "selected_experiment": selected,
        "selection_reason": comparison["reason"],
        "model_path": str(args.active_model_output),
        "model_sha256": active_sha256,
        "feature_names": baseline_features,
        "feature_count": len(baseline_features),
        "extra_feature_policy": "reject",
        "label_mapping": LABEL_MAPPING,
        "class_names": list(CLASS_NAMES),
        "parameters": parameters,
        "metrics": selected_result["metrics"],
        "dataset_identity": tuned["dataset_identity"],
        "preprocessing": {
            "infinity_handling": "replace with NaN",
            "imputation": "median fitted inside pipeline",
            "numeric_dtype": "float32",
        },
    }
    args.metadata_output.parent.mkdir(parents=True, exist_ok=True)
    args.metadata_output.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
