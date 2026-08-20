"""Train and evaluate the RF-NIDS baseline Random Forest pipeline."""

from __future__ import annotations

import argparse
import json
import logging
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

from src.common.config import PROJECT_ROOT, Settings
from src.common.logging import configure_logging
from src.data.inspect_dataset import load_leakage_config
from src.data.loading import load_csv_files
from src.evaluation.baseline import (
    evaluate_predictions,
    save_confusion_matrix,
    save_feature_importance,
)
from src.preprocessing.columns import normalize_column_name
from src.preprocessing.dataset import PreparedDataset, prepare_dataset

LOGGER = logging.getLogger(__name__)
BASELINE_PARAMETERS: dict[str, Any] = {
    "n_estimators": 100,
    "random_state": 42,
    "n_jobs": -1,
    "class_weight": "balanced",
}


def build_baseline_pipeline() -> Pipeline:
    """Build an unfitted median-imputer and baseline Random Forest Pipeline."""
    return Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", RandomForestClassifier(**BASELINE_PARAMETERS)),
        ]
    )


def read_data_understanding(path: Path) -> dict[str, Any]:
    """Load the required Stage 1 report."""
    if not path.is_file():
        raise ValueError(f"Data-understanding report not found: {path}")
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to read data-understanding report {path}: {exc}") from exc
    required = {"source_files", "label_column", "rows", "mapped_class_distribution"}
    missing = sorted(required - report.keys())
    if missing:
        raise ValueError(f"Data-understanding report is missing fields: {missing}")
    return report


def validate_understanding(
    report: dict[str, Any],
    *,
    inputs: list[Path],
    label_column: str,
    loaded_rows: int,
) -> list[str]:
    """Validate training inputs against Stage 1 and return research warnings."""
    if report["label_column"] != normalize_column_name(label_column):
        raise ValueError(
            "Label column does not match data-understanding report: "
            f"{label_column!r} vs {report['label_column']!r}"
        )
    if int(report["rows"]) != loaded_rows:
        raise ValueError(
            f"Loaded row count ({loaded_rows}) differs from data-understanding report "
            f"({report['rows']})"
        )
    report_inputs = [Path(path) for path in report["source_files"]]
    if inputs != report_inputs:
        raise ValueError("Training input files differ from the data-understanding source files")
    warnings = [
        "CICIDS2017 attacks are concentrated in particular capture files/days; "
        "random row splitting "
        "may overestimate generalization to unseen networks or capture periods."
    ]
    mapped = report["mapped_class_distribution"]
    counts = [int(mapped[name]) for name in ("Normal", "DDoS", "PortScan")]
    if max(counts) / min(counts) >= 3:
        warnings.append("Target classes are imbalanced; accuracy must not be interpreted alone.")
    if report.get("constant_columns"):
        warnings.append(
            f"Constant features retained for baseline comparability: {report['constant_columns']}"
        )
    if "fwd_header_length.1" in report.get("column_types", {}):
        warnings.append(
            "Column fwd_header_length.1 appears to be a duplicate-name artifact and requires "
            "domain review as possible redundancy or leakage."
        )
    return warnings


def train_baseline(prepared: PreparedDataset) -> tuple[Pipeline, dict[str, Any]]:
    """Fit only on training rows and evaluate once on held-out rows."""
    pipeline = build_baseline_pipeline()
    training_started = time.perf_counter()
    pipeline.fit(prepared.x_train, prepared.y_train)
    training_time = time.perf_counter() - training_started
    prediction_started = time.perf_counter()
    predictions = pipeline.predict(prepared.x_test)
    prediction_time = time.perf_counter() - prediction_started
    metrics = evaluate_predictions(
        prepared.y_test,
        predictions,
        prediction_time_seconds=prediction_time,
    )
    metrics["training_time_seconds"] = training_time
    return pipeline, metrics


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        nargs="+",
        help="CSV paths; defaults to source_files in the data-understanding report",
    )
    parser.add_argument("--label-column", default="label")
    parser.add_argument(
        "--data-understanding",
        type=Path,
        default=PROJECT_ROOT / "reports/metrics/data_understanding.json",
    )
    parser.add_argument(
        "--model-output",
        type=Path,
        default=PROJECT_ROOT / "models/random_forest_baseline.joblib",
    )
    parser.add_argument(
        "--metrics-output",
        type=Path,
        default=PROJECT_ROOT / "reports/metrics/baseline_metrics.json",
    )
    parser.add_argument(
        "--confusion-matrix-output",
        type=Path,
        default=PROJECT_ROOT / "reports/figures/baseline_confusion_matrix.png",
    )
    parser.add_argument(
        "--feature-importance-output",
        type=Path,
        default=PROJECT_ROOT / "reports/figures/baseline_feature_importance.png",
    )
    parser.add_argument(
        "--feature-importance-csv",
        type=Path,
        default=PROJECT_ROOT / "reports/metrics/feature_importance.csv",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    settings = Settings.from_env()
    configure_logging(settings.log_level)
    try:
        understanding = read_data_understanding(args.data_understanding)
        inputs = args.input or [Path(path) for path in understanding["source_files"]]
        frame = load_csv_files(inputs)
        warnings = validate_understanding(
            understanding,
            inputs=inputs,
            label_column=args.label_column,
            loaded_rows=len(frame),
        )
        prepared = prepare_dataset(
            frame,
            label_column=args.label_column,
            leakage_columns=load_leakage_config(settings.leakage_columns_config),
            test_size=0.2,
            random_state=42,
        )
        del frame
        pipeline, scores = train_baseline(prepared)
    except (OSError, pd.errors.ParserError, UnicodeError, ValueError) as exc:
        LOGGER.error("Baseline training failed: %s", exc)
        raise SystemExit(str(exc)) from exc

    args.model_output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, args.model_output)
    save_confusion_matrix(scores, args.confusion_matrix_output)
    save_feature_importance(
        pipeline,
        prepared.audit["feature_names"],
        csv_path=args.feature_importance_csv,
        figure_path=args.feature_importance_output,
    )
    result: dict[str, Any] = {
        "experiment_name": "random_forest_baseline",
        "experiment_time_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_paths": [str(path) for path in inputs],
        "data_understanding_path": str(args.data_understanding),
        "warnings": warnings,
        "preprocessing": prepared.audit,
        "model_parameters": BASELINE_PARAMETERS,
        "pipeline_steps": ["median_imputer", "random_forest_classifier"],
        "metrics": scores,
        "model_path": str(args.model_output),
        "model_size_bytes": args.model_output.stat().st_size,
        "python_version": platform.python_version(),
        "scikit_learn_version": sklearn.__version__,
    }
    args.metrics_output.parent.mkdir(parents=True, exist_ok=True)
    args.metrics_output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    for warning in warnings:
        LOGGER.warning(warning)
    LOGGER.info("Baseline model=%s metrics=%s", args.model_output, args.metrics_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
