"""Tune and evaluate the RF-NIDS Random Forest with RandomizedSearchCV."""

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
import numpy as np
import pandas as pd
import sklearn
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline

from src.common.config import PROJECT_ROOT, Settings
from src.common.hashing import dataset_identity
from src.common.logging import configure_logging
from src.data.inspect_dataset import load_leakage_config
from src.data.loading import load_csv_files
from src.evaluation.baseline import (
    evaluate_predictions,
    save_confusion_matrix,
    save_feature_importance,
)
from src.preprocessing.dataset import PreparedDataset, prepare_dataset
from src.training.train_baseline import (
    build_baseline_pipeline,
    read_data_understanding,
    validate_understanding,
)

LOGGER = logging.getLogger(__name__)
PARAMETER_DISTRIBUTIONS: dict[str, list[Any]] = {
    "classifier__n_estimators": [100, 200, 300, 500],
    "classifier__max_depth": [None, 10, 20, 30, 50],
    "classifier__min_samples_split": [2, 5, 10],
    "classifier__min_samples_leaf": [1, 2, 4],
    "classifier__max_features": ["sqrt", "log2", None],
    "classifier__class_weight": [None, "balanced"],
    "classifier__bootstrap": [True, False],
}


def tune_random_forest(
    prepared: PreparedDataset,
    *,
    iterations: int = 20,
    cv: int = 5,
    parameter_distributions: dict[str, list[Any]] | None = None,
    n_jobs: int = -1,
    tuning_sample_size: int | None = None,
) -> tuple[Pipeline, dict[str, Any], pd.DataFrame]:
    """Tune on a stratified train sample, refit full train, and evaluate test."""
    if iterations < 1:
        raise ValueError("iterations must be at least 1")
    if cv < 2:
        raise ValueError("cv must be at least 2")
    if tuning_sample_size is not None and tuning_sample_size < cv * len(prepared.y_train.unique()):
        raise ValueError("tuning_sample_size is too small for stratified cross-validation")

    search_x = prepared.x_train
    search_y = prepared.y_train
    if tuning_sample_size is not None and tuning_sample_size < len(prepared.x_train):
        all_indices = np.arange(len(prepared.x_train))
        sample_indices, _ = train_test_split(
            all_indices,
            train_size=tuning_sample_size,
            random_state=42,
            stratify=prepared.y_train,
        )
        search_x = prepared.x_train.iloc[sample_indices].reset_index(drop=True)
        search_y = prepared.y_train.iloc[sample_indices].reset_index(drop=True)

    splitter = StratifiedKFold(n_splits=cv, shuffle=True, random_state=42)
    search_pipeline = build_baseline_pipeline()
    search_pipeline.set_params(classifier__n_jobs=1)
    search = RandomizedSearchCV(
        estimator=search_pipeline,
        param_distributions=parameter_distributions or PARAMETER_DISTRIBUTIONS,
        n_iter=iterations,
        scoring="f1_macro",
        n_jobs=n_jobs,
        cv=splitter,
        random_state=42,
        refit=False,
        return_train_score=True,
        verbose=1,
    )
    search_started = time.perf_counter()
    search.fit(search_x, search_y)
    search_time = time.perf_counter() - search_started

    final_model = build_baseline_pipeline()
    final_model.set_params(**search.best_params_, classifier__n_jobs=-1)
    refit_started = time.perf_counter()
    final_model.fit(prepared.x_train, prepared.y_train)
    refit_time = time.perf_counter() - refit_started
    prediction_started = time.perf_counter()
    predictions = final_model.predict(prepared.x_test)
    prediction_time = time.perf_counter() - prediction_started
    metrics = evaluate_predictions(
        prepared.y_test,
        predictions,
        prediction_time_seconds=prediction_time,
    )
    metrics.update(
        {
            "tuning_time_seconds": search_time,
            "full_training_refit_time_seconds": refit_time,
            "tuning_sample_rows": int(len(search_x)),
            "tuning_sample_distribution": {
                str(name): int(count) for name, count in search_y.value_counts().items()
            },
            "best_cross_validation_f1_macro": float(search.best_score_),
            "best_cross_validation_index": int(search.best_index_),
        }
    )
    results = pd.DataFrame(search.cv_results_)
    return final_model, metrics, results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, nargs="+")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--cv", type=int, default=5)
    parser.add_argument(
        "--tuning-sample-size",
        type=int,
        default=50_000,
        help="Stratified training rows used for CV; final refit still uses all training rows",
    )
    parser.add_argument(
        "--search-jobs",
        type=int,
        default=-1,
        help="Parallel CV workers; use 1 in restricted environments",
    )
    parser.add_argument(
        "--data-understanding",
        type=Path,
        default=PROJECT_ROOT / "reports/metrics/data_understanding.json",
    )
    parser.add_argument(
        "--model-output",
        type=Path,
        default=PROJECT_ROOT / "models/random_forest_tuned.joblib",
    )
    parser.add_argument(
        "--metrics-output",
        type=Path,
        default=PROJECT_ROOT / "reports/metrics/tuned_metrics.json",
    )
    parser.add_argument(
        "--best-parameters-output",
        type=Path,
        default=PROJECT_ROOT / "reports/metrics/tuned_best_parameters.json",
    )
    parser.add_argument(
        "--cv-results-output",
        type=Path,
        default=PROJECT_ROOT / "reports/metrics/tuning_results.csv",
    )
    parser.add_argument(
        "--confusion-matrix-output",
        type=Path,
        default=PROJECT_ROOT / "reports/figures/tuned_confusion_matrix.png",
    )
    parser.add_argument(
        "--feature-importance-output",
        type=Path,
        default=PROJECT_ROOT / "reports/figures/tuned_feature_importance.png",
    )
    parser.add_argument(
        "--feature-importance-csv",
        type=Path,
        default=PROJECT_ROOT / "reports/metrics/tuned_feature_importance.csv",
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
        model, scores, cv_results = tune_random_forest(
            prepared,
            iterations=args.iterations,
            cv=args.cv,
            tuning_sample_size=args.tuning_sample_size,
            n_jobs=args.search_jobs,
        )
    except (OSError, pd.errors.ParserError, UnicodeError, ValueError) as exc:
        LOGGER.error("Tuned training failed: %s", exc)
        raise SystemExit(str(exc)) from exc

    args.model_output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.model_output)
    best_parameters = model.named_steps["classifier"].get_params()
    tuned_parameters = {
        key.removeprefix("classifier__"): value
        for key, value in cv_results.loc[scores["best_cross_validation_index"], "params"].items()
    }
    args.best_parameters_output.parent.mkdir(parents=True, exist_ok=True)
    args.best_parameters_output.write_text(
        json.dumps(tuned_parameters, indent=2), encoding="utf-8"
    )
    args.cv_results_output.parent.mkdir(parents=True, exist_ok=True)
    cv_results.to_csv(args.cv_results_output, index=False)
    save_confusion_matrix(
        scores,
        args.confusion_matrix_output,
        title="Tuned Random Forest Confusion Matrix",
    )
    save_feature_importance(
        model,
        prepared.audit["feature_names"],
        csv_path=args.feature_importance_csv,
        figure_path=args.feature_importance_output,
        title="Tuned Random Forest Feature Importance",
    )
    result: dict[str, Any] = {
        "experiment_name": "random_forest_tuned",
        "experiment_time_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_paths": [str(path) for path in inputs],
        "dataset_identity": dataset_identity(inputs),
        "data_understanding_path": str(args.data_understanding),
        "warnings": warnings,
        "preprocessing": prepared.audit,
        "search_configuration": {
            "scoring": "f1_macro",
            "iterations": args.iterations,
            "cv": args.cv,
            "cv_strategy": "StratifiedKFold(shuffle=True, random_state=42)",
            "random_state": 42,
            "n_jobs": args.search_jobs,
            "classifier_n_jobs_during_search": 1,
            "classifier_n_jobs_during_full_refit": -1,
            "tuning_sample_size": args.tuning_sample_size,
            "full_training_rows_for_refit": prepared.audit["train_rows"],
            "parameter_distributions": PARAMETER_DISTRIBUTIONS,
        },
        "best_parameters": tuned_parameters,
        "effective_classifier_parameters": best_parameters,
        "metrics": scores,
        "model_path": str(args.model_output),
        "model_size_bytes": args.model_output.stat().st_size,
        "python_version": platform.python_version(),
        "scikit_learn_version": sklearn.__version__,
    }
    args.metrics_output.parent.mkdir(parents=True, exist_ok=True)
    args.metrics_output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    LOGGER.info("Tuned model=%s metrics=%s", args.model_output, args.metrics_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
