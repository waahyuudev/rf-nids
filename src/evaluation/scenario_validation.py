"""Capture-aware, ordered-block validation for the three-class RF-NIDS task."""

from __future__ import annotations

import argparse
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.common.config import PROJECT_ROOT, Settings
from src.common.logging import configure_logging
from src.data.inspect_dataset import load_leakage_config
from src.data.loading import load_csv_files
from src.evaluation.baseline import evaluate_predictions, save_confusion_matrix
from src.preprocessing.columns import normalize_column_name, normalize_columns
from src.preprocessing.dataset import PreparedDataset, class_distribution
from src.preprocessing.labels import CLASS_NAMES, map_label
from src.training.train_baseline import build_baseline_pipeline, read_data_understanding

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ScenarioData:
    prepared: PreparedDataset
    source_distribution: dict[str, Any]
    feature_audit: dict[str, Any]
    limitations: list[str]


def _source_distribution(data: pd.DataFrame, label: str) -> dict[str, Any]:
    rows: dict[str, Any] = {}
    for source, part in data.groupby("source_file", sort=False):
        mapped = part[label].map(map_label)
        counts = mapped.value_counts()
        rows[str(source)] = {
            "rows_total": int(len(part)),
            **{name: int(counts.get(name, 0)) for name in CLASS_NAMES},
        }
    class_sources = {
        name: [source for source, values in rows.items() if values[name] > 0]
        for name in CLASS_NAMES
    }
    single_capture = {
        name: sources for name, sources in class_sources.items() if len(sources) == 1
    }
    return {
        "by_source_file": rows,
        "source_files_by_class": class_sources,
        "classes_confined_to_one_source_file": single_capture,
        "full_source_file_holdout_valid": not bool(single_capture),
    }


def _feature_audit(features: pd.DataFrame) -> dict[str, Any]:
    constant = [name for name in features if features[name].nunique(dropna=False) <= 1]
    first, second = "fwd_header_length", "fwd_header_length.1"
    result: dict[str, Any] = {
        "constant_features": constant,
        "audited_features": [first, second],
    }
    if first in features and second in features:
        pair = features[[first, second]].replace([np.inf, -np.inf], np.nan).dropna()
        identical = bool(pair[first].equals(pair[second]))
        correlation = float(pair[first].corr(pair[second])) if len(pair) > 1 else None
        result["fwd_header_length_comparison"] = {
            "rows_compared": int(len(pair)),
            "identical": identical,
            "pearson_correlation": correlation,
            "very_highly_correlated": bool(
                correlation is not None and abs(correlation) >= 0.99
            ),
            "action": "retained; audit does not modify the main model",
        }
    else:
        result["fwd_header_length_comparison"] = {
            "available": [name for name in (first, second) if name in features],
            "identical": None,
            "pearson_correlation": None,
        }
    return result


def prepare_scenario_dataset(
    frame: pd.DataFrame,
    *,
    label_column: str,
    leakage_columns: dict[str, str],
    test_fraction: float = 0.2,
    block_size: int = 5000,
) -> ScenarioData:
    """Use final whole ordered blocks within each capture/class as unseen test."""
    if not 0 < test_fraction < 1:
        raise ValueError("test_fraction must be between 0 and 1")
    if block_size < 1:
        raise ValueError("block_size must be positive")
    data = frame.copy()
    data.columns = normalize_columns(data.columns)
    label = normalize_column_name(label_column)
    if label not in data or "source_file" not in data:
        raise ValueError("Scenario validation requires label and source_file columns")
    distribution = _source_distribution(data, label)
    mapped = data[label].map(map_label)
    retained = mapped.notna()
    data = data.loc[retained].copy()
    data[label] = mapped.loc[retained]
    before_dedup = len(data)
    dedup_columns = [name for name in data if name != "source_file"]
    data = data.drop_duplicates(subset=dedup_columns).reset_index(drop=True)
    if set(data[label]) != set(CLASS_NAMES):
        raise ValueError("All target classes must be present before scenario splitting")

    candidates = data.drop(columns=[label])
    normalized_leakage = {normalize_column_name(name) for name in leakage_columns}
    metadata_columns = [
        name for name in candidates if name in normalized_leakage or name == "source_file"
    ]
    without_metadata = candidates.drop(columns=metadata_columns)
    numeric = without_metadata.select_dtypes(include=["number"]).copy()
    if numeric.empty:
        raise ValueError("No numeric model features remain")
    feature_audit = _feature_audit(numeric)
    infinity_counts = {
        name: int(np.isinf(numeric[name].to_numpy(dtype=float)).sum()) for name in numeric
    }
    numeric = numeric.replace([np.inf, -np.inf], np.nan).astype(np.float32)

    # Fixed contiguous blocks preserve CSV order. Entire final blocks are held out.
    group_ids = pd.Series(index=data.index, dtype="object")
    test_mask = pd.Series(False, index=data.index)
    stratum_details: list[dict[str, Any]] = []
    for (source, class_name), indices in data.groupby(
        ["source_file", label], sort=False
    ).groups.items():
        ordered = np.asarray(list(indices), dtype=int)
        if len(ordered) < 2:
            raise ValueError(f"Stratum {source}/{class_name} has fewer than two rows")
        local_blocks = np.arange(len(ordered)) // block_size
        unique_blocks = np.unique(local_blocks)
        if len(unique_blocks) == 1:
            # A small stratum still gets two contiguous, non-overlapping groups.
            boundary = max(1, int(np.floor(len(ordered) * (1 - test_fraction))))
            local_blocks = (np.arange(len(ordered)) >= boundary).astype(int)
            unique_blocks = np.unique(local_blocks)
        blocks_for_test = max(1, int(np.ceil(len(unique_blocks) * test_fraction)))
        selected = set(unique_blocks[-blocks_for_test:])
        for row_index, block in zip(ordered, local_blocks, strict=True):
            group_ids.at[row_index] = f"{source}|{class_name}|block-{int(block)}"
            if block in selected:
                test_mask.at[row_index] = True
        stratum_details.append(
            {
                "source_file": str(source),
                "class": str(class_name),
                "rows": int(len(ordered)),
                "blocks": int(len(unique_blocks)),
                "test_blocks": int(blocks_for_test),
            }
        )

    train_indices = np.flatnonzero(~test_mask.to_numpy())
    test_indices = np.flatnonzero(test_mask.to_numpy())
    labels = data[label].astype(str)
    train_groups = set(group_ids.iloc[train_indices])
    test_groups = set(group_ids.iloc[test_indices])
    overlap = sorted(train_groups & test_groups)
    if overlap:
        raise AssertionError("Scenario groups overlap")
    for split_name, indices in (("training", train_indices), ("testing", test_indices)):
        missing = set(CLASS_NAMES) - set(labels.iloc[indices])
        if missing:
            raise ValueError(f"{split_name} is missing target classes: {sorted(missing)}")

    metadata = data[["source_file"]].copy()
    metadata["scenario_group"] = group_ids
    audit = {
        "strategy": "ordered contiguous block holdout within source_file × class",
        "strategy_rationale": (
            "DDoS and PortScan are capture-confined, so full-file holdout would remove a "
            "target class from training. Final whole row-order blocks provide separation "
            "without a random row split."
        ),
        "rows_initial": int(len(frame)),
        "rows_excluded_out_of_scope": int((~retained).sum()),
        "duplicate_rows_removed": int(before_dedup - len(data)),
        "rows_after_filtering_and_deduplication": int(len(data)),
        "feature_names": list(numeric.columns),
        "features_final": int(numeric.shape[1]),
        "metadata_columns": metadata_columns,
        "source_file_used_as_feature": False,
        "infinite_values_replaced": infinity_counts,
        "block_size": block_size,
        "test_fraction_target": test_fraction,
        "strata": stratum_details,
        "train_rows": int(len(train_indices)),
        "test_rows": int(len(test_indices)),
        "train_distribution": class_distribution(labels.iloc[train_indices]),
        "test_distribution": class_distribution(labels.iloc[test_indices]),
        "train_group_count": len(train_groups),
        "test_group_count": len(test_groups),
        "group_overlap_count": 0,
        "group_overlap": overlap,
    }
    prepared = PreparedDataset(
        x_train=numeric.iloc[train_indices].reset_index(drop=True),
        x_test=numeric.iloc[test_indices].reset_index(drop=True),
        y_train=labels.iloc[train_indices].reset_index(drop=True),
        y_test=labels.iloc[test_indices].reset_index(drop=True),
        metadata_train=metadata.iloc[train_indices].reset_index(drop=True),
        metadata_test=metadata.iloc[test_indices].reset_index(drop=True),
        audit=audit,
    )
    limitations = [
        "DDoS and/or PortScan occur in only one source capture; full source-file holdout is invalid.",
        "CICIDS2017 CSVs expose no validated session identifier or reliable row-level timestamp here; "
        "CSV row order is therefore only a proxy for scenario separation.",
        "Experiment B is an additional stress test, not a perfect representation of production traffic.",
    ]
    return ScenarioData(prepared, distribution, feature_audit, limitations)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def build_validation_comparison(baseline: dict[str, Any], scenario: dict[str, Any]) -> dict[str, Any]:
    """Compare baseline Experiment A against scenario Experiment B."""
    a = baseline["metrics"]
    b = scenario["metrics"]
    selected = {
        "accuracy": (a["accuracy"], b["accuracy"]),
        "macro_f1": (a["macro_f1"], b["macro_f1"]),
        "ddos_recall": (
            a["classification_report"]["DDoS"]["recall"], b["recall_by_class"]["DDoS"]
        ),
        "portscan_recall": (
            a["classification_report"]["PortScan"]["recall"],
            b["recall_by_class"]["PortScan"],
        ),
        "false_positive_rate_normal_as_attack": (
            a["ids_error_counts"]["normal_predicted_as_attack"]
            / a["classification_report"]["Normal"]["support"],
            b["false_positive_rate_normal_as_attack"],
        ),
    }
    return {
        "active_model_reselected": False,
        "experiment_a": {"name": "Stratified Random Split", **{k: v[0] for k, v in selected.items()}},
        "experiment_b": {"name": "Scenario/Unseen Split", **{k: v[1] for k, v in selected.items()}},
        "change_b_minus_a": {k: v[1] - v[0] for k, v in selected.items()},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, nargs="+")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--block-size", type=int, default=5000)
    args = parser.parse_args()
    settings = Settings.from_env()
    configure_logging(settings.log_level)
    understanding = read_data_understanding(PROJECT_ROOT / "reports/metrics/data_understanding.json")
    inputs = args.input or [Path(path) for path in understanding["source_files"]]
    frame = load_csv_files(inputs)
    scenario = prepare_scenario_dataset(
        frame,
        label_column=args.label_column,
        leakage_columns=load_leakage_config(settings.leakage_columns_config),
        block_size=args.block_size,
    )
    del frame
    pipeline = build_baseline_pipeline()
    started = time.perf_counter()
    pipeline.fit(scenario.prepared.x_train, scenario.prepared.y_train)
    training_seconds = time.perf_counter() - started
    started = time.perf_counter()
    predictions = pipeline.predict(scenario.prepared.x_test)
    prediction_seconds = time.perf_counter() - started
    metrics = evaluate_predictions(
        scenario.prepared.y_test, predictions, prediction_time_seconds=prediction_seconds
    )
    normal_support = float(metrics["classification_report"]["Normal"]["support"])
    metrics["false_positive_rate_normal_as_attack"] = (
        metrics["ids_error_counts"]["normal_predicted_as_attack"] / normal_support
        if normal_support
        else 0.0
    )
    metrics["recall_by_class"] = {
        name: float(metrics["classification_report"][name]["recall"])
        for name in CLASS_NAMES
    }
    metrics["training_time_seconds"] = training_seconds
    result = {
        "experiment_name": "Experiment B — Unseen/Scenario Validation",
        "experiment_time_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_paths": [str(path) for path in inputs],
        "limitations": scenario.limitations,
        "preprocessing": scenario.prepared.audit,
        "metrics": metrics,
    }
    _write_json(PROJECT_ROOT / "reports/metrics/source_file_distribution.json", scenario.source_distribution)
    _write_json(PROJECT_ROOT / "reports/metrics/feature_audit.json", scenario.feature_audit)
    _write_json(PROJECT_ROOT / "reports/metrics/scenario_validation_metrics.json", result)
    baseline = json.loads(
        (PROJECT_ROOT / "reports/metrics/baseline_metrics.json").read_text(encoding="utf-8")
    )
    _write_json(
        PROJECT_ROOT / "reports/metrics/validation_comparison.json",
        build_validation_comparison(baseline, result),
    )
    save_confusion_matrix(
        metrics,
        PROJECT_ROOT / "reports/figures/scenario_validation_confusion_matrix.png",
        title="Experiment B — Ordered-Block Scenario Validation",
    )
    LOGGER.info("Scenario validation complete: %s", metrics)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
