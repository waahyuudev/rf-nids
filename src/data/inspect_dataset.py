"""Generate a reproducible data-understanding report for a labelled CSV dataset."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
from matplotlib import pyplot as plt  # noqa: E402

from src.common.config import PROJECT_ROOT, Settings
from src.common.logging import configure_logging
from src.data.loading import load_csv_files
from src.preprocessing.columns import normalize_column_name, normalize_columns
from src.preprocessing.labels import CLASS_NAMES, map_label

LOGGER = logging.getLogger(__name__)


def _json_value(value: Any) -> Any:
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return None if not np.isfinite(value) else float(value)
    if isinstance(value, (np.bool_,)):
        return bool(value)
    return value


def load_leakage_config(path: Path) -> dict[str, str]:
    """Load configurable leakage-column names and their reasons."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        columns = document["columns"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"Unable to load leakage config {path}: {exc}") from exc
    if not isinstance(columns, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in columns.items()
    ):
        raise ValueError("Leakage config 'columns' must map column names to reasons")
    return {normalize_column_name(key): value for key, value in columns.items()}


def inspect_dataframe(
    frame: pd.DataFrame,
    *,
    dataset_name: str,
    label_column: str,
    leakage_columns: dict[str, str],
    low_variance_threshold: float = 0.01,
) -> tuple[dict[str, Any], pd.Series]:
    """Inspect a dataframe without fitting or transforming model features."""
    data = frame.copy()
    data.columns = normalize_columns(data.columns)
    normalized_label = normalize_column_name(label_column)
    if normalized_label not in data.columns:
        raise ValueError(
            f"Label column '{normalized_label}' not found. Available columns: {list(data.columns)}"
        )

    raw_labels = data[normalized_label]
    mapped_labels = raw_labels.map(map_label)
    retained = mapped_labels.notna()
    numeric = data.select_dtypes(include=["number"])
    finite_numeric = numeric.replace([np.inf, -np.inf], np.nan)
    infinities = {
        column: int(np.isinf(pd.to_numeric(numeric[column], errors="coerce")).sum())
        for column in numeric.columns
    }
    class_counts = mapped_labels[retained].value_counts().reindex(CLASS_NAMES, fill_value=0)
    total_retained = int(retained.sum())
    low_variance: list[str] = []
    for column in numeric.columns:
        non_null = numeric[column].replace([np.inf, -np.inf], np.nan).dropna()
        if not non_null.empty and non_null.nunique() / len(non_null) <= low_variance_threshold:
            low_variance.append(column)

    leakage_found = {
        column: leakage_columns[column]
        for column in data.columns
        if column in leakage_columns
    }
    out_of_scope_counts = raw_labels[~retained].fillna("<missing>").astype(str).value_counts()
    report: dict[str, Any] = {
        "dataset_name": dataset_name,
        "rows": int(len(data)),
        "columns": int(data.shape[1]),
        "column_types": {column: str(dtype) for column, dtype in data.dtypes.items()},
        "label_column": normalized_label,
        "raw_class_count": int(raw_labels.nunique(dropna=True)),
        "raw_class_distribution": {
            str(key): int(value)
            for key, value in raw_labels.fillna("<missing>").value_counts().items()
        },
        "retained_rows": total_retained,
        "excluded_rows": int((~retained).sum()),
        "excluded_class_distribution": {
            str(key): int(value) for key, value in out_of_scope_counts.items()
        },
        "mapped_class_distribution": {key: int(value) for key, value in class_counts.items()},
        "mapped_class_percentages": {
            key: round(int(value) * 100 / total_retained, 4) if total_retained else 0.0
            for key, value in class_counts.items()
        },
        "missing_values": {column: int(value) for column, value in data.isna().sum().items()},
        "infinite_values": infinities,
        "duplicate_rows": int(data.duplicated().sum()),
        "descriptive_statistics": {
            column: {key: _json_value(value) for key, value in stats.items()}
            for column, stats in finite_numeric.describe().to_dict().items()
        },
        "constant_columns": [
            column for column in data.columns if data[column].nunique(dropna=False) <= 1
        ],
        "low_variance_numeric_columns": low_variance,
        "numeric_correlation": {
            column: {key: _json_value(value) for key, value in values.items()}
            for column, values in finite_numeric.corr().to_dict().items()
        },
        "potential_leakage_columns": leakage_found,
    }
    return report, mapped_labels[retained]


def save_class_distribution(labels: pd.Series, output_path: Path) -> None:
    """Save a Matplotlib class-distribution chart."""
    counts = labels.value_counts().reindex(CLASS_NAMES, fill_value=0)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure, axis = plt.subplots(figsize=(8, 5))
    bars = axis.bar(counts.index, counts.values, color=["#2e7d32", "#c62828", "#ef6c00"])
    axis.set(title="RF-NIDS Class Distribution", xlabel="Class", ylabel="Rows")
    axis.ticklabel_format(style="plain", axis="y")
    axis.bar_label(bars, labels=[f"{int(value):,}" for value in counts.values], padding=3)
    figure.tight_layout()
    figure.savefig(output_path, dpi=160)
    plt.close(figure)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        nargs="+",
        help="One or more source CSV paths",
    )
    parser.add_argument("--label-column", default="label", help="Dataset label column")
    parser.add_argument(
        "--output", type=Path, default=PROJECT_ROOT / "reports/metrics/data_understanding.json"
    )
    parser.add_argument(
        "--figure", type=Path, default=PROJECT_ROOT / "reports/figures/class_distribution.png"
    )
    parser.add_argument("--low-variance-threshold", type=float, default=0.01)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    settings = Settings.from_env()
    configure_logging(settings.log_level)
    if not 0 <= args.low_variance_threshold <= 1:
        raise SystemExit("--low-variance-threshold must be between 0 and 1")
    LOGGER.info("Inspecting dataset files=%s", args.input)
    try:
        frame = load_csv_files(args.input)
        leakage = load_leakage_config(settings.leakage_columns_config)
        report, labels = inspect_dataframe(
            frame,
            dataset_name=args.input[0].parent.name if len(args.input) > 1 else args.input[0].name,
            label_column=args.label_column,
            leakage_columns=leakage,
            low_variance_threshold=args.low_variance_threshold,
        )
        report["source_files"] = [str(path) for path in args.input]
        report["source_file_sizes_bytes"] = {
            str(path): path.stat().st_size for path in args.input
        }
    except (OSError, pd.errors.ParserError, UnicodeError, ValueError) as exc:
        LOGGER.error("Dataset inspection failed: %s", exc)
        raise SystemExit(str(exc)) from exc
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    save_class_distribution(labels, args.figure)
    LOGGER.info("Wrote report=%s figure=%s", args.output, args.figure)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
