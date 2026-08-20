"""Leakage-aware dataset preparation before model fitting."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from src.preprocessing.columns import normalize_column_name, normalize_columns
from src.preprocessing.labels import CLASS_NAMES, map_label


@dataclass(frozen=True, slots=True)
class PreparedDataset:
    """Train/test partitions and their reproducible preprocessing audit."""

    x_train: pd.DataFrame
    x_test: pd.DataFrame
    y_train: pd.Series
    y_test: pd.Series
    metadata_train: pd.DataFrame
    metadata_test: pd.DataFrame
    audit: dict[str, Any]


def class_distribution(values: pd.Series) -> dict[str, int]:
    """Return stable integer class counts."""
    counts = values.value_counts()
    return {str(name): int(count) for name, count in counts.items()}


def prepare_dataset(
    frame: pd.DataFrame,
    *,
    label_column: str,
    leakage_columns: dict[str, str],
    test_size: float = 0.2,
    random_state: int = 42,
) -> PreparedDataset:
    """Filter and split data without fitting any data-dependent transform.

    Median imputation is deliberately absent here. It belongs to the Scikit-learn
    Pipeline and is fitted exclusively through the training partition.
    """
    if not 0 < test_size < 1:
        raise ValueError("test_size must be between 0 and 1")

    data = frame.copy()
    data.columns = normalize_columns(data.columns)
    normalized_label = normalize_column_name(label_column)
    if normalized_label not in data.columns:
        raise ValueError(
            f"Label column '{normalized_label}' not found. Available columns: {list(data.columns)}"
        )

    raw_labels = data[normalized_label]
    distribution_before = class_distribution(raw_labels.fillna("<missing>").astype(str))
    mapped_labels = raw_labels.map(map_label)
    retained_mask = mapped_labels.notna()
    excluded_distribution = class_distribution(
        raw_labels.loc[~retained_mask].fillna("<missing>").astype(str)
    )
    data = data.loc[retained_mask].copy()
    data[normalized_label] = mapped_labels.loc[retained_mask]
    distribution_after_filtering = class_distribution(data[normalized_label])

    duplicate_rows = int(data.duplicated().sum())
    data = data.drop_duplicates().reset_index(drop=True)
    labels = data[normalized_label].astype(str)
    distribution_after_deduplication = class_distribution(labels)
    missing_classes = [class_name for class_name in CLASS_NAMES if class_name not in set(labels)]
    if missing_classes:
        raise ValueError(f"Dataset must contain all target classes; missing: {missing_classes}")
    if int(labels.value_counts().min()) < 2:
        raise ValueError(
            "Each target class needs at least two unique rows for stratified splitting"
        )

    candidates = data.drop(columns=[normalized_label])
    normalized_leakage = {
        normalize_column_name(column): reason for column, reason in leakage_columns.items()
    }
    leakage_found = {
        column: normalized_leakage[column]
        for column in candidates.columns
        if column in normalized_leakage
    }
    metadata_columns = list(leakage_found)
    metadata = candidates[metadata_columns].copy()
    without_leakage = candidates.drop(columns=metadata_columns)
    numeric = without_leakage.select_dtypes(include=["number"]).copy()
    non_numeric_columns = [column for column in without_leakage if column not in numeric]
    if numeric.empty:
        raise ValueError("No numeric model features remain after leakage removal")

    infinity_counts = {
        column: int(np.isinf(numeric[column].to_numpy(dtype=float)).sum())
        for column in numeric
    }
    numeric = numeric.replace([np.inf, -np.inf], np.nan).astype(np.float32)
    all_missing_columns = [column for column in numeric if numeric[column].isna().all()]
    if all_missing_columns:
        raise ValueError(f"Numeric features contain no finite values: {all_missing_columns}")

    row_indices = np.arange(len(data))
    train_indices, test_indices = train_test_split(
        row_indices,
        test_size=test_size,
        random_state=random_state,
        stratify=labels,
    )
    x_train = numeric.iloc[train_indices].reset_index(drop=True)
    x_test = numeric.iloc[test_indices].reset_index(drop=True)
    y_train = labels.iloc[train_indices].reset_index(drop=True)
    y_test = labels.iloc[test_indices].reset_index(drop=True)
    metadata_train = metadata.iloc[train_indices].reset_index(drop=True)
    metadata_test = metadata.iloc[test_indices].reset_index(drop=True)

    audit: dict[str, Any] = {
        "rows_initial": int(len(frame)),
        "class_distribution_before_filtering": distribution_before,
        "rows_excluded_out_of_scope": int((~retained_mask).sum()),
        "excluded_class_distribution": excluded_distribution,
        "class_distribution_after_filtering": distribution_after_filtering,
        "duplicate_rows_removed": duplicate_rows,
        "rows_after_filtering_and_deduplication": int(len(data)),
        "class_distribution_after_deduplication": distribution_after_deduplication,
        "features_initial_excluding_label": int(candidates.shape[1]),
        "features_final": int(numeric.shape[1]),
        "feature_names": list(numeric.columns),
        "metadata_columns": metadata_columns,
        "removed_features": {
            **leakage_found,
            **{column: "non-numeric feature" for column in non_numeric_columns},
        },
        "infinite_values_replaced": infinity_counts,
        "train_rows": int(len(x_train)),
        "test_rows": int(len(x_test)),
        "train_distribution": class_distribution(y_train),
        "test_distribution": class_distribution(y_test),
        "test_size": test_size,
        "random_state": random_state,
    }
    return PreparedDataset(
        x_train=x_train,
        x_test=x_test,
        y_train=y_train,
        y_test=y_test,
        metadata_train=metadata_train,
        metadata_test=metadata_test,
        audit=audit,
    )
