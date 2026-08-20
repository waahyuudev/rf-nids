"""Shared CSV loading with normalized-schema validation."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pandas as pd

from src.preprocessing.columns import normalize_columns


def load_csv_files(paths: Sequence[Path]) -> pd.DataFrame:
    """Load one or more CSV files that share the same normalized schema."""
    if not paths:
        raise ValueError("At least one input CSV is required")
    missing = [path for path in paths if not path.is_file()]
    if missing:
        raise ValueError(f"Input CSV does not exist: {missing}")
    frames = [pd.read_csv(path, low_memory=False) for path in paths]
    schemas = [normalize_columns(frame.columns) for frame in frames]
    if any(schema != schemas[0] for schema in schemas[1:]):
        raise ValueError("Input CSV files do not have the same normalized column schema")
    combined = pd.concat(frames, ignore_index=True)
    combined.columns = schemas[0]
    return combined

