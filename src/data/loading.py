"""Shared CSV loading with normalized-schema validation."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pandas as pd

from src.preprocessing.columns import normalize_columns


def load_csv_files(paths: Sequence[Path], *, include_source_file: bool = True) -> pd.DataFrame:
    """Load CSV files, attaching their origin before concatenation.

    ``source_file`` is metadata and must never be supplied to a model as a
    feature.  Keeping it here makes capture-aware evaluation possible.
    """
    if not paths:
        raise ValueError("At least one input CSV is required")
    missing = [path for path in paths if not path.is_file()]
    if missing:
        raise ValueError(f"Input CSV does not exist: {missing}")
    frames = []
    for path in paths:
        frame = pd.read_csv(path, low_memory=False)
        if include_source_file:
            frame["source_file"] = path.name
        frames.append(frame)
    schemas = [normalize_columns(frame.columns) for frame in frames]
    if any(schema != schemas[0] for schema in schemas[1:]):
        raise ValueError("Input CSV files do not have the same normalized column schema")
    combined = pd.concat(frames, ignore_index=True)
    combined.columns = schemas[0]
    return combined
