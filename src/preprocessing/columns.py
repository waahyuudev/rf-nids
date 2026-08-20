"""Column-name normalization utilities."""

from __future__ import annotations

import re
from collections.abc import Iterable


def normalize_column_name(name: object) -> str:
    """Normalize one column name to a stable snake-like representation."""
    normalized = str(name).strip().lower().replace("/", "_")
    normalized = re.sub(r"\s+", "_", normalized)
    return normalized


def normalize_columns(columns: Iterable[object]) -> list[str]:
    """Normalize columns and reject collisions caused by normalization."""
    normalized = [normalize_column_name(column) for column in columns]
    duplicates = sorted({name for name in normalized if normalized.count(name) > 1})
    if duplicates:
        raise ValueError(f"Column normalization produced duplicates: {duplicates}")
    return normalized

