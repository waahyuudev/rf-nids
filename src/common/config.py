"""Environment-based application configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _resolve_project_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


@dataclass(frozen=True, slots=True)
class Settings:
    """Non-secret runtime settings loaded from environment variables."""

    app_env: str
    log_level: str
    leakage_columns_config: Path

    @classmethod
    def from_env(cls) -> "Settings":
        """Build settings from the current process environment."""
        return cls(
            app_env=os.getenv("APP_ENV", "development"),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            leakage_columns_config=_resolve_project_path(
                os.getenv("LEAKAGE_COLUMNS_CONFIG", "config/leakage_columns.json")
            ),
        )

