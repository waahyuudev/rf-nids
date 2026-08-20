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
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    database_url: str = "postgresql+psycopg2://postgres:postgres@localhost:5432/rf_nids"
    model_path: Path = PROJECT_ROOT / "models/random_forest_active.joblib"
    model_metadata_path: Path = PROJECT_ROOT / "models/model_metadata.json"
    alert_confidence_threshold: float = 0.70
    max_batch_size: int = 1000
    max_page_size: int = 100

    @classmethod
    def from_env(cls) -> "Settings":
        """Build settings from the current process environment."""
        return cls(
            app_env=os.getenv("APP_ENV", "development"),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            leakage_columns_config=_resolve_project_path(
                os.getenv("LEAKAGE_COLUMNS_CONFIG", "config/leakage_columns.json")
            ),
            app_host=os.getenv("APP_HOST", "0.0.0.0"),
            app_port=int(os.getenv("APP_PORT", "8000")),
            database_url=os.getenv(
                "DATABASE_URL",
                "postgresql+psycopg2://postgres:postgres@localhost:5432/rf_nids",
            ),
            model_path=_resolve_project_path(
                os.getenv("MODEL_PATH", "models/random_forest_active.joblib")
            ),
            model_metadata_path=_resolve_project_path(
                os.getenv("MODEL_METADATA_PATH", "models/model_metadata.json")
            ),
            alert_confidence_threshold=float(
                os.getenv("ALERT_CONFIDENCE_THRESHOLD", "0.70")
            ),
            max_batch_size=int(os.getenv("MAX_BATCH_SIZE", "1000")),
            max_page_size=int(os.getenv("MAX_PAGE_SIZE", "100")),
        )
