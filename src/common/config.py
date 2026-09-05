"""Environment-based application configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from src.ingestion.cicflowmeter_v3_adapter import CICFLOWMETER_V3_IMAGE_DIGEST


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
    model_path: Path = PROJECT_ROOT / "models/experiment_d/random_forest_rf_v2.joblib"
    model_metadata_path: Path = (
        PROJECT_ROOT / "models/experiment_d/random_forest_rf_v2_runtime_metadata.json"
    )
    max_batch_size: int = 1000
    max_page_size: int = 100
    auth_session_hours: int = 8
    runtime_monitoring_root: Path = PROJECT_ROOT / "data/runtime/monitoring"
    capture_window_seconds: float = 10.0
    capture_stop_timeout_seconds: float = 15.0
    cicflowmeter_v3_image: str = "rf-nids-cicflowmeter-v3:a26aae27"
    cicflowmeter_v3_image_digest: str = CICFLOWMETER_V3_IMAGE_DIGEST
    extraction_timeout_seconds: float = 120.0

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
                os.getenv(
                    "MODEL_PATH", "models/experiment_d/random_forest_rf_v2.joblib"
                )
            ),
            model_metadata_path=_resolve_project_path(
                os.getenv(
                    "MODEL_METADATA_PATH",
                    "models/experiment_d/random_forest_rf_v2_runtime_metadata.json",
                )
            ),
            max_batch_size=int(os.getenv("MAX_BATCH_SIZE", "1000")),
            max_page_size=int(os.getenv("MAX_PAGE_SIZE", "100")),
            auth_session_hours=int(os.getenv("AUTH_SESSION_HOURS", "8")),
            runtime_monitoring_root=_resolve_project_path(
                os.getenv("RUNTIME_MONITORING_ROOT", "data/runtime/monitoring")
            ),
            capture_window_seconds=float(os.getenv("CAPTURE_WINDOW_SECONDS", "10")),
            capture_stop_timeout_seconds=float(
                os.getenv("CAPTURE_STOP_TIMEOUT_SECONDS", "15")
            ),
            cicflowmeter_v3_image=os.getenv(
                "CICFLOWMETER_V3_IMAGE", "rf-nids-cicflowmeter-v3:a26aae27"
            ),
            cicflowmeter_v3_image_digest=os.getenv(
                "CICFLOWMETER_V3_IMAGE_DIGEST", CICFLOWMETER_V3_IMAGE_DIGEST
            ),
            extraction_timeout_seconds=float(
                os.getenv("EXTRACTION_TIMEOUT_SECONDS", "120")
            ),
        )
