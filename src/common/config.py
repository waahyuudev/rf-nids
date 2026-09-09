"""Environment-based application configuration."""

from __future__ import annotations

import os
import json
from dataclasses import dataclass
from pathlib import Path

from src.ingestion.cicflowmeter_v3_adapter import CICFLOWMETER_V3_IMAGE_DIGEST
from src.ingestion.cicflowmeter_v3_adapter import MODEL_FEATURES
from src.common.hashing import sha256_file


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEMO_MODEL_ENV = "RF_NIDS_DEMO_MODEL"
DEMO_MODEL_VERSION = "rf-v3.0-candidate"
DEMO_MODEL_PATH = PROJECT_ROOT / "models/experiment_e/random_forest_rf_v3_candidate.joblib"
DEMO_METADATA_PATH = PROJECT_ROOT / "models/experiment_e/random_forest_rf_v3_candidate_metadata.json"
DEMO_MODEL_SHA256 = "6b01c7b3923c1a6bd471862d011f8f5b88a31378e51d1dde082bd2e72bedef86"
DEMO_METADATA_SHA256 = "30b6bdf2a6cb2d60e2be36d4db1e124d71504393081b229e6d94da7e70322cbc"


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
    runtime_monitoring_host_root: Path | None = None
    capture_window_seconds: float = 10.0
    capture_stop_timeout_seconds: float = 15.0
    cicflowmeter_v3_image: str = "rf-nids-cicflowmeter-v3:a26aae27"
    cicflowmeter_v3_image_digest: str = CICFLOWMETER_V3_IMAGE_DIGEST
    extraction_timeout_seconds: float = 120.0
    demo_model_version: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        """Build settings from the current process environment."""
        demo = os.getenv(DEMO_MODEL_ENV)
        if demo not in (None, "", DEMO_MODEL_VERSION):
            raise ValueError(f"{DEMO_MODEL_ENV} is not an approved demo model")
        if demo == DEMO_MODEL_VERSION:
            _validate_demo_candidate()
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
            model_path=(DEMO_MODEL_PATH if demo == DEMO_MODEL_VERSION else _resolve_project_path(
                os.getenv(
                    "MODEL_PATH", "models/experiment_d/random_forest_rf_v2.joblib"
                )
            )),
            model_metadata_path=(DEMO_METADATA_PATH if demo == DEMO_MODEL_VERSION else _resolve_project_path(
                os.getenv(
                    "MODEL_METADATA_PATH",
                    "models/experiment_d/random_forest_rf_v2_runtime_metadata.json",
                )
            )),
            max_batch_size=int(os.getenv("MAX_BATCH_SIZE", "1000")),
            max_page_size=int(os.getenv("MAX_PAGE_SIZE", "100")),
            auth_session_hours=int(os.getenv("AUTH_SESSION_HOURS", "8")),
            runtime_monitoring_root=_resolve_project_path(
                os.getenv("RUNTIME_MONITORING_ROOT", "data/runtime/monitoring")
            ),
            runtime_monitoring_host_root=(
                Path(os.environ["RUNTIME_MONITORING_HOST_ROOT"])
                if os.getenv("RUNTIME_MONITORING_HOST_ROOT") else None
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
            demo_model_version=DEMO_MODEL_VERSION if demo == DEMO_MODEL_VERSION else None,
        )


def _validate_demo_candidate() -> None:
    """Fail closed for the sole allowlisted, explicitly non-active demo artifact."""
    if not DEMO_MODEL_PATH.is_file() or sha256_file(DEMO_MODEL_PATH) != DEMO_MODEL_SHA256:
        raise ValueError("RF-v3 demo candidate artifact is missing or has an unexpected SHA-256")
    if not DEMO_METADATA_PATH.is_file() or sha256_file(DEMO_METADATA_PATH) != DEMO_METADATA_SHA256:
        raise ValueError("RF-v3 demo candidate metadata is missing or has an unexpected SHA-256")
    metadata = json.loads(DEMO_METADATA_PATH.read_text(encoding="utf-8"))
    if (metadata.get("version") != DEMO_MODEL_VERSION
            or metadata.get("status") != "CANDIDATE / NOT_ACTIVE"
            or metadata.get("model_sha256") != DEMO_MODEL_SHA256
            or metadata.get("feature_names") != list(MODEL_FEATURES)
            or metadata.get("feature_count") != 78):
        raise ValueError("RF-v3 demo candidate metadata violates the locked demo contract")
