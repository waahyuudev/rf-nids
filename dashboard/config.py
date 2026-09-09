"""Environment-backed dashboard configuration."""

from dataclasses import dataclass
import os

DEMO_MODEL_VERSION = "rf-v3.0-candidate"


@dataclass(frozen=True)
class DashboardConfig:
    api_base_url: str
    refresh_seconds: int
    request_timeout: float
    demo_model_version: str | None = None

    @classmethod
    def from_env(cls) -> "DashboardConfig":
        demo = os.getenv("RF_NIDS_DEMO_MODEL")
        if demo not in (None, "", DEMO_MODEL_VERSION):
            raise ValueError("RF_NIDS_DEMO_MODEL is not an approved demo model")
        return cls(
            api_base_url=os.getenv("FASTAPI_BASE_URL", "http://localhost:8000").rstrip("/"),
            refresh_seconds=max(1, int(os.getenv("DASHBOARD_REFRESH_SECONDS", "5"))),
            request_timeout=max(0.1, float(os.getenv("DASHBOARD_REQUEST_TIMEOUT", "10"))),
            demo_model_version=DEMO_MODEL_VERSION if demo == DEMO_MODEL_VERSION else None,
        )
