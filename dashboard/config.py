"""Environment-backed dashboard configuration."""

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class DashboardConfig:
    api_base_url: str
    refresh_seconds: int
    request_timeout: float

    @classmethod
    def from_env(cls) -> "DashboardConfig":
        return cls(
            api_base_url=os.getenv("FASTAPI_BASE_URL", "http://localhost:8000").rstrip("/"),
            refresh_seconds=max(1, int(os.getenv("DASHBOARD_REFRESH_SECONDS", "5"))),
            request_timeout=max(0.1, float(os.getenv("DASHBOARD_REQUEST_TIMEOUT", "10"))),
        )
