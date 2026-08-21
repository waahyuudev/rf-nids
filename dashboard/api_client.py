"""Resilient HTTP client for the RF-NIDS FastAPI backend."""

from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class APIError(Exception):
    message: str
    status_code: int | None = None

    def __str__(self) -> str:
        return self.message


class RFNIDSClient:
    def __init__(self, base_url: str, timeout: float = 10, session=None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()

    def _request(self, method: str, path: str, **kwargs) -> Any:
        try:
            response = self.session.request(
                method, f"{self.base_url}{path}", timeout=self.timeout, **kwargs
            )
        except requests.Timeout as exc:
            raise APIError("Backend API request timed out.") from exc
        except requests.RequestException as exc:
            raise APIError("Backend API is currently unavailable.") from exc
        if not response.ok:
            message = f"Backend API returned HTTP {response.status_code}."
            try:
                detail = response.json().get("detail")
                if isinstance(detail, str):
                    message = detail
            except (ValueError, AttributeError):
                pass
            raise APIError(message, response.status_code)
        try:
            return response.json()
        except ValueError as exc:
            raise APIError("Backend API returned an invalid response.") from exc

    def health(self):
        return self._request("GET", "/health")

    def model_info(self):
        return self._request("GET", "/api/model")

    def summary(self):
        return self._request("GET", "/api/dashboard/summary")

    def timeline(self, minutes: int = 60):
        return self._request("GET", "/api/dashboard/timeline", params={"minutes": minutes})

    def predictions(self, *, limit=20, offset=0, **filters):
        params = {"limit": limit, "offset": offset, **filters}
        return self._request("GET", "/api/predictions", params={k: v for k, v in params.items() if v})

    def prediction(self, prediction_id: int):
        return self._request("GET", f"/api/predictions/{prediction_id}")

    def alerts(self, *, limit=20, offset=0, **filters):
        params = {"limit": limit, "offset": offset, **filters}
        return self._request("GET", "/api/alerts", params={k: v for k, v in params.items() if v})

    def alert(self, alert_id: int):
        return self._request("GET", f"/api/alerts/{alert_id}")

    def acknowledge_alert(self, alert_id: int):
        return self._request("PATCH", f"/api/alerts/{alert_id}/acknowledge")
