"""Resilient HTTP client for the RF-NIDS FastAPI backend."""

from dataclasses import dataclass
from typing import Any, Callable

import requests


@dataclass
class APIError(Exception):
    message: str
    status_code: int | None = None

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class Download:
    content: bytes
    filename: str
    content_type: str


class RFNIDSClient:
    def __init__(
        self,
        base_url: str,
        timeout: float = 10,
        session=None,
        access_token: str | None = None,
        token_provider: Callable[[], str | None] | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.access_token = access_token
        self.token_provider = token_provider

    def _access_token(self) -> str | None:
        return self.token_provider() if self.token_provider is not None else self.access_token

    def _request(self, method: str, path: str, **kwargs) -> Any:
        headers = dict(kwargs.pop("headers", {}))
        token = self._access_token()
        if token:
            headers.setdefault("Authorization", f"Bearer {token}")
        try:
            response = self.session.request(
                method,
                f"{self.base_url}{path}",
                timeout=self.timeout,
                headers=headers,
                **kwargs,
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

    def _download(self, path: str, **params) -> Download:
        headers = {}
        token = self._access_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            response = self.session.request(
                "GET", f"{self.base_url}{path}", timeout=self.timeout,
                headers=headers, params={k: v for k, v in params.items() if v is not None and v != ""},
            )
        except requests.Timeout as exc:
            raise APIError("Backend API request timed out.") from exc
        except requests.RequestException as exc:
            raise APIError("Backend API is currently unavailable.") from exc
        if not response.ok:
            try:
                message = response.json().get("detail")
            except (ValueError, AttributeError):
                message = None
            raise APIError(message or f"Backend API returned HTTP {response.status_code}.", response.status_code)
        disposition = response.headers.get("Content-Disposition", "")
        filename = disposition.split("filename=", 1)[-1].strip('"') if "filename=" in disposition else "rf_nids_export"
        return Download(response.content, filename, response.headers.get("Content-Type", "application/octet-stream"))

    def health(self):
        return self._request("GET", "/health")

    def login(self, email: str, password: str):
        return self._request(
            "POST", "/api/auth/login", json={"email": email, "password": password}
        )

    def current_user(self):
        return self._request("GET", "/api/auth/me")

    def logout(self):
        return self._request("POST", "/api/auth/logout")

    def model_info(self):
        return self._request("GET", "/api/model")

    def active_model(self):
        return self._request("GET", "/api/models/active")

    def datasets(self):
        return self._request("GET", "/api/datasets")

    def experiments(self):
        return self._request("GET", "/api/experiments")

    def experiment_evaluation(self, experiment_id: int):
        return self._request("GET", f"/api/experiments/{experiment_id}/evaluation")

    def evidence_sources(self, *, owner_type=None, owner_key=None):
        params = {"owner_type": owner_type, "owner_key": owner_key}
        return self._request(
            "GET", "/api/evidence-sources", params={k: v for k, v in params.items() if v}
        )

    def summary(self):
        return self._request("GET", "/api/dashboard/summary")

    def timeline(self, minutes: int = 60):
        return self._request("GET", "/api/dashboard/timeline", params={"minutes": minutes})

    def predictions(self, *, limit=20, offset=0, **filters):
        params = {"limit": limit, "offset": offset, **filters}
        return self._request("GET", "/api/predictions", params={k: v for k, v in params.items() if v is not None and v != ""})

    def prediction(self, prediction_id: int):
        return self._request("GET", f"/api/predictions/{prediction_id}")

    def traffic_flows(self, *, limit=20, offset=0, **filters):
        params = {"limit": limit, "offset": offset, **filters}
        return self._request(
            "GET",
            "/api/traffic-flows",
            params={k: v for k, v in params.items() if v is not None and v != ""},
        )

    def monitoring_summary(self):
        return self._request("GET", "/api/monitoring/summary")

    def alerts(self, *, limit=20, offset=0, **filters):
        params = {"limit": limit, "offset": offset, **filters}
        return self._request(
            "GET",
            "/api/alerts",
            params={k: v for k, v in params.items() if v is not None and v != ""},
        )

    def alert(self, alert_id: int):
        return self._request("GET", f"/api/alerts/{alert_id}")

    def acknowledge_alert(self, alert_id: int):
        return self._request("PATCH", f"/api/alerts/{alert_id}/acknowledge")

    def export_dataset(self):
        return self._download("/api/export/dataset")

    def export_experiment(self, experiment_id: int, format: str = "json"):
        return self._download(f"/api/export/experiments/{experiment_id}", format=format)

    def export_confusion_matrix(self, experiment_id: int):
        return self._download(f"/api/export/experiments/{experiment_id}/confusion-matrix")

    def export_predictions(self, format: str = "csv", **filters):
        return self._download("/api/export/predictions", format=format, **filters)

    def export_alerts(self, format: str = "csv", **filters):
        return self._download("/api/export/alerts", format=format, **filters)
