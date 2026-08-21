import requests

import pytest

from dashboard.api_client import APIError, RFNIDSClient
from dashboard.config import DashboardConfig


class Response:
    def __init__(self, payload=None, status=200, invalid=False):
        self.payload = payload
        self.status_code = status
        self.ok = status < 400
        self.invalid = invalid

    def json(self):
        if self.invalid:
            raise ValueError("invalid json")
        return self.payload


class Session:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


def client(*responses):
    return RFNIDSClient("http://api.test/", timeout=3, session=Session(responses))


def test_successful_health_and_summary_parsing():
    api = client(Response({"status": "healthy"}), Response({"total_flows": 0}))
    assert api.health() == {"status": "healthy"}
    assert api.summary()["total_flows"] == 0


def test_prediction_and_alert_empty_results_are_preserved():
    api = client(Response([]), Response([]))
    assert api.predictions(limit=20) == []
    assert api.alerts(limit=20) == []


def test_prediction_and_alert_parsing():
    prediction = {"id": 1, "predicted_label": "Normal"}
    alert = {"id": 2, "status": "ACTIVE"}
    api = client(Response([prediction]), Response([alert]))
    assert api.predictions() == [prediction]
    assert api.alerts() == [alert]


def test_acknowledge_uses_patch_request():
    session = Session([Response({"id": 4, "status": "ACKNOWLEDGED"})])
    api = RFNIDSClient("http://api.test", session=session)
    assert api.acknowledge_alert(4)["status"] == "ACKNOWLEDGED"
    assert session.calls[0][0:2] == ("PATCH", "http://api.test/api/alerts/4/acknowledge")


@pytest.mark.parametrize(
    "response, message",
    [
        (requests.ConnectionError(), "unavailable"),
        (requests.Timeout(), "timed out"),
        (Response({"detail": "Not found"}, 404), "Not found"),
        (Response(invalid=True), "invalid response"),
    ],
)
def test_failures_become_user_friendly_api_errors(response, message):
    with pytest.raises(APIError, match=message):
        client(response).health()


def test_config_reads_dashboard_environment(monkeypatch):
    monkeypatch.setenv("FASTAPI_BASE_URL", "http://backend:9000/")
    monkeypatch.setenv("DASHBOARD_REFRESH_SECONDS", "7")
    monkeypatch.setenv("DASHBOARD_REQUEST_TIMEOUT", "2.5")
    config = DashboardConfig.from_env()
    assert config.api_base_url == "http://backend:9000"
    assert config.refresh_seconds == 7
    assert config.request_timeout == 2.5
