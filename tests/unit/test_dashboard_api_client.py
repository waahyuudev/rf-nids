import requests

import pytest

from dashboard.api_client import APIError, RFNIDSClient
from dashboard.config import DashboardConfig


class Response:
    def __init__(self, payload=None, status=200, invalid=False, content=b"", headers=None):
        self.payload = payload
        self.status_code = status
        self.ok = status < 400
        self.invalid = invalid
        self.content = content
        self.headers = headers or {}

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
    api = RFNIDSClient("http://api.test", session=session, access_token="session-token")
    assert api.acknowledge_alert(4)["status"] == "ACKNOWLEDGED"
    assert session.calls[0][0:2] == ("PATCH", "http://api.test/api/alerts/4/acknowledge")
    assert session.calls[0][2]["headers"] == {"Authorization": "Bearer session-token"}


def test_dynamic_token_provider_and_auth_paths():
    token = {"value": "first-token"}
    session = Session([
        Response({"access_token": "new-token", "user": {"role": "ADMIN"}}),
        Response({"email": "admin@example.test"}),
        Response({"status": "logged_out"}),
    ])
    api = RFNIDSClient(
        "http://api.test", session=session, token_provider=lambda: token["value"]
    )
    api.login("admin@example.test", "secret")
    token["value"] = "second-token"
    api.current_user()
    api.logout()
    assert session.calls[0][2]["json"] == {
        "email": "admin@example.test", "password": "secret"
    }
    assert session.calls[1][2]["headers"] == {
        "Authorization": "Bearer second-token"
    }


def test_phase_3_read_clients_map_paths_and_filters():
    session = Session([
        Response({"model_version": "rf-v1.0"}), Response([{"id": 1}]),
        Response([{"experiment_code": "EXPERIMENT_C"}]), Response([{"metric_key": "OVERALL"}]),
        Response([{"evidence_role": "FINAL_REPORT"}]),
    ])
    api = RFNIDSClient("http://api.test", session=session)
    assert api.active_model()["model_version"] == "rf-v1.0"
    assert api.datasets() == [{"id": 1}]
    assert api.experiments()[0]["experiment_code"] == "EXPERIMENT_C"
    assert api.experiment_evaluation(7)[0]["metric_key"] == "OVERALL"
    assert api.evidence_sources(owner_type="EXPERIMENT", owner_key="EXPERIMENT_C")
    assert [call[1] for call in session.calls] == [
        "http://api.test/api/models/active", "http://api.test/api/datasets",
        "http://api.test/api/experiments", "http://api.test/api/experiments/7/evaluation",
        "http://api.test/api/evidence-sources",
    ]
    assert session.calls[-1][2]["params"] == {
        "owner_type": "EXPERIMENT", "owner_key": "EXPERIMENT_C"
    }


def test_phase_4_monitoring_clients_preserve_zero_offset_and_filters():
    session = Session([Response({"total_flows": 0}), Response([])])
    api = RFNIDSClient("http://api.test", session=session)
    assert api.monitoring_summary() == {"total_flows": 0}
    assert api.traffic_flows(limit=20, offset=0, protocol="TCP", source_ip=None) == []
    assert session.calls[0][1] == "http://api.test/api/monitoring/summary"
    assert session.calls[1][1] == "http://api.test/api/traffic-flows"
    assert session.calls[1][2]["params"] == {"limit": 20, "offset": 0, "protocol": "TCP"}


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


def test_alert_client_maps_phase_5_server_side_filters():
    session = Session([Response([])])
    api = RFNIDSClient("http://api.test", session=session)
    assert api.alerts(
        limit=20,
        offset=0,
        predicted_label="DDoS",
        severity="HIGH",
        status="ACTIVE",
        source_ip="192.0.2.1",
        destination_ip="198.51.100.1",
    ) == []
    assert session.calls[0][2]["params"] == {
        "limit": 20,
        "offset": 0,
        "predicted_label": "DDoS",
        "severity": "HIGH",
        "status": "ACTIVE",
        "source_ip": "192.0.2.1",
        "destination_ip": "198.51.100.1",
    }


def test_phase_7_download_clients_preserve_bytes_names_auth_and_filters():
    response = Response(
        content=b"prediction_id\n",
        headers={"Content-Disposition": 'attachment; filename="rf_nids_predictions_2026-09-02.csv"',
                 "Content-Type": "text/csv; charset=utf-8"},
    )
    session = Session([response])
    api = RFNIDSClient("http://api.test", session=session, access_token="admin-token")
    download = api.export_predictions(
        format="csv", predicted_label="DDoS", source_ip="192.0.2.1", destination_ip=None
    )
    assert download.content == b"prediction_id\n"
    assert download.filename == "rf_nids_predictions_2026-09-02.csv"
    assert download.content_type.startswith("text/csv")
    assert session.calls[0][2]["headers"] == {"Authorization": "Bearer admin-token"}
    assert session.calls[0][2]["params"] == {
        "format": "csv", "predicted_label": "DDoS", "source_ip": "192.0.2.1"
    }
