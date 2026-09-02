from pathlib import Path
import csv
from io import StringIO

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from src.api import main as api_main
from src.api.main import create_app
from src.api.models import Alert, Prediction, TrafficFlow
from src.api.auth import hash_password
from src.api.models import Dataset, EvidenceSource, EvaluationResult, Experiment, User
from src.api.schemas import PredictionRequest
from src.api.service import persist_predictions
from src.application.evidence_sync import synchronize_evidence
from src.common.config import Settings
from src.inference import FeatureValidationError


class FakeInferenceEngine:
    def __init__(self, model_path, metadata_path):
        self.metadata = {
            "model_name": "Test RF",
            "model_version": "test-v1",
            "feature_names": ["feature_a", "feature_b"],
            "class_names": ["Normal", "DDoS", "PortScan"],
            "created_at_utc": "2026-08-20T00:00:00+00:00",
            "metrics": {
                "accuracy": 0.99,
                "macro_f1": 0.98,
                "classification_report": {
                    "DDoS": {"recall": 0.97},
                    "PortScan": {"recall": 0.96},
                },
            },
        }

    def predict_one(self, features):
        missing = [name for name in self.metadata["feature_names"] if name not in features]
        if missing:
            raise FeatureValidationError(f"Missing required features: {missing}")
        try:
            value = float(features["feature_a"])
            float(features["feature_b"])
        except (TypeError, ValueError) as exc:
            raise FeatureValidationError("Feature must be numeric") from exc
        if value < 10:
            label, confidence = "Normal", 0.99
        elif value < 20:
            label, confidence = "DDoS", 0.95
        elif value < 30:
            label, confidence = "PortScan", 0.90
        elif value < 40:
            label, confidence = "DDoS", 0.60
        else:
            label, confidence = "PortScan", 0.40
        remaining = (1 - confidence) / 2
        probabilities = {name: remaining for name in self.metadata["class_names"]}
        probabilities[label] = confidence
        return {
            "prediction": label,
            "confidence": confidence,
            "probabilities": probabilities,
            "model_version": "test-v1",
            "ignored_features": [],
        }

    def predict_batch(self, rows):
        if not rows:
            raise FeatureValidationError("Prediction batch must not be empty")
        return [self.predict_one(row) for row in rows]


@pytest.fixture
def client(tmp_path: Path):
    settings = Settings(
        app_env="test",
        log_level="WARNING",
        leakage_columns_config=tmp_path / "unused.json",
        database_url=f"sqlite:///{tmp_path / 'api.db'}",
        model_path=tmp_path / "unused.joblib",
        model_metadata_path=tmp_path / "unused.json",
        max_batch_size=2,
        max_page_size=10,
    )
    app = create_app(settings, engine_factory=FakeInferenceEngine, create_tables=True)
    with TestClient(app) as test_client:
        with app.state.session_factory() as db:
            db.add(
                User(
                    name="Default Test Admin",
                    email="default-admin@example.test",
                    password_hash=hash_password("default-test-password"),
                    role="ADMIN",
                    is_active=True,
                )
            )
            db.commit()
        login = test_client.post(
            "/api/auth/login",
            json={
                "email": "default-admin@example.test",
                "password": "default-test-password",
            },
        )
        test_client.headers.update(
            {"Authorization": f"Bearer {login.json()['access_token']}"}
        )
        yield test_client, app


def payload(value, **metadata):
    return {
        "features": {"feature_a": value, "feature_b": 1},
        "metadata": metadata or None,
    }


def authenticated_admin(http, app, *, email="admin@example.test"):
    with app.state.session_factory() as db:
        admin = User(
            name="Thesis Admin",
            email=email,
            password_hash=hash_password("correct-horse-battery"),
            role="ADMIN",
            is_active=True,
        )
        db.add(admin)
        db.commit()
        user_id = admin.id
    login = http.post(
        "/api/auth/login",
        json={"email": email, "password": "correct-horse-battery"},
    )
    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}, user_id


def test_health_and_model(client):
    http, _ = client
    assert http.get("/health").json() == {
        "status": "healthy",
        "database": "connected",
        "model_loaded": True,
    }
    model = http.get("/api/model")
    assert model.status_code == 200
    assert model.json()["feature_count"] == 2
    assert model.json()["ddos_recall"] == 0.97
    assert "model_path" not in model.json()


def test_application_endpoints_require_admin_but_runtime_inference_stays_local(client):
    http, _ = client
    no_auth = {"Authorization": ""}
    assert http.get("/health", headers=no_auth).status_code == 200
    assert http.post("/api/predict", json=payload(1), headers=no_auth).status_code == 201
    assert http.get("/api/model", headers=no_auth).status_code == 401
    assert http.get("/api/dashboard/summary", headers=no_auth).status_code == 401
    assert http.get("/api/alerts", headers=no_auth).status_code == 401
    assert http.get("/api/auth/me", headers={"Authorization": "Bearer unknown"}).status_code == 401


def test_validation_and_batch_limit(client):
    http, _ = client
    assert http.post("/api/predict", json={"features": {"feature_a": 1}}).status_code == 422
    invalid = payload("bad")
    assert http.post("/api/predict", json=invalid).status_code == 422
    assert http.post("/api/predict/batch", json={"flows": []}).status_code == 422
    too_large = {"flows": [payload(1), payload(2), payload(3)]}
    assert http.post("/api/predict/batch", json=too_large).status_code == 413


def test_prediction_alert_rules_and_persistence(client):
    http, app = client
    normal = http.post(
        "/api/predict", json=payload(1, source_ip="10.0.0.1", destination_ip="10.0.0.2")
    )
    assert normal.status_code == 201
    ddos = http.post("/api/predict", json=payload(10)).json()
    portscan = http.post("/api/predict", json=payload(20)).json()
    low_confidence = http.post("/api/predict", json=payload(30)).json()
    assert ddos["prediction"] == "DDoS"
    assert portscan["prediction"] == "PortScan"
    assert low_confidence["prediction"] == "DDoS"

    with app.state.session_factory() as db:
        assert db.scalar(select(func.count(TrafficFlow.id))) == 4
        assert db.scalar(select(func.count(Prediction.id))) == 4
        alerts = db.scalars(select(Alert).order_by(Alert.id)).all()
        assert [(row.severity, row.status) for row in alerts] == [
            ("HIGH", "ACTIVE"),
            ("MEDIUM", "ACTIVE"),
            ("HIGH", "ACTIVE"),
        ]

    listed = http.get("/api/predictions", params={"source_ip": "10.0.0.1"}).json()
    assert len(listed) == 1
    assert http.get(f"/api/predictions/{normal.json()['prediction_id']}").status_code == 200
    detail = http.get(f"/api/predictions/{normal.json()['prediction_id']}").json()
    assert detail["source_ip"] == "10.0.0.1"
    assert detail["model_version"] == "test-v1"
    alerts_response = http.get("/api/alerts")
    assert alerts_response.status_code == 200, alerts_response.text
    alerts = alerts_response.json()
    summary = http.get("/api/dashboard/summary").json()
    assert summary["total_flows"] == 4
    assert summary["total_normal"] == 1
    assert summary["total_ddos"] == 2
    assert summary["total_portscan"] == 1
    assert summary["active_alerts"] == 3
    assert summary["active_high_alerts"] == 2
    assert summary["active_medium_alerts"] == 1
    assert summary["acknowledged_alerts"] == 0
    assert summary["latest_prediction_timestamp"] is not None
    timeline = http.get("/api/dashboard/timeline", params={"minutes": 60})
    assert timeline.status_code == 200
    assert sum(point["normal"] for point in timeline.json()) == 1


def test_batch_is_persisted_and_not_found_responses(client):
    http, _ = client
    response = http.post(
        "/api/predict/batch", json={"flows": [payload(1), payload(10)]}
    )
    assert response.status_code == 201
    assert len(response.json()["predictions"]) == 2
    assert http.get("/api/predictions/999").status_code == 404
    assert http.get("/api/alerts/999").status_code == 404
    assert http.patch(
        "/api/alerts/999/acknowledge", headers={"Authorization": ""}
    ).status_code == 401


def test_invalid_prediction_and_alert_filters_are_rejected(client):
    http, _ = client
    assert http.get("/api/predictions", params={"predicted_label": "Malware"}).status_code == 422
    assert http.get("/api/alerts", params={"severity": "LOW"}).status_code == 422
    assert http.get("/api/alerts", params={"status": "CLOSED"}).status_code == 422


def test_prediction_batch_rolls_back_atomically_when_commit_fails(client, monkeypatch):
    _, app = client
    output = {
        "prediction": "Normal",
        "confidence": 0.99,
        "probabilities": {"Normal": 0.99, "DDoS": 0.005, "PortScan": 0.005},
        "model_version": "test-v1",
    }
    with app.state.session_factory() as db:
        rollback_called = False
        original_rollback = db.rollback

        def fail_commit():
            raise SQLAlchemyError("simulated database failure containing sensitive SQL")

        def track_rollback():
            nonlocal rollback_called
            rollback_called = True
            original_rollback()

        monkeypatch.setattr(db, "commit", fail_commit)
        monkeypatch.setattr(db, "rollback", track_rollback)
        with pytest.raises(SQLAlchemyError):
            persist_predictions(
                db,
                [PredictionRequest(features={"feature_a": 1, "feature_b": 1})] * 2,
                [output, output],
                app.state.model_record.id,
            )
        assert rollback_called

    with app.state.session_factory() as verification_db:
        assert verification_db.scalar(select(func.count(TrafficFlow.id))) == 0
        assert verification_db.scalar(select(func.count(Prediction.id))) == 0


def test_database_error_is_logged_but_response_is_sanitized(client, monkeypatch, caplog):
    http, _ = client
    sensitive_message = "password=secret SELECT raw_features FROM traffic_flows"

    def fail_persistence(*args, **kwargs):
        raise SQLAlchemyError(sensitive_message)

    monkeypatch.setattr(api_main, "persist_predictions", fail_persistence)
    response = http.post("/api/predict", json=payload(1))

    assert response.status_code == 503
    assert response.json() == {"detail": "Database unavailable"}
    assert sensitive_message not in response.text
    assert sensitive_message in caplog.text


def test_authentication_login_me_logout_and_failures(client):
    http, app = client
    with app.state.session_factory() as db:
        admin = User(
            name="Thesis Admin",
            email="admin@example.test",
            password_hash=hash_password("correct-horse-battery"),
            role="ADMIN",
            is_active=True,
        )
        db.add(admin)
        db.commit()

    assert http.get("/api/auth/me", headers={"Authorization": ""}).status_code == 401
    assert http.post(
        "/api/auth/login",
        json={"email": "admin@example.test", "password": "wrong-password"},
    ).status_code == 401
    login = http.post(
        "/api/auth/login",
        json={"email": " ADMIN@example.test ", "password": "correct-horse-battery"},
    )
    assert login.status_code == 200
    body = login.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["role"] == "ADMIN"
    assert "password" not in body["user"]
    assert "password_hash" not in body["user"]
    headers = {"Authorization": f"Bearer {body['access_token']}"}
    assert http.get("/api/auth/me", headers=headers).json()["email"] == "admin@example.test"
    assert http.post("/api/auth/logout", headers=headers).json() == {"status": "logged_out"}
    assert http.get("/api/auth/me", headers=headers).status_code == 401


def test_inactive_user_cannot_login(client):
    http, app = client
    with app.state.session_factory() as db:
        db.add(
            User(
                name="Inactive Admin",
                email="inactive@example.test",
                password_hash=hash_password("correct-horse-battery"),
                role="ADMIN",
                is_active=False,
            )
        )
        db.commit()
    response = http.post(
        "/api/auth/login",
        json={"email": "inactive@example.test", "password": "correct-horse-battery"},
    )
    assert response.status_code == 403


def test_phase_7_dataset_and_experiment_exports_preserve_evidence(client):
    http, app = client
    with app.state.session_factory() as db:
        synchronize_evidence(db, root=Path(__file__).resolve().parents[2])

    assert http.get("/api/export/dataset", headers={"Authorization": ""}).status_code == 401
    dataset_response = http.get("/api/export/dataset")
    assert dataset_response.headers["content-type"].startswith("application/json")
    assert "rf_nids_dataset.json" in dataset_response.headers["content-disposition"]
    dataset = dataset_response.json()["datasets"][0]
    assert dataset["total_rows"] == 2_830_743
    assert dataset["total_features"] == 78
    assert dataset["source_sha256"] == "f3eb36a4949a7fc157d731b6a20cf732c718d8cf1ce9a75b67edcd43df3c0543"
    assert "password" not in dataset_response.text.lower()
    assert "token" not in dataset_response.text.lower()

    experiments = {row["experiment_code"]: row for row in http.get("/api/experiments").json()}
    for code in ("EXPERIMENT_A", "EXPERIMENT_B", "EXPERIMENT_C"):
        response = http.get(f"/api/export/experiments/{experiments[code]['id']}")
        assert response.status_code == 200
        assert response.json()["experiment"]["experiment_code"] == code
        assert response.json()["provenance"]

    experiment_c = experiments["EXPERIMENT_C"]
    exported = http.get(f"/api/export/experiments/{experiment_c['id']}").json()
    by_key = {row["metric_key"]: row for row in exported["evaluations"]}
    assert by_key["OVERALL"]["accuracy"] == 0.005404447594577833
    assert by_key["OVERALL"]["macro_precision"] is None
    assert by_key["OVERALL"]["macro_recall"] is None
    assert by_key["OVERALL"]["macro_f1"] is None
    assert by_key["CLASS:DDoS"]["recall"] == 0.0
    assert by_key["CLASS:PortScan"]["recall"] == 0.0

    metrics = http.get(f"/api/export/experiments/{experiment_c['id']}", params={"format": "csv"})
    assert metrics.headers["content-type"].startswith("text/csv")
    assert "_metrics.csv" in metrics.headers["content-disposition"]
    csv_rows = list(csv.DictReader(StringIO(metrics.text)))
    assert next(row for row in csv_rows if row["metric_key"] == "OVERALL")["macro_f1"] == ""

    matrix = http.get(f"/api/export/experiments/{experiment_c['id']}/confusion-matrix")
    matrix_rows = list(csv.DictReader(StringIO(matrix.text)))
    assert matrix_rows == [
        {"actual_class": "Normal", "predicted_Normal": "61", "predicted_DDoS": "0", "predicted_PortScan": "0"},
        {"actual_class": "DDoS", "predicted_Normal": "10226", "predicted_DDoS": "0", "predicted_PortScan": "0"},
        {"actual_class": "PortScan", "predicted_Normal": "1000", "predicted_DDoS": "0", "predicted_PortScan": "0"},
    ]
    assert http.get("/api/export/experiments/999").status_code == 404
    assert http.get("/api/export/experiments/999/confusion-matrix").status_code == 404


def test_phase_7_prediction_and_alert_exports_filters_order_and_empty_state(client):
    http, _ = client
    for value, source, destination in (
        (10, "192.0.2.2", "198.51.100.1"),
        (20, "192.0.2.1", "198.51.100.2"),
        (1, "192.0.2.3", "198.51.100.3"),
    ):
        assert http.post("/api/predict", json=payload(
            value, source_ip=source, destination_ip=destination, protocol="TCP"
        )).status_code == 201

    for path in ("/api/export/predictions", "/api/export/alerts"):
        assert http.get(path, headers={"Authorization": ""}).status_code == 401

    predictions = http.get("/api/export/predictions", params={
        "format": "json", "predicted_label": "DDoS", "source_ip": "192.0.2.2", "protocol": "TCP"
    }).json()
    assert predictions["metadata"]["filters"] == {
        "predicted_label": "DDoS", "protocol": "TCP", "source_ip": "192.0.2.2"
    }
    assert [row["prediction_id"] for row in predictions["predictions"]] == [1]
    assert "flow_features" not in predictions["predictions"][0]

    empty_predictions = http.get("/api/export/predictions", params={"source_ip": "203.0.113.99"})
    assert list(csv.DictReader(StringIO(empty_predictions.text))) == []
    assert "prediction_id" in empty_predictions.text

    alert_list = http.get("/api/alerts", params={"predicted_label": "PortScan"}).json()
    alert_id = alert_list[0]["id"]
    http.patch(f"/api/alerts/{alert_id}/acknowledge")
    alerts = http.get("/api/export/alerts", params={
        "format": "json", "predicted_label": "PortScan", "severity": "MEDIUM",
        "status": "ACKNOWLEDGED", "destination_ip": "198.51.100.2",
    }).json()
    assert [row["alert_id"] for row in alerts["alerts"]] == [alert_id]
    assert alerts["alerts"][0]["acknowledged_by_name"] == "Default Test Admin"
    assert alerts["alerts"][0]["acknowledged_by_email"] == "default-admin@example.test"
    assert "password_hash" not in str(alerts)
    assert "access_token" not in str(alerts)

    all_predictions = http.get("/api/export/predictions", params={"format": "json"}).json()["predictions"]
    assert [row["prediction_id"] for row in all_predictions] == sorted(row["prediction_id"] for row in all_predictions)
    empty_alerts = http.get("/api/export/alerts", params={"source_ip": "203.0.113.99"})
    assert list(csv.DictReader(StringIO(empty_alerts.text))) == []


def test_evidence_read_endpoints(client):
    http, app = client
    with app.state.session_factory() as db:
        dataset = Dataset(
            name="Presentation dataset",
            source_path="reports/metrics/data_understanding.json",
            source_sha256="a" * 64,
            total_rows=None,
            total_features=78,
            label_column="label",
            class_distribution=None,
        )
        experiment = Experiment(
            experiment_code="EXPERIMENT_C",
            experiment_name="External validation",
            experiment_type="EXTERNAL_VALIDATION",
            dataset=dataset,
            status="COMPLETED",
            source_path="reports/metrics/experiment_c_v3_final.json",
            source_sha256="b" * 64,
        )
        evaluation = EvaluationResult(
            experiment=experiment,
            metric_key="OVERALL",
            accuracy=0.005404447594577833,
            macro_f1=None,
            source_path="reports/metrics/experiment_c_v3_final.json",
            source_sha256="b" * 64,
        )
        source = EvidenceSource(
            owner_type="EXPERIMENT", owner_key="EXPERIMENT_C", evidence_role="FINAL_REPORT",
            source_path="reports/metrics/experiment_c_v3_final.json", source_sha256="b" * 64,
        )
        db.add_all([evaluation, source])
        db.commit()
        dataset_id, experiment_id, evaluation_id = dataset.id, experiment.id, evaluation.id

    datasets = http.get("/api/datasets")
    assert datasets.status_code == 200
    assert datasets.json()[0]["total_rows"] is None
    assert http.get(f"/api/datasets/{dataset_id}").json()["total_features"] == 78
    assert http.get("/api/datasets/999").status_code == 404

    experiments = http.get("/api/experiments")
    assert experiments.status_code == 200
    assert experiments.json()[0]["experiment_code"] == "EXPERIMENT_C"
    assert http.get(f"/api/experiments/{experiment_id}").status_code == 200
    evaluations = http.get(f"/api/experiments/{experiment_id}/evaluation").json()
    assert evaluations[0]["accuracy"] == 0.005404447594577833
    assert evaluations[0]["macro_f1"] is None
    assert http.get("/api/experiments/999/evaluation").status_code == 404
    assert http.get("/api/evaluations").status_code == 200
    assert http.get(f"/api/evaluations/{evaluation_id}").status_code == 200
    assert http.get("/api/evaluations/999").status_code == 404
    provenance = http.get("/api/evidence-sources", params={"owner_key": "EXPERIMENT_C"})
    assert provenance.status_code == 200
    assert provenance.json()[0]["source_sha256"] == "b" * 64


def test_active_model_presentation_endpoint(client):
    http, _ = client
    response = http.get("/api/models/active")
    assert response.status_code == 200
    body = response.json()
    assert body["model_name"] == "Test RF"
    assert body["algorithm"] == "Random Forest"
    assert body["feature_count"] == 2
    assert body["is_active"] is True
    assert body["parameters"] is None


def test_monitoring_empty_state_and_unpredicted_legacy_flow(client):
    http, app = client
    assert http.get("/api/traffic-flows").json() == []
    assert http.get("/api/monitoring/summary").json() == {
        "total_flows": 0,
        "total_normal": 0,
        "total_ddos": 0,
        "total_portscan": 0,
        "total_alerts": 0,
        "active_alerts": 0,
        "latest_detection_timestamp": None,
        "active_model": "test-v1",
    }
    with app.state.session_factory() as db:
        db.add(TrafficFlow(raw_features={}, source_ip=None, protocol=None))
        db.commit()

    rows = http.get("/api/traffic-flows").json()
    assert len(rows) == 1
    assert rows[0]["prediction_id"] is None
    assert rows[0]["predicted_label"] is None
    assert rows[0]["confidence_score"] is None
    assert http.get("/api/monitoring/summary").json()["total_flows"] == 1


def test_monitoring_server_side_filters_and_pagination(client):
    http, _ = client
    records = [
        payload(1, source_ip="10.0.0.1", destination_ip="10.0.1.1", protocol="TCP"),
        payload(10, source_ip="10.0.0.2", destination_ip="10.0.1.2", protocol="UDP"),
        payload(20, source_ip="10.0.0.3", destination_ip="10.0.1.3", protocol="TCP"),
    ]
    for record in records:
        assert http.post("/api/predict", json=record).status_code == 201

    first = http.get("/api/traffic-flows", params={"limit": 1, "offset": 0}).json()
    second = http.get("/api/traffic-flows", params={"limit": 1, "offset": 1}).json()
    assert len(first) == len(second) == 1
    assert first[0]["flow_id"] != second[0]["flow_id"]
    assert http.get(
        "/api/traffic-flows", params={"predicted_label": "DDoS"}
    ).json()[0]["source_ip"] == "10.0.0.2"
    assert len(http.get("/api/traffic-flows", params={"protocol": "TCP"}).json()) == 2
    assert http.get(
        "/api/traffic-flows", params={"source_ip": "10.0.0.3"}
    ).json()[0]["predicted_label"] == "PortScan"
    assert http.get(
        "/api/traffic-flows", params={"destination_ip": "10.0.1.1"}
    ).json()[0]["predicted_label"] == "Normal"
    summary = http.get("/api/monitoring/summary").json()
    assert summary["total_flows"] == 3
    assert summary["total_alerts"] == 2
    assert summary["active_alerts"] == 2
    assert summary["latest_detection_timestamp"] is not None


def test_prediction_pagination_filters_and_enriched_detail(client):
    http, _ = client
    normal = http.post(
        "/api/predict",
        json=payload(
            1,
            source_ip="192.0.2.1",
            source_port=1234,
            destination_ip="198.51.100.1",
            destination_port=443,
            protocol="TCP",
            capture_session_id="runtime-session",
            capture_interface="eth0",
        ),
    ).json()
    attack = http.post("/api/predict", json=payload(10, protocol="UDP")).json()

    page_one = http.get("/api/predictions", params={"limit": 1, "offset": 0}).json()
    page_two = http.get("/api/predictions", params={"limit": 1, "offset": 1}).json()
    assert page_one[0]["id"] != page_two[0]["id"]
    assert len(http.get(
        "/api/predictions", params={"predicted_label": "Normal"}
    ).json()) == 1
    assert http.get("/api/predictions", params={"protocol": "TCP"}).json()[0]["id"] == normal["prediction_id"]

    detail = http.get(f"/api/predictions/{normal['prediction_id']}").json()
    assert detail["model_name"] == "Test RF"
    assert detail["model_version"] == "test-v1"
    assert detail["source_type"] == "RUNTIME"
    assert detail["experiment_code"] is None
    assert detail["external_key"] is None
    assert detail["flow_features"] == {"feature_a": 1, "feature_b": 1}
    assert detail["class_probabilities"]["Normal"] == 0.99
    assert detail["alert_id"] is None
    attack_detail = http.get(f"/api/predictions/{attack['prediction_id']}").json()
    assert attack_detail["alert_id"] is not None
    assert attack_detail["alert_severity"] == "HIGH"
    assert attack_detail["alert_status"] == "ACTIVE"


def test_runtime_views_exclude_imported_scientific_prediction_context(client):
    http, app = client
    assert http.post("/api/predict", json=payload(1)).status_code == 201
    with app.state.session_factory() as db:
        imported = Prediction(
            traffic_flow=TrafficFlow(raw_features={"evidence": 1}),
            model_id=app.state.model_record.id,
            source_type="EXPERIMENT_IMPORT",
            external_key="experiment-c-row-1",
            predicted_label="Normal",
            confidence_score=1.0,
            class_probabilities={"Normal": 1.0},
        )
        db.add(imported)
        db.commit()
        imported_id = imported.id

    assert [row["id"] for row in http.get("/api/predictions").json()] != [imported_id]
    assert len(http.get("/api/predictions").json()) == 1
    assert len(http.get("/api/traffic-flows").json()) == 1
    assert http.get("/api/monitoring/summary").json()["total_flows"] == 1
    assert http.get("/api/dashboard/summary").json()["total_flows"] == 1
    # Direct detail remains available for provenance-aware read-only inspection.
    detail = http.get(f"/api/predictions/{imported_id}").json()
    assert detail["source_type"] == "EXPERIMENT_IMPORT"


def test_low_confidence_attacks_always_create_mapped_alerts(client):
    http, app = client
    low_ddos = http.post("/api/predict", json=payload(30)).json()
    low_portscan = http.post("/api/predict", json=payload(40)).json()
    assert low_ddos["confidence"] == 0.60
    assert low_portscan["confidence"] == 0.40
    with app.state.session_factory() as db:
        alerts = db.scalars(select(Alert).order_by(Alert.id)).all()
        assert [(row.prediction_id, row.severity, row.status) for row in alerts] == [
            (low_ddos["prediction_id"], "HIGH", "ACTIVE"),
            (low_portscan["prediction_id"], "MEDIUM", "ACTIVE"),
        ]


def test_database_constraint_prevents_duplicate_alert_for_prediction(client):
    http, app = client
    prediction_id = http.post("/api/predict", json=payload(10)).json()["prediction_id"]
    with app.state.session_factory() as db:
        db.add(
            Alert(
                prediction_id=prediction_id,
                severity="HIGH",
                title="Duplicate",
                description="Must be rejected by the existing unique constraint.",
                status="ACTIVE",
            )
        )
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
        assert db.scalar(
            select(func.count(Alert.id)).where(Alert.prediction_id == prediction_id)
        ) == 1


def test_alert_filters_and_joined_detail(client):
    http, _ = client
    http.post(
        "/api/predict",
        json=payload(
            10,
            source_ip="192.0.2.10",
            source_port=12345,
            destination_ip="198.51.100.20",
            destination_port=443,
            protocol="TCP",
            capture_time="2026-09-02T04:00:00Z",
        ),
    )
    http.post(
        "/api/predict",
        json=payload(
            20,
            source_ip="192.0.2.30",
            destination_ip="198.51.100.40",
            protocol="UDP",
        ),
    )
    assert len(http.get("/api/alerts", params={"predicted_label": "DDoS"}).json()) == 1
    assert len(http.get("/api/alerts", params={"severity": "MEDIUM"}).json()) == 1
    assert len(http.get("/api/alerts", params={"status": "ACTIVE"}).json()) == 2
    assert len(http.get("/api/alerts", params={"source_ip": "192.0.2.10"}).json()) == 1
    filtered = http.get(
        "/api/alerts", params={"destination_ip": "198.51.100.20"}
    ).json()
    detail = http.get(f"/api/alerts/{filtered[0]['id']}").json()
    assert detail["predicted_label"] == "DDoS"
    assert detail["class_probabilities"]["DDoS"] == 0.95
    assert detail["source_port"] == 12345
    assert detail["destination_port"] == 443
    assert detail["protocol"] == "TCP"
    assert detail["capture_time"].startswith("2026-09-02T04:00:00")
    assert detail["model_name"] == "Test RF"
    assert detail["model_version"] == "test-v1"
    assert detail["source_type"] == "RUNTIME"


def test_acknowledge_requires_admin_and_is_repeat_safe(client):
    http, app = client
    http.post("/api/predict", json=payload(10))
    alert_id = http.get("/api/alerts").json()[0]["id"]
    assert http.patch(
        f"/api/alerts/{alert_id}/acknowledge", headers={"Authorization": ""}
    ).status_code == 401
    headers, user_id = authenticated_admin(http, app)
    first = http.patch(f"/api/alerts/{alert_id}/acknowledge", headers=headers)
    assert first.status_code == 200
    body = first.json()
    assert body["status"] == "ACKNOWLEDGED"
    assert body["acknowledged_at"] is not None
    assert body["acknowledged_by_user_id"] == user_id
    assert body["acknowledged_by_name"] == "Thesis Admin"
    timestamp = body["acknowledged_at"]
    second = http.patch(f"/api/alerts/{alert_id}/acknowledge", headers=headers).json()
    assert second["acknowledged_at"] == timestamp
    assert second["acknowledged_by_user_id"] == user_id


def test_legacy_acknowledged_alert_without_user_remains_readable(client):
    http, app = client
    http.post("/api/predict", json=payload(20))
    with app.state.session_factory() as db:
        row = db.scalar(select(Alert))
        row.status = "ACKNOWLEDGED"
        row.acknowledged_at = row.created_at
        row.acknowledged_by_user_id = None
        db.commit()
        alert_id = row.id
    detail = http.get(f"/api/alerts/{alert_id}").json()
    assert detail["status"] == "ACKNOWLEDGED"
    assert detail["acknowledged_at"] is not None
    assert detail["acknowledged_by_user_id"] is None
    assert detail["acknowledged_by_name"] is None
