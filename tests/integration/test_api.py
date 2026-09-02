from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from src.api import main as api_main
from src.api.main import create_app
from src.api.models import Alert, Prediction, TrafficFlow
from src.api.auth import hash_password
from src.api.models import Dataset, EvaluationResult, Experiment, User
from src.api.schemas import PredictionRequest
from src.api.service import persist_predictions
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
        else:
            label, confidence = "DDoS", 0.60
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
        alert_confidence_threshold=0.70,
        max_batch_size=2,
        max_page_size=10,
    )
    app = create_app(settings, engine_factory=FakeInferenceEngine, create_tables=True)
    with TestClient(app) as test_client:
        yield test_client, app


def payload(value, **metadata):
    return {
        "features": {"feature_a": value, "feature_b": 1},
        "metadata": metadata or None,
    }


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
    high = next(item for item in alerts if item["severity"] == "HIGH")
    acknowledged = http.patch(f"/api/alerts/{high['id']}/acknowledge")
    assert acknowledged.json()["status"] == "ACKNOWLEDGED"
    assert acknowledged.json()["acknowledged_at"] is not None

    summary = http.get("/api/dashboard/summary").json()
    assert summary["total_flows"] == 4
    assert summary["total_normal"] == 1
    assert summary["total_ddos"] == 2
    assert summary["total_portscan"] == 1
    assert summary["active_alerts"] == 1
    assert summary["active_high_alerts"] == 0
    assert summary["active_medium_alerts"] == 1
    assert summary["acknowledged_alerts"] == 1
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
    assert http.patch("/api/alerts/999/acknowledge").status_code == 404


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
                threshold=0.70,
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

    assert http.get("/api/auth/me").status_code == 401
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
        db.add(evaluation)
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
