from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from scripts.bootstrap_admin import create_admin
from fastapi import HTTPException

from src.api.auth import hash_password, require_admin, verify_password
from src.api.database import Base
from src.api.models import (
    Alert,
    Dataset,
    EvaluationResult,
    Experiment,
    ModelRecord,
    Prediction,
    TrafficFlow,
    User,
)


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'foundation.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def test_password_hashing_and_admin_bootstrap_duplicate_email(db):
    encoded = hash_password("a-secure-local-password")
    assert encoded.startswith("scrypt$")
    assert "a-secure-local-password" not in encoded
    assert verify_password("a-secure-local-password", encoded)
    assert not verify_password("incorrect-password", encoded)

    user = create_admin(
        db,
        name="Administrator",
        email=" Admin@Example.Test ",
        password="a-secure-local-password",
    )
    assert user.email == "admin@example.test"
    assert user.role == "ADMIN"
    assert user.password_hash != "a-secure-local-password"
    with pytest.raises(ValueError, match="already exists"):
        create_admin(
            db,
            name="Duplicate",
            email="ADMIN@example.test",
            password="another-secure-password",
        )


def test_database_unique_email_constraint(db):
    password = hash_password("a-secure-local-password")
    db.add_all(
        [
            User(name="One", email="same@example.test", password_hash=password, role="ADMIN"),
            User(name="Two", email="same@example.test", password_hash=password, role="ADMIN"),
        ]
    )
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_admin_dependency_rejects_other_roles():
    user = User(
        name="Viewer",
        email="viewer@example.test",
        password_hash=hash_password("a-secure-local-password"),
        role="VIEWER",
    )
    with pytest.raises(HTTPException) as raised:
        require_admin(user)
    assert raised.value.status_code == 403


def test_dataset_experiment_evaluation_and_model_relationships(db):
    admin = User(
        name="Administrator",
        email="admin@example.test",
        password_hash=hash_password("a-secure-local-password"),
        role="ADMIN",
    )
    dataset = Dataset(name="Verified dataset metadata", created_by_user=admin)
    experiment = Experiment(
        experiment_code="EXPERIMENT_A",
        experiment_name="Experiment A",
        experiment_type="STRATIFIED_RANDOM_SPLIT",
        dataset=dataset,
        description="Relationship test only; no evidence imported.",
        status="DEFINED",
    )
    evaluation = EvaluationResult(
        experiment=experiment,
        class_name=None,
        accuracy=None,
        confusion_matrix=None,
        notes="NULL metrics remain valid.",
    )
    model = ModelRecord(
        model_name="Relationship test model",
        model_version="relationship-v1",
        algorithm="Random Forest",
        experiment=experiment,
        is_active=False,
    )
    db.add_all([evaluation, model])
    db.commit()

    assert dataset in admin.datasets
    assert experiment in dataset.experiments
    assert evaluation in experiment.evaluation_results
    assert model in experiment.models
    assert model.experiment is experiment
    assert evaluation.accuracy is None


def _prediction_graph(db, *, source_type=None, external_key=None):
    model = db.scalar(select(ModelRecord).where(ModelRecord.model_version == "runtime-v1"))
    if model is None:
        model = ModelRecord(
            model_name="Runtime model",
            model_version="runtime-v1",
            algorithm="Random Forest",
            is_active=True,
        )
        db.add(model)
        db.flush()
    flow = TrafficFlow(raw_features={"feature": 1})
    prediction = Prediction(
        traffic_flow=flow,
        model=model,
        predicted_label="Normal",
        confidence_score=1.0,
        class_probabilities={"Normal": 1.0, "DDoS": 0.0, "PortScan": 0.0},
        source_type=source_type,
        external_key=external_key,
    )
    db.add(prediction)
    return prediction


def test_prediction_provenance_idempotency_and_runtime_null_compatibility(db):
    _prediction_graph(db)
    _prediction_graph(db)
    db.commit()
    assert db.scalar(select(Prediction).where(Prediction.source_type.is_(None))) is not None

    _prediction_graph(db, source_type="EXPERIMENT_EVIDENCE", external_key="C:row:1")
    db.commit()
    _prediction_graph(db, source_type="EXPERIMENT_EVIDENCE", external_key="C:row:1")
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_alert_acknowledging_user_relationship_is_nullable(db):
    attack = _prediction_graph(db)
    attack.predicted_label = "DDoS"
    alert = Alert(
        prediction=attack,
        severity="HIGH",
        title="Relationship test",
        description="No alert generation behavior is changed by this test.",
        status="ACTIVE",
    )
    db.add(alert)
    db.commit()
    assert alert.acknowledged_by_user is None

    admin = User(
        name="Administrator",
        email="ack@example.test",
        password_hash=hash_password("a-secure-local-password"),
        role="ADMIN",
    )
    alert.acknowledged_by_user = admin
    alert.status = "ACKNOWLEDGED"
    alert.acknowledged_at = datetime.now(timezone.utc)
    db.commit()
    assert alert in admin.acknowledged_alerts
    assert alert.acknowledged_by_user_id == admin.id
