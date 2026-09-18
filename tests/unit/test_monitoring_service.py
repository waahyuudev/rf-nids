import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from src.api.database import Base, build_engine
from src.api.models import ModelRecord, MonitoringSession, User
from src.api.monitoring import CollectorController, MonitoringService


@pytest.fixture
def monitoring_db(tmp_path, monkeypatch):
    engine = build_engine(f"sqlite:///{tmp_path / 'monitoring-service.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(
        "src.api.monitoring.list_capture_interfaces",
        lambda: ([{"name": "test0", "is_up": True}], True),
    )
    yield sessions
    engine.dispose()


def add_operator_and_model(db, *, version, sha256, active):
    user = User(
        name="Operator", email=f"{version}@example.test", password_hash="not-used"
    )
    model = ModelRecord(
        model_name="RF", model_version=version, algorithm="Random Forest",
        artifact_sha256=sha256, is_active=active,
    )
    db.add_all([user, model])
    db.commit()
    return user, model


@pytest.mark.parametrize(
    ("version", "sha256", "active", "selection_mode"),
    [
        ("rf-v5-candidate-01", "5" * 64, False, "MANUAL / DEMO SELECTION"),
        ("rf-v2.0", "2" * 64, True, "DEFAULT"),
    ],
)
def test_monitoring_session_persists_selection_and_model_provenance(
    monitoring_db, version, sha256, active, selection_mode
):
    with monitoring_db() as db:
        user, model = add_operator_and_model(
            db, version=version, sha256=sha256, active=active
        )
        row = MonitoringService(CollectorController()).start(
            db,
            target_ip="192.168.128.2",
            interface_name="test0",
            user=user,
            model_id=model.id,
            selection_mode=selection_mode,
        )
        session_id = row.id

    with monitoring_db() as db:
        persisted = db.get(MonitoringSession, session_id)
        assert persisted.status == "RUNNING"
        assert persisted.selection_mode == selection_mode
        assert persisted.selected_model_version == version
        assert persisted.selected_model_sha256 == sha256


def test_monitoring_session_database_failure_rolls_back_and_preserves_original_error(
    monitoring_db, monkeypatch
):
    with monitoring_db() as db:
        user, model = add_operator_and_model(
            db, version="rf-v5-candidate-01", sha256="5" * 64, active=False
        )
        original_error = SQLAlchemyError("original insert failure")
        rollback_calls = 0
        commit_calls = 0
        real_rollback = db.rollback

        def fail_commit():
            nonlocal commit_calls
            commit_calls += 1
            raise original_error

        def track_rollback():
            nonlocal rollback_calls
            rollback_calls += 1
            real_rollback()

        monkeypatch.setattr(db, "commit", fail_commit)
        monkeypatch.setattr(db, "rollback", track_rollback)

        with pytest.raises(SQLAlchemyError) as caught:
            MonitoringService(CollectorController()).start(
                db,
                target_ip="192.168.128.2",
                interface_name="test0",
                user=user,
                model_id=model.id,
                selection_mode="MANUAL / DEMO SELECTION",
            )

        assert caught.value is original_error
        assert commit_calls == 1
        assert rollback_calls == 1

    with monitoring_db() as db:
        assert db.scalar(select(func.count(MonitoringSession.id))) == 0
