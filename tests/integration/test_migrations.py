from alembic import command
from alembic.config import Config
from sqlalchemy import inspect


def test_initial_migration_creates_detection_schema(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    database_path = tmp_path / "migration.db"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")

    command.upgrade(config, "head")

    from sqlalchemy import create_engine

    engine = create_engine(f"sqlite:///{database_path}")
    schema = inspect(engine)
    assert {"models", "traffic_flows", "predictions", "alerts"} <= set(
        schema.get_table_names()
    )
    prediction_fks = schema.get_foreign_keys("predictions")
    assert {fk["options"].get("ondelete") for fk in prediction_fks} == {
        "CASCADE",
        "RESTRICT",
        "SET NULL",
    }
    alert_checks = {constraint["name"] for constraint in schema.get_check_constraints("alerts")}
    assert {"ck_alerts_severity", "ck_alerts_status"} <= alert_checks
    assert {"users", "datasets", "experiments", "evaluation_results", "evidence_sources"} <= set(
        schema.get_table_names()
    )
    assert {"experiment_id", "artifact_path", "artifact_sha256", "parameters"} <= {
        column["name"] for column in schema.get_columns("models")
    }
    assert "feature_count" in {column["name"] for column in schema.get_columns("models")}
    assert "metric_key" in {
        column["name"] for column in schema.get_columns("evaluation_results")
    }
    assert {"experiment_id", "source_type", "external_key"} <= {
        column["name"] for column in schema.get_columns("predictions")
    }
    assert "acknowledged_by_user_id" in {
        column["name"] for column in schema.get_columns("alerts")
    }
    engine.dispose()


def test_phase_1_migration_preserves_legacy_rows(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    database_path = tmp_path / "legacy.db"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")
    command.upgrade(config, "20260820_02")

    from sqlalchemy import create_engine, text

    engine = create_engine(f"sqlite:///{database_path}")
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO models "
                "(id, model_name, model_version, algorithm, is_active, created_at) "
                "VALUES (1, 'Legacy RF', 'legacy-v1', 'Random Forest', 1, CURRENT_TIMESTAMP)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO traffic_flows (id, raw_features, created_at) "
                "VALUES (1, '{}', CURRENT_TIMESTAMP)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO predictions "
                "(id, traffic_flow_id, model_id, predicted_label, confidence_score, "
                "class_probabilities, prediction_time, created_at) "
                "VALUES (1, 1, 1, 'Normal', 1.0, '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )
    engine.dispose()

    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database_path}")
    with engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT experiment_id, source_type, external_key FROM predictions WHERE id=1"
            )
        ).one()
        assert tuple(row) == (None, None, None)
        model = connection.execute(
            text("SELECT experiment_id, artifact_path FROM models WHERE id=1")
        ).one()
        assert tuple(model) == (None, None)
    engine.dispose()
