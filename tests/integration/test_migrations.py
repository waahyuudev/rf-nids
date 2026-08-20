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
    }
    alert_checks = {constraint["name"] for constraint in schema.get_check_constraints("alerts")}
    assert {"ck_alerts_severity", "ck_alerts_status"} <= alert_checks
    engine.dispose()
