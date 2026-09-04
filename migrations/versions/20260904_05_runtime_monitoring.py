"""Add persistent runtime monitoring controller sessions.

Revision ID: 20260904_05
Revises: 20260902_04
"""

from alembic import op
import sqlalchemy as sa

revision = "20260904_05"
down_revision = "20260902_04"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "monitoring_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_ip", sa.String(45), nullable=False),
        sa.Column("interface_name", sa.String(100), nullable=False),
        sa.Column("model_id", sa.Integer(), sa.ForeignKey("models.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("stopped_at", sa.DateTime(timezone=True)),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error", sa.Text()),
        sa.Column("runtime_handle", sa.String(100)),
        sa.Column("flow_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("prediction_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("alert_count", sa.Integer(), nullable=False, server_default="0"),
        sa.CheckConstraint("status IN ('STARTING', 'RUNNING', 'STOPPING', 'STOPPED', 'FAILED')", name="ck_monitoring_sessions_status"),
        sa.CheckConstraint("flow_count >= 0", name="ck_monitoring_sessions_flow_count"),
        sa.CheckConstraint("prediction_count >= 0", name="ck_monitoring_sessions_prediction_count"),
        sa.CheckConstraint("alert_count >= 0", name="ck_monitoring_sessions_alert_count"),
    )
    op.create_index("ix_monitoring_sessions_model_id", "monitoring_sessions", ["model_id"])
    op.create_index("ix_monitoring_sessions_status", "monitoring_sessions", ["status"])
    op.create_index("ix_monitoring_sessions_created_by_user_id", "monitoring_sessions", ["created_by_user_id"])
    op.create_index("ix_monitoring_sessions_status_created", "monitoring_sessions", ["status", "created_at"])
    op.create_index(
        "uq_monitoring_sessions_single_active",
        "monitoring_sessions",
        ["status"],
        unique=True,
        postgresql_where=sa.text("status IN ('STARTING', 'RUNNING', 'STOPPING')"),
        sqlite_where=sa.text("status IN ('STARTING', 'RUNNING', 'STOPPING')"),
    )
    with op.batch_alter_table("predictions") as batch:
        batch.add_column(sa.Column("monitoring_session_id", sa.Integer()))
        batch.create_foreign_key(
            "fk_predictions_monitoring_session_id", "monitoring_sessions",
            ["monitoring_session_id"], ["id"], ondelete="SET NULL"
        )
        batch.create_index("ix_predictions_monitoring_session_id", ["monitoring_session_id"])


def downgrade():
    with op.batch_alter_table("predictions") as batch:
        batch.drop_index("ix_predictions_monitoring_session_id")
        batch.drop_constraint("fk_predictions_monitoring_session_id", type_="foreignkey")
        batch.drop_column("monitoring_session_id")
    op.drop_table("monitoring_sessions")
