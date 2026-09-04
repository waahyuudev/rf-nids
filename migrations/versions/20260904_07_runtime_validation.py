"""Add Phase 11 runtime validation evidence.

Revision ID: 20260904_07
Revises: 20260904_06
"""
from alembic import op
import sqlalchemy as sa

revision = "20260904_07"
down_revision = "20260904_06"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "runtime_validation_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("monitoring_session_id", sa.Integer(), sa.ForeignKey("monitoring_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scenario", sa.String(30), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("target_ip", sa.String(45), nullable=False),
        sa.Column("interface_name", sa.String(100), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("pcap_files_processed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("pcap_bytes_processed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("flows_extracted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("flows_adapter_valid", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("predictions_committed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("alerts_committed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("normal_predictions", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("portscan_predictions", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ddos_predictions", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("pipeline_result", sa.String(20), nullable=False, server_default="NOT_EVALUATED"),
        sa.Column("detection_result", sa.String(20), nullable=False, server_default="NOT_EVALUATED"),
        sa.Column("extractor_identity", sa.String(300)),
        sa.Column("adapter_identity", sa.String(300)),
        sa.Column("model_id", sa.Integer(), sa.ForeignKey("models.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("model_version", sa.String(100), nullable=False),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("notes", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("scenario IN ('NORMAL_HTTP', 'PORTSCAN', 'STOP_RESTART')", name="ck_runtime_validation_scenario"),
        sa.CheckConstraint("status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')", name="ck_runtime_validation_status"),
        sa.CheckConstraint("pipeline_result IN ('PASS', 'FAIL', 'NOT_EVALUATED')", name="ck_runtime_validation_pipeline_result"),
        sa.CheckConstraint("detection_result IN ('PASS', 'FAIL', 'NOT_APPLICABLE', 'NOT_EVALUATED')", name="ck_runtime_validation_detection_result"),
    )
    op.create_index("ix_runtime_validation_runs_monitoring_session_id", "runtime_validation_runs", ["monitoring_session_id"])
    op.create_index("ix_runtime_validation_session_created", "runtime_validation_runs", ["monitoring_session_id", "created_at"])


def downgrade():
    op.drop_index("ix_runtime_validation_session_created", table_name="runtime_validation_runs")
    op.drop_index("ix_runtime_validation_runs_monitoring_session_id", table_name="runtime_validation_runs")
    op.drop_table("runtime_validation_runs")
