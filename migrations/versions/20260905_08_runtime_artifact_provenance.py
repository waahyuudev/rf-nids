"""Add durable runtime capture artifact provenance.

Revision ID: 20260905_08
Revises: 20260904_07
"""
from alembic import op
import sqlalchemy as sa

revision = "20260905_08"
down_revision = "20260904_07"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("monitoring_sessions") as batch:
        batch.add_column(sa.Column("extractor_identity", sa.String(300)))
        batch.add_column(sa.Column("artifact_key", sa.String(36)))
        batch.add_column(sa.Column("artifact_root", sa.String(1000)))
        batch.add_column(sa.Column("processing_state", sa.String(30)))
        batch.create_unique_constraint("uq_monitoring_sessions_artifact_key", ["artifact_key"])
    op.create_table(
        "runtime_capture_artifacts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("monitoring_session_id", sa.Integer(), sa.ForeignKey("monitoring_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("artifact_key", sa.String(36), nullable=False),
        sa.Column("window_number", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("pcap_relative_path", sa.String(1000)),
        sa.Column("pcap_sha256", sa.String(64)),
        sa.Column("pcap_size", sa.Integer()),
        sa.Column("csv_relative_path", sa.String(1000)),
        sa.Column("csv_sha256", sa.String(64)),
        sa.Column("csv_size", sa.Integer()),
        sa.Column("extractor_identity", sa.String(300)),
        sa.Column("extracted_row_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("adapted_row_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_stage", sa.String(50)),
        sa.Column("error_message", sa.Text()),
        sa.Column("capture_started_at", sa.DateTime(timezone=True)),
        sa.Column("capture_finished_at", sa.DateTime(timezone=True)),
        sa.Column("extraction_finished_at", sa.DateTime(timezone=True)),
        sa.Column("committed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("state IN ('CAPTURING', 'CAPTURED', 'EXTRACTED', 'COMMITTED', 'FAILED')", name="ck_runtime_capture_artifacts_state"),
        sa.UniqueConstraint("monitoring_session_id", "window_number", name="uq_runtime_artifact_session_window"),
        sa.UniqueConstraint("artifact_key", name="uq_runtime_capture_artifact_key"),
    )
    op.create_index("ix_runtime_capture_artifacts_monitoring_session_id", "runtime_capture_artifacts", ["monitoring_session_id"])
    op.create_index("ix_runtime_artifact_session_state", "runtime_capture_artifacts", ["monitoring_session_id", "state"])
    with op.batch_alter_table("predictions") as batch:
        batch.add_column(sa.Column("runtime_artifact_id", sa.Integer()))
        batch.create_foreign_key("fk_predictions_runtime_artifact_id", "runtime_capture_artifacts", ["runtime_artifact_id"], ["id"], ondelete="SET NULL")
        batch.create_index("ix_predictions_runtime_artifact_id", ["runtime_artifact_id"])


def downgrade():
    with op.batch_alter_table("predictions") as batch:
        batch.drop_index("ix_predictions_runtime_artifact_id")
        batch.drop_constraint("fk_predictions_runtime_artifact_id", type_="foreignkey")
        batch.drop_column("runtime_artifact_id")
    op.drop_index("ix_runtime_artifact_session_state", table_name="runtime_capture_artifacts")
    op.drop_index("ix_runtime_capture_artifacts_monitoring_session_id", table_name="runtime_capture_artifacts")
    op.drop_table("runtime_capture_artifacts")
    with op.batch_alter_table("monitoring_sessions") as batch:
        batch.drop_constraint("uq_monitoring_sessions_artifact_key", type_="unique")
        batch.drop_column("processing_state")
        batch.drop_column("artifact_root")
        batch.drop_column("artifact_key")
        batch.drop_column("extractor_identity")
