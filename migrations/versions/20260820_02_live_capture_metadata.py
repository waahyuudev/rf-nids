"""Persist live capture provenance separately from model features."""

from alembic import op
import sqlalchemy as sa


revision = "20260820_02"
down_revision = "20260820_01"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("traffic_flows", sa.Column("capture_session_id", sa.String(80)))
    op.add_column("traffic_flows", sa.Column("capture_interface", sa.String(100)))
    op.add_column("traffic_flows", sa.Column("pcap_segment", sa.String(255)))
    op.create_index(
        "ix_traffic_flows_capture_session_id",
        "traffic_flows",
        ["capture_session_id"],
    )


def downgrade():
    op.drop_index("ix_traffic_flows_capture_session_id", table_name="traffic_flows")
    op.drop_column("traffic_flows", "pcap_segment")
    op.drop_column("traffic_flows", "capture_interface")
    op.drop_column("traffic_flows", "capture_session_id")
