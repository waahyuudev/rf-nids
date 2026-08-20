"""Create RF-NIDS detection backend tables."""

from alembic import op
import sqlalchemy as sa

revision = "20260820_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("models", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("model_name", sa.String(200), nullable=False), sa.Column("model_version", sa.String(100), nullable=False), sa.Column("algorithm", sa.String(100), nullable=False), sa.Column("accuracy", sa.Float()), sa.Column("macro_f1", sa.Float()), sa.Column("ddos_recall", sa.Float()), sa.Column("portscan_recall", sa.Float()), sa.Column("is_active", sa.Boolean(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_models_model_version", "models", ["model_version"], unique=True)
    op.create_index("ix_models_is_active", "models", ["is_active"])
    op.create_table("traffic_flows", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("capture_time", sa.DateTime(timezone=True)), sa.Column("source_ip", sa.String(45)), sa.Column("source_port", sa.Integer()), sa.Column("destination_ip", sa.String(45)), sa.Column("destination_port", sa.Integer()), sa.Column("protocol", sa.String(30)), sa.Column("raw_features", sa.JSON(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_traffic_flows_capture_time", "traffic_flows", ["capture_time"])
    op.create_index("ix_traffic_flows_source_ip", "traffic_flows", ["source_ip"])
    op.create_index("ix_traffic_flows_destination_ip", "traffic_flows", ["destination_ip"])
    op.create_table("predictions", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("traffic_flow_id", sa.Integer(), sa.ForeignKey("traffic_flows.id"), nullable=False, unique=True), sa.Column("model_id", sa.Integer(), sa.ForeignKey("models.id"), nullable=False), sa.Column("predicted_label", sa.String(50), nullable=False), sa.Column("confidence_score", sa.Float(), nullable=False), sa.Column("class_probabilities", sa.JSON(), nullable=False), sa.Column("prediction_time", sa.DateTime(timezone=True), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_predictions_model_id", "predictions", ["model_id"])
    op.create_index("ix_predictions_predicted_label", "predictions", ["predicted_label"])
    op.create_index("ix_predictions_label_time", "predictions", ["predicted_label", "prediction_time"])
    op.create_table("alerts", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("prediction_id", sa.Integer(), sa.ForeignKey("predictions.id"), nullable=False, unique=True), sa.Column("severity", sa.String(20), nullable=False), sa.Column("title", sa.String(200), nullable=False), sa.Column("description", sa.Text(), nullable=False), sa.Column("status", sa.String(30), nullable=False), sa.Column("acknowledged_at", sa.DateTime(timezone=True)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_status_severity", "alerts", ["status", "severity"])


def downgrade():
    op.drop_table("alerts")
    op.drop_table("predictions")
    op.drop_table("traffic_flows")
    op.drop_table("models")
