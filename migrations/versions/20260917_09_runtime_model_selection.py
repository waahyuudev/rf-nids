"""freeze runtime model selection mode on monitoring sessions

Revision ID: 20260917_09
Revises: 20260905_08
"""

from alembic import op
import sqlalchemy as sa

revision = "20260917_09"
down_revision = "20260905_08"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("monitoring_sessions") as batch:
        batch.add_column(
            sa.Column(
                "selection_mode", sa.String(20), nullable=False,
                server_default="DEFAULT",
            )
        )
        batch.add_column(sa.Column("selected_model_version", sa.String(100)))
        batch.add_column(sa.Column("selected_model_sha256", sa.String(64)))
    op.execute(
        sa.text(
            "UPDATE monitoring_sessions SET selected_model_version = "
            "(SELECT model_version FROM models WHERE models.id = monitoring_sessions.model_id), "
            "selected_model_sha256 = "
            "(SELECT artifact_sha256 FROM models WHERE models.id = monitoring_sessions.model_id)"
        )
    )


def downgrade():
    with op.batch_alter_table("monitoring_sessions") as batch:
        batch.drop_column("selected_model_sha256")
        batch.drop_column("selected_model_version")
        batch.drop_column("selection_mode")
