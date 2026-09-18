"""expand monitoring session selection mode

Revision ID: 20260917_10
Revises: 20260917_09
"""

from alembic import op
import sqlalchemy as sa

revision = "20260917_10"
down_revision = "20260917_09"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("monitoring_sessions") as batch:
        batch.alter_column(
            "selection_mode",
            existing_type=sa.String(20),
            type_=sa.String(64),
            existing_nullable=False,
            existing_server_default="DEFAULT",
        )


def downgrade():
    connection = op.get_bind()
    longest = connection.scalar(
        sa.text("SELECT MAX(LENGTH(selection_mode)) FROM monitoring_sessions")
    )
    if longest is not None and longest > 20:
        raise RuntimeError(
            "Cannot downgrade monitoring_sessions.selection_mode to VARCHAR(20): "
            "existing values exceed 20 characters. Migrate those rows explicitly first."
        )
    with op.batch_alter_table("monitoring_sessions") as batch:
        batch.alter_column(
            "selection_mode",
            existing_type=sa.String(64),
            type_=sa.String(20),
            existing_nullable=False,
            existing_server_default="DEFAULT",
        )
