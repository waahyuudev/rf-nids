"""Add runtime extractor and processing metadata.

Revision ID: 20260904_06
Revises: 20260904_05
"""

from alembic import op
import sqlalchemy as sa

revision = "20260904_06"
down_revision = "20260904_05"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("monitoring_sessions") as batch:
        batch.add_column(sa.Column("extractor_name", sa.String(150)))
        batch.add_column(sa.Column("extractor_version", sa.String(100)))
        batch.add_column(sa.Column("latest_processing_at", sa.DateTime(timezone=True)))


def downgrade():
    with op.batch_alter_table("monitoring_sessions") as batch:
        batch.drop_column("latest_processing_at")
        batch.drop_column("extractor_version")
        batch.drop_column("extractor_name")
