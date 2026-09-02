"""Add evidence-source provenance and evaluation idempotency keys.

Revision ID: 20260902_04
Revises: 20260902_03
"""

from alembic import op
import sqlalchemy as sa


revision = "20260902_04"
down_revision = "20260902_03"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "evidence_sources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_type", sa.String(50), nullable=False),
        sa.Column("owner_key", sa.String(150), nullable=False),
        sa.Column("evidence_role", sa.String(100), nullable=False),
        sa.Column("source_path", sa.String(1000), nullable=False),
        sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column("schema_version", sa.String(100)),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "owner_type", "owner_key", "evidence_role", name="uq_evidence_owner_role"
        ),
        sa.UniqueConstraint("source_path", name="uq_evidence_source_path"),
    )
    op.create_index("ix_evidence_sources_owner_type", "evidence_sources", ["owner_type"])
    op.create_index("ix_evidence_sources_owner_key", "evidence_sources", ["owner_key"])
    with op.batch_alter_table("evaluation_results") as batch:
        batch.add_column(sa.Column("metric_key", sa.String(150)))
        batch.create_unique_constraint(
            "uq_evaluation_metric_key", ["experiment_id", "metric_key"]
        )
    with op.batch_alter_table("models") as batch:
        batch.add_column(sa.Column("feature_count", sa.Integer()))


def downgrade():
    with op.batch_alter_table("models") as batch:
        batch.drop_column("feature_count")
    with op.batch_alter_table("evaluation_results") as batch:
        batch.drop_constraint("uq_evaluation_metric_key", type_="unique")
        batch.drop_column("metric_key")
    op.drop_table("evidence_sources")
