"""Add thesis application domain and provenance foundation.

Revision ID: 20260902_03
Revises: 20260820_02
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260902_03"
down_revision = "20260820_02"
branch_labels = None
depends_on = None

portable_json = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("role", sa.String(30), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("role IN ('ADMIN')", name="ck_users_role"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_is_active", "users", ["is_active"])

    op.create_table(
        "datasets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("source_path", sa.String(1000)),
        sa.Column("source_sha256", sa.String(64)),
        sa.Column("total_rows", sa.Integer()),
        sa.Column("total_features", sa.Integer()),
        sa.Column("label_column", sa.String(255)),
        sa.Column("class_distribution", portable_json),
        sa.Column(
            "created_by_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_datasets_source_sha256", "datasets", ["source_sha256"])
    op.create_index("ix_datasets_created_by_user_id", "datasets", ["created_by_user_id"])

    op.create_table(
        "experiments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("experiment_code", sa.String(100), nullable=False),
        sa.Column("experiment_name", sa.String(255), nullable=False),
        sa.Column("experiment_type", sa.String(100), nullable=False),
        sa.Column(
            "dataset_id",
            sa.Integer(),
            sa.ForeignKey("datasets.id", ondelete="SET NULL"),
        ),
        sa.Column("description", sa.Text()),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("source_path", sa.String(1000)),
        sa.Column("source_sha256", sa.String(64)),
        sa.Column("schema_version", sa.String(100)),
        sa.Column("imported_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_experiments_experiment_code", "experiments", ["experiment_code"], unique=True
    )
    op.create_index("ix_experiments_dataset_id", "experiments", ["dataset_id"])
    op.create_index("ix_experiments_source_sha256", "experiments", ["source_sha256"])

    op.create_table(
        "evaluation_results",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "experiment_id",
            sa.Integer(),
            sa.ForeignKey("experiments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("class_name", sa.String(100)),
        sa.Column("accuracy", sa.Float()),
        sa.Column("precision_score", sa.Float()),
        sa.Column("recall_score", sa.Float()),
        sa.Column("f1_score", sa.Float()),
        sa.Column("macro_precision", sa.Float()),
        sa.Column("macro_recall", sa.Float()),
        sa.Column("macro_f1", sa.Float()),
        sa.Column("false_positive_rate", sa.Float()),
        sa.Column("true_positive", sa.Integer()),
        sa.Column("true_negative", sa.Integer()),
        sa.Column("false_positive", sa.Integer()),
        sa.Column("false_negative", sa.Integer()),
        sa.Column("confusion_matrix", portable_json),
        sa.Column("notes", sa.Text()),
        sa.Column("source_path", sa.String(1000)),
        sa.Column("source_sha256", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_evaluation_results_experiment_id", "evaluation_results", ["experiment_id"]
    )

    with op.batch_alter_table("models") as batch:
        batch.add_column(sa.Column("experiment_id", sa.Integer()))
        batch.add_column(sa.Column("artifact_path", sa.String(1000)))
        batch.add_column(sa.Column("artifact_sha256", sa.String(64)))
        batch.add_column(sa.Column("parameters", portable_json))
        batch.create_foreign_key(
            "fk_models_experiment_id_experiments",
            "experiments",
            ["experiment_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_index("ix_models_experiment_id", ["experiment_id"])

    with op.batch_alter_table("predictions") as batch:
        batch.add_column(sa.Column("experiment_id", sa.Integer()))
        batch.add_column(sa.Column("source_type", sa.String(50)))
        batch.add_column(sa.Column("external_key", sa.String(255)))
        batch.create_foreign_key(
            "fk_predictions_experiment_id_experiments",
            "experiments",
            ["experiment_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_index("ix_predictions_experiment_id", ["experiment_id"])
        batch.create_index("ix_predictions_source_type", ["source_type"])
        batch.create_unique_constraint(
            "uq_predictions_source_external_key", ["source_type", "external_key"]
        )

    with op.batch_alter_table("alerts") as batch:
        batch.add_column(sa.Column("acknowledged_by_user_id", sa.Integer()))
        batch.create_foreign_key(
            "fk_alerts_acknowledged_by_user_id_users",
            "users",
            ["acknowledged_by_user_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_index("ix_alerts_acknowledged_by_user_id", ["acknowledged_by_user_id"])


def downgrade():
    with op.batch_alter_table("alerts") as batch:
        batch.drop_index("ix_alerts_acknowledged_by_user_id")
        batch.drop_constraint(
            "fk_alerts_acknowledged_by_user_id_users", type_="foreignkey"
        )
        batch.drop_column("acknowledged_by_user_id")

    with op.batch_alter_table("predictions") as batch:
        batch.drop_constraint("uq_predictions_source_external_key", type_="unique")
        batch.drop_index("ix_predictions_source_type")
        batch.drop_index("ix_predictions_experiment_id")
        batch.drop_constraint(
            "fk_predictions_experiment_id_experiments", type_="foreignkey"
        )
        batch.drop_column("external_key")
        batch.drop_column("source_type")
        batch.drop_column("experiment_id")

    with op.batch_alter_table("models") as batch:
        batch.drop_index("ix_models_experiment_id")
        batch.drop_constraint("fk_models_experiment_id_experiments", type_="foreignkey")
        batch.drop_column("parameters")
        batch.drop_column("artifact_sha256")
        batch.drop_column("artifact_path")
        batch.drop_column("experiment_id")

    op.drop_table("evaluation_results")
    op.drop_table("experiments")
    op.drop_table("datasets")
    op.drop_table("users")
