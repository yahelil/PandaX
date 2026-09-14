"""Store typed analysis inputs by secure object reference."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260914_0009"
down_revision = "20260914_0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("analysis_jobs") as batch:
        batch.add_column(sa.Column("input_type", sa.String(24), nullable=False, server_default="sbom"))
        batch.add_column(sa.Column("object_key", sa.String(500), nullable=True))
        batch.add_column(sa.Column("retained_until", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("input_metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")))
        batch.add_column(sa.Column("consented_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("consent_actor_id", sa.String(128), nullable=True))
        batch.alter_column("input_content", existing_type=sa.LargeBinary(), nullable=True)
        batch.create_check_constraint(
            "analysis_jobs_input_type",
            "input_type IN ('sbom','collector','raw_artifact')",
        )
        batch.create_check_constraint(
            "analysis_jobs_input_reference",
            "input_content IS NOT NULL OR (object_key IS NOT NULL AND retained_until IS NOT NULL)",
        )
        batch.create_check_constraint(
            "analysis_jobs_raw_consent",
            "input_type != 'raw_artifact' OR (consented_at IS NOT NULL AND consent_actor_id IS NOT NULL)",
        )
    op.create_index("ix_analysis_jobs_retention", "analysis_jobs", ["retained_until"])


def downgrade() -> None:
    op.drop_index("ix_analysis_jobs_retention", table_name="analysis_jobs")
    # Externally stored inputs cannot be reconstructed in the legacy inline schema.
    op.execute("DELETE FROM analysis_jobs WHERE input_content IS NULL")
    with op.batch_alter_table("analysis_jobs") as batch:
        batch.drop_constraint("analysis_jobs_raw_consent", type_="check")
        batch.drop_constraint("analysis_jobs_input_reference", type_="check")
        batch.drop_constraint("analysis_jobs_input_type", type_="check")
        batch.alter_column("input_content", existing_type=sa.LargeBinary(), nullable=False)
        batch.drop_column("consent_actor_id")
        batch.drop_column("consented_at")
        batch.drop_column("input_metadata")
        batch.drop_column("retained_until")
        batch.drop_column("object_key")
        batch.drop_column("input_type")
