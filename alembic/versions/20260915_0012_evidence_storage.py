"""Add durable evidence bundle metadata and lifecycle state."""
from alembic import op
import sqlalchemy as sa


revision = "20260915_0012"
down_revision = "20260915_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("analysis_jobs") as batch:
        batch.add_column(sa.Column("storage_size_bytes", sa.Integer(), nullable=True))
    op.execute("UPDATE analysis_jobs SET storage_size_bytes = size_bytes")
    with op.batch_alter_table("analysis_jobs") as batch:
        batch.alter_column("storage_size_bytes", existing_type=sa.Integer(), nullable=False)

    op.create_table(
        "evidence_bundles",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("job_id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("object_key", sa.String(500), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retained_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("legal_hold", sa.Boolean(), nullable=False),
        sa.Column("hold_reason", sa.String(500)),
        sa.Column("held_at", sa.DateTime(timezone=True)),
        sa.Column("held_by", sa.String(128)),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.Column("backup_expires_at", sa.DateTime(timezone=True)),
        sa.Column("deletion_receipt", sa.JSON()),
        sa.CheckConstraint("size_bytes > 0", name="ck_evidence_bundles_size"),
        sa.CheckConstraint(
            "state IN ('active','deletion_pending','deleted')",
            name="ck_evidence_bundles_state",
        ),
        sa.CheckConstraint(
            "(legal_hold = false AND hold_reason IS NULL AND held_at IS NULL AND held_by IS NULL) "
            "OR (legal_hold = true AND hold_reason IS NOT NULL AND held_at IS NOT NULL AND held_by IS NOT NULL)",
            name="ck_evidence_bundles_hold",
        ),
        sa.ForeignKeyConstraint(
            ["job_id"], ["analysis_jobs.id"], name="fk_evidence_bundles_job", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_evidence_bundles"),
        sa.UniqueConstraint("job_id", name="uq_evidence_bundles_job_id"),
        sa.UniqueConstraint("object_key", name="uq_evidence_bundles_object_key"),
    )
    op.create_index(
        "ix_evidence_bundles_org_state",
        "evidence_bundles",
        ["organization_id", "state"],
    )
    op.create_index(
        "ix_evidence_bundles_retention",
        "evidence_bundles",
        ["retained_until"],
    )


def downgrade() -> None:
    op.drop_index("ix_evidence_bundles_retention", table_name="evidence_bundles")
    op.drop_index("ix_evidence_bundles_org_state", table_name="evidence_bundles")
    op.drop_table("evidence_bundles")
    with op.batch_alter_table("analysis_jobs") as batch:
        batch.drop_column("storage_size_bytes")
