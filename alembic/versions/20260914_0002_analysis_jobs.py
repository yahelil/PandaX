"""Create persisted release analysis jobs and immutable event history."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260914_0002"
down_revision = "20260914_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analysis_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("product_id", sa.String(36), nullable=False),
        sa.Column("release_id", sa.String(36), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("media_type", sa.String(100), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("input_format", sa.String(24), nullable=False),
        sa.Column("input_version", sa.String(24), nullable=False),
        sa.Column("preview", sa.JSON(), nullable=False),
        sa.Column("input_content", sa.LargeBinary(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("stage", sa.String(80), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error", sa.String(1000), nullable=True),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["release_id", "product_id", "organization_id"],
            [
                "portfolio_releases.id",
                "portfolio_releases.product_id",
                "portfolio_releases.organization_id",
            ],
            name="fk_analysis_jobs_release_scope",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "release_id",
            "idempotency_key",
            name="uq_analysis_jobs_release_idempotency",
        ),
    )
    op.create_index(
        "ix_analysis_jobs_release_created",
        "analysis_jobs",
        ["organization_id", "release_id", "created_at"],
    )
    op.create_table(
        "analysis_job_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "job_id",
            sa.String(36),
            sa.ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("stage", sa.String(80), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("message", sa.String(1000), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "job_id", "sequence", name="uq_analysis_job_events_sequence"
        ),
    )
    op.create_index(
        "ix_analysis_job_events_job_sequence",
        "analysis_job_events",
        ["job_id", "sequence"],
    )

    if op.get_bind().dialect.name == "postgresql":
        op.execute("""
            CREATE FUNCTION prevent_analysis_event_mutation() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'analysis events are append-only';
            END;
            $$ LANGUAGE plpgsql
        """)
        op.execute("""
            CREATE TRIGGER analysis_job_events_immutable
            BEFORE UPDATE OR DELETE ON analysis_job_events
            FOR EACH ROW EXECUTE FUNCTION prevent_analysis_event_mutation()
        """)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS analysis_job_events_immutable ON analysis_job_events"
        )
        op.execute("DROP FUNCTION IF EXISTS prevent_analysis_event_mutation()")
    op.drop_index(
        "ix_analysis_job_events_job_sequence", table_name="analysis_job_events"
    )
    op.drop_table("analysis_job_events")
    op.drop_index("ix_analysis_jobs_release_created", table_name="analysis_jobs")
    op.drop_table("analysis_jobs")
