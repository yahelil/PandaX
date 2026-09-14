"""Create persisted release monitoring configuration and run events."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260914_0003"
down_revision = "20260914_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "release_monitoring",
        sa.Column("release_id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("product_id", sa.String(36), nullable=False),
        sa.Column("enabled_sources", sa.JSON(), nullable=False),
        sa.Column("cadence_minutes", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("health", sa.String(24), nullable=False),
        sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("coverage", sa.JSON(), nullable=False),
        sa.Column("limitations", sa.JSON(), nullable=False),
        sa.Column("active_claim_id", sa.String(36), nullable=True),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["release_id", "product_id", "organization_id"],
            [
                "portfolio_releases.id",
                "portfolio_releases.product_id",
                "portfolio_releases.organization_id",
            ],
            name="fk_release_monitoring_release_scope",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "release_id",
            "product_id",
            "organization_id",
            name="uq_release_monitoring_release_scope",
        ),
        sa.CheckConstraint(
            "cadence_minutes >= 5", name="ck_release_monitoring_minimum_cadence"
        ),
        sa.CheckConstraint(
            "consecutive_failures >= 0", name="ck_release_monitoring_failure_count"
        ),
    )
    op.create_index(
        "ix_release_monitoring_due",
        "release_monitoring",
        ["enabled", "next_check_at"],
    )
    op.create_table(
        "release_monitoring_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("product_id", sa.String(36), nullable=False),
        sa.Column("release_id", sa.String(36), nullable=False),
        sa.Column("event_type", sa.String(24), nullable=False),
        sa.Column("trigger", sa.String(24), nullable=False),
        sa.Column("health", sa.String(24), nullable=False),
        sa.Column("coverage", sa.JSON(), nullable=False),
        sa.Column("limitations", sa.JSON(), nullable=False),
        sa.Column("message", sa.String(1000), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["release_id", "product_id", "organization_id"],
            [
                "release_monitoring.release_id",
                "release_monitoring.product_id",
                "release_monitoring.organization_id",
            ],
            name="fk_release_monitoring_events_release_scope",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "run_id", "sequence", name="uq_release_monitoring_events_run_sequence"
        ),
    )
    op.create_index(
        "ix_release_monitoring_events_release_time",
        "release_monitoring_events",
        ["organization_id", "release_id", "occurred_at"],
    )

    if op.get_bind().dialect.name == "postgresql":
        op.execute("""
            CREATE FUNCTION prevent_release_monitoring_event_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'release monitoring events are append-only';
            END;
            $$ LANGUAGE plpgsql
        """)
        op.execute("""
            CREATE TRIGGER release_monitoring_events_immutable
            BEFORE UPDATE OR DELETE ON release_monitoring_events
            FOR EACH ROW
            EXECUTE FUNCTION prevent_release_monitoring_event_mutation()
        """)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS release_monitoring_events_immutable "
            "ON release_monitoring_events"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS prevent_release_monitoring_event_mutation()"
        )
    op.drop_index(
        "ix_release_monitoring_events_release_time",
        table_name="release_monitoring_events",
    )
    op.drop_table("release_monitoring_events")
    op.drop_index("ix_release_monitoring_due", table_name="release_monitoring")
    op.drop_table("release_monitoring")
