"""Add durable external notification delivery jobs."""
from alembic import op
import sqlalchemy as sa


revision = "20260915_0014"
down_revision = "20260915_0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_delivery_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("notification_id", sa.String(36), nullable=False),
        sa.Column("integration_id", sa.String(36), nullable=False),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("idempotency_key", sa.String(64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
        sa.Column("provider_reference", sa.String(240)),
        sa.Column("error_code", sa.String(80)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(
            ["notification_id"], ["notifications.id"],
            name="fk_notification_delivery_notification", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["integration_id"], ["organization_integrations.id"],
            name="fk_notification_delivery_integration", ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "organization_id", "idempotency_key",
            name="uq_notification_delivery_idempotency",
        ),
        sa.CheckConstraint(
            "channel IN ('email','webhook','jira')",
            name="ck_notification_delivery_jobs_channel",
        ),
        sa.CheckConstraint(
            "status IN ('queued','delivering','retrying','delivered','dead_letter','suppressed')",
            name="ck_notification_delivery_jobs_status",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 10",
            name="ck_notification_delivery_jobs_attempts",
        ),
    )
    op.create_index(
        "ix_notification_delivery_due", "notification_delivery_jobs",
        ["status", "next_attempt_at", "lease_until"],
    )
    op.create_index(
        "ix_notification_delivery_org_created", "notification_delivery_jobs",
        ["organization_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_notification_delivery_org_created",
        table_name="notification_delivery_jobs",
    )
    op.drop_index(
        "ix_notification_delivery_due",
        table_name="notification_delivery_jobs",
    )
    op.drop_table("notification_delivery_jobs")
