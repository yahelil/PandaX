"""Create organization settings, access, integrations, and safe analytics."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260914_0008"
down_revision = "20260914_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organization_settings",
        sa.Column("organization_id", sa.String(36), primary_key=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("urgent_findings", sa.Boolean(), nullable=False),
        sa.Column("deadline_warnings", sa.Boolean(), nullable=False),
        sa.Column("monitoring_failures", sa.Boolean(), nullable=False),
        sa.Column("approval_requests", sa.Boolean(), nullable=False),
        sa.Column("email_digest", sa.String(16), nullable=False),
        sa.Column("session_timeout_minutes", sa.Integer(), nullable=False),
        sa.Column("evidence_retention_months", sa.Integer(), nullable=False),
        sa.Column("require_mfa", sa.Boolean(), nullable=False),
        sa.Column("allow_raw_artifacts", sa.Boolean(), nullable=False),
        sa.Column("theme", sa.String(16), nullable=False),
        sa.Column("density", sa.String(16), nullable=False),
        sa.Column("analytics_enabled", sa.Boolean(), nullable=False),
        sa.Column("analytics_retention_days", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.String(128), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["portfolio_organizations.id"], ondelete="CASCADE"),
        sa.CheckConstraint("version >= 1", name="ck_organization_settings_version_positive"),
        sa.CheckConstraint("email_digest IN ('off','daily','weekly')", name="ck_organization_settings_email_digest"),
        sa.CheckConstraint("theme IN ('light','dark','system')", name="ck_organization_settings_theme"),
        sa.CheckConstraint("density IN ('comfortable','compact')", name="ck_organization_settings_density"),
        sa.CheckConstraint("session_timeout_minutes BETWEEN 5 AND 1440", name="ck_organization_settings_session_timeout"),
        sa.CheckConstraint("evidence_retention_months BETWEEN 1 AND 240", name="ck_organization_settings_evidence_retention"),
        sa.CheckConstraint("analytics_retention_days BETWEEN 1 AND 365", name="ck_organization_settings_analytics_retention"),
    )

    op.create_table(
        "organization_team_members",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("subject", sa.String(160), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("initials", sa.String(8), nullable=False),
        sa.Column("roles", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("last_active_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["portfolio_organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("organization_id", "subject", name="uq_organization_team_members_subject"),
        sa.UniqueConstraint("organization_id", "email", name="uq_organization_team_members_email"),
        sa.CheckConstraint("status IN ('active','invited','disabled')", name="ck_organization_team_members_status"),
        sa.CheckConstraint("version >= 1", name="ck_organization_team_members_version_positive"),
    )
    op.create_index("ix_organization_team_members_org_status", "organization_team_members", ["organization_id", "status"])

    op.create_table(
        "organization_integrations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("type", sa.String(24), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column("secret_reference", sa.String(500), nullable=True),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["portfolio_organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("organization_id", "name", name="uq_organization_integrations_name"),
        sa.CheckConstraint("type IN ('email','webhook','collector','jira')", name="ck_organization_integrations_type"),
        sa.CheckConstraint("status IN ('connected','attention','not_connected')", name="ck_organization_integrations_status"),
        sa.CheckConstraint("version >= 1", name="ck_organization_integrations_version_positive"),
        sa.CheckConstraint(
            "secret_reference IS NULL OR secret_reference LIKE 'vault://%' OR secret_reference LIKE 'aws-secrets://%' OR secret_reference LIKE 'gcp-secret://%' OR secret_reference LIKE 'azure-keyvault://%'",
            name="ck_organization_integrations_external_secret_reference",
        ),
    )

    op.create_table(
        "organization_settings_audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_id", sa.String(128), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("changes", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["portfolio_organizations.id"], ondelete="CASCADE"),
        sa.CheckConstraint("version >= 1", name="ck_organization_settings_audit_events_version_positive"),
    )
    op.create_index("ix_organization_settings_audit_org_time", "organization_settings_audit_events", ["organization_id", "occurred_at"])

    op.create_table(
        "privacy_safe_analytics_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("event_name", sa.String(40), nullable=False),
        sa.Column("properties", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["portfolio_organizations.id"], ondelete="CASCADE"),
        sa.CheckConstraint("event_name IN ('page_viewed','workflow_completed','feature_used','error_observed')", name="ck_privacy_safe_analytics_events_event_name"),
        sa.CheckConstraint("expires_at > ingested_at", name="ck_privacy_safe_analytics_events_retention"),
    )
    op.create_index("ix_privacy_safe_analytics_org_event_time", "privacy_safe_analytics_events", ["organization_id", "event_name", "occurred_at"])
    op.create_index("ix_privacy_safe_analytics_expiry", "privacy_safe_analytics_events", ["expires_at"])

    if op.get_bind().dialect.name == "postgresql":
        op.execute("""
            CREATE FUNCTION prevent_organization_settings_audit_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'organization settings audit is append-only';
            END;
            $$ LANGUAGE plpgsql
        """)
        op.execute("""
            CREATE TRIGGER organization_settings_audit_events_immutable
            BEFORE UPDATE OR DELETE ON organization_settings_audit_events
            FOR EACH ROW EXECUTE FUNCTION prevent_organization_settings_audit_mutation()
        """)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS organization_settings_audit_events_immutable ON organization_settings_audit_events")
        op.execute("DROP FUNCTION IF EXISTS prevent_organization_settings_audit_mutation()")
    op.drop_index("ix_privacy_safe_analytics_expiry", table_name="privacy_safe_analytics_events")
    op.drop_index("ix_privacy_safe_analytics_org_event_time", table_name="privacy_safe_analytics_events")
    op.drop_table("privacy_safe_analytics_events")
    op.drop_index("ix_organization_settings_audit_org_time", table_name="organization_settings_audit_events")
    op.drop_table("organization_settings_audit_events")
    op.drop_table("organization_integrations")
    op.drop_index("ix_organization_team_members_org_status", table_name="organization_team_members")
    op.drop_table("organization_team_members")
    op.drop_table("organization_settings")
