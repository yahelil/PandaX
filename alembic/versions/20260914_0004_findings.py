"""Add release-scoped findings and immutable review history.

Revision ID: 20260914_0004
Revises: 20260914_0003
"""
from alembic import op
import sqlalchemy as sa

revision = "20260914_0004"
down_revision = "20260914_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("product_id", sa.String(36), nullable=False),
        sa.Column("release_id", sa.String(36), nullable=False),
        sa.Column("source_key", sa.String(128), nullable=False),
        sa.Column("reference_id", sa.String(160), nullable=False),
        sa.Column("cve", sa.String(32)),
        sa.Column("component", sa.String(255), nullable=False),
        sa.Column("purl", sa.String(1000)),
        sa.Column("component_version", sa.String(255), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.String(4000), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("cvss", sa.Float()),
        sa.Column("kev", sa.Boolean(), nullable=False),
        sa.Column("epss", sa.Float()),
        sa.Column("reachability", sa.String(24), nullable=False),
        sa.Column("reachability_evidence", sa.JSON(), nullable=False),
        sa.Column("reachability_limitations", sa.JSON(), nullable=False),
        sa.Column("source", sa.String(120), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("assignee_id", sa.String(128)),
        sa.Column("current_decision", sa.String(24)),
        sa.Column("decision_rationale", sa.String(4000)),
        sa.Column("decision_by", sa.String(128)),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.Column("remediation_plan", sa.String(4000)),
        sa.Column("remediation_status", sa.String(24), nullable=False),
        sa.Column("remediation_due_date", sa.Date()),
        sa.Column("verification_evidence", sa.JSON(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["release_id", "product_id", "organization_id"],
            ["portfolio_releases.id", "portfolio_releases.product_id", "portfolio_releases.organization_id"],
            name="fk_findings_release_scope",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("release_id", "source_key", name="uq_findings_release_source_key"),
        sa.UniqueConstraint("id", "organization_id", name="uq_findings_id_org"),
        sa.CheckConstraint("version > 0", name="ck_findings_version_positive"),
        sa.CheckConstraint("severity IN ('critical','high','medium','low','unknown')", name="ck_findings_severity"),
        sa.CheckConstraint("reachability IN ('reachable','not_reachable','unknown')", name="ck_findings_reachability"),
        sa.CheckConstraint("status IN ('needs_review','open','in_progress','resolved')", name="ck_findings_status"),
        sa.CheckConstraint("cvss IS NULL OR (cvss >= 0 AND cvss <= 10)", name="ck_findings_cvss"),
        sa.CheckConstraint("epss IS NULL OR (epss >= 0 AND epss <= 1)", name="ck_findings_epss"),
    )
    op.create_index("ix_findings_action_queue", "findings", ["organization_id", "status", "severity"])
    op.create_index("ix_findings_release_seen", "findings", ["release_id", "last_seen_at"])
    op.create_table(
        "finding_decisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("finding_id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("decision", sa.String(24), nullable=False),
        sa.Column("rationale", sa.String(4000), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finding_version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id", "organization_id"], ["findings.id", "findings.organization_id"],
            name="fk_finding_decisions_finding_org", ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "decision IN ('affected','not_affected','accepted_risk','deferred')",
            name="ck_finding_decisions_decision",
        ),
    )
    op.create_index("ix_finding_decisions_history", "finding_decisions", ["finding_id", "occurred_at"])
    op.create_table(
        "finding_audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("finding_id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id", "organization_id"], ["findings.id", "findings.organization_id"],
            name="fk_finding_audit_finding_org", ondelete="CASCADE",
        ),
    )
    op.create_index("ix_finding_audit_history", "finding_audit_events", ["finding_id", "occurred_at"])

    for table in ("finding_decisions", "finding_audit_events"):
        op.execute(sa.text(f"""
            CREATE FUNCTION {table}_reject_mutation() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION '{table} is append-only';
            END;
            $$ LANGUAGE plpgsql
        """))
        op.execute(sa.text(
            f"CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION {table}_reject_mutation()"
        ))
        op.execute(sa.text(
            f"CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION {table}_reject_mutation()"
        ))


def downgrade() -> None:
    for table in ("finding_audit_events", "finding_decisions"):
        op.execute(sa.text(f"DROP TRIGGER IF EXISTS {table}_no_update ON {table}"))
        op.execute(sa.text(f"DROP TRIGGER IF EXISTS {table}_no_delete ON {table}"))
        op.execute(sa.text(f"DROP FUNCTION IF EXISTS {table}_reject_mutation()"))
    op.drop_index("ix_finding_audit_history", table_name="finding_audit_events")
    op.drop_table("finding_audit_events")
    op.drop_index("ix_finding_decisions_history", table_name="finding_decisions")
    op.drop_table("finding_decisions")
    op.drop_index("ix_findings_release_seen", table_name="findings")
    op.drop_index("ix_findings_action_queue", table_name="findings")
    op.drop_table("findings")
