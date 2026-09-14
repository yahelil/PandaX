"""Add durable organization notification inbox.

Revision ID: 20260914_0007
Revises: 20260914_0006
"""
from alembic import op
import sqlalchemy as sa

revision = "20260914_0007"
down_revision = "20260914_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notifications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("source_fingerprint", sa.String(160), nullable=False),
        sa.Column("content_fingerprint", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("priority", sa.String(16), nullable=False),
        sa.Column("title", sa.String(240), nullable=False),
        sa.Column("detail", sa.String(2000), nullable=False),
        sa.Column("product_id", sa.String(36), nullable=True),
        sa.Column("release_id", sa.String(36), nullable=True),
        sa.Column("target_url", sa.String(1000), nullable=False),
        sa.Column("requires_action", sa.Boolean(), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.String(128), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["product_id", "organization_id"],
            ["portfolio_products.id", "portfolio_products.organization_id"],
            name="fk_notifications_product_org", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["release_id", "product_id", "organization_id"],
            ["portfolio_releases.id", "portfolio_releases.product_id", "portfolio_releases.organization_id"],
            name="fk_notifications_release_scope", ondelete="CASCADE",
        ),
        sa.UniqueConstraint("organization_id", "source_fingerprint", name="uq_notifications_source"),
        sa.CheckConstraint("char_length(content_fingerprint) = 64", name="ck_notifications_content_fingerprint_length"),
        sa.CheckConstraint(
            "kind IN ('finding','compliance','monitoring','document','analysis','system')",
            name="ck_notifications_kind",
        ),
        sa.CheckConstraint(
            "priority IN ('critical','high','medium','low','info')",
            name="ck_notifications_priority",
        ),
        sa.CheckConstraint(
            "acknowledged_at IS NULL OR read_at IS NOT NULL",
            name="ck_notifications_acknowledged_is_read",
        ),
    )
    op.create_index(
        "ix_notifications_inbox", "notifications",
        ["organization_id", "acknowledged_at", "read_at", "priority"],
    )
    op.create_index(
        "ix_notifications_target", "notifications",
        ["organization_id", "product_id", "release_id"],
    )
    # Portable b-tree lookup support for categorized LIKE search. PostgreSQL
    # deployments may add trigram indexes after measuring real query volume.
    op.create_index("ix_portfolio_products_search", "portfolio_products", ["organization_id", "name", "identifier"])
    op.create_index("ix_portfolio_releases_search", "portfolio_releases", ["organization_id", "version"])
    op.create_index("ix_findings_search", "findings", ["organization_id", "reference_id", "component"])
    op.create_index("ix_compliance_items_search", "compliance_items", ["organization_id", "title"])
    op.create_index("ix_regulatory_documents_search", "regulatory_documents", ["organization_id", "name"])


def downgrade() -> None:
    op.drop_index("ix_regulatory_documents_search", table_name="regulatory_documents")
    op.drop_index("ix_compliance_items_search", table_name="compliance_items")
    op.drop_index("ix_findings_search", table_name="findings")
    op.drop_index("ix_portfolio_releases_search", table_name="portfolio_releases")
    op.drop_index("ix_portfolio_products_search", table_name="portfolio_products")
    op.drop_index("ix_notifications_target", table_name="notifications")
    op.drop_index("ix_notifications_inbox", table_name="notifications")
    op.drop_table("notifications")
