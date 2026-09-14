"""Create organization, product, release, and audit persistence."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260914_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "portfolio_organizations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("legal_name", sa.String(240), nullable=False),
        sa.Column("country", sa.String(2), nullable=False),
        sa.Column("registration_number", sa.String(120), nullable=False),
        sa.Column("timezone", sa.String(80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "portfolio_products",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("portfolio_organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("slug", sa.String(160), nullable=False),
        sa.Column("identifier", sa.String(160), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("manufacturer", sa.String(240), nullable=False),
        sa.Column("description", sa.String(2000), nullable=False),
        sa.Column("cra_class", sa.String(32), nullable=False),
        sa.Column("classification_status", sa.String(32), nullable=False),
        sa.Column("support_start", sa.Date(), nullable=False),
        sa.Column("support_end", sa.Date(), nullable=False),
        sa.Column("owner_id", sa.String(128), nullable=True),
        sa.Column("readiness", sa.String(32), nullable=False),
        sa.Column("monitoring_health", sa.String(32), nullable=False),
        sa.Column("active_release_id", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("organization_id", "slug", name="uq_portfolio_products_org_slug"),
        sa.UniqueConstraint("organization_id", "identifier", name="uq_portfolio_products_org_identifier"),
        sa.UniqueConstraint("id", "organization_id", name="uq_portfolio_products_id_org"),
        sa.CheckConstraint("support_end >= support_start", name=op.f("ck_portfolio_products_support_period")),
    )
    op.create_table(
        "portfolio_releases",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("portfolio_organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("product_id", sa.String(36), nullable=False),
        sa.Column("version", sa.String(120), nullable=False),
        sa.Column("channel", sa.String(24), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("release_date", sa.Date(), nullable=False),
        sa.Column("support_start", sa.Date(), nullable=False),
        sa.Column("support_end", sa.Date(), nullable=False),
        sa.Column("owner_id", sa.String(128), nullable=True),
        sa.Column("readiness", sa.String(32), nullable=False),
        sa.Column("monitoring_health", sa.String(32), nullable=False),
        sa.Column("sbom_status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["product_id", "organization_id"],
            ["portfolio_products.id", "portfolio_products.organization_id"],
            name="fk_portfolio_releases_product_org",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("product_id", "version", name="uq_portfolio_releases_product_version"),
        sa.UniqueConstraint("id", "product_id", "organization_id", name="uq_portfolio_releases_id_product_org"),
        sa.CheckConstraint("support_end >= support_start", name=op.f("ck_portfolio_releases_support_period")),
    )
    op.create_foreign_key(
        "fk_portfolio_products_active_release",
        "portfolio_products",
        "portfolio_releases",
        ["active_release_id", "id", "organization_id"],
        ["id", "product_id", "organization_id"],
        ondelete="RESTRICT",
    )
    op.create_table(
        "portfolio_audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("portfolio_organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_portfolio_audit_org_entity", "portfolio_audit_events", ["organization_id", "entity_type", "entity_id", "occurred_at"])
    op.create_index("ix_portfolio_releases_org_product", "portfolio_releases", ["organization_id", "product_id", "release_date"])

    if op.get_bind().dialect.name == "postgresql":
        op.execute("""
            CREATE FUNCTION prevent_portfolio_audit_mutation() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'portfolio audit events are append-only';
            END;
            $$ LANGUAGE plpgsql
        """)
        op.execute("""
            CREATE TRIGGER portfolio_audit_events_immutable
            BEFORE UPDATE OR DELETE ON portfolio_audit_events
            FOR EACH ROW EXECUTE FUNCTION prevent_portfolio_audit_mutation()
        """)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS portfolio_audit_events_immutable ON portfolio_audit_events")
        op.execute("DROP FUNCTION IF EXISTS prevent_portfolio_audit_mutation()")
    op.drop_index("ix_portfolio_releases_org_product", table_name="portfolio_releases")
    op.drop_index("ix_portfolio_audit_org_entity", table_name="portfolio_audit_events")
    op.drop_table("portfolio_audit_events")
    op.drop_constraint("fk_portfolio_products_active_release", "portfolio_products", type_="foreignkey")
    op.drop_table("portfolio_releases")
    op.drop_table("portfolio_products")
    op.drop_table("portfolio_organizations")
