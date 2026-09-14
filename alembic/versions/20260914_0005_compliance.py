"""Add tenant-scoped CRA compliance obligations.

Revision ID: 20260914_0005
Revises: 20260914_0004
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260914_0005"
down_revision: str | None = "20260914_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "compliance_items",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("product_id", sa.String(36), nullable=True),
        sa.Column("release_id", sa.String(36), nullable=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("title", sa.String(240), nullable=False),
        sa.Column("description", sa.String(3000), nullable=False),
        sa.Column("priority", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("owner_id", sa.String(128), nullable=True),
        sa.Column("source_type", sa.String(48), nullable=False),
        sa.Column("source_id", sa.String(200), nullable=False),
        sa.Column("reporting_stage", sa.String(32), nullable=True),
        sa.Column("self_filing_record_id", sa.String(200), nullable=True),
        sa.Column("self_filing_record_url", sa.String(1000), nullable=True),
        sa.Column("approved_by", sa.String(128), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["product_id", "organization_id"],
            ["portfolio_products.id", "portfolio_products.organization_id"],
            name="fk_compliance_items_product_org",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["release_id", "product_id", "organization_id"],
            ["portfolio_releases.id", "portfolio_releases.product_id", "portfolio_releases.organization_id"],
            name="fk_compliance_items_release_product_org",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("id", "organization_id", name="uq_compliance_items_id_org"),
        sa.UniqueConstraint(
            "organization_id", "source_type", "source_id", "reporting_stage",
            name="uq_compliance_items_source_stage",
        ),
        sa.CheckConstraint("version >= 0", name="ck_compliance_items_compliance_item_version"),
    )
    op.create_index(
        "ix_compliance_items_action_queue",
        "compliance_items",
        ["organization_id", "status", "due_at"],
    )
    op.create_index(
        "ix_compliance_items_product_release",
        "compliance_items",
        ["organization_id", "product_id", "release_id"],
    )
    op.create_table(
        "compliance_audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("item_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("item_version", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["item_id", "organization_id"],
            ["compliance_items.id", "compliance_items.organization_id"],
            name="fk_compliance_audit_item_org",
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_compliance_audit_item_version",
        "compliance_audit_events",
        ["organization_id", "item_id", "item_version"],
    )


def downgrade() -> None:
    op.drop_index("ix_compliance_audit_item_version", table_name="compliance_audit_events")
    op.drop_table("compliance_audit_events")
    op.drop_index("ix_compliance_items_product_release", table_name="compliance_items")
    op.drop_index("ix_compliance_items_action_queue", table_name="compliance_items")
    op.drop_table("compliance_items")
