"""Create immutable regulatory documents and self-filing records."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260914_0006"
down_revision = "20260914_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "regulatory_documents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("product_id", sa.String(36), nullable=False),
        sa.Column("release_id", sa.String(36), nullable=True),
        sa.Column("case_id", sa.String(128), nullable=True),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("name", sa.String(240), nullable=False),
        sa.Column("current_revision", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["product_id", "organization_id"],
            ["portfolio_products.id", "portfolio_products.organization_id"],
            name="fk_regulatory_documents_product_scope", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["release_id", "product_id", "organization_id"],
            ["portfolio_releases.id", "portfolio_releases.product_id", "portfolio_releases.organization_id"],
            name="fk_regulatory_documents_release_scope", ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("id", "organization_id", name="uq_regulatory_documents_id_org"),
        sa.CheckConstraint("current_revision >= 1", name="ck_regulatory_documents_current_revision_positive"),
        sa.CheckConstraint(
            "kind IN ('cra_reporting_pack','conformity','sbom','vex','evidence','verification')",
            name="ck_regulatory_documents_kind",
        ),
    )
    op.create_index("ix_regulatory_documents_scope", "regulatory_documents", ["organization_id", "product_id", "release_id"])
    op.create_index("ix_regulatory_documents_updated", "regulatory_documents", ["organization_id", "updated_at"])

    op.create_table(
        "regulatory_document_revisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("document_id", sa.String(36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("format", sa.String(32), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("storage_locator", sa.String(500), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["document_id", "organization_id"],
            ["regulatory_documents.id", "regulatory_documents.organization_id"],
            name="fk_regulatory_document_revisions_document_scope", ondelete="CASCADE",
        ),
        sa.UniqueConstraint("document_id", "revision", "organization_id", name="uq_regulatory_document_revisions_scope"),
        sa.CheckConstraint("revision >= 1", name="ck_regulatory_document_revisions_revision_positive"),
        sa.CheckConstraint("size_bytes >= 0", name="ck_regulatory_document_revisions_size_nonnegative"),
        sa.CheckConstraint(
            "format IN ('pdf_a_2b','cyclonedx_json','csaf_vex','zip','json')",
            name="ck_regulatory_document_revisions_format",
        ),
        sa.CheckConstraint("char_length(content_hash) = 64", name="ck_regulatory_document_revisions_hash_length"),
    )

    op.create_table(
        "regulatory_document_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("document_id", sa.String(36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["document_id", "revision", "organization_id"],
            ["regulatory_document_revisions.document_id", "regulatory_document_revisions.revision", "regulatory_document_revisions.organization_id"],
            name="fk_regulatory_document_events_revision_scope", ondelete="CASCADE",
        ),
        sa.UniqueConstraint("document_id", "sequence", name="uq_regulatory_document_events_sequence"),
        sa.CheckConstraint("sequence >= 1", name="ck_regulatory_document_events_sequence_positive"),
        sa.CheckConstraint(
            "event_type IN ('revision_created','approval_requested','approved','rejected','superseded','self_filing_recorded')",
            name="ck_regulatory_document_events_type",
        ),
    )
    op.create_index("ix_regulatory_document_events_audit", "regulatory_document_events", ["organization_id", "document_id", "occurred_at"])

    op.create_table(
        "regulatory_self_filing_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("document_id", sa.String(36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("external_submission_reference", sa.String(240), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("receipt_evidence_locator", sa.String(500), nullable=False),
        sa.Column("receipt_content_hash", sa.String(64), nullable=True),
        sa.Column("recorded_by", sa.String(128), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["document_id", "revision", "organization_id"],
            ["regulatory_document_revisions.document_id", "regulatory_document_revisions.revision", "regulatory_document_revisions.organization_id"],
            name="fk_regulatory_self_filings_revision_scope", ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("organization_id", "external_submission_reference", name="uq_regulatory_self_filings_external_reference"),
        sa.CheckConstraint(
            "receipt_content_hash IS NULL OR char_length(receipt_content_hash) = 64",
            name="ck_regulatory_self_filings_receipt_hash_length",
        ),
    )

    if op.get_bind().dialect.name == "postgresql":
        op.execute("""
            CREATE FUNCTION prevent_regulatory_document_history_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'regulatory document history is append-only';
            END;
            $$ LANGUAGE plpgsql
        """)
        for table in ("regulatory_document_revisions", "regulatory_document_events", "regulatory_self_filing_records"):
            op.execute(f"""
                CREATE TRIGGER {table}_immutable
                BEFORE UPDATE OR DELETE ON {table}
                FOR EACH ROW EXECUTE FUNCTION prevent_regulatory_document_history_mutation()
            """)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in ("regulatory_self_filing_records", "regulatory_document_events", "regulatory_document_revisions"):
            op.execute(f"DROP TRIGGER IF EXISTS {table}_immutable ON {table}")
        op.execute("DROP FUNCTION IF EXISTS prevent_regulatory_document_history_mutation()")
    op.drop_table("regulatory_self_filing_records")
    op.drop_index("ix_regulatory_document_events_audit", table_name="regulatory_document_events")
    op.drop_table("regulatory_document_events")
    op.drop_table("regulatory_document_revisions")
    op.drop_index("ix_regulatory_documents_updated", table_name="regulatory_documents")
    op.drop_index("ix_regulatory_documents_scope", table_name="regulatory_documents")
    op.drop_table("regulatory_documents")
