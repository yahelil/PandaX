"""Add tenant-scoped customer trust-key lifecycle records."""
from alembic import op
import sqlalchemy as sa


revision = "20260915_0013"
down_revision = "20260915_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organization_trust_keys",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("key_name", sa.String(80), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("algorithm", sa.String(24), nullable=False),
        sa.Column("public_key_pem", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("proof_verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revocation_reason", sa.String(500)),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.CheckConstraint("key_version >= 1", name="ck_trust_keys_key_version_positive"),
        sa.CheckConstraint("algorithm = 'Ed25519'", name="ck_trust_keys_algorithm"),
        sa.CheckConstraint(
            "status IN ('active','rotated','revoked')",
            name="ck_trust_keys_status",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["portfolio_organizations.id"],
            name="fk_trust_keys_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_organization_trust_keys"),
        sa.UniqueConstraint(
            "organization_id",
            "key_name",
            "key_version",
            name="uq_trust_keys_name_version",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "fingerprint",
            name="uq_trust_keys_fingerprint",
        ),
    )
    op.create_index(
        "ix_trust_keys_org_name_status",
        "organization_trust_keys",
        ["organization_id", "key_name", "status"],
    )


def downgrade() -> None:
    op.drop_index("ix_trust_keys_org_name_status", table_name="organization_trust_keys")
    op.drop_table("organization_trust_keys")
