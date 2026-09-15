"""Require single-use, short-lived customer key enrollment challenges."""
from alembic import op
import sqlalchemy as sa

revision = "20260915_0014"
down_revision = "20260915_0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organization_trust_key_challenges",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36),
                  sa.ForeignKey("portfolio_organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key_name", sa.String(80), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("nonce", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_table("organization_trust_key_challenges")
