"""Allow products to leave the active workspace without erasing records."""

from alembic import op
import sqlalchemy as sa

revision = "20260920_0017"
down_revision = "20260917_0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("portfolio_products", sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("portfolio_products", "archived_at")
