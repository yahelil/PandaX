"""Retain the versioned CRA classification assessment on products."""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260915_0010"
down_revision = "20260914_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("portfolio_products") as batch:
        batch.add_column(sa.Column("classification_assessment", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("portfolio_products") as batch:
        batch.drop_column("classification_assessment")
