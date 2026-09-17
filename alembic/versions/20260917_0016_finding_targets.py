"""Backfill internal remediation targets for existing findings."""
from datetime import datetime, timedelta

from alembic import op
import sqlalchemy as sa

revision = "20260917_0016"
down_revision = "20260915_0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    rows = connection.execute(sa.text(
        "SELECT id, first_seen_at, severity, kev FROM findings "
        "WHERE remediation_due_date IS NULL"
    )).mappings().all()
    for row in rows:
        first_seen = row["first_seen_at"]
        if isinstance(first_seen, str):
            first_seen = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        days = 14 if row["kev"] or row["severity"] in {"critical", "high"} else 30
        connection.execute(sa.text(
            "UPDATE findings SET remediation_due_date = :due WHERE id = :id"
        ), {"id": row["id"], "due": (first_seen + timedelta(days=days)).date()})


def downgrade() -> None:
    # Existing and manually edited targets cannot safely be distinguished.
    pass
