"""Add membership lifecycle and chained immutable admin audit."""
from __future__ import annotations

import hashlib
import json

from alembic import op
import sqlalchemy as sa


revision = "20260915_0011"
down_revision = "20260915_0010"
branch_labels = None
depends_on = None

LEGACY_MEMBER_STATUS_CONSTRAINT = (
    "ck_organization_team_members_ck_organization_team_members_status"
)
MEMBER_STATUS_CONSTRAINT = "ck_organization_team_members_status"


def _digest(row: sa.RowMapping, previous_digest: str | None) -> str:
    occurred_at = row["occurred_at"]
    payload = {
        "id": row["id"],
        "organization_id": row["organization_id"],
        "entity_type": row["entity_type"],
        "entity_id": row["entity_id"],
        "action": row["action"],
        "version": row["version"],
        "actor_id": row["actor_id"],
        "occurred_at": occurred_at.isoformat(),
        "changes": row["changes"],
        "previous_digest": previous_digest,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def upgrade() -> None:
    bind = op.get_bind()
    with op.batch_alter_table("organization_team_members") as batch:
        batch.add_column(sa.Column("expires_at", sa.DateTime(timezone=True)))
        batch.add_column(sa.Column("revoked_at", sa.DateTime(timezone=True)))
        batch.add_column(sa.Column("removed_at", sa.DateTime(timezone=True)))
        batch.drop_constraint(op.f(LEGACY_MEMBER_STATUS_CONSTRAINT), type_="check")
        batch.create_check_constraint(
            "status",
            "status IN ('active','invited','disabled','revoked','removed')",
        )

    bind.execute(
        sa.text(
            "UPDATE organization_team_members "
            "SET revoked_at = updated_at WHERE status = 'disabled'"
        )
    )

    with op.batch_alter_table("organization_settings_audit_events") as batch:
        batch.add_column(sa.Column("previous_digest", sa.String(64)))
        batch.add_column(sa.Column("digest", sa.String(64)))

    if bind.dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER organization_settings_audit_events_immutable "
            "ON organization_settings_audit_events"
        )

    audit = sa.table(
        "organization_settings_audit_events",
        sa.column("id", sa.String),
        sa.column("organization_id", sa.String),
        sa.column("entity_type", sa.String),
        sa.column("entity_id", sa.String),
        sa.column("action", sa.String),
        sa.column("version", sa.Integer),
        sa.column("actor_id", sa.String),
        sa.column("occurred_at", sa.DateTime(timezone=True)),
        sa.column("changes", sa.JSON),
        sa.column("previous_digest", sa.String),
        sa.column("digest", sa.String),
    )
    rows = bind.execute(
        sa.select(audit).order_by(
            audit.c.organization_id, audit.c.occurred_at, audit.c.id
        )
    ).mappings()
    previous_by_organization: dict[str, str] = {}
    for row in rows:
        previous = previous_by_organization.get(row["organization_id"])
        digest = _digest(row, previous)
        bind.execute(
            sa.update(audit)
            .where(audit.c.id == row["id"])
            .values(previous_digest=previous, digest=digest)
        )
        previous_by_organization[row["organization_id"]] = digest

    if bind.dialect.name == "postgresql":
        op.execute("""
            CREATE TRIGGER organization_settings_audit_events_immutable
            BEFORE UPDATE OR DELETE ON organization_settings_audit_events
            FOR EACH ROW EXECUTE FUNCTION prevent_organization_settings_audit_mutation()
        """)

    with op.batch_alter_table("organization_settings_audit_events") as batch:
        batch.alter_column("digest", existing_type=sa.String(64), nullable=False)
        batch.create_unique_constraint(
            "uq_settings_audit_org_digest", ["organization_id", "digest"]
        )


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text(
            "UPDATE organization_team_members SET status = 'disabled' "
            "WHERE status IN ('revoked','removed')"
        )
    )
    with op.batch_alter_table("organization_settings_audit_events") as batch:
        batch.drop_constraint("uq_settings_audit_org_digest", type_="unique")
        batch.drop_column("digest")
        batch.drop_column("previous_digest")
    with op.batch_alter_table("organization_team_members") as batch:
        batch.drop_constraint(op.f(MEMBER_STATUS_CONSTRAINT), type_="check")
        batch.create_check_constraint(
            "ck_organization_team_members_status",
            "status IN ('active','invited','disabled')",
        )
        batch.drop_column("removed_at")
        batch.drop_column("revoked_at")
        batch.drop_column("expires_at")
