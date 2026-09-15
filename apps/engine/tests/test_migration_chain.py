from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text


def test_production_migrations_form_one_ordered_head():
    root = Path(__file__).resolve().parents[3]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    scripts = ScriptDirectory.from_config(config)

    assert scripts.get_heads() == ["20260915_0013"]
    assert [revision.revision for revision in scripts.walk_revisions()] == [
        "20260915_0013",
        "20260915_0012",
        "20260915_0011",
        "20260915_0010",
        "20260914_0009",
        "20260914_0008",
        "20260914_0007",
        "20260914_0006",
        "20260914_0005",
        "20260914_0004",
        "20260914_0003",
        "20260914_0002",
        "20260914_0001",
    ]


def test_tenant_authorization_migration_upgrades_existing_rows(tmp_path):
    root = Path(__file__).resolve().parents[3]
    database = tmp_path / "before-tenant-authorization.sqlite3"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with engine.begin() as connection:
        connection.execute(text("""
            CREATE TABLE portfolio_organizations (
                id VARCHAR(36) PRIMARY KEY
            )
        """))
        connection.execute(text("""
            CREATE TABLE organization_team_members (
                id VARCHAR(36) PRIMARY KEY,
                organization_id VARCHAR(36) NOT NULL,
                subject VARCHAR(160) NOT NULL,
                name VARCHAR(200) NOT NULL,
                email VARCHAR(320) NOT NULL,
                title VARCHAR(160) NOT NULL,
                initials VARCHAR(8) NOT NULL,
                roles JSON NOT NULL,
                status VARCHAR(16) NOT NULL,
                last_active_at DATETIME,
                version INTEGER NOT NULL,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                CONSTRAINT ck_organization_team_members_ck_organization_team_members_status
                    CHECK (status IN ('active','invited','disabled'))
            )
        """))
        connection.execute(text("""
            CREATE TABLE organization_settings_audit_events (
                id VARCHAR(36) PRIMARY KEY,
                organization_id VARCHAR(36) NOT NULL,
                entity_type VARCHAR(40) NOT NULL,
                entity_id VARCHAR(80) NOT NULL,
                action VARCHAR(80) NOT NULL,
                version INTEGER NOT NULL,
                actor_id VARCHAR(128) NOT NULL,
                occurred_at DATETIME NOT NULL,
                changes JSON NOT NULL
            )
        """))
        connection.execute(text("""
            CREATE TABLE analysis_jobs (
                id VARCHAR(36) PRIMARY KEY,
                size_bytes INTEGER NOT NULL
            )
        """))
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) PRIMARY KEY)"))
        connection.execute(text("INSERT INTO alembic_version VALUES ('20260915_0010')"))
        connection.execute(text("INSERT INTO portfolio_organizations VALUES ('org-a')"))
        connection.execute(text("""
            INSERT INTO organization_team_members VALUES (
                'member-a', 'org-a', 'user-a', 'User A', 'a@example.test',
                'Viewer', 'UA', '["viewer"]', 'disabled', NULL, 1,
                '2026-09-14 00:00:00', '2026-09-15 00:00:00'
            )
        """))
        connection.execute(text("""
            INSERT INTO organization_settings_audit_events VALUES (
                'event-a', 'org-a', 'team_member', 'member-a',
                'team_member.created', 1, 'admin', '2026-09-15 00:00:00', '{}'
            )
        """))

    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database.as_posix()}")
    command.upgrade(config, "head")

    with engine.connect() as connection:
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "20260915_0013"
        member = connection.execute(text("SELECT revoked_at FROM organization_team_members")).one()
        audit = connection.execute(text("SELECT previous_digest, digest FROM organization_settings_audit_events")).one()
    assert member.revoked_at == "2026-09-15 00:00:00"
    assert audit.previous_digest is None
    assert len(audit.digest) == 64
    assert {column["name"] for column in inspect(engine).get_columns("organization_team_members")} >= {"expires_at", "revoked_at", "removed_at"}
