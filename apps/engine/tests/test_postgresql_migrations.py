from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from pandax.portfolio import PortfolioRepository


POSTGRES_URL = os.environ.get("PANDAX_TEST_POSTGRES_URL", "")
pytestmark = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="PANDAX_TEST_POSTGRES_URL is required for PostgreSQL migration rehearsals",
)


def _config() -> Config:
    root = Path(__file__).resolve().parents[3]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    config.set_main_option("sqlalchemy.url", POSTGRES_URL)
    return config


def _reset_database(engine) -> None:
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))


def _libpq_url() -> str:
    return make_url(POSTGRES_URL).set(drivername="postgresql").render_as_string(
        hide_password=False
    )


def test_postgresql_clean_upgrade_rollback_lock_and_backup_restore(tmp_path):
    engine = create_engine(POSTGRES_URL)
    config = _config()
    backup = tmp_path / "actis.dump"
    pg_dump = shutil.which("pg_dump")
    pg_restore = shutil.which("pg_restore")
    assert pg_dump and pg_restore, "PostgreSQL client tools are required for restore rehearsal"

    try:
        _reset_database(engine)
        command.upgrade(config, "20260915_0010")
        repository = PortfolioRepository(engine)
        organization = repository.create_organization(
            organization_id="restore-org",
            name="Restore Test",
            legal_name="Restore Test GmbH",
            country="DE",
            registration_number="HRB-RESTORE",
            actor_id="migration-test",
        )

        with engine.connect() as blocker:
            blocker.execute(text(
                "SELECT pg_advisory_lock(hashtext('actis'), hashtext('schema-migrations'))"
            ))
            with pytest.raises(RuntimeError, match="another Actis database migration"):
                command.upgrade(config, "head")
            with engine.connect() as observer:
                assert observer.scalar(text("SELECT version_num FROM alembic_version")) == "20260915_0010"
                assert observer.scalar(text(
                    "SELECT name FROM portfolio_organizations WHERE id = 'restore-org'"
                )) == organization.name
            blocker.execute(text(
                "SELECT pg_advisory_unlock(hashtext('actis'), hashtext('schema-migrations'))"
            ))

        command.upgrade(config, "head")
        command.downgrade(config, "20260915_0010")
        assert repository.get_organization("restore-org").name == organization.name
        command.upgrade(config, "head")

        subprocess.run(
            [pg_dump, "--format=custom", "--no-owner", "--no-privileges", "--file", str(backup), _libpq_url()],
            check=True,
            capture_output=True,
            text=True,
        )
        _reset_database(engine)
        subprocess.run(
            [pg_restore, "--no-owner", "--no-privileges", "--dbname", _libpq_url(), str(backup)],
            check=True,
            capture_output=True,
            text=True,
        )
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260917_0016"
            assert connection.scalar(text(
                "SELECT name FROM portfolio_organizations WHERE id = 'restore-org'"
            )) == organization.name
    finally:
        _reset_database(engine)
        engine.dispose()
