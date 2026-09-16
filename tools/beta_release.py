"""Guarded beta migration step for Render Free releases.

Render Free has no pre-deploy command. Run this command from the exact candidate
image after creating an external backup, then deploy that same Git revision.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

from pandax.portfolio_runtime import EXPECTED_DATABASE_REVISION
from pandax.runtime_metadata import build_metadata

REQUIRED = (
    "PANDAX_DATABASE_URL",
    "PANDAX_STORAGE_URL",
    "PANDAX_STORAGE_SECRET_KEY",
    "PANDAX_STORAGE_BUCKET",
    "PANDAX_SIGNER_PROVIDER",
    "PANDAX_SIGNING_KEY_B64",
    "PANDAX_SIGNING_KEY_ID",
    "PANDAX_SIGNING_KEY_VERSION",
    "PANDAX_OIDC_ISSUER",
    "PANDAX_OIDC_AUDIENCE",
    "PANDAX_OIDC_JWKS_URI",
    "PANDAX_SCHEDULER_SECRET",
)


def validate_environment() -> str:
    if os.environ.get("PANDAX_ENVIRONMENT") != "beta":
        raise RuntimeError("release migration requires PANDAX_ENVIRONMENT=beta")
    missing = [name for name in REQUIRED if not os.environ.get(name, "").strip()]
    if missing:
        raise RuntimeError("missing beta configuration: " + ", ".join(missing))
    url = make_url(os.environ["PANDAX_DATABASE_URL"])
    if url.get_backend_name() != "postgresql":
        raise RuntimeError("beta migration requires PostgreSQL")
    return url.set(drivername="postgresql+psycopg").render_as_string(hide_password=False)


def revision(database_url: str) -> str | None:
    engine = create_engine(database_url, connect_args={"connect_timeout": 5})
    try:
        try:
            with engine.connect() as connection:
                return connection.scalar(text("SELECT version_num FROM alembic_version"))
        except SQLAlchemyError:
            return None
    finally:
        engine.dispose()


def migrate(backup_reference: str) -> dict[str, object]:
    if not backup_reference.strip():
        raise RuntimeError("an external backup reference is required before migration")
    database_url = validate_environment()
    before = revision(database_url)
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    command.upgrade(config, "head")
    after = revision(database_url)
    if after != EXPECTED_DATABASE_REVISION:
        raise RuntimeError(f"migration ended at {after}, expected {EXPECTED_DATABASE_REVISION}")
    return {
        **build_metadata(),
        "environment": "beta",
        "backup_reference": backup_reference,
        "schema_before": before,
        "schema_after": after,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backup-reference", required=True)
    args = parser.parse_args()
    print(json.dumps(migrate(args.backup_reference), sort_keys=True))


if __name__ == "__main__":
    main()
