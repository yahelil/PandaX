from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from pandax import portfolio_runtime, server
from pandax.analysis_storage import SupabaseAnalysisInputStorage
from pandax.portfolio_runtime import DatabaseSettings, DatabaseStatus


def test_managed_environments_require_postgresql_and_bounded_capacity(monkeypatch):
    monkeypatch.setenv("PANDAX_ENVIRONMENT", "beta")
    monkeypatch.delenv("PANDAX_DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="required"):
        portfolio_runtime.database_settings()

    monkeypatch.setenv("PANDAX_DATABASE_URL", "sqlite:///beta.sqlite3")
    with pytest.raises(ValueError, match="PostgreSQL"):
        portfolio_runtime.database_settings()

    monkeypatch.setenv("PANDAX_DATABASE_URL", "postgresql://actis:secret@db.example/actis")
    settings = portfolio_runtime.database_settings()
    assert settings.url.startswith("postgresql+psycopg://")
    assert settings.hard_stop_bytes == 250_000_000

    monkeypatch.setenv("PANDAX_DATABASE_HARD_STOP_MB", "351")
    with pytest.raises(ValueError, match="between 1 and 350"):
        portfolio_runtime.database_settings()


def test_postgresql_pool_is_small_bounded_and_pooler_safe():
    options = portfolio_runtime._engine_options(
        "postgresql+psycopg://actis:secret@db.example/actis"
    )

    assert options["pool_size"] == 3
    assert options["max_overflow"] == 2
    assert options["pool_timeout"] == 5
    assert options["pool_pre_ping"] is True
    assert options["connect_args"]["prepare_threshold"] is None
    assert "statement_timeout=15000" in options["connect_args"]["options"]


def test_managed_storage_requires_private_supabase_configuration(monkeypatch):
    monkeypatch.setenv("PANDAX_ENVIRONMENT", "beta")
    for name in ("PANDAX_STORAGE_URL", "PANDAX_STORAGE_SECRET_KEY", "PANDAX_STORAGE_BUCKET"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="required"):
        portfolio_runtime._analysis_storage()

    monkeypatch.setenv("PANDAX_ANALYSIS_INPUT_DIR", "./local-objects")
    with pytest.raises(ValueError, match="cannot use local"):
        portfolio_runtime._analysis_storage()
    monkeypatch.delenv("PANDAX_ANALYSIS_INPUT_DIR")
    monkeypatch.setenv("PANDAX_STORAGE_URL", "https://project.supabase.co")
    monkeypatch.setenv("PANDAX_STORAGE_SECRET_KEY", "secret")
    monkeypatch.setenv("PANDAX_STORAGE_BUCKET", "actis-evidence")
    assert isinstance(portfolio_runtime._analysis_storage(), SupabaseAnalysisInputStorage)


def test_local_database_is_ready_without_managed_capacity(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'local.sqlite3').as_posix()}")
    status = portfolio_runtime.inspect_database(
        engine,
        DatabaseSettings("development", str(engine.url), True, None),
    )

    assert status == DatabaseStatus(True, "sqlite", None, "development", None, None)


def test_health_distinguishes_process_from_database_and_blocks_full_writes(monkeypatch):
    client = TestClient(server.api)
    full = DatabaseStatus(
        ready=False,
        backend="postgresql",
        revision=portfolio_runtime.EXPECTED_DATABASE_REVISION,
        capacity="full",
        used_bytes=250_000_000,
        hard_stop_bytes=250_000_000,
    )
    monkeypatch.setattr(portfolio_runtime, "get_database_status", lambda: full)
    monkeypatch.setenv("PANDAX_ENVIRONMENT", "beta")

    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").status_code == 503
    blocked = client.post("/v1/organizations", json={})
    assert blocked.status_code == 507
    assert blocked.json() == {"detail": "database capacity hard stop reached"}
