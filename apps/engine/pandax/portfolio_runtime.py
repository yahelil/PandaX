"""Runtime wiring for the portfolio persistence boundary."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from .portfolio import PortfolioRepository, create_portfolio_engine


def _database_url() -> tuple[str, bool]:
    configured = os.environ.get("PANDAX_DATABASE_URL", "").strip()
    if configured:
        return configured, False

    data_dir = Path(os.environ.get("PANDAX_DATA_DIR", Path.cwd() / "output" / ".pandax"))
    data_dir.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{(data_dir / 'portfolio.sqlite3').as_posix()}", True


@lru_cache(maxsize=1)
def get_portfolio_repository() -> PortfolioRepository:
    """Return the process repository; configured databases require migrations."""

    database_url, create_schema = _database_url()
    repository = PortfolioRepository(create_portfolio_engine(database_url))
    if create_schema:
        repository.create_schema()
    return repository


def reset_portfolio_repository() -> None:
    """Clear process wiring after configuration changes in tests or operators."""

    get_portfolio_repository.cache_clear()
