"""Runtime wiring for the portfolio persistence boundary."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .analysis_jobs import AnalysisJobRepository
from .auth import OIDCAuthenticator, OIDCSettings, Principal
from .compliance import ComplianceRepository
from .documents import DocumentRepository
from .findings import FindingRepository
from .portfolio import PortfolioRepository, create_portfolio_engine
from .portfolio_api import PortfolioIdentity
from .release_monitoring import ReleaseMonitoringRepository
from .search_notifications import SearchNotificationRepository


_bearer = HTTPBearer(auto_error=False)


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


@lru_cache(maxsize=1)
def get_analysis_repository() -> AnalysisJobRepository:
    repository = AnalysisJobRepository(get_portfolio_repository().engine)
    if repository.engine.dialect.name == "sqlite":
        repository.create_schema()
    return repository


@lru_cache(maxsize=1)
def get_release_monitoring_repository() -> ReleaseMonitoringRepository:
    repository = ReleaseMonitoringRepository(get_portfolio_repository().engine)
    if repository.engine.dialect.name == "sqlite":
        repository.create_schema()
    return repository


@lru_cache(maxsize=1)
def get_finding_repository() -> FindingRepository:
    repository = FindingRepository(get_portfolio_repository().engine)
    if repository.engine.dialect.name == "sqlite":
        repository.create_schema()
    return repository


@lru_cache(maxsize=1)
def get_compliance_repository() -> ComplianceRepository:
    repository = ComplianceRepository(get_portfolio_repository().engine)
    if repository.engine.dialect.name == "sqlite":
        repository.create_schema()
    return repository


@lru_cache(maxsize=1)
def get_document_repository() -> DocumentRepository:
    repository = DocumentRepository(get_portfolio_repository().engine)
    if repository.engine.dialect.name == "sqlite":
        repository.create_schema()
    return repository


@lru_cache(maxsize=1)
def get_search_notification_repository() -> SearchNotificationRepository:
    repository = SearchNotificationRepository(get_portfolio_repository().engine)
    if repository.engine.dialect.name == "sqlite":
        repository.create_schema()
    return repository


@lru_cache(maxsize=1)
def get_oidc_authenticator() -> OIDCAuthenticator:
    return OIDCAuthenticator(OIDCSettings.from_env())


async def get_authenticated_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
) -> Principal:
    """Fail closed when OIDC is unconfigured or the bearer token is invalid."""

    try:
        authenticator = get_oidc_authenticator()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC authentication is not configured",
        ) from exc
    return await authenticator(credentials)


async def get_portfolio_identity(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
) -> PortfolioIdentity:
    principal = await get_authenticated_principal(credentials)
    return PortfolioIdentity(
        actor_id=principal.subject,
        organization_id=principal.organization_id,
        roles=frozenset(role.value for role in principal.roles),
    )


def reset_portfolio_repository() -> None:
    """Clear process wiring after configuration changes in tests or operators."""

    get_portfolio_repository.cache_clear()
    get_analysis_repository.cache_clear()
    get_release_monitoring_repository.cache_clear()
    get_finding_repository.cache_clear()
    get_compliance_repository.cache_clear()
    get_document_repository.cache_clear()
    get_search_notification_repository.cache_clear()
    get_oidc_authenticator.cache_clear()
