"""Runtime wiring for the portfolio persistence boundary."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .analysis_jobs import AnalysisJobRecord, AnalysisJobRepository
from .analysis_storage import LocalAnalysisInputStorage
from .auth import OIDCAuthenticator, OIDCSettings, Principal, Role
from .compliance import ComplianceRepository
from .documents import DocumentRepository
from .domain_projections import (
    ProjectedComplianceRepository,
    ProjectedHomeReadModel,
    ProjectedSearchNotificationRepository,
)
from .findings import FindingRepository
from .home import HomeReadModel
from .organization_settings import OrganizationSettingsRepository, SettingsNotFound
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
    configured = os.environ.get("PANDAX_ANALYSIS_INPUT_DIR", "").strip()
    root = Path(configured) if configured else Path(os.environ.get("PANDAX_DATA_DIR", Path.cwd() / "output" / ".pandax")) / "analysis-objects"
    repository = AnalysisJobRepository(
        get_portfolio_repository().engine,
        LocalAnalysisInputStorage(root),
    )
    if repository.engine.dialect.name == "sqlite":
        repository.create_schema()
    return repository


@lru_cache(maxsize=1)
def get_release_monitoring_repository() -> ReleaseMonitoringRepository:
    repository = ReleaseMonitoringRepository(get_portfolio_repository().engine)
    if repository.engine.dialect.name == "sqlite":
        repository.create_schema()
    return repository


def enroll_completed_analysis(job: AnalysisJobRecord) -> None:
    """Enroll eligible releases in the standard hourly monitoring policy."""

    release = get_portfolio_repository().get_release(job.organization_id, job.release_id)
    if release.status not in {"active", "supported"}:
        return
    get_release_monitoring_repository().configure(
        job.organization_id,
        job.product_id,
        job.release_id,
        enabled_sources=("osv", "cisa_kev", "epss"),
        cadence_minutes=60,
        enabled=True,
        actor_id=job.actor_id,
    )


@lru_cache(maxsize=1)
def get_finding_repository() -> FindingRepository:
    repository = FindingRepository(get_portfolio_repository().engine)
    if repository.engine.dialect.name == "sqlite":
        repository.create_schema()
    return repository


@lru_cache(maxsize=1)
def get_compliance_repository() -> ComplianceRepository:
    repository = ProjectedComplianceRepository(get_portfolio_repository().engine)
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
    repository = ProjectedSearchNotificationRepository(get_portfolio_repository().engine)
    if repository.engine.dialect.name == "sqlite":
        repository.create_schema()
    return repository


@lru_cache(maxsize=1)
def get_home_read_model() -> HomeReadModel:
    return ProjectedHomeReadModel(get_portfolio_repository().engine)


@lru_cache(maxsize=1)
def get_organization_settings_repository() -> OrganizationSettingsRepository:
    repository = OrganizationSettingsRepository(get_portfolio_repository().engine)
    if repository.engine.dialect.name == "sqlite":
        repository.create_schema()
    return repository


@lru_cache(maxsize=1)
def get_oidc_authenticator() -> OIDCAuthenticator:
    return OIDCAuthenticator(OIDCSettings.from_env())


async def get_authenticated_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
) -> Principal:
    """Verify identity, then resolve tenant roles only from PostgreSQL."""

    try:
        authenticator = get_oidc_authenticator()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC authentication is not configured",
        ) from exc
    identity = await authenticator(credentials)
    path_organization = request.path_params.get("organization_id")
    header_organization = request.headers.get("x-organization-id")
    if (
        path_organization
        and header_organization
        and path_organization != header_organization
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "organization not found")
    organization_id = (
        path_organization or header_organization or identity.organization_hint
    )
    if not organization_id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "an organization context is required",
        )
    try:
        membership = get_organization_settings_repository().resolve_membership(
            identity.subject,
            organization_id,
        )
    except SettingsNotFound as exc:
        code = status.HTTP_404_NOT_FOUND if path_organization else status.HTTP_403_FORBIDDEN
        raise HTTPException(code, "organization access denied") from exc
    return Principal(
        subject=identity.subject,
        organization_id=organization_id,
        roles=frozenset(Role(role) for role in membership.roles),
        reauthenticated_at=identity.reauthenticated_at,
        session_id=identity.session_id,
    )


async def get_portfolio_identity(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
) -> PortfolioIdentity:
    principal = await get_authenticated_principal(request, credentials)
    return PortfolioIdentity(
        actor_id=principal.subject,
        organization_id=principal.organization_id,
        roles=frozenset(role.value for role in principal.roles),
        reauthenticated_at=principal.reauthenticated_at,
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
    get_home_read_model.cache_clear()
    get_organization_settings_repository.cache_clear()
    get_oidc_authenticator.cache_clear()
