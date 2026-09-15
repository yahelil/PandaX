"""Runtime wiring for the portfolio persistence boundary."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text
from sqlalchemy.engine import Engine, make_url

from .analysis_jobs import AnalysisJobRecord, AnalysisJobRepository
from .analysis_storage import LocalAnalysisInputStorage
from .context import WORKSPACE_DIR
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

MANAGED_ENVIRONMENTS = frozenset({"staging", "beta", "production"})
DATABASE_HARD_STOP_MB = {"staging": 100, "beta": 250, "production": 350}
EXPECTED_DATABASE_REVISION = "20260915_0011"


@dataclass(frozen=True, slots=True)
class DatabaseSettings:
    environment: str
    url: str
    create_schema: bool
    hard_stop_bytes: int | None


@dataclass(frozen=True, slots=True)
class DatabaseStatus:
    ready: bool
    backend: str
    revision: str | None
    capacity: str
    used_bytes: int | None
    hard_stop_bytes: int | None

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def runtime_environment() -> str:
    value = os.environ.get("PANDAX_ENVIRONMENT", "development").strip().lower()
    if value not in {"development", "test", *MANAGED_ENVIRONMENTS}:
        raise ValueError("PANDAX_ENVIRONMENT must be development, test, staging, beta, or production")
    return value


def database_settings() -> DatabaseSettings:
    environment = runtime_environment()
    configured = os.environ.get("PANDAX_DATABASE_URL", "").strip()
    if environment in MANAGED_ENVIRONMENTS and not configured:
        raise ValueError(f"PANDAX_DATABASE_URL is required for {environment}")

    if configured:
        parsed = make_url(configured)
        if parsed.drivername == "postgresql":
            parsed = parsed.set(drivername="postgresql+psycopg")
        if environment in MANAGED_ENVIRONMENTS and parsed.get_backend_name() != "postgresql":
            raise ValueError(f"{environment} requires PostgreSQL; SQLite is development-only")
        hard_stop = None
        if environment in MANAGED_ENVIRONMENTS:
            default_mb = DATABASE_HARD_STOP_MB[environment]
            try:
                limit_mb = int(os.environ.get("PANDAX_DATABASE_HARD_STOP_MB", default_mb))
            except ValueError as exc:
                raise ValueError("PANDAX_DATABASE_HARD_STOP_MB must be an integer") from exc
            if not 1 <= limit_mb <= 350:
                raise ValueError("PANDAX_DATABASE_HARD_STOP_MB must be between 1 and 350")
            hard_stop = limit_mb * 1_000_000
        return DatabaseSettings(
            environment=environment,
            url=parsed.render_as_string(hide_password=False),
            create_schema=False,
            hard_stop_bytes=hard_stop,
        )

    data_dir = Path(os.environ.get("PANDAX_DATA_DIR", WORKSPACE_DIR / "data"))
    data_dir.mkdir(parents=True, exist_ok=True)
    return DatabaseSettings(
        environment=environment,
        url=f"sqlite:///{(data_dir / 'portfolio.sqlite3').as_posix()}",
        create_schema=True,
        hard_stop_bytes=None,
    )


def _engine_options(database_url: str) -> dict[str, object]:
    if make_url(database_url).get_backend_name() != "postgresql":
        return {}
    return {
        "pool_size": 3,
        "max_overflow": 2,
        "pool_timeout": 5,
        "pool_recycle": 300,
        "pool_pre_ping": True,
        "pool_use_lifo": True,
        "connect_args": {
            "connect_timeout": 5,
            "prepare_threshold": None,
            "options": (
                "-c statement_timeout=15000 "
                "-c lock_timeout=5000 "
                "-c idle_in_transaction_session_timeout=30000"
            ),
        },
    }


def _database_url() -> tuple[str, bool]:
    settings = database_settings()
    return settings.url, settings.create_schema


@lru_cache(maxsize=1)
def get_portfolio_repository() -> PortfolioRepository:
    """Return the process repository; configured databases require migrations."""

    settings = database_settings()
    repository = PortfolioRepository(
        create_portfolio_engine(settings.url, **_engine_options(settings.url))
    )
    if settings.create_schema:
        repository.create_schema()
    return repository


def inspect_database(engine: Engine, settings: DatabaseSettings) -> DatabaseStatus:
    if engine.dialect.name != "postgresql":
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return DatabaseStatus(True, engine.dialect.name, None, "development", None, None)

    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
        revision = connection.scalar(text("SELECT version_num FROM alembic_version"))
        used_bytes = int(connection.scalar(text("SELECT pg_database_size(current_database())")))
    hard_stop = settings.hard_stop_bytes
    ratio = used_bytes / hard_stop if hard_stop else 0
    capacity = "full" if ratio >= 1 else "restricted" if ratio >= 0.8 else "warning" if ratio >= 0.7 else "ok"
    return DatabaseStatus(
        ready=revision == EXPECTED_DATABASE_REVISION and capacity != "full",
        backend="postgresql",
        revision=str(revision) if revision is not None else None,
        capacity=capacity,
        used_bytes=used_bytes,
        hard_stop_bytes=hard_stop,
    )


def get_database_status() -> DatabaseStatus:
    settings = database_settings()
    return inspect_database(get_portfolio_repository().engine, settings)


def database_allows_background_growth() -> bool:
    try:
        return get_database_status().capacity not in {"restricted", "full"}
    except Exception:
        return False


@lru_cache(maxsize=1)
def get_analysis_repository() -> AnalysisJobRepository:
    configured = os.environ.get("PANDAX_ANALYSIS_INPUT_DIR", "").strip()
    root = Path(configured) if configured else Path(os.environ.get("PANDAX_DATA_DIR", WORKSPACE_DIR / "data")) / "analysis-objects"
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
