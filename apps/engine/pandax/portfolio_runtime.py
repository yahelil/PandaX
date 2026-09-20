"""Runtime wiring for the portfolio persistence boundary."""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Mapping
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text
from sqlalchemy.engine import Engine, make_url

from .analysis_jobs import AnalysisJobRecord, AnalysisJobRepository
from .analysis_storage import LocalAnalysisInputStorage, SupabaseAnalysisInputStorage
from .context import WORKSPACE_DIR
from .auth import OIDCAuthenticator, OIDCSettings, Principal, Role
from .compliance import ComplianceRepository
from .documents import DocumentRepository
from .domain_projections import (
    ProjectedComplianceRepository,
    ProjectedHomeReadModel,
    ProjectedSearchNotificationRepository,
)
from .findings import FindingRepository, observation_from_scan_finding
from .home import HomeReadModel
from .notification_delivery import (
    NotificationDeliveryRepository, NotificationDeliveryWorker,
    environment_secret_resolver,
)
from .organization_settings import OrganizationSettingsRepository, SettingsNotFound
from .portfolio import PortfolioRepository, create_portfolio_engine
from .portfolio_api import PortfolioIdentity
from .release_monitoring import ReleaseMonitoringRepository, ReleaseMonitoringRunner
from .search_notifications import SearchNotificationRepository


logger = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=False)

MANAGED_ENVIRONMENTS = frozenset({"staging", "beta", "production"})
DATABASE_HARD_STOP_MB = {"staging": 100, "beta": 250, "production": 350}
EXPECTED_DATABASE_REVISION = "20260920_0017"


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


def _analysis_storage():
    environment = runtime_environment()
    configured_root = os.environ.get("PANDAX_ANALYSIS_INPUT_DIR", "").strip()
    if environment in MANAGED_ENVIRONMENTS:
        if configured_root:
            raise ValueError("managed environments cannot use local analysis storage")
        endpoint = os.environ.get("PANDAX_STORAGE_URL", "").strip()
        api_key = os.environ.get("PANDAX_STORAGE_SECRET_KEY", "").strip()
        bucket = os.environ.get("PANDAX_STORAGE_BUCKET", "").strip()
        if not endpoint or not api_key or not bucket:
            raise ValueError(
                "PANDAX_STORAGE_URL, PANDAX_STORAGE_SECRET_KEY, and "
                "PANDAX_STORAGE_BUCKET are required for managed environments"
            )
        parsed = urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("PANDAX_STORAGE_URL must be an HTTPS Supabase project URL")
        return SupabaseAnalysisInputStorage(endpoint, api_key, bucket)
    root = Path(configured_root) if configured_root else Path(
        os.environ.get("PANDAX_DATA_DIR", Path.cwd() / "output" / ".pandax")
    ) / "analysis-objects"
    return LocalAnalysisInputStorage(root)


@lru_cache(maxsize=1)
def get_analysis_repository() -> AnalysisJobRepository:
    repository = AnalysisJobRepository(
        get_portfolio_repository().engine,
        _analysis_storage(),
    )
    if repository.engine.dialect.name == "sqlite":
        repository.create_schema()
    return repository


def get_document_content_reader():
    """Read a document revision's bytes from the same private bucket.

    Returned as a callable rather than an object so the documents router keeps
    depending on a function it can be handed in a test.
    """
    from .document_content import read_document_content

    def read(repository, organization_id: str, document_id: str, revision: int):
        # Resolved per call, so importing the server does not open a bucket.
        storage = get_analysis_repository().storage
        return read_document_content(repository, storage, organization_id, document_id, revision)

    return read


def get_storage_status() -> dict[str, object]:
    storage = get_analysis_repository().storage
    storage.check_ready()
    return {
        "ready": True,
        "provider": "supabase" if isinstance(storage, SupabaseAnalysisInputStorage) else "local",
    }


@lru_cache(maxsize=1)
def get_release_monitoring_repository() -> ReleaseMonitoringRepository:
    repository = ReleaseMonitoringRepository(get_portfolio_repository().engine)
    if repository.engine.dialect.name == "sqlite":
        repository.create_schema()
    return repository


@lru_cache(maxsize=1)
def get_release_monitoring_runner() -> ReleaseMonitoringRunner:
    from .release_monitoring_refresh import durable_release_monitoring_runner

    return durable_release_monitoring_runner(
        get_analysis_repository(), get_finding_repository()
    )


def enroll_completed_analysis(job: AnalysisJobRecord) -> None:
    """Project completed findings, enroll eligible releases for monitoring, and enroll generated documents."""

    _project_completed_findings(job)
    _enroll_completed_documents(job)

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


def _enroll_completed_documents(job: AnalysisJobRecord) -> None:
    """Extract compiled regulatory documents from the sealed bundle and register them in DocumentRepository."""

    result = getattr(job, "result", None)
    if not isinstance(result, Mapping) or not isinstance(result.get("bundle"), Mapping):
        return
    try:
        content, _ = get_analysis_repository().export_evidence(
            job.organization_id, job.product_id, job.release_id, job.id
        )
    except Exception as exc:
        logger.warning("could not export evidence bundle for document enrollment: %s", exc)
        return

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as bundle:
            namelist = set(bundle.namelist())
            dossier_data = None
            if "dossier.json" in namelist:
                try:
                    dossier_data = json.loads(bundle.read("dossier.json").decode("utf-8"))
                except Exception:
                    pass

            doc_specs = (
                {
                    "filename": "EU_Declaration_of_Conformity.pdf",
                    "name": "EU Declaration of Conformity",
                    "kind": "conformity",
                    "format": "pdf_a_2b",
                    "suffix": ".pdf",
                },
                {
                    "filename": "AnnexVII_Technical_Documentation.pdf",
                    "name": "Annex VII Technical Documentation",
                    "kind": "cra_reporting_pack",
                    "format": "pdf_a_2b",
                    "suffix": ".pdf",
                },
                {
                    "filename": "Simplified_EU_Declaration_of_Conformity.pdf",
                    "name": "Simplified EU Declaration of Conformity",
                    "kind": "conformity",
                    "format": "pdf_a_2b",
                    "suffix": ".pdf",
                },
            )

            completeness = "missing_inputs"
            if isinstance(dossier_data, Mapping):
                summary = dossier_data.get("summary", {})
                if isinstance(summary, Mapping) and summary.get("required_input", 1) == 0:
                    completeness = "complete"

            storage = get_analysis_repository().storage
            doc_repo = get_document_repository()

            for spec in doc_specs:
                if spec["filename"] not in namelist:
                    continue
                file_bytes = bundle.read(spec["filename"])
                content_hash = hashlib.sha256(file_bytes).hexdigest()
                size_bytes = len(file_bytes)

                existing = None
                for rec in doc_repo.list_documents(
                    job.organization_id,
                    product_id=job.product_id,
                    release_id=job.release_id,
                ):
                    if rec.name == spec["name"]:
                        existing = rec
                        break

                provenance = {
                    "generator": "analysis_pipeline",
                    "analysis_job_id": job.id,
                    "bundle_filename": spec["filename"],
                    "completeness": completeness,
                }

                if existing is None:
                    stored = storage.put_document(
                        job.organization_id,
                        job.release_id,
                        file_bytes,
                        spec["suffix"],
                    )
                    doc_repo.create_document(
                        job.organization_id,
                        job.product_id,
                        name=spec["name"],
                        kind=spec["kind"],
                        format=spec["format"],
                        content_hash=stored.sha256,
                        storage_locator=stored.object_key,
                        size_bytes=size_bytes,
                        provenance=provenance,
                        actor_id=job.actor_id or "system",
                        release_id=job.release_id,
                    )
                else:
                    if existing.current.content_hash == content_hash:
                        continue
                    stored = storage.put_document(
                        job.organization_id,
                        existing.id,
                        file_bytes,
                        spec["suffix"],
                    )
                    doc_repo.add_revision(
                        job.organization_id,
                        existing.id,
                        expected_current_revision=existing.current_revision,
                        format=spec["format"],
                        content_hash=stored.sha256,
                        storage_locator=stored.object_key,
                        size_bytes=size_bytes,
                        provenance=provenance,
                        actor_id=job.actor_id or "system",
                    )
    except Exception as exc:
        logger.warning("failed to enroll completed documents for job %s: %s", job.id, exc)


def _project_completed_findings(job: AnalysisJobRecord) -> None:
    """Load the sealed findings projection without retaining another bundle copy."""

    result = getattr(job, "result", None)
    if not isinstance(result, Mapping) or not isinstance(result.get("bundle"), Mapping):
        return
    content, _ = get_analysis_repository().export_evidence(
        job.organization_id, job.product_id, job.release_id, job.id
    )
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as bundle:
            raw = json.loads(bundle.read("findings.json"))
    except (KeyError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        raise ValueError("completed analysis bundle has invalid findings") from exc
    if not isinstance(raw, list) or any(not isinstance(item, Mapping) for item in raw):
        raise ValueError("completed analysis findings must be an array of objects")
    observations = [observation_from_scan_finding(item, job.id) for item in raw]
    get_finding_repository().upsert_from_analysis(
        job.organization_id,
        job.product_id,
        job.release_id,
        job.id,
        observations,
        actor_id=job.actor_id,
        seen_at=job.completed_at,
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
    repository = ProjectedSearchNotificationRepository(
        get_portfolio_repository().engine,
        delivery_daily_limit=_notification_daily_limit(),
    )
    if repository.engine.dialect.name == "sqlite":
        repository.create_schema()
    return repository


@lru_cache(maxsize=1)
def get_notification_delivery_repository() -> NotificationDeliveryRepository:
    return NotificationDeliveryRepository(
        get_portfolio_repository().engine, daily_limit=_notification_daily_limit()
    )


def _notification_daily_limit() -> int:
    try:
        daily_limit = int(os.environ.get("PANDAX_NOTIFICATION_DAILY_LIMIT", "500"))
    except ValueError as exc:
        raise ValueError("PANDAX_NOTIFICATION_DAILY_LIMIT must be an integer") from exc
    return daily_limit


def get_notification_delivery_worker() -> NotificationDeliveryWorker:
    return NotificationDeliveryWorker(
        get_notification_delivery_repository(), environment_secret_resolver
    )


@lru_cache(maxsize=1)
def get_home_read_model() -> HomeReadModel:
    return ProjectedHomeReadModel(
        get_portfolio_repository().engine,
        delivery_daily_limit=_notification_daily_limit(),
    )


@lru_cache(maxsize=1)
def get_organization_settings_repository() -> OrganizationSettingsRepository:
    repository = OrganizationSettingsRepository(get_portfolio_repository().engine)
    if repository.engine.dialect.name == "sqlite":
        repository.create_schema()
    return repository


@lru_cache(maxsize=1)
def get_oidc_authenticator() -> OIDCAuthenticator:
    return OIDCAuthenticator(OIDCSettings.from_env())


def _ensure_local_development_seed(organization_id: str = "org-acme-devices") -> None:
    """In local development SQLite mode, ensure default organization and admin member exist."""
    portfolio_repo = get_portfolio_repository()
    settings_repo = get_organization_settings_repository()

    try:
        portfolio_repo.get_organization(organization_id)
    except Exception:
        try:
            portfolio_repo.create_organization(
                organization_id=organization_id,
                name="Acme Devices",
                legal_name="Acme Devices Ltd.",
                country="DE",
                registration_number="DE-12345678",
                actor_id="system",
            )
        except Exception:
            pass

    try:
        settings_repo.resolve_membership("member-jane-doe", organization_id)
    except Exception:
        try:
            settings_repo.create_member(
                organization_id,
                subject="member-jane-doe",
                name="Jane Doe",
                email="jane@example.com",
                title="Lead Compliance Officer",
                initials="JD",
                roles=[role.value for role in Role],
                actor_id="system",
                status="active",
                member_id="member-jane-doe",
            )
        except Exception:
            pass


async def get_authenticated_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
) -> Principal:
    """Verify identity, then resolve tenant roles only from PostgreSQL."""

    allow_dev_token = (
        runtime_environment() != "production"
        or os.environ.get("PANDAX_ALLOW_DEV_TOKEN", "").strip().lower() in {"1", "true", "yes"}
    )
    is_dev = runtime_environment() not in MANAGED_ENVIRONMENTS or allow_dev_token
    token = credentials.credentials if credentials else None

    authenticator = None
    try:
        authenticator = get_oidc_authenticator()
    except ValueError:
        if not is_dev:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OIDC authentication is not configured",
            )

    if allow_dev_token and (token == "dev-token" or (is_dev and authenticator is None)):
        path_organization = request.path_params.get("organization_id")
        header_organization = request.headers.get("x-organization-id")
        organization_id = path_organization or header_organization or "org-acme-devices"
        _ensure_local_development_seed(organization_id)
        return Principal(
            subject="member-jane-doe",
            organization_id=organization_id,
            roles=frozenset(Role),
            reauthenticated_at=datetime.now(timezone.utc),
            session_id="local-dev-session",
        )

    if authenticator is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC authentication is not configured",
        )
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
    get_release_monitoring_runner.cache_clear()
    get_finding_repository.cache_clear()
    get_compliance_repository.cache_clear()
    get_document_repository.cache_clear()
    get_search_notification_repository.cache_clear()
    get_notification_delivery_repository.cache_clear()
    get_home_read_model.cache_clear()
    get_organization_settings_repository.cache_clear()
    get_oidc_authenticator.cache_clear()
