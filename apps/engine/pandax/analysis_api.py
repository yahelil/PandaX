"""Typed HTTP interface for release SBOM analysis jobs."""
from collections.abc import Callable, Mapping
from datetime import datetime
import logging
from typing import Annotated, Any, Literal

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

from . import exposure, telemetry
from .analysis_jobs import (
    MAX_SBOM_BYTES,
    MAX_COLLECTOR_BYTES,
    MAX_RAW_ARTIFACT_BYTES,
    AnalysisJobConflict,
    AnalysisJobError,
    AnalysisJobNotFound,
    AnalysisJobRecord,
    AnalysisJobRepository,
    AnalysisJobValidationError,
    AnalysisRunner,
    pipeline_runner,
)
from .portfolio_api import (
    PORTFOLIO_ROLES,
    IdentityDependency,
    PortfolioIdentity,
    local_identity,
)
from .organization_settings import OrganizationSettingsRepository

ANALYSIS_EDIT_ROLES = frozenset(
    {"org_admin", "compliance_operator", "security_reviewer"}
)
JobStatus = Literal["queued", "running", "completed", "failed", "unsupported"]


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SbomPreviewResponse(ApiModel):
    format: str
    version: str
    components: int
    matchable_components: int
    skipped_components: int
    product: dict[str, Any] = Field(default_factory=dict)
    collector: dict[str, Any] | None = None
    analysis_support: Literal["pending_worker"] | None = None


class EvidenceLinkResponse(ApiModel):
    name: str
    sha256: str
    href: str


class AnalysisResultResponse(ApiModel):
    components: int = 0
    findings: int = 0
    kev: int = 0
    incidents: int = 0
    input_format: str
    input_version: str
    coverage_summary: dict[str, int] = Field(default_factory=dict)
    evidence: list[EvidenceLinkResponse] = Field(default_factory=list)


class AnalysisJobResponse(ApiModel):
    id: str
    organization_id: str
    product_id: str
    release_id: str
    input_type: Literal["sbom", "collector", "raw_artifact"]
    filename: str
    media_type: str
    size_bytes: int
    sha256: str
    preview: SbomPreviewResponse
    retained_until: datetime | None
    input_metadata: dict[str, Any]
    consented_at: datetime | None
    consent_actor_id: str | None
    status: JobStatus
    stage: str
    progress: int = Field(ge=0, le=100)
    result: AnalysisResultResponse | None
    error: str | None
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class AnalysisJobEventResponse(ApiModel):
    id: str
    job_id: str
    sequence: int
    kind: str
    status: JobStatus
    stage: str
    progress: int = Field(ge=0, le=100)
    message: str
    details: dict[str, Any]
    occurred_at: datetime


RepositoryDependency = Callable[[], AnalysisJobRepository]
SettingsRepositoryDependency = Callable[[], OrganizationSettingsRepository]
JobDispatcher = Callable[[Callable[[], Any]], None]
CompletionCallback = Callable[[AnalysisJobRecord], None]
logger = logging.getLogger(__name__)


def create_analysis_router(
    repository_dependency: RepositoryDependency,
    identity_dependency: IdentityDependency = local_identity,
    runner: AnalysisRunner = pipeline_runner,
    dispatcher: JobDispatcher | None = None,
    settings_repository_dependency: SettingsRepositoryDependency | None = None,
    completion_callback: CompletionCallback | None = None,
) -> APIRouter:
    """Build tenant-scoped routes with replaceable repository, identity, and runner adapters."""
    router = APIRouter(prefix="/v1", tags=["analysis"])
    Repository = Annotated[AnalysisJobRepository, Depends(repository_dependency)]
    Identity = Annotated[PortfolioIdentity, Depends(identity_dependency)]

    def unavailable_settings_repository() -> OrganizationSettingsRepository:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "organization settings repository is unavailable")

    SettingsRepository = Annotated[
        OrganizationSettingsRepository,
        Depends(settings_repository_dependency or unavailable_settings_repository),
    ]

    @router.post(
        "/organizations/{organization_id}/products/{product_id}/releases/{release_id}/analysis-jobs",
        response_model=AnalysisJobResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def upload_sbom(
        organization_id: str,
        product_id: str,
        release_id: str,
        repository: Repository,
        identity: Identity,
        sbom: Annotated[UploadFile, File(...)],
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=128)],
        telemetry_file: Annotated[UploadFile | None, File(alias="telemetry")] = None,
        exposure_context: Annotated[UploadFile | None, File()] = None,
        changed_digest_confirmed: Annotated[bool, Form()] = False,
    ):
        _authorize(identity, organization_id, ANALYSIS_EDIT_ROLES)
        content = await sbom.read(MAX_SBOM_BYTES + 1)
        runtime_input = await _optional_json_input(telemetry_file, telemetry.MAX_BYTES)
        exposure_input = await _optional_json_input(exposure_context, exposure.MAX_BYTES)
        job = _call(
            lambda: repository.create(
                organization_id,
                product_id,
                release_id,
                filename=sbom.filename or "",
                media_type=sbom.content_type or "",
                content=content,
                idempotency_key=idempotency_key,
                actor_id=identity.actor_id,
                changed_digest_confirmed=changed_digest_confirmed,
                runtime_telemetry=runtime_input,
                exposure_context=exposure_input,
            )
        )
        return _job_response(job)

    @router.post(
        "/organizations/{organization_id}/products/{product_id}/releases/{release_id}/analysis-jobs/inputs",
        response_model=AnalysisJobResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def upload_analysis_input(
        organization_id: str,
        product_id: str,
        release_id: str,
        repository: Repository,
        identity: Identity,
        settings_repository: SettingsRepository,
        input_type: Annotated[Literal["collector", "raw_artifact"], Form(...)],
        file: Annotated[UploadFile, File(...)],
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=128)],
        telemetry_file: Annotated[UploadFile | None, File(alias="telemetry")] = None,
        exposure_context: Annotated[UploadFile | None, File()] = None,
        raw_artifact_consent: Annotated[bool, Form()] = False,
        changed_digest_confirmed: Annotated[bool, Form()] = False,
    ):
        _authorize(identity, organization_id, ANALYSIS_EDIT_ROLES)
        settings = settings_repository.get_settings(organization_id)
        maximum = MAX_COLLECTOR_BYTES if input_type == "collector" else MAX_RAW_ARTIFACT_BYTES
        content = await file.read(maximum + 1)
        runtime_input = await _optional_json_input(telemetry_file, telemetry.MAX_BYTES)
        exposure_input = await _optional_json_input(exposure_context, exposure.MAX_BYTES)
        job = _call(lambda: repository.create_input(
            organization_id, product_id, release_id,
            input_type=input_type, filename=file.filename or "",
            media_type=file.content_type or "", content=content,
            idempotency_key=idempotency_key, actor_id=identity.actor_id,
            raw_artifact_allowed=bool(settings.security["allow_raw_artifacts"]),
            raw_artifact_consent=raw_artifact_consent,
            changed_digest_confirmed=changed_digest_confirmed,
            retention_days=int(settings.security["evidence_retention_months"]) * 30,
            runtime_telemetry=runtime_input,
            exposure_context=exposure_input,
        ))
        return _job_response(job)

    @router.get(
        "/organizations/{organization_id}/products/{product_id}/releases/{release_id}/analysis-jobs",
        response_model=list[AnalysisJobResponse],
    )
    def list_jobs(
        organization_id: str,
        product_id: str,
        release_id: str,
        repository: Repository,
        identity: Identity,
    ):
        _authorize(identity, organization_id, PORTFOLIO_ROLES)
        jobs = _call(lambda: repository.list(organization_id, product_id, release_id))
        return [_job_response(job) for job in jobs]

    @router.get(
        "/organizations/{organization_id}/products/{product_id}/releases/{release_id}/analysis-jobs/{job_id}",
        response_model=AnalysisJobResponse,
    )
    def get_job(
        organization_id: str,
        product_id: str,
        release_id: str,
        job_id: str,
        repository: Repository,
        identity: Identity,
    ):
        _authorize(identity, organization_id, PORTFOLIO_ROLES)
        job = _scoped_job(repository, organization_id, product_id, release_id, job_id)
        return _job_response(job)

    @router.get(
        "/organizations/{organization_id}/products/{product_id}/releases/{release_id}/analysis-jobs/{job_id}/events",
        response_model=list[AnalysisJobEventResponse],
    )
    def list_events(
        organization_id: str,
        product_id: str,
        release_id: str,
        job_id: str,
        repository: Repository,
        identity: Identity,
    ):
        _authorize(identity, organization_id, PORTFOLIO_ROLES)
        _scoped_job(repository, organization_id, product_id, release_id, job_id)
        return _call(
            lambda: repository.events(organization_id, product_id, release_id, job_id)
        )

    @router.post(
        "/organizations/{organization_id}/products/{product_id}/releases/{release_id}/analysis-jobs/{job_id}/run",
        response_model=AnalysisJobResponse,
    )
    def run_job(
        organization_id: str,
        product_id: str,
        release_id: str,
        job_id: str,
        background_tasks: BackgroundTasks,
        repository: Repository,
        identity: Identity,
    ):
        _authorize(identity, organization_id, ANALYSIS_EDIT_ROLES)
        _scoped_job(repository, organization_id, product_id, release_id, job_id)
        job = _call(
            lambda: repository.start(organization_id, product_id, release_id, job_id)
        )
        def work() -> None:
            completed = repository.execute(
                organization_id, product_id, release_id, job_id, runner
            )
            if completed.status == "completed" and completion_callback is not None:
                try:
                    completion_callback(completed)
                except Exception:
                    logger.exception("Post-analysis monitoring enrollment failed for job %s", completed.id)
                    try:
                        repository.record_follow_up_failure(
                            organization_id,
                            product_id,
                            release_id,
                            job_id,
                            kind="analysis.monitoring_enrollment_failed",
                            message="Automatic monitoring enrollment failed and requires retry.",
                            details={"integration": "monitoring", "retry_required": True},
                        )
                    except Exception:
                        logger.exception("Could not persist monitoring enrollment failure for job %s", completed.id)
        if dispatcher is None:
            background_tasks.add_task(work)
        else:
            dispatcher(work)
        return _job_response(job)

    @router.get(
        "/organizations/{organization_id}/products/{product_id}/releases/{release_id}/analysis-jobs/{job_id}/evidence/{digest}",
        response_class=FileResponse,
    )
    def download_evidence(
        organization_id: str,
        product_id: str,
        release_id: str,
        job_id: str,
        digest: str,
        repository: Repository,
        identity: Identity,
    ):
        _authorize(identity, organization_id, PORTFOLIO_ROLES)
        _scoped_job(repository, organization_id, product_id, release_id, job_id)
        path, filename = _call(
            lambda: repository.evidence_path(
                organization_id, product_id, release_id, job_id, digest
            )
        )
        return FileResponse(path, filename=filename, media_type="application/octet-stream")

    return router


def _authorize(
    identity: PortfolioIdentity,
    organization_id: str,
    roles: frozenset[str],
) -> None:
    if identity.organization_id and identity.organization_id != organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "organization not found")
    if identity.roles.isdisjoint(roles):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")


def _scoped_job(
    repository: AnalysisJobRepository,
    organization_id: str,
    product_id: str,
    release_id: str,
    job_id: str,
) -> AnalysisJobRecord:
    return _call(
        lambda: repository.get(organization_id, product_id, release_id, job_id)
    )


def _call(operation: Callable[[], Any]):
    try:
        return operation()
    except AnalysisJobNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except AnalysisJobConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except AnalysisJobValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    except AnalysisJobError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


def _job_response(job: AnalysisJobRecord) -> dict[str, Any]:
    prefix = (
        f"/v1/organizations/{job.organization_id}/products/{job.product_id}"
        f"/releases/{job.release_id}/analysis-jobs/{job.id}/evidence"
    )
    result = _public_result(job.result, prefix) if job.result is not None else None
    return {
        "id": job.id,
        "organization_id": job.organization_id,
        "product_id": job.product_id,
        "release_id": job.release_id,
        "input_type": job.input_type,
        "filename": job.filename,
        "media_type": job.media_type,
        "size_bytes": job.size_bytes,
        "sha256": job.sha256,
        "preview": dict(job.preview),
        "retained_until": job.retained_until,
        "input_metadata": _public_input_metadata(job.input_metadata),
        "consented_at": job.consented_at,
        "consent_actor_id": job.consent_actor_id,
        "status": job.status,
        "stage": job.stage,
        "progress": job.progress,
        "result": result,
        "error": job.error,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
    }


async def _optional_json_input(
    upload: UploadFile | None, maximum: int,
) -> tuple[str, str, bytes] | None:
    if upload is None:
        return None
    content = await upload.read(maximum + 1)
    return upload.filename or "", upload.content_type or "", content


def _public_input_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    def scrub(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {str(key): scrub(item) for key, item in value.items() if key != "object_key"}
        if isinstance(value, list):
            return [scrub(item) for item in value]
        return value

    return scrub(metadata)


def _public_result(result: Mapping[str, Any], prefix: str) -> dict[str, Any]:
    evidence = []
    for item in result.get("evidence", []):
        digest = str(item.get("sha256", ""))
        if len(digest) == 64:
            evidence.append(
                {"name": str(item.get("name", "evidence")), "sha256": digest, "href": f"{prefix}/{digest}"}
            )
    return {
        "components": int(result.get("components", 0)),
        "findings": int(result.get("findings", 0)),
        "kev": int(result.get("kev", 0)),
        "incidents": int(result.get("incidents", 0)),
        "input_format": str(result.get("input_format", "")),
        "input_version": str(result.get("input_version", "")),
        "coverage_summary": dict(result.get("coverage_summary", {})),
        "evidence": evidence,
    }
