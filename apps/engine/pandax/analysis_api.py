"""Typed HTTP interface for release SBOM analysis jobs."""
from collections.abc import Callable, Mapping
from functools import partial
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Header,
    HTTPException,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

from .analysis_jobs import (
    MAX_SBOM_BYTES,
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

ANALYSIS_EDIT_ROLES = frozenset(
    {"org_admin", "compliance_operator", "security_reviewer"}
)
JobStatus = Literal["queued", "running", "completed", "failed"]


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SbomPreviewResponse(ApiModel):
    format: str
    version: str
    components: int
    matchable_components: int
    skipped_components: int
    product: dict[str, Any] = Field(default_factory=dict)


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
    filename: str
    media_type: str
    size_bytes: int
    sha256: str
    preview: SbomPreviewResponse
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
JobDispatcher = Callable[[Callable[[], Any]], None]


def create_analysis_router(
    repository_dependency: RepositoryDependency,
    identity_dependency: IdentityDependency = local_identity,
    runner: AnalysisRunner = pipeline_runner,
    dispatcher: JobDispatcher | None = None,
) -> APIRouter:
    """Build tenant-scoped routes with replaceable repository, identity, and runner adapters."""
    router = APIRouter(prefix="/v1", tags=["analysis"])
    Repository = Annotated[AnalysisJobRepository, Depends(repository_dependency)]
    Identity = Annotated[PortfolioIdentity, Depends(identity_dependency)]

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
    ):
        _authorize(identity, organization_id, ANALYSIS_EDIT_ROLES)
        content = await sbom.read(MAX_SBOM_BYTES + 1)
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
            )
        )
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
        work = partial(
            repository.execute,
            organization_id,
            product_id,
            release_id,
            job_id,
            runner,
        )
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
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    except AnalysisJobError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc


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
        "filename": job.filename,
        "media_type": job.media_type,
        "size_bytes": job.size_bytes,
        "sha256": job.sha256,
        "preview": dict(job.preview),
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
