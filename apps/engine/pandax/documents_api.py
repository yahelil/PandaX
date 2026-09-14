"""HTTP interface for regulatory documents; storage downloads remain adapter-owned."""
from datetime import datetime
from typing import Annotated, Any, Callable, Literal, Mapping, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .auth import Principal, Role
from .documents import (
    DocumentConflict, DocumentError, DocumentNotFound, DocumentRepository,
    DocumentValidationError,
)

DocumentKind = Literal["cra_reporting_pack", "conformity", "sbom", "vex", "evidence", "verification"]
DocumentFormat = Literal["pdf_a_2b", "cyclonedx_json", "csaf_vex", "zip", "json"]
DocumentStatus = Literal["draft", "pending", "approved", "rejected", "superseded"]
DocumentSort = Literal["updated_desc", "created_desc", "name_asc", "kind_asc"]
RepositoryDependency = Callable[[], DocumentRepository]
IdentityDependency = Callable[..., Principal]
Result = TypeVar("Result")

READ_ROLES = frozenset(Role)
WRITE_ROLES = frozenset({Role.ORG_ADMIN, Role.COMPLIANCE_OPERATOR})
APPROVER_ROLES = frozenset({Role.AUTHORIZED_APPROVER})


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class RevisionInput(ApiModel):
    format: DocumentFormat
    content_hash: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    storage_locator: str = Field(min_length=1, max_length=500)
    size_bytes: int = Field(ge=0)
    provenance: dict[str, Any]


class DocumentCreate(RevisionInput):
    product_id: str = Field(min_length=1, max_length=36)
    release_id: str | None = Field(default=None, max_length=36)
    case_id: str | None = Field(default=None, max_length=128)
    name: str = Field(min_length=1, max_length=240)
    kind: DocumentKind


class RevisionCreate(RevisionInput):
    expected_current_revision: int = Field(ge=1)


class TransitionRequest(ApiModel):
    expected_status: DocumentStatus


class ApprovalRequest(TransitionRequest):
    comment: str | None = Field(default=None, max_length=1000)


class RejectionRequest(TransitionRequest):
    reason: str = Field(min_length=1, max_length=1000)


class SelfFilingCreate(ApiModel):
    external_submission_reference: str = Field(min_length=1, max_length=240)
    submitted_at: datetime
    receipt_evidence_locator: str = Field(min_length=1, max_length=500)
    receipt_content_hash: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")

    @model_validator(mode="after")
    def timezone_required(self) -> "SelfFilingCreate":
        if self.submitted_at.tzinfo is None:
            raise ValueError("submitted_at requires a timezone")
        return self


class RevisionResponse(ApiModel):
    id: str
    organization_id: str
    document_id: str
    revision: int
    format: DocumentFormat
    content_hash: str
    storage_locator: str
    size_bytes: int
    provenance: Mapping[str, Any]
    created_by: str
    created_at: datetime
    status: DocumentStatus


class EventResponse(ApiModel):
    id: str
    organization_id: str
    document_id: str
    revision: int
    sequence: int
    event_type: str
    actor_id: str
    reason: str | None
    occurred_at: datetime
    details: Mapping[str, Any]


class SelfFilingResponse(ApiModel):
    id: str
    organization_id: str
    document_id: str
    revision: int
    external_submission_reference: str
    submitted_at: datetime
    receipt_evidence_locator: str
    receipt_content_hash: str | None
    recorded_by: str
    recorded_at: datetime
    record_type: Literal["operator_recorded_external_submission"]
    actis_submitted_externally: Literal[False] = False


class DocumentResponse(ApiModel):
    id: str
    organization_id: str
    product_id: str
    release_id: str | None
    case_id: str | None
    kind: DocumentKind
    name: str
    current_revision: int
    created_by: str
    created_at: datetime
    updated_at: datetime
    status: DocumentStatus
    current: RevisionResponse


class DocumentDetailResponse(ApiModel):
    document: DocumentResponse
    revisions: tuple[RevisionResponse, ...]
    audit: tuple[EventResponse, ...]
    approval_history: tuple[EventResponse, ...]
    self_filings: tuple[SelfFilingResponse, ...]


class DownloadMetadataResponse(ApiModel):
    document_id: str
    revision: int
    filename: str
    format: DocumentFormat
    content_hash: str
    size_bytes: int
    storage_locator: str
    content_type: str
    download_type: Literal["storage_metadata_only"]


def _unauthenticated() -> Principal:
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")


def _authorize(principal: Principal, organization_id: str, roles: frozenset[Role]) -> None:
    if principal.organization_id != organization_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "organization access denied")
    if principal.roles.isdisjoint(roles):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")


def _call(operation: Callable[[], Result]) -> Result:
    try:
        return operation()
    except DocumentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except DocumentConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except DocumentValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    except DocumentError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc


def create_documents_router(
    repository_dependency: RepositoryDependency,
    identity_dependency: IdentityDependency = _unauthenticated,
) -> APIRouter:
    router = APIRouter(prefix="/v1/organizations/{organization_id}/documents", tags=["documents"])
    Repository = Annotated[DocumentRepository, Depends(repository_dependency)]
    Identity = Annotated[Principal, Depends(identity_dependency)]

    @router.get("", response_model=list[DocumentResponse])
    def list_documents(
        organization_id: str, repository: Repository, principal: Identity,
        product_id: str | None = None, release_id: str | None = None,
        kind: DocumentKind | None = None, document_status: Annotated[DocumentStatus | None, Query(alias="status")] = None,
        sort: DocumentSort = "updated_desc",
    ):
        _authorize(principal, organization_id, READ_ROLES)
        return _call(lambda: repository.list_documents(
            organization_id, product_id=product_id, release_id=release_id,
            kind=kind, status=document_status, sort=sort,
        ))

    @router.post("", response_model=DocumentDetailResponse, status_code=status.HTTP_201_CREATED)
    def create_document(body: DocumentCreate, organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, WRITE_ROLES)
        return _call(lambda: repository.create_document(
            organization_id, body.product_id, name=body.name, kind=body.kind,
            format=body.format, content_hash=body.content_hash,
            storage_locator=body.storage_locator, size_bytes=body.size_bytes,
            provenance=body.provenance, actor_id=principal.subject,
            release_id=body.release_id, case_id=body.case_id,
        ))

    @router.get("/{document_id}", response_model=DocumentDetailResponse)
    def get_document(document_id: str, organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, READ_ROLES)
        return _call(lambda: repository.get_document(organization_id, document_id))

    @router.post("/{document_id}/revisions", response_model=RevisionResponse, status_code=status.HTTP_201_CREATED)
    def add_revision(body: RevisionCreate, document_id: str, organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, WRITE_ROLES)
        return _call(lambda: repository.add_revision(
            organization_id, document_id,
            expected_current_revision=body.expected_current_revision,
            format=body.format, content_hash=body.content_hash,
            storage_locator=body.storage_locator, size_bytes=body.size_bytes,
            provenance=body.provenance, actor_id=principal.subject,
        ))

    @router.get("/{document_id}/revisions/{revision}", response_model=RevisionResponse)
    def get_revision(document_id: str, revision: int, organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, READ_ROLES)
        return _call(lambda: repository.get_revision(organization_id, document_id, revision))

    @router.get("/{document_id}/revisions/{revision}/download", response_model=DownloadMetadataResponse)
    def download_metadata(document_id: str, revision: int, organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, READ_ROLES)
        return _call(lambda: repository.download_metadata(organization_id, document_id, revision))

    @router.post("/{document_id}/revisions/{revision}/approval-request", response_model=RevisionResponse)
    def request_approval(body: ApprovalRequest, document_id: str, revision: int, organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, WRITE_ROLES)
        return _call(lambda: repository.request_approval(
            organization_id, document_id, revision,
            expected_status=body.expected_status, actor_id=principal.subject,
            comment=body.comment,
        ))

    @router.post("/{document_id}/revisions/{revision}/approve", response_model=RevisionResponse)
    def approve(body: ApprovalRequest, document_id: str, revision: int, organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, APPROVER_ROLES)
        return _call(lambda: repository.approve(
            organization_id, document_id, revision,
            expected_status=body.expected_status, actor_id=principal.subject,
            comment=body.comment,
        ))

    @router.post("/{document_id}/revisions/{revision}/reject", response_model=RevisionResponse)
    def reject(body: RejectionRequest, document_id: str, revision: int, organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, APPROVER_ROLES)
        return _call(lambda: repository.reject(
            organization_id, document_id, revision,
            expected_status=body.expected_status, actor_id=principal.subject,
            reason=body.reason,
        ))

    @router.post("/{document_id}/revisions/{revision}/self-filings", response_model=SelfFilingResponse, status_code=status.HTTP_201_CREATED)
    def record_self_filing(body: SelfFilingCreate, document_id: str, revision: int, organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, WRITE_ROLES)
        filing = _call(lambda: repository.record_self_filing(
            organization_id, document_id, revision,
            external_submission_reference=body.external_submission_reference,
            submitted_at=body.submitted_at,
            receipt_evidence_locator=body.receipt_evidence_locator,
            receipt_content_hash=body.receipt_content_hash,
            actor_id=principal.subject,
        ))
        return SelfFilingResponse.model_validate(filing)

    return router
