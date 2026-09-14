"""Typed, organization-scoped HTTP API for CRA compliance obligations."""
from datetime import datetime
from typing import Annotated, Callable, Literal, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .compliance import (
    APPROVE_ROLES,
    EDIT_ROLES,
    READ_ROLES,
    ComplianceAuditRecord,
    ComplianceChanges,
    ComplianceConflict,
    ComplianceError,
    ComplianceItemRecord,
    ComplianceNotFound,
    ComplianceRepository,
    ComplianceValidationError,
)
from .portfolio_api import PortfolioIdentity, local_identity

ComplianceKind = Literal["deadline", "missing_evidence", "missing_document", "reporting_case", "approval"]
CompliancePriority = Literal["critical", "high", "medium", "low"]
ComplianceStatus = Literal["action_required", "in_progress", "pending_approval", "approved", "acknowledged", "resolved"]
ComplianceReadiness = Literal["ready", "review_required", "action_required"]
ComplianceSort = Literal["due_at", "priority", "updated_at", "status"]


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class ComplianceResponse(ApiModel):
    id: str
    organization_id: str
    product_id: str | None
    release_id: str | None
    kind: ComplianceKind
    title: str
    description: str
    priority: CompliancePriority
    status: ComplianceStatus
    readiness: ComplianceReadiness
    due_at: datetime | None
    owner_id: str | None
    source_type: str
    source_id: str
    reporting_stage: Literal["early_warning", "notification", "final_report"] | None
    self_filing_record_id: str | None
    self_filing_record_url: str | None
    approved_by: str | None
    approved_at: datetime | None
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    version: int
    created_at: datetime
    updated_at: datetime


class ComplianceUpdate(ApiModel):
    expected_version: int = Field(ge=0)
    title: str | None = Field(default=None, min_length=1, max_length=240)
    description: str | None = Field(default=None, max_length=3000)
    priority: CompliancePriority | None = None
    status: ComplianceStatus | None = None
    due_at: datetime | None = None
    clear_due_at: bool = False
    owner_id: str | None = Field(default=None, min_length=1, max_length=128)
    clear_owner: bool = False
    self_filing_record_id: str | None = Field(default=None, min_length=1, max_length=200)
    self_filing_record_url: str | None = Field(default=None, min_length=1, max_length=1000)

    @model_validator(mode="after")
    def require_change(self) -> "ComplianceUpdate":
        fields = self.model_fields_set - {"expected_version"}
        if not fields or fields <= {"clear_due_at", "clear_owner"} and not (self.clear_due_at or self.clear_owner):
            raise ValueError("at least one change is required")
        if self.due_at is not None and self.clear_due_at:
            raise ValueError("due_at and clear_due_at cannot be combined")
        if self.owner_id is not None and self.clear_owner:
            raise ValueError("owner_id and clear_owner cannot be combined")
        return self


class ComplianceApproval(ApiModel):
    expected_version: int = Field(ge=0)
    self_filing_record_id: str | None = Field(default=None, min_length=1, max_length=200)
    self_filing_record_url: str | None = Field(default=None, min_length=1, max_length=1000)


class ComplianceAuditResponse(ApiModel):
    id: str
    organization_id: str
    item_id: str
    action: str
    actor_id: str
    item_version: int
    occurred_at: datetime
    payload: dict[str, object]


RepositoryDependency = Callable[[], ComplianceRepository]
IdentityDependency = Callable[[], PortfolioIdentity]
Result = TypeVar("Result")


def _call(operation: Callable[[], Result]) -> Result:
    try:
        return operation()
    except ComplianceNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except ComplianceConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except ComplianceValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    except ComplianceError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc


def _authorize(
    identity: PortfolioIdentity,
    organization_id: str,
    roles: frozenset[str],
) -> None:
    if identity.organization_id and identity.organization_id != organization_id:
        # Tenant mismatches are hidden to prevent resource enumeration.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "organization not found")
    if identity.roles.isdisjoint(roles):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")


def create_compliance_v1_router(
    repository_dependency: RepositoryDependency,
    identity_dependency: IdentityDependency = local_identity,
) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["compliance"])
    Repository = Annotated[ComplianceRepository, Depends(repository_dependency)]
    Identity = Annotated[PortfolioIdentity, Depends(identity_dependency)]

    @router.get(
        "/organizations/{organization_id}/compliance",
        response_model=list[ComplianceResponse],
    )
    def list_compliance(
        organization_id: str,
        repository: Repository,
        identity: Identity,
        view: Literal["action", "all"] = "action",
        kind: ComplianceKind | None = None,
        item_status: Annotated[ComplianceStatus | None, Query(alias="status")] = None,
        priority: CompliancePriority | None = None,
        product_id: str | None = None,
        release_id: str | None = None,
        owner_id: str | None = None,
        sort: ComplianceSort = "due_at",
        direction: Literal["asc", "desc"] = "asc",
    ) -> list[ComplianceItemRecord]:
        _authorize(identity, organization_id, READ_ROLES)
        return _call(lambda: repository.list_items(
            organization_id,
            action_only=view == "action",
            kind=kind,
            status=item_status,
            priority=priority,
            product_id=product_id,
            release_id=release_id,
            owner_id=owner_id,
            sort=sort,
            descending=direction == "desc",
        ))

    @router.get(
        "/organizations/{organization_id}/compliance/{item_id}",
        response_model=ComplianceResponse,
    )
    def get_compliance(
        organization_id: str,
        item_id: str,
        repository: Repository,
        identity: Identity,
    ) -> ComplianceItemRecord:
        _authorize(identity, organization_id, READ_ROLES)
        return _call(lambda: repository.get_item(organization_id, item_id))

    @router.patch(
        "/organizations/{organization_id}/compliance/{item_id}",
        response_model=ComplianceResponse,
    )
    def update_compliance(
        body: ComplianceUpdate,
        organization_id: str,
        item_id: str,
        repository: Repository,
        identity: Identity,
    ) -> ComplianceItemRecord:
        _authorize(identity, organization_id, EDIT_ROLES)
        values = body.model_dump(exclude_unset=True, exclude={"expected_version"})
        return _call(lambda: repository.update_item(
            organization_id,
            item_id,
            body.expected_version,
            ComplianceChanges(**values),
            identity.actor_id,
        ))

    @router.post(
        "/organizations/{organization_id}/compliance/{item_id}/approve",
        response_model=ComplianceResponse,
    )
    def approve_compliance(
        body: ComplianceApproval,
        organization_id: str,
        item_id: str,
        repository: Repository,
        identity: Identity,
    ) -> ComplianceItemRecord:
        _authorize(identity, organization_id, APPROVE_ROLES)
        return _call(lambda: repository.approve_item(
            organization_id,
            item_id,
            body.expected_version,
            identity.actor_id,
            self_filing_record_id=body.self_filing_record_id,
            self_filing_record_url=body.self_filing_record_url,
        ))

    @router.get(
        "/organizations/{organization_id}/compliance/{item_id}/audit",
        response_model=list[ComplianceAuditResponse],
    )
    def list_compliance_audit(
        organization_id: str,
        item_id: str,
        repository: Repository,
        identity: Identity,
    ) -> list[ComplianceAuditRecord]:
        _authorize(identity, organization_id, READ_ROLES)
        return _call(lambda: repository.list_audit_events(organization_id, item_id))

    return router
