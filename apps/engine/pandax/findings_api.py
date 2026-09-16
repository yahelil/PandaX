"""Typed, tenant-scoped finding and decision workflow API."""
from collections.abc import Callable, Mapping
from datetime import date, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .auth import authorize_request
from .findings import (
    FindingConflict,
    FindingError,
    FindingNotFound,
    FindingRecord,
    FindingRepository,
    FindingValidationError,
    build_cyclonedx_vex,
)
from .portfolio_api import IdentityDependency, PORTFOLIO_ROLES, PortfolioIdentity, local_identity

Severity = Literal["critical", "high", "medium", "low", "unknown"]
Reachability = Literal["reachable", "not_reachable", "unknown"]
RecommendedReachability = Literal["reachable", "not_reachable", "review"]
RecommendationConfidence = Literal["high", "medium", "low"]
FindingStatus = Literal["needs_review", "open", "in_progress", "resolved"]
Decision = Literal["affected", "not_affected", "accepted_risk", "deferred"]
RemediationStatus = Literal["not_planned", "planned", "in_progress", "completed", "verified"]
Sort = Literal["priority", "severity", "newest", "last_seen", "due_date"]

DECISION_ROLES = frozenset({"org_admin", "security_reviewer"})
REMEDIATION_ROLES = frozenset({"org_admin", "security_reviewer", "compliance_operator"})


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class DecisionResponse(ApiModel):
    id: str
    finding_id: str
    organization_id: str
    decision: Decision
    rationale: str
    actor_id: str
    occurred_at: datetime
    finding_version: int


class AuditResponse(ApiModel):
    id: str
    finding_id: str
    organization_id: str
    action: str
    actor_id: str
    payload: dict[str, Any]
    occurred_at: datetime


class FindingResponse(ApiModel):
    id: str
    organization_id: str
    product_id: str
    release_id: str
    source_key: str
    reference_id: str
    cve: str | None
    component: str
    purl: str | None
    component_version: str
    title: str
    description: str
    severity: Severity
    cvss: float | None
    kev: bool
    epss: float | None
    reachability: Reachability
    reachability_evidence: dict[str, Any]
    reachability_limitations: list[str]
    recommendation_reachability: RecommendedReachability | None = None
    recommendation_confidence: RecommendationConfidence | None = None
    recommendation_reason_codes: list[str] = Field(default_factory=list)
    recommendation_review_required: bool = False
    source: str
    provenance: dict[str, Any]
    first_seen_at: datetime
    last_seen_at: datetime
    status: FindingStatus
    assignee_id: str | None
    current_decision: Decision | None
    decision_rationale: str | None
    decision_by: str | None
    decided_at: datetime | None
    remediation_plan: str | None
    remediation_status: RemediationStatus
    remediation_due_date: date | None
    verification_evidence: list[dict[str, Any]]
    version: int
    created_at: datetime
    updated_at: datetime


class FindingDetailResponse(FindingResponse):
    decision_history: list[DecisionResponse]
    audit_history: list[AuditResponse]


class AssignmentUpdate(ApiModel):
    assignee_id: str | None = Field(default=None, max_length=128)
    expected_version: int = Field(ge=1)


class DecisionCreate(ApiModel):
    decision: Decision
    rationale: str = Field(min_length=1, max_length=4000)
    expected_version: int = Field(ge=1)


class RecommendationApprovalItem(ApiModel):
    finding_id: str = Field(min_length=1, max_length=36)
    expected_version: int = Field(ge=1)


class RecommendationBatchApproval(ApiModel):
    rationale: str = Field(min_length=1, max_length=4000)
    items: list[RecommendationApprovalItem] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_unique_findings(self) -> "RecommendationBatchApproval":
        finding_ids = [item.finding_id for item in self.items]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("items must contain unique finding ids")
        return self


class RemediationUpdate(ApiModel):
    plan: str | None = Field(default=None, max_length=4000)
    status: RemediationStatus
    due_date: date | None = None
    verification_evidence: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    expected_version: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_evidence(self) -> "RemediationUpdate":
        if self.status in {"planned", "in_progress", "completed", "verified"} and not (self.plan or "").strip():
            raise ValueError("plan is required for active remediation")
        if self.status == "verified" and not self.verification_evidence:
            raise ValueError("verification_evidence is required when verified")
        return self


RepositoryDependency = Callable[[], FindingRepository]


def create_findings_router(
    repository_dependency: RepositoryDependency,
    identity_dependency: IdentityDependency = local_identity,
) -> APIRouter:
    """Build finding routes over replaceable repository and identity seams."""
    router = APIRouter(prefix="/v1", tags=["findings"])
    collection = "/organizations/{organization_id}/findings"
    release_collection = (
        "/organizations/{organization_id}/products/{product_id}"
        "/releases/{release_id}/findings"
    )

    @router.get(collection, response_model=list[FindingResponse])
    def list_organization_findings(
        organization_id: str,
        repository: Annotated[FindingRepository, Depends(repository_dependency)],
        identity: Annotated[PortfolioIdentity, Depends(identity_dependency)],
        product_id: str | None = None,
        release_id: str | None = None,
        view: Literal["needs_action", "all"] = "needs_action",
        severity: Annotated[list[Severity] | None, Query()] = None,
        finding_status: Annotated[list[FindingStatus] | None, Query(alias="status")] = None,
        kev: bool | None = None,
        reachability: Reachability | None = None,
        assignee_id: str | None = None,
        sort: Sort = "priority",
    ):
        _authorize(identity, organization_id, PORTFOLIO_ROLES)
        return _call(lambda: repository.list(
            organization_id, product_id=product_id, release_id=release_id,
            action_required=view == "needs_action", severities=severity or (),
            statuses=finding_status or (), kev=kev, reachability=reachability,
            assignee_id=assignee_id, sort=sort,
        ))

    @router.get(release_collection, response_model=list[FindingResponse])
    def list_release_findings(
        organization_id: str,
        product_id: str,
        release_id: str,
        repository: Annotated[FindingRepository, Depends(repository_dependency)],
        identity: Annotated[PortfolioIdentity, Depends(identity_dependency)],
        view: Literal["needs_action", "all"] = "needs_action",
        severity: Annotated[list[Severity] | None, Query()] = None,
        finding_status: Annotated[list[FindingStatus] | None, Query(alias="status")] = None,
        kev: bool | None = None,
        reachability: Reachability | None = None,
        assignee_id: str | None = None,
        sort: Sort = "priority",
    ):
        _authorize(identity, organization_id, PORTFOLIO_ROLES)
        return _call(lambda: repository.list(
            organization_id, product_id=product_id, release_id=release_id,
            action_required=view == "needs_action", severities=severity or (),
            statuses=finding_status or (), kev=kev, reachability=reachability,
            assignee_id=assignee_id, sort=sort,
        ))

    @router.post(
        release_collection + "/recommendations/approve",
        response_model=list[FindingResponse],
        status_code=status.HTTP_201_CREATED,
    )
    def approve_recommendations(
        body: RecommendationBatchApproval,
        organization_id: str,
        product_id: str,
        release_id: str,
        repository: Annotated[FindingRepository, Depends(repository_dependency)],
        identity: Annotated[PortfolioIdentity, Depends(identity_dependency)],
    ):
        _authorize(identity, organization_id, DECISION_ROLES, sensitive=True)
        return _call(lambda: repository.approve_not_reachable_recommendations(
            organization_id,
            product_id,
            release_id,
            [item.model_dump() for item in body.items],
            rationale=body.rationale,
            actor_id=identity.actor_id,
        ))

    @router.get(release_collection + "/vex")
    def export_reviewed_vex(
        organization_id: str,
        product_id: str,
        release_id: str,
        repository: Annotated[FindingRepository, Depends(repository_dependency)],
        identity: Annotated[PortfolioIdentity, Depends(identity_dependency)],
    ):
        _authorize(identity, organization_id, PORTFOLIO_ROLES)
        records = _call(lambda: repository.list(
            organization_id,
            product_id=product_id,
            release_id=release_id,
            action_required=False,
            sort="severity",
        ))
        return build_cyclonedx_vex(
            records, product_id=product_id, release_id=release_id
        )

    item = release_collection + "/{finding_id}"

    @router.get(item, response_model=FindingDetailResponse)
    def get_finding(
        organization_id: str,
        product_id: str,
        release_id: str,
        finding_id: str,
        repository: Annotated[FindingRepository, Depends(repository_dependency)],
        identity: Annotated[PortfolioIdentity, Depends(identity_dependency)],
    ):
        _authorize(identity, organization_id, PORTFOLIO_ROLES)
        record = _call(lambda: repository.get(organization_id, product_id, release_id, finding_id))
        return _detail(repository, record)

    @router.patch(item + "/assignment", response_model=FindingResponse)
    def assign_finding(
        body: AssignmentUpdate,
        organization_id: str,
        product_id: str,
        release_id: str,
        finding_id: str,
        repository: Annotated[FindingRepository, Depends(repository_dependency)],
        identity: Annotated[PortfolioIdentity, Depends(identity_dependency)],
    ):
        _authorize(identity, organization_id, REMEDIATION_ROLES, sensitive=True)
        return _call(lambda: repository.assign(
            organization_id, product_id, release_id, finding_id,
            assignee_id=body.assignee_id, expected_version=body.expected_version,
            actor_id=identity.actor_id,
        ))

    @router.post(item + "/decisions", response_model=FindingDetailResponse, status_code=status.HTTP_201_CREATED)
    def record_decision(
        body: DecisionCreate,
        organization_id: str,
        product_id: str,
        release_id: str,
        finding_id: str,
        repository: Annotated[FindingRepository, Depends(repository_dependency)],
        identity: Annotated[PortfolioIdentity, Depends(identity_dependency)],
    ):
        _authorize(identity, organization_id, DECISION_ROLES, sensitive=True)
        record = _call(lambda: repository.decide(
            organization_id, product_id, release_id, finding_id,
            decision=body.decision, rationale=body.rationale,
            expected_version=body.expected_version, actor_id=identity.actor_id,
        ))
        return _detail(repository, record)

    @router.put(item + "/remediation", response_model=FindingDetailResponse)
    def update_remediation(
        body: RemediationUpdate,
        organization_id: str,
        product_id: str,
        release_id: str,
        finding_id: str,
        repository: Annotated[FindingRepository, Depends(repository_dependency)],
        identity: Annotated[PortfolioIdentity, Depends(identity_dependency)],
    ):
        _authorize(identity, organization_id, REMEDIATION_ROLES, sensitive=True)
        record = _call(lambda: repository.update_remediation(
            organization_id, product_id, release_id, finding_id,
            plan=body.plan, status=body.status, due_date=body.due_date,
            verification_evidence=body.verification_evidence,
            expected_version=body.expected_version, actor_id=identity.actor_id,
        ))
        return _detail(repository, record)

    return router


def _detail(repository: FindingRepository, record: FindingRecord) -> Mapping[str, Any]:
    values = {name: getattr(record, name) for name in record.__dataclass_fields__}
    values.update({
        "recommendation_reachability": record.recommendation_reachability,
        "recommendation_confidence": record.recommendation_confidence,
        "recommendation_reason_codes": record.recommendation_reason_codes,
        "recommendation_review_required": record.recommendation_review_required,
    })
    values["decision_history"] = _call(lambda: repository.decisions(record.organization_id, record.id))
    values["audit_history"] = _call(lambda: repository.audit_history(record.organization_id, record.id))
    return values


def _authorize(
    identity: PortfolioIdentity,
    organization_id: str,
    roles: frozenset[str],
    *,
    sensitive: bool = False,
) -> None:
    authorize_request(identity, organization_id, roles, sensitive=sensitive)


def _call(operation: Callable[[], Any]):
    try:
        return operation()
    except FindingNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except FindingConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except FindingValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    except FindingError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
