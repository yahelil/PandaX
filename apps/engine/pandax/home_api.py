"""Typed authenticated HTTP boundary for the Home read model."""
from datetime import datetime
from typing import Annotated, Callable, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict

from .home import (
    HomeNotFound,
    HomeReadModel,
    HomeSnapshot,
    HomeValidationError,
)
from .portfolio_api import PORTFOLIO_ROLES, PortfolioIdentity, local_identity


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class MonitoringResponse(ApiModel):
    state: Literal["healthy", "degraded", "failed", "stale", "inactive", "not_configured"]
    supported_releases: int
    configured: int
    healthy: int
    degraded: int
    failed: int
    stale: int
    inactive: int
    not_configured: int
    last_success_at: datetime | None


class CounterResponse(ApiModel):
    action_total: int
    findings_needing_action: int
    urgent_findings: int
    reachable_kev_findings: int
    compliance_actions: int
    overdue_obligations: int
    due_soon_obligations: int
    missing_evidence: int
    pending_approvals: int
    documents_needing_action: int
    monitoring_issues: int


class ActionResponse(ApiModel):
    id: str
    source_type: Literal["finding", "compliance", "monitoring", "document"]
    source_id: str
    product_id: str | None
    release_id: str | None
    product_name: str | None
    release_version: str | None
    title: str
    reason: str
    priority: Literal["urgent", "high", "normal", "low"]
    due_at: datetime | None
    score: int
    target_url: str
    updated_at: datetime


class RecentChangeResponse(ApiModel):
    id: str
    source_type: Literal["finding", "compliance", "monitoring", "document", "portfolio"]
    source_id: str
    product_id: str | None
    release_id: str | None
    title: str
    description: str
    actor_id: str
    occurred_at: datetime
    target_url: str


class HomeResponse(ApiModel):
    organization_id: str
    generated_at: datetime
    monitoring: MonitoringResponse
    counters: CounterResponse
    action_queue: tuple[ActionResponse, ...]
    recent_changes: tuple[RecentChangeResponse, ...]
    data_warnings: tuple[str, ...]


ReadModelDependency = Callable[[], HomeReadModel]
IdentityDependency = Callable[[], PortfolioIdentity]


def create_home_router(
    read_model_dependency: ReadModelDependency,
    identity_dependency: IdentityDependency = local_identity,
) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["home"])
    ReadModel = Annotated[HomeReadModel, Depends(read_model_dependency)]
    Identity = Annotated[PortfolioIdentity, Depends(identity_dependency)]

    @router.get("/organizations/{organization_id}/home", response_model=HomeResponse)
    def get_home(
        organization_id: str,
        read_model: ReadModel,
        identity: Identity,
        queue_limit: Annotated[int, Query(ge=1, le=50)] = 8,
        recent_limit: Annotated[int, Query(ge=1, le=50)] = 8,
    ) -> HomeSnapshot:
        if identity.organization_id and identity.organization_id != organization_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "organization not found")
        if identity.roles.isdisjoint(PORTFOLIO_ROLES):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        try:
            return read_model.get(
                organization_id,
                queue_limit=queue_limit,
                recent_limit=recent_limit,
            )
        except HomeNotFound as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
        except HomeValidationError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    return router
