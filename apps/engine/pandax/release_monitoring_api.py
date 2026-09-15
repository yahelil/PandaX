"""Typed tenant-scoped HTTP interface for release monitoring."""
from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from .auth import authorize_request
from .portfolio_api import (
    PORTFOLIO_ROLES,
    IdentityDependency,
    PortfolioIdentity,
    local_identity,
)
from .release_monitoring import (
    MONITORING_SOURCES,
    MonitoringRunEventRecord,
    ReleaseMonitoringConflict,
    ReleaseMonitoringError,
    ReleaseMonitoringNotFound,
    ReleaseMonitoringRecord,
    ReleaseMonitoringRepository,
    ReleaseMonitoringRunner,
    ReleaseMonitoringValidationError,
)

MonitoringSource = Literal[
    "osv", "cisa_kev", "epss", "native_advisory", "vendor_advisory"
]
MonitoringHealth = Literal["healthy", "degraded", "failed", "inactive"]
MONITORING_EDIT_ROLES = frozenset(
    {"org_admin", "compliance_operator", "security_reviewer"}
)


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class MonitoringConfigUpdate(ApiModel):
    enabled_sources: list[MonitoringSource] = Field(min_length=1)
    cadence_minutes: int = Field(ge=5, le=43_200)
    enabled: bool = True


class MonitoringStatusResponse(ApiModel):
    organization_id: str
    product_id: str
    release_id: str
    enabled_sources: list[MonitoringSource]
    cadence_minutes: int
    enabled: bool
    health: MonitoringHealth
    next_check_at: datetime | None
    last_check_at: datetime | None
    last_success_at: datetime | None
    consecutive_failures: int
    coverage: dict[str, Any]
    limitations: list[str]
    running: bool
    created_at: datetime
    updated_at: datetime


class MonitoringRunEventResponse(ApiModel):
    id: str
    run_id: str
    sequence: int
    event_type: Literal["started", "succeeded", "failed"]
    trigger: Literal["manual", "scheduled"]
    health: MonitoringHealth
    coverage: dict[str, Any]
    limitations: list[str]
    message: str
    actor_id: str
    occurred_at: datetime


RepositoryDependency = Callable[[], ReleaseMonitoringRepository]


def create_release_monitoring_router(
    repository_dependency: RepositoryDependency,
    runner: ReleaseMonitoringRunner,
    identity_dependency: IdentityDependency = local_identity,
) -> APIRouter:
    """Build release-scoped routes over repository, runner, and identity seams."""
    router = APIRouter(prefix="/v1", tags=["release-monitoring"])
    prefix = (
        "/organizations/{organization_id}/products/{product_id}"
        "/releases/{release_id}/monitoring"
    )

    @router.get(prefix, response_model=MonitoringStatusResponse)
    def get_status(
        organization_id: str,
        product_id: str,
        release_id: str,
        repository: Annotated[ReleaseMonitoringRepository, Depends(repository_dependency)],
        identity: Annotated[PortfolioIdentity, Depends(identity_dependency)],
    ):
        _authorize(identity, organization_id, PORTFOLIO_ROLES)
        return _response(
            _call(lambda: repository.get(organization_id, product_id, release_id))
        )

    @router.put(prefix, response_model=MonitoringStatusResponse)
    def configure(
        organization_id: str,
        product_id: str,
        release_id: str,
        payload: MonitoringConfigUpdate,
        repository: Annotated[ReleaseMonitoringRepository, Depends(repository_dependency)],
        identity: Annotated[PortfolioIdentity, Depends(identity_dependency)],
    ):
        _authorize(identity, organization_id, MONITORING_EDIT_ROLES, sensitive=True)
        record = _call(
            lambda: repository.configure(
                organization_id,
                product_id,
                release_id,
                enabled_sources=payload.enabled_sources,
                cadence_minutes=payload.cadence_minutes,
                enabled=payload.enabled,
                actor_id=identity.actor_id,
            )
        )
        return _response(record)

    @router.post(
        prefix + "/runs",
        response_model=MonitoringStatusResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def run_now(
        organization_id: str,
        product_id: str,
        release_id: str,
        repository: Annotated[ReleaseMonitoringRepository, Depends(repository_dependency)],
        identity: Annotated[PortfolioIdentity, Depends(identity_dependency)],
    ):
        _authorize(identity, organization_id, MONITORING_EDIT_ROLES, sensitive=True)
        return _response(
            _call(
                lambda: repository.run_now(
                    organization_id,
                    product_id,
                    release_id,
                    runner,
                    actor_id=identity.actor_id,
                )
            )
        )

    @router.get(prefix + "/runs", response_model=list[MonitoringRunEventResponse])
    def list_runs(
        organization_id: str,
        product_id: str,
        release_id: str,
        repository: Annotated[ReleaseMonitoringRepository, Depends(repository_dependency)],
        identity: Annotated[PortfolioIdentity, Depends(identity_dependency)],
    ):
        _authorize(identity, organization_id, PORTFOLIO_ROLES)
        return _call(lambda: repository.events(organization_id, product_id, release_id))

    return router


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
    except ReleaseMonitoringNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except ReleaseMonitoringConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except ReleaseMonitoringValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    except ReleaseMonitoringError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


def _response(record: ReleaseMonitoringRecord) -> dict[str, Any]:
    return {
        "organization_id": record.organization_id,
        "product_id": record.product_id,
        "release_id": record.release_id,
        "enabled_sources": list(record.enabled_sources),
        "cadence_minutes": record.cadence_minutes,
        "enabled": record.enabled,
        "health": record.health,
        "next_check_at": record.next_check_at,
        "last_check_at": record.last_check_at,
        "last_success_at": record.last_success_at,
        "consecutive_failures": record.consecutive_failures,
        "coverage": dict(record.coverage),
        "limitations": list(record.limitations),
        "running": record.active_claim_id is not None,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }
