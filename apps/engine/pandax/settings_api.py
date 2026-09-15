"""Typed tenant and role-scoped settings and privacy-safe analytics routes."""
from datetime import datetime
from typing import Annotated, Any, Callable, Literal, Mapping, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .auth import Principal, Role, authorize_request
from .organization_settings import (
    OrganizationSettingsRepository, SettingsConflict, SettingsError,
    SettingsNotFound, SettingsValidationError,
)

RepositoryDependency = Callable[[], OrganizationSettingsRepository]
IdentityDependency = Callable[..., Principal]
Result = TypeVar("Result")
READ_ROLES = frozenset(Role)
ADMIN_ROLES = frozenset({Role.ORG_ADMIN})
ANALYTICS_READ_ROLES = frozenset({Role.ORG_ADMIN, Role.COMPLIANCE_OPERATOR})


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class OrganizationProfile(ApiModel):
    name: str
    legal_name: str
    country: str
    registration_number: str
    timezone: str


class OrganizationProfilePatch(ApiModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    legal_name: str | None = Field(default=None, min_length=1, max_length=240)
    country: str | None = Field(default=None, pattern=r"^[A-Za-z]{2}$")
    registration_number: str | None = Field(default=None, min_length=1, max_length=120)
    timezone: str | None = Field(default=None, min_length=1, max_length=80)


class NotificationSettings(ApiModel):
    urgent_findings: bool
    deadline_warnings: bool
    monitoring_failures: bool
    approval_requests: bool
    email_digest: Literal["off", "daily", "weekly"]


class NotificationPatch(ApiModel):
    urgent_findings: bool | None = None
    deadline_warnings: bool | None = None
    monitoring_failures: bool | None = None
    approval_requests: bool | None = None
    email_digest: Literal["off", "daily", "weekly"] | None = None


class SecuritySettings(ApiModel):
    session_timeout_minutes: int
    evidence_retention_months: int
    require_mfa: bool
    allow_raw_artifacts: bool


class SecurityPatch(ApiModel):
    session_timeout_minutes: int | None = Field(default=None, ge=5, le=1440)
    evidence_retention_months: int | None = Field(default=None, ge=1, le=240)
    require_mfa: bool | None = None
    allow_raw_artifacts: bool | None = None


class AppearanceSettings(ApiModel):
    theme: Literal["light", "dark", "system"]
    density: Literal["comfortable", "compact"]


class AppearancePatch(ApiModel):
    theme: Literal["light", "dark", "system"] | None = None
    density: Literal["comfortable", "compact"] | None = None


class AnalyticsSettings(ApiModel):
    enabled: bool
    retention_days: int


class AnalyticsPatch(ApiModel):
    enabled: bool | None = None
    retention_days: int | None = Field(default=None, ge=1, le=365)


class SettingsResponse(ApiModel):
    organization_id: str
    version: int
    organization_profile: OrganizationProfile
    notifications: NotificationSettings
    security: SecuritySettings
    appearance: AppearanceSettings
    analytics: AnalyticsSettings
    updated_by: str | None
    updated_at: datetime | None


class SettingsPatch(ApiModel):
    expected_version: int = Field(ge=0)
    organization_profile: OrganizationProfilePatch | None = None
    notifications: NotificationPatch | None = None
    security: SecurityPatch | None = None
    appearance: AppearancePatch | None = None
    analytics: AnalyticsPatch | None = None

    @model_validator(mode="after")
    def require_changes(self) -> "SettingsPatch":
        if not (self.model_fields_set - {"expected_version"}):
            raise ValueError("at least one settings section is required")
        for section in self.model_fields_set - {"expected_version"}:
            value = getattr(self, section)
            if value is None or not value.model_fields_set:
                raise ValueError(f"{section} changes are required")
        return self


class TeamMemberResponse(ApiModel):
    id: str
    organization_id: str
    subject: str
    name: str
    email: str
    title: str
    initials: str
    roles: tuple[str, ...]
    status: Literal["active", "invited", "disabled", "revoked", "removed"]
    expires_at: datetime | None
    revoked_at: datetime | None
    removed_at: datetime | None
    last_active_at: datetime | None
    version: int
    created_at: datetime
    updated_at: datetime


class TeamMemberPatch(ApiModel):
    expected_version: int = Field(ge=1)
    title: str | None = Field(default=None, min_length=1, max_length=160)
    roles: list[Role] | None = Field(default=None, min_length=1)
    status: Literal["active", "invited", "disabled", "revoked", "removed"] | None = None
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def require_changes(self) -> "TeamMemberPatch":
        if not (self.model_fields_set - {"expected_version"}):
            raise ValueError("team member changes are required")
        return self


class IntegrationResponse(ApiModel):
    id: str
    organization_id: str
    name: str
    type: Literal["email", "webhook", "collector", "jira"]
    status: Literal["connected", "attention", "not_connected"]
    description: str
    configuration: Mapping[str, Any]
    secret_reference: str | None
    last_sync_at: datetime | None
    version: int
    created_at: datetime
    updated_at: datetime


class IntegrationPatch(ApiModel):
    expected_version: int = Field(ge=1)
    status: Literal["connected", "attention", "not_connected"] | None = None
    description: str | None = Field(default=None, min_length=1, max_length=1000)
    configuration: dict[str, Any] | None = None
    secret_reference: str | None = Field(default=None, max_length=500)
    last_sync_at: datetime | None = None

    @model_validator(mode="after")
    def require_changes(self) -> "IntegrationPatch":
        if not (self.model_fields_set - {"expected_version"}):
            raise ValueError("integration changes are required")
        return self


class AnalyticsEvent(ApiModel):
    event_name: Literal["page_viewed", "workflow_completed", "feature_used", "error_observed"]
    properties: dict[str, str]
    occurred_at: datetime

    @model_validator(mode="after")
    def timezone_required(self) -> "AnalyticsEvent":
        if self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at requires a timezone")
        return self


class AnalyticsBatch(ApiModel):
    events: list[AnalyticsEvent] = Field(min_length=1, max_length=100)


class AnalyticsIngestResponse(ApiModel):
    accepted: int
    dropped: int


class AnalyticsAggregate(ApiModel):
    event_name: str
    count: int


class AuditResponse(ApiModel):
    id: str
    organization_id: str
    entity_type: str
    entity_id: str
    action: str
    version: int
    actor_id: str
    occurred_at: datetime
    changes: Mapping[str, Any]
    previous_digest: str | None
    digest: str


def _unauthenticated() -> Principal:
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")


def _authorize(
    principal: Principal,
    organization_id: str,
    roles: frozenset[Role],
    *,
    sensitive: bool = False,
) -> None:
    authorize_request(
        principal, organization_id, roles, sensitive=sensitive
    )


def _call(operation: Callable[[], Result]) -> Result:
    try:
        return operation()
    except SettingsNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except SettingsConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except SettingsValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    except SettingsError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


def create_settings_router(repository_dependency: RepositoryDependency, identity_dependency: IdentityDependency = _unauthenticated) -> APIRouter:
    router = APIRouter(prefix="/v1/organizations/{organization_id}", tags=["settings"])
    Repository = Annotated[OrganizationSettingsRepository, Depends(repository_dependency)]
    Identity = Annotated[Principal, Depends(identity_dependency)]

    @router.get("/settings", response_model=SettingsResponse)
    def get_settings(organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, READ_ROLES)
        return _call(lambda: repository.get_settings(organization_id))

    @router.patch("/settings", response_model=SettingsResponse)
    def update_settings(body: SettingsPatch, organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, ADMIN_ROLES, sensitive=True)
        patch = body.model_dump(exclude={"expected_version"}, exclude_unset=True, exclude_none=True, mode="json")
        return _call(lambda: repository.update_settings(
            organization_id, expected_version=body.expected_version,
            patch=patch, actor_id=principal.subject,
        ))

    @router.get("/settings/audit", response_model=list[AuditResponse])
    def settings_audit(organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, ADMIN_ROLES | frozenset({Role.VIEWER}))
        return _call(lambda: repository.list_audit(organization_id))

    @router.get("/team", response_model=list[TeamMemberResponse])
    def list_team(organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, READ_ROLES)
        return _call(lambda: repository.list_members(organization_id))

    @router.get("/team/{member_id}", response_model=TeamMemberResponse)
    def get_member(member_id: str, organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, READ_ROLES)
        return _call(lambda: repository.get_member(organization_id, member_id))

    @router.patch("/team/{member_id}", response_model=TeamMemberResponse)
    def update_member(body: TeamMemberPatch, member_id: str, organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, ADMIN_ROLES, sensitive=True)
        changes = body.model_dump(exclude={"expected_version"}, exclude_unset=True, mode="json")
        return _call(lambda: repository.update_member(
            organization_id, member_id, expected_version=body.expected_version,
            changes=changes, actor_id=principal.subject,
        ))

    @router.get("/integrations", response_model=list[IntegrationResponse])
    def list_integrations(organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, READ_ROLES)
        return _call(lambda: repository.list_integrations(organization_id))

    @router.get("/integrations/{integration_id}", response_model=IntegrationResponse)
    def get_integration(integration_id: str, organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, READ_ROLES)
        return _call(lambda: repository.get_integration(organization_id, integration_id))

    @router.patch("/integrations/{integration_id}", response_model=IntegrationResponse)
    def update_integration(body: IntegrationPatch, integration_id: str, organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, ADMIN_ROLES, sensitive=True)
        changes = body.model_dump(exclude={"expected_version"}, exclude_unset=True)
        return _call(lambda: repository.update_integration(
            organization_id, integration_id, expected_version=body.expected_version,
            changes=changes, actor_id=principal.subject,
        ))

    @router.post("/analytics/events", response_model=AnalyticsIngestResponse, status_code=status.HTTP_202_ACCEPTED)
    def ingest_analytics(body: AnalyticsBatch, organization_id: str, repository: Repository, principal: Identity):
        _authorize(principal, organization_id, READ_ROLES)
        events = [item.model_dump() for item in body.events]
        return _call(lambda: repository.ingest_analytics(organization_id, events))

    @router.get("/analytics/aggregates", response_model=list[AnalyticsAggregate])
    def analytics_aggregates(
        organization_id: str, repository: Repository, principal: Identity,
        since: Annotated[datetime | None, Query()] = None,
        until: Annotated[datetime | None, Query()] = None,
    ):
        _authorize(principal, organization_id, ANALYTICS_READ_ROLES)
        return _call(lambda: repository.analytics_aggregates(organization_id, since=since, until=until))

    return router
