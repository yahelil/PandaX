"""Typed tenant and role-scoped settings and privacy-safe analytics routes."""
from contextlib import contextmanager
from datetime import datetime
import io
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
from typing import Annotated, Any, Callable, Iterator, Literal, Mapping, TypeVar
import zipfile

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .auth import Principal, Role, authorize_request
from .organization_settings import (
    OrganizationSettingsRepository, SettingsConflict, SettingsError,
    SettingsNotFound, SettingsValidationError, TrustKeyRecord,
)

RepositoryDependency = Callable[[], OrganizationSettingsRepository]
IdentityDependency = Callable[..., Principal]
Result = TypeVar("Result")
READ_ROLES = frozenset(Role)
ADMIN_ROLES = frozenset({Role.ORG_ADMIN})
ANALYTICS_READ_ROLES = frozenset({Role.ORG_ADMIN, Role.COMPLIANCE_OPERATOR})
MAX_TRUST_BUNDLE_BYTES = 50_000_000
MAX_TRUST_BUNDLE_UNCOMPRESSED_BYTES = 200_000_000
MAX_TRUST_BUNDLE_ENTRIES = 2_000
_DRIVE_PATH = re.compile(r"^[A-Za-z]:")


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


class IntegrationCreate(ApiModel):
    name: str = Field(min_length=1, max_length=200)
    type: Literal["email", "webhook", "collector", "jira"]
    description: str = Field(min_length=1, max_length=1000)
    configuration: dict[str, Any]
    status: Literal["connected", "attention", "not_connected"] = "not_connected"
    secret_reference: str | None = Field(default=None, max_length=500)


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


class TrustKeyEnrollmentRequest(ApiModel):
    key_name: str = Field(min_length=1, max_length=80)
    public_key_pem: str = Field(min_length=1, max_length=1000)
    proof_signature: str = Field(pattern=r"^[0-9a-fA-F]{128}$")
    challenge_id: str = Field(min_length=36, max_length=36)


class TrustKeyChallengeRequest(ApiModel):
    key_name: str = Field(min_length=1, max_length=80)
    public_key_pem: str = Field(min_length=1, max_length=1000)


class TrustKeyChallengeResponse(ApiModel):
    challenge_id: str
    organization_id: str
    key_name: str
    fingerprint: str
    nonce: str
    expires_at: datetime


class TrustKeyResponse(ApiModel):
    id: str
    organization_id: str
    key_name: str
    key_version: int
    algorithm: Literal["Ed25519"]
    public_key_pem: str
    fingerprint: str
    status: Literal["active", "rotated", "revoked"]
    proof_verified_at: datetime
    activated_at: datetime
    valid_until: datetime | None
    revoked_at: datetime | None
    revocation_reason: str | None
    created_by: str


class TrustKeyRevocationRequest(ApiModel):
    reason: str = Field(min_length=1, max_length=500)


class TrustVerificationResponse(ApiModel):
    schema_version: str = Field(alias="schema")
    status: Literal["trusted", "untrusted", "invalid", "incomplete"]
    ok: bool
    integrity_ok: bool
    signature_valid: bool
    signer_trust: str
    reason: str
    bundle_key_fingerprint: str | None
    trusted_key_fingerprint: str | None
    checks: list[dict[str, Any]]
    trust_policy: Literal["organization_enrolled_ed25519_v1"]
    trust_source: Literal["organization_registry"]
    trust_decision: Literal["trusted", "not_enrolled", "revoked", "expired"]
    algorithm: Literal["Ed25519"]
    key_id: str | None
    key_version: int | None
    key_status: Literal["active", "rotated", "revoked"] | None
    verified_at: datetime


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

    @router.post("/trust-keys", response_model=TrustKeyResponse, status_code=status.HTTP_201_CREATED)
    def enroll_trust_key(
        body: TrustKeyEnrollmentRequest,
        organization_id: str,
        repository: Repository,
        principal: Identity,
    ):
        _authorize(principal, organization_id, ADMIN_ROLES, sensitive=True)
        return _call(lambda: repository.enroll_trust_key(
            organization_id,
            key_name=body.key_name,
            public_key_pem=body.public_key_pem,
            proof_signature=body.proof_signature,
            challenge_id=body.challenge_id,
            actor_id=principal.subject,
        ))

    @router.post("/trust-keys/challenges", response_model=TrustKeyChallengeResponse,
                 status_code=status.HTTP_201_CREATED)
    def create_trust_key_challenge(
        body: TrustKeyChallengeRequest, organization_id: str,
        repository: Repository, principal: Identity,
    ):
        _authorize(principal, organization_id, ADMIN_ROLES, sensitive=True)
        return _call(lambda: repository.create_trust_key_challenge(
            organization_id, key_name=body.key_name,
            public_key_pem=body.public_key_pem, actor_id=principal.subject,
        ))

    @router.get("/trust-keys", response_model=list[TrustKeyResponse])
    def list_trust_keys(
        organization_id: str, repository: Repository, principal: Identity
    ):
        _authorize(principal, organization_id, READ_ROLES)
        return _call(lambda: repository.list_trust_keys(organization_id))

    @router.post("/trust-keys/{key_id}/revoke", response_model=TrustKeyResponse)
    def revoke_trust_key(
        body: TrustKeyRevocationRequest,
        key_id: str,
        organization_id: str,
        repository: Repository,
        principal: Identity,
    ):
        _authorize(principal, organization_id, ADMIN_ROLES, sensitive=True)
        return _call(lambda: repository.revoke_trust_key(
            organization_id,
            key_id,
            reason=body.reason,
            actor_id=principal.subject,
        ))

    @router.post("/trust-verifications", response_model=TrustVerificationResponse)
    async def verify_trust(
        organization_id: str,
        repository: Repository,
        principal: Identity,
        bundle: Annotated[UploadFile, File()],
    ):
        _authorize(principal, organization_id, READ_ROLES, sensitive=True)
        content = await bundle.read(MAX_TRUST_BUNDLE_BYTES + 1)
        if not content or len(content) > MAX_TRUST_BUNDLE_BYTES:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                "evidence bundle must be between 1 byte and 50 MB",
            )
        try:
            with _bundle_directory(content) as directory:
                return _call(lambda: repository.verify_registered_bundle(
                    organization_id,
                    directory,
                    actor_id=principal.subject,
                ))
        except SettingsValidationError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc

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

    @router.post("/integrations", response_model=IntegrationResponse, status_code=status.HTTP_201_CREATED)
    def create_integration(
        body: IntegrationCreate,
        organization_id: str,
        repository: Repository,
        principal: Identity,
    ):
        _authorize(principal, organization_id, ADMIN_ROLES, sensitive=True)
        return _call(lambda: repository.create_integration(
            organization_id,
            **body.model_dump(),
            actor_id=principal.subject,
        ))

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


@contextmanager
def _bundle_directory(content: bytes) -> Iterator[Path]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:
        raise SettingsValidationError("evidence bundle must be a valid ZIP archive") from exc
    with archive, tempfile.TemporaryDirectory(prefix="actis-trust-") as temporary:
        root = Path(temporary)
        seen: set[str] = set()
        total = 0
        try:
            for info in archive.infolist():
                name = info.filename.rstrip("/")
                if not name:
                    continue
                path = PurePosixPath(name)
                if (
                    "\\" in name
                    or "\x00" in name
                    or name.startswith("/")
                    or _DRIVE_PATH.match(name)
                    or any(part in {"", ".", ".."} for part in path.parts)
                ):
                    raise SettingsValidationError("evidence bundle contains an unsafe path")
                folded = path.as_posix().casefold()
                if folded in seen:
                    raise SettingsValidationError("evidence bundle contains duplicate paths")
                seen.add(folded)
                if len(seen) > MAX_TRUST_BUNDLE_ENTRIES:
                    raise SettingsValidationError("evidence bundle contains too many entries")
                if info.flag_bits & 0x1 or ((info.external_attr >> 16) & 0o170000) == stat.S_IFLNK:
                    raise SettingsValidationError("evidence bundle contains an unsupported entry")
                if info.is_dir():
                    continue
                total += info.file_size
                if total > MAX_TRUST_BUNDLE_UNCOMPRESSED_BYTES:
                    raise SettingsValidationError("evidence bundle expands beyond 200 MB")
                target = root.joinpath(*path.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with archive.open(info) as source, target.open("xb") as destination:
                    while chunk := source.read(1024 * 1024):
                        written += len(chunk)
                        if written > info.file_size:
                            raise SettingsValidationError("evidence bundle entry size is invalid")
                        destination.write(chunk)
        except (zipfile.BadZipFile, RuntimeError, EOFError) as exc:
            raise SettingsValidationError("evidence bundle is corrupt or unsupported") from exc
        yield root
