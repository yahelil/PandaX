"""Organization policy, access, integrations, and privacy-safe analytics."""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy import (
    JSON, Boolean, CheckConstraint, Column, DateTime, Engine, ForeignKey, Index, Integer,
    String, Table, Text, UniqueConstraint, func, insert, select, update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import Role
from .evidence import canonical, public_key_fingerprint, verify_bundle
from .portfolio import organizations, portfolio_metadata


class SettingsError(RuntimeError):
    pass


class SettingsNotFound(SettingsError):
    pass


class SettingsConflict(SettingsError):
    pass


class SettingsValidationError(SettingsError):
    pass


def _col(name: str, length_or_type: Any, *args: Any, **kwargs: Any) -> Column[Any]:
    return Column(name, String(length_or_type) if isinstance(length_or_type, int) else length_or_type, *args, **kwargs)


organization_settings = Table(
    "organization_settings", portfolio_metadata,
    _col("organization_id", 36, ForeignKey(organizations.c.id, ondelete="CASCADE"), primary_key=True),
    _col("version", Integer, nullable=False),
    _col("urgent_findings", Boolean, nullable=False),
    _col("deadline_warnings", Boolean, nullable=False),
    _col("monitoring_failures", Boolean, nullable=False),
    _col("approval_requests", Boolean, nullable=False),
    _col("email_digest", 16, nullable=False),
    _col("session_timeout_minutes", Integer, nullable=False),
    _col("evidence_retention_months", Integer, nullable=False),
    _col("require_mfa", Boolean, nullable=False),
    _col("allow_raw_artifacts", Boolean, nullable=False),
    _col("theme", 16, nullable=False),
    _col("density", 16, nullable=False),
    _col("analytics_enabled", Boolean, nullable=False),
    _col("analytics_retention_days", Integer, nullable=False),
    _col("updated_by", 128, nullable=False),
    _col("updated_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("version >= 1", name="version_positive"),
    CheckConstraint("email_digest IN ('off','daily','weekly')", name="email_digest"),
    CheckConstraint("theme IN ('light','dark','system')", name="theme"),
    CheckConstraint("density IN ('comfortable','compact')", name="density"),
    CheckConstraint("session_timeout_minutes BETWEEN 5 AND 1440", name="session_timeout"),
    CheckConstraint("evidence_retention_months BETWEEN 1 AND 240", name="evidence_retention"),
    CheckConstraint("analytics_retention_days BETWEEN 1 AND 365", name="analytics_retention"),
)

team_members = Table(
    "organization_team_members", portfolio_metadata,
    _col("id", 36, primary_key=True),
    _col("organization_id", 36, ForeignKey(organizations.c.id, ondelete="CASCADE"), nullable=False),
    _col("subject", 160, nullable=False),
    _col("name", 200, nullable=False),
    _col("email", 320, nullable=False),
    _col("title", 160, nullable=False),
    _col("initials", 8, nullable=False),
    _col("roles", JSON, nullable=False),
    _col("status", 16, nullable=False),
    _col("expires_at", DateTime(timezone=True), nullable=True),
    _col("revoked_at", DateTime(timezone=True), nullable=True),
    _col("removed_at", DateTime(timezone=True), nullable=True),
    _col("last_active_at", DateTime(timezone=True), nullable=True),
    _col("version", Integer, nullable=False),
    _col("created_at", DateTime(timezone=True), nullable=False),
    _col("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("organization_id", "subject", name="uq_organization_team_members_subject"),
    UniqueConstraint("organization_id", "email", name="uq_organization_team_members_email"),
    CheckConstraint(
        "status IN ('active','invited','disabled','revoked','removed')",
        name="status",
    ),
    CheckConstraint("version >= 1", name="version_positive"),
)

integrations = Table(
    "organization_integrations", portfolio_metadata,
    _col("id", 36, primary_key=True),
    _col("organization_id", 36, ForeignKey(organizations.c.id, ondelete="CASCADE"), nullable=False),
    _col("name", 200, nullable=False),
    _col("type", 24, nullable=False),
    _col("status", 24, nullable=False),
    _col("description", 1000, nullable=False),
    _col("configuration", JSON, nullable=False),
    _col("secret_reference", 500, nullable=True),
    _col("last_sync_at", DateTime(timezone=True), nullable=True),
    _col("version", Integer, nullable=False),
    _col("created_at", DateTime(timezone=True), nullable=False),
    _col("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("organization_id", "name", name="uq_organization_integrations_name"),
    CheckConstraint("type IN ('email','webhook','collector','jira')", name="type"),
    CheckConstraint("status IN ('connected','attention','not_connected')", name="status"),
    CheckConstraint("version >= 1", name="version_positive"),
    CheckConstraint("secret_reference IS NULL OR secret_reference LIKE 'vault://%' OR secret_reference LIKE 'aws-secrets://%' OR secret_reference LIKE 'gcp-secret://%' OR secret_reference LIKE 'azure-keyvault://%'", name="external_secret_reference"),
)

settings_audit_events = Table(
    "organization_settings_audit_events", portfolio_metadata,
    _col("id", 36, primary_key=True),
    _col("organization_id", 36, ForeignKey(organizations.c.id, ondelete="CASCADE"), nullable=False),
    _col("entity_type", 32, nullable=False),
    _col("entity_id", 128, nullable=False),
    _col("action", 64, nullable=False),
    _col("version", Integer, nullable=False),
    _col("actor_id", 128, nullable=False),
    _col("occurred_at", DateTime(timezone=True), nullable=False),
    _col("changes", JSON, nullable=False),
    _col("previous_digest", 64, nullable=True),
    _col("digest", 64, nullable=False),
    UniqueConstraint("organization_id", "digest", name="uq_settings_audit_org_digest"),
    CheckConstraint("version >= 1", name="version_positive"),
)

trust_keys = Table(
    "organization_trust_keys", portfolio_metadata,
    _col("id", 36, primary_key=True),
    _col("organization_id", 36, ForeignKey(organizations.c.id, ondelete="CASCADE"), nullable=False),
    _col("key_name", 80, nullable=False),
    _col("key_version", Integer, nullable=False),
    _col("algorithm", 24, nullable=False),
    _col("public_key_pem", Text, nullable=False),
    _col("fingerprint", 64, nullable=False),
    _col("status", 16, nullable=False),
    _col("proof_verified_at", DateTime(timezone=True), nullable=False),
    _col("activated_at", DateTime(timezone=True), nullable=False),
    _col("valid_until", DateTime(timezone=True), nullable=True),
    _col("revoked_at", DateTime(timezone=True), nullable=True),
    _col("revocation_reason", 500, nullable=True),
    _col("created_by", 128, nullable=False),
    UniqueConstraint("organization_id", "key_name", "key_version", name="uq_trust_keys_name_version"),
    UniqueConstraint("organization_id", "fingerprint", name="uq_trust_keys_fingerprint"),
    CheckConstraint("key_version >= 1", name="key_version_positive"),
    CheckConstraint("algorithm = 'Ed25519'", name="algorithm"),
    CheckConstraint("status IN ('active','rotated','revoked')", name="status"),
)
Index(
    "ix_trust_keys_org_name_status",
    trust_keys.c.organization_id,
    trust_keys.c.key_name,
    trust_keys.c.status,
)

trust_key_challenges = Table(
    "organization_trust_key_challenges", portfolio_metadata,
    _col("id", 36, primary_key=True),
    _col("organization_id", 36, ForeignKey(organizations.c.id, ondelete="CASCADE"), nullable=False),
    _col("key_name", 80, nullable=False),
    _col("fingerprint", 64, nullable=False),
    _col("nonce", 64, nullable=False),
    _col("created_by", 128, nullable=False),
    _col("expires_at", DateTime(timezone=True), nullable=False),
    _col("consumed_at", DateTime(timezone=True), nullable=True),
)

analytics_events = Table(
    "privacy_safe_analytics_events", portfolio_metadata,
    _col("id", 36, primary_key=True),
    _col("organization_id", 36, ForeignKey(organizations.c.id, ondelete="CASCADE"), nullable=False),
    _col("event_name", 40, nullable=False),
    _col("properties", JSON, nullable=False),
    _col("occurred_at", DateTime(timezone=True), nullable=False),
    _col("ingested_at", DateTime(timezone=True), nullable=False),
    _col("expires_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("event_name IN ('page_viewed','workflow_completed','feature_used','error_observed')", name="event_name"),
    CheckConstraint("expires_at > ingested_at", name="retention"),
)


DEFAULTS: dict[str, Any] = {
    "urgent_findings": True, "deadline_warnings": True, "monitoring_failures": True,
    "approval_requests": True, "email_digest": "daily", "session_timeout_minutes": 60,
    "evidence_retention_months": 120, "require_mfa": True, "allow_raw_artifacts": False,
    "theme": "system", "density": "comfortable", "analytics_enabled": True,
    "analytics_retention_days": 90,
}
SETTING_FIELDS = frozenset(DEFAULTS)
PROFILE_FIELDS = frozenset({"name", "legal_name", "country", "registration_number", "timezone"})
ROLE_VALUES = frozenset(role.value for role in Role)
INTEGRATION_TYPES = frozenset({"email", "webhook", "collector", "jira"})
INTEGRATION_STATUSES = frozenset({"connected", "attention", "not_connected"})
TRUST_KEY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
TRUST_POLICY = "organization_enrolled_ed25519_v1"
INTEGRATION_CONFIG = {
    "email": frozenset({"provider", "from_address"}),
    "webhook": frozenset({"endpoint_name", "event_types"}),
    "collector": frozenset({"collector_id", "environment"}),
    "jira": frozenset({"site", "project_key"}),
}
SECRET_REFERENCE_RE = re.compile(r"^(vault|aws-secrets|gcp-secret|azure-keyvault)://[A-Za-z0-9._/@-]+$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
ANALYTICS_PROPERTIES = {
    "page_viewed": {"area": frozenset({"home", "products", "releases", "findings", "compliance", "documents", "settings"})},
    "workflow_completed": {"workflow": frozenset({"release_analysis", "finding_decision", "document_approval", "self_filing_record"}), "result": frozenset({"succeeded", "failed", "cancelled"})},
    "feature_used": {"feature": frozenset({"search", "filter", "theme", "export", "scope_selector"})},
    "error_observed": {"area": frozenset({"portfolio", "analysis", "monitoring", "findings", "compliance", "documents", "settings"}), "error_code": frozenset({"validation", "unauthorized", "forbidden", "not_found", "conflict", "unavailable", "timeout"})},
}


@dataclass(frozen=True, slots=True)
class SettingsRecord:
    organization_id: str
    version: int
    organization_profile: Mapping[str, str]
    notifications: Mapping[str, Any]
    security: Mapping[str, Any]
    appearance: Mapping[str, str]
    analytics: Mapping[str, Any]
    updated_by: str | None
    updated_at: datetime | None


@dataclass(frozen=True, slots=True)
class TeamMemberRecord:
    id: str
    organization_id: str
    subject: str
    name: str
    email: str
    title: str
    initials: str
    roles: tuple[str, ...]
    status: str
    expires_at: datetime | None
    revoked_at: datetime | None
    removed_at: datetime | None
    last_active_at: datetime | None
    version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class IntegrationRecord:
    id: str
    organization_id: str
    name: str
    type: str
    status: str
    description: str
    configuration: Mapping[str, Any]
    secret_reference: str | None
    last_sync_at: datetime | None
    version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class AuditRecord:
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


@dataclass(frozen=True, slots=True)
class TrustKeyRecord:
    id: str
    organization_id: str
    key_name: str
    key_version: int
    algorithm: str
    public_key_pem: str
    fingerprint: str
    status: str
    proof_verified_at: datetime
    activated_at: datetime
    valid_until: datetime | None
    revoked_at: datetime | None
    revocation_reason: str | None
    created_by: str


class OrganizationSettingsRepository:
    def __init__(self, engine: Engine):
        self.engine = engine

    def create_schema(self) -> None:
        portfolio_metadata.create_all(self.engine)

    def get_settings(self, organization_id: str) -> SettingsRecord:
        with Session(self.engine) as session:
            profile = self._profile(session, organization_id)
            row = session.execute(select(organization_settings).where(organization_settings.c.organization_id == organization_id)).one_or_none()
        return _settings_record(profile, row)

    def update_settings(self, organization_id: str, *, expected_version: int, patch: Mapping[str, Any], actor_id: str) -> SettingsRecord:
        if not isinstance(patch, Mapping) or not patch:
            raise SettingsValidationError("settings patch is required")
        unknown = set(patch) - {"organization_profile", "notifications", "security", "appearance", "analytics"}
        if unknown:
            raise SettingsValidationError("unsupported settings section")
        flat, profile_changes = _normalize_settings_patch(patch)
        with Session(self.engine) as session, session.begin():
            profile = self._profile(session, organization_id)
            row = session.execute(select(organization_settings).where(organization_settings.c.organization_id == organization_id)).one_or_none()
            current_version = row.version if row else 0
            if current_version != expected_version:
                raise SettingsConflict("settings version changed")
            now = _now()
            next_version = current_version + 1
            if profile_changes:
                changed = session.execute(update(organizations).where(organizations.c.id == organization_id).values(**profile_changes, updated_at=now))
                if changed.rowcount != 1:
                    raise SettingsNotFound("organization not found")
            values = {**DEFAULTS, **({key: getattr(row, key) for key in SETTING_FIELDS} if row else {}), **flat}
            if row:
                changed = session.execute(update(organization_settings).where(
                    organization_settings.c.organization_id == organization_id,
                    organization_settings.c.version == expected_version,
                ).values(**values, version=next_version, updated_by=_required(actor_id, "actor_id", 128), updated_at=now))
                if changed.rowcount != 1:
                    raise SettingsConflict("settings version changed")
            else:
                try:
                    session.execute(insert(organization_settings).values(
                        organization_id=organization_id, **values, version=next_version,
                        updated_by=_required(actor_id, "actor_id", 128), updated_at=now,
                    ))
                except IntegrityError as exc:
                    raise SettingsConflict("settings version changed") from exc
            self._audit(session, organization_id, "settings", organization_id, "settings.updated", next_version, actor_id, _safe_changes(patch))
        return self.get_settings(organization_id)

    def create_member(self, organization_id: str, *, subject: str, name: str, email: str, title: str, initials: str, roles: Sequence[str], actor_id: str, status: str = "invited", expires_at: datetime | None = None, member_id: str | None = None) -> TeamMemberRecord:
        now = _now()
        member_status = _member_status(status)
        values = {
            "id": member_id or _id(), "organization_id": organization_id,
            "subject": _required(subject, "subject", 160), "name": _required(name, "name", 200),
            "email": _email(email), "title": _required(title, "title", 160),
            "initials": _required(initials, "initials", 8), "roles": list(_roles(roles)),
            "status": member_status,
            "expires_at": _timestamp(expires_at, "expires_at") if expires_at else None,
            "revoked_at": now if member_status in {"disabled", "revoked"} else None,
            "removed_at": now if member_status == "removed" else None,
            "last_active_at": None, "version": 1, "created_at": now, "updated_at": now,
        }
        with Session(self.engine) as session, session.begin():
            self._profile(session, organization_id)
            try:
                session.execute(insert(team_members).values(**values))
                self._audit(session, organization_id, "team_member", values["id"], "team_member.created", 1, actor_id, {"roles": values["roles"], "status": values["status"]})
            except IntegrityError as exc:
                raise SettingsConflict("team member already exists") from exc
        return self.get_member(organization_id, values["id"])

    def get_member(self, organization_id: str, member_id: str) -> TeamMemberRecord:
        with Session(self.engine) as session:
            row = session.execute(select(team_members).where(team_members.c.organization_id == organization_id, team_members.c.id == member_id)).one_or_none()
        if row is None:
            raise SettingsNotFound("team member not found")
        return _member_record(row)

    def list_members(self, organization_id: str) -> list[TeamMemberRecord]:
        with Session(self.engine) as session:
            rows = session.execute(select(team_members).where(team_members.c.organization_id == organization_id).order_by(team_members.c.name, team_members.c.id)).all()
        return [_member_record(row) for row in rows]

    def resolve_membership(
        self,
        subject: str,
        organization_id: str,
        *,
        now: datetime | None = None,
    ) -> TeamMemberRecord:
        """Resolve application authority from PostgreSQL, never identity claims."""

        checked_at = now or _now()
        with Session(self.engine) as session:
            row = session.execute(
                select(team_members).where(
                    team_members.c.subject == _required(subject, "subject", 160),
                    team_members.c.organization_id
                    == _required(organization_id, "organization_id", 36),
                    team_members.c.status == "active",
                    team_members.c.revoked_at.is_(None),
                    team_members.c.removed_at.is_(None),
                    (team_members.c.expires_at.is_(None))
                    | (team_members.c.expires_at > checked_at),
                )
            ).one_or_none()
        if row is None:
            raise SettingsNotFound("active membership not found")
        return _member_record(row)

    def update_member(self, organization_id: str, member_id: str, *, expected_version: int, changes: Mapping[str, Any], actor_id: str) -> TeamMemberRecord:
        current = self.get_member(organization_id, member_id)
        allowed = {"title", "roles", "status", "expires_at"}
        values = _strict_changes(changes, allowed, "team member")
        if "title" in values:
            values["title"] = _required(values["title"], "title", 160)
        if "roles" in values:
            values["roles"] = list(_roles(values["roles"]))
        if "status" in values:
            next_status = _member_status(values["status"])
            if current.status == "removed" and next_status != "removed":
                raise SettingsValidationError("removed membership cannot be restored")
            values["status"] = next_status
            values["revoked_at"] = _now() if next_status in {"disabled", "revoked"} else None
            values["removed_at"] = _now() if next_status == "removed" else None
        if "expires_at" in values and values["expires_at"] is not None:
            values["expires_at"] = _timestamp(values["expires_at"], "expires_at")
        return self._versioned_update(team_members, organization_id, member_id, expected_version, values, actor_id, "team_member")

    def create_integration(self, organization_id: str, *, name: str, type: str, description: str, configuration: Mapping[str, Any], actor_id: str, status: str = "not_connected", secret_reference: str | None = None, integration_id: str | None = None) -> IntegrationRecord:
        integration_type = _choice(type, INTEGRATION_TYPES, "type")
        now = _now()
        values = {
            "id": integration_id or _id(), "organization_id": organization_id,
            "name": _required(name, "name", 200), "type": integration_type,
            "status": _choice(status, INTEGRATION_STATUSES, "status"),
            "description": _required(description, "description", 1000),
            "configuration": _integration_configuration(integration_type, configuration),
            "secret_reference": _secret_reference(secret_reference), "last_sync_at": None,
            "version": 1, "created_at": now, "updated_at": now,
        }
        _validate_connected_integration(
            integration_type, values["status"], values["configuration"],
            values["secret_reference"],
        )
        with Session(self.engine) as session, session.begin():
            self._profile(session, organization_id)
            try:
                session.execute(insert(integrations).values(**values))
                self._audit(session, organization_id, "integration", values["id"], "integration.created", 1, actor_id, {"type": integration_type, "status": values["status"], "secret_reference_configured": bool(values["secret_reference"])})
            except IntegrityError as exc:
                raise SettingsConflict("integration already exists") from exc
        return self.get_integration(organization_id, values["id"])

    def get_integration(self, organization_id: str, integration_id: str) -> IntegrationRecord:
        with Session(self.engine) as session:
            row = session.execute(select(integrations).where(integrations.c.organization_id == organization_id, integrations.c.id == integration_id)).one_or_none()
        if row is None:
            raise SettingsNotFound("integration not found")
        return _integration_record(row)

    def list_integrations(self, organization_id: str) -> list[IntegrationRecord]:
        with Session(self.engine) as session:
            rows = session.execute(select(integrations).where(integrations.c.organization_id == organization_id).order_by(integrations.c.name, integrations.c.id)).all()
        return [_integration_record(row) for row in rows]

    def update_integration(self, organization_id: str, integration_id: str, *, expected_version: int, changes: Mapping[str, Any], actor_id: str) -> IntegrationRecord:
        current = self.get_integration(organization_id, integration_id)
        values = _strict_changes(changes, {"status", "description", "configuration", "secret_reference", "last_sync_at"}, "integration")
        if "status" in values:
            values["status"] = _choice(values["status"], INTEGRATION_STATUSES, "status")
        if "description" in values:
            values["description"] = _required(values["description"], "description", 1000)
        if "configuration" in values:
            values["configuration"] = _integration_configuration(current.type, values["configuration"])
        if "secret_reference" in values:
            values["secret_reference"] = _secret_reference(values["secret_reference"])
        if "last_sync_at" in values and values["last_sync_at"] is not None:
            values["last_sync_at"] = _timestamp(values["last_sync_at"], "last_sync_at")
        _validate_connected_integration(
            current.type,
            values.get("status", current.status),
            values.get("configuration", current.configuration),
            values.get("secret_reference", current.secret_reference),
        )
        safe = {**values}
        if "secret_reference" in safe:
            safe["secret_reference"] = "configured" if safe["secret_reference"] else None
        return self._versioned_update(integrations, organization_id, integration_id, expected_version, values, actor_id, "integration", safe)

    def enroll_trust_key(
        self,
        organization_id: str,
        *,
        key_name: str,
        public_key_pem: str,
        proof_signature: str,
        challenge_id: str,
        actor_id: str,
        now: datetime | None = None,
    ) -> TrustKeyRecord:
        name = _trust_key_name(key_name)
        key, canonical_pem = _public_key(public_key_pem)
        fingerprint = public_key_fingerprint(key)
        activated_at = _timestamp(now, "now") if now else _now()
        actor = _required(actor_id, "actor_id", 128)
        with Session(self.engine) as session:
            challenge = session.execute(select(trust_key_challenges).where(
                trust_key_challenges.c.id == challenge_id,
                trust_key_challenges.c.organization_id == organization_id,
            )).one_or_none()
        if (
            challenge is None or challenge.consumed_at is not None
            or _aware(challenge.expires_at) <= activated_at
            or challenge.key_name != name or challenge.fingerprint != fingerprint
            or challenge.created_by != actor
        ):
            raise SettingsValidationError("trust key challenge is missing, expired, or already used")
        try:
            signature = bytes.fromhex(proof_signature)
            if len(signature) != 64:
                raise ValueError
            key.verify(
                signature,
                trust_key_enrollment_payload(organization_id, name, fingerprint, challenge.id, challenge.nonce),
            )
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise SettingsValidationError("trust key proof of possession is invalid") from exc

        key_id = _id()
        with Session(self.engine) as session, session.begin():
            self._profile(session, organization_id)
            consumed = session.execute(update(trust_key_challenges).where(
                trust_key_challenges.c.id == challenge_id,
                trust_key_challenges.c.organization_id == organization_id,
                trust_key_challenges.c.consumed_at.is_(None),
                trust_key_challenges.c.expires_at > activated_at,
            ).values(consumed_at=activated_at))
            if consumed.rowcount != 1:
                raise SettingsValidationError("trust key challenge is already used")
            existing = session.execute(
                select(trust_keys).where(
                    trust_keys.c.organization_id == organization_id,
                    trust_keys.c.key_name == name,
                    trust_keys.c.status == "active",
                ).with_for_update()
            ).one_or_none()
            duplicate = session.execute(
                select(trust_keys.c.id).where(
                    trust_keys.c.organization_id == organization_id,
                    trust_keys.c.fingerprint == fingerprint,
                )
            ).scalar_one_or_none()
            if duplicate is not None:
                raise SettingsConflict("trust key is already enrolled")
            key_version = existing.key_version + 1 if existing else 1
            if existing:
                session.execute(
                    update(trust_keys)
                    .where(trust_keys.c.id == existing.id)
                    .values(status="rotated", valid_until=activated_at)
                )
            values = {
                "id": key_id,
                "organization_id": organization_id,
                "key_name": name,
                "key_version": key_version,
                "algorithm": "Ed25519",
                "public_key_pem": canonical_pem,
                "fingerprint": fingerprint,
                "status": "active",
                "proof_verified_at": activated_at,
                "activated_at": activated_at,
                "valid_until": None,
                "revoked_at": None,
                "revocation_reason": None,
                "created_by": actor,
            }
            try:
                session.execute(insert(trust_keys).values(**values))
            except IntegrityError as exc:
                raise SettingsConflict("trust key enrollment conflict") from exc
            self._audit(
                session,
                organization_id,
                "trust_key",
                key_id,
                "trust_key.rotated" if existing else "trust_key.enrolled",
                key_version,
                actor,
                {
                    "key_name": name,
                    "key_version": key_version,
                    "algorithm": "Ed25519",
                    "fingerprint": fingerprint,
                    "replaces_fingerprint": existing.fingerprint if existing else None,
                },
            )
        return self.get_trust_key(organization_id, key_id)

    def create_trust_key_challenge(
        self, organization_id: str, *, key_name: str,
        public_key_pem: str, actor_id: str,
    ) -> Mapping[str, str]:
        name = _trust_key_name(key_name)
        key, _ = _public_key(public_key_pem)
        fingerprint = public_key_fingerprint(key)
        challenge_id = _id()
        nonce = secrets.token_hex(32)
        expires_at = _now() + timedelta(minutes=5)
        actor = _required(actor_id, "actor_id", 128)
        with Session(self.engine) as session, session.begin():
            self._profile(session, organization_id)
            session.execute(insert(trust_key_challenges).values(
                id=challenge_id, organization_id=organization_id,
                key_name=name, fingerprint=fingerprint, nonce=nonce,
                created_by=actor, expires_at=expires_at, consumed_at=None,
            ))
        return {
            "challenge_id": challenge_id, "organization_id": organization_id,
            "key_name": name, "fingerprint": fingerprint, "nonce": nonce,
            "expires_at": expires_at.isoformat(),
        }

    def get_trust_key(self, organization_id: str, key_id: str) -> TrustKeyRecord:
        with Session(self.engine) as session:
            row = session.execute(
                select(trust_keys).where(
                    trust_keys.c.organization_id == organization_id,
                    trust_keys.c.id == key_id,
                )
            ).one_or_none()
        if row is None:
            raise SettingsNotFound("trust key not found")
        return _trust_key_record(row)

    def list_trust_keys(self, organization_id: str) -> list[TrustKeyRecord]:
        with Session(self.engine) as session:
            self._profile(session, organization_id)
            rows = session.execute(
                select(trust_keys)
                .where(trust_keys.c.organization_id == organization_id)
                .order_by(trust_keys.c.key_name, trust_keys.c.key_version.desc())
            ).all()
        return [_trust_key_record(row) for row in rows]

    def revoke_trust_key(
        self,
        organization_id: str,
        key_id: str,
        *,
        reason: str,
        actor_id: str,
        now: datetime | None = None,
    ) -> TrustKeyRecord:
        revoked_at = _timestamp(now, "now") if now else _now()
        clean_reason = _required(reason, "reason", 500)
        with Session(self.engine) as session, session.begin():
            row = session.execute(
                select(trust_keys).where(
                    trust_keys.c.organization_id == organization_id,
                    trust_keys.c.id == key_id,
                ).with_for_update()
            ).one_or_none()
            if row is None:
                raise SettingsNotFound("trust key not found")
            if row.status == "revoked":
                return _trust_key_record(row)
            session.execute(
                update(trust_keys)
                .where(trust_keys.c.id == key_id)
                .values(
                    status="revoked",
                    valid_until=row.valid_until or revoked_at,
                    revoked_at=revoked_at,
                    revocation_reason=clean_reason,
                )
            )
            self._audit(
                session,
                organization_id,
                "trust_key",
                key_id,
                "trust_key.revoked",
                row.key_version,
                actor_id,
                {
                    "fingerprint": row.fingerprint,
                    "reason": clean_reason,
                    "revoked_at": revoked_at,
                },
            )
        return self.get_trust_key(organization_id, key_id)

    def verify_registered_bundle(
        self,
        organization_id: str,
        bundle_dir: Path,
        *,
        actor_id: str,
        now: datetime | None = None,
    ) -> Mapping[str, Any]:
        verified_at = _timestamp(now, "now") if now else _now()
        inspection = verify_bundle(bundle_dir)
        key = None
        fingerprint = inspection.bundle_key_fingerprint
        signed_at = _manifest_created(bundle_dir)
        with Session(self.engine) as session:
            self._profile(session, organization_id)
            row = session.execute(
                select(trust_keys).where(
                    trust_keys.c.organization_id == organization_id,
                    trust_keys.c.fingerprint == fingerprint,
                )
            ).one_or_none() if fingerprint else None

        decision = "not_enrolled"
        if row is not None:
            if row.status == "revoked":
                decision = "revoked"
            elif row.status == "rotated" and (
                signed_at is None or row.valid_until is None or signed_at > _aware(row.valid_until)
            ):
                decision = "expired"
            else:
                decision = "trusted"
                key, _ = _public_key(row.public_key_pem)
        result = verify_bundle(bundle_dir, key) if key else inspection
        payload = result.as_dict()
        if decision != "trusted" and result.integrity_ok and result.signature_valid:
            payload.update(
                status="untrusted",
                ok=False,
                signer_trust=decision,
                reason=f"bundle signer is {decision.replace('_', ' ')} under organization policy",
            )
        payload.update({
            "trust_policy": TRUST_POLICY,
            "trust_source": "organization_registry",
            "trust_decision": decision,
            "algorithm": "Ed25519",
            "key_id": row.key_name if row else None,
            "key_version": row.key_version if row else None,
            "key_status": row.status if row else None,
            "verified_at": verified_at.isoformat(),
        })
        with Session(self.engine) as session, session.begin():
            self._audit(
                session,
                organization_id,
                "trust_verification",
                str(_manifest_run_id(bundle_dir) or fingerprint or "unknown"),
                "trust_key.verified",
                row.key_version if row else 1,
                actor_id,
                {
                    "status": payload["status"],
                    "trust_decision": decision,
                    "fingerprint": fingerprint,
                    "key_id": row.key_name if row else None,
                    "key_version": row.key_version if row else None,
                    "verified_at": verified_at,
                },
            )
        return payload

    def ingest_analytics(self, organization_id: str, events: Sequence[Mapping[str, Any]]) -> Mapping[str, int]:
        if not isinstance(events, Sequence) or isinstance(events, (str, bytes)) or not 1 <= len(events) <= 100:
            raise SettingsValidationError("analytics batch must contain 1 to 100 events")
        settings = self.get_settings(organization_id)
        if not settings.analytics["enabled"]:
            return {"accepted": 0, "dropped": len(events)}
        normalized = [_analytics_event(event) for event in events]
        ingested = _now()
        expires = ingested + timedelta(days=int(settings.analytics["retention_days"]))
        with Session(self.engine) as session, session.begin():
            for event in normalized:
                session.execute(insert(analytics_events).values(
                    id=_id(), organization_id=organization_id, **event,
                    ingested_at=ingested, expires_at=expires,
                ))
        return {"accepted": len(normalized), "dropped": 0}

    def analytics_aggregates(self, organization_id: str, *, since: datetime | None = None, until: datetime | None = None) -> list[Mapping[str, Any]]:
        now = _now()
        normalized_since = _timestamp(since, "since") if since is not None else None
        normalized_until = _timestamp(until, "until") if until is not None else None
        if normalized_since is not None and normalized_until is not None and normalized_until <= normalized_since:
            raise SettingsValidationError("until must be after since")
        with Session(self.engine) as session:
            query = select(analytics_events.c.event_name, func.count().label("count")).where(
                analytics_events.c.organization_id == organization_id,
                analytics_events.c.expires_at > now,
            )
            if normalized_since is not None:
                query = query.where(analytics_events.c.occurred_at >= normalized_since)
            if normalized_until is not None:
                query = query.where(analytics_events.c.occurred_at < normalized_until)
            rows = session.execute(query.group_by(analytics_events.c.event_name).order_by(analytics_events.c.event_name)).all()
        return [{"event_name": row.event_name, "count": row.count} for row in rows]

    def list_audit(self, organization_id: str) -> list[AuditRecord]:
        with Session(self.engine) as session:
            rows = session.execute(select(settings_audit_events).where(settings_audit_events.c.organization_id == organization_id).order_by(settings_audit_events.c.occurred_at.desc(), settings_audit_events.c.id.desc())).all()
        return [_audit_record(row) for row in rows]

    def _versioned_update(self, table: Table, organization_id: str, entity_id: str, expected_version: int, values: Mapping[str, Any], actor_id: str, entity_type: str, safe_changes: Mapping[str, Any] | None = None):
        if not values:
            raise SettingsValidationError(f"{entity_type} changes are required")
        with Session(self.engine) as session, session.begin():
            row = session.execute(select(table).where(table.c.organization_id == organization_id, table.c.id == entity_id)).one_or_none()
            if row is None:
                raise SettingsNotFound(f"{entity_type.replace('_', ' ')} not found")
            if row.version != expected_version:
                raise SettingsConflict(f"{entity_type.replace('_', ' ')} version changed")
            next_version = expected_version + 1
            try:
                changed = session.execute(update(table).where(
                    table.c.organization_id == organization_id, table.c.id == entity_id,
                    table.c.version == expected_version,
                ).values(**values, version=next_version, updated_at=_now()))
                if changed.rowcount != 1:
                    raise SettingsConflict(f"{entity_type.replace('_', ' ')} version changed")
                self._audit(session, organization_id, entity_type, entity_id, f"{entity_type}.updated", next_version, actor_id, safe_changes or values)
            except IntegrityError as exc:
                raise SettingsConflict(f"{entity_type.replace('_', ' ')} update conflict") from exc
        return self.get_member(organization_id, entity_id) if entity_type == "team_member" else self.get_integration(organization_id, entity_id)

    def _profile(self, session: Session, organization_id: str):
        row = session.execute(select(organizations).where(organizations.c.id == organization_id)).one_or_none()
        if row is None:
            raise SettingsNotFound("organization not found")
        return row

    def _audit(self, session: Session, organization_id: str, entity_type: str, entity_id: str, action: str, version: int, actor_id: str, changes: Mapping[str, Any]) -> None:
        session.execute(
            select(organizations.c.id)
            .where(organizations.c.id == organization_id)
            .with_for_update()
        ).one()
        previous = session.execute(
            select(
                settings_audit_events.c.digest,
                settings_audit_events.c.occurred_at,
            )
            .where(settings_audit_events.c.organization_id == organization_id)
            .order_by(
                settings_audit_events.c.occurred_at.desc(),
                settings_audit_events.c.id.desc(),
            )
            .limit(1)
        ).one_or_none()
        previous_digest = previous.digest if previous else None
        event_id = _id()
        occurred_at = _now()
        if previous and occurred_at <= _aware(previous.occurred_at):
            occurred_at = _aware(previous.occurred_at) + timedelta(microseconds=1)
        safe_changes = _json_safe(changes)
        payload = {
            "id": event_id,
            "organization_id": organization_id,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "action": action,
            "version": version,
            "actor_id": _required(actor_id, "actor_id", 128),
            "occurred_at": occurred_at.isoformat(),
            "changes": safe_changes,
            "previous_digest": previous_digest,
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        session.execute(
            insert(settings_audit_events).values(
                **{**payload, "occurred_at": occurred_at, "digest": digest}
            )
        )


def _settings_record(profile: Any, row: Any | None) -> SettingsRecord:
    values = {**DEFAULTS, **({key: getattr(row, key) for key in SETTING_FIELDS} if row else {})}
    return SettingsRecord(
        organization_id=profile.id, version=row.version if row else 0,
        organization_profile={"name": profile.name, "legal_name": profile.legal_name, "country": profile.country, "registration_number": profile.registration_number, "timezone": profile.timezone},
        notifications={"urgent_findings": values["urgent_findings"], "deadline_warnings": values["deadline_warnings"], "monitoring_failures": values["monitoring_failures"], "approval_requests": values["approval_requests"], "email_digest": values["email_digest"]},
        security={"session_timeout_minutes": values["session_timeout_minutes"], "evidence_retention_months": values["evidence_retention_months"], "require_mfa": values["require_mfa"], "allow_raw_artifacts": values["allow_raw_artifacts"]},
        appearance={"theme": values["theme"], "density": values["density"]},
        analytics={"enabled": values["analytics_enabled"], "retention_days": values["analytics_retention_days"]},
        updated_by=row.updated_by if row else None, updated_at=_aware(row.updated_at) if row else None,
    )


def _normalize_settings_patch(patch: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    flat: dict[str, Any] = {}
    profile: dict[str, str] = {}
    sections = {
        "notifications": {"urgent_findings", "deadline_warnings", "monitoring_failures", "approval_requests", "email_digest"},
        "security": {"session_timeout_minutes", "evidence_retention_months", "require_mfa", "allow_raw_artifacts"},
        "appearance": {"theme", "density"}, "analytics": {"enabled", "retention_days"},
    }
    aliases = {"enabled": "analytics_enabled", "retention_days": "analytics_retention_days"}
    for section, allowed in sections.items():
        if section not in patch:
            continue
        values = _strict_changes(patch[section], allowed, section)
        flat.update({aliases.get(key, key): value for key, value in values.items()})
    if "organization_profile" in patch:
        profile = _strict_changes(patch["organization_profile"], PROFILE_FIELDS, "organization profile")
        for key in tuple(profile):
            profile[key] = _required(profile[key], key, 240)
        if "country" in profile and not re.fullmatch(r"[A-Za-z]{2}", profile["country"]):
            raise SettingsValidationError("country must be a two-letter code")
        if "country" in profile:
            profile["country"] = profile["country"].upper()
    if "email_digest" in flat:
        flat["email_digest"] = _choice(flat["email_digest"], {"off", "daily", "weekly"}, "email_digest")
    if "theme" in flat:
        flat["theme"] = _choice(flat["theme"], {"light", "dark", "system"}, "theme")
    if "density" in flat:
        flat["density"] = _choice(flat["density"], {"comfortable", "compact"}, "density")
    for key in ("urgent_findings", "deadline_warnings", "monitoring_failures", "approval_requests", "require_mfa", "allow_raw_artifacts", "analytics_enabled"):
        if key in flat and not isinstance(flat[key], bool):
            raise SettingsValidationError(f"{key} must be boolean")
    _range(flat, "session_timeout_minutes", 5, 1440)
    _range(flat, "evidence_retention_months", 1, 240)
    _range(flat, "analytics_retention_days", 1, 365)
    return flat, profile


def _analytics_event(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"event_name", "properties", "occurred_at"}:
        raise SettingsValidationError("analytics event has unsupported fields")
    name = value["event_name"]
    if name not in ANALYTICS_PROPERTIES:
        raise SettingsValidationError("analytics event name is not allowlisted")
    properties = value["properties"]
    if not isinstance(properties, Mapping) or set(properties) != set(ANALYTICS_PROPERTIES[name]):
        raise SettingsValidationError("analytics properties do not match allowlist")
    normalized = {}
    for key, allowed in ANALYTICS_PROPERTIES[name].items():
        item = properties[key]
        if not isinstance(item, str) or item not in allowed:
            raise SettingsValidationError(f"analytics property {key} is not allowlisted")
        normalized[key] = item
    return {"event_name": name, "properties": normalized, "occurred_at": _timestamp(value["occurred_at"], "occurred_at")}


def _integration_configuration(integration_type: str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) - INTEGRATION_CONFIG[integration_type]:
        raise SettingsValidationError("integration configuration contains unsupported fields")
    result = dict(value)
    for key, item in result.items():
        if key == "event_types":
            if not isinstance(item, list) or any(event not in {"urgent_finding", "deadline", "monitoring_failure", "approval_request"} for event in item):
                raise SettingsValidationError("unsupported integration event type")
        elif not isinstance(item, str) or not item.strip() or len(item) > 320:
            raise SettingsValidationError(f"invalid integration configuration field: {key}")
    if "from_address" in result:
        result["from_address"] = _email(result["from_address"])
    if "provider" in result and result["provider"] not in {"resend", "smtp", "sendgrid", "ses", "microsoft_graph"}:
        raise SettingsValidationError("unsupported email provider")
    for key in ("endpoint_name", "collector_id"):
        if key in result and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", result[key]):
            raise SettingsValidationError(f"invalid integration configuration field: {key}")
    if "environment" in result and result["environment"] not in {"production", "staging", "development"}:
        raise SettingsValidationError("unsupported collector environment")
    if "site" in result and not re.fullmatch(r"[A-Za-z0-9.-]+", result["site"]):
        raise SettingsValidationError("integration site must be a hostname")
    if "project_key" in result and not re.fullmatch(r"[A-Z][A-Z0-9_]{0,31}", result["project_key"]):
        raise SettingsValidationError("invalid Jira project key")
    return result


def _secret_reference(value: str | None) -> str | None:
    if value is None:
        return None
    result = _required(value, "secret_reference", 500)
    if not SECRET_REFERENCE_RE.fullmatch(result):
        raise SettingsValidationError("secret_reference must identify an external secret manager")
    return result


def _validate_connected_integration(
    integration_type: str,
    status: str,
    configuration: Mapping[str, Any],
    secret_reference: str | None,
) -> None:
    if status != "connected":
        return
    required = {
        "email": {"provider", "from_address"},
        "webhook": {"endpoint_name", "event_types"},
        "collector": {"collector_id", "environment"},
        "jira": {"site", "project_key"},
    }[integration_type]
    if not secret_reference or not required.issubset(configuration):
        raise SettingsValidationError(
            "connected integration requires complete configuration and an external secret reference"
        )
    if integration_type == "email" and configuration["provider"] != "resend":
        raise SettingsValidationError("connected notification email must use Resend")


def _member_record(row: Any) -> TeamMemberRecord:
    return TeamMemberRecord(
        row.id, row.organization_id, row.subject, row.name, row.email, row.title,
        row.initials, tuple(sorted(row.roles)), row.status,
        _aware(row.expires_at) if row.expires_at else None,
        _aware(row.revoked_at) if row.revoked_at else None,
        _aware(row.removed_at) if row.removed_at else None,
        _aware(row.last_active_at) if row.last_active_at else None,
        row.version, _aware(row.created_at), _aware(row.updated_at),
    )


def _integration_record(row: Any) -> IntegrationRecord:
    return IntegrationRecord(row.id, row.organization_id, row.name, row.type, row.status, row.description, dict(row.configuration), row.secret_reference, _aware(row.last_sync_at) if row.last_sync_at else None, row.version, _aware(row.created_at), _aware(row.updated_at))


def _trust_key_record(row: Any) -> TrustKeyRecord:
    return TrustKeyRecord(
        row.id,
        row.organization_id,
        row.key_name,
        row.key_version,
        row.algorithm,
        row.public_key_pem,
        row.fingerprint,
        row.status,
        _aware(row.proof_verified_at),
        _aware(row.activated_at),
        _aware(row.valid_until) if row.valid_until else None,
        _aware(row.revoked_at) if row.revoked_at else None,
        row.revocation_reason,
        row.created_by,
    )


def _audit_record(row: Any) -> AuditRecord:
    return AuditRecord(
        row.id, row.organization_id, row.entity_type, row.entity_id, row.action,
        row.version, row.actor_id, _aware(row.occurred_at), dict(row.changes),
        row.previous_digest, row.digest,
    )


def _strict_changes(value: Mapping[str, Any], allowed: set[str] | frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not value:
        raise SettingsValidationError(f"{label} changes are required")
    if set(value) - set(allowed):
        raise SettingsValidationError(f"unsupported {label} field")
    return dict(value)


def _safe_changes(value: Mapping[str, Any]) -> dict[str, Any]:
    result = {key: dict(item) if isinstance(item, Mapping) else item for key, item in value.items()}
    integration = result.get("integration")
    if isinstance(integration, dict) and "secret_reference" in integration:
        integration["secret_reference"] = "configured"
    return result


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _roles(values: Sequence[str]) -> tuple[str, ...]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)) or not values:
        raise SettingsValidationError("at least one role is required")
    result = tuple(sorted(set(values)))
    if any(value not in ROLE_VALUES for value in result):
        raise SettingsValidationError("unsupported role")
    return result


def _member_status(value: str) -> str:
    return _choice(
        value, {"active", "invited", "disabled", "revoked", "removed"}, "status"
    )


def _email(value: str) -> str:
    result = _required(value, "email", 320).lower()
    if not EMAIL_RE.fullmatch(result):
        raise SettingsValidationError("invalid email")
    return result


def _required(value: str, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SettingsValidationError(f"{field} is required")
    result = value.strip()
    if len(result) > maximum:
        raise SettingsValidationError(f"{field} is too long")
    return result


def _trust_key_name(value: str) -> str:
    result = _required(value, "key_name", 80)
    if not TRUST_KEY_NAME_RE.fullmatch(result):
        raise SettingsValidationError("key_name must use letters, numbers, dot, underscore, or hyphen")
    return result


def _public_key(value: str) -> tuple[Ed25519PublicKey, str]:
    if not isinstance(value, str) or "PRIVATE KEY" in value:
        raise SettingsValidationError("public_key_pem must contain only an Ed25519 public key")
    try:
        key = serialization.load_pem_public_key(value.encode("ascii"))
    except (UnicodeEncodeError, TypeError, ValueError) as exc:
        raise SettingsValidationError("public_key_pem is not a valid PEM public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SettingsValidationError("public_key_pem must be an Ed25519 public key")
    pem = key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return key, pem


def trust_key_enrollment_payload(
    organization_id: str, key_name: str, fingerprint: str,
    challenge_id: str, nonce: str,
) -> bytes:
    return canonical({
        "schema": "actis/trust-key-enrollment/v1",
        "organization_id": _required(organization_id, "organization_id", 36),
        "key_name": _trust_key_name(key_name),
        "algorithm": "Ed25519",
        "fingerprint": fingerprint,
        "challenge_id": challenge_id,
        "nonce": nonce,
    })


def create_trust_key_enrollment(
    key: Ed25519PrivateKey, organization_id: str, key_name: str,
    challenge: Mapping[str, str],
) -> Mapping[str, str]:
    public = key.public_key()
    pem = public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    fingerprint = public_key_fingerprint(public)
    if (
        challenge.get("organization_id") != organization_id
        or challenge.get("key_name") != key_name
        or challenge.get("fingerprint") != fingerprint
    ):
        raise SettingsValidationError("trust key challenge does not match the signing key")
    return {
        "key_name": _trust_key_name(key_name),
        "public_key_pem": pem,
        "challenge_id": challenge["challenge_id"],
        "proof_signature": key.sign(
            trust_key_enrollment_payload(organization_id, key_name, fingerprint,
                                         challenge["challenge_id"], challenge["nonce"])
        ).hex(),
    }


def _manifest(bundle_dir: Path) -> Mapping[str, Any] | None:
    try:
        value = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, Mapping) else None


def _manifest_created(bundle_dir: Path) -> datetime | None:
    manifest = _manifest(bundle_dir)
    value = manifest.get("created") if manifest else None
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def _manifest_run_id(bundle_dir: Path) -> str | None:
    manifest = _manifest(bundle_dir)
    value = manifest.get("run_id") if manifest else None
    return value if isinstance(value, str) and value else None


def _choice(value: str, choices: set[str] | frozenset[str], field: str) -> str:
    result = _required(value, field, 64)
    if result not in choices:
        raise SettingsValidationError(f"unsupported {field}")
    return result


def _range(values: Mapping[str, Any], key: str, minimum: int, maximum: int) -> None:
    if key in values and (isinstance(values[key], bool) or not isinstance(values[key], int) or not minimum <= values[key] <= maximum):
        raise SettingsValidationError(f"{key} is out of range")


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise SettingsValidationError(f"{field} requires a timezone")
    return value.astimezone(timezone.utc)


def _id() -> str:
    return str(uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
