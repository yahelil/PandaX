"""Durable, tenant-scoped delivery for external notification integrations."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from sqlalchemy import (
    JSON, CheckConstraint, Column, DateTime, ForeignKey, Index, Integer, String,
    Table, UniqueConstraint, and_, func, insert, or_, select, update,
)
from sqlalchemy.engine import Engine, RowMapping
from sqlalchemy.orm import Session

from .organization_settings import DEFAULTS, integrations, organization_settings, team_members
from .portfolio import portfolio_metadata


DELIVERY_CHANNELS = frozenset({"email", "webhook", "jira"})
DELIVERY_STATUSES = frozenset({"queued", "delivering", "retrying", "delivered", "dead_letter", "suppressed"})
EVENT_PREFERENCES = {
    "urgent_finding": "urgent_findings",
    "deadline": "deadline_warnings",
    "monitoring_failure": "monitoring_failures",
    "approval_request": "approval_requests",
}
EVENT_ROLES = {
    "urgent_finding": {"org_admin", "security_reviewer"},
    "deadline": {"org_admin", "compliance_operator", "authorized_approver"},
    "monitoring_failure": {"org_admin", "security_reviewer"},
    "approval_request": {"org_admin", "authorized_approver"},
}


class NotificationDeliveryError(RuntimeError):
    pass


class DeliveryNotFound(NotificationDeliveryError):
    pass


class DeliveryConflict(NotificationDeliveryError):
    pass


@dataclass(frozen=True, slots=True)
class DeliveryJob:
    id: str
    organization_id: str
    notification_id: str
    integration_id: str
    channel: str
    idempotency_key: str
    payload: Mapping[str, Any]
    status: str
    attempt_count: int
    max_attempts: int
    next_attempt_at: datetime
    lease_until: datetime | None
    provider_reference: str | None
    error_code: str | None
    created_at: datetime
    updated_at: datetime
    delivered_at: datetime | None


notification_delivery_jobs = Table(
    "notification_delivery_jobs",
    portfolio_metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("notification_id", String(36), ForeignKey("notifications.id", ondelete="CASCADE"), nullable=False),
    Column("integration_id", String(36), ForeignKey(integrations.c.id, ondelete="CASCADE"), nullable=False),
    Column("channel", String(16), nullable=False),
    Column("idempotency_key", String(64), nullable=False),
    Column("payload", JSON, nullable=False),
    Column("status", String(16), nullable=False),
    Column("attempt_count", Integer, nullable=False),
    Column("max_attempts", Integer, nullable=False),
    Column("next_attempt_at", DateTime(timezone=True), nullable=False),
    Column("lease_until", DateTime(timezone=True), nullable=True),
    Column("provider_reference", String(240), nullable=True),
    Column("error_code", String(80), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("delivered_at", DateTime(timezone=True), nullable=True),
    UniqueConstraint("organization_id", "idempotency_key", name="uq_notification_delivery_idempotency"),
    CheckConstraint("channel IN ('email','webhook','jira')", name="channel"),
    CheckConstraint(
        "status IN ('queued','delivering','retrying','delivered','dead_letter','suppressed')",
        name="status",
    ),
    CheckConstraint("attempt_count >= 0 AND max_attempts BETWEEN 1 AND 10", name="attempts"),
)
Index(
    "ix_notification_delivery_due",
    notification_delivery_jobs.c.status,
    notification_delivery_jobs.c.next_attempt_at,
    notification_delivery_jobs.c.lease_until,
)
Index(
    "ix_notification_delivery_org_created",
    notification_delivery_jobs.c.organization_id,
    notification_delivery_jobs.c.created_at,
)


class NotificationDeliveryRepository:
    def __init__(self, engine: Engine, *, daily_limit: int = 500):
        if not 1 <= daily_limit <= 5000:
            raise ValueError("daily notification delivery limit must be between 1 and 5000")
        self.engine = engine
        self.daily_limit = daily_limit

    def enqueue(
        self,
        session: Session,
        organization_id: str,
        notification_id: str,
        content_fingerprint: str,
        notification: Mapping[str, Any],
        now: datetime,
    ) -> None:
        event_type = _event_type(notification)
        if event_type is None or not self._preference_enabled(session, organization_id, event_type):
            return
        configured = session.execute(
            select(integrations).where(
                integrations.c.organization_id == organization_id,
                integrations.c.type.in_(DELIVERY_CHANNELS),
                integrations.c.status == "connected",
                integrations.c.secret_reference.is_not(None),
            )
        ).mappings().all()
        recipients = self._recipients(session, organization_id, event_type)
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        used = session.scalar(select(func.count()).select_from(notification_delivery_jobs).where(
            notification_delivery_jobs.c.organization_id == organization_id,
            notification_delivery_jobs.c.created_at >= start,
            notification_delivery_jobs.c.status != "suppressed",
        )) or 0
        for integration in configured:
            channel = integration["type"]
            config = dict(integration["configuration"])
            if channel == "webhook" and event_type not in config.get("event_types", []):
                continue
            if channel == "jira" and not notification.get("requires_action"):
                continue
            key = hashlib.sha256(
                f"{organization_id}:{notification_id}:{integration['id']}:{content_fingerprint}".encode()
            ).hexdigest()
            if session.scalar(select(notification_delivery_jobs.c.id).where(
                notification_delivery_jobs.c.organization_id == organization_id,
                notification_delivery_jobs.c.idempotency_key == key,
            )):
                continue
            error = None
            if used >= self.daily_limit:
                error = "daily_quota_exceeded"
            elif channel == "email" and not recipients:
                error = "no_active_recipients"
            status = "suppressed" if error else "queued"
            payload = {
                "event_type": event_type,
                "notification_id": notification_id,
                "kind": notification["kind"],
                "priority": notification["priority"],
                "title": notification["title"],
                "detail": notification["detail"],
                "target_url": notification["target_url"],
                "product_id": notification.get("product_id"),
                "release_id": notification.get("release_id"),
                "recipients": recipients if channel == "email" else [],
            }
            session.execute(insert(notification_delivery_jobs).values(
                id=str(uuid4()), organization_id=organization_id,
                notification_id=notification_id, integration_id=integration["id"],
                channel=channel, idempotency_key=key, payload=payload, status=status,
                attempt_count=0, max_attempts=5, next_attempt_at=now,
                lease_until=None, provider_reference=None, error_code=error,
                created_at=now, updated_at=now, delivered_at=None,
            ))
            if not error:
                used += 1

    def list(self, organization_id: str, *, status: str | None = None, limit: int = 100) -> list[DeliveryJob]:
        if status is not None and status not in DELIVERY_STATUSES:
            raise ValueError("invalid delivery status")
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        conditions = [notification_delivery_jobs.c.organization_id == organization_id]
        if status:
            conditions.append(notification_delivery_jobs.c.status == status)
        with Session(self.engine) as session:
            rows = session.execute(
                select(notification_delivery_jobs)
                .where(and_(*conditions))
                .order_by(notification_delivery_jobs.c.created_at.desc())
                .limit(limit)
            ).mappings().all()
        return [_job(row) for row in rows]

    def get(self, organization_id: str, job_id: str) -> DeliveryJob:
        with Session(self.engine) as session:
            row = session.execute(select(notification_delivery_jobs).where(
                notification_delivery_jobs.c.organization_id == organization_id,
                notification_delivery_jobs.c.id == job_id,
            )).mappings().one_or_none()
        if row is None:
            raise DeliveryNotFound("notification delivery not found")
        return _job(row)

    def claim(self, *, now: datetime | None = None, lease_seconds: int = 300) -> DeliveryJob | None:
        timestamp = _utc(now or datetime.now(timezone.utc))
        with Session(self.engine) as session, session.begin():
            row = session.execute(
                select(notification_delivery_jobs).where(
                    notification_delivery_jobs.c.next_attempt_at <= timestamp,
                    or_(
                        notification_delivery_jobs.c.status.in_(("queued", "retrying")),
                        and_(
                            notification_delivery_jobs.c.status == "delivering",
                            notification_delivery_jobs.c.lease_until <= timestamp,
                        ),
                    ),
                )
                .order_by(notification_delivery_jobs.c.next_attempt_at, notification_delivery_jobs.c.id)
                .with_for_update(skip_locked=True)
                .limit(1)
            ).mappings().one_or_none()
            if row is None:
                return None
            session.execute(update(notification_delivery_jobs).where(
                notification_delivery_jobs.c.id == row["id"],
            ).values(
                status="delivering",
                attempt_count=row["attempt_count"] + 1,
                lease_until=timestamp + timedelta(seconds=lease_seconds),
                updated_at=timestamp,
            ))
        return self.get(row["organization_id"], row["id"])

    def delivered(self, job: DeliveryJob, provider_reference: str | None, *, now: datetime | None = None) -> DeliveryJob:
        timestamp = _utc(now or datetime.now(timezone.utc))
        reference = provider_reference[:240] if provider_reference else None
        self._finish(job, status="delivered", now=timestamp, provider_reference=reference)
        return self.get(job.organization_id, job.id)

    def failed(
        self,
        job: DeliveryJob,
        error_code: str,
        *,
        retryable: bool,
        retry_after_seconds: int | None = None,
        now: datetime | None = None,
    ) -> DeliveryJob:
        timestamp = _utc(now or datetime.now(timezone.utc))
        retry = retryable and job.attempt_count < job.max_attempts
        delay = min(3600, max(retry_after_seconds or 0, 60 * (2 ** max(0, job.attempt_count - 1))))
        self._finish(
            job,
            status="retrying" if retry else "dead_letter",
            now=timestamp,
            error_code=error_code[:80],
            next_attempt_at=timestamp + timedelta(seconds=delay) if retry else timestamp,
        )
        return self.get(job.organization_id, job.id)

    def retry(self, organization_id: str, job_id: str, *, now: datetime | None = None) -> DeliveryJob:
        current = self.get(organization_id, job_id)
        if current.status not in {"dead_letter", "suppressed"}:
            raise DeliveryConflict("only dead-lettered or suppressed deliveries can be retried")
        timestamp = _utc(now or datetime.now(timezone.utc))
        if current.error_code == "daily_quota_exceeded":
            start = timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
            with Session(self.engine) as session:
                used = session.scalar(select(func.count()).select_from(notification_delivery_jobs).where(
                    notification_delivery_jobs.c.organization_id == organization_id,
                    notification_delivery_jobs.c.created_at >= start,
                    notification_delivery_jobs.c.status != "suppressed",
                )) or 0
            if used >= self.daily_limit:
                raise DeliveryConflict("daily notification delivery quota remains exhausted")
        with self.engine.begin() as connection:
            connection.execute(update(notification_delivery_jobs).where(
                notification_delivery_jobs.c.organization_id == organization_id,
                notification_delivery_jobs.c.id == job_id,
            ).values(
                status="queued", attempt_count=0, next_attempt_at=timestamp,
                lease_until=None, error_code=None, updated_at=timestamp,
            ))
        return self.get(organization_id, job_id)

    def _finish(self, job: DeliveryJob, *, status: str, now: datetime, **values: Any) -> None:
        with self.engine.begin() as connection:
            result = connection.execute(update(notification_delivery_jobs).where(
                notification_delivery_jobs.c.organization_id == job.organization_id,
                notification_delivery_jobs.c.id == job.id,
                notification_delivery_jobs.c.status == "delivering",
            ).values(
                status=status, lease_until=None, updated_at=now,
                delivered_at=now if status == "delivered" else None,
                **values,
            ))
        if result.rowcount != 1:
            raise DeliveryConflict("notification delivery is not claimed")

    @staticmethod
    def _preference_enabled(session: Session, organization_id: str, event_type: str) -> bool:
        field = EVENT_PREFERENCES[event_type]
        row = session.execute(select(organization_settings).where(
            organization_settings.c.organization_id == organization_id,
        )).mappings().one_or_none()
        return bool(row[field] if row else DEFAULTS[field])

    @staticmethod
    def _recipients(
        session: Session, organization_id: str, event_type: str
    ) -> list[str]:
        rows = session.execute(select(team_members.c.email, team_members.c.roles).where(
            team_members.c.organization_id == organization_id,
            team_members.c.status == "active",
            team_members.c.revoked_at.is_(None),
            team_members.c.removed_at.is_(None),
            or_(team_members.c.expires_at.is_(None), team_members.c.expires_at > func.now()),
        ).order_by(team_members.c.email)).all()
        return [email for email, roles in rows if EVENT_ROLES[event_type].intersection(roles)]


SecretResolver = Callable[[str], Mapping[str, str]]


class NotificationDeliveryWorker:
    def __init__(
        self,
        repository: NotificationDeliveryRepository,
        secret_resolver: SecretResolver,
        *,
        client: httpx.Client | None = None,
    ):
        self.repository = repository
        self.secret_resolver = secret_resolver
        self.client = client or httpx.Client(timeout=10)

    def run(self, *, limit: int = 20, now: datetime | None = None) -> list[DeliveryJob]:
        completed = []
        for _ in range(limit):
            job = self.repository.claim(now=now)
            if job is None:
                break
            completed.append(self._deliver(job, now=now))
        return completed

    def _deliver(self, job: DeliveryJob, *, now: datetime | None) -> DeliveryJob:
        try:
            integration = self._integration(job)
            secret = self.secret_resolver(integration["secret_reference"])
            response = self._send(job, integration, secret, now=now)
            if response.is_success:
                reference = response.headers.get("x-request-id")
                if not reference:
                    try:
                        reference = str(response.json().get("id", "")) or None
                    except (ValueError, AttributeError):
                        reference = None
                return self.repository.delivered(job, reference, now=now)
            retryable = (
                job.channel != "jira"
                and (response.status_code in {408, 425, 429} or response.status_code >= 500)
            )
            return self.repository.failed(
                job, f"http_{response.status_code}", retryable=retryable,
                retry_after_seconds=_retry_after(response), now=now,
            )
        except (httpx.TimeoutException, httpx.NetworkError):
            return self.repository.failed(
                job, "delivery_unknown" if job.channel == "jira" else "network_error",
                retryable=job.channel != "jira", now=now,
            )
        except (KeyError, TypeError, ValueError, DeliveryNotFound):
            return self.repository.failed(job, "configuration_error", retryable=False, now=now)

    def _integration(self, job: DeliveryJob) -> RowMapping:
        with Session(self.repository.engine) as session:
            row = session.execute(select(integrations).where(
                integrations.c.organization_id == job.organization_id,
                integrations.c.id == job.integration_id,
                integrations.c.type == job.channel,
                integrations.c.status == "connected",
            )).mappings().one_or_none()
        if row is None or not row["secret_reference"]:
            raise DeliveryNotFound("notification integration unavailable")
        return row

    def _send(
        self,
        job: DeliveryJob,
        integration: RowMapping,
        secret: Mapping[str, str],
        *,
        now: datetime | None,
    ) -> httpx.Response:
        config = dict(integration["configuration"])
        payload = dict(job.payload)
        if job.channel == "email":
            if config.get("provider") != "resend" or not secret.get("api_key"):
                raise ValueError("Resend is not configured")
            return self.client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {secret['api_key']}", "Idempotency-Key": job.idempotency_key},
                json={
                    "from": config["from_address"], "to": payload["recipients"],
                    "subject": payload["title"],
                    "text": f"{payload['detail']}\n\nOpen in Actis: {payload['target_url']}",
                },
            )
        if job.channel == "webhook":
            endpoint = _https_url(secret["endpoint_url"])
            if len(secret["signing_secret"]) < 32:
                raise ValueError("webhook signing secret must contain at least 32 characters")
            timestamp = str(int(_utc(now or datetime.now(timezone.utc)).timestamp()))
            body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            signature = hmac.new(
                secret["signing_secret"].encode(), timestamp.encode() + b"." + body, hashlib.sha256
            ).hexdigest()
            return self.client.post(
                endpoint,
                headers={
                    "Content-Type": "application/json", "Idempotency-Key": job.idempotency_key,
                    "X-Actis-Timestamp": timestamp, "X-Actis-Signature": f"sha256={signature}",
                },
                content=body,
            )
        site = config["site"]
        auth = base64.b64encode(f"{secret['email']}:{secret['api_token']}".encode()).decode()
        return self.client.post(
            f"https://{site}/rest/api/3/issue",
            headers={"Authorization": f"Basic {auth}", "Idempotency-Key": job.idempotency_key},
            json={
                "fields": {
                    "project": {"key": config["project_key"]},
                    "summary": payload["title"],
                    "issuetype": {"name": "Task"},
                    "description": {
                        "type": "doc", "version": 1,
                        "content": [{"type": "paragraph", "content": [{"type": "text", "text": payload["detail"]}]}],
                    },
                }
            },
        )


def environment_secret_resolver(reference: str) -> Mapping[str, str]:
    """Resolve platform-injected JSON without deriving a secret-bearing env name."""
    name = "PANDAX_NOTIFICATION_SECRET_" + hashlib.sha256(reference.encode()).hexdigest()[:16].upper()
    raw = os.environ.get(name, "")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"notification secret {name} is unavailable") from exc
    if not isinstance(value, dict) or not all(isinstance(key, str) and isinstance(item, str) for key, item in value.items()):
        raise ValueError(f"notification secret {name} must be a JSON string map")
    return value


def _event_type(notification: Mapping[str, Any]) -> str | None:
    kind = notification.get("kind")
    if kind == "finding" and notification.get("priority") in {"critical", "high"}:
        return "urgent_finding"
    if kind == "compliance":
        return "deadline"
    if kind == "monitoring":
        return "monitoring_failure"
    if kind == "document" and notification.get("requires_action"):
        return "approval_request"
    return None


def _job(row: RowMapping) -> DeliveryJob:
    values = dict(row)
    values["payload"] = dict(values["payload"])
    for name in ("next_attempt_at", "lease_until", "created_at", "updated_at", "delivered_at"):
        if values[name] is not None:
            values[name] = _utc(values[name])
    return DeliveryJob(**values)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _https_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("webhook endpoint must be an HTTPS URL without credentials or fragment")
    if parsed.hostname.casefold() == "localhost":
        raise ValueError("webhook endpoint cannot target localhost")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise ValueError("webhook endpoint must use a public address")
    return value


def _retry_after(response: httpx.Response) -> int | None:
    value = response.headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0, int(value))
    except ValueError:
        try:
            return max(0, int((parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()))
        except (TypeError, ValueError):
            return None


class NotificationDeliveryLoop:
    def __init__(
        self,
        worker_factory: Callable[[], NotificationDeliveryWorker],
        *,
        interval_seconds: float = 30,
        growth_allowed: Callable[[], bool] | None = None,
    ):
        self.worker_factory = worker_factory
        self.interval_seconds = max(1.0, interval_seconds)
        self.growth_allowed = growth_allowed or (lambda: True)
        self.last_error: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run_forever, name="actis-notification-delivery", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.interval_seconds + 1)

    def run_once(self) -> int:
        try:
            if not self.growth_allowed():
                self.last_error = "database capacity restricts external delivery"
                return 0
            completed = self.worker_factory().run()
            self.last_error = None
            return len(completed)
        except Exception as exc:
            self.last_error = str(exc)
            return 0

    def _run_forever(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self.run_once()
