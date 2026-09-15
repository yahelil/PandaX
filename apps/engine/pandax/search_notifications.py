"""Tenant-safe portfolio search and durable notification inbox."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    Table,
    UniqueConstraint,
    and_,
    func,
    insert,
    or_,
    select,
    update,
)
from sqlalchemy.engine import Engine, RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .compliance import compliance_items
from .documents import documents
from .findings import findings
from .notification_delivery import DeliveryJob, NotificationDeliveryRepository
from .portfolio import portfolio_metadata, products, releases


class SearchNotificationError(RuntimeError):
    pass


class NotificationNotFound(SearchNotificationError):
    pass


class SearchNotificationConflict(SearchNotificationError):
    pass


class SearchNotificationValidationError(SearchNotificationError):
    pass


SEARCH_CATEGORIES = frozenset({"products", "releases", "findings", "compliance", "documents"})
NOTIFICATION_KINDS = frozenset({"finding", "compliance", "monitoring", "document", "analysis", "system"})
NOTIFICATION_PRIORITIES = frozenset({"critical", "high", "medium", "low", "info"})
PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CATEGORY_ORDER = {name: index for index, name in enumerate(("products", "releases", "findings", "compliance", "documents"))}


@dataclass(frozen=True, slots=True)
class SearchResult:
    category: str
    id: str
    title: str
    subtitle: str
    product_id: str | None
    release_id: str | None
    priority: str | None
    url: str
    rank: int


@dataclass(frozen=True, slots=True)
class NotificationInput:
    source_fingerprint: str
    kind: str
    priority: str
    title: str
    detail: str
    target_url: str
    requires_action: bool = False
    product_id: str | None = None
    release_id: str | None = None


@dataclass(frozen=True, slots=True)
class NotificationRecord:
    id: str
    organization_id: str
    source_fingerprint: str
    content_fingerprint: str
    kind: str
    priority: str
    title: str
    detail: str
    product_id: str | None
    release_id: str | None
    target_url: str
    requires_action: bool
    read_at: datetime | None
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime


notifications = Table(
    "notifications",
    portfolio_metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("source_fingerprint", String(160), nullable=False),
    Column("content_fingerprint", String(64), nullable=False),
    Column("kind", String(24), nullable=False),
    Column("priority", String(16), nullable=False),
    Column("title", String(240), nullable=False),
    Column("detail", String(2000), nullable=False),
    Column("product_id", String(36), nullable=True),
    Column("release_id", String(36), nullable=True),
    Column("target_url", String(1000), nullable=False),
    Column("requires_action", Boolean, nullable=False),
    Column("read_at", DateTime(timezone=True), nullable=True),
    Column("acknowledged_at", DateTime(timezone=True), nullable=True),
    Column("acknowledged_by", String(128), nullable=True),
    Column("first_seen_at", DateTime(timezone=True), nullable=False),
    Column("last_seen_at", DateTime(timezone=True), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    ForeignKeyConstraint(
        ["product_id", "organization_id"],
        [products.c.id, products.c.organization_id],
        name="fk_notifications_product_org",
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["release_id", "product_id", "organization_id"],
        [releases.c.id, releases.c.product_id, releases.c.organization_id],
        name="fk_notifications_release_scope",
        ondelete="CASCADE",
    ),
    UniqueConstraint("organization_id", "source_fingerprint", name="uq_notifications_source"),
    CheckConstraint("length(content_fingerprint) = 64", name="content_fingerprint_length"),
)
Index(
    "ix_notifications_inbox",
    notifications.c.organization_id,
    notifications.c.acknowledged_at,
    notifications.c.read_at,
    notifications.c.priority,
)
Index("ix_notifications_target", notifications.c.organization_id, notifications.c.product_id, notifications.c.release_id)
Index("ix_portfolio_products_search", products.c.organization_id, products.c.name, products.c.identifier)
Index("ix_portfolio_releases_search", releases.c.organization_id, releases.c.version)
Index("ix_findings_search", findings.c.organization_id, findings.c.reference_id, findings.c.component)
Index("ix_compliance_items_search", compliance_items.c.organization_id, compliance_items.c.title)
Index("ix_regulatory_documents_search", documents.c.organization_id, documents.c.name)


class SearchNotificationRepository:
    def __init__(self, engine: Engine, *, delivery_daily_limit: int = 500):
        self.engine = engine
        self.delivery_daily_limit = delivery_daily_limit

    def create_schema(self) -> None:
        portfolio_metadata.create_all(self.engine)

    def search(
        self,
        organization_id: str,
        query: str,
        *,
        categories: Sequence[str] = (),
        limit: int = 20,
    ) -> list[SearchResult]:
        term = _query(query)
        if not 1 <= limit <= 50:
            raise SearchNotificationValidationError("limit must be between 1 and 50")
        selected = tuple(_choice(value, SEARCH_CATEGORIES, "category") for value in categories)
        if len(selected) != len(set(selected)):
            raise SearchNotificationValidationError("duplicate search category")
        wanted = frozenset(selected) if selected else SEARCH_CATEGORIES
        candidate_limit = 50
        pattern = f"%{_escape_like(term.casefold())}%"
        results: list[SearchResult] = []
        with Session(self.engine) as session:
            if "products" in wanted:
                rows = session.execute(
                    select(products).where(
                        products.c.organization_id == organization_id,
                        _matches(pattern, products.c.name, products.c.identifier, products.c.manufacturer),
                    ).order_by(products.c.id).limit(candidate_limit)
                ).mappings().all()
                for row in rows:
                    title = row["name"]
                    results.append(SearchResult(
                        "products", row["id"], title,
                        f"{row['identifier']} · {row['manufacturer']}", row["id"], None,
                        _readiness_priority(row["readiness"]), f"/products/{row['id']}",
                        _rank(term, title, row["identifier"], row["manufacturer"]),
                    ))
            if "releases" in wanted:
                rows = session.execute(
                    select(releases, products.c.name.label("product_name"))
                    .join(products, and_(
                        releases.c.product_id == products.c.id,
                        releases.c.organization_id == products.c.organization_id,
                    ))
                    .where(
                        releases.c.organization_id == organization_id,
                        _matches(pattern, releases.c.version, products.c.name, releases.c.channel),
                    ).order_by(releases.c.id).limit(candidate_limit)
                ).mappings().all()
                for row in rows:
                    title = f"{row['product_name']} {row['version']}"
                    results.append(SearchResult(
                        "releases", row["id"], title,
                        f"{row['channel']} · {row['status']}", row["product_id"], row["id"],
                        _readiness_priority(row["readiness"]),
                        f"/products/{row['product_id']}/releases/{row['id']}",
                        _rank(term, title, row["version"], row["product_name"]),
                    ))
            if "findings" in wanted:
                rows = session.execute(
                    select(findings).where(
                        findings.c.organization_id == organization_id,
                        _matches(
                            pattern, findings.c.reference_id, findings.c.cve,
                            findings.c.title, findings.c.component, findings.c.purl,
                        ),
                    ).order_by(findings.c.id).limit(candidate_limit)
                ).mappings().all()
                for row in rows:
                    title = row["cve"] or row["reference_id"]
                    results.append(SearchResult(
                        "findings", row["id"], title,
                        f"{row['component']} {row['component_version']} · {row['title']}",
                        row["product_id"], row["release_id"], row["severity"],
                        f"/findings/{row['id']}",
                        _rank(term, title, row["reference_id"], row["title"], row["component"], row["purl"]),
                    ))
            if "compliance" in wanted:
                rows = session.execute(
                    select(compliance_items).where(
                        compliance_items.c.organization_id == organization_id,
                        _matches(pattern, compliance_items.c.title, compliance_items.c.description, compliance_items.c.kind),
                    ).order_by(compliance_items.c.id).limit(candidate_limit)
                ).mappings().all()
                for row in rows:
                    results.append(SearchResult(
                        "compliance", row["id"], row["title"],
                        f"{row['kind'].replace('_', ' ')} · {row['status'].replace('_', ' ')}",
                        row["product_id"], row["release_id"], row["priority"],
                        f"/compliance?item={row['id']}",
                        _rank(term, row["title"], row["description"], row["kind"]),
                    ))
            if "documents" in wanted:
                rows = session.execute(
                    select(documents).where(
                        documents.c.organization_id == organization_id,
                        _matches(pattern, documents.c.name, documents.c.kind, documents.c.case_id),
                    ).order_by(documents.c.id).limit(candidate_limit)
                ).mappings().all()
                for row in rows:
                    results.append(SearchResult(
                        "documents", row["id"], row["name"],
                        f"{row['kind'].replace('_', ' ')} · revision {row['current_revision']}",
                        row["product_id"], row["release_id"], None,
                        f"/documents/{row['id']}",
                        _rank(term, row["name"], row["kind"], row["case_id"]),
                    ))
        results.sort(key=lambda item: (item.rank, CATEGORY_ORDER[item.category], item.title.casefold(), item.id))
        return results[:limit]

    def upsert_notification(
        self,
        organization_id: str,
        notification: NotificationInput | Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> NotificationRecord:
        item = _notification_input(notification)
        timestamp = _utc(now or datetime.now(timezone.utc))
        material = {
            "kind": item.kind,
            "priority": item.priority,
            "title": item.title,
            "detail": item.detail,
            "product_id": item.product_id,
            "release_id": item.release_id,
            "target_url": item.target_url,
            "requires_action": item.requires_action,
        }
        digest = hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        with Session(self.engine) as session, session.begin():
            self._validate_target(session, organization_id, item.product_id, item.release_id)
            current = session.execute(select(notifications).where(
                notifications.c.organization_id == organization_id,
                notifications.c.source_fingerprint == item.source_fingerprint,
            )).mappings().one_or_none()
            if current is None:
                values = {
                    "id": str(uuid4()), "organization_id": organization_id,
                    "source_fingerprint": item.source_fingerprint,
                    "content_fingerprint": digest, **material,
                    "read_at": None, "acknowledged_at": None, "acknowledged_by": None,
                    "first_seen_at": timestamp, "last_seen_at": timestamp,
                    "created_at": timestamp, "updated_at": timestamp,
                }
                try:
                    session.execute(insert(notifications).values(**values))
                except IntegrityError as exc:
                    raise SearchNotificationConflict("notification source already exists") from exc
                notification_id = values["id"]
            else:
                notification_id = current["id"]
                values = {**material, "content_fingerprint": digest, "last_seen_at": timestamp, "updated_at": timestamp}
                if current["content_fingerprint"] != digest:
                    values.update(read_at=None, acknowledged_at=None, acknowledged_by=None)
                session.execute(update(notifications).where(notifications.c.id == notification_id).values(**values))
            NotificationDeliveryRepository(
                self.engine, daily_limit=self.delivery_daily_limit
            ).enqueue(
                session, organization_id, notification_id, digest, material, timestamp
            )
        return self.get_notification(organization_id, notification_id)

    def get_notification(self, organization_id: str, notification_id: str) -> NotificationRecord:
        with Session(self.engine) as session:
            row = session.execute(select(notifications).where(
                notifications.c.organization_id == organization_id,
                notifications.c.id == notification_id,
            )).mappings().one_or_none()
        if row is None:
            raise NotificationNotFound("notification not found")
        return _notification_record(row)

    def list_notifications(
        self,
        organization_id: str,
        *,
        view: str = "unread_action",
        kind: str | None = None,
        priority: str | None = None,
        product_id: str | None = None,
        limit: int = 50,
    ) -> list[NotificationRecord]:
        if view not in {"unread_action", "unread", "action", "all"}:
            raise SearchNotificationValidationError("invalid notification view")
        if not 1 <= limit <= 100:
            raise SearchNotificationValidationError("limit must be between 1 and 100")
        conditions = [notifications.c.organization_id == organization_id]
        if view == "unread_action":
            conditions.append(or_(
                notifications.c.read_at.is_(None),
                and_(notifications.c.requires_action.is_(True), notifications.c.acknowledged_at.is_(None)),
            ))
        elif view == "unread":
            conditions.append(notifications.c.read_at.is_(None))
        elif view == "action":
            conditions.extend((notifications.c.requires_action.is_(True), notifications.c.acknowledged_at.is_(None)))
        if kind:
            conditions.append(notifications.c.kind == _choice(kind, NOTIFICATION_KINDS, "kind"))
        if priority:
            conditions.append(notifications.c.priority == _choice(priority, NOTIFICATION_PRIORITIES, "priority"))
        if product_id:
            conditions.append(notifications.c.product_id == product_id)
        with Session(self.engine) as session:
            rows = session.execute(select(notifications).where(and_(*conditions))).mappings().all()
        records = [_notification_record(row) for row in rows]
        records.sort(key=lambda item: (PRIORITY_ORDER[item.priority], -item.last_seen_at.timestamp(), item.id))
        return records[:limit]

    def mark_read(
        self, organization_id: str, notification_id: str, *, now: datetime | None = None
    ) -> NotificationRecord:
        return self._mark(organization_id, notification_id, read=True, actor_id=None, now=now)

    def acknowledge(
        self, organization_id: str, notification_id: str, *, actor_id: str,
        now: datetime | None = None,
    ) -> NotificationRecord:
        return self._mark(
            organization_id, notification_id, read=True,
            actor_id=_required(actor_id, "actor_id", 128), now=now,
        )

    def list_deliveries(
        self, organization_id: str, *, status: str | None = None, limit: int = 100
    ) -> list[DeliveryJob]:
        return NotificationDeliveryRepository(self.engine).list(
            organization_id, status=status, limit=limit
        )

    def retry_delivery(
        self, organization_id: str, delivery_id: str, *, now: datetime | None = None
    ) -> DeliveryJob:
        return NotificationDeliveryRepository(self.engine).retry(
            organization_id, delivery_id, now=now
        )

    def _mark(
        self, organization_id: str, notification_id: str, *, read: bool,
        actor_id: str | None, now: datetime | None,
    ) -> NotificationRecord:
        timestamp = _utc(now or datetime.now(timezone.utc))
        current = self.get_notification(organization_id, notification_id)
        if actor_id and current.acknowledged_at is not None:
            return current
        if not actor_id and read and current.read_at is not None:
            return current
        values: dict[str, Any] = {"updated_at": timestamp}
        if read:
            values["read_at"] = timestamp
        if actor_id:
            values.update(acknowledged_at=timestamp, acknowledged_by=actor_id)
        with self.engine.begin() as connection:
            result = connection.execute(update(notifications).where(
                notifications.c.organization_id == organization_id,
                notifications.c.id == notification_id,
            ).values(**values))
        if result.rowcount != 1:
            raise NotificationNotFound("notification not found")
        return self.get_notification(organization_id, notification_id)

    @staticmethod
    def _validate_target(
        session: Session, organization_id: str, product_id: str | None, release_id: str | None
    ) -> None:
        if release_id and not product_id:
            raise SearchNotificationValidationError("release notification requires product_id")
        if product_id and session.execute(select(products.c.id).where(
            products.c.organization_id == organization_id, products.c.id == product_id,
        )).one_or_none() is None:
            raise NotificationNotFound("product not found")
        if release_id and session.execute(select(releases.c.id).where(
            releases.c.organization_id == organization_id,
            releases.c.product_id == product_id,
            releases.c.id == release_id,
        )).one_or_none() is None:
            raise NotificationNotFound("release not found")


def _matches(pattern: str, *columns: Any):
    return or_(*(func.lower(column).like(pattern, escape="\\") for column in columns))


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _rank(term: str, *values: str | None) -> int:
    candidates = [value.casefold() for value in values if value]
    needle = term.casefold()
    if needle in candidates:
        return 0
    if any(value.startswith(needle) for value in candidates):
        return 1
    if any(any(word.startswith(needle) for word in value.replace("_", " ").split()) for value in candidates):
        return 2
    return 3


def _query(value: str) -> str:
    clean = " ".join(value.split()) if isinstance(value, str) else ""
    if len(clean) < 2:
        raise SearchNotificationValidationError("query must contain at least 2 characters")
    if len(clean) > 100:
        raise SearchNotificationValidationError("query is too long")
    return clean


def _notification_input(value: NotificationInput | Mapping[str, Any]) -> NotificationInput:
    if isinstance(value, Mapping):
        try:
            value = NotificationInput(**value)
        except TypeError as exc:
            raise SearchNotificationValidationError("invalid notification") from exc
    return NotificationInput(
        source_fingerprint=_required(value.source_fingerprint, "source_fingerprint", 160),
        kind=_choice(value.kind, NOTIFICATION_KINDS, "kind"),
        priority=_choice(value.priority, NOTIFICATION_PRIORITIES, "priority"),
        title=_required(value.title, "title", 240),
        detail=_required(value.detail, "detail", 2000),
        target_url=_target_url(value.target_url),
        requires_action=bool(value.requires_action),
        product_id=_optional(value.product_id, "product_id", 36),
        release_id=_optional(value.release_id, "release_id", 36),
    )


def _notification_record(row: RowMapping) -> NotificationRecord:
    values = dict(row)
    for field in ("read_at", "acknowledged_at", "first_seen_at", "last_seen_at", "created_at", "updated_at"):
        if values[field] is not None:
            values[field] = _as_utc(values[field])
    return NotificationRecord(**values)


def _readiness_priority(value: str) -> str | None:
    return {"needs_attention": "high", "incomplete_evidence": "medium"}.get(value)


def _target_url(value: str) -> str:
    clean = _required(value, "target_url", 1000)
    if not clean.startswith("/") or clean.startswith("//"):
        raise SearchNotificationValidationError("target_url must be an application-relative path")
    return clean


def _choice(value: str, choices: frozenset[str], name: str) -> str:
    clean = _required(value, name, 40).lower()
    if clean not in choices:
        raise SearchNotificationValidationError(f"invalid {name}")
    return clean


def _required(value: str, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SearchNotificationValidationError(f"{name} is required")
    clean = value.strip()
    if len(clean) > maximum:
        raise SearchNotificationValidationError(f"{name} is too long")
    return clean


def _optional(value: str | None, name: str, maximum: int) -> str | None:
    return None if value is None else _required(value, name, maximum)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise SearchNotificationValidationError("timestamp must include timezone")
    return value.astimezone(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
