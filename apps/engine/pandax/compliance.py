"""Tenant-scoped CRA compliance obligations and case projections.

This module deliberately models evidence gaps and reporting work as obligations,
not as a percentage. An obligation is only ready after its required lifecycle is
complete; importing a case can therefore never turn missing proof into readiness.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Iterator, Mapping, Protocol
from uuid import uuid4

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKeyConstraint,
    Integer,
    String,
    Table,
    UniqueConstraint,
    and_,
    case as sql_case,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Engine, RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .portfolio import portfolio_metadata, products, releases


class ComplianceError(RuntimeError):
    """Base error safe for translation at the HTTP boundary."""


class ComplianceNotFound(ComplianceError):
    pass


class ComplianceConflict(ComplianceError):
    pass


class ComplianceValidationError(ComplianceError):
    pass


KINDS = frozenset({"deadline", "missing_evidence", "missing_document", "reporting_case", "approval"})
PRIORITIES = frozenset({"critical", "high", "medium", "low"})
STATUSES = frozenset({"action_required", "in_progress", "pending_approval", "approved", "acknowledged", "resolved"})
REPORTING_STAGES = frozenset({"early_warning", "notification", "final_report"})
READ_ROLES = frozenset({"org_admin", "compliance_operator", "authorized_approver", "security_reviewer", "viewer"})
EDIT_ROLES = frozenset({"org_admin", "compliance_operator", "security_reviewer"})
APPROVE_ROLES = frozenset({"org_admin", "authorized_approver"})


@dataclass(frozen=True, slots=True)
class ComplianceItemRecord:
    id: str
    organization_id: str
    product_id: str | None
    release_id: str | None
    kind: str
    title: str
    description: str
    priority: str
    status: str
    due_at: datetime | None
    owner_id: str | None
    source_type: str
    source_id: str
    reporting_stage: str | None
    self_filing_record_id: str | None
    self_filing_record_url: str | None
    approved_by: str | None
    approved_at: datetime | None
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    version: int
    created_at: datetime
    updated_at: datetime

    @property
    def readiness(self) -> str:
        if self.status == "resolved":
            return "ready"
        if self.status in {"pending_approval", "approved", "acknowledged"}:
            return "review_required"
        return "action_required"


@dataclass(frozen=True, slots=True)
class ComplianceAuditRecord:
    id: str
    organization_id: str
    item_id: str
    action: str
    actor_id: str
    item_version: int
    occurred_at: datetime
    payload: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ComplianceChanges:
    title: str | None = None
    description: str | None = None
    priority: str | None = None
    status: str | None = None
    due_at: datetime | None = None
    clear_due_at: bool = False
    owner_id: str | None = None
    clear_owner: bool = False
    self_filing_record_id: str | None = None
    self_filing_record_url: str | None = None


class ComplianceCaseImporter(Protocol):
    """Replaceable reader for the legacy CaseStore or a future case service."""

    def list_cases(self, organization_id: str) -> Iterable[Mapping[str, Any]]: ...


CaseTargetResolver = Callable[[Mapping[str, Any]], tuple[str | None, str | None]]


class CaseStoreImporter:
    """Read-only adapter; it never mutates the existing case workflow."""

    def __init__(
        self,
        store: Any,
        *,
        organization_id: str,
        target_resolver: CaseTargetResolver | None = None,
    ) -> None:
        self.store = store
        self.organization_id = organization_id
        self.target_resolver = target_resolver or (lambda _case: (None, None))

    def list_cases(self, organization_id: str) -> Iterable[Mapping[str, Any]]:
        if organization_id != self.organization_id:
            return ()
        result = []
        for case in self.store.list():
            product_id, release_id = self.target_resolver(case)
            result.append({**case, "product_id": product_id, "release_id": release_id})
        return result


compliance_items = Table(
    "compliance_items",
    portfolio_metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("product_id", String(36), nullable=True),
    Column("release_id", String(36), nullable=True),
    Column("kind", String(32), nullable=False),
    Column("title", String(240), nullable=False),
    Column("description", String(3000), nullable=False),
    Column("priority", String(16), nullable=False),
    Column("status", String(32), nullable=False),
    Column("due_at", DateTime(timezone=True), nullable=True),
    Column("owner_id", String(128), nullable=True),
    Column("source_type", String(48), nullable=False),
    Column("source_id", String(200), nullable=False),
    Column("reporting_stage", String(32), nullable=True),
    Column("self_filing_record_id", String(200), nullable=True),
    Column("self_filing_record_url", String(1000), nullable=True),
    Column("approved_by", String(128), nullable=True),
    Column("approved_at", DateTime(timezone=True), nullable=True),
    Column("acknowledged_at", DateTime(timezone=True), nullable=True),
    Column("resolved_at", DateTime(timezone=True), nullable=True),
    Column("version", Integer, nullable=False, default=0),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    ForeignKeyConstraint(
        ["product_id", "organization_id"],
        [products.c.id, products.c.organization_id],
        name="fk_compliance_items_product_org",
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["release_id", "product_id", "organization_id"],
        [releases.c.id, releases.c.product_id, releases.c.organization_id],
        name="fk_compliance_items_release_product_org",
        ondelete="CASCADE",
    ),
    UniqueConstraint(
        "organization_id", "source_type", "source_id", "reporting_stage",
        name="uq_compliance_items_source_stage",
    ),
    CheckConstraint("version >= 0", name="compliance_item_version"),
)


compliance_audit_events = Table(
    "compliance_audit_events",
    portfolio_metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("item_id", String(36), nullable=False),
    Column("action", String(80), nullable=False),
    Column("actor_id", String(128), nullable=False),
    Column("item_version", Integer, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    Column("payload", JSON, nullable=False),
    ForeignKeyConstraint(
        ["item_id", "organization_id"],
        [compliance_items.c.id, compliance_items.c.organization_id],
        name="fk_compliance_audit_item_org",
        ondelete="CASCADE",
    ),
)

# Required for the composite audit FK.
compliance_items.append_constraint(
    UniqueConstraint("id", "organization_id", name="uq_compliance_items_id_org")
)


_TRANSITIONS = {
    "action_required": frozenset({"in_progress", "pending_approval", "resolved"}),
    "in_progress": frozenset({"action_required", "pending_approval", "resolved"}),
    "pending_approval": frozenset({"action_required", "in_progress"}),
    "approved": frozenset({"acknowledged", "resolved"}),
    "acknowledged": frozenset({"resolved"}),
    "resolved": frozenset(),
}


class ComplianceRepository:
    def __init__(self, engine: Engine, *, clock: Callable[[], datetime] | None = None):
        self.engine = engine
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def create_schema(self) -> None:
        portfolio_metadata.create_all(self.engine)

    def create_item(
        self,
        organization_id: str,
        *,
        kind: str,
        title: str,
        description: str,
        priority: str,
        source_type: str,
        source_id: str,
        actor_id: str,
        product_id: str | None = None,
        release_id: str | None = None,
        status: str = "action_required",
        due_at: datetime | None = None,
        owner_id: str | None = None,
        reporting_stage: str | None = None,
        item_id: str | None = None,
        self_filing_record_id: str | None = None,
        self_filing_record_url: str | None = None,
    ) -> ComplianceItemRecord:
        values = self._validated_values(
            organization_id=organization_id,
            product_id=product_id,
            release_id=release_id,
            kind=kind,
            title=title,
            description=description,
            priority=priority,
            status=status,
            due_at=due_at,
            owner_id=owner_id,
            source_type=source_type,
            source_id=source_id,
            reporting_stage=reporting_stage,
            self_filing_record_id=self_filing_record_id,
            self_filing_record_url=self_filing_record_url,
        )
        now = _utc(self.clock())
        values.update(
            id=item_id or str(uuid4()), approved_by=None, approved_at=None,
            acknowledged_at=None, resolved_at=now if status == "resolved" else None,
            version=0, created_at=now, updated_at=now,
        )
        with self._transaction() as session:
            self._validate_target(session, organization_id, product_id, release_id)
            try:
                session.execute(insert(compliance_items).values(**values))
                session.flush()
            except IntegrityError as exc:
                raise ComplianceConflict("compliance source already projected") from exc
            self._audit(session, values, "compliance.created", actor_id, values)
        return self.get_item(organization_id, values["id"])

    def get_item(self, organization_id: str, item_id: str) -> ComplianceItemRecord:
        with Session(self.engine) as session:
            row = session.execute(
                select(compliance_items).where(
                    (compliance_items.c.organization_id == organization_id)
                    & (compliance_items.c.id == item_id)
                )
            ).mappings().one_or_none()
        if row is None:
            raise ComplianceNotFound("compliance item not found")
        return _item(row)

    def list_items(
        self,
        organization_id: str,
        *,
        action_only: bool = True,
        kind: str | None = None,
        status: str | None = None,
        priority: str | None = None,
        product_id: str | None = None,
        release_id: str | None = None,
        owner_id: str | None = None,
        sort: str = "due_at",
        descending: bool = False,
    ) -> list[ComplianceItemRecord]:
        statement = select(compliance_items).where(compliance_items.c.organization_id == organization_id)
        if action_only:
            statement = statement.where(compliance_items.c.status != "resolved")
        filters = {
            "kind": kind,
            "status": status,
            "priority": priority,
            "product_id": product_id,
            "release_id": release_id,
            "owner_id": owner_id,
        }
        for field, value in filters.items():
            if value is not None:
                statement = statement.where(getattr(compliance_items.c, field) == value)
        columns = {
            "due_at": compliance_items.c.due_at,
            "priority": sql_case(
                {"critical": 0, "high": 1, "medium": 2, "low": 3},
                value=compliance_items.c.priority,
                else_=4,
            ),
            "updated_at": compliance_items.c.updated_at,
            "status": sql_case(
                {
                    "action_required": 0, "in_progress": 1,
                    "pending_approval": 2, "approved": 3,
                    "acknowledged": 4, "resolved": 5,
                },
                value=compliance_items.c.status,
                else_=6,
            ),
        }
        if sort not in columns:
            raise ComplianceValidationError("invalid sort")
        order = columns[sort].desc() if descending else columns[sort].asc()
        # Null due dates are placed last on both SQLite and PostgreSQL.
        ordering = [order, compliance_items.c.id]
        if sort == "due_at":
            ordering.insert(0, compliance_items.c.due_at.is_(None))
        statement = statement.order_by(*ordering)
        with Session(self.engine) as session:
            rows = session.execute(statement).mappings().all()
        return [_item(row) for row in rows]

    def update_item(
        self,
        organization_id: str,
        item_id: str,
        expected_version: int,
        changes: ComplianceChanges,
        actor_id: str,
    ) -> ComplianceItemRecord:
        current = self.get_item(organization_id, item_id)
        if expected_version != current.version:
            raise ComplianceConflict("stale compliance item version")
        values = {
            key: value for key, value in asdict(changes).items()
            if value is not None and key not in {"clear_due_at", "clear_owner"}
        }
        if changes.clear_due_at:
            values["due_at"] = None
        if changes.clear_owner:
            values["owner_id"] = None
        if "title" in values:
            values["title"] = _required(values["title"], "title")
        if "priority" in values:
            values["priority"] = _choice(values["priority"], PRIORITIES, "priority")
        if "status" in values:
            status = _choice(values["status"], STATUSES, "status")
            if status == "approved":
                raise ComplianceValidationError("use approval action to approve an item")
            if status != current.status and status not in _TRANSITIONS[current.status]:
                raise ComplianceConflict(f"cannot transition {current.status} to {status}")
            if current.kind == "reporting_case" and status == "resolved" and current.status != "acknowledged":
                raise ComplianceConflict("reporting case must be acknowledged before resolution")
            now = _utc(self.clock())
            if status == "acknowledged":
                values["acknowledged_at"] = now
            if status == "resolved":
                values["resolved_at"] = now
        self._validate_filing_link(current, values)
        if not values:
            raise ComplianceValidationError("at least one change is required")
        return self._write(current, values, expected_version, actor_id, "compliance.updated")

    def approve_item(
        self,
        organization_id: str,
        item_id: str,
        expected_version: int,
        actor_id: str,
        *,
        self_filing_record_id: str | None = None,
        self_filing_record_url: str | None = None,
    ) -> ComplianceItemRecord:
        current = self.get_item(organization_id, item_id)
        if expected_version != current.version:
            raise ComplianceConflict("stale compliance item version")
        if current.status != "pending_approval":
            raise ComplianceConflict("item must be pending approval")
        now = _utc(self.clock())
        values: dict[str, Any] = {
            "status": "approved", "approved_by": _required(actor_id, "actor_id"),
            "approved_at": now,
        }
        if self_filing_record_id is not None:
            values["self_filing_record_id"] = _required(self_filing_record_id, "self_filing_record_id")
        if self_filing_record_url is not None:
            values["self_filing_record_url"] = _required(self_filing_record_url, "self_filing_record_url")
        self._validate_filing_link(current, values)
        return self._write(current, values, expected_version, actor_id, "compliance.approved")

    def list_audit_events(self, organization_id: str, item_id: str) -> list[ComplianceAuditRecord]:
        # Tenant-scoped lookup prevents audit existence from leaking across organizations.
        self.get_item(organization_id, item_id)
        with Session(self.engine) as session:
            rows = session.execute(
                select(compliance_audit_events).where(
                    (compliance_audit_events.c.organization_id == organization_id)
                    & (compliance_audit_events.c.item_id == item_id)
                ).order_by(compliance_audit_events.c.item_version, compliance_audit_events.c.occurred_at)
            ).mappings().all()
        return [_audit_record(row) for row in rows]

    def project_cases(
        self,
        organization_id: str,
        importer: ComplianceCaseImporter,
        actor_id: str = "case-projector",
    ) -> list[ComplianceItemRecord]:
        projected: list[ComplianceItemRecord] = []
        for case in importer.list_cases(organization_id):
            case_id = _required(case.get("id"), "case id")
            for stage in ("early_warning", "notification", "final_report"):
                projected.append(self._upsert_case_stage(organization_id, case_id, stage, case, actor_id))
        return projected

    def _upsert_case_stage(
        self,
        organization_id: str,
        case_id: str,
        stage: str,
        case: Mapping[str, Any],
        actor_id: str,
    ) -> ComplianceItemRecord:
        values = _case_projection(case_id, stage, case, _utc(self.clock()))
        with Session(self.engine) as session:
            row = session.execute(select(compliance_items).where(and_(
                compliance_items.c.organization_id == organization_id,
                compliance_items.c.source_type == "case_store",
                compliance_items.c.source_id == case_id,
                compliance_items.c.reporting_stage == stage,
            ))).mappings().one_or_none()
        if row is None:
            return self.create_item(organization_id, actor_id=actor_id, **values)
        current = _item(row)
        changed = {
            key: value for key, value in values.items()
            if key in {"product_id", "release_id", "title", "description", "priority", "status", "due_at", "owner_id", "self_filing_record_id", "self_filing_record_url"}
            and getattr(current, key) != value
        }
        if not changed:
            return current
        now = _utc(self.clock())
        if changed.get("status") == "approved":
            changed.update(approved_by="case-workflow", approved_at=now)
        elif "status" in changed and changed["status"] not in {"approved", "acknowledged", "resolved"}:
            changed.update(approved_by=None, approved_at=None, acknowledged_at=None, resolved_at=None)
        if changed.get("status") == "acknowledged":
            changed["acknowledged_at"] = now
        if changed.get("status") == "resolved":
            changed["resolved_at"] = now
        return self._write(current, changed, current.version, actor_id, "compliance.case_projected")

    def _write(
        self,
        current: ComplianceItemRecord,
        values: dict[str, Any],
        expected_version: int,
        actor_id: str,
        action: str,
    ) -> ComplianceItemRecord:
        values = dict(values)
        values.update(version=expected_version + 1, updated_at=_utc(self.clock()))
        with self._transaction() as session:
            self._validate_target(
                session,
                current.organization_id,
                values.get("product_id", current.product_id),
                values.get("release_id", current.release_id),
            )
            result = session.execute(
                update(compliance_items).where(and_(
                    compliance_items.c.organization_id == current.organization_id,
                    compliance_items.c.id == current.id,
                    compliance_items.c.version == expected_version,
                )).values(**values)
            )
            if result.rowcount != 1:
                raise ComplianceConflict("stale compliance item version")
            event_values = {**asdict(current), **values}
            self._audit(session, event_values, action, actor_id, values)
        return self.get_item(current.organization_id, current.id)

    def _validated_values(self, **values: Any) -> dict[str, Any]:
        values = dict(values)
        values["kind"] = _choice(values["kind"], KINDS, "kind")
        values["priority"] = _choice(values["priority"], PRIORITIES, "priority")
        values["status"] = _choice(values["status"], STATUSES, "status")
        values["title"] = _required(values["title"], "title")
        values["description"] = str(values["description"] or "").strip()
        values["source_type"] = _required(values["source_type"], "source_type")
        values["source_id"] = _required(values["source_id"], "source_id")
        if values["release_id"] and not values["product_id"]:
            raise ComplianceValidationError("release target requires product target")
        stage = values["reporting_stage"]
        if values["kind"] == "reporting_case":
            values["reporting_stage"] = _choice(stage, REPORTING_STAGES, "reporting_stage")
        elif stage is not None:
            raise ComplianceValidationError("reporting_stage is only valid for reporting cases")
        if values["due_at"] is not None:
            values["due_at"] = _utc(values["due_at"])
        for field in ("self_filing_record_id", "self_filing_record_url"):
            if values[field] is not None:
                values[field] = _required(values[field], field)
        return values

    @staticmethod
    def _validate_target(
        session: Session,
        organization_id: str,
        product_id: str | None,
        release_id: str | None,
    ) -> None:
        if product_id is None:
            return
        product = session.execute(select(products.c.id).where(and_(
            products.c.organization_id == organization_id,
            products.c.id == product_id,
        ))).scalar_one_or_none()
        if product is None:
            raise ComplianceNotFound("product not found")
        if release_id is not None:
            release = session.execute(select(releases.c.id).where(and_(
                releases.c.organization_id == organization_id,
                releases.c.product_id == product_id,
                releases.c.id == release_id,
            ))).scalar_one_or_none()
            if release is None:
                raise ComplianceNotFound("release not found")

    @staticmethod
    def _validate_filing_link(current: ComplianceItemRecord, values: Mapping[str, Any]) -> None:
        for field in ("self_filing_record_id", "self_filing_record_url"):
            incoming = values.get(field)
            existing = getattr(current, field)
            if existing is not None and incoming is not None and incoming != existing:
                raise ComplianceConflict("self-filing record link is immutable")

    @contextmanager
    def _transaction(self) -> Iterator[Session]:
        with Session(self.engine) as session:
            with session.begin():
                yield session

    def _audit(
        self,
        session: Session,
        item: Mapping[str, Any],
        action: str,
        actor_id: str,
        payload: Mapping[str, Any],
    ) -> None:
        session.execute(insert(compliance_audit_events).values(
            id=str(uuid4()), organization_id=item["organization_id"], item_id=item["id"],
            action=action, actor_id=_required(actor_id, "actor_id"), item_version=item["version"],
            occurred_at=_utc(self.clock()), payload=_json_payload(payload),
        ))


def _case_projection(
    case_id: str,
    stage: str,
    case: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    deadlines = case.get("deadlines") if isinstance(case.get("deadlines"), Mapping) else {}
    due_at = _timestamp(deadlines.get(stage))
    submissions = case.get("submissions") if isinstance(case.get("submissions"), list) else []
    actual = [
        item for item in submissions
        if isinstance(item, Mapping)
        and isinstance(item.get("payload"), Mapping)
        and item["payload"].get("stage") == stage
        and item["payload"].get("simulated") is False
        and item["payload"].get("result") == "submitted"
    ]
    acknowledged = any(item.get("status") == "acknowledged" or item.get("receipts") for item in actual)
    closed = str(case.get("status", "")).lower() in {"closed", "resolved"}
    report = case.get("report") if isinstance(case.get("report"), Mapping) else None
    report_payload = report.get("payload") if report and isinstance(report.get("payload"), Mapping) else {}
    report_stage = report_payload.get("stage") or ("final_report" if report else None)
    stage_has_report = report is not None and report_stage == stage
    if acknowledged and closed:
        status = "resolved"
    elif acknowledged:
        status = "acknowledged"
    elif stage_has_report and case.get("approved") is True:
        status = "approved"
    elif stage_has_report:
        status = "pending_approval"
    elif case.get("status") in {"under_review", "candidate_resolution", "measure_confirmed"}:
        status = "in_progress"
    else:
        status = "action_required"
    priority = "critical" if due_at and due_at <= now else "high" if stage in {"early_warning", "notification"} else "medium"
    snapshots = case.get("snapshots") if isinstance(case.get("snapshots"), list) else []
    snapshot = snapshots[-1] if snapshots and isinstance(snapshots[-1], Mapping) else None
    record_id = str(snapshot.get("id")) if snapshot and snapshot.get("id") else None
    product = case.get("source_product") if isinstance(case.get("source_product"), Mapping) else {}
    product_label = str(product.get("name") or "affected product")
    return {
        "kind": "reporting_case",
        "title": f"{_stage_label(stage)} for {product_label}",
        "description": f"CRA reporting stage for case {case_id}. Evidence, approval, filing, and acknowledgement remain explicit.",
        "priority": priority,
        "source_type": "case_store",
        "source_id": case_id,
        "product_id": case.get("product_id"),
        "release_id": case.get("release_id"),
        "status": status,
        "due_at": due_at,
        "owner_id": case.get("operator"),
        "reporting_stage": stage,
        "self_filing_record_id": record_id,
        "self_filing_record_url": f"/v1/cases/{case_id}/snapshots/{record_id}" if record_id else None,
    }


def _stage_label(stage: str) -> str:
    return {
        "early_warning": "24-hour early warning",
        "notification": "72-hour notification",
        "final_report": "14-day final report",
    }[stage]


def _timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return _utc(value)
    try:
        return _utc(datetime.fromisoformat(str(value).replace("Z", "+00:00")))
    except ValueError as exc:
        raise ComplianceValidationError("case deadline must be an ISO 8601 timestamp") from exc


def _required(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ComplianceValidationError(f"{field} is required")
    return value.strip()


def _choice(value: Any, choices: frozenset[str], field: str) -> str:
    if value not in choices:
        raise ComplianceValidationError(f"invalid {field}: {value}")
    return str(value)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _item(row: RowMapping | Mapping[str, Any]) -> ComplianceItemRecord:
    values = {field: row[field] for field in ComplianceItemRecord.__dataclass_fields__}
    for field in ("due_at", "approved_at", "acknowledged_at", "resolved_at", "created_at", "updated_at"):
        if values[field] is not None:
            values[field] = _utc(values[field])
    return ComplianceItemRecord(**values)


def _audit_record(row: RowMapping | Mapping[str, Any]) -> ComplianceAuditRecord:
    values = {field: row[field] for field in ComplianceAuditRecord.__dataclass_fields__}
    values["occurred_at"] = _utc(values["occurred_at"])
    return ComplianceAuditRecord(**values)


def _json_payload(values: Mapping[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in values.items():
        if isinstance(value, datetime):
            payload[key] = _utc(value).isoformat()
        elif hasattr(value, "isoformat"):
            payload[key] = value.isoformat()
        else:
            payload[key] = value
    return payload
