"""Tenant-scoped finding, decision, and remediation persistence.

Findings are current projections of scanner observations. Decisions and audit
events are append-only facts; subsequent analyses may refresh technical data
but cannot erase human review history.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Iterator
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    Date,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Table,
    UniqueConstraint,
    and_,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Engine, RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .portfolio import portfolio_metadata, releases


class FindingError(RuntimeError):
    """Base error safe to translate at an HTTP boundary."""


class FindingNotFound(FindingError):
    pass


class FindingConflict(FindingError):
    pass


class FindingValidationError(FindingError):
    pass


SEVERITIES = frozenset({"critical", "high", "medium", "low", "unknown"})
REACHABILITY_STATES = frozenset({"reachable", "not_reachable", "unknown"})
FINDING_STATUSES = frozenset({"needs_review", "open", "in_progress", "resolved"})
DECISIONS = frozenset({"affected", "not_affected", "accepted_risk", "deferred"})
REMEDIATION_STATUSES = frozenset({"not_planned", "planned", "in_progress", "completed", "verified"})
ACTION_STATUSES = frozenset({"needs_review", "open", "in_progress"})


@dataclass(frozen=True, slots=True)
class FindingObservation:
    reference_id: str
    component: str
    version: str
    source: str
    purl: str | None = None
    cve: str | None = None
    title: str = ""
    description: str = ""
    severity: str = "unknown"
    cvss: float | None = None
    kev: bool = False
    epss: float | None = None
    reachability: str = "unknown"
    reachability_evidence: Mapping[str, Any] | None = None
    reachability_limitations: Sequence[str] = ()
    provenance: Mapping[str, Any] | None = None
    source_key: str | None = None


@dataclass(frozen=True, slots=True)
class FindingRecord:
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
    severity: str
    cvss: float | None
    kev: bool
    epss: float | None
    reachability: str
    reachability_evidence: Mapping[str, Any]
    reachability_limitations: tuple[str, ...]
    source: str
    provenance: Mapping[str, Any]
    first_seen_at: datetime
    last_seen_at: datetime
    status: str
    assignee_id: str | None
    current_decision: str | None
    decision_rationale: str | None
    decision_by: str | None
    decided_at: datetime | None
    remediation_plan: str | None
    remediation_status: str
    remediation_due_date: date | None
    verification_evidence: tuple[Mapping[str, Any], ...]
    version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    id: str
    finding_id: str
    organization_id: str
    decision: str
    rationale: str
    actor_id: str
    occurred_at: datetime
    finding_version: int


@dataclass(frozen=True, slots=True)
class FindingAuditRecord:
    id: str
    finding_id: str
    organization_id: str
    action: str
    actor_id: str
    payload: Mapping[str, Any]
    occurred_at: datetime


findings = Table(
    "findings",
    portfolio_metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("product_id", String(36), nullable=False),
    Column("release_id", String(36), nullable=False),
    Column("source_key", String(128), nullable=False),
    Column("reference_id", String(160), nullable=False),
    Column("cve", String(32), nullable=True),
    Column("component", String(255), nullable=False),
    Column("purl", String(1000), nullable=True),
    Column("component_version", String(255), nullable=False),
    Column("title", String(500), nullable=False),
    Column("description", String(4000), nullable=False),
    Column("severity", String(16), nullable=False),
    Column("cvss", Float, nullable=True),
    Column("kev", Boolean, nullable=False),
    Column("epss", Float, nullable=True),
    Column("reachability", String(24), nullable=False),
    Column("reachability_evidence", JSON, nullable=False),
    Column("reachability_limitations", JSON, nullable=False),
    Column("source", String(120), nullable=False),
    Column("provenance", JSON, nullable=False),
    Column("first_seen_at", DateTime(timezone=True), nullable=False),
    Column("last_seen_at", DateTime(timezone=True), nullable=False),
    Column("status", String(24), nullable=False),
    Column("assignee_id", String(128), nullable=True),
    Column("current_decision", String(24), nullable=True),
    Column("decision_rationale", String(4000), nullable=True),
    Column("decision_by", String(128), nullable=True),
    Column("decided_at", DateTime(timezone=True), nullable=True),
    Column("remediation_plan", String(4000), nullable=True),
    Column("remediation_status", String(24), nullable=False),
    Column("remediation_due_date", Date, nullable=True),
    Column("verification_evidence", JSON, nullable=False),
    Column("version", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    ForeignKeyConstraint(
        ["release_id", "product_id", "organization_id"],
        ["portfolio_releases.id", "portfolio_releases.product_id", "portfolio_releases.organization_id"],
        name="fk_findings_release_scope",
        ondelete="CASCADE",
    ),
    UniqueConstraint("release_id", "source_key", name="uq_findings_release_source_key"),
    UniqueConstraint("id", "organization_id", name="uq_findings_id_org"),
    CheckConstraint("version > 0", name="version_positive"),
)
Index("ix_findings_action_queue", findings.c.organization_id, findings.c.status, findings.c.severity)
Index("ix_findings_release_seen", findings.c.release_id, findings.c.last_seen_at)

finding_decisions = Table(
    "finding_decisions",
    portfolio_metadata,
    Column("id", String(36), primary_key=True),
    Column("finding_id", String(36), nullable=False),
    Column("organization_id", String(36), nullable=False),
    Column("decision", String(24), nullable=False),
    Column("rationale", String(4000), nullable=False),
    Column("actor_id", String(128), nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    Column("finding_version", Integer, nullable=False),
    ForeignKeyConstraint(
        ["finding_id", "organization_id"],
        ["findings.id", "findings.organization_id"],
        name="fk_finding_decisions_finding_org",
        ondelete="CASCADE",
    ),
)
Index("ix_finding_decisions_history", finding_decisions.c.finding_id, finding_decisions.c.occurred_at)

finding_audit_events = Table(
    "finding_audit_events",
    portfolio_metadata,
    Column("id", String(36), primary_key=True),
    Column("finding_id", String(36), nullable=False),
    Column("organization_id", String(36), nullable=False),
    Column("action", String(64), nullable=False),
    Column("actor_id", String(128), nullable=False),
    Column("payload", JSON, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    ForeignKeyConstraint(
        ["finding_id", "organization_id"],
        ["findings.id", "findings.organization_id"],
        name="fk_finding_audit_finding_org",
        ondelete="CASCADE",
    ),
)
Index("ix_finding_audit_history", finding_audit_events.c.finding_id, finding_audit_events.c.occurred_at)


class FindingRepository:
    """Own technical observation projection and immutable human history."""

    def __init__(self, engine: Engine):
        self.engine = engine

    def create_schema(self) -> None:
        portfolio_metadata.create_all(self.engine)
        if self.engine.dialect.name == "sqlite":
            self._install_sqlite_immutability()

    def upsert_from_analysis(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        analysis_id: str,
        observations: Iterable[FindingObservation | Mapping[str, Any]],
        *,
        actor_id: str,
        seen_at: datetime | None = None,
    ) -> list[FindingRecord]:
        now = _aware(seen_at or _utc_now(), "seen_at")
        clean_actor = _required(actor_id, "actor_id", 128)
        normalized = [_observation(item) for item in observations]
        keys = [item.source_key for item in normalized]
        if len(keys) != len(set(keys)):
            raise FindingValidationError("analysis contains duplicate finding source keys")
        ids: list[str] = []
        with self._transaction() as session:
            self._require_release(session, organization_id, product_id, release_id)
            for observation in normalized:
                current = session.execute(
                    select(findings).where(
                        (findings.c.release_id == release_id)
                        & (findings.c.source_key == observation.source_key)
                    )
                ).mappings().one_or_none()
                technical = _technical_values(observation)
                if current is None:
                    finding_id = str(uuid4())
                    values = {
                        "id": finding_id,
                        "organization_id": organization_id,
                        "product_id": product_id,
                        "release_id": release_id,
                        **technical,
                        "first_seen_at": now,
                        "last_seen_at": now,
                        "status": "needs_review",
                        "assignee_id": None,
                        "current_decision": None,
                        "decision_rationale": None,
                        "decision_by": None,
                        "decided_at": None,
                        "remediation_plan": None,
                        "remediation_status": "not_planned",
                        "remediation_due_date": None,
                        "verification_evidence": [],
                        "version": 1,
                        "created_at": now,
                        "updated_at": now,
                    }
                    session.execute(insert(findings).values(**values))
                    self._audit(session, finding_id, organization_id, "finding.discovered", clean_actor, {
                        "analysis_id": analysis_id, "source_key": observation.source_key
                    }, now)
                else:
                    finding_id = current["id"]
                    session.execute(
                        update(findings)
                        .where(findings.c.id == finding_id)
                        .values(**technical, last_seen_at=now, updated_at=now, version=current["version"] + 1)
                    )
                    self._audit(session, finding_id, organization_id, "finding.observed", clean_actor, {
                        "analysis_id": analysis_id, "source_key": observation.source_key
                    }, now)
                ids.append(finding_id)
        return [self.get(organization_id, product_id, release_id, item) for item in ids]

    def get(self, organization_id: str, product_id: str, release_id: str, finding_id: str) -> FindingRecord:
        with Session(self.engine) as session:
            row = self._finding_row(session, organization_id, product_id, release_id, finding_id)
        if row is None:
            raise FindingNotFound("finding not found")
        return _finding_record(row)

    def list(
        self,
        organization_id: str,
        *,
        product_id: str | None = None,
        release_id: str | None = None,
        action_required: bool = True,
        severities: Sequence[str] = (),
        statuses: Sequence[str] = (),
        kev: bool | None = None,
        reachability: str | None = None,
        assignee_id: str | None = None,
        sort: str = "priority",
    ) -> list[FindingRecord]:
        conditions = [findings.c.organization_id == organization_id]
        if product_id:
            conditions.append(findings.c.product_id == product_id)
        if release_id:
            conditions.append(findings.c.release_id == release_id)
        clean_severities = tuple(_choice(item, SEVERITIES, "severity") for item in severities)
        clean_statuses = tuple(_choice(item, FINDING_STATUSES, "status") for item in statuses)
        if clean_severities:
            conditions.append(findings.c.severity.in_(clean_severities))
        if clean_statuses:
            conditions.append(findings.c.status.in_(clean_statuses))
        elif action_required:
            conditions.append(findings.c.status.in_(ACTION_STATUSES))
        if kev is not None:
            conditions.append(findings.c.kev == kev)
        if reachability:
            conditions.append(findings.c.reachability == _choice(reachability, REACHABILITY_STATES, "reachability"))
        if assignee_id:
            conditions.append(findings.c.assignee_id == assignee_id)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        order = {
            "priority": (findings.c.kev.desc(), findings.c.cvss.desc(), findings.c.last_seen_at.desc()),
            "newest": (findings.c.first_seen_at.desc(),),
            "last_seen": (findings.c.last_seen_at.desc(),),
            "due_date": (findings.c.remediation_due_date.asc().nullslast(),),
        }.get(sort)
        if order is None and sort != "severity":
            raise FindingValidationError("unsupported sort")
        with Session(self.engine) as session:
            rows = session.execute(select(findings).where(and_(*conditions))).mappings().all()
        records = [_finding_record(row) for row in rows]
        if sort == "severity":
            return sorted(records, key=lambda item: (severity_order[item.severity], -int(item.kev), -float(item.cvss or -1)))
        if sort == "priority":
            return sorted(records, key=lambda item: (-int(item.kev), severity_order[item.severity], -float(item.cvss or -1), -item.last_seen_at.timestamp()))
        key = {
            "newest": lambda item: item.first_seen_at,
            "last_seen": lambda item: item.last_seen_at,
            "due_date": lambda item: item.remediation_due_date or date.max,
        }[sort]
        return sorted(records, key=key, reverse=sort != "due_date")

    def assign(
        self, organization_id: str, product_id: str, release_id: str, finding_id: str,
        *, assignee_id: str | None, expected_version: int, actor_id: str,
    ) -> FindingRecord:
        clean_assignee = _optional(assignee_id, "assignee_id", 128)
        return self._mutate(
            organization_id, product_id, release_id, finding_id, expected_version, actor_id,
            "finding.assigned", {"assignee_id": clean_assignee}, {"assignee_id": clean_assignee},
        )

    def decide(
        self, organization_id: str, product_id: str, release_id: str, finding_id: str,
        *, decision: str, rationale: str, expected_version: int, actor_id: str,
    ) -> FindingRecord:
        clean_decision = _choice(decision, DECISIONS, "decision")
        clean_rationale = _required(rationale, "rationale", 4000)
        now = _utc_now()
        status = "open" if clean_decision in {"affected", "deferred"} else "resolved"
        with self._transaction() as session:
            current = self._required_finding(session, organization_id, product_id, release_id, finding_id)
            new_version = self._update_versioned(session, current, expected_version, {
                "current_decision": clean_decision,
                "decision_rationale": clean_rationale,
                "decision_by": _required(actor_id, "actor_id", 128),
                "decided_at": now,
                "status": status,
                "updated_at": now,
            })
            session.execute(insert(finding_decisions).values(
                id=str(uuid4()), finding_id=finding_id, organization_id=organization_id,
                decision=clean_decision, rationale=clean_rationale, actor_id=actor_id,
                occurred_at=now, finding_version=new_version,
            ))
            self._audit(session, finding_id, organization_id, "finding.decision_recorded", actor_id, {
                "decision": clean_decision, "rationale": clean_rationale, "version": new_version
            }, now)
        return self.get(organization_id, product_id, release_id, finding_id)

    def update_remediation(
        self, organization_id: str, product_id: str, release_id: str, finding_id: str,
        *, plan: str | None, status: str, due_date: date | None,
        verification_evidence: Sequence[Mapping[str, Any]], expected_version: int, actor_id: str,
    ) -> FindingRecord:
        clean_status = _choice(status, REMEDIATION_STATUSES, "remediation_status")
        clean_plan = _optional(plan, "plan", 4000)
        evidence = [_json_object(item, "verification_evidence") for item in verification_evidence]
        if clean_status in {"planned", "in_progress", "completed", "verified"} and not clean_plan:
            raise FindingValidationError("remediation plan is required")
        if clean_status == "verified" and not evidence:
            raise FindingValidationError("verification evidence is required")
        finding_status = "resolved" if clean_status == "verified" else ("in_progress" if clean_status in {"planned", "in_progress", "completed"} else None)
        values: dict[str, Any] = {
            "remediation_plan": clean_plan,
            "remediation_status": clean_status,
            "remediation_due_date": due_date,
            "verification_evidence": evidence,
        }
        if finding_status:
            values["status"] = finding_status
        return self._mutate(
            organization_id, product_id, release_id, finding_id, expected_version, actor_id,
            "finding.remediation_updated", values, {
                "plan": clean_plan, "status": clean_status,
                "due_date": due_date.isoformat() if due_date else None,
                "verification_evidence": evidence,
            },
        )

    def decisions(self, organization_id: str, finding_id: str) -> list[DecisionRecord]:
        self._require_finding_identity(organization_id, finding_id)
        with Session(self.engine) as session:
            rows = session.execute(
                select(finding_decisions).where(
                    (finding_decisions.c.organization_id == organization_id)
                    & (finding_decisions.c.finding_id == finding_id)
                ).order_by(finding_decisions.c.occurred_at, finding_decisions.c.id)
            ).mappings().all()
        return [_decision_record(row) for row in rows]

    def audit_history(self, organization_id: str, finding_id: str) -> list[FindingAuditRecord]:
        self._require_finding_identity(organization_id, finding_id)
        with Session(self.engine) as session:
            rows = session.execute(
                select(finding_audit_events).where(
                    (finding_audit_events.c.organization_id == organization_id)
                    & (finding_audit_events.c.finding_id == finding_id)
                ).order_by(finding_audit_events.c.occurred_at, finding_audit_events.c.id)
            ).mappings().all()
        return [_audit_record(row) for row in rows]

    def _mutate(
        self, organization_id: str, product_id: str, release_id: str, finding_id: str,
        expected_version: int, actor_id: str, action: str,
        values: Mapping[str, Any], payload: Mapping[str, Any],
    ) -> FindingRecord:
        now = _utc_now()
        with self._transaction() as session:
            current = self._required_finding(session, organization_id, product_id, release_id, finding_id)
            new_version = self._update_versioned(session, current, expected_version, {**values, "updated_at": now})
            self._audit(session, finding_id, organization_id, action, actor_id, {**payload, "version": new_version}, now)
        return self.get(organization_id, product_id, release_id, finding_id)

    @staticmethod
    def _update_versioned(session: Session, current: RowMapping, expected_version: int, values: Mapping[str, Any]) -> int:
        if expected_version < 1 or current["version"] != expected_version:
            raise FindingConflict("finding was modified; refresh and retry")
        new_version = expected_version + 1
        result = session.execute(
            update(findings).where(
                (findings.c.id == current["id"]) & (findings.c.version == expected_version)
            ).values(**values, version=new_version)
        )
        if result.rowcount != 1:
            raise FindingConflict("finding was modified; refresh and retry")
        return new_version

    def _require_release(self, session: Session, organization_id: str, product_id: str, release_id: str) -> None:
        if session.execute(select(releases.c.id).where(
            (releases.c.id == release_id) & (releases.c.product_id == product_id)
            & (releases.c.organization_id == organization_id)
        )).one_or_none() is None:
            raise FindingNotFound("release not found")

    def _required_finding(self, session: Session, organization_id: str, product_id: str, release_id: str, finding_id: str) -> RowMapping:
        row = self._finding_row(session, organization_id, product_id, release_id, finding_id)
        if row is None:
            raise FindingNotFound("finding not found")
        return row

    @staticmethod
    def _finding_row(session: Session, organization_id: str, product_id: str, release_id: str, finding_id: str) -> RowMapping | None:
        return session.execute(select(findings).where(
            (findings.c.id == finding_id) & (findings.c.organization_id == organization_id)
            & (findings.c.product_id == product_id) & (findings.c.release_id == release_id)
        )).mappings().one_or_none()

    def _require_finding_identity(self, organization_id: str, finding_id: str) -> None:
        with Session(self.engine) as session:
            exists = session.execute(select(findings.c.id).where(
                (findings.c.id == finding_id) & (findings.c.organization_id == organization_id)
            )).one_or_none()
        if exists is None:
            raise FindingNotFound("finding not found")

    @staticmethod
    def _audit(session: Session, finding_id: str, organization_id: str, action: str, actor_id: str, payload: Mapping[str, Any], occurred_at: datetime) -> None:
        session.execute(insert(finding_audit_events).values(
            id=str(uuid4()), finding_id=finding_id, organization_id=organization_id,
            action=action, actor_id=_required(actor_id, "actor_id", 128),
            payload=dict(payload), occurred_at=occurred_at,
        ))

    @contextmanager
    def _transaction(self) -> Iterator[Session]:
        with Session(self.engine) as session:
            try:
                with session.begin():
                    yield session
            except (FindingError,):
                raise
            except IntegrityError as exc:
                raise FindingConflict("finding persistence conflict") from exc

    def _install_sqlite_immutability(self) -> None:
        with self.engine.begin() as connection:
            for table in ("finding_decisions", "finding_audit_events"):
                connection.exec_driver_sql(
                    f"CREATE TRIGGER IF NOT EXISTS {table}_no_update BEFORE UPDATE ON {table} "
                    "BEGIN SELECT RAISE(ABORT, 'append-only history'); END"
                )
                connection.exec_driver_sql(
                    f"CREATE TRIGGER IF NOT EXISTS {table}_no_delete BEFORE DELETE ON {table} "
                    "BEGIN SELECT RAISE(ABORT, 'append-only history'); END"
                )


def _observation(value: FindingObservation | Mapping[str, Any]) -> FindingObservation:
    if isinstance(value, Mapping):
        try:
            value = FindingObservation(**value)
        except (TypeError, ValueError) as exc:
            raise FindingValidationError("invalid finding observation") from exc
    reference_id = _required(value.reference_id, "reference_id", 160)
    cve = _optional(value.cve, "cve", 32)
    purl = _optional(value.purl, "purl", 1000)
    source = _required(value.source, "source", 120)
    source_key = value.source_key or hashlib.sha256(
        f"{source.lower()}\0{reference_id.upper()}\0{purl or value.component}\0{value.version}".encode()
    ).hexdigest()
    cvss = _score(value.cvss, "cvss", 10.0)
    epss = _score(value.epss, "epss", 1.0)
    return FindingObservation(
        reference_id=reference_id, cve=cve.upper() if cve else None,
        component=_required(value.component, "component", 255),
        purl=purl, version=_required(value.version, "version", 255),
        title=_required(value.title or reference_id, "title", 500),
        description=value.description.strip()[:4000],
        severity=_choice(value.severity, SEVERITIES, "severity"), cvss=cvss,
        kev=bool(value.kev), epss=epss,
        reachability=_choice(value.reachability, REACHABILITY_STATES, "reachability"),
        reachability_evidence=_json_object(value.reachability_evidence or {}, "reachability_evidence"),
        reachability_limitations=tuple(_required(item, "reachability limitation", 1000) for item in value.reachability_limitations),
        source=source, provenance=_json_object(value.provenance or {}, "provenance"),
        source_key=_required(source_key, "source_key", 128),
    )


def _technical_values(value: FindingObservation) -> dict[str, Any]:
    return {
        "source_key": value.source_key, "reference_id": value.reference_id,
        "cve": value.cve, "component": value.component, "purl": value.purl,
        "component_version": value.version, "title": value.title,
        "description": value.description, "severity": value.severity,
        "cvss": value.cvss, "kev": value.kev, "epss": value.epss,
        "reachability": value.reachability,
        "reachability_evidence": dict(value.reachability_evidence or {}),
        "reachability_limitations": list(value.reachability_limitations),
        "source": value.source, "provenance": dict(value.provenance or {}),
    }


def _finding_record(row: Mapping[str, Any]) -> FindingRecord:
    values = dict(row)
    values["reachability_evidence"] = dict(values["reachability_evidence"] or {})
    values["reachability_limitations"] = tuple(values["reachability_limitations"] or ())
    values["provenance"] = dict(values["provenance"] or {})
    values["verification_evidence"] = tuple(dict(item) for item in values["verification_evidence"] or ())
    for field in ("first_seen_at", "last_seen_at", "decided_at", "created_at", "updated_at"):
        if values.get(field) is not None:
            values[field] = _as_utc(values[field])
    return FindingRecord(**values)


def _decision_record(row: Mapping[str, Any]) -> DecisionRecord:
    values = dict(row)
    values["occurred_at"] = _as_utc(values["occurred_at"])
    return DecisionRecord(**values)


def _audit_record(row: Mapping[str, Any]) -> FindingAuditRecord:
    values = dict(row)
    values["payload"] = dict(values["payload"] or {})
    values["occurred_at"] = _as_utc(values["occurred_at"])
    return FindingAuditRecord(**values)


def _required(value: str, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FindingValidationError(f"{name} is required")
    clean = value.strip()
    if len(clean) > maximum:
        raise FindingValidationError(f"{name} is too long")
    return clean


def _optional(value: str | None, name: str, maximum: int) -> str | None:
    if value is None:
        return None
    return _required(value, name, maximum)


def _choice(value: str, choices: frozenset[str], name: str) -> str:
    clean = _required(value, name, 40).lower()
    if clean not in choices:
        raise FindingValidationError(f"invalid {name}")
    return clean


def _score(value: float | None, name: str, maximum: float) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= float(value) <= maximum:
        raise FindingValidationError(f"{name} must be between 0 and {maximum:g}")
    return float(value)


def _json_object(value: Mapping[str, Any], name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise FindingValidationError(f"{name} must be an object")
    return dict(value)


def _aware(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise FindingValidationError(f"{name} must include timezone")
    return value.astimezone(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
