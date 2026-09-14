"""Persisted release monitoring orchestration over existing scanner adapters."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator, Protocol
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Table,
    UniqueConstraint,
    and_,
    insert,
    or_,
    select,
    update,
)
from sqlalchemy.engine import Engine, RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .portfolio import portfolio_metadata


class ReleaseMonitoringError(RuntimeError):
    """Base error safe for translation at an HTTP seam."""


class ReleaseMonitoringNotFound(ReleaseMonitoringError):
    pass


class ReleaseMonitoringConflict(ReleaseMonitoringError):
    pass


class ReleaseMonitoringValidationError(ReleaseMonitoringError):
    pass


class MonitoringRunFailed(RuntimeError):
    """Runner failure with bounded limitations safe to persist."""

    def __init__(self, message: str, limitations: Sequence[str] = ()):
        super().__init__(message)
        self.limitations = tuple(limitations)


@dataclass(frozen=True, slots=True)
class ReleaseMonitoringRecord:
    organization_id: str
    product_id: str
    release_id: str
    enabled_sources: tuple[str, ...]
    cadence_minutes: int
    enabled: bool
    health: str
    next_check_at: datetime | None
    last_check_at: datetime | None
    last_success_at: datetime | None
    consecutive_failures: int
    coverage: Mapping[str, Any]
    limitations: tuple[str, ...]
    active_claim_id: str | None
    claim_expires_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class MonitoringClaim:
    id: str
    organization_id: str
    product_id: str
    release_id: str
    trigger: str
    actor_id: str
    enabled_sources: tuple[str, ...]
    cadence_minutes: int
    claimed_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class MonitoringObservation:
    coverage: Mapping[str, Any]
    limitations: tuple[str, ...] = ()
    message: str = "Monitoring check completed"


@dataclass(frozen=True, slots=True)
class MonitoringRunEventRecord:
    id: str
    run_id: str
    sequence: int
    organization_id: str
    product_id: str
    release_id: str
    event_type: str
    trigger: str
    health: str
    coverage: Mapping[str, Any]
    limitations: tuple[str, ...]
    message: str
    actor_id: str
    occurred_at: datetime


class ReleaseMonitoringRunner(Protocol):
    def __call__(self, claim: MonitoringClaim) -> MonitoringObservation: ...


release_monitoring_metadata = portfolio_metadata

release_monitoring = Table(
    "release_monitoring",
    release_monitoring_metadata,
    Column("release_id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("product_id", String(36), nullable=False),
    Column("enabled_sources", JSON, nullable=False),
    Column("cadence_minutes", Integer, nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("health", String(24), nullable=False),
    Column("next_check_at", DateTime(timezone=True), nullable=True),
    Column("last_check_at", DateTime(timezone=True), nullable=True),
    Column("last_success_at", DateTime(timezone=True), nullable=True),
    Column("consecutive_failures", Integer, nullable=False),
    Column("coverage", JSON, nullable=False),
    Column("limitations", JSON, nullable=False),
    Column("active_claim_id", String(36), nullable=True),
    Column("claim_expires_at", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    ForeignKeyConstraint(
        ["release_id", "product_id", "organization_id"],
        [
            "portfolio_releases.id",
            "portfolio_releases.product_id",
            "portfolio_releases.organization_id",
        ],
        name="fk_release_monitoring_release_scope",
        ondelete="CASCADE",
    ),
    CheckConstraint("cadence_minutes >= 5", name="minimum_cadence"),
    CheckConstraint("consecutive_failures >= 0", name="failure_count"),
    UniqueConstraint(
        "release_id",
        "product_id",
        "organization_id",
        name="uq_release_monitoring_release_scope",
    ),
)
Index(
    "ix_release_monitoring_due",
    release_monitoring.c.enabled,
    release_monitoring.c.next_check_at,
)

release_monitoring_events = Table(
    "release_monitoring_events",
    release_monitoring_metadata,
    Column("id", String(36), primary_key=True),
    Column("run_id", String(36), nullable=False),
    Column("sequence", Integer, nullable=False),
    Column("organization_id", String(36), nullable=False),
    Column("product_id", String(36), nullable=False),
    Column("release_id", String(36), nullable=False),
    Column("event_type", String(24), nullable=False),
    Column("trigger", String(24), nullable=False),
    Column("health", String(24), nullable=False),
    Column("coverage", JSON, nullable=False),
    Column("limitations", JSON, nullable=False),
    Column("message", String(1000), nullable=False),
    Column("actor_id", String(128), nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    ForeignKeyConstraint(
        ["release_id", "product_id", "organization_id"],
        [
            "release_monitoring.release_id",
            "release_monitoring.product_id",
            "release_monitoring.organization_id",
        ],
        name="fk_release_monitoring_events_release_scope",
        ondelete="CASCADE",
    ),
    UniqueConstraint("run_id", "sequence", name="uq_release_monitoring_events_run_sequence"),
)
Index(
    "ix_release_monitoring_events_release_time",
    release_monitoring_events.c.organization_id,
    release_monitoring_events.c.release_id,
    release_monitoring_events.c.occurred_at,
)

MONITORING_SOURCES = frozenset(
    {"osv", "cisa_kev", "epss", "native_advisory", "vendor_advisory"}
)
MONITORING_HEALTH = frozenset({"healthy", "degraded", "failed", "inactive"})


class ReleaseMonitoringRepository:
    """Tenant-safe scheduling, claims, state transitions, and immutable history."""

    def __init__(self, engine: Engine):
        self.engine = engine

    def create_schema(self) -> None:
        release_monitoring_metadata.create_all(self.engine)
        if self.engine.dialect.name == "sqlite":
            with self.engine.begin() as connection:
                connection.exec_driver_sql("""
                    CREATE TRIGGER IF NOT EXISTS release_monitoring_events_no_update
                    BEFORE UPDATE ON release_monitoring_events
                    BEGIN SELECT RAISE(ABORT, 'release monitoring events are append-only'); END
                """)
                connection.exec_driver_sql("""
                    CREATE TRIGGER IF NOT EXISTS release_monitoring_events_no_delete
                    BEFORE DELETE ON release_monitoring_events
                    BEGIN SELECT RAISE(ABORT, 'release monitoring events are append-only'); END
                """)

    def configure(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        *,
        enabled_sources: Sequence[str],
        cadence_minutes: int,
        enabled: bool,
        actor_id: str,
        now: datetime | None = None,
    ) -> ReleaseMonitoringRecord:
        checked_at = _as_utc(now)
        _required(actor_id, "actor_id", 128)
        sources = _sources(enabled_sources)
        cadence = _cadence(cadence_minutes)
        values = {
            "enabled_sources": list(sources),
            "cadence_minutes": cadence,
            "enabled": bool(enabled),
            "health": "inactive" if not enabled else "degraded",
            "next_check_at": checked_at if enabled else None,
            "updated_at": checked_at,
        }
        with self._transaction() as session:
            current = self._row(session, organization_id, product_id, release_id)
            if current is None:
                session.execute(
                    insert(release_monitoring).values(
                        release_id=release_id,
                        organization_id=organization_id,
                        product_id=product_id,
                        **values,
                        last_check_at=None,
                        last_success_at=None,
                        consecutive_failures=0,
                        coverage={},
                        limitations=[],
                        active_claim_id=None,
                        claim_expires_at=None,
                        created_at=checked_at,
                    )
                )
            else:
                if current["active_claim_id"] and _future(current["claim_expires_at"], checked_at):
                    raise ReleaseMonitoringConflict("monitoring check is running")
                if enabled and current["enabled"]:
                    values["health"] = current["health"]
                    values["next_check_at"] = current["next_check_at"] or checked_at
                session.execute(
                    update(release_monitoring)
                    .where(release_monitoring.c.release_id == release_id)
                    .values(**values, active_claim_id=None, claim_expires_at=None)
                )
        return self.get(organization_id, product_id, release_id)

    def get(self, organization_id: str, product_id: str, release_id: str) -> ReleaseMonitoringRecord:
        with Session(self.engine) as session:
            row = self._row(session, organization_id, product_id, release_id)
        if row is None:
            raise ReleaseMonitoringNotFound("release monitoring configuration not found")
        return _record(row)

    def claim_now(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        *,
        actor_id: str,
        now: datetime | None = None,
        lease: timedelta = timedelta(minutes=15),
    ) -> MonitoringClaim:
        claimed_at = _as_utc(now)
        with self._transaction() as session:
            row = self._locked_row(session, organization_id, product_id, release_id)
            if row is None:
                raise ReleaseMonitoringNotFound("release monitoring configuration not found")
            if not row["enabled"]:
                raise ReleaseMonitoringConflict("release monitoring is inactive")
            return self._claim(session, row, "manual", actor_id, claimed_at, lease)

    def claim_due(
        self,
        *,
        now: datetime | None = None,
        limit: int = 50,
        actor_id: str = "monitoring-scheduler",
        lease: timedelta = timedelta(minutes=15),
    ) -> list[MonitoringClaim]:
        claimed_at = _as_utc(now)
        if limit < 1 or limit > 500:
            raise ReleaseMonitoringValidationError("limit must be between 1 and 500")
        with self._transaction() as session:
            predicate = and_(
                release_monitoring.c.enabled.is_(True),
                release_monitoring.c.next_check_at <= claimed_at,
                or_(
                    release_monitoring.c.active_claim_id.is_(None),
                    release_monitoring.c.claim_expires_at <= claimed_at,
                ),
            )
            query = select(release_monitoring).where(predicate).order_by(
                release_monitoring.c.next_check_at, release_monitoring.c.release_id
            ).limit(limit)
            if self.engine.dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True)
            rows = session.execute(query).mappings().all()
            claims: list[MonitoringClaim] = []
            for row in rows:
                try:
                    claims.append(self._claim(session, row, "scheduled", actor_id, claimed_at, lease))
                except ReleaseMonitoringConflict:
                    # SQLite cannot SKIP LOCKED; conditional update safely loses races.
                    continue
            return claims

    def complete_success(
        self,
        claim: MonitoringClaim,
        observation: MonitoringObservation,
        *,
        now: datetime | None = None,
    ) -> ReleaseMonitoringRecord:
        completed_at = _as_utc(now)
        coverage = _mapping(observation.coverage, "coverage")
        limitations = _limitations(observation.limitations)
        health = "degraded" if limitations else "healthy"
        with self._transaction() as session:
            row = self._claimed_row(session, claim)
            self._finish(
                session,
                row,
                claim,
                completed_at,
                health=health,
                coverage=coverage,
                limitations=limitations,
                failures=0,
                last_success_at=completed_at,
                event_type="succeeded",
                message=_message(observation.message),
            )
        return self.get(claim.organization_id, claim.product_id, claim.release_id)

    def complete_failure(
        self,
        claim: MonitoringClaim,
        error: Exception,
        *,
        now: datetime | None = None,
    ) -> ReleaseMonitoringRecord:
        completed_at = _as_utc(now)
        message = _message(f"{type(error).__name__}: {error}")
        supplied = error.limitations if isinstance(error, MonitoringRunFailed) else ()
        limitations = _limitations((*supplied, message))
        with self._transaction() as session:
            row = self._claimed_row(session, claim)
            failures = int(row["consecutive_failures"]) + 1
            health = "failed" if failures >= 3 or row["last_success_at"] is None else "degraded"
            self._finish(
                session,
                row,
                claim,
                completed_at,
                health=health,
                coverage=dict(row["coverage"] or {}),
                limitations=limitations,
                failures=failures,
                last_success_at=row["last_success_at"],
                event_type="failed",
                message=message,
            )
        return self.get(claim.organization_id, claim.product_id, claim.release_id)

    def run(
        self,
        claim: MonitoringClaim,
        runner: ReleaseMonitoringRunner,
        *,
        completed_at: datetime | None = None,
    ) -> ReleaseMonitoringRecord:
        try:
            observation = runner(claim)
        except Exception as exc:
            return self.complete_failure(claim, exc, now=completed_at)
        return self.complete_success(claim, observation, now=completed_at)

    def run_now(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        runner: ReleaseMonitoringRunner,
        *,
        actor_id: str,
        now: datetime | None = None,
    ) -> ReleaseMonitoringRecord:
        claim = self.claim_now(
            organization_id, product_id, release_id, actor_id=actor_id, now=now
        )
        return self.run(claim, runner, completed_at=now)

    def events(
        self, organization_id: str, product_id: str, release_id: str
    ) -> list[MonitoringRunEventRecord]:
        self.get(organization_id, product_id, release_id)
        with Session(self.engine) as session:
            rows = session.execute(
                select(release_monitoring_events)
                .where(
                    (release_monitoring_events.c.organization_id == organization_id)
                    & (release_monitoring_events.c.product_id == product_id)
                    & (release_monitoring_events.c.release_id == release_id)
                )
                .order_by(
                    release_monitoring_events.c.occurred_at,
                    release_monitoring_events.c.run_id,
                    release_monitoring_events.c.sequence,
                )
            ).mappings().all()
        return [_event_record(row) for row in rows]

    def _claim(
        self,
        session: Session,
        row: RowMapping,
        trigger: str,
        actor_id: str,
        claimed_at: datetime,
        lease: timedelta,
    ) -> MonitoringClaim:
        if lease <= timedelta(0):
            raise ReleaseMonitoringValidationError("lease must be positive")
        if row["active_claim_id"] and _future(row["claim_expires_at"], claimed_at):
            raise ReleaseMonitoringConflict("monitoring check is running")
        claim_id = str(uuid4())
        expires_at = claimed_at + lease
        stale_claim = row["active_claim_id"]
        predicate = release_monitoring.c.release_id == row["release_id"]
        if stale_claim:
            predicate &= release_monitoring.c.active_claim_id == stale_claim
            predicate &= release_monitoring.c.claim_expires_at <= claimed_at
        else:
            predicate &= release_monitoring.c.active_claim_id.is_(None)
        changed = session.execute(
            update(release_monitoring)
            .where(predicate)
            .values(
                active_claim_id=claim_id,
                claim_expires_at=expires_at,
                updated_at=claimed_at,
            )
        ).rowcount
        if changed != 1:
            raise ReleaseMonitoringConflict("monitoring check is running")
        claim = MonitoringClaim(
            id=claim_id,
            organization_id=row["organization_id"],
            product_id=row["product_id"],
            release_id=row["release_id"],
            trigger=trigger,
            actor_id=_required(actor_id, "actor_id", 128),
            enabled_sources=tuple(row["enabled_sources"]),
            cadence_minutes=row["cadence_minutes"],
            claimed_at=claimed_at,
            expires_at=expires_at,
        )
        self._event(session, claim, 1, "started", row["health"], row["coverage"], row["limitations"], "Monitoring check started", claimed_at)
        return claim

    def _finish(
        self,
        session: Session,
        row: RowMapping,
        claim: MonitoringClaim,
        completed_at: datetime,
        *,
        health: str,
        coverage: Mapping[str, Any],
        limitations: tuple[str, ...],
        failures: int,
        last_success_at: datetime | None,
        event_type: str,
        message: str,
    ) -> None:
        changed = session.execute(
            update(release_monitoring)
            .where(
                (release_monitoring.c.release_id == claim.release_id)
                & (release_monitoring.c.active_claim_id == claim.id)
            )
            .values(
                health=health,
                next_check_at=completed_at + timedelta(minutes=claim.cadence_minutes),
                last_check_at=completed_at,
                last_success_at=last_success_at,
                consecutive_failures=failures,
                coverage=dict(coverage),
                limitations=list(limitations),
                active_claim_id=None,
                claim_expires_at=None,
                updated_at=completed_at,
            )
        ).rowcount
        if changed != 1:
            raise ReleaseMonitoringConflict("monitoring claim expired or was replaced")
        self._event(session, claim, 2, event_type, health, coverage, limitations, message, completed_at)

    def _event(
        self,
        session: Session,
        claim: MonitoringClaim,
        sequence: int,
        event_type: str,
        health: str,
        coverage: Mapping[str, Any],
        limitations: Sequence[str],
        message: str,
        occurred_at: datetime,
    ) -> None:
        session.execute(
            insert(release_monitoring_events).values(
                id=str(uuid4()),
                run_id=claim.id,
                sequence=sequence,
                organization_id=claim.organization_id,
                product_id=claim.product_id,
                release_id=claim.release_id,
                event_type=event_type,
                trigger=claim.trigger,
                health=health,
                coverage=dict(coverage or {}),
                limitations=list(limitations or []),
                message=message,
                actor_id=claim.actor_id,
                occurred_at=occurred_at,
            )
        )

    def _claimed_row(self, session: Session, claim: MonitoringClaim) -> RowMapping:
        row = self._locked_row(session, claim.organization_id, claim.product_id, claim.release_id)
        if row is None:
            raise ReleaseMonitoringNotFound("release monitoring configuration not found")
        if row["active_claim_id"] != claim.id:
            raise ReleaseMonitoringConflict("monitoring claim expired or was replaced")
        return row

    def _locked_row(
        self, session: Session, organization_id: str, product_id: str, release_id: str
    ) -> RowMapping | None:
        query = select(release_monitoring).where(
            (release_monitoring.c.organization_id == organization_id)
            & (release_monitoring.c.product_id == product_id)
            & (release_monitoring.c.release_id == release_id)
        )
        if self.engine.dialect.name == "postgresql":
            query = query.with_for_update()
        return session.execute(query).mappings().one_or_none()

    @staticmethod
    def _row(
        session: Session, organization_id: str, product_id: str, release_id: str
    ) -> RowMapping | None:
        return session.execute(
            select(release_monitoring).where(
                (release_monitoring.c.organization_id == organization_id)
                & (release_monitoring.c.product_id == product_id)
                & (release_monitoring.c.release_id == release_id)
            )
        ).mappings().one_or_none()

    @contextmanager
    def _transaction(self) -> Iterator[Session]:
        try:
            with Session(self.engine) as session, session.begin():
                yield session
        except IntegrityError as exc:
            raise ReleaseMonitoringNotFound("release not found in organization and product scope") from exc


def advisory_watch_runner(
    service_factory: Callable[[], Any],
    watch_id_for_release: Callable[[str, str, str], str],
) -> ReleaseMonitoringRunner:
    """Adapt existing AdvisoryWatchService without duplicating advisory matching."""

    def run(claim: MonitoringClaim) -> MonitoringObservation:
        watch_id = watch_id_for_release(
            claim.organization_id, claim.product_id, claim.release_id
        )
        result = service_factory().refresh(watch_id)[0]
        if result.get("last_error"):
            raise MonitoringRunFailed(
                str(result["last_error"]),
                ("Advisory coverage is stale; last-known coverage retained.",),
            )
        return MonitoringObservation(
            coverage=dict(result.get("coverage") or {}),
            limitations=tuple(result.get("limitations") or ()),
            message="Advisory refresh completed",
        )

    return run


def monitoring_store_runner(
    store: Any,
    policy_id_for_release: Callable[[str, str, str], str],
) -> ReleaseMonitoringRunner:
    """Adapt existing MonitoringStore pipeline rather than reimplement scanning."""

    def run(claim: MonitoringClaim) -> MonitoringObservation:
        policy_id = policy_id_for_release(
            claim.organization_id, claim.product_id, claim.release_id
        )
        result = store.run_policy(policy_id)
        checks = tuple(result.get("source_checks") or ())
        coverage = {
            "status": str(result.get("coverage_state", "bounded_unknown")),
            "sources": list(checks),
        }
        if result.get("status") == "failed":
            raise MonitoringRunFailed(
                str(result.get("error") or "monitoring pipeline failed"),
                ("Pipeline produced no complete coverage result.",),
            )
        limitations = () if result.get("status") == "completed" else (
            str(result.get("error") or "One or more sources were incomplete."),
        )
        return MonitoringObservation(coverage=coverage, limitations=limitations)

    return run


def _record(row: RowMapping) -> ReleaseMonitoringRecord:
    return ReleaseMonitoringRecord(
        organization_id=row["organization_id"],
        product_id=row["product_id"],
        release_id=row["release_id"],
        enabled_sources=tuple(row["enabled_sources"]),
        cadence_minutes=row["cadence_minutes"],
        enabled=bool(row["enabled"]),
        health=row["health"],
        next_check_at=_aware(row["next_check_at"]),
        last_check_at=_aware(row["last_check_at"]),
        last_success_at=_aware(row["last_success_at"]),
        consecutive_failures=row["consecutive_failures"],
        coverage=dict(row["coverage"] or {}),
        limitations=tuple(row["limitations"] or ()),
        active_claim_id=row["active_claim_id"],
        claim_expires_at=_aware(row["claim_expires_at"]),
        created_at=_aware(row["created_at"]),
        updated_at=_aware(row["updated_at"]),
    )


def _event_record(row: RowMapping) -> MonitoringRunEventRecord:
    return MonitoringRunEventRecord(
        id=row["id"], run_id=row["run_id"], sequence=row["sequence"],
        organization_id=row["organization_id"], product_id=row["product_id"],
        release_id=row["release_id"], event_type=row["event_type"],
        trigger=row["trigger"], health=row["health"],
        coverage=dict(row["coverage"] or {}),
        limitations=tuple(row["limitations"] or ()), message=row["message"],
        actor_id=row["actor_id"], occurred_at=_aware(row["occurred_at"]),
    )


def _sources(values: Sequence[str]) -> tuple[str, ...]:
    sources = tuple(dict.fromkeys(str(value).strip().lower() for value in values))
    if not sources:
        raise ReleaseMonitoringValidationError("at least one monitoring source is required")
    unknown = set(sources) - MONITORING_SOURCES
    if unknown:
        raise ReleaseMonitoringValidationError(
            "unknown monitoring source: " + ", ".join(sorted(unknown))
        )
    return sources


def _cadence(value: int) -> int:
    if type(value) is not int or value < 5 or value > 43_200:
        raise ReleaseMonitoringValidationError("cadence_minutes must be between 5 and 43200")
    return value


def _mapping(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReleaseMonitoringValidationError(f"{field} must be an object")
    return dict(value)


def _limitations(values: Sequence[str]) -> tuple[str, ...]:
    result = tuple(dict.fromkeys(str(value).strip()[:500] for value in values if str(value).strip()))
    return result[:25]


def _message(value: str) -> str:
    return (str(value).strip() or "Monitoring check completed")[:1000]


def _required(value: str, field: str, maximum: int) -> str:
    clean = str(value).strip()
    if not clean or len(clean) > maximum:
        raise ReleaseMonitoringValidationError(f"invalid {field}")
    return clean


def _as_utc(value: datetime | None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _future(value: datetime | None, now: datetime) -> bool:
    aware = _aware(value)
    return aware is not None and aware > now
