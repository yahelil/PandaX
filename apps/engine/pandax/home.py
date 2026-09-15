"""Bounded tenant-scoped Home aggregation over production tables."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from sqlalchemy import and_, case, func, literal, or_, select, union_all
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .compliance import compliance_audit_events, compliance_items
from .documents import EVENT_STATUS, document_events, documents
from .findings import ACTION_STATUSES, finding_audit_events, findings
from .portfolio import audit_events, organizations, products, releases
from .release_monitoring import release_monitoring, release_monitoring_events


class HomeError(ValueError):
    pass


class HomeNotFound(HomeError):
    pass


class HomeValidationError(HomeError):
    pass


@dataclass(frozen=True, slots=True)
class MonitoringSourceSummary:
    source: str
    state: str
    release_count: int


@dataclass(frozen=True, slots=True)
class MonitoringSummary:
    state: str
    supported_releases: int
    configured: int
    healthy: int
    degraded: int
    failed: int
    stale: int
    inactive: int
    not_configured: int
    last_success_at: datetime | None
    last_check_at: datetime | None
    next_check_at: datetime | None
    cadence_minutes: tuple[int, ...]
    sources: tuple[MonitoringSourceSummary, ...]


@dataclass(frozen=True, slots=True)
class ActionCounters:
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


@dataclass(frozen=True, slots=True)
class HomeAction:
    id: str
    source_type: str
    source_id: str
    product_id: str | None
    release_id: str | None
    product_name: str | None
    release_version: str | None
    title: str
    reason: str
    priority: str
    due_at: datetime | None
    score: int
    target_url: str
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class RecentChange:
    id: str
    source_type: str
    source_id: str
    product_id: str | None
    release_id: str | None
    title: str
    description: str
    actor_id: str
    occurred_at: datetime
    target_url: str


@dataclass(frozen=True, slots=True)
class HomeSnapshot:
    organization_id: str
    generated_at: datetime
    monitoring: MonitoringSummary
    counters: ActionCounters
    action_queue: tuple[HomeAction, ...]
    recent_changes: tuple[RecentChange, ...]
    data_warnings: tuple[str, ...]


class HomeReadModel:
    """Read-only aggregate. Every query is tenant-filtered and bounded."""

    def __init__(self, engine: Engine, *, clock: Callable[[], datetime] | None = None):
        self.engine = engine
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def get(
        self,
        organization_id: str,
        *,
        queue_limit: int = 8,
        recent_limit: int = 8,
        now: datetime | None = None,
    ) -> HomeSnapshot:
        if not organization_id.strip():
            raise HomeValidationError("organization_id is required")
        if queue_limit < 1 or queue_limit > 50:
            raise HomeValidationError("queue_limit must be between 1 and 50")
        if recent_limit < 1 or recent_limit > 50:
            raise HomeValidationError("recent_limit must be between 1 and 50")
        generated_at = _utc(now or self.clock())
        with Session(self.engine) as session:
            monitoring, product_count = self._monitoring_summary(session, organization_id, generated_at)
            finding_counts = self._finding_counts(session, organization_id)
            compliance_counts = self._compliance_counts(session, organization_id, generated_at)
            document_counts = self._document_counts(session, organization_id)
            candidates = [
                *self._finding_actions(session, organization_id, queue_limit),
                *self._compliance_actions(session, organization_id, queue_limit, generated_at),
                *self._monitoring_actions(session, organization_id, queue_limit, generated_at),
                *self._document_actions(session, organization_id, queue_limit),
            ]
            recent = self._recent_changes(session, organization_id, recent_limit)
        monitoring_issues = (
            monitoring.degraded + monitoring.failed + monitoring.stale
            + monitoring.inactive + monitoring.not_configured
        )
        documents_needing_action = document_counts["draft"] + document_counts["pending"] + document_counts["rejected"]
        action_total = (
            finding_counts["action"] + compliance_counts["action"]
            + documents_needing_action + monitoring_issues
        )
        counters = ActionCounters(
            action_total=action_total,
            findings_needing_action=finding_counts["action"],
            urgent_findings=finding_counts["urgent"],
            reachable_kev_findings=finding_counts["reachable_kev"],
            compliance_actions=compliance_counts["action"],
            overdue_obligations=compliance_counts["overdue"],
            due_soon_obligations=compliance_counts["due_soon"],
            missing_evidence=compliance_counts["missing_evidence"],
            pending_approvals=compliance_counts["pending_approval"] + document_counts["pending"],
            documents_needing_action=documents_needing_action,
            monitoring_issues=monitoring_issues,
        )
        warnings: list[str] = []
        if product_count == 0:
            warnings.append("No products are registered for this organization.")
        elif monitoring.supported_releases == 0:
            warnings.append("No active or supported releases are registered; monitoring status is unknown.")
        if monitoring.not_configured:
            warnings.append(f"{monitoring.not_configured} supported release(s) have no monitoring configuration.")
        if monitoring.stale:
            warnings.append(f"{monitoring.stale} monitored release(s) have stale or missing successful checks.")
        ordered = sorted(candidates, key=_action_order)[:queue_limit]
        return HomeSnapshot(
            organization_id=organization_id,
            generated_at=generated_at,
            monitoring=monitoring,
            counters=counters,
            action_queue=tuple(ordered),
            recent_changes=tuple(recent),
            data_warnings=tuple(warnings),
        )

    @staticmethod
    def _monitoring_summary(
        session: Session, organization_id: str, now: datetime,
    ) -> tuple[MonitoringSummary, int]:
        scope = and_(
            releases.c.organization_id == organization_id,
            releases.c.status.in_(("active", "supported")),
        )
        missing = release_monitoring.c.release_id.is_(None)
        inactive = and_(~missing, or_(release_monitoring.c.enabled.is_(False), release_monitoring.c.health == "inactive"))
        failed = and_(~missing, ~inactive, release_monitoring.c.health == "failed")
        stale = and_(
            ~missing, ~inactive, ~failed, release_monitoring.c.enabled.is_(True),
            or_(
                release_monitoring.c.last_success_at.is_(None),
                release_monitoring.c.next_check_at.is_(None),
                release_monitoring.c.next_check_at <= now,
            ),
        )
        degraded = and_(~missing, ~inactive, ~failed, ~stale, release_monitoring.c.health == "degraded")
        healthy = and_(~missing, ~inactive, ~failed, ~stale, ~degraded, release_monitoring.c.health == "healthy")
        product_count = select(func.count(products.c.id)).where(products.c.organization_id == organization_id).scalar_subquery()
        organization_count = select(func.count(organizations.c.id)).where(organizations.c.id == organization_id).scalar_subquery()
        row = session.execute(
            select(
                organization_count.label("organization_count"),
                product_count.label("product_count"),
                func.count(releases.c.id).label("supported"),
                func.sum(case((~missing, 1), else_=0)).label("configured"),
                func.sum(case((healthy, 1), else_=0)).label("healthy"),
                func.sum(case((degraded, 1), else_=0)).label("degraded"),
                func.sum(case((failed, 1), else_=0)).label("failed"),
                func.sum(case((stale, 1), else_=0)).label("stale"),
                func.sum(case((inactive, 1), else_=0)).label("inactive"),
                func.sum(case((missing, 1), else_=0)).label("not_configured"),
                func.max(release_monitoring.c.last_success_at).label("last_success_at"),
                func.max(release_monitoring.c.last_check_at).label("last_check_at"),
                func.min(release_monitoring.c.next_check_at).label("next_check_at"),
            ).select_from(
                releases.outerjoin(
                    release_monitoring,
                    and_(
                        release_monitoring.c.organization_id == releases.c.organization_id,
                        release_monitoring.c.product_id == releases.c.product_id,
                        release_monitoring.c.release_id == releases.c.id,
                    ),
                )
            ).where(scope)
        ).mappings().one()
        if int(row["organization_count"] or 0) == 0:
            raise HomeNotFound("organization not found")
        counts = {key: int(row[key] or 0) for key in (
            "supported", "configured", "healthy", "degraded", "failed", "stale", "inactive", "not_configured"
        )}
        state = "healthy"
        if counts["degraded"]:
            state = "degraded"
        if counts["inactive"]:
            state = "inactive"
        if counts["supported"] == 0 or counts["not_configured"]:
            state = "not_configured"
        if counts["stale"]:
            state = "stale"
        if counts["failed"]:
            state = "failed"
        configured_rows = session.execute(
            select(
                release_monitoring.c.enabled_sources,
                release_monitoring.c.cadence_minutes,
                release_monitoring.c.enabled,
                release_monitoring.c.health,
                release_monitoring.c.last_success_at,
                release_monitoring.c.next_check_at,
            )
            .select_from(release_monitoring.join(
                releases,
                and_(
                    release_monitoring.c.organization_id == releases.c.organization_id,
                    release_monitoring.c.product_id == releases.c.product_id,
                    release_monitoring.c.release_id == releases.c.id,
                ),
            ))
            .where(scope)
        ).mappings().all()
        source_states: dict[str, tuple[str, int]] = {}
        state_rank = {"healthy": 0, "degraded": 1, "inactive": 2, "stale": 3, "failed": 4}
        for configured_row in configured_rows:
            row_state = _monitoring_row_state(configured_row, now)
            for source in configured_row["enabled_sources"] or ():
                clean_source = str(source)
                previous_state, release_count = source_states.get(clean_source, (row_state, 0))
                worst = row_state if state_rank[row_state] > state_rank[previous_state] else previous_state
                source_states[clean_source] = (worst, release_count + 1)
        summary = MonitoringSummary(
            state=state,
            supported_releases=counts["supported"],
            configured=counts["configured"],
            healthy=counts["healthy"],
            degraded=counts["degraded"],
            failed=counts["failed"],
            stale=counts["stale"],
            inactive=counts["inactive"],
            not_configured=counts["not_configured"],
            last_success_at=_optional_utc(row["last_success_at"]),
            last_check_at=_optional_utc(row["last_check_at"]),
            next_check_at=_optional_utc(row["next_check_at"]),
            cadence_minutes=tuple(sorted({
                int(configured_row["cadence_minutes"])
                for configured_row in configured_rows if configured_row["enabled"]
            })),
            sources=tuple(
                MonitoringSourceSummary(source, source_state, release_count)
                for source, (source_state, release_count) in sorted(source_states.items())
            ),
        )
        return summary, int(row["product_count"] or 0)

    @staticmethod
    def _finding_counts(session: Session, organization_id: str) -> Mapping[str, int]:
        action = findings.c.status.in_(tuple(ACTION_STATUSES))
        row = session.execute(select(
            func.sum(case((action, 1), else_=0)).label("action"),
            func.sum(case((and_(action, findings.c.severity.in_(("critical", "high"))), 1), else_=0)).label("urgent"),
            func.sum(case((and_(action, findings.c.kev.is_(True), findings.c.reachability == "reachable"), 1), else_=0)).label("reachable_kev"),
        ).where(findings.c.organization_id == organization_id)).mappings().one()
        return {key: int(row[key] or 0) for key in ("action", "urgent", "reachable_kev")}

    @staticmethod
    def _compliance_counts(session: Session, organization_id: str, now: datetime) -> Mapping[str, int]:
        open_item = compliance_items.c.status != "resolved"
        due_soon = and_(open_item, compliance_items.c.due_at > now, compliance_items.c.due_at <= now + timedelta(days=7))
        row = session.execute(select(
            func.sum(case((open_item, 1), else_=0)).label("action"),
            func.sum(case((and_(open_item, compliance_items.c.due_at <= now), 1), else_=0)).label("overdue"),
            func.sum(case((due_soon, 1), else_=0)).label("due_soon"),
            func.sum(case((and_(open_item, compliance_items.c.kind.in_(("missing_evidence", "missing_document"))), 1), else_=0)).label("missing_evidence"),
            func.sum(case((and_(open_item, compliance_items.c.status == "pending_approval"), 1), else_=0)).label("pending_approval"),
        ).where(compliance_items.c.organization_id == organization_id)).mappings().one()
        return {key: int(row[key] or 0) for key in ("action", "overdue", "due_soon", "missing_evidence", "pending_approval")}

    @staticmethod
    def _document_status_expression():
        latest_event = select(document_events.c.event_type).where(and_(
            document_events.c.organization_id == documents.c.organization_id,
            document_events.c.document_id == documents.c.id,
            document_events.c.revision == documents.c.current_revision,
            document_events.c.event_type.in_(tuple(EVENT_STATUS)),
        )).order_by(document_events.c.sequence.desc()).limit(1).scalar_subquery()
        return case(EVENT_STATUS, value=latest_event, else_="draft")

    def _document_counts(self, session: Session, organization_id: str) -> Mapping[str, int]:
        status_expression = self._document_status_expression()
        row = session.execute(select(
            func.sum(case((status_expression == "draft", 1), else_=0)).label("draft"),
            func.sum(case((status_expression == "pending", 1), else_=0)).label("pending"),
            func.sum(case((status_expression == "rejected", 1), else_=0)).label("rejected"),
        ).where(documents.c.organization_id == organization_id)).mappings().one()
        return {key: int(row[key] or 0) for key in ("draft", "pending", "rejected")}

    @staticmethod
    def _finding_actions(session: Session, organization_id: str, limit: int) -> list[HomeAction]:
        severity_order = case({"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}, value=findings.c.severity, else_=5)
        rows = session.execute(select(
            findings, products.c.name.label("product_name"), releases.c.version.label("release_version"),
        ).join(products, and_(products.c.id == findings.c.product_id, products.c.organization_id == findings.c.organization_id)).join(
            releases, and_(releases.c.id == findings.c.release_id, releases.c.organization_id == findings.c.organization_id)
        ).where(
            findings.c.organization_id == organization_id,
            findings.c.status.in_(tuple(ACTION_STATUSES)),
        ).order_by(
            findings.c.kev.desc(),
            case((findings.c.reachability == "reachable", 0), else_=1),
            severity_order,
            findings.c.updated_at.desc(),
        ).limit(limit * 4)).mappings().all()
        result = []
        for row in rows:
            score = {"critical": 900, "high": 800, "medium": 620, "low": 450, "unknown": 500}[row["severity"]]
            score += 90 if row["kev"] else 0
            score += 60 if row["reachability"] == "reachable" else 0
            reason = f"{row['severity'].title()} severity"
            if row["kev"] and row["reachability"] == "reachable":
                reason = "Known exploited vulnerability is reachable in this release"
            result.append(HomeAction(
                id=f"finding:{row['id']}", source_type="finding", source_id=row["id"],
                product_id=row["product_id"], release_id=row["release_id"],
                product_name=row["product_name"], release_version=row["release_version"],
                title=row["title"] or row["reference_id"], reason=reason,
                priority=_priority(score), due_at=_date_due(row["remediation_due_date"]), score=score,
                target_url=_url("finding", row["id"], row["product_id"], row["release_id"]),
                updated_at=_utc(row["updated_at"]),
            ))
        return result

    @staticmethod
    def _compliance_actions(
        session: Session, organization_id: str, limit: int, now: datetime,
    ) -> list[HomeAction]:
        priority_order = case({"critical": 0, "high": 1, "medium": 2, "low": 3}, value=compliance_items.c.priority, else_=4)
        candidate_score = (
            case({"critical": 860, "high": 760, "medium": 660, "low": 480}, value=compliance_items.c.priority, else_=0)
            + case((compliance_items.c.due_at <= now, 300), else_=0)
            + case((compliance_items.c.kind.in_(("missing_evidence", "missing_document")), 80), else_=0)
            + case((compliance_items.c.status == "pending_approval", 40), else_=0)
        )
        rows = session.execute(select(
            compliance_items,
            products.c.name.label("product_name"),
            releases.c.version.label("release_version"),
        ).select_from(compliance_items.outerjoin(
            products, and_(products.c.id == compliance_items.c.product_id, products.c.organization_id == compliance_items.c.organization_id)
        ).outerjoin(
            releases, and_(releases.c.id == compliance_items.c.release_id, releases.c.organization_id == compliance_items.c.organization_id)
        )).where(
            compliance_items.c.organization_id == organization_id,
            compliance_items.c.status != "resolved",
        ).order_by(candidate_score.desc(), compliance_items.c.due_at.is_(None), compliance_items.c.due_at, priority_order).limit(limit * 4)).mappings().all()
        result = []
        for row in rows:
            overdue = row["due_at"] is not None and _utc(row["due_at"]) <= now
            score = {"critical": 860, "high": 760, "medium": 660, "low": 480}[row["priority"]]
            if overdue:
                score = max(score, 940)
            if row["kind"] in {"missing_evidence", "missing_document"}:
                score += 80
            if row["status"] == "pending_approval":
                score += 40
            reason = "Overdue CRA obligation" if overdue else _compliance_reason(row)
            result.append(HomeAction(
                id=f"compliance:{row['id']}", source_type="compliance", source_id=row["id"],
                product_id=row["product_id"], release_id=row["release_id"],
                product_name=row["product_name"], release_version=row["release_version"],
                title=row["title"], reason=reason, priority=_priority(score),
                due_at=_optional_utc(row["due_at"]), score=score,
                target_url=_url("compliance", row["id"], row["product_id"], row["release_id"]),
                updated_at=_utc(row["updated_at"]),
            ))
        return result

    @staticmethod
    def _monitoring_actions(
        session: Session, organization_id: str, limit: int, now: datetime,
    ) -> list[HomeAction]:
        missing = release_monitoring.c.release_id.is_(None)
        issue = or_(
            missing,
            release_monitoring.c.enabled.is_(False),
            release_monitoring.c.health != "healthy",
            release_monitoring.c.last_success_at.is_(None),
            release_monitoring.c.next_check_at.is_(None),
            release_monitoring.c.next_check_at <= now,
        )
        issue_order = case(
            (release_monitoring.c.health == "failed", 0),
            (
                and_(release_monitoring.c.enabled.is_(True), or_(
                    release_monitoring.c.last_success_at.is_(None),
                    release_monitoring.c.next_check_at.is_(None),
                    release_monitoring.c.next_check_at <= now,
                )),
                1,
            ),
            (release_monitoring.c.health == "degraded", 2),
            (missing, 3),
            else_=4,
        )
        rows = session.execute(select(
            releases.c.id.label("release_id"), releases.c.product_id,
            releases.c.version.label("release_version"), releases.c.updated_at.label("release_updated_at"),
            products.c.name.label("product_name"),
            release_monitoring.c.enabled, release_monitoring.c.health,
            release_monitoring.c.next_check_at, release_monitoring.c.last_success_at,
            release_monitoring.c.updated_at.label("monitoring_updated_at"),
        ).join(products, and_(products.c.id == releases.c.product_id, products.c.organization_id == releases.c.organization_id)).outerjoin(
            release_monitoring, and_(
                release_monitoring.c.release_id == releases.c.id,
                release_monitoring.c.product_id == releases.c.product_id,
                release_monitoring.c.organization_id == releases.c.organization_id,
            )
        ).where(
            releases.c.organization_id == organization_id,
            releases.c.status.in_(("active", "supported")),
            issue,
        ).order_by(issue_order, releases.c.updated_at.desc()).limit(limit * 4)).mappings().all()
        result = []
        for row in rows:
            state = _monitoring_row_state(row, now)
            if state == "healthy":
                continue
            score = {"failed": 740, "stale": 700, "degraded": 620, "not_configured": 600, "inactive": 560}[state]
            result.append(HomeAction(
                id=f"monitoring:{row['release_id']}", source_type="monitoring", source_id=row["release_id"],
                product_id=row["product_id"], release_id=row["release_id"],
                product_name=row["product_name"], release_version=row["release_version"],
                title=f"Restore monitoring for {row['product_name']} {row['release_version']}",
                reason={
                    "failed": "Latest monitoring check failed", "stale": "Successful monitoring evidence is stale or missing",
                    "degraded": "Monitoring completed with coverage limitations", "not_configured": "Monitoring is not configured",
                    "inactive": "Monitoring is disabled",
                }[state],
                priority=_priority(score), due_at=_optional_utc(row["next_check_at"]), score=score,
                target_url=_url("monitoring", row["release_id"], row["product_id"], row["release_id"]),
                updated_at=_utc(row["monitoring_updated_at"] or row["release_updated_at"]),
            ))
        return result

    def _document_actions(self, session: Session, organization_id: str, limit: int) -> list[HomeAction]:
        status_expression = self._document_status_expression()
        status_order = case({"rejected": 0, "pending": 1, "draft": 2}, value=status_expression, else_=3)
        rows = session.execute(select(
            documents, status_expression.label("document_status"),
            products.c.name.label("product_name"), releases.c.version.label("release_version"),
        ).join(products, and_(products.c.id == documents.c.product_id, products.c.organization_id == documents.c.organization_id)).outerjoin(
            releases, and_(releases.c.id == documents.c.release_id, releases.c.organization_id == documents.c.organization_id)
        ).where(
            documents.c.organization_id == organization_id,
            status_expression.in_(("draft", "pending", "rejected")),
        ).order_by(status_order, documents.c.updated_at.desc()).limit(limit * 4)).mappings().all()
        result = []
        for row in rows:
            state = row["document_status"]
            score = {"rejected": 640, "pending": 600, "draft": 520}[state]
            result.append(HomeAction(
                id=f"document:{row['id']}", source_type="document", source_id=row["id"],
                product_id=row["product_id"], release_id=row["release_id"],
                product_name=row["product_name"], release_version=row["release_version"],
                title=row["name"], reason={
                    "rejected": "Document was rejected and needs revision",
                    "pending": "Document is waiting for approval",
                    "draft": "Draft document is not approved evidence",
                }[state], priority=_priority(score), due_at=None, score=score,
                target_url=_url("document", row["id"], row["product_id"], row["release_id"]),
                updated_at=_utc(row["updated_at"]),
            ))
        return result

    @staticmethod
    def _recent_changes(session: Session, organization_id: str, limit: int) -> list[RecentChange]:
        statements = [
            select(
                finding_audit_events.c.id.label("id"), literal("finding").label("source_type"),
                finding_audit_events.c.finding_id.label("source_id"), findings.c.product_id, findings.c.release_id,
                findings.c.title.label("title"), finding_audit_events.c.action.label("description"),
                finding_audit_events.c.actor_id, finding_audit_events.c.occurred_at,
            ).join(findings, and_(findings.c.id == finding_audit_events.c.finding_id, findings.c.organization_id == finding_audit_events.c.organization_id)).where(finding_audit_events.c.organization_id == organization_id),
            select(
                compliance_audit_events.c.id.label("id"), literal("compliance").label("source_type"),
                compliance_audit_events.c.item_id.label("source_id"), compliance_items.c.product_id, compliance_items.c.release_id,
                compliance_items.c.title.label("title"), compliance_audit_events.c.action.label("description"),
                compliance_audit_events.c.actor_id, compliance_audit_events.c.occurred_at,
            ).join(compliance_items, and_(compliance_items.c.id == compliance_audit_events.c.item_id, compliance_items.c.organization_id == compliance_audit_events.c.organization_id)).where(compliance_audit_events.c.organization_id == organization_id),
            select(
                document_events.c.id.label("id"), literal("document").label("source_type"),
                document_events.c.document_id.label("source_id"), documents.c.product_id, documents.c.release_id,
                documents.c.name.label("title"), document_events.c.event_type.label("description"),
                document_events.c.actor_id, document_events.c.occurred_at,
            ).join(documents, and_(documents.c.id == document_events.c.document_id, documents.c.organization_id == document_events.c.organization_id)).where(document_events.c.organization_id == organization_id),
            select(
                release_monitoring_events.c.id.label("id"), literal("monitoring").label("source_type"),
                release_monitoring_events.c.release_id.label("source_id"), release_monitoring_events.c.product_id, release_monitoring_events.c.release_id,
                literal("Release monitoring").label("title"), release_monitoring_events.c.message.label("description"),
                release_monitoring_events.c.actor_id, release_monitoring_events.c.occurred_at,
            ).where(release_monitoring_events.c.organization_id == organization_id),
            select(
                audit_events.c.id.label("id"), literal("portfolio").label("source_type"),
                audit_events.c.entity_id.label("source_id"),
                case(
                    (audit_events.c.entity_type == "product", audit_events.c.entity_id),
                    (
                        audit_events.c.entity_type == "release",
                        select(releases.c.product_id).where(
                            releases.c.id == audit_events.c.entity_id,
                            releases.c.organization_id == audit_events.c.organization_id,
                        ).limit(1).scalar_subquery(),
                    ),
                    else_=None,
                ).label("product_id"),
                case((audit_events.c.entity_type == "release", audit_events.c.entity_id), else_=None).label("release_id"),
                audit_events.c.action.label("title"), audit_events.c.entity_type.label("description"),
                audit_events.c.actor_id, audit_events.c.occurred_at,
            ).where(audit_events.c.organization_id == organization_id),
        ]
        combined = union_all(*statements).subquery()
        rows = session.execute(select(combined).order_by(combined.c.occurred_at.desc(), combined.c.id).limit(limit)).mappings().all()
        return [RecentChange(
            id=row["id"], source_type=row["source_type"], source_id=row["source_id"],
            product_id=row["product_id"], release_id=row["release_id"],
            title=row["title"] or row["source_type"].title(), description=_humanize(row["description"]),
            actor_id=row["actor_id"], occurred_at=_utc(row["occurred_at"]),
            target_url=_url(row["source_type"], row["source_id"], row["product_id"], row["release_id"]),
        ) for row in rows]


def _monitoring_row_state(row: Mapping[str, Any], now: datetime) -> str:
    if row["health"] is None:
        return "not_configured"
    if not row["enabled"] or row["health"] == "inactive":
        return "inactive"
    if row["health"] == "failed":
        return "failed"
    next_check = _optional_utc(row["next_check_at"])
    if row["last_success_at"] is None or next_check is None or next_check <= now:
        return "stale"
    if row["health"] == "degraded":
        return "degraded"
    return "healthy"


def _compliance_reason(row: Mapping[str, Any]) -> str:
    if row["kind"] in {"missing_evidence", "missing_document"}:
        return "Required compliance evidence is missing"
    if row["status"] == "pending_approval":
        return "Compliance record is waiting for approval"
    if row["reporting_stage"]:
        return f"CRA {str(row['reporting_stage']).replace('_', ' ')} requires action"
    return "Compliance obligation requires action"


def _action_order(item: HomeAction) -> tuple[Any, ...]:
    due = item.due_at or datetime.max.replace(tzinfo=timezone.utc)
    return (-item.score, due, -item.updated_at.timestamp(), item.id)


def _priority(score: int) -> str:
    if score >= 900:
        return "urgent"
    if score >= 700:
        return "high"
    if score >= 550:
        return "normal"
    return "low"


def _url(source_type: str, source_id: str, product_id: str | None, release_id: str | None) -> str:
    scope = []
    if product_id:
        scope.append(f"product={product_id}")
    if release_id:
        scope.append(f"release={release_id}")
    query = ("?" + "&".join(scope)) if scope else ""
    if source_type == "finding":
        return f"/findings/{source_id}{query}"
    if source_type == "compliance":
        separator = "&" if query else "?"
        return f"/compliance{query}{separator}item={source_id}"
    if source_type == "document":
        return f"/documents/{source_id}{query}"
    if source_type == "monitoring" and product_id and release_id:
        return f"/products/{product_id}/releases/{release_id}?tab=overview"
    if source_type == "portfolio":
        if release_id and product_id:
            return f"/products/{product_id}/releases/{release_id}"
        if product_id:
            return f"/products/{product_id}"
        return "/products"
    return "/"


def _humanize(value: Any) -> str:
    return str(value or "Updated").replace(".", " ").replace("_", " ").strip().capitalize()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _optional_utc(value: datetime | None) -> datetime | None:
    return _utc(value) if value is not None else None


def _date_due(value: Any) -> datetime | None:
    if value is None:
        return None
    return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
