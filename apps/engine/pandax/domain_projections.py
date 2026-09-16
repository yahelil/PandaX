"""Runtime projectors from durable domain state into actionable read models."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.engine import Engine

from .compliance import ComplianceRepository
from .home import HomeReadModel, HomeSnapshot
from .search_notifications import (
    NotificationInput,
    SearchNotificationRepository,
)


class DomainProjector:
    """Idempotent tenant-scoped projection at production read boundaries."""

    def __init__(self, engine: Engine, *, delivery_daily_limit: int = 500):
        self.engine = engine
        self.delivery_daily_limit = delivery_daily_limit

    def project(self, organization_id: str) -> None:
        ComplianceRepository(self.engine).project_release_evidence(organization_id)
        snapshot = HomeReadModel(self.engine).get(
            organization_id, queue_limit=50, recent_limit=1,
        )
        inbox = SearchNotificationRepository(
            self.engine, delivery_daily_limit=self.delivery_daily_limit
        )
        for action in snapshot.action_queue:
            inbox.upsert_notification(
                organization_id,
                NotificationInput(
                    source_fingerprint=f"domain-action:{action.source_type}:{action.source_id}",
                    kind=action.source_type,
                    priority={"urgent": "critical", "high": "high", "normal": "medium", "low": "low"}[action.priority],
                    title=action.title,
                    detail=action.reason,
                    target_url=action.target_url,
                    requires_action=True,
                    product_id=action.product_id,
                    release_id=action.release_id,
                ),
            )


class ProjectedHomeReadModel(HomeReadModel):
    def __init__(
        self, engine: Engine, *, clock: Any = None, delivery_daily_limit: int = 500
    ):
        super().__init__(engine, clock=clock)
        self.projector = DomainProjector(
            engine, delivery_daily_limit=delivery_daily_limit
        )

    def get(
        self,
        organization_id: str,
        *,
        queue_limit: int = 8,
        recent_limit: int = 8,
        now: datetime | None = None,
    ) -> HomeSnapshot:
        self.projector.project(organization_id)
        return super().get(
            organization_id, queue_limit=queue_limit, recent_limit=recent_limit, now=now,
        )


class ProjectedComplianceRepository(ComplianceRepository):
    def list_items(self, organization_id: str, **filters: Any):
        self.project_release_evidence(organization_id)
        return super().list_items(organization_id, **filters)


class ProjectedSearchNotificationRepository(SearchNotificationRepository):
    def __init__(self, engine: Engine, *, delivery_daily_limit: int = 500):
        super().__init__(engine, delivery_daily_limit=delivery_daily_limit)
        self.projector = DomainProjector(
            engine, delivery_daily_limit=delivery_daily_limit
        )

    def list_notifications(self, organization_id: str, **filters: Any):
        self.projector.project(organization_id)
        return super().list_notifications(organization_id, **filters)
