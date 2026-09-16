"""Authenticated search and notification inbox HTTP API."""
from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict

from .auth import authorize_request
from .notification_delivery import DeliveryConflict, DeliveryNotFound, NotificationDeliveryError
from .portfolio_api import (
    IdentityDependency, PORTFOLIO_EDIT_ROLES, PORTFOLIO_ROLES,
    PortfolioIdentity, local_identity,
)
from .search_notifications import (
    NotificationNotFound,
    SearchNotificationConflict,
    SearchNotificationError,
    SearchNotificationRepository,
    SearchNotificationValidationError,
    SearchResult,
)

Category = Literal["products", "releases", "findings", "compliance", "documents"]
NotificationKind = Literal["finding", "compliance", "monitoring", "document", "analysis", "system"]
Priority = Literal["critical", "high", "medium", "low", "info"]
InboxView = Literal["unread_action", "unread", "action", "all"]


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class SearchResultResponse(ApiModel):
    category: Category
    id: str
    title: str
    subtitle: str
    product_id: str | None
    release_id: str | None
    priority: str | None
    url: str
    rank: int


class SearchGroupResponse(ApiModel):
    category: Category
    results: list[SearchResultResponse]


class SearchResponse(ApiModel):
    query: str
    total: int
    groups: list[SearchGroupResponse]


class NotificationResponse(ApiModel):
    id: str
    organization_id: str
    source_fingerprint: str
    kind: NotificationKind
    priority: Priority
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


class DeliveryResponse(ApiModel):
    id: str
    organization_id: str
    notification_id: str
    integration_id: str
    channel: Literal["email", "webhook", "jira"]
    status: Literal["queued", "delivering", "retrying", "delivered", "dead_letter", "suppressed"]
    attempt_count: int
    max_attempts: int
    next_attempt_at: datetime
    provider_reference: str | None
    error_code: str | None
    created_at: datetime
    updated_at: datetime
    delivered_at: datetime | None


RepositoryDependency = Callable[[], SearchNotificationRepository]


def create_search_notifications_router(
    repository_dependency: RepositoryDependency,
    identity_dependency: IdentityDependency = local_identity,
) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["search", "notifications"])
    Repository = Annotated[SearchNotificationRepository, Depends(repository_dependency)]
    Identity = Annotated[PortfolioIdentity, Depends(identity_dependency)]

    @router.get("/organizations/{organization_id}/search", response_model=SearchResponse)
    def search(
        organization_id: str,
        q: Annotated[str, Query(min_length=2, max_length=100)],
        repository: Repository,
        identity: Identity,
        category: Annotated[list[Category] | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=50)] = 20,
    ):
        _authorize(identity, organization_id)
        results = _call(lambda: repository.search(
            organization_id, q, categories=category or (), limit=limit,
        ))
        return _grouped(q, results)

    collection = "/organizations/{organization_id}/notifications"

    @router.get(collection, response_model=list[NotificationResponse])
    def list_notifications(
        organization_id: str,
        repository: Repository,
        identity: Identity,
        view: InboxView = "unread_action",
        kind: NotificationKind | None = None,
        priority: Priority | None = None,
        product_id: str | None = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ):
        _authorize(identity, organization_id)
        return _call(lambda: repository.list_notifications(
            organization_id, view=view, kind=kind, priority=priority,
            product_id=product_id, limit=limit,
        ))

    @router.post(collection + "/{notification_id}/read", response_model=NotificationResponse)
    def mark_read(
        organization_id: str,
        notification_id: str,
        repository: Repository,
        identity: Identity,
    ):
        _authorize(identity, organization_id)
        return _call(lambda: repository.mark_read(organization_id, notification_id))

    @router.post(collection + "/{notification_id}/acknowledge", response_model=NotificationResponse)
    def acknowledge(
        organization_id: str,
        notification_id: str,
        repository: Repository,
        identity: Identity,
    ):
        _authorize(identity, organization_id)
        return _call(lambda: repository.acknowledge(
            organization_id, notification_id, actor_id=identity.actor_id,
        ))

    @router.get(collection + "/deliveries", response_model=list[DeliveryResponse])
    def list_deliveries(
        organization_id: str,
        repository: Repository,
        identity: Identity,
        delivery_status: Literal["queued", "delivering", "retrying", "delivered", "dead_letter", "suppressed"] | None = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 100,
    ):
        _authorize(identity, organization_id)
        return _call(lambda: repository.list_deliveries(
            organization_id, status=delivery_status, limit=limit
        ))

    @router.post(collection + "/deliveries/{delivery_id}/retry", response_model=DeliveryResponse)
    def retry_delivery(
        organization_id: str,
        delivery_id: str,
        repository: Repository,
        identity: Identity,
    ):
        authorize_request(
            identity, organization_id, PORTFOLIO_EDIT_ROLES, sensitive=True
        )
        return _call(lambda: repository.retry_delivery(organization_id, delivery_id))

    return router


def _grouped(query: str, results: list[SearchResult]) -> dict[str, Any]:
    groups: dict[str, list[SearchResult]] = {}
    for result in results:
        groups.setdefault(result.category, []).append(result)
    category_order = {name: index for index, name in enumerate(
        ("products", "releases", "findings", "compliance", "documents")
    )}
    return {
        "query": " ".join(query.split()),
        "total": len(results),
        "groups": [
            {"category": category, "results": groups[category]}
            for category in sorted(groups, key=category_order.__getitem__)
        ],
    }


def _authorize(identity: PortfolioIdentity, organization_id: str) -> None:
    authorize_request(identity, organization_id, PORTFOLIO_ROLES)


def _call(operation: Callable[[], Any]):
    try:
        return operation()
    except NotificationNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except SearchNotificationConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except SearchNotificationValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    except DeliveryNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except DeliveryConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except (NotificationDeliveryError, ValueError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    except SearchNotificationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
