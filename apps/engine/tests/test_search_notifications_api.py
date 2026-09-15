from __future__ import annotations

from datetime import date, datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pandax.findings import FindingObservation, FindingRepository
from pandax.notification_delivery import NotificationDeliveryRepository
from pandax.organization_settings import OrganizationSettingsRepository
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.portfolio_api import PortfolioIdentity
from pandax.search_notifications import NotificationInput, SearchNotificationRepository
from pandax.search_notifications_api import create_search_notifications_router

NOW = datetime(2026, 9, 14, 9, 0, tzinfo=timezone.utc)
SEARCH = "/v1/organizations/org-acme/search"
INBOX = "/v1/organizations/org-acme/notifications"


@pytest.fixture
def repository(tmp_path) -> SearchNotificationRepository:
    engine = create_portfolio_engine(f"sqlite:///{tmp_path / 'search-api.db'}")
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    portfolio.create_organization(
        organization_id="org-acme", name="Acme", legal_name="Acme B.V.",
        country="NL", registration_number="NL-1", actor_id="admin",
    )
    portfolio.create_product(
        "org-acme", product_id="camera", name="Smart Camera", identifier="CAM-100",
        manufacturer="Acme", cra_class="important_i", support_start=date(2026, 1, 1),
        support_end=date(2031, 1, 1), actor_id="admin",
    )
    portfolio.create_release(
        "org-acme", "camera", release_id="release-21", version="2.1", channel="stable",
        release_date=date(2026, 9, 1), support_start=date(2026, 9, 1),
        support_end=date(2031, 1, 1), actor_id="admin",
    )
    findings = FindingRepository(engine)
    findings.create_schema()
    findings.upsert_from_analysis(
        "org-acme", "camera", "release-21", "analysis-1",
        [FindingObservation(
            reference_id="CVE-2026-4100", component="camera-auth", version="1.0",
            title="Camera authentication bypass", severity="critical", source="osv",
        )], actor_id="analyzer", seen_at=NOW,
    )
    result = SearchNotificationRepository(engine)
    result.create_schema()
    result.upsert_notification("org-acme", NotificationInput(
        source_fingerprint="finding:CVE-2026-4100", kind="finding", priority="critical",
        title="Reachable vulnerability requires review", detail="Review CVE-2026-4100.",
        target_url="/findings/finding-1", requires_action=True,
        product_id="camera", release_id="release-21",
    ), now=NOW)
    return result


def make_client(repository, *, roles={"viewer"}, organization_id="org-acme"):
    app = FastAPI()
    app.include_router(create_search_notifications_router(
        lambda: repository,
        lambda: PortfolioIdentity(
            actor_id="user-1", organization_id=organization_id, roles=frozenset(roles),
        ),
    ))
    return TestClient(app)


def test_categorized_search_and_validation(repository):
    api = make_client(repository)
    response = api.get(SEARCH, params=[("q", "camera"), ("category", "products"), ("category", "findings")])

    assert response.status_code == 200
    assert response.json()["total"] == 2
    assert [group["category"] for group in response.json()["groups"]] == ["products", "findings"]
    assert api.get(SEARCH, params={"q": "x"}).status_code == 422
    assert api.get(SEARCH, params={"q": "camera", "limit": 51}).status_code == 422


def test_inbox_read_and_acknowledge(repository):
    api = make_client(repository)
    found = api.get(INBOX).json()[0]

    read = api.post(INBOX + f"/{found['id']}/read")
    assert read.status_code == 200
    assert read.json()["read_at"] is not None
    assert len(api.get(INBOX).json()) == 1  # unread OR unacknowledged action

    acknowledged = api.post(INBOX + f"/{found['id']}/acknowledge")
    assert acknowledged.status_code == 200
    assert acknowledged.json()["acknowledged_by"] == "user-1"
    assert api.get(INBOX).json() == []
    assert len(api.get(INBOX, params={"view": "all"}).json()) == 1


def test_scope_and_known_role_authorization(repository):
    hidden = make_client(repository, organization_id="org-other")
    assert hidden.get(SEARCH, params={"q": "camera"}).status_code == 404
    assert hidden.get(INBOX).status_code == 404

    unknown = make_client(repository, roles={"external"})
    assert unknown.get(SEARCH, params={"q": "camera"}).status_code == 403
    assert unknown.get(INBOX).status_code == 403
    assert unknown.post(INBOX + "/missing/acknowledge").status_code == 403


def test_missing_notification_is_hidden(repository):
    api = make_client(repository, roles={"security_reviewer"})
    assert api.post(INBOX + "/missing/read").status_code == 404
    assert api.post(INBOX + "/missing/acknowledge").status_code == 404


def test_delivery_visibility_retry_and_admin_authorization(repository):
    settings = OrganizationSettingsRepository(repository.engine)
    settings.create_integration(
        "org-acme", name="Webhook", type="webhook", description="Automation",
        configuration={"endpoint_name": "automation", "event_types": ["urgent_finding"]},
        status="connected", secret_reference="vault://actis/acme/webhook",
        actor_id="admin", integration_id="integration-webhook",
    )
    repository.upsert_notification("org-acme", NotificationInput(
        source_fingerprint="finding:CVE-2026-4200", kind="finding", priority="critical",
        title="Another critical finding", detail="Review CVE-2026-4200.",
        target_url="/findings/finding-2", requires_action=True,
    ), now=NOW)
    outbox = NotificationDeliveryRepository(repository.engine)
    claimed = outbox.claim(now=NOW)
    assert claimed
    dead = outbox.failed(claimed, "http_400", retryable=False, now=NOW)

    admin = make_client(repository, roles={"org_admin"})
    response = admin.get(INBOX + "/deliveries")
    assert response.status_code == 200
    assert "payload" not in response.json()[0] and "idempotency_key" not in response.json()[0]
    assert admin.post(INBOX + f"/deliveries/{dead.id}/retry").json()["status"] == "queued"
    assert make_client(repository).post(
        INBOX + f"/deliveries/{dead.id}/retry"
    ).status_code == 403
