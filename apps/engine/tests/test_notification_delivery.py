from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from pandax.notification_delivery import (
    DeliveryConflict, DeliveryNotFound, NotificationDeliveryRepository,
    NotificationDeliveryWorker,
)
from pandax.organization_settings import OrganizationSettingsRepository
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.search_notifications import NotificationInput, SearchNotificationRepository


NOW = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def delivery_scope(tmp_path):
    engine = create_portfolio_engine(f"sqlite:///{(tmp_path / 'notifications.sqlite3').as_posix()}")
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    for organization_id in ("org-acme", "org-other"):
        portfolio.create_organization(
            organization_id=organization_id, name=organization_id,
            legal_name=f"{organization_id} GmbH", country="DE",
            registration_number=organization_id, actor_id="seed",
        )
    settings = OrganizationSettingsRepository(engine)
    settings.create_member(
        "org-acme", subject="admin", name="Acme Admin", email="admin@acme.test",
        title="Administrator", initials="AA", roles=["org_admin"], actor_id="seed",
        status="active",
    )
    integrations = [
        ("email", {"provider": "resend", "from_address": "alerts@pandax.test"}),
        ("webhook", {"endpoint_name": "security-automation", "event_types": ["urgent_finding"]}),
        ("jira", {"site": "acme.atlassian.net", "project_key": "SEC"}),
    ]
    for channel, configuration in integrations:
        settings.create_integration(
            "org-acme", name=channel.title(), type=channel,
            description=f"{channel} notifications", configuration=configuration,
            status="connected", secret_reference=f"vault://actis/acme/{channel}",
            actor_id="seed", integration_id=f"integration-{channel}",
        )
    return engine, settings, SearchNotificationRepository(engine)


def _notification(source: str = "finding:CVE-2026-1") -> NotificationInput:
    return NotificationInput(
        source_fingerprint=source, kind="finding", priority="critical",
        title="Critical vulnerability requires review", detail="Review CVE-2026-1.",
        target_url="/findings/finding-1", requires_action=True,
    )


def test_delivery_outbox_is_tenant_scoped_idempotent_and_honors_preferences(delivery_scope):
    engine, settings, inbox = delivery_scope
    created = inbox.upsert_notification("org-acme", _notification(), now=NOW)
    inbox.upsert_notification("org-acme", _notification(), now=NOW + timedelta(minutes=1))
    outbox = NotificationDeliveryRepository(engine)

    assert len(outbox.list("org-acme")) == 3
    assert outbox.list("org-other") == []
    with pytest.raises(DeliveryNotFound):
        outbox.get("org-other", outbox.list("org-acme")[0].id)

    settings.update_settings(
        "org-acme", expected_version=0, actor_id="admin",
        patch={"notifications": {"urgent_findings": False}},
    )
    inbox.upsert_notification("org-acme", _notification("finding:CVE-2026-2"), now=NOW)
    assert len(outbox.list("org-acme")) == 3
    assert created.id


def test_resend_signed_webhook_and_jira_deliver_without_leaking_secrets(delivery_scope):
    engine, _, inbox = delivery_scope
    inbox.upsert_notification("org-acme", _notification(), now=NOW)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"id": f"provider-{len(requests)}"})

    secrets = {
        "vault://actis/acme/email": {"api_key": "resend-secret"},
        "vault://actis/acme/webhook": {
            "endpoint_url": "https://hooks.acme.test/actis", "signing_secret": "h" * 32,
        },
        "vault://actis/acme/jira": {"email": "jira@acme.test", "api_token": "jira-secret"},
    }
    outbox = NotificationDeliveryRepository(engine)
    completed = NotificationDeliveryWorker(
        outbox, secrets.__getitem__,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    ).run(now=NOW)

    assert len(completed) == 3
    assert {job.status for job in completed} == {"delivered"}
    assert {request.url.host for request in requests} == {
        "api.resend.com", "hooks.acme.test", "acme.atlassian.net",
    }
    webhook = next(request for request in requests if request.url.host == "hooks.acme.test")
    expected = hmac.new(
        b"h" * 32, webhook.headers["x-actis-timestamp"].encode() + b"." + webhook.content,
        hashlib.sha256,
    ).hexdigest()
    assert webhook.headers["x-actis-signature"] == f"sha256={expected}"
    persisted = json.dumps([job.payload for job in outbox.list("org-acme")])
    assert all(secret not in persisted for secret in ("resend-secret", "h" * 32, "jira-secret"))


def test_retry_dead_letter_and_quota_fallback_keep_in_app_notification(delivery_scope):
    engine, _, inbox = delivery_scope
    inbox.upsert_notification("org-acme", _notification(), now=NOW)
    outbox = NotificationDeliveryRepository(engine)
    email = next(job for job in outbox.list("org-acme") if job.channel == "email")
    claimed = outbox.claim(now=NOW)
    while claimed and claimed.id != email.id:
        outbox.delivered(claimed, "skip", now=NOW)
        claimed = outbox.claim(now=NOW)
    assert claimed and claimed.id == email.id
    retrying = outbox.failed(
        claimed, "http_429", retryable=True, retry_after_seconds=120, now=NOW
    )
    assert retrying.status == "retrying" and retrying.next_attempt_at == NOW + timedelta(seconds=120)
    reclaimed = outbox.claim(now=NOW + timedelta(seconds=121))
    while reclaimed and reclaimed.id != email.id:
        outbox.delivered(reclaimed, "skip", now=NOW)
        reclaimed = outbox.claim(now=NOW + timedelta(seconds=121))
    assert reclaimed and reclaimed.id == email.id and reclaimed.attempt_count == 2
    dead = outbox.failed(reclaimed, "http_400", retryable=False, now=NOW)
    assert dead.status == "dead_letter"
    assert outbox.retry("org-acme", dead.id, now=NOW).status == "queued"

    limited = NotificationDeliveryRepository(engine, daily_limit=1)
    inbox2 = SearchNotificationRepository(engine, delivery_daily_limit=1)
    # Existing deliveries count against the quota; the inbox record still succeeds.
    notification = inbox2.upsert_notification(
        "org-acme", _notification("finding:CVE-2026-3"), now=NOW + timedelta(hours=1)
    )
    assert notification.title
    suppressed = next(
        job for job in limited.list("org-acme")
        if job.notification_id == notification.id and job.status == "suppressed"
    )
    with pytest.raises(DeliveryConflict, match="quota remains exhausted"):
        limited.retry("org-acme", suppressed.id, now=NOW + timedelta(hours=1))
