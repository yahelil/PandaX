from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest

from pandax.compliance import ComplianceRepository
from pandax.documents import DocumentRepository
from pandax.findings import FindingObservation, FindingRepository
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.search_notifications import (
    NotificationInput,
    NotificationNotFound,
    SearchNotificationRepository,
    SearchNotificationValidationError,
)

NOW = datetime(2026, 9, 14, 9, 0, tzinfo=timezone.utc)


@pytest.fixture
def repository(tmp_path) -> SearchNotificationRepository:
    engine = create_portfolio_engine(f"sqlite:///{tmp_path / 'search.db'}")
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    for organization_id, name in (("org-acme", "Acme"), ("org-other", "Other")):
        portfolio.create_organization(
            organization_id=organization_id, name=name, legal_name=f"{name} B.V.",
            country="NL", registration_number=f"{organization_id}-1", actor_id="admin",
        )
        portfolio.create_product(
            organization_id, product_id=f"{organization_id}-camera", name="Smart Camera",
            identifier=f"CAM-{organization_id}", manufacturer=name, cra_class="important_i",
            support_start=date(2026, 1, 1), support_end=date(2031, 1, 1), actor_id="admin",
        )
        portfolio.create_release(
            organization_id, f"{organization_id}-camera", release_id=f"{organization_id}-release",
            version="2.1", channel="stable", release_date=date(2026, 9, 1),
            support_start=date(2026, 9, 1), support_end=date(2031, 1, 1), actor_id="admin",
        )
    findings = FindingRepository(engine)
    findings.create_schema()
    findings.upsert_from_analysis(
        "org-acme", "org-acme-camera", "org-acme-release", "analysis-1",
        [FindingObservation(
            reference_id="CVE-2026-4100", cve="CVE-2026-4100",
            component="camera-auth", version="1.0.0", title="Camera authentication bypass",
            severity="critical", cvss=9.8, kev=True, reachability="reachable", source="osv",
        )], actor_id="analyzer", seen_at=NOW,
    )
    ComplianceRepository(engine, clock=lambda: NOW).create_item(
        "org-acme", product_id="org-acme-camera", release_id="org-acme-release",
        kind="deadline", title="Camera declaration deadline",
        description="Declaration must be approved before market placement.",
        priority="high", source_type="cra", source_id="camera-declaration",
        actor_id="operator", due_at=NOW + timedelta(days=2),
    )
    DocumentRepository(engine).create_document(
        "org-acme", "org-acme-camera", release_id="org-acme-release",
        name="Smart Camera CRA reporting pack", kind="cra_reporting_pack",
        format="pdf_a_2b", content_hash="a" * 64, storage_locator="evidence/report.pdf",
        size_bytes=4096, provenance={"generator": "pandax"}, actor_id="operator",
    )
    result = SearchNotificationRepository(engine)
    result.create_schema()
    return result


def notification(**changes) -> NotificationInput:
    values = {
        "source_fingerprint": "finding:CVE-2026-4100",
        "kind": "finding",
        "priority": "critical",
        "title": "Reachable KEV requires review",
        "detail": "CVE-2026-4100 affects camera-auth 1.0.0.",
        "product_id": "org-acme-camera",
        "release_id": "org-acme-release",
        "target_url": "/findings/finding-1",
        "requires_action": True,
    }
    values.update(changes)
    return NotificationInput(**values)


def test_search_is_categorized_ranked_bounded_and_tenant_scoped(repository):
    results = repository.search("org-acme", "camera", limit=20)

    assert {item.category for item in results} == {
        "products", "releases", "findings", "compliance", "documents"
    }
    assert all("org-other" not in (item.product_id or "") for item in results)
    assert results == sorted(
        results,
        key=lambda item: (item.rank, {"products": 0, "releases": 1, "findings": 2, "compliance": 3, "documents": 4}[item.category], item.title.casefold(), item.id),
    )
    findings = repository.search("org-acme", "CVE-2026-4100", categories=["findings"], limit=1)
    assert len(findings) == 1
    assert findings[0].url.startswith("/findings/")
    with pytest.raises(SearchNotificationValidationError):
        repository.search("org-acme", "x")
    with pytest.raises(SearchNotificationValidationError):
        repository.search("org-acme", "camera", limit=51)
    assert repository.search("org-acme", "%%") == []


def test_notification_upsert_preserves_ack_until_material_change(repository):
    created = repository.upsert_notification("org-acme", notification(), now=NOW)
    acknowledged = repository.acknowledge(
        "org-acme", created.id, actor_id="reviewer", now=NOW + timedelta(minutes=1)
    )
    repeated = repository.upsert_notification(
        "org-acme", notification(), now=NOW + timedelta(hours=1)
    )

    assert repeated.id == created.id
    assert repeated.first_seen_at == NOW
    assert repeated.last_seen_at == NOW + timedelta(hours=1)
    assert repeated.acknowledged_at == acknowledged.acknowledged_at
    assert repository.acknowledge(
        "org-acme", created.id, actor_id="another-reviewer", now=NOW + timedelta(minutes=30)
    ).acknowledged_by == "reviewer"
    changed = repository.upsert_notification(
        "org-acme", notification(detail="EPSS increased to 99%; immediate review required."),
        now=NOW + timedelta(hours=2),
    )
    assert changed.id == created.id
    assert changed.acknowledged_at is None
    assert changed.read_at is None


def test_default_inbox_unions_unread_and_unacknowledged_actions(repository):
    action = repository.upsert_notification("org-acme", notification(), now=NOW)
    info = repository.upsert_notification("org-acme", notification(
        source_fingerprint="analysis:42", kind="analysis", priority="info",
        title="Analysis completed", detail="Release 2.1 analysis completed.",
        target_url="/products/org-acme-camera/releases/org-acme-release/analysis/result",
        requires_action=False,
    ), now=NOW + timedelta(minutes=1))
    repository.mark_read("org-acme", action.id, now=NOW + timedelta(minutes=2))
    repository.mark_read("org-acme", info.id, now=NOW + timedelta(minutes=2))

    assert [item.id for item in repository.list_notifications("org-acme")] == [action.id]
    assert repository.list_notifications("org-acme", view="unread") == []
    assert [item.id for item in repository.list_notifications("org-acme", view="all")] == [action.id, info.id]
    repository.acknowledge("org-acme", action.id, actor_id="reviewer", now=NOW + timedelta(minutes=3))
    assert repository.list_notifications("org-acme") == []


def test_notification_targets_and_acknowledgement_are_tenant_safe(repository):
    created = repository.upsert_notification("org-acme", notification(), now=NOW)
    with pytest.raises(NotificationNotFound):
        repository.get_notification("org-other", created.id)
    with pytest.raises(NotificationNotFound):
        repository.acknowledge("org-other", created.id, actor_id="reviewer", now=NOW)
    with pytest.raises(NotificationNotFound):
        repository.upsert_notification("org-acme", notification(
            source_fingerprint="bad", product_id="org-other-camera", release_id="org-other-release",
        ), now=NOW)
    with pytest.raises(SearchNotificationValidationError):
        repository.upsert_notification("org-acme", notification(
            source_fingerprint="external", product_id=None, release_id=None,
            target_url="https://evil.example/path",
        ), now=NOW)
