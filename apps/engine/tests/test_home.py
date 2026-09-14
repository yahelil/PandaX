from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest

from pandax.compliance import ComplianceRepository
from pandax.documents import DocumentRepository
from pandax.findings import FindingObservation, FindingRepository
from pandax.home import HomeNotFound, HomeReadModel, HomeValidationError
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.release_monitoring import MonitoringObservation, ReleaseMonitoringRepository


NOW = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)


@pytest.fixture()
def seeded(tmp_path):
    engine = create_portfolio_engine(f"sqlite+pysqlite:///{tmp_path / 'home.sqlite3'}")
    portfolio = PortfolioRepository(engine)
    findings = FindingRepository(engine)
    compliance = ComplianceRepository(engine, clock=lambda: NOW)
    documents = DocumentRepository(engine)
    monitoring = ReleaseMonitoringRepository(engine)
    portfolio.create_schema()
    findings.create_schema()
    compliance.create_schema()
    documents.create_schema()
    monitoring.create_schema()

    for organization_id in ("org-acme", "org-other"):
        portfolio.create_organization(
            organization_id=organization_id,
            name=organization_id,
            legal_name=f"{organization_id} GmbH",
            country="DE",
            registration_number=organization_id,
            actor_id="admin",
        )
        portfolio.create_product(
            organization_id,
            product_id=f"product-{organization_id}",
            name="Home Hub" if organization_id == "org-acme" else "Hidden Hub",
            identifier=f"HUB-{organization_id}",
            manufacturer="Acme",
            cra_class="important_i",
            support_start=date(2026, 1, 1),
            support_end=date(2031, 1, 1),
            readiness="needs_attention",
            actor_id="admin",
        )
        portfolio.create_release(
            organization_id,
            f"product-{organization_id}",
            release_id=f"release-{organization_id}",
            version="1.4",
            channel="stable",
            status="active",
            release_date=date(2026, 9, 1),
            support_start=date(2026, 9, 1),
            support_end=date(2031, 1, 1),
            actor_id="admin",
        )

    findings.upsert_from_analysis(
        "org-acme", "product-org-acme", "release-org-acme", "analysis-acme",
        [FindingObservation(
            reference_id="CVE-2026-9001", cve="CVE-2026-9001", component="libcamera",
            version="4.2", source="osv", title="Reachable command injection",
            severity="critical", cvss=9.8, kev=True, epss=0.96, reachability="reachable",
        )], actor_id="scanner", seen_at=NOW - timedelta(hours=2),
    )
    findings.upsert_from_analysis(
        "org-other", "product-org-other", "release-org-other", "analysis-other",
        [FindingObservation(
            reference_id="CVE-2026-9999", component="hidden", version="1",
            source="osv", title="Other tenant finding", severity="critical", kev=True,
            reachability="reachable",
        )], actor_id="scanner", seen_at=NOW - timedelta(hours=1),
    )

    compliance.create_item(
        "org-acme", item_id="deadline-acme", product_id="product-org-acme",
        release_id="release-org-acme", kind="deadline", title="Submit CRA early warning",
        description="24-hour reporting deadline.", priority="critical",
        status="action_required", due_at=NOW - timedelta(hours=1),
        source_type="case_store", source_id="case-acme", reporting_stage=None,
        actor_id="projector",
    )
    compliance.create_item(
        "org-acme", item_id="evidence-acme", product_id="product-org-acme",
        release_id="release-org-acme", kind="missing_evidence", title="Add exploitability evidence",
        description="Reachability decision lacks verification evidence.", priority="high",
        status="action_required", source_type="evidence_service", source_id="gap-acme",
        actor_id="projector",
    )
    compliance.create_item(
        "org-other", item_id="deadline-other", product_id="product-org-other",
        release_id="release-org-other", kind="deadline", title="Other tenant deadline",
        description="Must never cross tenant boundary.", priority="critical",
        status="action_required", due_at=NOW - timedelta(days=2),
        source_type="case_store", source_id="case-other", actor_id="projector",
    )

    document = documents.create_document(
        "org-acme", "product-org-acme", release_id="release-org-acme",
        document_id="document-acme", name="EU Declaration of Conformity", kind="conformity",
        format="pdf_a_2b", content_hash="a" * 64,
        storage_locator="evidence/conformity-r1.pdf", size_bytes=1042,
        provenance={"source": "manufacturer"}, actor_id="author",
    )
    documents.request_approval(
        "org-acme", document.document.id, 1,
        expected_status="draft", actor_id="author",
    )

    monitoring.configure(
        "org-acme", "product-org-acme", "release-org-acme",
        enabled_sources=["osv", "cisa_kev"], cadence_minutes=60, enabled=True,
        actor_id="security", now=NOW - timedelta(minutes=60),
    )
    claim = monitoring.claim_now(
        "org-acme", "product-org-acme", "release-org-acme",
        actor_id="security", now=NOW - timedelta(minutes=50),
    )
    monitoring.complete_success(
        claim,
        MonitoringObservation(
            {"status": "partial"},
            limitations=("Vendor advisory endpoint unavailable",),
        ),
        now=NOW - timedelta(minutes=45),
    )
    return engine


def test_home_aggregates_truth_and_prioritizes_action_queue(seeded):
    snapshot = HomeReadModel(seeded).get("org-acme", queue_limit=5, recent_limit=10, now=NOW)

    assert snapshot.monitoring.state == "degraded"
    assert snapshot.monitoring.degraded == 1
    assert snapshot.monitoring.cadence_minutes == (60,)
    assert snapshot.monitoring.next_check_at == NOW + timedelta(minutes=15)
    assert snapshot.monitoring.last_check_at == NOW - timedelta(minutes=45)
    assert [(item.source, item.state, item.release_count) for item in snapshot.monitoring.sources] == [
        ("cisa_kev", "degraded", 1), ("osv", "degraded", 1),
    ]
    assert snapshot.counters.findings_needing_action == 1
    assert snapshot.counters.urgent_findings == 1
    assert snapshot.counters.reachable_kev_findings == 1
    assert snapshot.counters.overdue_obligations == 1
    assert snapshot.counters.missing_evidence == 1
    assert snapshot.counters.pending_approvals == 1
    assert snapshot.counters.documents_needing_action == 1
    assert snapshot.counters.monitoring_issues == 1
    assert [item.source_type for item in snapshot.action_queue[:4]] == [
        "finding", "compliance", "compliance", "monitoring",
    ]
    assert [item.source_id for item in snapshot.action_queue[1:4]] == [
        "deadline-acme", "evidence-acme", "release-org-acme",
    ]
    assert snapshot.action_queue[0].priority == "urgent"
    assert snapshot.action_queue[0].target_url.startswith("/findings/")
    assert "product=product-org-acme" in snapshot.action_queue[0].target_url


def test_cross_tenant_data_is_excluded_from_all_home_sections(seeded):
    snapshot = HomeReadModel(seeded).get("org-acme", queue_limit=50, recent_limit=50, now=NOW)
    serialized = repr(snapshot)

    assert "org-other" not in serialized
    assert "Other tenant" not in serialized
    assert snapshot.counters.findings_needing_action == 1
    assert snapshot.counters.compliance_actions == 2
    assert all(change.source_id != "deadline-other" for change in snapshot.recent_changes)


def test_missing_monitoring_is_not_reported_healthy(seeded):
    portfolio = PortfolioRepository(seeded)
    portfolio.create_release(
        "org-acme", "product-org-acme", release_id="release-unmonitored",
        version="1.5", channel="stable", status="supported",
        release_date=date(2026, 9, 10), support_start=date(2026, 9, 10),
        support_end=date(2031, 1, 1), actor_id="admin",
    )

    snapshot = HomeReadModel(seeded).get("org-acme", now=NOW)

    assert snapshot.monitoring.state == "not_configured"
    assert snapshot.monitoring.not_configured == 1
    assert snapshot.counters.monitoring_issues == 2
    assert any("no monitoring configuration" in warning for warning in snapshot.data_warnings)


def test_empty_and_invalid_requests_are_explicit(seeded):
    model = HomeReadModel(seeded)

    with pytest.raises(HomeNotFound):
        model.get("org-missing", now=NOW)
    with pytest.raises(HomeValidationError):
        model.get("org-acme", queue_limit=0, now=NOW)
    with pytest.raises(HomeValidationError):
        model.get("org-acme", recent_limit=51, now=NOW)
