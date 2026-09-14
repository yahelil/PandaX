from datetime import date, datetime, timezone

from sqlalchemy.pool import StaticPool

from pandax.compliance import ComplianceRepository
from pandax.domain_projections import ProjectedComplianceRepository, ProjectedHomeReadModel
from pandax.documents import DocumentRepository
from pandax.findings import FindingObservation, FindingRepository
from pandax.portfolio import PortfolioRepository, ReleaseChanges, create_portfolio_engine
from pandax.search_notifications import SearchNotificationRepository


def test_projector_activates_release_compliance_and_domain_notifications():
    engine = create_portfolio_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    ComplianceRepository(engine).create_schema()
    DocumentRepository(engine).create_schema()
    FindingRepository(engine).create_schema()
    SearchNotificationRepository(engine).create_schema()
    portfolio.create_organization(
        organization_id="org-acme", name="Acme", legal_name="Acme GmbH",
        country="DE", registration_number="HRB-1", actor_id="admin",
    )
    portfolio.create_product(
        "org-acme", product_id="product-camera", name="Smart Camera",
        identifier="CAM-1", manufacturer="Acme", cra_class="important_i",
        support_start=date(2026, 1, 1), support_end=date(2031, 1, 1), actor_id="admin",
    )
    portfolio.create_release(
        "org-acme", "product-camera", release_id="release-1", version="1.0.0",
        channel="stable", status="active", release_date=date(2026, 9, 1),
        support_start=date(2026, 9, 1), support_end=date(2031, 1, 1), actor_id="admin",
    )
    FindingRepository(engine).upsert_from_analysis(
        "org-acme", "product-camera", "release-1", "analysis-1",
        [FindingObservation(
            reference_id="CVE-2026-1001", cve="CVE-2026-1001", component="camera-core",
            version="1.0", title="Reachable command injection", severity="critical",
            cvss=9.8, kev=True, reachability="reachable", source="osv",
        )], actor_id="scanner", seen_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
    )
    document = DocumentRepository(engine).create_document(
        "org-acme", "product-camera", release_id="release-1",
        name="EU Declaration of Conformity", kind="conformity", format="pdf_a_2b",
        content_hash="a" * 64, storage_locator="evidence/declaration.pdf", size_bytes=512,
        provenance={"source": "manufacturer"}, actor_id="author",
    )
    DocumentRepository(engine).request_approval(
        "org-acme", document.document.id, 1, expected_status="draft", actor_id="author",
    )

    home = ProjectedHomeReadModel(engine)
    assert home.get("org-acme").counters.findings_needing_action == 1
    home.get("org-acme")

    compliance = ComplianceRepository(engine).list_items("org-acme", action_only=False)
    assert [(item.source_type, item.kind, item.status) for item in compliance] == [
        ("release_evidence", "missing_evidence", "action_required")
    ]
    inbox = SearchNotificationRepository(engine).list_notifications("org-acme", view="all")
    assert {item.kind for item in inbox} >= {"finding", "compliance", "monitoring", "document"}
    assert len({item.source_fingerprint for item in inbox}) == len(inbox)

    release = portfolio.get_release("org-acme", "release-1")
    portfolio.update_release(
        "org-acme", release.id, ReleaseChanges(sbom_status="validated"), "scanner",
    )
    projected = ProjectedComplianceRepository(engine).list_items("org-acme", action_only=False)
    assert projected[0].status == "resolved"
