from datetime import date

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool

from pandax.analysis_storage import MemoryAnalysisInputStorage
from pandax.auth import Principal, Role
from pandax.documents import DocumentRepository
from pandax.findings import FindingObservation, FindingRepository
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.release_report_api import create_release_report_router


PATH = "/v1/organizations/org-acme/products/product-hub/releases/release-14/reports/findings"


def test_report_action_downloads_stored_reviewed_release_report():
    engine = create_portfolio_engine("sqlite+pysqlite:///:memory:",
                                     connect_args={"check_same_thread": False}, poolclass=StaticPool)
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    portfolio.create_organization(organization_id="org-acme", name="Acme", legal_name="Acme",
                                  country="NL", registration_number="NL-1", actor_id="admin")
    portfolio.create_product("org-acme", product_id="product-hub", name="Home Hub",
                             identifier="HUB-1", manufacturer="Acme", cra_class="important_i",
                             support_start=date(2026, 1, 1), support_end=date(2031, 1, 1), actor_id="admin")
    portfolio.create_release("org-acme", "product-hub", release_id="release-14", version="1.4",
                             channel="stable", release_date=date(2026, 9, 1),
                             support_start=date(2026, 9, 1), support_end=date(2031, 1, 1), actor_id="admin")
    findings = FindingRepository(engine)
    findings.create_schema()
    documents = DocumentRepository(engine)
    documents.create_schema()
    storage = MemoryAnalysisInputStorage()
    found = findings.upsert_from_analysis("org-acme", "product-hub", "release-14", "analysis-1",
        [FindingObservation(reference_id="CVE-2026-1000", component="library", version="1.0",
                            title="Vulnerable library", severity="high", source="osv")], actor_id="scanner")[0]
    findings.decide("org-acme", "product-hub", "release-14", found.id,
                    decision="affected", rationale="Present in the release image",
                    expected_version=found.version, actor_id="reviewer")
    identity = {"value": Principal("reviewer", "org-acme", frozenset({Role.SECURITY_REVIEWER}))}
    app = FastAPI()
    app.include_router(create_release_report_router(lambda: portfolio, lambda: findings,
                            lambda: documents, lambda: storage, lambda: identity["value"]))
    client = TestClient(app)

    result = client.post(PATH)
    assert result.status_code == 200, result.text
    assert result.headers["content-disposition"].endswith('"release-report-release-14-r1.json"')
    assert result.json()["findings"][0]["decision"] == "affected"
    assert result.json()["summary"]["awaiting_decision"] == 0
    document_id = result.headers["x-document-id"]
    revision = documents.get_revision("org-acme", document_id, 1)
    assert storage.get(revision.storage_locator, revision.content_hash) == result.content
    assert client.post(PATH).headers["x-document-revision"] == "1"

    identity["value"] = Principal("viewer", "org-acme", frozenset({Role.VIEWER}))
    assert client.post(PATH).status_code == 403
    identity["value"] = Principal("reviewer", "org-acme", frozenset({Role.SECURITY_REVIEWER}))
    wrong_product = PATH.replace("product-hub", "other-product")
    assert client.post(wrong_product).status_code == 404
