from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone

import pytest

from pandax.analysis_storage import MemoryAnalysisInputStorage
from pandax.documents import DocumentRepository
from pandax.findings import FindingObservation, FindingRepository
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.release_report_service import REPORT_NAME, generate_release_report

NOW = datetime(2026, 9, 16, 9, 0, tzinfo=timezone.utc)
ORG, PRODUCT, RELEASE = "org-acme", "product-hub", "release-14"


@pytest.fixture
def scope(tmp_path):
    engine = create_portfolio_engine(f"sqlite:///{tmp_path / 'reports.db'}")
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    portfolio.create_organization(
        organization_id=ORG, name="Acme", legal_name="Acme B.V.",
        country="NL", registration_number="NL-1", actor_id="admin",
    )
    portfolio.create_product(
        ORG, product_id=PRODUCT, name="Home Hub", identifier="HUB-100",
        manufacturer="Acme", cra_class="important_i", support_start=date(2026, 1, 1),
        support_end=date(2031, 1, 1), actor_id="admin",
    )
    portfolio.create_release(
        ORG, PRODUCT, release_id=RELEASE, version="1.4", channel="stable",
        release_date=date(2026, 9, 1), support_start=date(2026, 9, 1),
        support_end=date(2031, 1, 1), actor_id="admin",
    )
    findings = FindingRepository(engine)
    findings.create_schema()
    documents = DocumentRepository(engine)
    documents.create_schema()

    class Scope:
        def __init__(self):
            self.findings = findings
            self.documents = documents
            self.storage = MemoryAnalysisInputStorage()

        def ingest(self, analysis_id="analysis-1", seen_at=NOW, **changes):
            values = {
                "reference_id": "CVE-2021-44228", "cve": "CVE-2021-44228",
                "component": "log4j-core", "purl": "pkg:maven/log4j@2.14.1",
                "version": "2.14.1", "title": "Remote code execution",
                "description": "Attacker-controlled lookup runs code.",
                "severity": "critical", "cvss": 10.0, "kev": True, "epss": 0.975,
                "reachability": "reachable", "reachability_evidence": {},
                "reachability_limitations": [], "source": "osv", "provenance": {},
            }
            values.update(changes)
            return findings.upsert_from_analysis(
                ORG, PRODUCT, RELEASE, analysis_id,
                [FindingObservation(**values)], actor_id="analyzer", seen_at=seen_at,
            )[0]

        def generate(self, **kwargs):
            kwargs.setdefault("now", NOW)
            return generate_release_report(
                organization_id=ORG, product_id=PRODUCT, release_id=RELEASE,
                findings=self.findings, documents=self.documents,
                storage=self.storage, actor_id="operator", **kwargs,
            )

    return Scope()


def test_the_first_report_creates_a_document_and_stores_the_bytes(scope):
    scope.ingest()
    result = scope.generate()

    assert result.created is True
    assert result.revision == 1
    stored = scope.storage.objects[result.storage_locator]
    assert stored == result.report.content
    assert json.loads(stored)["summary"]["total"] == 1


def test_the_stored_bytes_are_what_the_revision_describes(scope):
    """The row has to describe the object, or a download verifies nothing."""
    scope.ingest()
    result = scope.generate()

    revision = scope.documents.get_revision(ORG, result.document_id, result.revision)
    stored = scope.storage.objects[revision.storage_locator]
    assert revision.content_hash == result.report.content_hash
    assert revision.size_bytes == len(stored)
    assert revision.format == "json"
    # and the store verifies the digest on the way back out
    assert scope.storage.get(revision.storage_locator, revision.content_hash) == stored


def test_regenerating_an_unchanged_release_adds_no_revision(scope):
    scope.ingest()
    first = scope.generate()
    again = scope.generate()

    assert again.created is False
    assert again.revision == first.revision == 1
    assert again.document_id == first.document_id
    detail = scope.documents.get_document(ORG, first.document_id)
    assert len(detail.revisions) == 1


def test_regenerating_at_a_later_time_reuses_the_same_report(scope):
    scope.ingest()
    first = scope.generate()
    later = scope.generate(now=NOW + timedelta(hours=2))
    assert later.document_id == first.document_id
    assert later.revision == 1
    assert later.report.content_hash == first.report.content_hash


def test_a_changed_finding_produces_a_second_revision(scope):
    scope.ingest()
    first = scope.generate()
    scope.ingest(analysis_id="analysis-2", cvss=9.8, seen_at=NOW + timedelta(hours=1))
    second = scope.generate()

    assert second.created is True
    assert second.revision == 2
    assert second.document_id == first.document_id
    assert second.report.content_hash != first.report.content_hash
    detail = scope.documents.get_document(ORG, first.document_id)
    assert detail.document.current_revision == 2


def test_both_revisions_stay_retrievable(scope):
    """A superseded report is still the report that was reviewed at the time."""
    scope.ingest()
    first = scope.generate()
    scope.ingest(analysis_id="analysis-2", cvss=9.8, seen_at=NOW + timedelta(hours=1))
    second = scope.generate()

    assert first.storage_locator != second.storage_locator
    assert scope.storage.objects[first.storage_locator] == first.report.content
    assert scope.storage.objects[second.storage_locator] == second.report.content


def test_a_release_with_no_findings_still_produces_a_report(scope):
    result = scope.generate()
    assert result.created is True
    body = json.loads(result.report.content)
    assert body["summary"]["total"] == 0
    assert body["findings"] == []


def test_the_report_covers_the_release_not_the_worklist(scope):
    """A decided finding leaves the worklist. It must not leave the report."""
    created = scope.ingest()
    scope.findings.decide(
        ORG, PRODUCT, RELEASE, created.id, decision="not_affected",
        rationale="Component not built in", expected_version=created.version,
        actor_id="reviewer",
    )

    # the default listing is a worklist, and no longer shows it
    worklist = scope.findings.list(ORG, product_id=PRODUCT, release_id=RELEASE)
    assert worklist == []

    body = json.loads(scope.generate().report.content)
    assert body["summary"]["total"] == 1
    assert body["findings"][0]["decision"] == "not_affected"
    assert body["findings"][0]["status"] == "resolved"


def test_missing_monitoring_is_reported_rather_than_raised(scope):
    class Absent:
        def get(self, *args):
            raise LookupError("no monitoring configured")

    body = json.loads(scope.generate(monitoring=Absent()).report.content)
    assert body["coverage"]["monitored"] is False


def test_provenance_records_how_the_report_was_made(scope):
    scope.ingest()
    result = scope.generate()
    revision = scope.documents.get_revision(ORG, result.document_id, result.revision)
    assert revision.provenance["generator"] == "release_report"
    assert revision.provenance["finding_count"] == 1
    assert revision.provenance["generated_at"] == "2026-09-16T09:00:00+00:00"


def test_the_document_is_found_again_rather_than_duplicated(scope):
    scope.ingest()
    first = scope.generate()
    scope.ingest(analysis_id="analysis-2", cvss=9.8, seen_at=NOW + timedelta(hours=1))
    scope.generate()

    reports = [
        item for item in scope.documents.list_documents(ORG, product_id=PRODUCT, release_id=RELEASE)
        if item.name == REPORT_NAME
    ]
    assert len(reports) == 1
    assert reports[0].id == first.document_id
