from __future__ import annotations

from datetime import datetime, timezone

import pytest

from pandax.documents import (
    DocumentConflict, DocumentNotFound, DocumentRepository, DocumentValidationError,
)
from pandax.portfolio import PortfolioRepository, create_portfolio_engine

HASH_A = "a" * 64
HASH_B = "b" * 64


@pytest.fixture
def scope():
    engine = create_portfolio_engine("sqlite+pysqlite:///:memory:")
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    org = portfolio.create_organization(
        name="Acme", legal_name="Acme GmbH", country="DE",
        registration_number="HRB-1", actor_id="admin", organization_id="org-acme",
    )
    product = portfolio.create_product(
        org.id, name="Gateway", identifier="GTW-1", manufacturer="Acme",
        cra_class="important_i", support_start=datetime(2026, 1, 1).date(),
        support_end=datetime(2031, 1, 1).date(), actor_id="admin", product_id="product-gateway",
    )
    release = portfolio.create_release(
        org.id, product.id, version="1.0.0", channel="stable",
        release_date=datetime(2026, 1, 2).date(), support_start=datetime(2026, 1, 2).date(),
        support_end=datetime(2031, 1, 1).date(), actor_id="admin", release_id="release-1",
    )
    return DocumentRepository(engine), org, product, release


def create_document(repository, org, product, release, **overrides):
    values = {
        "name": "CRA reporting pack", "kind": "cra_reporting_pack", "format": "zip",
        "content_hash": HASH_A, "storage_locator": "documents/org-acme/report-r1.zip",
        "size_bytes": 8120, "provenance": {"generator": "case_export", "case_revision": 3},
        "actor_id": "operator", "release_id": release.id, "case_id": "case-14",
    }
    values.update(overrides)
    return repository.create_document(org.id, product.id, **values)


def test_revision_and_workflow_history_is_append_only(scope):
    repository, org, product, release = scope
    created = create_document(repository, org, product, release)
    assert created.document.status == "draft"
    assert created.document.current.content_hash == HASH_A

    pending = repository.request_approval(org.id, created.document.id, 1, expected_status="draft", actor_id="operator", comment="Ready for review")
    assert pending.status == "pending"
    with pytest.raises(DocumentConflict):
        repository.approve(org.id, created.document.id, 1, expected_status="draft", actor_id="approver")
    approved = repository.approve(org.id, created.document.id, 1, expected_status="pending", actor_id="approver", comment="Evidence verified")
    assert approved.status == "approved"

    second = repository.add_revision(
        org.id, created.document.id, expected_current_revision=1, format="zip",
        content_hash=HASH_B, storage_locator="documents/org-acme/report-r2.zip",
        size_bytes=9000, provenance={"generator": "case_export", "case_revision": 4}, actor_id="operator",
    )
    detail = repository.get_document(org.id, created.document.id)
    assert second.revision == 2 and second.status == "draft"
    assert detail.document.current_revision == 2
    assert detail.revisions[1].content_hash == HASH_A
    assert detail.revisions[1].status == "superseded"
    assert [event.event_type for event in detail.audit] == [
        "revision_created", "superseded", "approved", "approval_requested", "revision_created",
    ]
    assert detail.approval_history[-1].reason == "Ready for review"
    with pytest.raises(DocumentConflict):
        repository.add_revision(
            org.id, created.document.id, expected_current_revision=1, format="zip",
            content_hash="c" * 64, storage_locator="documents/stale.zip", size_bytes=1,
            provenance={}, actor_id="operator",
        )


def test_rejection_reason_and_approval_history_are_retained(scope):
    repository, org, product, release = scope
    document = create_document(repository, org, product, release).document
    repository.request_approval(org.id, document.id, 1, expected_status="draft", actor_id="operator")
    rejected = repository.reject(
        org.id, document.id, 1, expected_status="pending", actor_id="approver",
        reason="Declaration signature evidence is missing.",
    )
    detail = repository.get_document(org.id, document.id)
    assert rejected.status == "rejected"
    assert [event.event_type for event in detail.approval_history] == ["rejected", "approval_requested"]
    assert detail.approval_history[0].reason == "Declaration signature evidence is missing."


def test_self_filing_records_operator_claim_only_after_approval(scope):
    repository, org, product, release = scope
    document = create_document(repository, org, product, release).document
    submitted_at = datetime(2026, 9, 14, 10, 5, tzinfo=timezone.utc)
    with pytest.raises(DocumentConflict):
        repository.record_self_filing(
            org.id, document.id, 1, external_submission_reference="SRP-2026-1942",
            submitted_at=submitted_at, receipt_evidence_locator="receipts/srp-1942.pdf",
            receipt_content_hash=HASH_B, actor_id="operator",
        )
    repository.request_approval(org.id, document.id, 1, expected_status="draft", actor_id="operator")
    repository.approve(org.id, document.id, 1, expected_status="pending", actor_id="approver")
    record = repository.record_self_filing(
        org.id, document.id, 1, external_submission_reference="SRP-2026-1942",
        submitted_at=submitted_at, receipt_evidence_locator="receipts/srp-1942.pdf",
        receipt_content_hash=HASH_B, actor_id="operator",
    )
    assert record.record_type == "operator_recorded_external_submission"
    assert record.submitted_at == submitted_at
    assert repository.get_document(org.id, document.id).audit[0].event_type == "self_filing_recorded"
    with pytest.raises(DocumentConflict):
        repository.record_self_filing(
            org.id, document.id, 1, external_submission_reference="SRP-2026-1942",
            submitted_at=submitted_at, receipt_evidence_locator="receipts/duplicate.pdf",
            receipt_content_hash=None, actor_id="operator",
        )


@pytest.mark.parametrize("locator", ["../secret.pdf", "/etc/passwd", r"..\secret.pdf", "file://secret", "~/secret"])
def test_storage_locators_cannot_escape_storage_namespace(scope, locator):
    repository, org, product, release = scope
    with pytest.raises(DocumentValidationError):
        create_document(repository, org, product, release, storage_locator=locator)


def test_tenant_scope_filters_sort_and_download_metadata(scope):
    repository, org, product, release = scope
    first = create_document(repository, org, product, release).document
    second = create_document(
        repository, org, product, release, name="Software bill of materials",
        kind="sbom", format="cyclonedx_json", content_hash=HASH_B,
        storage_locator="documents/org-acme/sbom.json",
    ).document
    assert [item.id for item in repository.list_documents(org.id, kind="sbom", sort="name_asc")] == [second.id]
    assert repository.list_documents(org.id, status="draft", release_id=release.id)
    metadata = repository.download_metadata(org.id, second.id, 1)
    assert metadata == {
        "document_id": second.id, "revision": 1,
        "filename": "Software bill of materials-r1.json", "format": "cyclonedx_json",
        "content_hash": HASH_B, "size_bytes": 8120,
        "storage_locator": "documents/org-acme/sbom.json",
        "content_type": "application/json", "download_type": "storage_metadata_only",
    }
    with pytest.raises(DocumentNotFound):
        repository.get_document("org-other", first.id)
