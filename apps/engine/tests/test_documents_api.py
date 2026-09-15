from __future__ import annotations

from datetime import date

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool

from pandax.auth import Principal, Role
from pandax.documents import DocumentRepository
from pandax.documents_api import create_documents_router
from pandax.portfolio import PortfolioRepository, create_portfolio_engine

HASH = "d" * 64


@pytest.fixture
def api():
    engine = create_portfolio_engine(
        "sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    portfolio.create_organization(
        name="Acme", legal_name="Acme GmbH", country="DE",
        registration_number="HRB-1", actor_id="admin", organization_id="org-acme",
    )
    portfolio.create_product(
        "org-acme", name="Gateway", identifier="GTW-1", manufacturer="Acme",
        cra_class="important_i", support_start=date(2026, 1, 1), support_end=date(2031, 1, 1),
        actor_id="admin", product_id="product-gateway",
    )
    portfolio.create_release(
        "org-acme", "product-gateway", version="1.0.0", channel="stable",
        release_date=date(2026, 1, 2), support_start=date(2026, 1, 2), support_end=date(2031, 1, 1),
        actor_id="admin", release_id="release-1",
    )
    repository = DocumentRepository(engine)
    identity = {"value": Principal("operator", "org-acme", frozenset({Role.COMPLIANCE_OPERATOR}))}
    app = FastAPI()
    app.include_router(create_documents_router(lambda: repository, lambda: identity["value"]))
    return TestClient(app), identity


def payload(**overrides):
    result = {
        "product_id": "product-gateway", "release_id": "release-1", "case_id": "case-14",
        "name": "CRA reporting pack", "kind": "cra_reporting_pack", "format": "zip",
        "content_hash": HASH, "storage_locator": "documents/org-acme/report.zip",
        "size_bytes": 1200, "provenance": {"generator": "case_export", "case_revision": 3},
    }
    result.update(overrides)
    return result


def test_document_api_workflow_rbac_and_self_filing_disclaimer(api):
    client, identity = api
    created = client.post("/v1/organizations/org-acme/documents", json=payload())
    assert created.status_code == 201, created.text
    document_id = created.json()["document"]["id"]

    pending = client.post(
        f"/v1/organizations/org-acme/documents/{document_id}/revisions/1/approval-request",
        json={"expected_status": "draft", "comment": "Ready for independent review."},
    )
    assert pending.status_code == 200 and pending.json()["status"] == "pending"

    denied = client.post(
        f"/v1/organizations/org-acme/documents/{document_id}/revisions/1/approve",
        json={"expected_status": "pending"},
    )
    assert denied.status_code == 403
    identity["value"] = Principal("approver", "org-acme", frozenset({Role.AUTHORIZED_APPROVER}))
    approved = client.post(
        f"/v1/organizations/org-acme/documents/{document_id}/revisions/1/approve",
        json={"expected_status": "pending", "comment": "Exact revision and evidence verified."},
    )
    assert approved.status_code == 200 and approved.json()["status"] == "approved"

    identity["value"] = Principal("operator", "org-acme", frozenset({Role.COMPLIANCE_OPERATOR}))
    filing = client.post(
        f"/v1/organizations/org-acme/documents/{document_id}/revisions/1/self-filings",
        json={
            "external_submission_reference": "SRP-2026-1942",
            "submitted_at": "2026-09-14T10:05:00Z",
            "receipt_evidence_locator": "receipts/srp-1942.pdf",
            "receipt_content_hash": "e" * 64,
        },
    )
    assert filing.status_code == 201
    assert filing.json()["record_type"] == "operator_recorded_external_submission"
    assert filing.json()["actis_submitted_externally"] is False

    detail = client.get(f"/v1/organizations/org-acme/documents/{document_id}")
    assert [item["event_type"] for item in detail.json()["approval_history"]] == ["approved", "approval_requested"]


def test_list_filter_sort_detail_revision_and_download_metadata(api):
    client, identity = api
    first = client.post("/v1/organizations/org-acme/documents", json=payload()).json()["document"]
    client.post("/v1/organizations/org-acme/documents", json=payload(
        name="SBOM", kind="sbom", format="cyclonedx_json",
        storage_locator="documents/org-acme/sbom.json",
    ))
    identity["value"] = Principal("auditor", "org-acme", frozenset({Role.VIEWER}))
    listed = client.get("/v1/organizations/org-acme/documents?kind=sbom&status=draft&sort=name_asc")
    assert listed.status_code == 200 and [item["name"] for item in listed.json()] == ["SBOM"]
    revision = client.get(f"/v1/organizations/org-acme/documents/{first['id']}/revisions/1")
    assert revision.status_code == 200 and revision.json()["content_hash"] == HASH
    download = client.get(f"/v1/organizations/org-acme/documents/{first['id']}/revisions/1/download")
    assert download.json()["download_type"] == "storage_metadata_only"
    assert download.json()["storage_locator"] == "documents/org-acme/report.zip"


def test_api_tenant_scope_validation_and_optimistic_conflicts(api):
    client, identity = api
    document_id = client.post("/v1/organizations/org-acme/documents", json=payload()).json()["document"]["id"]
    identity["value"] = Principal("operator", "org-other", frozenset({Role.COMPLIANCE_OPERATOR}))
    assert client.get("/v1/organizations/org-acme/documents").status_code == 404

    identity["value"] = Principal("operator", "org-acme", frozenset({Role.COMPLIANCE_OPERATOR}))
    stale = client.post(
        f"/v1/organizations/org-acme/documents/{document_id}/revisions",
        json={
            "expected_current_revision": 9, "format": "zip", "content_hash": "f" * 64,
            "storage_locator": "documents/org-acme/report-r2.zip", "size_bytes": 1400,
            "provenance": {"generator": "case_export", "case_revision": 4},
        },
    )
    assert stale.status_code == 409
    unsafe = client.post("/v1/organizations/org-acme/documents", json=payload(storage_locator="../secret.zip"))
    assert unsafe.status_code == 422

    missing_reason = client.post(
        f"/v1/organizations/org-acme/documents/{document_id}/revisions/1/reject",
        json={"expected_status": "draft", "reason": ""},
    )
    assert missing_reason.status_code == 422
