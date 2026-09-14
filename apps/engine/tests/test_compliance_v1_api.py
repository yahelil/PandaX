from __future__ import annotations

from datetime import date, datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pandax.compliance import ComplianceRepository
from pandax.compliance_v1_api import create_compliance_v1_router
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.portfolio_api import PortfolioIdentity


@pytest.fixture()
def repository(tmp_path):
    engine = create_portfolio_engine(f"sqlite+pysqlite:///{tmp_path / 'compliance-api.sqlite3'}")
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    portfolio.create_organization(
        organization_id="org-acme", name="Acme", legal_name="Acme GmbH",
        country="DE", registration_number="HRB-1", actor_id="admin",
    )
    portfolio.create_product(
        "org-acme", product_id="product-camera", name="Smart Camera",
        identifier="CAM-200", manufacturer="Acme", cra_class="important_i",
        support_start=date(2026, 1, 1), support_end=date(2031, 1, 1), actor_id="admin",
    )
    result = ComplianceRepository(
        engine,
        clock=lambda: datetime(2026, 9, 14, 10, 0, tzinfo=timezone.utc),
    )
    result.create_schema()
    result.create_item(
        "org-acme", item_id="item-report", product_id="product-camera",
        kind="reporting_case", title="72-hour notification",
        description="Prepared notification awaiting approval.", priority="critical",
        status="pending_approval", due_at=datetime(2026, 9, 16, tzinfo=timezone.utc),
        source_type="case_store", source_id="case-1", reporting_stage="notification",
        actor_id="projector",
    )
    result.create_item(
        "org-acme", item_id="item-done", product_id="product-camera",
        kind="missing_document", title="Declaration supplied",
        description="Declaration verified.", priority="low", status="resolved",
        source_type="document_service", source_id="document-1", actor_id="operator",
    )
    return result


def make_client(repository, *, organization_id="org-acme", roles=None):
    app = FastAPI()
    app.include_router(create_compliance_v1_router(
        lambda: repository,
        lambda: PortfolioIdentity(
            actor_id="user-1",
            organization_id=organization_id,
            roles=frozenset(roles or {"compliance_operator"}),
        ),
    ))
    return TestClient(app)


BASE = "/v1/organizations/org-acme/compliance"


def test_default_action_view_filters_and_detail_are_typed(repository):
    client = make_client(repository, roles={"viewer"})

    action = client.get(BASE)
    all_items = client.get(BASE, params={"view": "all", "product_id": "product-camera"})
    detail = client.get(BASE + "/item-report")

    assert action.status_code == all_items.status_code == detail.status_code == 200
    assert [item["id"] for item in action.json()] == ["item-report"]
    assert {item["id"] for item in all_items.json()} == {"item-report", "item-done"}
    assert detail.json()["readiness"] == "review_required"
    assert detail.json()["reporting_stage"] == "notification"


def test_approver_records_exact_version_and_audit_history(repository):
    client = make_client(repository, roles={"authorized_approver"})

    approved = client.post(BASE + "/item-report/approve", json={
        "expected_version": 0,
        "self_filing_record_id": "snapshot-1",
        "self_filing_record_url": "/v1/cases/case-1/snapshots/snapshot-1",
    })
    stale = client.post(BASE + "/item-report/approve", json={"expected_version": 0})
    audit = client.get(BASE + "/item-report/audit")

    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    assert approved.json()["approved_by"] == "user-1"
    assert stale.status_code == 409
    assert [event["action"] for event in audit.json()] == [
        "compliance.created", "compliance.approved",
    ]
    assert audit.json()[-1]["item_version"] == 1


def test_roles_and_organization_scope_fail_closed(repository):
    viewer = make_client(repository, roles={"viewer"})
    hidden = make_client(repository, organization_id="org-other", roles={"org_admin"})

    assert viewer.patch(BASE + "/item-report", json={
        "expected_version": 0, "owner_id": "owner-2",
    }).status_code == 403
    assert viewer.post(BASE + "/item-report/approve", json={
        "expected_version": 0,
    }).status_code == 403
    assert hidden.get(BASE).status_code == 404
    assert hidden.get(BASE + "/item-report").status_code == 404


def test_operator_can_update_but_cannot_approve(repository):
    client = make_client(repository, roles={"compliance_operator"})

    updated = client.patch(BASE + "/item-report", json={
        "expected_version": 0,
        "status": "in_progress",
        "owner_id": "security-lead",
    })
    denied = client.post(BASE + "/item-report/approve", json={"expected_version": 1})

    assert updated.status_code == 200, updated.text
    assert updated.json()["owner_id"] == "security-lead"
    assert updated.json()["version"] == 1
    assert denied.status_code == 403


def test_query_and_body_validation_are_explicit(repository):
    client = make_client(repository)

    assert client.get(BASE, params={"sort": "unknown"}).status_code == 422
    assert client.patch(BASE + "/item-report", json={"expected_version": 0}).status_code == 422
    assert client.patch(BASE + "/item-report", json={
        "expected_version": 0,
        "due_at": "2026-09-17T00:00:00Z",
        "clear_due_at": True,
    }).status_code == 422
