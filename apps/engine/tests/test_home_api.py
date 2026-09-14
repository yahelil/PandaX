from __future__ import annotations

from datetime import date, datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pandax.compliance import ComplianceRepository
from pandax.home import HomeReadModel
from pandax.home_api import create_home_router
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.portfolio_api import PortfolioIdentity


NOW = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)
BASE = "/v1/organizations/org-acme/home"


@pytest.fixture()
def read_model(tmp_path):
    engine = create_portfolio_engine(f"sqlite+pysqlite:///{tmp_path / 'home-api.sqlite3'}")
    portfolio = PortfolioRepository(engine)
    compliance = ComplianceRepository(engine, clock=lambda: NOW)
    portfolio.create_schema()
    compliance.create_schema()
    portfolio.create_organization(
        organization_id="org-acme", name="Acme", legal_name="Acme GmbH",
        country="DE", registration_number="HRB-1", actor_id="admin",
    )
    portfolio.create_product(
        "org-acme", product_id="product-camera", name="Smart Camera",
        identifier="CAM-200", manufacturer="Acme", cra_class="important_i",
        support_start=date(2026, 1, 1), support_end=date(2031, 1, 1), actor_id="admin",
    )
    compliance.create_item(
        "org-acme", item_id="evidence-gap", product_id="product-camera",
        kind="missing_evidence", title="Add signed test evidence",
        description="Verification record is incomplete.", priority="high",
        source_type="evidence_service", source_id="gap-1", actor_id="projector",
    )
    return HomeReadModel(engine, clock=lambda: NOW)


def make_client(read_model, *, organization_id="org-acme", roles=None):
    app = FastAPI()
    app.include_router(create_home_router(
        lambda: read_model,
        lambda: PortfolioIdentity(
            actor_id="user-1", organization_id=organization_id,
            roles=frozenset({"viewer"} if roles is None else roles),
        ),
    ))
    return TestClient(app)


def test_home_endpoint_returns_typed_bounded_snapshot(read_model):
    response = make_client(read_model).get(BASE, params={"queue_limit": 1, "recent_limit": 2})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["organization_id"] == "org-acme"
    assert body["generated_at"] == "2026-09-14T12:00:00Z"
    assert body["monitoring"]["state"] == "not_configured"
    assert body["counters"]["missing_evidence"] == 1
    assert len(body["action_queue"]) == 1
    assert len(body["recent_changes"]) <= 2
    assert body["action_queue"][0]["target_url"].startswith("/compliance?")


def test_home_endpoint_hides_cross_tenant_and_missing_organizations(read_model):
    wrong_tenant = make_client(read_model, organization_id="org-other")
    missing = make_client(read_model, organization_id="org-missing")

    assert wrong_tenant.get(BASE).status_code == 404
    assert missing.get("/v1/organizations/org-missing/home").status_code == 404


def test_home_endpoint_requires_known_role_and_valid_limits(read_model):
    denied = make_client(read_model, roles=set())
    client = make_client(read_model)

    assert denied.get(BASE).status_code == 403
    assert client.get(BASE, params={"queue_limit": 0}).status_code == 422
    assert client.get(BASE, params={"recent_limit": 51}).status_code == 422
