from __future__ import annotations

from datetime import date

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool

from pandax.auth import Principal, Role
from pandax.organization_settings import OrganizationSettingsRepository
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.settings_api import create_settings_router


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
    repository = OrganizationSettingsRepository(engine)
    repository.create_member(
        "org-acme", subject="oidc|jane", name="Jane Doe", email="jane@acme.test",
        title="Security Lead", initials="JD", roles=["compliance_operator"],
        actor_id="seed", member_id="member-jane",
    )
    repository.create_integration(
        "org-acme", name="Collector", type="collector", description="Signed evidence collection",
        configuration={"collector_id": "edge-eu-1", "environment": "production"},
        secret_reference="vault://actis/acme/collector", actor_id="seed", integration_id="integration-collector",
    )
    identity = {"value": Principal("admin", "org-acme", frozenset({Role.ORG_ADMIN}))}
    app = FastAPI()
    app.include_router(create_settings_router(lambda: repository, lambda: identity["value"]))
    return TestClient(app), identity


def test_settings_get_patch_rbac_and_optimistic_version(api):
    client, identity = api
    initial = client.get("/v1/organizations/org-acme/settings")
    assert initial.status_code == 200 and initial.json()["version"] == 0
    updated = client.patch("/v1/organizations/org-acme/settings", json={
        "expected_version": 0,
        "organization_profile": {"timezone": "Europe/Berlin"},
        "notifications": {"email_digest": "weekly"},
        "security": {"session_timeout_minutes": 240},
        "appearance": {"theme": "dark"},
        "analytics": {"retention_days": 30},
    })
    assert updated.status_code == 200
    assert updated.json()["organization_profile"]["timezone"] == "Europe/Berlin"
    assert updated.json()["analytics"] == {"enabled": True, "retention_days": 30}
    assert client.patch("/v1/organizations/org-acme/settings", json={"expected_version": 0, "appearance": {"theme": "light"}}).status_code == 409

    identity["value"] = Principal("viewer", "org-acme", frozenset({Role.VIEWER}))
    assert client.get("/v1/organizations/org-acme/settings").status_code == 200
    assert client.patch("/v1/organizations/org-acme/settings", json={"expected_version": 1, "appearance": {"theme": "light"}}).status_code == 403


def test_team_and_integration_get_patch_tenant_and_secret_validation(api):
    client, identity = api
    assert client.get("/v1/organizations/org-acme/team").json()[0]["email"] == "jane@acme.test"
    member = client.patch("/v1/organizations/org-acme/team/member-jane", json={
        "expected_version": 1, "roles": ["authorized_approver"], "status": "active",
    })
    assert member.status_code == 200 and member.json()["roles"] == ["authorized_approver"]
    integration = client.patch("/v1/organizations/org-acme/integrations/integration-collector", json={
        "expected_version": 1, "status": "connected",
        "secret_reference": "azure-keyvault://actis/acme/collector",
    })
    assert integration.status_code == 200 and integration.json()["status"] == "connected"
    plaintext = client.patch("/v1/organizations/org-acme/integrations/integration-collector", json={
        "expected_version": 2, "secret_reference": "plaintext-secret",
    })
    assert plaintext.status_code == 422

    identity["value"] = Principal("admin", "org-other", frozenset({Role.ORG_ADMIN}))
    assert client.get("/v1/organizations/org-acme/team").status_code == 403


def test_analytics_ingest_privacy_aggregate_permissions_and_opt_out(api):
    client, identity = api
    identity["value"] = Principal("viewer", "org-acme", frozenset({Role.VIEWER}))
    accepted = client.post("/v1/organizations/org-acme/analytics/events", json={"events": [
        {"event_name": "page_viewed", "properties": {"area": "home"}, "occurred_at": "2026-09-14T09:00:00Z"},
        {"event_name": "feature_used", "properties": {"feature": "search"}, "occurred_at": "2026-09-14T09:01:00Z"},
    ]})
    assert accepted.status_code == 202 and accepted.json() == {"accepted": 2, "dropped": 0}
    assert client.get("/v1/organizations/org-acme/analytics/aggregates").status_code == 403

    forbidden_payload = client.post("/v1/organizations/org-acme/analytics/events", json={"events": [
        {"event_name": "page_viewed", "properties": {"area": "home", "email": "jane@acme.test"}, "occurred_at": "2026-09-14T09:00:00Z"},
    ]})
    assert forbidden_payload.status_code == 422
    identity["value"] = Principal("operator", "org-acme", frozenset({Role.COMPLIANCE_OPERATOR}))
    aggregates = client.get("/v1/organizations/org-acme/analytics/aggregates")
    assert aggregates.status_code == 200
    assert aggregates.json() == [{"event_name": "feature_used", "count": 1}, {"event_name": "page_viewed", "count": 1}]
