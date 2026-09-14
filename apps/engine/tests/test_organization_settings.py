from __future__ import annotations

from datetime import date, datetime, timezone

import pytest
from sqlalchemy import select

from pandax.organization_settings import (
    OrganizationSettingsRepository, SettingsConflict, SettingsNotFound,
    SettingsValidationError, analytics_events,
)
from pandax.portfolio import PortfolioRepository, create_portfolio_engine


@pytest.fixture
def settings_repo():
    engine = create_portfolio_engine("sqlite+pysqlite:///:memory:")
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    portfolio.create_organization(
        name="Acme", legal_name="Acme GmbH", country="DE",
        registration_number="HRB-1", actor_id="admin", organization_id="org-acme",
    )
    return OrganizationSettingsRepository(engine)


def test_settings_profile_policy_version_and_audit(settings_repo):
    initial = settings_repo.get_settings("org-acme")
    assert initial.version == 0
    assert initial.notifications["urgent_findings"] is True
    assert initial.security["evidence_retention_months"] == 120

    updated = settings_repo.update_settings(
        "org-acme", expected_version=0, actor_id="admin",
        patch={
            "organization_profile": {"name": "Acme Cyber Devices", "timezone": "Europe/Berlin"},
            "notifications": {"email_digest": "weekly"},
            "appearance": {"theme": "dark"},
            "analytics": {"retention_days": 30},
        },
    )
    assert updated.version == 1
    assert updated.organization_profile["name"] == "Acme Cyber Devices"
    assert updated.notifications["email_digest"] == "weekly"
    assert updated.appearance["theme"] == "dark"
    assert updated.analytics["retention_days"] == 30
    audit = settings_repo.list_audit("org-acme")
    assert audit[0].action == "settings.updated" and audit[0].version == 1

    with pytest.raises(SettingsConflict):
        settings_repo.update_settings("org-acme", expected_version=0, actor_id="admin", patch={"appearance": {"theme": "light"}})


def test_team_roles_are_typed_tenant_scoped_and_optimistic(settings_repo):
    member = settings_repo.create_member(
        "org-acme", subject="oidc|jane", name="Jane Doe", email="Jane@Acme.test",
        title="Product Security Lead", initials="JD",
        roles=["compliance_operator"], actor_id="admin", member_id="member-jane",
    )
    assert member.email == "jane@acme.test" and member.version == 1
    updated = settings_repo.update_member(
        "org-acme", member.id, expected_version=1,
        changes={"roles": ["authorized_approver", "compliance_operator"], "status": "active"},
        actor_id="admin",
    )
    assert updated.roles == ("authorized_approver", "compliance_operator")
    assert updated.version == 2
    with pytest.raises(SettingsConflict):
        settings_repo.update_member("org-acme", member.id, expected_version=1, changes={"title": "Stale"}, actor_id="admin")
    with pytest.raises(SettingsValidationError):
        settings_repo.update_member("org-acme", member.id, expected_version=2, changes={"roles": ["root"]}, actor_id="admin")
    with pytest.raises(SettingsNotFound):
        settings_repo.get_member("org-other", member.id)


def test_integrations_store_external_secret_references_never_secret_values(settings_repo):
    with pytest.raises(SettingsValidationError):
        settings_repo.create_integration(
            "org-acme", name="Jira", type="jira", description="Action sync",
            configuration={"site": "acme.atlassian.net", "api_token": "plaintext"},
            secret_reference=None, actor_id="admin",
        )
    with pytest.raises(SettingsValidationError):
        settings_repo.create_integration(
            "org-acme", name="Jira", type="jira", description="Action sync",
            configuration={"site": "acme.atlassian.net", "project_key": "SEC"},
            secret_reference="plaintext-token", actor_id="admin",
        )

    integration = settings_repo.create_integration(
        "org-acme", name="Jira", type="jira", description="Action sync",
        configuration={"site": "acme.atlassian.net", "project_key": "SEC"},
        secret_reference="vault://actis/acme/jira", actor_id="admin", integration_id="integration-jira",
    )
    assert integration.secret_reference == "vault://actis/acme/jira"
    updated = settings_repo.update_integration(
        "org-acme", integration.id, expected_version=1,
        changes={"status": "connected", "secret_reference": "aws-secrets://actis/acme/jira"},
        actor_id="admin",
    )
    assert updated.version == 2 and updated.status == "connected"
    audits = [item for item in settings_repo.list_audit("org-acme") if item.entity_type == "integration"]
    assert audits[0].changes["secret_reference"] == "configured"
    assert "aws-secrets" not in str(audits[0].changes)


@pytest.mark.parametrize(
    "event",
    [
        {"event_name": "page_viewed", "properties": {"area": "home", "email": "jane@acme.test"}},
        {"event_name": "page_viewed", "properties": {"area": "CVE-2026-1234"}},
        {"event_name": "feature_used", "properties": {"feature": "package:openssl"}},
        {"event_name": "error_observed", "properties": {"area": "analysis", "error_code": "token=secret"}},
        {"event_name": "sbom_uploaded", "properties": {}},
        {"event_name": "page_viewed", "properties": {"area": "home", "ip": "203.0.113.7"}},
    ],
    ids=["email", "cve-free-text", "package", "token", "sbom-name", "ip"],
)
def test_analytics_rejects_non_allowlisted_or_identifying_payloads(settings_repo, event):
    event["occurred_at"] = datetime(2026, 9, 14, 9, 0, tzinfo=timezone.utc)
    with pytest.raises(SettingsValidationError):
        settings_repo.ingest_analytics("org-acme", [event])
    assert settings_repo.analytics_aggregates("org-acme") == []


def test_analytics_opt_out_retention_and_aggregate_only(settings_repo):
    occurred = datetime(2026, 9, 14, 9, 0, tzinfo=timezone.utc)
    accepted = settings_repo.ingest_analytics("org-acme", [
        {"event_name": "page_viewed", "properties": {"area": "home"}, "occurred_at": occurred},
        {"event_name": "page_viewed", "properties": {"area": "products"}, "occurred_at": occurred},
        {"event_name": "feature_used", "properties": {"feature": "search"}, "occurred_at": occurred},
    ])
    assert accepted == {"accepted": 3, "dropped": 0}
    assert settings_repo.analytics_aggregates("org-acme") == [
        {"event_name": "feature_used", "count": 1},
        {"event_name": "page_viewed", "count": 2},
    ]
    with settings_repo.engine.connect() as connection:
        rows = connection.execute(select(analytics_events)).all()
    assert all((row.expires_at.replace(tzinfo=timezone.utc) - row.ingested_at.replace(tzinfo=timezone.utc)).days == 90 for row in rows)
    disabled = settings_repo.update_settings(
        "org-acme", expected_version=0, patch={"analytics": {"enabled": False}}, actor_id="admin",
    )
    assert disabled.analytics["enabled"] is False
    dropped = settings_repo.ingest_analytics("org-acme", [
        {"event_name": "page_viewed", "properties": {"area": "settings"}, "occurred_at": occurred},
    ])
    assert dropped == {"accepted": 0, "dropped": 1}
