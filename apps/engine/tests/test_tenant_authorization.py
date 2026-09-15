from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials

from pandax.auth import AuthenticatedIdentity, Role
from pandax.organization_settings import OrganizationSettingsRepository
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax import portfolio_runtime


NOW = datetime(2026, 9, 15, 9, 0, tzinfo=timezone.utc)


class IdentityProvider:
    def __init__(self, subject: str, organization_hint: str):
        self.identity = AuthenticatedIdentity(
            subject=subject,
            organization_hint=organization_hint,
            session_id=f"session-{subject}",
            reauthenticated_at=NOW,
            issued_at=NOW,
        )

    async def __call__(self, _credentials):
        return self.identity


def _request(organization_id: str, *, header_organization: str | None = None) -> Request:
    headers = []
    if header_organization:
        headers.append((b"x-organization-id", header_organization.encode()))
    return Request({
        "type": "http",
        "method": "GET",
        "path": f"/v1/organizations/{organization_id}/products",
        "headers": headers,
        "path_params": {"organization_id": organization_id},
    })


@pytest.fixture
def memberships():
    engine = create_portfolio_engine("sqlite+pysqlite:///:memory:")
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    for organization_id in ("org-a", "org-b"):
        portfolio.create_organization(
            name=organization_id,
            legal_name=f"{organization_id} Ltd",
            country="DE",
            registration_number=organization_id,
            actor_id="bootstrap",
            organization_id=organization_id,
        )
    repository = OrganizationSettingsRepository(engine)
    repository.create_member(
        "org-a", subject="active-a", name="Active A", email="active-a@test.dev",
        title="Admin", initials="AA", roles=["org_admin"], status="active",
        actor_id="bootstrap",
    )
    repository.create_member(
        "org-b", subject="active-b", name="Active B", email="active-b@test.dev",
        title="Viewer", initials="AB", roles=["viewer"], status="active",
        actor_id="bootstrap",
    )
    for status in ("invited", "disabled", "revoked", "removed"):
        repository.create_member(
            "org-a", subject=status, name=status, email=f"{status}@test.dev",
            title="Viewer", initials="X", roles=["viewer"], status=status,
            actor_id="bootstrap",
        )
    repository.create_member(
        "org-a", subject="expired", name="Expired", email="expired@test.dev",
        title="Viewer", initials="EX", roles=["viewer"], status="active",
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        actor_id="bootstrap",
    )
    return repository


def _resolve(monkeypatch, memberships, subject: str, organization_id: str):
    monkeypatch.setattr(
        portfolio_runtime,
        "get_oidc_authenticator",
        lambda: IdentityProvider(subject, organization_id),
    )
    monkeypatch.setattr(
        portfolio_runtime,
        "get_organization_settings_repository",
        lambda: memberships,
    )
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="signed")
    return asyncio.run(
        portfolio_runtime.get_authenticated_principal(
            _request(organization_id), credentials
        )
    )


def test_two_organization_membership_and_role_matrix(monkeypatch, memberships):
    principal_a = _resolve(monkeypatch, memberships, "active-a", "org-a")
    principal_b = _resolve(monkeypatch, memberships, "active-b", "org-b")
    assert principal_a.roles == frozenset({Role.ORG_ADMIN})
    assert principal_b.roles == frozenset({Role.VIEWER})

    for subject, organization_id in (("active-a", "org-b"), ("active-b", "org-a")):
        with pytest.raises(HTTPException) as raised:
            _resolve(monkeypatch, memberships, subject, organization_id)
        assert raised.value.status_code == 404


def test_path_and_header_tenant_mismatch_is_hidden(monkeypatch, memberships):
    monkeypatch.setattr(
        portfolio_runtime,
        "get_oidc_authenticator",
        lambda: IdentityProvider("active-a", "org-a"),
    )
    monkeypatch.setattr(
        portfolio_runtime,
        "get_organization_settings_repository",
        lambda: memberships,
    )
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="signed")
    with pytest.raises(HTTPException) as raised:
        asyncio.run(
            portfolio_runtime.get_authenticated_principal(
                _request("org-a", header_organization="org-b"), credentials
            )
        )
    assert raised.value.status_code == 404


@pytest.mark.parametrize(
    "subject", ["invited", "disabled", "revoked", "removed", "expired"]
)
def test_inactive_memberships_cannot_establish_authority(
    monkeypatch, memberships, subject
):
    with pytest.raises(HTTPException) as raised:
        _resolve(monkeypatch, memberships, subject, "org-a")
    assert raised.value.status_code == 404
