from datetime import date

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from pandax import server
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.portfolio_api import PORTFOLIO_ROLES, PortfolioIdentity
from pandax.portfolio_runtime import (
    get_authenticated_principal,
    get_portfolio_identity,
    get_portfolio_repository,
)
from pandax.auth import Principal, Role


def test_server_applies_browser_security_headers():
    response = TestClient(server.api).get("/openapi.json")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert response.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_cors_origins_are_explicit_https_or_local_development():
    assert server._allowed_cors_origins(
        "https://dashboard.actis.example, http://localhost:4173,https://dashboard.actis.example/"
    ) == ["https://dashboard.actis.example", "http://localhost:4173"]

    for invalid in ("*", "http://dashboard.actis.example", "https://user@dashboard.actis.example", "https://dashboard.actis.example/path"):
        with pytest.raises(ValueError, match="CORS"):
            server._allowed_cors_origins(invalid)


def test_server_exposes_portfolio_router_with_replaceable_repository(tmp_path):
    repository = PortfolioRepository(
        create_portfolio_engine(f"sqlite+pysqlite:///{(tmp_path / 'portfolio.sqlite3').as_posix()}")
    )
    repository.create_schema()
    server.api.dependency_overrides[get_portfolio_repository] = lambda: repository
    def identity(request: Request) -> PortfolioIdentity:
        return PortfolioIdentity(
            actor_id="test-admin",
            organization_id=request.path_params.get("organization_id"),
            roles=PORTFOLIO_ROLES,
        )

    server.api.dependency_overrides[get_portfolio_identity] = identity
    server.api.dependency_overrides[get_authenticated_principal] = lambda: Principal(
        subject="test-admin",
        organization_id="test-organization",
        roles=frozenset({Role.ORG_ADMIN}),
    )

    try:
        client = TestClient(server.api)
        organization = client.post(
            "/v1/organizations",
            json={
                "name": "PandaX",
                "legal_name": "PandaX Technologies Ltd.",
                "country": "IL",
                "registration_number": "515555555",
                "timezone": "Asia/Jerusalem",
            },
        )
        assert organization.status_code == 201

        product = client.post(
            f"/v1/organizations/{organization.json()['id']}/products",
            json={
                "name": "Smart Camera",
                "identifier": "actis-camera",
                "manufacturer": "PandaX Technologies Ltd.",
                "cra_class": "important_i",
                "support_start": date(2026, 9, 14).isoformat(),
                "support_end": date(2031, 9, 14).isoformat(),
            },
        )

        assert product.status_code == 201
        assert product.json()["name"] == "Smart Camera"
        assert any(
            path.endswith("/analysis-jobs")
            for path in server.api.openapi()["paths"]
        )
        assert any(
            path.endswith("/monitoring")
            for path in server.api.openapi()["paths"]
        )
        assert "/v1/organizations/{organization_id}/findings" in server.api.openapi()["paths"]
        assert "/v1/organizations/{organization_id}/compliance" in server.api.openapi()["paths"]
        assert "/v1/organizations/{organization_id}/documents" in server.api.openapi()["paths"]
        assert "/v1/organizations/{organization_id}/search" in server.api.openapi()["paths"]
        assert "/v1/organizations/{organization_id}/notifications" in server.api.openapi()["paths"]
        assert "/v1/organizations/{organization_id}/home" in server.api.openapi()["paths"]
        assert "/v1/organizations/{organization_id}/settings" in server.api.openapi()["paths"]
        assert "/v1/organizations/{organization_id}/analytics/events" in server.api.openapi()["paths"]
    finally:
        server.api.dependency_overrides.pop(get_portfolio_repository, None)
        server.api.dependency_overrides.pop(get_portfolio_identity, None)
        server.api.dependency_overrides.pop(get_authenticated_principal, None)
