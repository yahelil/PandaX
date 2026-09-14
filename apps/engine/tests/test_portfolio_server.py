from datetime import date

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


def test_server_exposes_portfolio_router_with_replaceable_repository(tmp_path):
    repository = PortfolioRepository(
        create_portfolio_engine(f"sqlite+pysqlite:///{(tmp_path / 'portfolio.sqlite3').as_posix()}")
    )
    repository.create_schema()
    server.api.dependency_overrides[get_portfolio_repository] = lambda: repository
    server.api.dependency_overrides[get_portfolio_identity] = lambda: PortfolioIdentity(
        actor_id="test-admin", roles=PORTFOLIO_ROLES
    )
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
    finally:
        server.api.dependency_overrides.pop(get_portfolio_repository, None)
        server.api.dependency_overrides.pop(get_portfolio_identity, None)
        server.api.dependency_overrides.pop(get_authenticated_principal, None)
