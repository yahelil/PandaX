from datetime import date

from fastapi.testclient import TestClient

from pandax import server
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.portfolio_runtime import get_portfolio_repository


def test_server_exposes_portfolio_router_with_replaceable_repository(tmp_path):
    repository = PortfolioRepository(
        create_portfolio_engine(f"sqlite+pysqlite:///{(tmp_path / 'portfolio.sqlite3').as_posix()}")
    )
    repository.create_schema()
    server.api.dependency_overrides[get_portfolio_repository] = lambda: repository

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
    finally:
        server.api.dependency_overrides.pop(get_portfolio_repository, None)
