from datetime import date

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool

from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.portfolio_api import PortfolioIdentity, create_portfolio_router


def test_viewer_is_tenant_scoped_and_cannot_mutate():
    engine = create_portfolio_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    repository = PortfolioRepository(engine)
    repository.create_schema()
    first = repository.create_organization(
        name="Acme",
        legal_name="Acme Devices GmbH",
        country="DE",
        registration_number="HRB 128991",
        actor_id="bootstrap",
    )
    second = repository.create_organization(
        name="Other",
        legal_name="Other Devices Ltd.",
        country="GB",
        registration_number="12345678",
        actor_id="bootstrap",
    )
    app = FastAPI()
    app.include_router(create_portfolio_router(
        lambda: repository,
        lambda: PortfolioIdentity(
            actor_id="viewer-1",
            organization_id=first.id,
            roles=frozenset({"viewer"}),
        ),
    ))
    client = TestClient(app)

    organizations = client.get("/v1/organizations")
    assert organizations.status_code == 200
    assert [item["id"] for item in organizations.json()] == [first.id]
    assert client.get(f"/v1/organizations/{second.id}").status_code == 404

    mutation = client.post(
        f"/v1/organizations/{first.id}/products",
        json={
            "name": "Camera",
            "identifier": "camera-1",
            "manufacturer": "Acme Devices GmbH",
            "cra_class": "default",
            "support_start": date(2026, 9, 14).isoformat(),
            "support_end": date(2031, 9, 14).isoformat(),
        },
    )
    assert mutation.status_code == 403

    engine.dispose()
