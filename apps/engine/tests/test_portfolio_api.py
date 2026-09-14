from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool

from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.portfolio_api import PortfolioIdentity, create_portfolio_router


@pytest.fixture
def repository() -> Iterator[PortfolioRepository]:
    engine = create_portfolio_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    repository = PortfolioRepository(engine)
    repository.create_schema()
    yield repository
    engine.dispose()


@pytest.fixture
def client(repository: PortfolioRepository) -> TestClient:
    app = FastAPI()
    app.include_router(
        create_portfolio_router(
            lambda: repository,
            lambda: PortfolioIdentity(actor_id="member-compliance-lead"),
        )
    )
    return TestClient(app)


def organization_payload(**overrides):
    return {
        "name": "Acme Devices",
        "legal_name": "Acme Devices GmbH",
        "country": "DE",
        "registration_number": "HRB 128991",
        "timezone": "Europe/Berlin",
        **overrides,
    }


def product_payload(**overrides):
    return {
        "name": "Home Hub",
        "identifier": "ACM-HUB-110",
        "manufacturer": "Acme Devices GmbH",
        "description": "Residential gateway coordinating local sensors and cloud services.",
        "cra_class": "critical",
        "classification_status": "confirmed",
        "support_start": "2026-01-15",
        "support_end": "2030-12-31",
        "owner_id": "member-product-security",
        **overrides,
    }


def release_payload(**overrides):
    return {
        "version": "1.8.0",
        "channel": "stable",
        "status": "active",
        "release_date": "2026-09-02",
        "support_start": "2026-09-02",
        "support_end": "2030-12-31",
        "owner_id": "member-product-security",
        **overrides,
    }


def create_organization(client: TestClient, **overrides) -> dict:
    response = client.post("/v1/organizations", json=organization_payload(**overrides))
    assert response.status_code == 201, response.text
    return response.json()


def create_product(client: TestClient, organization_id: str, **overrides) -> dict:
    response = client.post(
        f"/v1/organizations/{organization_id}/products",
        json=product_payload(**overrides),
    )
    assert response.status_code == 201, response.text
    return response.json()


def create_release(client: TestClient, organization_id: str, product_id: str, **overrides) -> dict:
    response = client.post(
        f"/v1/organizations/{organization_id}/products/{product_id}/releases",
        json=release_payload(**overrides),
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_organization_create_list_detail_and_update(client: TestClient, repository: PortfolioRepository):
    organization = create_organization(client, country="de")

    assert organization["country"] == "DE"
    assert client.get("/v1/organizations").json() == [organization]
    assert client.get(f"/v1/organizations/{organization['id']}").json() == organization

    updated = client.patch(
        f"/v1/organizations/{organization['id']}",
        json={"name": "Acme Connected Products"},
    )

    assert updated.status_code == 200
    assert updated.json()["name"] == "Acme Connected Products"
    events = repository.list_audit_events(
        organization["id"], entity_type="organization", entity_id=organization["id"]
    )
    assert [event.action for event in events] == ["organization.created", "organization.updated"]
    assert all(event.actor_id == "member-compliance-lead" for event in events)


def test_product_contract_supports_portfolio_fields_and_updates(client: TestClient):
    organization = create_organization(client)
    product = create_product(client, organization["id"])

    assert product | {
        "readiness": "incomplete_evidence",
        "monitoring_health": "inactive",
        "action_count": 0,
        "next_deadline": None,
        "tags": [],
    } == product
    assert product["slug"] == "home-hub"
    assert client.get(
        f"/v1/organizations/{organization['id']}/products"
    ).json() == [product]

    response = client.patch(
        f"/v1/organizations/{organization['id']}/products/{product['id']}",
        json={
            "readiness": "needs_attention",
            "monitoring_health": "healthy",
            "owner_id": "member-compliance-lead",
        },
    )

    assert response.status_code == 200
    assert response.json()["readiness"] == "needs_attention"
    assert response.json()["monitoring_health"] == "healthy"
    assert response.json()["owner_id"] == "member-compliance-lead"


def test_product_identifier_conflict_maps_to_409(client: TestClient):
    organization = create_organization(client)
    create_product(client, organization["id"])

    response = client.post(
        f"/v1/organizations/{organization['id']}/products",
        json=product_payload(name="Duplicate Hub"),
    )

    assert response.status_code == 409
    assert "already exists" in response.json()["detail"]


def test_product_lookup_is_scoped_to_organization(client: TestClient):
    first = create_organization(client)
    second = create_organization(
        client,
        name="Other Manufacturer",
        legal_name="Other Manufacturer B.V.",
        country="NL",
        registration_number="NL-99813",
    )
    product = create_product(client, first["id"])

    response = client.get(f"/v1/organizations/{second['id']}/products/{product['id']}")

    assert response.status_code == 404
    assert response.json()["detail"] == "product not found"


def test_release_create_list_detail_update_and_activate(client: TestClient):
    organization = create_organization(client)
    product = create_product(client, organization["id"])
    release = create_release(client, organization["id"], product["id"])
    release_url = (
        f"/v1/organizations/{organization['id']}/products/{product['id']}"
        f"/releases/{release['id']}"
    )

    assert release["sbom_status"] == "missing"
    assert release["coverage"]["components"] == 0
    assert client.get(release_url).json() == release
    assert client.get(release_url.rsplit("/", 1)[0]).json() == [release]

    updated = client.patch(
        release_url,
        json={"status": "supported", "sbom_status": "validated", "monitoring_health": "healthy"},
    )
    activated = client.patch(
        f"/v1/organizations/{organization['id']}/products/{product['id']}",
        json={"active_release_id": release["id"]},
    )

    assert updated.status_code == 200
    assert updated.json()["sbom_status"] == "validated"
    assert activated.status_code == 200
    assert activated.json()["active_release_id"] == release["id"]


def test_release_detail_rejects_product_scope_mismatch(client: TestClient):
    organization = create_organization(client)
    product = create_product(client, organization["id"])
    other = create_product(
        client,
        organization["id"],
        name="Smart Lock",
        identifier="ACM-LOCK-140",
    )
    release = create_release(client, organization["id"], product["id"])

    response = client.get(
        f"/v1/organizations/{organization['id']}/products/{other['id']}/releases/{release['id']}"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "release not found"


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("products", product_payload(cra_class="unclassified")),
        ("products", product_payload(support_start="2031-01-01", support_end="2030-01-01")),
    ],
)
def test_product_request_validation_returns_422(client: TestClient, path: str, payload: dict):
    organization = create_organization(client)

    response = client.post(f"/v1/organizations/{organization['id']}/{path}", json=payload)

    assert response.status_code == 422


def test_release_request_and_repository_validation_return_422(client: TestClient):
    organization = create_organization(client)
    product = create_product(client, organization["id"])
    collection = f"/v1/organizations/{organization['id']}/products/{product['id']}/releases"

    invalid_status = client.post(collection, json=release_payload(status="withdrawn"))
    invalid_period = client.post(
        collection,
        json=release_payload(support_start="2031-01-01", support_end="2030-01-01"),
    )

    assert invalid_status.status_code == 422
    assert invalid_period.status_code == 422


def test_missing_parent_collections_return_404(client: TestClient):
    assert client.get("/v1/organizations/missing/products").status_code == 404
    assert client.get(
        "/v1/organizations/missing/products/missing/releases"
    ).status_code == 404

