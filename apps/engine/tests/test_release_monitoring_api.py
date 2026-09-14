from __future__ import annotations

from datetime import date

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.portfolio_api import PortfolioIdentity
from pandax.release_monitoring import MonitoringObservation, ReleaseMonitoringRepository
from pandax.release_monitoring_api import create_release_monitoring_router


@pytest.fixture
def repository(tmp_path) -> ReleaseMonitoringRepository:
    engine = create_portfolio_engine(f"sqlite:///{tmp_path / 'api-monitoring.db'}")
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    portfolio.create_organization(
        organization_id="org-acme", name="Acme", legal_name="Acme B.V.",
        country="NL", registration_number="NL-1", actor_id="admin",
    )
    portfolio.create_product(
        "org-acme", product_id="product-camera", name="Smart Camera",
        identifier="CAM-100", manufacturer="Acme", cra_class="important_i",
        support_start=date(2026, 1, 1), support_end=date(2031, 1, 1), actor_id="admin",
    )
    portfolio.create_release(
        "org-acme", "product-camera", release_id="release-21", version="2.1",
        channel="stable", release_date=date(2026, 9, 1),
        support_start=date(2026, 9, 1), support_end=date(2031, 1, 1), actor_id="admin",
    )
    result = ReleaseMonitoringRepository(engine)
    result.create_schema()
    return result


def make_client(repository, *, organization_id="org-acme", roles=None, runner=None):
    app = FastAPI()
    app.include_router(
        create_release_monitoring_router(
            lambda: repository,
            runner or (lambda claim: MonitoringObservation(
                {"status": "complete", "sources_checked": len(claim.enabled_sources)}
            )),
            lambda: PortfolioIdentity(
                actor_id="user-1",
                organization_id=organization_id,
                roles=frozenset(roles or {"security_reviewer"}),
            ),
        )
    )
    return TestClient(app)


BASE = "/v1/organizations/org-acme/products/product-camera/releases/release-21/monitoring"
CONFIG = {
    "enabled_sources": ["osv", "cisa_kev", "epss"],
    "cadence_minutes": 60,
    "enabled": True,
}


def test_config_status_manual_run_and_event_history(repository):
    client = make_client(repository)

    configured = client.put(BASE, json=CONFIG)
    status = client.get(BASE)
    completed = client.post(BASE + "/runs")
    events = client.get(BASE + "/runs")

    assert configured.status_code == status.status_code == 200, configured.text
    assert configured.json()["health"] == "degraded"
    assert status.json()["enabled_sources"] == CONFIG["enabled_sources"]
    assert completed.status_code == 201
    assert completed.json()["health"] == "healthy"
    assert completed.json()["coverage"] == {"status": "complete", "sources_checked": 3}
    assert [item["event_type"] for item in events.json()] == ["started", "succeeded"]
    assert all(item["actor_id"] == "user-1" for item in events.json())


def test_missing_config_and_scope_mismatch_are_hidden(repository):
    client = make_client(repository)

    assert client.get(BASE).status_code == 404
    hidden = make_client(repository, organization_id="org-other")
    assert hidden.put(BASE, json=CONFIG).status_code == 404


def test_viewer_can_read_but_cannot_configure_or_run(repository):
    editor = make_client(repository)
    assert editor.put(BASE, json=CONFIG).status_code == 200
    viewer = make_client(repository, roles={"viewer"})

    assert viewer.get(BASE).status_code == 200
    assert viewer.get(BASE + "/runs").status_code == 200
    assert viewer.put(BASE, json=CONFIG).status_code == 403
    assert viewer.post(BASE + "/runs").status_code == 403


def test_validation_and_repository_conflicts_map_to_http(repository):
    client = make_client(repository)

    invalid = client.put(BASE, json={**CONFIG, "cadence_minutes": 1})
    assert invalid.status_code == 422

    assert client.put(BASE, json={**CONFIG, "enabled": False}).status_code == 200
    inactive = client.post(BASE + "/runs")
    assert inactive.status_code == 409
    assert inactive.json()["detail"] == "release monitoring is inactive"


def test_runner_failure_returns_persisted_failed_state(repository):
    def fail(claim):
        raise RuntimeError("vendor advisory feed unavailable")

    client = make_client(repository, runner=fail)
    assert client.put(BASE, json=CONFIG).status_code == 200

    response = client.post(BASE + "/runs")

    assert response.status_code == 201
    assert response.json()["health"] == "failed"
    assert response.json()["coverage"] == {}
    assert "vendor advisory feed unavailable" in response.json()["limitations"][0]
    assert [item["event_type"] for item in client.get(BASE + "/runs").json()] == [
        "started", "failed"
    ]
