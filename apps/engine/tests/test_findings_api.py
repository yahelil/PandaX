from __future__ import annotations

from datetime import date

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pandax.findings import FindingObservation, FindingRepository
from pandax.findings_api import create_findings_router
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.portfolio_api import PortfolioIdentity

ORG_BASE = "/v1/organizations/org-acme/findings"
BASE = "/v1/organizations/org-acme/products/product-hub/releases/release-14/findings"


@pytest.fixture
def repository(tmp_path) -> FindingRepository:
    engine = create_portfolio_engine(f"sqlite:///{tmp_path / 'finding-api.db'}")
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    portfolio.create_organization(
        organization_id="org-acme", name="Acme", legal_name="Acme B.V.",
        country="NL", registration_number="NL-1", actor_id="admin",
    )
    portfolio.create_product(
        "org-acme", product_id="product-hub", name="Home Hub", identifier="HUB-100",
        manufacturer="Acme", cra_class="important_i", support_start=date(2026, 1, 1),
        support_end=date(2031, 1, 1), actor_id="admin",
    )
    portfolio.create_release(
        "org-acme", "product-hub", release_id="release-14", version="1.4",
        channel="stable", release_date=date(2026, 9, 1), support_start=date(2026, 9, 1),
        support_end=date(2031, 1, 1), actor_id="admin",
    )
    result = FindingRepository(engine)
    result.create_schema()
    result.upsert_from_analysis(
        "org-acme", "product-hub", "release-14", "analysis-1",
        [FindingObservation(
            reference_id="CVE-2021-44228", cve="CVE-2021-44228",
            component="log4j-core", purl="pkg:maven/log4j-core@2.14.1", version="2.14.1",
            title="Remote code execution in Log4j", severity="critical", cvss=10,
            kev=True, epss=.975, reachability="reachable",
            reachability_evidence={"paths": 1}, source="osv",
            provenance={"advisory": "GHSA-jfh8-c2jp-5v3q"},
        )], actor_id="analyzer",
    )
    return result


def client(repository, roles={"security_reviewer"}, organization_id="org-acme") -> TestClient:
    app = FastAPI()
    app.include_router(create_findings_router(
        lambda: repository,
        lambda: PortfolioIdentity(
            actor_id="user-1", organization_id=organization_id, roles=frozenset(roles),
        ),
    ))
    return TestClient(app)


def test_default_action_queue_filters_detail_and_history(repository):
    api = client(repository)

    queue = api.get(ORG_BASE, params={"severity": "critical", "kev": "true", "sort": "severity"})
    finding = queue.json()[0]
    detail = api.get(BASE + f"/{finding['id']}")

    assert queue.status_code == 200
    assert finding["reachability"] == "reachable"
    assert detail.status_code == 200
    assert detail.json()["decision_history"] == []
    assert detail.json()["audit_history"][0]["action"] == "finding.discovered"


def test_assignment_decision_remediation_workflow(repository):
    api = client(repository)
    found = api.get(BASE).json()[0]
    assigned = api.patch(BASE + f"/{found['id']}/assignment", json={
        "assignee_id": "alice", "expected_version": found["version"],
    })
    decided = api.post(BASE + f"/{found['id']}/decisions", json={
        "decision": "affected", "rationale": "Reachable from network input",
        "expected_version": assigned.json()["version"],
    })
    remediated = api.put(BASE + f"/{found['id']}/remediation", json={
        "plan": "Upgrade to fixed version and verify image",
        "status": "verified", "due_date": "2026-09-15",
        "verification_evidence": [{"kind": "test_run", "id": "run-42"}],
        "expected_version": decided.json()["version"],
    })

    assert assigned.status_code == 200
    assert decided.status_code == 201
    assert decided.json()["current_decision"] == "affected"
    assert len(decided.json()["decision_history"]) == 1
    assert remediated.status_code == 200
    assert remediated.json()["status"] == "resolved"
    assert remediated.json()["verification_evidence"][0]["id"] == "run-42"


def test_optimistic_conflict_scope_and_rbac(repository):
    reviewer = client(repository)
    found = reviewer.get(BASE).json()[0]
    assert reviewer.patch(BASE + f"/{found['id']}/assignment", json={
        "assignee_id": "alice", "expected_version": found["version"],
    }).status_code == 200
    stale = reviewer.post(BASE + f"/{found['id']}/decisions", json={
        "decision": "affected", "rationale": "Reachable", "expected_version": found["version"],
    })
    assert stale.status_code == 409

    viewer = client(repository, roles={"viewer"})
    assert viewer.get(BASE).status_code == 200
    assert viewer.post(BASE + f"/{found['id']}/decisions", json={
        "decision": "affected", "rationale": "Reachable", "expected_version": 2,
    }).status_code == 403
    operator = client(repository, roles={"compliance_operator"})
    assert operator.post(BASE + f"/{found['id']}/decisions", json={
        "decision": "affected", "rationale": "Reachable", "expected_version": 2,
    }).status_code == 403
    hidden = client(repository, organization_id="org-other")
    assert hidden.get(BASE).status_code == 404


def test_validation_maps_to_422(repository):
    api = client(repository)
    found = api.get(BASE).json()[0]
    invalid = api.put(BASE + f"/{found['id']}/remediation", json={
        "plan": "Upgrade", "status": "verified", "verification_evidence": [],
        "expected_version": found["version"],
    })
    assert invalid.status_code == 422
