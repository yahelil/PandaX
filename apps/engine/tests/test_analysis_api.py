from __future__ import annotations

import hashlib
import io
import json
import zipfile
from types import SimpleNamespace
from unittest.mock import Mock
from collections.abc import Iterator
from datetime import date
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool

from pandax import events as ev
from pandax.analysis_api import create_analysis_router
from pandax.analysis_jobs import AnalysisJobRepository
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.portfolio_api import PortfolioIdentity
from pandax import portfolio_runtime
from pandax.portfolio_runtime import enroll_completed_analysis


def sbom_bytes() -> bytes:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "type": "library",
                    "name": "jetty-server",
                    "version": "11.0.17",
                    "purl": "pkg:maven/org.eclipse.jetty/jetty-server@11.0.17",
                }
            ],
        }
    ).encode()


def telemetry_bytes() -> bytes:
    return json.dumps({
        "schema": "pandax/runtime-telemetry/v1",
        "product": {"name": "Smart Camera", "version": "2.1.0", "unique_id": "ACM-CAM-210"},
        "approval": {"operator": "Company reviewer", "approved_at": "2026-09-14T08:00:00Z", "authority_attestation": True},
        "observations": [],
    }).encode()


def exposure_bytes() -> bytes:
    return json.dumps({
        "schema": "pandax/exposure-context/v1",
        "product": {"name": "Smart Camera", "version": "2.1.0", "unique_id": "ACM-CAM-210"},
        "approval": {"reviewer": "Company reviewer", "reviewed_at": "2026-09-14T08:00:00Z", "authority_attestation": True},
        "components": [],
    }).encode()


@pytest.fixture
def setup(tmp_path: Path) -> Iterator[dict]:
    engine = create_portfolio_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    portfolio = PortfolioRepository(engine)
    repository = AnalysisJobRepository(engine)
    repository.create_schema()
    organization = portfolio.create_organization(
        name="Acme Devices",
        legal_name="Acme Devices GmbH",
        country="DE",
        registration_number="HRB-128991",
        actor_id="admin",
    )
    product = portfolio.create_product(
        organization.id,
        name="Smart Camera",
        identifier="ACM-CAM-210",
        manufacturer="Acme Devices GmbH",
        cra_class="important_i",
        support_start=date(2026, 1, 1),
        support_end=date(2030, 12, 31),
        actor_id="admin",
    )
    release = portfolio.create_release(
        organization.id,
        product.id,
        version="2.1.0",
        channel="stable",
        release_date=date(2026, 9, 1),
        support_start=date(2026, 9, 1),
        support_end=date(2030, 12, 31),
        actor_id="admin",
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"signed":true}', encoding="utf-8")
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()

    supplemental = {}

    def runner(path: Path, **kwargs):
        assert path.read_bytes() == sbom_bytes()
        supplemental.update({key: value.read_bytes() if value else None for key, value in kwargs.items()})
        yield ev.start("S2 SBOM", "Validating SBOM")
        yield ev.done("S2 SBOM", "SBOM ready")
        yield ev.artifact("SEAL", "manifest.json", digest)
        yield ev.run_done(
            "Complete",
            run_dir=str(tmp_path),
            components=1,
            findings=2,
            kev=1,
            incidents=0,
            coverage_summary={"completed": 1},
        )

    yield {
        "engine": engine,
        "repository": repository,
        "organization_id": organization.id,
        "product_id": product.id,
        "release_id": release.id,
        "runner": runner,
        "digest": digest,
        "pending": [],
        "completed": [],
        "supplemental": supplemental,
    }
    engine.dispose()


def make_client(
    setup: dict,
    identity: PortfolioIdentity | None = None,
    completion_callback=None,
) -> TestClient:
    principal = identity or PortfolioIdentity(
        actor_id="security-reviewer",
        organization_id=setup["organization_id"],
        roles=frozenset({"security_reviewer"}),
    )
    app = FastAPI()
    app.include_router(
        create_analysis_router(
            lambda: setup["repository"],
            lambda: principal,
            setup["runner"],
            setup["pending"].append,
            completion_callback=completion_callback or setup["completed"].append,
        )
    )
    return TestClient(app)


def collection(setup: dict) -> str:
    return (
        f"/v1/organizations/{setup['organization_id']}"
        f"/products/{setup['product_id']}/releases/{setup['release_id']}/analysis-jobs"
    )


def upload(client: TestClient, setup: dict, *, key: str = "analysis-001"):
    return client.post(
        collection(setup),
        headers={"Idempotency-Key": key},
        files={
            "sbom": (
                "smart-camera.cdx.json",
                sbom_bytes(),
                "application/vnd.cyclonedx+json",
            )
        },
    )


def test_upload_preview_run_events_and_evidence(setup):
    client = make_client(setup)

    response = upload(client, setup)
    assert response.status_code == 201, response.text
    job = response.json()
    assert job["status"] == "queued"
    assert job["preview"]["components"] == 1
    assert "idempotency_key" not in job

    run = client.post(f"{collection(setup)}/{job['id']}/run")
    assert run.status_code == 200, run.text
    assert run.json()["status"] == "running"
    assert len(setup["pending"]) == 1
    setup["pending"].pop()()
    assert [item.id for item in setup["completed"]] == [job["id"]]
    result = client.get(f"{collection(setup)}/{job['id']}").json()
    assert result["status"] == "completed"
    assert result["result"]["findings"] == 2
    assert result["result"]["evidence"] == [
        {
            "name": "manifest.json",
            "sha256": setup["digest"],
            "href": f"{collection(setup)}/{job['id']}/evidence/{setup['digest']}",
        }
    ]

    events = client.get(f"{collection(setup)}/{job['id']}/events")
    assert events.status_code == 200
    assert events.json()[0]["kind"] == "analysis.uploaded"
    assert events.json()[-1]["kind"] == "analysis.completed"

    evidence = client.get(result["result"]["evidence"][0]["href"])
    assert evidence.status_code == 200
    assert evidence.content == b'{"signed":true}'


def test_upload_validates_retains_and_forwards_release_bound_runtime_evidence(setup):
    client = make_client(setup)
    response = client.post(
        collection(setup),
        headers={"Idempotency-Key": "analysis-with-runtime"},
        files={
            "sbom": ("smart-camera.cdx.json", sbom_bytes(), "application/vnd.cyclonedx+json"),
            "telemetry": ("runtime.json", telemetry_bytes(), "application/json"),
            "exposure_context": ("exposure.json", exposure_bytes(), "application/json"),
        },
    )

    assert response.status_code == 201, response.text
    metadata = response.json()["input_metadata"]["supplemental_evidence"]
    assert set(metadata) == {"runtime_telemetry", "exposure_context"}
    assert metadata["runtime_telemetry"]["validation"]["schema"] == "pandax/runtime-telemetry/v1"
    assert "object_key" not in json.dumps(metadata)

    job_id = response.json()["id"]
    assert client.post(f"{collection(setup)}/{job_id}/run").status_code == 200
    setup["pending"].pop()()
    assert setup["supplemental"] == {
        "telemetry_path": telemetry_bytes(),
        "exposure_context_path": exposure_bytes(),
    }


def test_runtime_evidence_must_match_the_selected_product_release(setup):
    document = json.loads(telemetry_bytes())
    document["product"]["version"] = "9.9.9"
    client = make_client(setup)
    response = client.post(
        collection(setup),
        headers={"Idempotency-Key": "wrong-release-runtime"},
        files={
            "sbom": ("smart-camera.cdx.json", sbom_bytes(), "application/vnd.cyclonedx+json"),
            "telemetry": ("runtime.json", json.dumps(document).encode(), "application/json"),
        },
    )

    assert response.status_code == 422
    assert "selected product release" in response.json()["detail"]


def test_completed_active_release_enrolls_hourly_monitoring(monkeypatch):
    portfolio = Mock()
    portfolio.get_release.return_value = SimpleNamespace(status="active")
    monitoring = Mock()
    monkeypatch.setattr("pandax.portfolio_runtime.get_portfolio_repository", lambda: portfolio)
    monkeypatch.setattr("pandax.portfolio_runtime.get_release_monitoring_repository", lambda: monitoring)

    enroll_completed_analysis(SimpleNamespace(
        organization_id="org-1", product_id="product-1", release_id="release-1", actor_id="operator-1",
    ))

    monitoring.configure.assert_called_once_with(
        "org-1", "product-1", "release-1",
        enabled_sources=("osv", "cisa_kev", "epss"), cadence_minutes=60,
        enabled=True, actor_id="operator-1",
    )


def test_completed_analysis_projects_reachability_recommendations(monkeypatch):
    findings = [{
        "cve": "CVE-2026-1000",
        "osv_id": "OSV-1",
        "purl": "pkg:npm/example@1.0.0",
        "component": "example",
        "version": "1.0.0",
        "summary": "Example vulnerability",
        "severity": "HIGH",
        "source": "OSV",
        "bom_ref": "component-example",
        "reachability": "unknown",
        "exposure_assessment": "evidence_supports_not_reachable",
        "exposure_evidence": {
            "recommendation": {
                "reachability": "not_reachable",
                "confidence": "high",
                "reason_codes": ["component_excluded"],
                "limitations": ["The component exclusion requires reviewer confirmation."],
                "review_required": True,
                "recommended_vex": {
                    "state": "not_affected",
                    "justification": "code_not_present",
                },
            },
        },
    }]
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as bundle:
        bundle.writestr("findings.json", json.dumps(findings))
    analysis = Mock()
    analysis.export_evidence.return_value = (output.getvalue(), "evidence.zip")
    repository = Mock()
    portfolio = Mock()
    portfolio.get_release.return_value = SimpleNamespace(status="retired")
    monkeypatch.setattr(portfolio_runtime, "get_analysis_repository", lambda: analysis)
    monkeypatch.setattr(portfolio_runtime, "get_finding_repository", lambda: repository)
    monkeypatch.setattr(portfolio_runtime, "get_portfolio_repository", lambda: portfolio)
    job = SimpleNamespace(
        id="analysis-1", organization_id="org-1", product_id="product-1",
        release_id="release-1", actor_id="operator-1", completed_at=None,
        result={"bundle": {"id": "bundle-1"}},
    )

    enroll_completed_analysis(job)

    projected = repository.upsert_from_analysis.call_args.args[4][0]
    assert projected.reachability == "unknown"
    assert projected.reachability_evidence["recommendation"] == {
        "reachability": "not_reachable",
        "confidence": "high",
        "reason_codes": ["component_excluded"],
        "limitations": ["The component exclusion requires reviewer confirmation."],
        "review_required": True,
        "recommended_vex": {
            "state": "not_affected",
            "justification": "code_not_present",
        },
    }
    assert projected.reachability_limitations == (
        "The component exclusion requires reviewer confirmation.",
    )
    assert projected.provenance["bom_ref"] == "component-example"


def test_completed_analysis_enrolls_regulatory_documents(monkeypatch):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as bundle:
        bundle.writestr("findings.json", json.dumps([]))
        bundle.writestr("EU_Declaration_of_Conformity.pdf", b"%PDF-1.4 mock DoC")
        bundle.writestr("AnnexVII_Technical_Documentation.pdf", b"%PDF-1.4 mock Annex VII")
        bundle.writestr(
            "dossier.json",
            json.dumps({"summary": {"derived": 5, "attested": 3, "required_input": 0}}),
        )

    storage = Mock()
    storage.put_document.side_effect = lambda org_id, scope_id, content, suffix: SimpleNamespace(
        key=f"documents/{org_id}/{scope_id}{suffix}",
        digest=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
    )
    analysis = Mock()
    analysis.export_evidence.return_value = (output.getvalue(), "evidence.zip")
    analysis.storage = storage

    doc_repo = Mock()
    doc_repo.list_documents.return_value = []
    finding_repo = Mock()
    portfolio = Mock()
    portfolio.get_release.return_value = SimpleNamespace(status="retired")

    monkeypatch.setattr(portfolio_runtime, "get_analysis_repository", lambda: analysis)
    monkeypatch.setattr(portfolio_runtime, "get_document_repository", lambda: doc_repo)
    monkeypatch.setattr(portfolio_runtime, "get_finding_repository", lambda: finding_repo)
    monkeypatch.setattr(portfolio_runtime, "get_portfolio_repository", lambda: portfolio)

    job = SimpleNamespace(
        id="analysis-doc-test",
        organization_id="org-acme",
        product_id="product-device",
        release_id="release-1",
        actor_id="operator-1",
        completed_at=None,
        result={"bundle": {"id": "bundle-1"}},
    )

    enroll_completed_analysis(job)

    assert doc_repo.create_document.call_count == 2
    calls = doc_repo.create_document.call_args_list

    created_names = {call.kwargs["name"] for call in calls}
    assert created_names == {"EU Declaration of Conformity", "Annex VII Technical Documentation"}

    doc_call = next(call for call in calls if call.kwargs["name"] == "EU Declaration of Conformity")
    assert doc_call.kwargs["kind"] == "conformity"
    assert doc_call.kwargs["format"] == "pdf_a_2b"
    assert doc_call.kwargs["size_bytes"] == len(b"%PDF-1.4 mock DoC")
    assert doc_call.kwargs["provenance"]["completeness"] == "complete"
    assert doc_call.kwargs["provenance"]["analysis_job_id"] == "analysis-doc-test"


def test_monitoring_enrollment_failure_keeps_analysis_complete_and_records_follow_up(setup):
    def unavailable_monitoring(_job):
        raise RuntimeError("monitoring database unavailable")

    client = make_client(setup, completion_callback=unavailable_monitoring)
    uploaded = upload(client, setup).json()
    assert client.post(f"{collection(setup)}/{uploaded['id']}/run").status_code == 200

    setup["pending"].pop()()

    job = client.get(f"{collection(setup)}/{uploaded['id']}").json()
    events = client.get(f"{collection(setup)}/{uploaded['id']}/events").json()
    assert job["status"] == "completed"
    assert events[-1]["kind"] == "analysis.monitoring_enrollment_failed"
    assert events[-1]["details"] == {"integration": "monitoring", "retry_required": True}
    assert "database" not in events[-1]["message"]


def test_completed_analysis_enrollment_can_be_retried(setup):
    attempts = []

    def enroll(job):
        attempts.append(job.id)
        if len(attempts) == 1:
            raise RuntimeError("temporary projection failure")

    client = make_client(setup, completion_callback=enroll)
    uploaded = upload(client, setup).json()
    path = f"{collection(setup)}/{uploaded['id']}"
    assert client.post(path + "/enroll").status_code == 409
    assert client.post(path + "/run").status_code == 200
    setup["pending"].pop()()

    response = client.post(path + "/enroll")
    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert attempts == [uploaded["id"], uploaded["id"]]


def test_idempotent_http_replay_returns_same_job(setup):
    client = make_client(setup)
    first = upload(client, setup)
    second = upload(client, setup)

    assert second.status_code == 201
    assert second.json()["id"] == first.json()["id"]
    assert len(client.get(collection(setup)).json()) == 1


def test_rejects_missing_key_and_invalid_sbom(setup):
    client = make_client(setup)
    missing_key = client.post(
        collection(setup),
        files={"sbom": ("sbom.json", sbom_bytes(), "application/json")},
    )
    invalid = client.post(
        collection(setup),
        headers={"Idempotency-Key": "invalid"},
        files={"sbom": ("sbom.json", b"{}", "application/json")},
    )

    assert missing_key.status_code == 422
    assert invalid.status_code == 422
    assert "expected CycloneDX" in invalid.json()["detail"]


def test_read_and_write_role_enforcement(setup):
    viewer = make_client(
        setup,
        PortfolioIdentity(
            actor_id="viewer",
            organization_id=setup["organization_id"],
            roles=frozenset({"viewer"}),
        ),
    )

    assert viewer.get(collection(setup)).status_code == 200
    assert upload(viewer, setup).status_code == 403


def test_cross_organization_and_product_scope_are_hidden(setup):
    wrong_tenant = make_client(
        setup,
        PortfolioIdentity(
            actor_id="reviewer",
            organization_id="another-organization",
            roles=frozenset({"security_reviewer"}),
        ),
    )
    assert wrong_tenant.get(collection(setup)).status_code == 404

    client = make_client(setup)
    wrong_product = collection(setup).replace(setup["product_id"], "wrong-product")
    assert client.get(wrong_product).status_code == 404
