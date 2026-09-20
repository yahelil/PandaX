from __future__ import annotations

import hashlib
import json
import sys
from datetime import date, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from pandax import analysis_jobs, events as ev
from pandax.analysis_api import create_analysis_router
from pandax.analysis_jobs import (
    AnalysisJobConflict,
    AnalysisJobError,
    AnalysisJobRepository,
    AnalysisJobNotFound,
    evidence_bundles,
)
from pandax.analysis_storage import (
    AnalysisInputStorageError,
    LocalAnalysisInputStorage,
    MemoryAnalysisInputStorage,
    SupabaseAnalysisInputStorage,
)
from pandax.evidence import Ledger, sha256_file, write_manifest, write_public_key
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.portfolio_api import PortfolioIdentity

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "verifier" / "src"))
from pandax_verifier.verification import verify_bundle
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _sbom() -> bytes:
    return json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [{
            "type": "library", "name": "demo", "version": "1.0",
            "purl": "pkg:pypi/demo@1.0",
        }],
    }).encode()


def _completed(tmp_path: Path, storage=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    engine = create_portfolio_engine(f"sqlite:///{(tmp_path / 'actis.sqlite3').as_posix()}")
    portfolio = PortfolioRepository(engine)
    repository = AnalysisJobRepository(
        engine, storage or LocalAnalysisInputStorage(tmp_path / "objects")
    )
    repository.create_schema()
    organization = portfolio.create_organization(
        name="Acme", legal_name="Acme GmbH", country="DE",
        registration_number="HRB-1", actor_id="admin",
    )
    product = portfolio.create_product(
        organization.id, name="Camera", identifier="CAM-1", manufacturer="Acme",
        cra_class="default", support_start=date(2026, 1, 1),
        support_end=date(2030, 1, 1), actor_id="admin",
    )
    release = portfolio.create_release(
        organization.id, product.id, version="1.0", channel="stable",
        release_date=date(2026, 1, 1), support_start=date(2026, 1, 1),
        support_end=date(2030, 1, 1), actor_id="admin",
    )
    run_dir = tmp_path / "sealed"
    run_dir.mkdir()
    payload = run_dir / "report.json"
    payload.write_text('{"ok":true}', encoding="utf-8")
    ledger = Ledger(run_dir)
    ledger.append("TEST", "pytest", "1", [], [ledger.ref(payload)])
    key = Ed25519PrivateKey.generate()
    write_manifest(run_dir, "run-1", {}, {}, ledger, key)
    trusted_key = tmp_path / "trusted.pem"
    write_public_key(key, trusted_key)
    manifest_digest = sha256_file(run_dir / "manifest.json")
    job = repository.create(
        organization.id, product.id, release.id,
        filename="sbom.cdx.json", media_type="application/vnd.cyclonedx+json",
        content=_sbom(), idempotency_key="job-1", actor_id="operator",
    )

    def runner(_path: Path):
        yield ev.artifact("SEAL", "manifest.json", manifest_digest)
        yield ev.run_done("Complete", run_dir=str(run_dir), components=0)

    completed = repository.run(organization.id, product.id, release.id, job.id, runner)
    scope = (organization.id, product.id, release.id, job.id)
    return engine, repository, scope, trusted_key, completed


def test_bundle_survives_restart_is_tenant_scoped_and_verifies(tmp_path):
    engine, repository, scope, trusted_key, completed = _completed(tmp_path)
    assert completed.status == "completed"
    assert "_run_dir" not in completed.result

    restarted = AnalysisJobRepository(engine, LocalAnalysisInputStorage(tmp_path / "objects"))
    archive, filename = restarted.export_evidence(*scope)
    exported = tmp_path / filename
    exported.write_bytes(archive)
    assert verify_bundle(exported, trusted_key).status == "trusted"
    assert restarted.evidence_bundle(*scope).retained_until >= completed.created_at + timedelta(days=3650)
    with pytest.raises(AnalysisJobNotFound):
        restarted.export_evidence("another-org", *scope[1:])

    app = FastAPI()
    app.include_router(create_analysis_router(
        lambda: restarted,
        lambda: PortfolioIdentity("viewer", scope[0], frozenset({"viewer"})),
    ))
    path = (
        f"/v1/organizations/{scope[0]}/products/{scope[1]}/releases/{scope[2]}"
        f"/analysis-jobs/{scope[3]}/evidence/export"
    )
    response = TestClient(app).get(path)
    assert response.status_code == 200 and response.content == archive
    assert response.headers["content-type"] == "application/zip"


@pytest.mark.parametrize("failure", ["missing", "digest"])
def test_missing_or_changed_object_fails_closed(tmp_path, failure):
    _, repository, scope, _, _ = _completed(tmp_path)
    bundle = repository.evidence_bundle(*scope)
    path = repository.storage.root / bundle.object_key
    path.unlink() if failure == "missing" else path.write_bytes(b"changed")
    with pytest.raises(AnalysisJobError, match="unavailable|digest mismatch"):
        repository.export_evidence(*scope)


def test_retention_and_legal_hold_guard_verified_deletion(tmp_path):
    _, repository, scope, _, _ = _completed(tmp_path)
    bundle = repository.set_evidence_hold(
        *scope, held=True, reason="Regulatory inquiry", actor_id="admin"
    )
    after_retention = bundle.retained_until + timedelta(days=1)
    with pytest.raises(AnalysisJobConflict, match="legal hold"):
        repository.delete_evidence(
            *scope, reason="Customer request", actor_id="admin", now=after_retention
        )
    repository.set_evidence_hold(
        *scope, held=False, reason="Inquiry closed", actor_id="admin"
    )
    with pytest.raises(AnalysisJobConflict, match="retention period"):
        repository.delete_evidence(
            *scope, reason="Too early", actor_id="admin", now=bundle.created_at
        )

    receipt = repository.delete_evidence(
        *scope, reason="Retention expired", actor_id="admin", now=after_retention
    )
    assert len(receipt["receipt_sha256"]) == 64
    assert receipt["backup_expires_at"] > receipt["deleted_at"]
    assert repository.evidence_bundle(*scope).state == "deleted"
    with pytest.raises(AnalysisJobNotFound):
        repository.export_evidence(*scope)


def test_quota_and_interrupted_upload_leave_no_bundle(tmp_path, monkeypatch):
    monkeypatch.setattr(analysis_jobs, "EVIDENCE_ORGANIZATION_LIMIT_BYTES", 200)
    _, repository, scope, _, completed = _completed(tmp_path / "quota")
    assert completed.status == "failed" and "quota" in completed.error
    with repository.engine.connect() as connection:
        assert connection.scalar(select(func.count()).select_from(evidence_bundles)) == 0

    class InterruptedStorage(MemoryAnalysisInputStorage):
        def put_bundle(self, organization_id: str, bundle_id: str, content: bytes):
            raise AnalysisInputStorageError("upload interrupted")

    monkeypatch.setattr(analysis_jobs, "EVIDENCE_ORGANIZATION_LIMIT_BYTES", 200_000_000)
    _, repository, _, _, completed = _completed(tmp_path / "interrupted", InterruptedStorage())
    assert completed.status == "failed" and completed.error == "upload interrupted"
    with repository.engine.connect() as connection:
        assert connection.scalar(select(func.count()).select_from(evidence_bundles)) == 0


@pytest.mark.parametrize("duplicate_status", [400, 409])
def test_supabase_adapter_requires_private_bucket_and_idempotent_objects(duplicate_status):
    content = b"sealed bundle"
    posts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal posts
        assert request.headers["apikey"] == "secret-key"
        if request.url.path.endswith("/bucket/actis-evidence"):
            return httpx.Response(200, json={"public": False})
        if request.method == "POST":
            posts += 1
            return httpx.Response(200 if posts == 1 else duplicate_status, json={})
        if request.method == "GET":
            return httpx.Response(200, content=content)
        if request.method == "DELETE":
            return httpx.Response(200, json=[])
        return httpx.Response(500)

    storage = SupabaseAnalysisInputStorage(
        "https://project.supabase.co",
        "secret-key",
        "actis-evidence",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    storage.check_ready()
    first = storage.put_bundle("org-1", "bundle-1", content)
    duplicate = storage.put_bundle("org-1", "bundle-1", content)
    assert duplicate == first
    assert storage.get(first.object_key, hashlib.sha256(content).hexdigest()) == content
    storage.delete(first.object_key)
