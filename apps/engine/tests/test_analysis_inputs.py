from __future__ import annotations

import hashlib
import io
import json
import stat
import zipfile
from datetime import date

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.pool import StaticPool

from pandax import events as ev
from pandax.analysis_api import create_analysis_router
from pandax.analysis_jobs import (
    AnalysisJobConflict,
    AnalysisJobRepository,
    AnalysisJobValidationError,
    analysis_jobs,
)
from pandax.analysis_storage import (
    AnalysisInputStorageError,
    LocalAnalysisInputStorage,
    MemoryAnalysisInputStorage,
)
from pandax.evidence import Ledger, write_manifest
from pandax.organization_settings import create_trust_key_enrollment
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pandax.organization_settings import OrganizationSettingsRepository
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.portfolio_api import PortfolioIdentity


def sbom() -> bytes:
    return json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "components": [{
            "type": "library", "name": "camera-core", "version": "1.0",
            "purl": "pkg:generic/camera-core@1.0",
        }],
    }).encode()


def collector(*, product_id="product-1", release_id="release-1", payload_path="evidence/sbom.cdx.json", digest=None, mutate=None) -> bytes:
    payload = sbom()
    manifest = {
        "schema": "actis.collector/v1", "product_id": product_id, "release_id": release_id,
        "generated_at": "2026-09-14T10:00:00Z",
        "collector": {"name": "Actis Collector", "version": "1.2.0"},
        "provenance": {"source": "ci://camera/release", "build_id": "build-1042"},
        "sbom_path": payload_path,
        "files": [{"path": payload_path, "sha256": digest or hashlib.sha256(payload).hexdigest()}],
    }
    if mutate:
        mutate(manifest)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("actis-collector-manifest.json", json.dumps(manifest))
        archive.writestr(payload_path, payload)
    return output.getvalue()


def signed_collector(root, settings, *, organization_id="org-1", product_id="product-1", release_id="release-1"):
    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    challenge = settings.create_trust_key_challenge(
        organization_id, key_name="collector", public_key_pem=pem, actor_id="admin"
    )
    enrollment = create_trust_key_enrollment(key, organization_id, "collector", challenge)
    registered = settings.enroll_trust_key(organization_id, **enrollment, actor_id="admin")
    bundle = root / "signed-collector"
    bundle.mkdir()
    (bundle / "sbom.cdx.json").write_bytes(sbom())
    (bundle / "collection-summary.json").write_text('{"status":"complete"}', encoding="utf-8")
    (bundle / "coverage.json").write_text('{"status":"complete"}', encoding="utf-8")
    ledger = Ledger(bundle)
    ledger.append("COLLECT", "actis-collector", "0.1.0", [], [ledger.ref(bundle / "sbom.cdx.json")])
    write_manifest(bundle, "collector-test", {}, {"collector": "0.1.0"}, ledger, key, extensions={
        "organization_id": organization_id, "product_id": product_id,
        "release_id": release_id, "collector": {"name": "Actis Collector", "version": "0.1.0"},
        "sbom_path": "sbom.cdx.json", "rules_version": "test",
    })
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for file in bundle.iterdir():
            archive.write(file, file.name)
    return output.getvalue(), registered


def replace_signed_entry(content: bytes, name: str, replacement: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(content)) as source, zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as target:
        for entry in source.infolist():
            target.writestr(entry.filename, replacement if entry.filename == name else source.read(entry))
    return output.getvalue()


@pytest.fixture()
def setup():
    engine = create_portfolio_engine(
        "sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool,
    )
    portfolio = PortfolioRepository(engine)
    storage = MemoryAnalysisInputStorage()
    repository = AnalysisJobRepository(engine, storage)
    settings = OrganizationSettingsRepository(engine)
    portfolio.create_schema()
    repository.create_schema()
    settings.create_schema()
    portfolio.create_organization(
        organization_id="org-1", name="Acme", legal_name="Acme GmbH", country="DE",
        registration_number="HRB-1", actor_id="admin",
    )
    portfolio.create_product(
        "org-1", product_id="product-1", name="Camera", identifier="CAM-1",
        manufacturer="Acme", cra_class="important_i", support_start=date(2026, 1, 1),
        support_end=date(2031, 1, 1), actor_id="admin",
    )
    portfolio.create_release(
        "org-1", "product-1", release_id="release-1", version="1.0", channel="stable",
        release_date=date(2026, 9, 1), support_start=date(2026, 9, 1),
        support_end=date(2031, 1, 1), actor_id="admin",
    )
    yield repository, storage, settings
    engine.dispose()


def create(repository, content, **changes):
    values = {
        "input_type": "collector", "filename": "collector.zip", "media_type": "application/zip",
        "content": content, "idempotency_key": "input-1", "actor_id": "reviewer",
    }
    values.update(changes)
    return repository.create_input("org-1", "product-1", "release-1", **values)


def test_collector_is_bound_verified_stored_by_reference_and_executable(setup):
    repository, storage, _ = setup
    content = collector()
    job = create(repository, content)
    replay = create(repository, content)

    assert job.input_type == "collector"
    assert replay.id == job.id and len(storage.objects) == 1
    assert job.preview["components"] == 1
    assert job.input_metadata["provenance"]["build_id"] == "build-1042"
    assert job.object_key in storage.objects
    with repository.engine.connect() as connection:
        assert connection.execute(select(analysis_jobs.c.input_content)).scalar_one() is None

    def runner(path):
        assert path.read_bytes() == sbom()
        yield ev.run_done("Complete", components=1, findings=0, kev=0, incidents=0)

    assert repository.run("org-1", "product-1", "release-1", job.id, runner).status == "completed"


def test_signed_collector_requires_active_customer_key_and_signed_binding(setup, tmp_path):
    repository, _, settings = setup
    content, key = signed_collector(tmp_path, settings)
    job = create(repository, content)
    assert job.input_metadata["trust"]["status"] == "trusted"
    assert job.input_metadata["trust"]["key_version"] == 1
    settings.revoke_trust_key("org-1", key.id, reason="test", actor_id="admin")
    with pytest.raises(AnalysisJobValidationError, match="active enrolled"):
        create(repository, content, idempotency_key="signed-2")


@pytest.mark.parametrize("binding", ["product_id", "release_id"])
def test_signed_collector_rejects_wrong_release_binding(setup, tmp_path, binding):
    repository, _, settings = setup
    content, _ = signed_collector(tmp_path, settings, **{binding: "other"})
    with pytest.raises(AnalysisJobValidationError, match="binding mismatch"):
        create(repository, content)


@pytest.mark.parametrize("entry", ["manifest.json", "sbom.cdx.json"])
def test_signed_collector_rejects_tampering(setup, tmp_path, entry):
    repository, _, settings = setup
    content, _ = signed_collector(tmp_path, settings)
    if entry == "manifest.json":
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            manifest = json.loads(archive.read(entry))
        manifest["rules_version"] = "substituted"
        replacement = json.dumps(manifest).encode()
    else:
        replacement = sbom().replace(b"camera-core", b"other-core")
    with pytest.raises(AnalysisJobValidationError, match="active enrolled"):
        create(repository, replace_signed_entry(content, entry, replacement))


def test_managed_environment_rejects_legacy_unsigned_collector(setup, monkeypatch):
    repository, _, _ = setup
    monkeypatch.setenv("PANDAX_ENVIRONMENT", "beta")
    with pytest.raises(AnalysisJobValidationError, match="unsigned"):
        create(repository, collector())


def test_missing_retained_input_fails_closed(setup):
    repository, storage, _ = setup
    job = create(repository, collector())
    repository.start("org-1", "product-1", "release-1", job.id)
    storage.delete(job.object_key)
    failed = repository.execute("org-1", "product-1", "release-1", job.id, lambda _: ())

    assert failed.status == "failed"
    assert failed.error == "analysis input object not found"


def test_local_storage_is_rooted_and_verifies_digest(tmp_path):
    storage = LocalAnalysisInputStorage(tmp_path / "objects")
    stored = storage.put("org-1", "job-1", b"retained evidence")

    assert storage.get(stored.object_key, stored.sha256) == b"retained evidence"
    with pytest.raises(AnalysisInputStorageError, match="digest mismatch"):
        storage.get(stored.object_key, "0" * 64)
    with pytest.raises(AnalysisInputStorageError, match="unsafe"):
        storage.get("../escape", stored.sha256)


@pytest.mark.parametrize("bad", [
    lambda: collector(product_id="other"),
    lambda: collector(digest="0" * 64),
    lambda: collector(mutate=lambda value: value.update(schema="actis.collector/v2")),
])
def test_collector_rejects_binding_digest_and_schema_failures(setup, bad):
    repository, _, _ = setup
    with pytest.raises(AnalysisJobValidationError):
        create(repository, bad())


def test_collector_rejects_traversal_duplicates_symlinks_and_zip_bombs(setup):
    repository, _, _ = setup
    unsafe = io.BytesIO()
    with zipfile.ZipFile(unsafe, "w") as archive:
        archive.writestr("../escape", b"x")
    duplicate = io.BytesIO()
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr("same", b"x")
        archive.writestr("same", b"y")
    symlink = io.BytesIO()
    with zipfile.ZipFile(symlink, "w") as archive:
        entry = zipfile.ZipInfo("link")
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(entry, "target")
    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("zeros", b"0" * (2 * 1024 * 1024))
    for content in (unsafe.getvalue(), duplicate.getvalue(), symlink.getvalue(), bomb.getvalue()):
        with pytest.raises(AnalysisJobValidationError):
            create(repository, content)


def test_raw_requires_policy_consent_matching_type_and_records_immutable_consent(setup, monkeypatch):
    repository, storage, _ = setup
    base = dict(
        input_type="raw_artifact", filename="firmware.bin", media_type="application/octet-stream",
        content=b"firmware", idempotency_key="raw-1", actor_id="reviewer",
    )
    with pytest.raises(AnalysisJobValidationError, match="organization policy"):
        repository.create_input("org-1", "product-1", "release-1", **base)
    with pytest.raises(AnalysisJobValidationError, match="explicit"):
        repository.create_input("org-1", "product-1", "release-1", **base, raw_artifact_allowed=True)
    with pytest.raises(AnalysisJobValidationError, match="does not match"):
        repository.create_input(
            "org-1", "product-1", "release-1", **{**base, "media_type": "application/zip"},
            raw_artifact_allowed=True, raw_artifact_consent=True,
        )
    with pytest.raises(AnalysisJobValidationError, match="valid ZIP"):
        repository.create_input(
            "org-1", "product-1", "release-1",
            **{**base, "filename": "firmware.zip", "media_type": "application/zip"},
            raw_artifact_allowed=True, raw_artifact_consent=True,
        )
    job = repository.create_input(
        "org-1", "product-1", "release-1", **base,
        raw_artifact_allowed=True, raw_artifact_consent=True, retention_days=30,
    )
    assert job.status == "queued"
    assert job.consented_at and job.consent_actor_id == "reviewer"
    assert job.object_key in storage.objects and job.retained_until > job.created_at
    assert [item.kind for item in repository.events("org-1", "product-1", "release-1", job.id)] == [
        "analysis.uploaded", "analysis.consent_recorded",
    ]

    def runner(path):
        assert path.name.endswith(".bin") and path.read_bytes() == b"firmware"
        yield ev.run_done("Complete", components=1, findings=0, kev=0, incidents=0)

    monkeypatch.setattr("pandax.analysis_jobs.pipeline.run", runner)
    completed = repository.run("org-1", "product-1", "release-1", job.id, lambda _: ())
    assert completed.status == "completed"


def test_typed_upload_api_enforces_rbac_settings_and_hides_storage_reference(setup):
    repository, _, settings = setup
    settings.update_settings(
        "org-1", expected_version=0,
        patch={"security": {"allow_raw_artifacts": True, "evidence_retention_months": 24}},
        actor_id="admin",
    )
    identity = PortfolioIdentity("reviewer", "org-1", frozenset({"security_reviewer"}))
    app = FastAPI()
    app.include_router(create_analysis_router(
        lambda: repository, lambda: identity,
        settings_repository_dependency=lambda: settings,
    ))
    client = TestClient(app)
    path = "/v1/organizations/org-1/products/product-1/releases/release-1/analysis-jobs/inputs"
    response = client.post(
        path, headers={"Idempotency-Key": "raw-api"},
        data={"input_type": "raw_artifact", "raw_artifact_consent": "true"},
        files={"file": ("firmware.bin", b"firmware", "application/octet-stream")},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["input_type"] == "raw_artifact" and body["status"] == "queued"
    assert body["consent_actor_id"] == "reviewer" and "object_key" not in body
    events = client.get(f"{path.removesuffix('/inputs')}/{body['id']}/events").json()
    assert events and all("object_key" not in item["details"] for item in events)

    for blocked_identity, expected in (
        (PortfolioIdentity("viewer", "org-1", frozenset({"viewer"})), 403),
        (PortfolioIdentity("reviewer", "org-2", frozenset({"security_reviewer"})), 404),
    ):
        blocked_app = FastAPI()
        blocked_app.include_router(create_analysis_router(
            lambda: repository, lambda identity=blocked_identity: identity,
            settings_repository_dependency=lambda: settings,
        ))
        blocked = TestClient(blocked_app).post(
            path, headers={"Idempotency-Key": "blocked"},
            data={"input_type": "collector"},
            files={"file": ("collector.zip", collector(), "application/zip")},
        )
        assert blocked.status_code == expected
