from __future__ import annotations

import io
import json
import shutil
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from pandax import cli
from pandax.auth import Principal, Role
from pandax.evidence import Ledger, write_manifest
from pandax.organization_settings import (
    OrganizationSettingsRepository,
    SettingsValidationError,
    create_trust_key_enrollment,
)
from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.settings_api import create_settings_router


def _sealed_bundle(root: Path, key: Ed25519PrivateKey, name: str) -> tuple[Path, Path]:
    run = root / name
    run.mkdir(parents=True)
    report = run / "report.json"
    report.write_text('{"result":"ok"}', encoding="utf-8")
    ledger = Ledger(run)
    ledger.append("TEST", "pytest", "1", [], [ledger.ref(report)])
    write_manifest(run, name, {}, {"actis": "test"}, ledger, key)
    archive = Path(shutil.make_archive(str(root / name), "zip", root_dir=run))
    return run, archive


@pytest.fixture
def trust_scope(tmp_path):
    engine = create_portfolio_engine(f"sqlite:///{(tmp_path / 'trust.sqlite3').as_posix()}")
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    for organization_id in ("org-acme", "org-other"):
        portfolio.create_organization(
            organization_id=organization_id,
            name=organization_id,
            legal_name=f"{organization_id} GmbH",
            country="DE",
            registration_number=organization_id,
            actor_id="seed",
        )
    repository = OrganizationSettingsRepository(engine)
    return repository, tmp_path


def _enroll(repository, organization_id: str, key: Ed25519PrivateKey, name="release-signing", **kwargs):
    enrollment = create_trust_key_enrollment(key, organization_id, name)
    return repository.enroll_trust_key(
        organization_id,
        **enrollment,
        actor_id="admin",
        **kwargs,
    )


def test_proof_rotation_revocation_and_registry_verification(trust_scope):
    repository, tmp_path = trust_scope
    old_key = Ed25519PrivateKey.generate()
    old_run, _ = _sealed_bundle(tmp_path, old_key, "old-bundle")
    old = _enroll(repository, "org-acme", old_key)

    verified = repository.verify_registered_bundle(
        "org-acme", old_run, actor_id="auditor"
    )
    assert verified["status"] == verified["trust_decision"] == "trusted"
    assert verified["trust_source"] == "organization_registry"
    assert verified["algorithm"] == "Ed25519"
    assert verified["key_id"] == "release-signing" and verified["key_version"] == 1
    assert repository.verify_registered_bundle(
        "org-other", old_run, actor_id="auditor"
    )["trust_decision"] == "not_enrolled"

    new_key = Ed25519PrivateKey.generate()
    rotated_at = datetime.now(timezone.utc) + timedelta(seconds=1)
    current = _enroll(repository, "org-acme", new_key, now=rotated_at)
    assert current.key_version == 2
    assert repository.get_trust_key("org-acme", old.id).status == "rotated"
    assert repository.verify_registered_bundle(
        "org-acme", old_run, actor_id="auditor"
    )["status"] == "trusted"

    new_run, _ = _sealed_bundle(tmp_path, new_key, "new-bundle")
    assert repository.verify_registered_bundle(
        "org-acme", new_run, actor_id="auditor"
    )["key_version"] == 2

    repository.revoke_trust_key(
        "org-acme", old.id, reason="Compromise drill", actor_id="admin"
    )
    revoked = repository.verify_registered_bundle(
        "org-acme", old_run, actor_id="auditor"
    )
    assert revoked["status"] == "untrusted" and revoked["trust_decision"] == "revoked"

    (new_run / "report.json").write_text('{"result":"tampered"}', encoding="utf-8")
    tampered = repository.verify_registered_bundle(
        "org-acme", new_run, actor_id="auditor"
    )
    assert tampered["status"] == "invalid" and not tampered["integrity_ok"]
    actions = [event.action for event in repository.list_audit("org-acme")]
    assert {"trust_key.enrolled", "trust_key.rotated", "trust_key.revoked", "trust_key.verified"} <= set(actions)


def test_enrollment_rejects_bad_proof_and_private_material(trust_scope):
    repository, _ = trust_scope
    key = Ed25519PrivateKey.generate()
    enrollment = create_trust_key_enrollment(key, "org-acme", "release-signing")
    with pytest.raises(SettingsValidationError, match="proof of possession"):
        repository.enroll_trust_key(
            "org-acme",
            **{**enrollment, "proof_signature": "00" * 64},
            actor_id="admin",
        )
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    with pytest.raises(SettingsValidationError, match="public key"):
        repository.enroll_trust_key(
            "org-acme",
            key_name="release-signing",
            public_key_pem=private_pem,
            proof_signature="00" * 64,
            actor_id="admin",
        )


def test_trust_api_is_tenant_scoped_and_verifies_zip(trust_scope):
    repository, tmp_path = trust_scope
    key = Ed25519PrivateKey.generate()
    _, archive = _sealed_bundle(tmp_path, key, "api-bundle")
    identity = {"value": Principal("admin", "org-acme", frozenset({Role.ORG_ADMIN}))}
    app = FastAPI()
    app.include_router(create_settings_router(lambda: repository, lambda: identity["value"]))
    client = TestClient(app)
    enrollment = create_trust_key_enrollment(key, "org-acme", "release-signing")

    created = client.post("/v1/organizations/org-acme/trust-keys", json=enrollment)
    assert created.status_code == 201 and "PRIVATE KEY" not in created.text
    result = client.post(
        "/v1/organizations/org-acme/trust-verifications",
        files={"bundle": (archive.name, archive.read_bytes(), "application/zip")},
    )
    assert result.status_code == 200 and result.json()["status"] == "trusted"

    identity["value"] = Principal("admin", "org-other", frozenset({Role.ORG_ADMIN}))
    assert client.get("/v1/organizations/org-acme/trust-keys").status_code == 404
    identity["value"] = Principal("admin", "org-acme", frozenset({Role.ORG_ADMIN}))
    rejected = client.post(
        "/v1/organizations/org-acme/trust-keys",
        json={**enrollment, "private_key_pem": "forbidden"},
    )
    assert rejected.status_code == 422

    unsafe = io.BytesIO()
    with zipfile.ZipFile(unsafe, "w") as archive_file:
        archive_file.writestr("../manifest.json", "{}")
    response = client.post(
        "/v1/organizations/org-acme/trust-verifications",
        files={"bundle": ("unsafe.zip", unsafe.getvalue(), "application/zip")},
    )
    assert response.status_code == 422


def test_cli_enrollment_proof_contains_only_public_material(tmp_path):
    private = tmp_path / "customer.pem"
    result = CliRunner().invoke(
        cli.app,
        ["key", "enrollment-proof", "org-acme", "release-signing", "--signing-key", str(private)],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert set(payload) == {"key_name", "public_key_pem", "proof_signature"}
    assert "PUBLIC KEY" in payload["public_key_pem"] and "PRIVATE KEY" not in result.stdout
    assert private.exists()
