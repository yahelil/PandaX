from __future__ import annotations

import base64
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pandax.evidence import Ledger, verify_bundle, verify_run, write_manifest
from pandax.signing import (
    GoogleCloudKmsSigner,
    PrivateKeySigner,
    SigningConfigurationError,
    SigningProviderError,
    configured_registry,
    configured_signer,
    parse_registry,
)


def _private_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    ).decode("ascii")


def _registry(*signers_and_statuses) -> dict:
    keys = []
    pairs = iter(signers_and_statuses)
    for signer, status in zip(pairs, pairs):
        identity = signer.identity
        keys.append(
            {
                **identity.as_manifest(),
                "public_key_pem": signer.public_key_pem().decode("ascii"),
                "status": status,
            }
        )
    return {"schema": "actis/signing-key-registry/v1", "keys": keys}


def _seal(path: Path, signer) -> None:
    path.mkdir()
    evidence = path / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    ledger = Ledger(path)
    ledger.append("TEST", "pytest", "1", [], [ledger.ref(evidence)])
    write_manifest(path, path.name, {}, {"pytest": "1"}, ledger, signer)


def test_development_defaults_to_file_signer(tmp_path: Path):
    signer = configured_signer(tmp_path / "dev.pem", {"PANDAX_ENVIRONMENT": "development"})
    assert signer.identity.provider == "file"
    assert (tmp_path / "dev.pem").exists()


@pytest.mark.parametrize("environment", ["staging", "beta", "production"])
def test_managed_environments_never_default_to_a_file(environment: str, tmp_path: Path):
    with pytest.raises(SigningConfigurationError, match="PANDAX_SIGNER_PROVIDER is required"):
        configured_signer(tmp_path / "must-not-exist.pem", {"PANDAX_ENVIRONMENT": environment})
    assert not (tmp_path / "must-not-exist.pem").exists()


def test_beta_secret_signer_never_writes_private_material(tmp_path: Path):
    key = Ed25519PrivateKey.generate()
    env = {
        "PANDAX_ENVIRONMENT": "beta",
        "PANDAX_SIGNER_PROVIDER": "secret",
        "PANDAX_SIGNING_KEY_B64": _private_b64(key),
        "PANDAX_SIGNING_KEY_ID": "beta-release",
        "PANDAX_SIGNING_KEY_VERSION": "1",
    }
    signer = configured_signer(tmp_path / "unused.pem", env)
    assert signer.identity.provider == "secret"
    assert signer.sign(b"payload") == key.sign(b"payload")
    assert list(tmp_path.iterdir()) == []


def test_beta_secret_configuration_seals_complete_bundle(tmp_path: Path):
    key = Ed25519PrivateKey.generate()
    signer = configured_signer(
        tmp_path / "unused.pem",
        {
            "PANDAX_ENVIRONMENT": "beta",
            "PANDAX_SIGNER_PROVIDER": "secret",
            "PANDAX_SIGNING_KEY_B64": _private_b64(key),
            "PANDAX_SIGNING_KEY_ID": "beta-release",
            "PANDAX_SIGNING_KEY_VERSION": "1",
        },
    )
    run = tmp_path / "run"
    _seal(run, signer)
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["signing"]["provider"] == "secret"
    assert all(check.ok for check in verify_run(run))
    assert not (tmp_path / "unused.pem").exists()


@pytest.mark.parametrize("provider", ["file", "secret"])
def test_production_rejects_in_process_private_keys(provider: str, tmp_path: Path):
    with pytest.raises(SigningConfigurationError):
        configured_signer(
            tmp_path / "key.pem",
            {"PANDAX_ENVIRONMENT": "production", "PANDAX_SIGNER_PROVIDER": provider},
        )


class _FakeKms:
    def __init__(self, key: Ed25519PrivateKey, state="ENABLED", algorithm="EC_SIGN_ED25519"):
        self.key = key
        self.state = state
        self.algorithm = algorithm

    def get_crypto_key_version(self, **_):
        return SimpleNamespace(state=self.state, algorithm=self.algorithm)

    def get_public_key(self, **_):
        pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        return SimpleNamespace(pem=pem)

    def asymmetric_sign(self, request, **_):
        signature = self.key.sign(request["data"])
        return SimpleNamespace(
            verified_data_crc32c=True,
            signature=signature,
            signature_crc32c=SimpleNamespace(value=len(signature)),
        )


def test_google_kms_signer_validates_exact_version_and_response(monkeypatch):
    key = Ed25519PrivateKey.generate()
    local = PrivateKeySigner(
        key,
        "google-cloud-kms",
        "projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k",
        "7",
    )
    registry = parse_registry(_registry(local, "active"))
    monkeypatch.setattr("pandax.signing._crc32c", len)
    monkeypatch.setattr("pandax.signing._int64_value", lambda value: SimpleNamespace(value=value))
    signer = GoogleCloudKmsSigner(
        "projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/7",
        registry,
        _FakeKms(key),
    )
    signature = signer.sign(b"payload")
    key.public_key().verify(signature, b"payload")


def test_production_builds_only_exact_registered_kms_version():
    key = Ed25519PrivateKey.generate()
    key_id = "projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k"
    local = PrivateKeySigner(key, "google-cloud-kms", key_id, "7")
    encoded_registry = base64.b64encode(
        json.dumps(_registry(local, "active")).encode("utf-8")
    ).decode("ascii")
    signer = configured_signer(
        Path("unused"),
        {
            "PANDAX_ENVIRONMENT": "production",
            "PANDAX_SIGNER_PROVIDER": "google-cloud-kms",
            "PANDAX_GCP_KMS_KEY_VERSION": f"{key_id}/cryptoKeyVersions/7",
            "PANDAX_SIGNING_KEY_REGISTRY_B64": encoded_registry,
        },
        kms_client=_FakeKms(key),
    )
    assert signer.identity == local.identity


@pytest.mark.parametrize(
    ("state", "algorithm", "message"),
    [
        ("DISABLED", "EC_SIGN_ED25519", "must be enabled"),
        ("ENABLED", "EC_SIGN_P256_SHA256", "must be EC_SIGN_ED25519"),
    ],
)
def test_google_kms_rejects_wrong_state_or_algorithm(state, algorithm, message):
    key = Ed25519PrivateKey.generate()
    local = PrivateKeySigner(
        key,
        "google-cloud-kms",
        "projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k",
        "7",
    )
    registry = parse_registry(_registry(local, "active"))
    with pytest.raises(SigningConfigurationError, match=message):
        GoogleCloudKmsSigner(
            "projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/7",
            registry,
            _FakeKms(key, state=state, algorithm=algorithm),
        )


def test_google_kms_errors_do_not_expose_provider_details():
    key = Ed25519PrivateKey.generate()
    local = PrivateKeySigner(
        key,
        "google-cloud-kms",
        "projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k",
        "7",
    )
    registry = parse_registry(_registry(local, "active"))

    class FailingKms:
        def get_crypto_key_version(self, **_):
            raise RuntimeError("credential=secret-token")

    with pytest.raises(SigningProviderError, match="key validation failed") as caught:
        GoogleCloudKmsSigner(
            "projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/7",
            registry,
            FailingKms(),
        )
    assert "secret-token" not in str(caught.value)


def test_google_kms_outage_leaves_no_control_files(tmp_path: Path):
    class FailingSigner:
        identity = PrivateKeySigner(Ed25519PrivateKey.generate(), "file", "test", "1").identity

        def public_key_pem(self):
            raise AssertionError("public key must not be requested after failed signing")

        def sign(self, _payload):
            raise SigningProviderError("provider unavailable")

    run = tmp_path / "run"
    run.mkdir()
    evidence = run / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    ledger = Ledger(run)
    ledger.append("TEST", "pytest", "1", [], [ledger.ref(evidence)])
    with pytest.raises(SigningProviderError, match="provider unavailable"):
        write_manifest(run, "run", {}, {}, ledger, FailingSigner())
    assert not any((run / name).exists() for name in ("manifest.json", "manifest.sig", "pubkey.pem"))


def test_signing_audit_contains_metadata_without_payload_or_private_key(
    tmp_path: Path, caplog, monkeypatch
):
    key = Ed25519PrivateKey.generate()
    signer = PrivateKeySigner(key, "secret", "beta-release", "1")
    audit_logger = logging.getLogger("pandax.evidence")
    monkeypatch.setattr(logging.root.manager, "disable", logging.NOTSET)
    monkeypatch.setattr(audit_logger, "disabled", False)
    monkeypatch.setattr(audit_logger, "propagate", True)
    caplog.set_level(logging.INFO, logger="pandax.evidence")
    _seal(tmp_path / "audited", signer)
    message = next(record.message for record in caplog.records if "signing_audit" in record.message)
    assert '"run_id": "audited"' in message
    assert '"key_version": "1"' in message
    assert '"payload_sha256"' in message and '"latency_ms"' in message
    assert "PRIVATE KEY" not in message and '"files"' not in message


def test_registry_verifies_old_bundle_after_rotation_and_rejects_revocation(tmp_path: Path):
    old = PrivateKeySigner(Ed25519PrivateKey.generate(), "secret", "beta-release", "1")
    new = PrivateKeySigner(Ed25519PrivateKey.generate(), "secret", "beta-release", "2")
    old_run, new_run = tmp_path / "old", tmp_path / "new"
    _seal(old_run, old)
    _seal(new_run, new)

    registry_path = tmp_path / "registry.json"
    registry_path.write_text(json.dumps(_registry(old, "historical", new, "active")), encoding="utf-8")
    assert verify_bundle(old_run, trusted_registry=registry_path).status == "trusted"
    assert verify_bundle(new_run, trusted_registry=registry_path).status == "trusted"

    registry_path.write_text(json.dumps(_registry(old, "revoked", new, "active")), encoding="utf-8")
    revoked = verify_bundle(old_run, trusted_registry=registry_path)
    assert revoked.status == "untrusted"
    assert "revoked" in revoked.reason or any("revoked" in check.detail for check in revoked.checks)


def test_configured_registry_rejects_signer_mismatch():
    signer = PrivateKeySigner(Ed25519PrivateKey.generate(), "secret", "beta-release", "1")
    other = PrivateKeySigner(Ed25519PrivateKey.generate(), "secret", "beta-release", "1")
    encoded = base64.b64encode(json.dumps(_registry(other, "active")).encode()).decode()
    with pytest.raises(SigningConfigurationError, match="does not match"):
        configured_registry(signer, {"PANDAX_SIGNING_KEY_REGISTRY_B64": encoded})


def test_public_registry_endpoint_contains_no_private_material(monkeypatch):
    key = Ed25519PrivateKey.generate()
    env = {
        "PANDAX_ENVIRONMENT": "beta",
        "PANDAX_SIGNER_PROVIDER": "secret",
        "PANDAX_SIGNING_KEY_B64": _private_b64(key),
        "PANDAX_SIGNING_KEY_ID": "beta-release",
        "PANDAX_SIGNING_KEY_VERSION": "1",
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    from pandax.server import api

    response = TestClient(api).get("/.well-known/actis-signing-keys.json")
    assert response.status_code == 200
    body = response.text
    assert "PUBLIC KEY" in body
    assert "PRIVATE KEY" not in body
    assert env["PANDAX_SIGNING_KEY_B64"] not in body


def test_readiness_reports_public_signer_identity(monkeypatch):
    signer = PrivateKeySigner(Ed25519PrivateKey.generate(), "file", "test", "1")
    registry = parse_registry(_registry(signer, "active"))

    class Database:
        ready = True
        capacity = "ok"

        def as_dict(self):
            return {"ready": True, "capacity": "ok"}

    monkeypatch.setattr("pandax.portfolio_runtime.get_database_status", lambda: Database())
    monkeypatch.setattr("pandax.portfolio_runtime.get_storage_status", lambda: {"ready": True})
    monkeypatch.setattr("pandax.server._signing_state", lambda: (signer, registry))
    from pandax.server import api

    response = TestClient(api).get("/health/ready")
    assert response.status_code == 200
    assert response.json()["signing"] == {
        "provider": "file",
        "key_id": "test",
        "key_version": "1",
        "public_key_fingerprint": signer.identity.public_key_fingerprint,
        "registry_keys": 1,
    }
