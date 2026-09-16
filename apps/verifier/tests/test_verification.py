from __future__ import annotations

import json
import stat
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from conftest import canonical, digest, ledger_record, seal, write_public_key
from pandax_verifier.bundle import BundleError, open_bundle
from pandax_verifier.cli import main
from pandax_verifier.verification import TrustedKeyConfigurationError, verify_bundle


def _check(result, name: str):
    return next(check for check in result.checks if check.name == name)


def _zip_directory(source: Path, output: Path) -> None:
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source).as_posix())


def test_correct_external_key_is_trusted_for_directory_and_zip(sealed_bundle, tmp_path):
    run, trusted, _ = sealed_bundle
    archive = tmp_path / "evidence.zip"
    _zip_directory(run, archive)

    directory_result = verify_bundle(run, trusted)
    archive_result = verify_bundle(archive, trusted)

    assert directory_result.status == archive_result.status == "trusted"
    assert directory_result.ok and archive_result.ok
    assert directory_result.integrity_ok and directory_result.signature_valid
    assert directory_result.bundle_key_fingerprint == directory_result.trusted_key_fingerprint


def test_no_key_is_untrusted_but_explicit_inspection_can_exit_successfully(
    sealed_bundle, capsys
):
    run, _, _ = sealed_bundle

    result = verify_bundle(run)
    normal_exit = main([str(run), "--json"])
    normal_json = json.loads(capsys.readouterr().out)
    inspect_exit = main([str(run), "--inspect-only"])
    inspected_text = capsys.readouterr().out

    assert result.status == "untrusted" and not result.ok
    assert result.signer_trust == "not_configured"
    assert normal_exit == 1 and normal_json["schema"] == "actis/verification-result/v1"
    assert inspect_exit == 0
    assert "TRUST NOT ESTABLISHED" in inspected_text


def test_wrong_key_and_attacker_resealed_bundle_are_untrusted(sealed_bundle):
    run, trusted, _ = sealed_bundle
    original_fingerprint = verify_bundle(run, trusted).trusted_key_fingerprint
    attacker = Ed25519PrivateKey.generate()
    (run / "evidence.json").write_text('{"result":"attacker"}', encoding="utf-8")
    record = ledger_record("evidence.json", digest((run / "evidence.json").read_bytes()))
    seal(run, attacker, [record])

    result = verify_bundle(run, trusted)

    assert result.status == "untrusted"
    assert result.integrity_ok and result.signature_valid
    assert result.signer_trust == "untrusted"
    assert result.bundle_key_fingerprint != original_fingerprint


def test_versioned_registry_trusts_historical_key_and_rejects_revoked(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    evidence = run / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    key = Ed25519PrivateKey.generate()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    fingerprint = digest(
        key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    signing = {
        "provider": "secret",
        "algorithm": "Ed25519",
        "key_id": "beta-release",
        "key_version": "1",
        "public_key_fingerprint": fingerprint,
    }
    seal(
        run,
        key,
        [ledger_record("evidence.json", digest(evidence.read_bytes()))],
        signing=signing,
    )
    current = Ed25519PrivateKey.generate()
    current_pem = current.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    current_fingerprint = digest(
        current.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    registry = {
        "schema": "actis/signing-key-registry/v1",
        "keys": [
            {**signing, "public_key_pem": public_pem, "status": "historical"},
            {
                "provider": "secret",
                "algorithm": "Ed25519",
                "key_id": "beta-release",
                "key_version": "2",
                "public_key_fingerprint": current_fingerprint,
                "public_key_pem": current_pem,
                "status": "active",
            },
        ],
    }
    registry_path = tmp_path / "registry.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    assert verify_bundle(run, trusted_registry=registry_path).status == "trusted"
    assert main([str(run), "--trusted-key-registry", str(registry_path), "--json"]) == 0

    registry["keys"][0]["status"] = "revoked"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    result = verify_bundle(run, trusted_registry=registry_path)
    assert result.status == "untrusted"
    assert any("revoked" in check.detail for check in result.checks)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("changed", "invalid"),
        ("deleted", "incomplete"),
        ("unexpected", "invalid"),
    ],
)
def test_file_changes_are_detected(sealed_bundle, mutation, expected):
    run, trusted, _ = sealed_bundle
    evidence = run / "evidence.json"
    if mutation == "changed":
        evidence.write_text("changed", encoding="utf-8")
    elif mutation == "deleted":
        evidence.unlink()
    else:
        (run / "not-in-manifest.txt").write_text("surprise", encoding="utf-8")

    result = verify_bundle(run, trusted)

    assert result.status == expected
    assert not result.integrity_ok


def test_unsupported_schema_and_malformed_signature_are_incomplete(sealed_bundle):
    run, trusted, key = sealed_bundle
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["schema"] = "pandax/manifest/v99"
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run / "manifest.sig").write_text(key.sign(canonical(manifest)).hex(), encoding="ascii")
    unsupported = verify_bundle(run, trusted)

    (run / "manifest.sig").write_text("not-a-signature", encoding="ascii")
    malformed = verify_bundle(run, trusted)

    assert unsupported.status == "incomplete"
    assert malformed.status == "incomplete"


def test_ledger_count_sequence_chain_and_outputs_are_checked(sealed_bundle):
    run, trusted, key = sealed_bundle
    evidence_digest = digest((run / "evidence.json").read_bytes())
    first = ledger_record("evidence.json", evidence_digest, sequence=4)
    second = ledger_record(
        "evidence.json",
        "f" * 64,
        sequence=3,
        previous=first["record_hash"],
    )
    seal(run, key, [second, first])

    result = verify_bundle(run, trusted)

    assert result.status == "invalid"
    assert not _check(result, "ledger sequence").ok
    assert not _check(result, "hash chain (2 links)").ok
    assert not _check(result, "stage outputs re-hashed").ok


def test_truncated_ledger_is_detected_even_when_file_hash_is_resealed(sealed_bundle):
    run, trusted, key = sealed_bundle
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    (run / "ledger.jsonl").write_text("", encoding="utf-8")
    manifest["ledger_sha256"] = digest(b"")
    for entry in manifest["files"]:
        if entry["path"] == "ledger.jsonl":
            entry["sha256"] = digest(b"")
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run / "manifest.sig").write_text(key.sign(canonical(manifest)).hex(), encoding="ascii")

    result = verify_bundle(run, trusted)

    assert result.status == "invalid"
    assert not _check(result, "ledger record count").ok
    assert not _check(result, "chain head vs manifest").ok


def test_trusted_key_inside_directory_bundle_is_rejected(sealed_bundle):
    run, _, _ = sealed_bundle

    with pytest.raises(TrustedKeyConfigurationError, match="stored separately"):
        verify_bundle(run, run / "pubkey.pem")


def test_trusted_registry_inside_directory_bundle_is_rejected(sealed_bundle):
    run, _, _ = sealed_bundle
    registry = run / "registry.json"
    registry.write_text("{}", encoding="utf-8")

    with pytest.raises(TrustedKeyConfigurationError, match="stored separately"):
        verify_bundle(run, trusted_registry=registry)


@pytest.mark.parametrize(
    "unsafe_name",
    ["../escape.txt", "/absolute.txt", "C:/drive.txt", "deep/../../escape.txt"],
)
def test_zip_unsafe_paths_are_rejected(tmp_path, unsafe_name):
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(unsafe_name, "bad")

    result = verify_bundle(archive)

    assert result.status == "incomplete"
    assert any(
        word in result.reason.lower() for word in ("unsafe", "absolute", "missing")
    )


def test_zip_duplicate_case_collisions_are_rejected(tmp_path):
    archive = tmp_path / "collision.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("Evidence.json", "one")
        output.writestr("evidence.json", "two")

    with pytest.raises(BundleError, match="case-colliding"):
        open_bundle(archive)


def test_zip_symbolic_links_are_rejected(tmp_path):
    archive = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(info, "target")

    with pytest.raises(BundleError, match="symbolic link"):
        open_bundle(archive)


def test_zip_size_and_entry_limits_are_enforced(tmp_path, monkeypatch):
    from pandax_verifier import bundle

    archive = tmp_path / "limits.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("one", "1234")
        output.writestr("two", "5678")

    monkeypatch.setattr(bundle, "MAX_TOTAL_BYTES", 7)
    with pytest.raises(BundleError, match="safety limit"):
        open_bundle(archive)

    monkeypatch.setattr(bundle, "MAX_TOTAL_BYTES", 100)
    monkeypatch.setattr(bundle, "MAX_ENTRIES", 1)
    with pytest.raises(BundleError, match="more than 1"):
        open_bundle(archive)


def test_malformed_trusted_key_is_configuration_exit_2(sealed_bundle, tmp_path, capsys):
    run, _, _ = sealed_bundle
    bad_key = tmp_path / "bad.pem"
    bad_key.write_text("not a key", encoding="utf-8")

    exit_code = main([str(run), "--trusted-key", str(bad_key), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert payload["schema"] == "actis/verifier-error/v1"
    assert payload["error"] == "trusted_key_configuration"


def test_manifest_with_duplicate_json_key_is_rejected(sealed_bundle):
    run, trusted, _ = sealed_bundle
    (run / "manifest.json").write_text(
        '{"schema":"actis/manifest/v1","schema":"actis/manifest/v1"}',
        encoding="utf-8",
    )

    result = verify_bundle(run, trusted)

    assert result.status == "incomplete"
    assert "duplicate JSON key" in _check(result, "manifest structure").detail
