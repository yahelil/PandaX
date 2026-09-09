from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from pandax import cli, server
from pandax.evidence import Ledger, load_or_create_key, write_manifest, write_public_key


def sealed_bundle(tmp_path: Path) -> tuple[Path, Path]:
    run = tmp_path / "run-trusted"
    run.mkdir()
    evidence = run / "evidence.json"
    evidence.write_text('{"result":"original"}', encoding="utf-8")
    ledger = Ledger(run)
    ledger.append("TEST", "pandax", "1", [], [ledger.ref(evidence)])
    private = tmp_path / "installation-signing-key.pem"
    key = load_or_create_key(private)
    write_manifest(run, run.name, {"name": "Device"}, {"pandax": "test"}, ledger, key)
    trusted = tmp_path / "trusted-public.pem"
    write_public_key(key, trusted)
    return run, trusted


def test_cli_requires_trust_unless_inspection_is_explicit(tmp_path, monkeypatch):
    run, trusted = sealed_bundle(tmp_path)
    monkeypatch.delenv("PANDAX_TRUSTED_KEY", raising=False)
    runner = CliRunner()

    missing = runner.invoke(cli.app, ["verify", str(run)])
    inspected = runner.invoke(cli.app, ["verify", str(run), "--inspect-only"])
    verified = runner.invoke(cli.app, ["verify", str(run), "--trusted-key", str(trusted)])

    assert missing.exit_code == 1
    assert "TRUST NOT ESTABLISHED" in missing.stdout
    assert inspected.exit_code == 0
    assert "Inspection-only mode" in inspected.stdout
    assert verified.exit_code == 0
    assert "TRUSTED" in verified.stdout


def test_cli_environment_key_and_explicit_key_precedence(tmp_path, monkeypatch):
    run, trusted = sealed_bundle(tmp_path)
    wrong_private = load_or_create_key(tmp_path / "wrong-private.pem")
    wrong_public = tmp_path / "wrong-public.pem"
    write_public_key(wrong_private, wrong_public)
    monkeypatch.setenv("PANDAX_TRUSTED_KEY", str(wrong_public))
    runner = CliRunner()

    environment = runner.invoke(cli.app, ["verify", str(run)])
    explicit = runner.invoke(cli.app, ["verify", str(run), "--trusted-key", str(trusted)])

    assert environment.exit_code == 1
    assert explicit.exit_code == 0


def test_key_export_writes_public_material_and_refuses_overwrite(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    runner = CliRunner()

    exported = runner.invoke(
        cli.app,
        ["key", "export-public", str(public), "--signing-key", str(private)],
    )
    repeated = runner.invoke(
        cli.app,
        ["key", "export-public", str(public), "--signing-key", str(private)],
    )

    assert exported.exit_code == 0
    assert "SHA-256 fingerprint" in exported.stdout
    assert b"BEGIN PUBLIC KEY" in public.read_bytes()
    assert b"PRIVATE" not in public.read_bytes()
    assert repeated.exit_code != 0
    assert "refusing to overwrite" in repeated.stderr


def test_server_returns_structured_trust_result(tmp_path, monkeypatch):
    run, trusted = sealed_bundle(tmp_path)
    monkeypatch.setattr(server, "OUT_DIR", tmp_path)
    client = TestClient(server.api)

    monkeypatch.delenv("PANDAX_TRUSTED_KEY", raising=False)
    untrusted = client.get(f"/api/verify/{run.name}")
    monkeypatch.setenv("PANDAX_TRUSTED_KEY", str(trusted))
    verified = client.get(f"/api/verify/{run.name}")

    assert untrusted.status_code == 200
    assert untrusted.json()["status"] == "untrusted"
    assert untrusted.json()["ok"] is False
    payload = verified.json()
    assert verified.status_code == 200
    assert payload["status"] == "trusted" and payload["ok"] is True
    assert payload["integrity_ok"] and payload["signature_valid"]
    assert payload["signer_trust"] == "trusted"
    assert payload["trusted_key_fingerprint"] == payload["bundle_key_fingerprint"]


def test_server_rejects_invalid_trusted_key_configuration(tmp_path, monkeypatch):
    run, _ = sealed_bundle(tmp_path)
    invalid = tmp_path / "not-a-key.pem"
    invalid.write_text("not a key", encoding="utf-8")
    monkeypatch.setattr(server, "OUT_DIR", tmp_path)
    monkeypatch.setenv("PANDAX_TRUSTED_KEY", str(invalid))

    response = TestClient(server.api).get(f"/api/verify/{run.name}")

    assert response.status_code == 503
    assert "trusted-key configuration error" in response.json()["detail"]
