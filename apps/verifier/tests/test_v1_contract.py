from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pandax.evidence import (
    Ledger,
    canonical,
    verify_bundle as engine_verify_bundle,
    write_manifest,
    write_public_key,
)
from pandax_verifier.cli import main
from pandax_verifier.verification import canonical as verifier_canonical
from pandax_verifier.verification import verify_bundle

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "fixtures" / "evidence-v1"

CASES = [
    ("valid", "trusted-valid.pem", "trusted", 0),
    ("tampered", "trusted-valid.pem", "invalid", 1),
    ("missing", "trusted-valid.pem", "incomplete", 1),
    ("extra", "trusted-valid.pem", "invalid", 1),
    ("wrong-key", "trusted-wrong.pem", "untrusted", 1),
]


@pytest.mark.parametrize(("bundle", "key", "status", "exit_code"), CASES)
def test_public_v1_fixtures_lock_both_readers_and_cli(
    bundle: str,
    key: str,
    status: str,
    exit_code: int,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = FIXTURES / bundle
    trusted_key = FIXTURES / key

    engine_result = engine_verify_bundle(source, trusted_key)
    standalone_result = verify_bundle(source, trusted_key)
    cli_exit = main([str(source), "--trusted-key", str(trusted_key), "--json"])
    cli_result = json.loads(capsys.readouterr().out)

    assert engine_result.status == standalone_result.status == cli_result["status"] == status
    engine_payload = engine_result.as_dict()
    assert engine_payload["schema"] == standalone_result.schema == cli_result["schema"]
    assert engine_payload["signer_trust"] in {
        "trusted",
        "untrusted",
        "not_configured",
    }
    assert {check["category"] for check in engine_payload["checks"]} <= {
        "integrity",
        "bundle_signature",
        "signer_trust",
    }
    for field in ("bundle_key_fingerprint", "trusted_key_fingerprint"):
        fingerprint = engine_payload[field]
        assert fingerprint is None or (
            len(fingerprint) == 64
            and all(character in "0123456789abcdef" for character in fingerprint)
        )
    assert cli_exit == exit_code


def test_published_schema_ids_and_required_manifest_fields_are_frozen() -> None:
    schema_dir = ROOT / "docs" / "schemas"
    manifest_schema = json.loads(
        (schema_dir / "manifest-v1.schema.json").read_text(encoding="utf-8")
    )
    result_schema = json.loads(
        (schema_dir / "verification-result-v1.schema.json").read_text(encoding="utf-8")
    )
    ledger_schema = json.loads(
        (schema_dir / "ledger-record-v1.schema.json").read_text(encoding="utf-8")
    )
    manifest = json.loads(
        (FIXTURES / "valid" / "manifest.json").read_text(encoding="utf-8")
    )

    assert manifest_schema["properties"]["schema"]["const"] == "actis/manifest/v1"
    assert result_schema["properties"]["schema"]["const"] == "actis/verification-result/v1"
    assert ledger_schema["$id"].endswith("/ledger-record-v1.schema.json")
    assert set(manifest_schema["required"]) <= set(manifest)
    assert manifest["schema"] == "actis/manifest/v1"


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_both_writers_reject_non_standard_json_numbers(value: float) -> None:
    with pytest.raises(ValueError):
        canonical({"value": value})
    with pytest.raises(ValueError):
        verifier_canonical({"value": value})


def test_new_writer_uses_actis_v1_and_readers_keep_legacy_v1(tmp_path: Path) -> None:
    run = tmp_path / "bundle"
    run.mkdir()
    evidence = run / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    ledger = Ledger(run)
    ledger.append("TEST", "actis", "1", [], [ledger.ref(evidence)])
    signing_key = Ed25519PrivateKey.generate()
    trusted_key = tmp_path / "trusted.pem"
    write_public_key(signing_key, trusted_key)

    manifest = write_manifest(run, "run", {}, {"actis": "1"}, ledger, signing_key)
    assert manifest["schema"] == "actis/manifest/v1"
    assert verify_bundle(run, trusted_key).status == "trusted"

    manifest["schema"] = "pandax/manifest/v1"
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run / "manifest.sig").write_text(
        signing_key.sign(canonical(manifest)).hex(), encoding="ascii"
    )

    assert engine_verify_bundle(run, trusted_key).status == "trusted"
    assert verify_bundle(run, trusted_key).status == "trusted"
