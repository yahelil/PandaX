"""The evidence layer is the POC's central claim, so it gets the most tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pandax import evidence
from pandax.evidence import (
    GENESIS,
    Ledger,
    canonical,
    load_or_create_key,
    record_digest,
    verify_bundle,
    verify_run,
    write_public_key,
    write_manifest,
)


def _checks(run_dir: Path) -> dict[str, bool]:
    return {c.name: c.ok for c in verify_run(run_dir)}


def _ok(results: dict[str, bool], prefix: str) -> bool:
    """Look a check up by prefix so counts in the name are not load-bearing."""
    return next(v for k, v in results.items() if k.startswith(prefix))


def _detail(run_dir: Path, prefix: str) -> str:
    for check in verify_run(run_dir):
        if check.name.startswith(prefix):
            return check.detail
    return ""


def _key_path(run_dir: Path) -> Path:
    return run_dir.parent / f"{run_dir.name}-signing-key.pem"


def seal(run_dir: Path, files: dict[str, str], stages: int = 3):
    for name, body in files.items():
        (run_dir / name).write_text(body, encoding="utf-8")
    ledger = Ledger(run_dir)
    names = list(files)
    for i in range(stages):
        target = run_dir / names[i % len(names)]
        ledger.append(f"S{i}", "tool", "1.0", [], [ledger.ref(target)], {"i": i})
    key = load_or_create_key(_key_path(run_dir))
    manifest = write_manifest(run_dir, "run-test", {}, {"syft": "1.51.1"}, ledger, key)
    return ledger, manifest


# --- canonicalisation -------------------------------------------------------


def test_canonical_is_key_order_independent():
    assert canonical({"b": 1, "a": 2}) == canonical({"a": 2, "b": 1})


def test_canonical_is_reproducible_with_stdlib_only():
    """An auditor must be able to recompute a digest without PandaX installed."""
    record = {"seq": 0, "stage": "S1", "record_hash": "ignored"}
    expected = hashlib.sha256(
        json.dumps(
            {"seq": 0, "stage": "S1"}, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    assert record_digest(record) == expected


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_canonical_rejects_non_standard_json_numbers(value: float):
    with pytest.raises(ValueError, match="Out of range float values"):
        canonical({"value": value})


# --- chain ------------------------------------------------------------------


def test_chain_links_to_genesis_and_forward(run_dir: Path):
    ledger, _ = seal(run_dir, {"a.json": "{}", "b.json": "{}"}, stages=3)
    records = Ledger.load(run_dir)
    assert records[0]["prev_hash"] == GENESIS
    for earlier, later in zip(records, records[1:]):
        assert later["prev_hash"] == earlier["record_hash"]
    assert ledger.root == records[-1]["record_hash"]


def test_clean_bundle_passes_every_check(run_dir: Path):
    seal(run_dir, {"a.json": '{"x":1}'})
    assert all(_checks(run_dir).values())


# --- tamper detection -------------------------------------------------------


def test_changed_output_file_is_caught(run_dir: Path):
    seal(run_dir, {"a.json": '{"x":1}'})
    (run_dir / "a.json").write_text('{"x":2}', encoding="utf-8")
    results = _checks(run_dir)
    assert results["ed25519 signature"] is True  # manifest itself is untouched
    assert _detail(run_dir, "file digests").startswith("a.json")
    assert results["stage outputs re-hashed"] is False
    assert "a.json" in _detail(run_dir, "stage outputs")


def test_edited_manifest_breaks_the_signature(run_dir: Path):
    seal(run_dir, {"a.json": "{}"})
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest["product"] = {"name": "something else"}
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    assert _checks(run_dir)["ed25519 signature"] is False


def test_rewritten_ledger_record_is_caught_at_the_right_link(run_dir: Path):
    seal(run_dir, {"a.json": "{}", "b.json": "{}"}, stages=3)
    records = Ledger.load(run_dir)
    records[1]["tool"] = "not-the-tool-that-ran"
    (run_dir / "ledger.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
    )
    results = _checks(run_dir)
    assert _ok(results, "hash chain") is False
    assert "seq 1" in _detail(run_dir, "hash chain")


def test_recomputed_chain_still_fails_against_the_signed_root(run_dir: Path):
    """The strongest attack: rebuild the whole chain so it is internally valid."""
    seal(run_dir, {"a.json": "{}", "b.json": "{}"}, stages=3)
    records = Ledger.load(run_dir)
    records[1]["tool"] = "forged"
    prev = GENESIS
    for record in records:  # re-link and re-hash so the chain is self-consistent
        record["prev_hash"] = prev
        record["record_hash"] = record_digest(record)
        prev = record["record_hash"]
    (run_dir / "ledger.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
    )
    results = _checks(run_dir)
    assert _ok(results, "hash chain") is True  # internally consistent...
    assert results["ledger file digest"] is False  # ...but not what was signed
    assert results["chain head vs manifest"] is False


def test_deleted_file_is_caught(run_dir: Path):
    seal(run_dir, {"a.json": "{}"})
    (run_dir / "a.json").unlink()
    assert "missing" in _detail(run_dir, "file digests")


def test_missing_manifest_reports_cleanly(run_dir: Path):
    checks = verify_run(run_dir)
    assert len(checks) == 1 and checks[0].ok is False


# --- signing ----------------------------------------------------------------


def test_key_is_created_once_and_reused(tmp_path: Path):
    path = tmp_path / "k.pem"
    first = load_or_create_key(path)
    second = load_or_create_key(path)
    assert first.private_bytes_raw() == second.private_bytes_raw()


def test_signature_does_not_verify_under_a_different_key(run_dir: Path):
    seal(run_dir, {"a.json": "{}"})
    from cryptography.hazmat.primitives import serialization

    other = Ed25519PrivateKey.generate()
    (run_dir / evidence.PUBKEY_NAME).write_bytes(
        other.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    assert _checks(run_dir)["ed25519 signature"] is False


def test_manifest_excludes_its_own_signature_files(run_dir: Path):
    _, manifest = seal(run_dir, {"a.json": "{}"})
    listed = {f["path"] for f in manifest["files"]}
    assert listed.isdisjoint({"manifest.json", "manifest.sig", "pubkey.pem"})


def test_manifest_refuses_private_key_pem_inside_bundle(run_dir: Path):
    evidence_file = run_dir / "evidence.json"
    evidence_file.write_text("{}", encoding="utf-8")
    ledger = Ledger(run_dir)
    ledger.append("TEST", "tool", "1", [], [ledger.ref(evidence_file)])
    key = load_or_create_key(run_dir / "private.pem")

    with pytest.raises(ValueError, match="private key PEM: private.pem"):
        write_manifest(run_dir, "run-test", {}, {"tool": "1"}, ledger, key)

    assert not (run_dir / "manifest.json").exists()


# --- external trust --------------------------------------------------------


def test_correct_external_key_establishes_trust(run_dir: Path, tmp_path: Path):
    seal(run_dir, {"a.json": "{}"})
    trusted = tmp_path / "trusted.pem"
    key = load_or_create_key(_key_path(run_dir))
    fingerprint = write_public_key(key, trusted)

    result = verify_bundle(run_dir, trusted)

    assert result.status == "trusted"
    assert result.ok and result.integrity_ok and result.signature_valid
    assert result.signer_trust == "trusted"
    assert result.bundle_key_fingerprint == result.trusted_key_fingerprint == fingerprint


def test_missing_external_key_never_claims_trust(run_dir: Path):
    seal(run_dir, {"a.json": "{}"})

    result = verify_bundle(run_dir)

    assert result.status == "untrusted"
    assert not result.ok
    assert result.integrity_ok and result.signature_valid
    assert result.signer_trust == "not_configured"


def test_wrong_external_key_is_untrusted_not_tampered(run_dir: Path, tmp_path: Path):
    seal(run_dir, {"a.json": "{}"})
    wrong = tmp_path / "wrong.pem"
    write_public_key(Ed25519PrivateKey.generate(), wrong)

    result = verify_bundle(run_dir, wrong)

    assert result.status == "untrusted"
    assert result.integrity_ok and result.signature_valid
    assert result.signer_trust == "untrusted"


def test_attacker_resealed_bundle_fails_external_trust(run_dir: Path, tmp_path: Path):
    seal(run_dir, {"a.json": '{"owner":"original"}'})
    trusted = tmp_path / "trusted.pem"
    original = load_or_create_key(_key_path(run_dir))
    write_public_key(original, trusted)

    (run_dir / "a.json").write_text('{"owner":"attacker"}', encoding="utf-8")
    (run_dir / evidence.LEDGER_NAME).unlink()
    ledger = Ledger(run_dir)
    ledger.append("S0", "attacker", "1.0", [], [ledger.ref(run_dir / "a.json")])
    attacker = Ed25519PrivateKey.generate()
    write_manifest(run_dir, "run-test", {}, {"tool": "attacker"}, ledger, attacker)

    result = verify_bundle(run_dir, trusted)

    assert result.integrity_ok and result.signature_valid
    assert result.status == "untrusted"
    assert result.signer_trust == "untrusted"


def test_missing_required_bundle_file_is_incomplete(run_dir: Path):
    seal(run_dir, {"a.json": "{}"})
    (run_dir / "manifest.sig").unlink()

    result = verify_bundle(run_dir)

    assert result.status == "incomplete"


def test_malformed_manifest_is_incomplete_instead_of_crashing(run_dir: Path):
    (run_dir / "manifest.json").write_text("{not-json", encoding="utf-8")

    result = verify_bundle(run_dir)

    assert result.status == "incomplete"
    assert not result.ok


def test_changed_evidence_is_invalid_even_with_trusted_key(run_dir: Path, tmp_path: Path):
    seal(run_dir, {"a.json": "{}"})
    trusted = tmp_path / "trusted.pem"
    write_public_key(load_or_create_key(_key_path(run_dir)), trusted)
    (run_dir / "a.json").write_text('{"changed":true}', encoding="utf-8")

    result = verify_bundle(run_dir, trusted)

    assert result.status == "invalid"
    assert not result.integrity_ok
