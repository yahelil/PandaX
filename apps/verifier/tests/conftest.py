from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

VERIFIER_SRC = Path(__file__).resolve().parents[1] / "src"
if str(VERIFIER_SRC) not in sys.path:
    sys.path.insert(0, str(VERIFIER_SRC))

GENESIS = "0" * 64


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def ledger_record(
    output_path: str,
    output_digest: str,
    *,
    sequence: int = 0,
    previous: str = GENESIS,
) -> dict[str, object]:
    record: dict[str, object] = {
        "seq": sequence,
        "ts": "2026-09-09T08:00:00.000Z",
        "stage": "TEST",
        "tool": "fixture",
        "tool_version": "1",
        "inputs": [],
        "outputs": [{"path": output_path, "sha256": output_digest}],
        "params_sha256": digest(canonical({})),
        "prev_hash": previous,
    }
    record["record_hash"] = digest(canonical(record))
    return record


def write_public_key(key: Ed25519PrivateKey, path: Path) -> None:
    path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def seal(
    run: Path,
    key: Ed25519PrivateKey,
    records: list[dict[str, object]],
    *,
    schema: str = "pandax/manifest/v1",
) -> dict[str, object]:
    ledger = "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in records)
    (run / "ledger.jsonl").write_text(ledger, encoding="utf-8")
    files = []
    for path in sorted(run.rglob("*")):
        if path.is_file() and path.name not in {"manifest.json", "manifest.sig", "pubkey.pem"}:
            files.append(
                {
                    "path": path.relative_to(run).as_posix(),
                    "sha256": digest(path.read_bytes()),
                }
            )
    manifest: dict[str, object] = {
        "schema": schema,
        "run_id": run.name,
        "created": "2026-09-09T08:00:00.000Z",
        "product": {"name": "Café Sensor"},
        "tool_versions": {"fixture": "1"},
        "ledger_root": records[-1]["record_hash"] if records else GENESIS,
        "ledger_sha256": digest((run / "ledger.jsonl").read_bytes()),
        "ledger_records": len(records),
        "files": files,
        "signature_note": "fixture",
    }
    (run / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (run / "manifest.sig").write_text(key.sign(canonical(manifest)).hex(), encoding="ascii")
    write_public_key(key, run / "pubkey.pem")
    return manifest


@pytest.fixture
def sealed_bundle(tmp_path: Path) -> tuple[Path, Path, Ed25519PrivateKey]:
    run = tmp_path / "run-café"
    run.mkdir()
    evidence = run / "evidence.json"
    evidence.write_text('{"result":"original","name":"München"}', encoding="utf-8")
    key = Ed25519PrivateKey.generate()
    record = ledger_record("evidence.json", digest(evidence.read_bytes()))
    seal(run, key, [record])
    trusted = tmp_path / "trusted-public.pem"
    write_public_key(key, trusted)
    return run, trusted, key

