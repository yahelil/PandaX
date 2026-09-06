"""Hash-chained evidence ledger and Ed25519 bundle signing.

This is the part of the blueprint's architecture that nothing else addresses:
a compliance vendor's output is worthless if a regulator cannot check that it
was not edited after the fact.

Design goals, in order:
  1. Independently reproducible - every hash here can be recomputed with
     nothing but stdlib hashlib and json. Auditing requires no PandaX code.
  2. Tamper-evident - one flipped byte breaks a *named* link in the chain.
  3. Honest - Ed25519 over a locally generated key proves INTEGRITY, not
     legal identity. Production needs an eIDAS qualified seal (PAdES-B-LTA).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

GENESIS = "0" * 64
LEDGER_NAME = "ledger.jsonl"
MANIFEST_NAME = "manifest.json"
SIG_NAME = "manifest.sig"
PUBKEY_NAME = "pubkey.pem"

SIGNING_NOTE = (
    "Ed25519 over the canonical JSON of manifest.json (UTF-8, sorted keys, no "
    "whitespace). Proves integrity of this bundle, NOT the legal identity of "
    "the signer - a production CRA deployment requires an eIDAS qualified "
    "electronic seal."
)


# --- primitives -------------------------------------------------------------


def canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding. The single source of truth for hashing."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def record_digest(record: dict[str, Any]) -> str:
    """Hash of a ledger record with its own hash field excluded."""
    trimmed = {k: v for k, v in record.items() if k != "record_hash"}
    return sha256_bytes(canonical(trimmed))


# --- ledger -----------------------------------------------------------------


@dataclass
class FileRef:
    path: str
    sha256: str

    def as_dict(self) -> dict[str, str]:
        return {"path": self.path, "sha256": self.sha256}


class Ledger:
    """Append-only, hash-chained record of what each stage consumed and produced."""

    def __init__(self, run_dir: Path):
        self.run_dir = Path(run_dir)
        self.path = self.run_dir / LEDGER_NAME
        self.records: list[dict[str, Any]] = []

    def rel(self, path: Path) -> str:
        """Paths are stored relative to the run dir so bundles stay portable."""
        return Path(path).resolve().relative_to(self.run_dir.resolve()).as_posix()

    def ref(self, path: Path) -> FileRef:
        return FileRef(self.rel(path), sha256_file(Path(path)))

    def append(
        self,
        stage: str,
        tool: str,
        tool_version: str,
        inputs: list[FileRef],
        outputs: list[FileRef],
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        record: dict[str, Any] = {
            "seq": len(self.records),
            "ts": _utc_now(),
            "stage": stage,
            "tool": tool,
            "tool_version": tool_version,
            "inputs": [i.as_dict() for i in inputs],
            "outputs": [o.as_dict() for o in outputs],
            "params_sha256": sha256_bytes(canonical(params or {})),
            "prev_hash": self.records[-1]["record_hash"] if self.records else GENESIS,
        }
        record["record_hash"] = record_digest(record)
        self.records.append(record)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record

    @property
    def root(self) -> str:
        """Head of the chain - one hash committing to the entire run."""
        return self.records[-1]["record_hash"] if self.records else GENESIS

    @staticmethod
    def load(run_dir: Path) -> list[dict[str, Any]]:
        path = Path(run_dir) / LEDGER_NAME
        if not path.exists():
            return []
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]


def _utc_now() -> str:
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")
    return stamp.replace("+00:00", "Z")


# --- signing ----------------------------------------------------------------


def load_or_create_key(key_path: Path) -> Ed25519PrivateKey:
    key_path = Path(key_path)
    if key_path.exists():
        loaded = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise TypeError(f"{key_path} is not an Ed25519 private key")
        return loaded
    key = Ed25519PrivateKey.generate()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    try:
        key_path.chmod(0o600)
    except OSError:
        pass  # best effort; Windows ACLs do not map cleanly
    return key


def write_manifest(
    run_dir: Path,
    run_id: str,
    product: dict[str, Any],
    tool_versions: dict[str, str],
    ledger: Ledger,
    key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Digest every file in the bundle, commit to the ledger head, and sign."""
    run_dir = Path(run_dir)
    skip = {MANIFEST_NAME, SIG_NAME, PUBKEY_NAME}
    files: list[dict[str, str]] = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(run_dir).as_posix()
        if rel in skip:
            continue  # cannot commit to files that do not exist yet
        files.append({"path": rel, "sha256": sha256_file(path)})

    manifest = {
        "schema": "pandax/manifest/v1",
        "run_id": run_id,
        "created": _utc_now(),
        "product": product,
        "tool_versions": tool_versions,
        "ledger_root": ledger.root,
        "ledger_sha256": sha256_file(ledger.path) if ledger.path.exists() else GENESIS,
        "ledger_records": len(ledger.records),
        "files": files,
        "signature_note": SIGNING_NOTE,
    }

    (run_dir / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (run_dir / SIG_NAME).write_text(key.sign(canonical(manifest)).hex(), encoding="utf-8")
    (run_dir / PUBKEY_NAME).write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return manifest


# --- verification -----------------------------------------------------------


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


def verify_run(run_dir: Path) -> list[Check]:
    """Re-derive everything from scratch. Never trusts a value it did not recompute."""
    run_dir = Path(run_dir)
    checks: list[Check] = []

    manifest_path = run_dir / MANIFEST_NAME
    if not manifest_path.exists():
        return [Check("manifest present", False, f"{MANIFEST_NAME} not found")]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    checks.append(Check("manifest present", True, f"run {manifest.get('run_id', '?')}"))

    # 1. Ed25519 signature over the canonical manifest.
    try:
        pub = serialization.load_pem_public_key((run_dir / PUBKEY_NAME).read_bytes())
        if not isinstance(pub, Ed25519PublicKey):
            raise ValueError("public key is not Ed25519")
        sig = bytes.fromhex((run_dir / SIG_NAME).read_text(encoding="utf-8").strip())
        pub.verify(sig, canonical(manifest))
        checks.append(Check("ed25519 signature", True, "manifest signature valid"))
    except InvalidSignature:
        checks.append(
            Check("ed25519 signature", False, "signature does not match manifest content")
        )
    except (ValueError, OSError) as exc:
        checks.append(Check("ed25519 signature", False, f"{type(exc).__name__}: {exc}"))

    # 2. Every file digest recorded in the manifest.
    listed = manifest.get("files", [])
    bad_files = []
    for entry in listed:
        target = run_dir / entry["path"]
        if not target.exists():
            bad_files.append(f"{entry['path']} (missing)")
        elif sha256_file(target) != entry["sha256"]:
            bad_files.append(f"{entry['path']} (digest mismatch)")
    checks.append(
        Check(
            f"file digests ({len(listed)} files)",
            not bad_files,
            "all match" if not bad_files else "; ".join(bad_files),
        )
    )

    # 3. Ledger file digest as committed by the signed manifest.
    ledger_path = run_dir / LEDGER_NAME
    ledger_ok = (
        ledger_path.exists()
        and sha256_file(ledger_path) == manifest.get("ledger_sha256")
    )
    checks.append(
        Check(
            "ledger file digest",
            ledger_ok,
            "matches manifest" if ledger_ok else "ledger.jsonl altered or missing",
        )
    )

    # 4. Chain integrity, link by link, naming the exact break.
    records = Ledger.load(run_dir)
    prev = GENESIS
    broken: list[str] = []
    for rec in records:
        if record_digest(rec) != rec.get("record_hash"):
            broken.append(f"seq {rec.get('seq')} {rec.get('stage')}: record_hash")
        if rec.get("prev_hash") != prev:
            broken.append(f"seq {rec.get('seq')} {rec.get('stage')}: prev_hash")
        prev = rec.get("record_hash", "")
    checks.append(
        Check(
            f"hash chain ({len(records)} links)",
            not broken,
            "unbroken" if not broken else "; ".join(broken),
        )
    )

    # 5. The chain head must be what the signed manifest committed to.
    head_ok = bool(records) and prev == manifest.get("ledger_root")
    checks.append(
        Check(
            "chain head vs manifest",
            head_ok,
            f"root {str(manifest.get('ledger_root'))[:16]}..."
            if head_ok
            else "ledger head does not match the signed manifest",
        )
    )

    # 6. Stage outputs must still hash to what the producing stage recorded.
    stage_bad: list[str] = []
    for rec in records:
        for out in rec.get("outputs", []):
            target = run_dir / out["path"]
            if not target.exists():
                stage_bad.append(f"{rec['stage']} -> {out['path']} (missing)")
            elif sha256_file(target) != out["sha256"]:
                stage_bad.append(f"{rec['stage']} -> {out['path']} (digest mismatch)")
    checks.append(
        Check(
            "stage outputs re-hashed",
            not stage_bad,
            "all match" if not stage_bad else "; ".join(stage_bad),
        )
    )

    return checks
