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
    "whitespace). The bundled public key supports internal signature inspection "
    "but is not a trust anchor. Signer trust requires a public key obtained "
    "separately. This identifies a configured signing installation, not a legal "
    "person or an eIDAS qualified electronic seal."
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
    category: str = "integrity"
    problem: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "detail": self.detail,
            "category": self.category,
        }


@dataclass
class VerificationResult:
    status: str
    integrity_ok: bool
    signature_valid: bool
    signer_trust: str
    reason: str
    checks: list[Check]
    bundle_key_fingerprint: str = ""
    trusted_key_fingerprint: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "trusted"

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "ok": self.ok,
            "integrity_ok": self.integrity_ok,
            "signature_valid": self.signature_valid,
            "signer_trust": self.signer_trust,
            "reason": self.reason,
            "bundle_key_fingerprint": self.bundle_key_fingerprint,
            "trusted_key_fingerprint": self.trusted_key_fingerprint,
            "checks": [check.as_dict() for check in self.checks],
        }


class TrustedKeyConfigurationError(ValueError):
    """The configured trust anchor cannot be used for Ed25519 verification."""


def _parse_public_key(blob: bytes) -> Ed25519PublicKey:
    loaded = serialization.load_pem_public_key(blob)
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("public key is not Ed25519")
    return loaded


def load_trusted_key(path: Path) -> Ed25519PublicKey:
    path = Path(path)
    try:
        return _parse_public_key(path.read_bytes())
    except (OSError, TypeError, ValueError) as exc:
        raise TrustedKeyConfigurationError(
            f"trusted key cannot be loaded from {path}: {exc}"
        ) from exc


def public_key_fingerprint(key: Ed25519PublicKey) -> str:
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_bytes(der)


def write_public_key(key: Ed25519PrivateKey, output: Path, force: bool = False) -> str:
    """Export only the public half and return its stable SHA-256 fingerprint."""
    output = Path(output)
    if output.exists() and not force:
        raise FileExistsError(f"refusing to overwrite existing file: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    public = key.public_key()
    output.write_bytes(
        public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return public_key_fingerprint(public)


def _safe_bundle_path(run_dir: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError("file path must be a non-empty string")
    root = Path(run_dir).resolve()
    target = (root / relative).resolve()
    if not target.is_relative_to(root):
        raise ValueError(f"file path escapes bundle: {relative}")
    return target


def verify_run(run_dir: Path) -> list[Check]:
    """Inspect internal integrity without claiming that the signer is trusted."""
    run_dir = Path(run_dir)
    checks: list[Check] = []

    manifest_path = run_dir / MANIFEST_NAME
    if not manifest_path.exists():
        return [
            Check(
                "manifest present",
                False,
                f"{MANIFEST_NAME} not found",
                problem="missing",
            )
        ]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("manifest must be a JSON object")
    except (OSError, ValueError, TypeError) as exc:
        return [
            Check(
                "manifest present",
                False,
                f"{MANIFEST_NAME} is unreadable: {exc}",
                problem="malformed",
            )
        ]
    checks.append(Check("manifest present", True, f"run {manifest.get('run_id', '?')}"))

    # 1. Ed25519 signature against the key advertised by the bundle. This is
    # useful inspection evidence, but it is deliberately not a trust decision.
    try:
        pub = _parse_public_key((run_dir / PUBKEY_NAME).read_bytes())
        sig = bytes.fromhex((run_dir / SIG_NAME).read_text(encoding="utf-8").strip())
        pub.verify(sig, canonical(manifest))
        checks.append(
            Check(
                "ed25519 signature",
                True,
                "manifest signature valid against bundled public key",
                category="signature",
            )
        )
    except InvalidSignature:
        checks.append(
            Check(
                "ed25519 signature",
                False,
                "signature does not match manifest content",
                category="signature",
                problem="mismatch",
            )
        )
    except FileNotFoundError as exc:
        checks.append(
            Check(
                "ed25519 signature",
                False,
                f"required signature file is missing: {exc.filename}",
                category="signature",
                problem="missing",
            )
        )
    except (ValueError, TypeError, OSError) as exc:
        checks.append(
            Check(
                "ed25519 signature",
                False,
                f"signature or bundled public key is malformed: {exc}",
                category="signature",
                problem="malformed",
            )
        )

    # 2. Every file digest recorded in the manifest.
    listed = manifest.get("files")
    bad_files: list[str] = []
    file_problem = ""
    if not isinstance(listed, list):
        listed = []
        bad_files.append("manifest files must be a list")
        file_problem = "malformed"
    for entry in listed:
        try:
            if not isinstance(entry, dict) or not isinstance(entry.get("sha256"), str):
                raise ValueError("entry must contain path and sha256 strings")
            target = _safe_bundle_path(run_dir, entry.get("path"))
            if not target.is_file():
                bad_files.append(f"{entry.get('path')} (missing)")
                file_problem = "missing"
            elif sha256_file(target) != entry["sha256"]:
                bad_files.append(f"{entry['path']} (digest mismatch)")
                file_problem = file_problem or "mismatch"
        except (OSError, TypeError, ValueError) as exc:
            bad_files.append(str(exc))
            file_problem = "malformed"
    checks.append(
        Check(
            f"file digests ({len(listed)} files)",
            not bad_files,
            "all match" if not bad_files else "; ".join(bad_files),
            problem=file_problem,
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
            problem="" if ledger_ok else "missing" if not ledger_path.exists() else "mismatch",
        )
    )

    # 4. Chain integrity, link by link, naming the exact break.
    records: list[dict[str, Any]] = []
    chain_problem = ""
    try:
        records = Ledger.load(run_dir)
    except (OSError, ValueError, TypeError) as exc:
        chain_problem = "malformed"
        broken = [f"ledger.jsonl is unreadable: {exc}"]
    else:
        broken = []
    prev = GENESIS
    for rec in records:
        try:
            if not isinstance(rec, dict):
                raise ValueError("ledger record must be an object")
            if record_digest(rec) != rec.get("record_hash"):
                broken.append(f"seq {rec.get('seq')} {rec.get('stage')}: record_hash")
            if rec.get("prev_hash") != prev:
                broken.append(f"seq {rec.get('seq')} {rec.get('stage')}: prev_hash")
            prev = rec.get("record_hash", "")
        except (TypeError, ValueError) as exc:
            broken.append(f"malformed ledger record: {exc}")
            chain_problem = "malformed"
    checks.append(
        Check(
            f"hash chain ({len(records)} links)",
            not broken,
            "unbroken" if not broken else "; ".join(broken),
            problem=chain_problem or ("mismatch" if broken else ""),
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
            problem="" if head_ok else "mismatch",
        )
    )

    # 6. Stage outputs must still hash to what the producing stage recorded.
    stage_bad: list[str] = []
    stage_problem = ""
    for rec in records:
        outputs = rec.get("outputs", [])
        if not isinstance(outputs, list):
            stage_bad.append(f"{rec.get('stage')} outputs must be a list")
            stage_problem = "malformed"
            continue
        for out in outputs:
            try:
                if not isinstance(out, dict) or not isinstance(out.get("sha256"), str):
                    raise ValueError("output must contain path and sha256 strings")
                target = _safe_bundle_path(run_dir, out.get("path"))
                if not target.is_file():
                    stage_bad.append(f"{rec.get('stage')} -> {out.get('path')} (missing)")
                    stage_problem = "missing"
                elif sha256_file(target) != out["sha256"]:
                    stage_bad.append(f"{rec.get('stage')} -> {out['path']} (digest mismatch)")
                    stage_problem = stage_problem or "mismatch"
            except (OSError, TypeError, ValueError) as exc:
                stage_bad.append(str(exc))
                stage_problem = "malformed"
    checks.append(
        Check(
            "stage outputs re-hashed",
            not stage_bad,
            "all match" if not stage_bad else "; ".join(stage_bad),
            problem=stage_problem,
        )
    )

    return checks


def verify_bundle(
    run_dir: Path,
    trusted_key: Path | Ed25519PublicKey | None = None,
) -> VerificationResult:
    """Inspect a bundle and separately decide whether its signer is trusted."""
    run_dir = Path(run_dir)
    checks = verify_run(run_dir)
    integrity_checks = [check for check in checks if check.category == "integrity"]
    signature_checks = [check for check in checks if check.category == "signature"]
    integrity_ok = bool(integrity_checks) and all(check.ok for check in integrity_checks)
    signature_valid = bool(signature_checks) and all(check.ok for check in signature_checks)
    incomplete = any(check.problem in {"missing", "malformed"} for check in checks)

    bundle_fingerprint = ""
    try:
        bundle_fingerprint = public_key_fingerprint(
            _parse_public_key((run_dir / PUBKEY_NAME).read_bytes())
        )
    except (OSError, TypeError, ValueError):
        pass

    if trusted_key is None:
        signer_trust = "not_configured"
        trusted_fingerprint = ""
        trust_ok = False
        trust_detail = "no independently supplied trusted key was configured"
    else:
        key = (
            load_trusted_key(trusted_key)
            if isinstance(trusted_key, (str, Path))
            else trusted_key
        )
        if not isinstance(key, Ed25519PublicKey):
            raise TrustedKeyConfigurationError("trusted key is not Ed25519")
        trusted_fingerprint = public_key_fingerprint(key)
        try:
            manifest = json.loads((run_dir / MANIFEST_NAME).read_text(encoding="utf-8"))
            signature = bytes.fromhex(
                (run_dir / SIG_NAME).read_text(encoding="utf-8").strip()
            )
            key.verify(signature, canonical(manifest))
            signer_trust = "trusted"
            trust_ok = True
            trust_detail = f"signature verified with trusted key {trusted_fingerprint}"
        except InvalidSignature:
            signer_trust = "untrusted"
            trust_ok = False
            trust_detail = (
                "signature does not verify with the independently supplied trusted key"
            )
        except (OSError, ValueError, TypeError) as exc:
            signer_trust = "not_evaluated"
            trust_ok = False
            trust_detail = f"signer trust could not be evaluated: {exc}"

    checks.append(
        Check(
            "external signer trust",
            trust_ok,
            trust_detail,
            category="trust",
            problem="" if trust_ok else "untrusted",
        )
    )

    if incomplete:
        status = "incomplete"
        reason = "required evidence or signature information is missing or malformed"
    elif not integrity_ok or not signature_valid:
        status = "invalid"
        reason = "the bundle does not match its internal integrity seal"
    elif trust_ok:
        status = "trusted"
        reason = "bundle integrity and signer trust were independently verified"
    else:
        status = "untrusted"
        reason = (
            "bundle integrity passed, but the signer was not established as trusted"
        )

    return VerificationResult(
        status=status,
        integrity_ok=integrity_ok,
        signature_valid=signature_valid,
        signer_trust=signer_trust,
        reason=reason,
        checks=checks,
        bundle_key_fingerprint=bundle_fingerprint,
        trusted_key_fingerprint=trusted_fingerprint,
    )
