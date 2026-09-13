from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .bundle import BundleError, normalize_bundle_path, open_bundle
from .models import Check, VerificationResult

GENESIS = "0" * 64
LEDGER_NAME = "ledger.jsonl"
MANIFEST_NAME = "manifest.json"
SIG_NAME = "manifest.sig"
PUBKEY_NAME = "pubkey.pem"
MANIFEST_SCHEMA = "pandax/manifest/v1"
CONTROL_FILES = {MANIFEST_NAME, SIG_NAME, PUBKEY_NAME}
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class TrustedKeyConfigurationError(ValueError):
    """The separately supplied trust anchor is missing or invalid."""


class JsonFormatError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def record_digest(record: dict[str, Any]) -> str:
    trimmed = {k: v for k, v in record.items() if k != "record_hash"}
    return sha256_bytes(canonical(trimmed))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JsonFormatError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise JsonFormatError(f"non-standard JSON number: {value}")


def _load_json(blob: bytes, label: str) -> Any:
    try:
        return json.loads(
            blob.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, JsonFormatError) as exc:
        raise JsonFormatError(f"{label} is not valid JSON: {exc}") from exc


def _load_public_key(blob: bytes, label: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(blob)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not a valid PEM public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{label} is not an Ed25519 public key")
    return key


def _fingerprint(key: Ed25519PublicKey) -> str:
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_bytes(der)


def _load_signature(blob: bytes) -> bytes:
    try:
        text = blob.decode("ascii").strip()
        signature = bytes.fromhex(text)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("manifest.sig is not a hexadecimal Ed25519 signature") from exc
    if len(signature) != 64:
        raise ValueError("manifest.sig must contain exactly 64 signature bytes")
    return signature


def _validate_manifest(manifest: Any) -> tuple[dict[str, Any], list[dict[str, str]]]:
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    required_types: dict[str, type] = {
        "schema": str,
        "run_id": str,
        "created": str,
        "product": dict,
        "tool_versions": dict,
        "ledger_root": str,
        "ledger_sha256": str,
        "ledger_records": int,
        "files": list,
    }
    for field, expected in required_types.items():
        if field not in manifest:
            raise ValueError(f"manifest is missing {field}")
        if not isinstance(manifest[field], expected) or (
            expected is int and isinstance(manifest[field], bool)
        ):
            raise ValueError(f"manifest field {field} must be {expected.__name__}")
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise ValueError(f"unsupported manifest schema: {manifest['schema']}")
    if manifest["ledger_records"] < 0:
        raise ValueError("manifest ledger_records cannot be negative")
    for field in ("ledger_root", "ledger_sha256"):
        if not _HEX_DIGEST.fullmatch(manifest[field]):
            raise ValueError(f"manifest field {field} must be a lowercase SHA-256 digest")

    files: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, entry in enumerate(manifest["files"]):
        if not isinstance(entry, dict):
            raise ValueError(f"manifest file entry {index} must be an object")
        if set(entry) != {"path", "sha256"}:
            raise ValueError(f"manifest file entry {index} must contain only path and sha256")
        path = normalize_bundle_path(entry["path"]) if isinstance(entry["path"], str) else ""
        digest = entry["sha256"]
        if not path:
            raise ValueError(f"manifest file entry {index} has an invalid path")
        if path in CONTROL_FILES:
            raise ValueError(f"manifest must not list control file {path}")
        if not isinstance(digest, str) or not _HEX_DIGEST.fullmatch(digest):
            raise ValueError(f"manifest file entry {index} has an invalid SHA-256 digest")
        folded = path.casefold()
        if folded in seen:
            raise ValueError(f"manifest contains duplicate or case-colliding path {path}")
        seen.add(folded)
        files.append({"path": path, "sha256": digest})
    if LEDGER_NAME not in {entry["path"] for entry in files}:
        raise ValueError(f"manifest does not list {LEDGER_NAME}")
    return manifest, files


def _read_ledger(blob: bytes) -> list[dict[str, Any]]:
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JsonFormatError("ledger.jsonl is not UTF-8") from exc
    records: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        record = _load_json(line.encode("utf-8"), f"ledger line {number}")
        if not isinstance(record, dict):
            raise JsonFormatError(f"ledger line {number} must be a JSON object")
        records.append(record)
    return records


def _validate_record(record: dict[str, Any], index: int) -> None:
    if type(record.get("seq")) is not int:
        raise JsonFormatError(f"ledger record {index} seq must be an integer")
    for field in ("ts", "stage", "tool", "tool_version"):
        if not isinstance(record.get(field), str):
            raise JsonFormatError(f"ledger record {index} {field} must be a string")
    for field in ("params_sha256", "prev_hash", "record_hash"):
        value = record.get(field)
        if not isinstance(value, str) or not _HEX_DIGEST.fullmatch(value):
            raise JsonFormatError(
                f"ledger record {index} {field} must be a lowercase SHA-256 digest"
            )
    for group in ("inputs", "outputs"):
        references = record.get(group)
        if not isinstance(references, list):
            raise JsonFormatError(f"ledger record {index} {group} must be a list")
        for reference_index, reference in enumerate(references):
            if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
                raise JsonFormatError(
                    f"ledger record {index} {group} entry {reference_index} must contain path and sha256"
                )
            path = reference["path"]
            digest = reference["sha256"]
            if not isinstance(path, str):
                raise JsonFormatError(
                    f"ledger record {index} {group} entry {reference_index} path must be a string"
                )
            normalize_bundle_path(path)
            if not isinstance(digest, str) or not _HEX_DIGEST.fullmatch(digest):
                raise JsonFormatError(
                    f"ledger record {index} {group} entry {reference_index} has an invalid SHA-256 digest"
                )


def load_trusted_key(path: str | Path, bundle_source: str | Path) -> Ed25519PublicKey:
    key_path = Path(path)
    source = Path(bundle_source)
    try:
        if source.is_dir() and key_path.resolve().is_relative_to(source.resolve()):
            raise TrustedKeyConfigurationError(
                "the trusted key must be stored separately from the evidence bundle"
            )
        blob = key_path.read_bytes()
        return _load_public_key(blob, "trusted key")
    except TrustedKeyConfigurationError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise TrustedKeyConfigurationError(
            f"trusted key cannot be loaded from {key_path}: {exc}"
        ) from exc


def _verification_failure(reason: str) -> VerificationResult:
    return VerificationResult(
        status="incomplete",
        integrity_ok=False,
        signature_valid=False,
        signer_trust="not_configured",
        reason=reason,
        checks=[Check("bundle readable", False, "integrity", reason)],
    )


def verify_bundle(
    source: str | Path,
    trusted_key: str | Path | Ed25519PublicKey | None = None,
) -> VerificationResult:
    """Verify a PandaX bundle without importing or contacting PandaX."""
    if isinstance(trusted_key, (str, Path)):
        trusted_public_key = load_trusted_key(trusted_key, source)
    elif trusted_key is None or isinstance(trusted_key, Ed25519PublicKey):
        trusted_public_key = trusted_key
    else:
        raise TrustedKeyConfigurationError("trusted key is not Ed25519")

    try:
        reader = open_bundle(source)
    except BundleError as exc:
        return _verification_failure(str(exc))

    checks: list[Check] = []
    problems: list[str] = []

    def add(
        name: str,
        ok: bool,
        category: str,
        detail: str,
        problem: str = "",
    ) -> None:
        checks.append(Check(name, ok, category, detail))  # type: ignore[arg-type]
        if not ok and problem:
            problems.append(problem)

    manifest: dict[str, Any] | None = None
    listed_files: list[dict[str, str]] = []
    bundled_public_key: Ed25519PublicKey | None = None
    signature: bytes | None = None
    bundle_fingerprint: str | None = None

    with reader:
        try:
            parsed = _load_json(reader.read_bytes(MANIFEST_NAME), MANIFEST_NAME)
            manifest, listed_files = _validate_manifest(parsed)
            add("manifest structure", True, "integrity", f"schema {MANIFEST_SCHEMA}")
        except BundleError as exc:
            add("manifest structure", False, "integrity", str(exc), "missing")
        except (JsonFormatError, ValueError) as exc:
            problem = (
                "unsupported"
                if "unsupported manifest schema" in str(exc)
                else "malformed"
            )
            add("manifest structure", False, "integrity", str(exc), problem)

        try:
            bundled_public_key = _load_public_key(
                reader.read_bytes(PUBKEY_NAME), "bundled public key"
            )
            bundle_fingerprint = _fingerprint(bundled_public_key)
            signature = _load_signature(reader.read_bytes(SIG_NAME))
        except BundleError as exc:
            add("bundle signature", False, "bundle_signature", str(exc), "missing")
        except ValueError as exc:
            add("bundle signature", False, "bundle_signature", str(exc), "malformed")
        else:
            if manifest is None:
                add(
                    "bundle signature",
                    False,
                    "bundle_signature",
                    "manifest could not be validated",
                    "malformed",
                )
            else:
                try:
                    bundled_public_key.verify(signature, canonical(manifest))
                    add(
                        "bundle signature",
                        True,
                        "bundle_signature",
                        "valid against the public key included in the bundle",
                    )
                except InvalidSignature:
                    add(
                        "bundle signature",
                        False,
                        "bundle_signature",
                        "signature does not match the manifest",
                        "mismatch",
                    )

        if manifest is not None:
            bad_files: list[str] = []
            file_problem = ""
            for entry in listed_files:
                path = entry["path"]
                if not reader.exists(path):
                    bad_files.append(f"{path} is missing")
                    file_problem = "missing"
                    continue
                try:
                    if reader.sha256(path) != entry["sha256"]:
                        bad_files.append(f"{path} has changed")
                        file_problem = file_problem or "mismatch"
                except BundleError as exc:
                    bad_files.append(str(exc))
                    file_problem = "malformed"
            add(
                f"file digests ({len(listed_files)} files)",
                not bad_files,
                "integrity",
                "all match" if not bad_files else "; ".join(bad_files),
                file_problem,
            )

            expected = {entry["path"] for entry in listed_files} | CONTROL_FILES
            unexpected = sorted(set(reader.files()) - expected)
            add(
                "unexpected files",
                not unexpected,
                "integrity",
                "none" if not unexpected else "; ".join(unexpected),
                "mismatch" if unexpected else "",
            )

            ledger_blob: bytes | None = None
            try:
                ledger_blob = reader.read_bytes(LEDGER_NAME)
                ledger_digest_ok = sha256_bytes(ledger_blob) == manifest["ledger_sha256"]
                add(
                    "ledger file digest",
                    ledger_digest_ok,
                    "integrity",
                    "matches manifest" if ledger_digest_ok else "ledger.jsonl has changed",
                    "mismatch" if not ledger_digest_ok else "",
                )
            except BundleError as exc:
                add("ledger file digest", False, "integrity", str(exc), "missing")

            records: list[dict[str, Any]] = []
            if ledger_blob is not None:
                try:
                    records = _read_ledger(ledger_blob)
                    for index, record in enumerate(records):
                        _validate_record(record, index)
                    add("ledger format", True, "integrity", f"{len(records)} records")
                except (BundleError, JsonFormatError) as exc:
                    add("ledger format", False, "integrity", str(exc), "malformed")

            count_ok = len(records) == manifest["ledger_records"]
            add(
                "ledger record count",
                count_ok,
                "integrity",
                f"expected {manifest['ledger_records']}, found {len(records)}",
                "mismatch" if not count_ok else "",
            )

            sequence_bad: list[str] = []
            chain_bad: list[str] = []
            previous = GENESIS
            for expected_sequence, record in enumerate(records):
                sequence = record.get("seq")
                if sequence != expected_sequence:
                    sequence_bad.append(f"record {expected_sequence} says seq {sequence!r}")
                try:
                    digest = record_digest(record)
                    if not isinstance(record.get("record_hash"), str) or digest != record["record_hash"]:
                        chain_bad.append(f"seq {sequence!r}: record hash")
                    if record.get("prev_hash") != previous:
                        chain_bad.append(f"seq {sequence!r}: previous link")
                    previous = record.get("record_hash", "")
                except (TypeError, ValueError) as exc:
                    chain_bad.append(f"seq {sequence!r}: malformed record ({exc})")

            add(
                "ledger sequence",
                not sequence_bad,
                "integrity",
                "contiguous from zero" if not sequence_bad else "; ".join(sequence_bad),
                "mismatch" if sequence_bad else "",
            )
            add(
                f"hash chain ({len(records)} links)",
                not chain_bad,
                "integrity",
                "unbroken" if not chain_bad else "; ".join(chain_bad),
                "mismatch" if chain_bad else "",
            )

            head_ok = bool(records) and previous == manifest["ledger_root"]
            add(
                "chain head vs manifest",
                head_ok,
                "integrity",
                "matches manifest" if head_ok else "ledger head does not match manifest",
                "mismatch" if not head_ok else "",
            )

            output_bad: list[str] = []
            output_problem = ""
            for record in records:
                outputs = record.get("outputs")
                if not isinstance(outputs, list):
                    output_bad.append(f"seq {record.get('seq')!r}: outputs must be a list")
                    output_problem = "malformed"
                    continue
                for output in outputs:
                    try:
                        if not isinstance(output, dict):
                            raise ValueError("output must be an object")
                        path_value = output.get("path")
                        digest_value = output.get("sha256")
                        if not isinstance(path_value, str) or not isinstance(digest_value, str):
                            raise ValueError("output must contain path and sha256 strings")
                        path = normalize_bundle_path(path_value)
                        if not _HEX_DIGEST.fullmatch(digest_value):
                            raise ValueError("output SHA-256 digest is malformed")
                        if not reader.exists(path):
                            output_bad.append(f"{path} is missing")
                            output_problem = "missing"
                        elif reader.sha256(path) != digest_value:
                            output_bad.append(f"{path} has changed")
                            output_problem = output_problem or "mismatch"
                    except (BundleError, TypeError, ValueError) as exc:
                        output_bad.append(f"seq {record.get('seq')!r}: {exc}")
                        output_problem = "malformed"
            add(
                "stage outputs re-hashed",
                not output_bad,
                "integrity",
                "all match" if not output_bad else "; ".join(output_bad),
                output_problem,
            )

        trusted_fingerprint = (
            _fingerprint(trusted_public_key) if trusted_public_key is not None else None
        )
        trust_ok = False
        if trusted_public_key is None:
            signer_trust = "not_configured"
            trust_detail = "no separately supplied trusted key was configured"
        elif manifest is None or signature is None:
            signer_trust = "untrusted"
            trust_detail = "the bundle signature could not be checked with the trusted key"
        else:
            try:
                trusted_public_key.verify(signature, canonical(manifest))
                trust_ok = True
                signer_trust = "trusted"
                trust_detail = f"verified with trusted key {trusted_fingerprint}"
            except InvalidSignature:
                signer_trust = "untrusted"
                trust_detail = "signature does not match the separately supplied trusted key"
        add("external signer trust", trust_ok, "signer_trust", trust_detail)

    integrity_checks = [check for check in checks if check.category == "integrity"]
    signature_checks = [
        check for check in checks if check.category == "bundle_signature"
    ]
    integrity_ok = bool(integrity_checks) and all(check.ok for check in integrity_checks)
    signature_valid = bool(signature_checks) and all(check.ok for check in signature_checks)
    incomplete = any(problem in {"missing", "malformed", "unsupported"} for problem in problems)

    if incomplete:
        status = "incomplete"
        reason = "required evidence is missing, malformed, or uses an unsupported format"
    elif not integrity_ok or not signature_valid:
        status = "invalid"
        reason = "the bundle has been altered or does not match its internal seal"
    elif trust_ok:
        status = "trusted"
        reason = "evidence integrity and the approved PandaX signer were verified"
    else:
        status = "untrusted"
        reason = "the evidence is intact, but the signer was not established as trusted"

    return VerificationResult(
        status=status,  # type: ignore[arg-type]
        integrity_ok=integrity_ok,
        signature_valid=signature_valid,
        signer_trust=signer_trust,  # type: ignore[arg-type]
        reason=reason,
        bundle_key_fingerprint=bundle_fingerprint,
        trusted_key_fingerprint=trusted_fingerprint,
        checks=checks,
    )
