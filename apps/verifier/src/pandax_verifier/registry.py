"""Strict parser for independently distributed Actis signing-key registries."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REGISTRY_SCHEMA = "actis/signing-key-registry/v1"


@dataclass(frozen=True)
class RegistryKey:
    provider: str
    key_id: str
    key_version: str
    fingerprint: str
    public_key: Ed25519PublicKey
    status: str


def load_registry(path: str | Path) -> dict[tuple[str, str, str], RegistryKey]:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"trusted key registry cannot be read: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema") != REGISTRY_SCHEMA:
        raise ValueError(f"trusted key registry schema must be {REGISTRY_SCHEMA}")
    if set(document) != {"schema", "keys"}:
        raise ValueError("trusted key registry must contain only schema and keys")
    rows = document.get("keys")
    if not isinstance(rows, list) or not rows:
        raise ValueError("trusted key registry must contain keys")
    result: dict[tuple[str, str, str], RegistryKey] = {}
    active = 0
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("trusted key registry entry must be an object")
        required = {
            "provider", "algorithm", "key_id", "key_version",
            "public_key_fingerprint", "public_key_pem", "status",
        }
        if not required.issubset(row) or set(row) - required - {
            "activated_at", "retired_at", "revoked_at"
        }:
            raise ValueError("trusted key registry entry fields are invalid")
        if any(
            field in row and row[field] is not None and not isinstance(row[field], str)
            for field in ("activated_at", "retired_at", "revoked_at")
        ):
            raise ValueError("trusted key registry timestamps must be strings or null")
        try:
            provider = _text(row, "provider")
            algorithm = _text(row, "algorithm")
            key_id = _text(row, "key_id")
            key_version = _text(row, "key_version")
            fingerprint = _text(row, "public_key_fingerprint")
            pem = _text(row, "public_key_pem").encode("ascii")
            status = _text(row, "status")
        except UnicodeEncodeError as exc:
            raise ValueError("trusted key registry PEM must be ASCII") from exc
        if algorithm != "Ed25519" or status not in {"active", "historical", "revoked"}:
            raise ValueError("trusted key registry algorithm or status is invalid")
        try:
            public_key = serialization.load_pem_public_key(pem)
        except (TypeError, ValueError) as exc:
            raise ValueError("trusted key registry public key is invalid") from exc
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("trusted key registry public key must be Ed25519")
        der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if hashlib.sha256(der).hexdigest() != fingerprint:
            raise ValueError("trusted key registry fingerprint does not match")
        identity = provider, key_id, key_version
        if identity in result:
            raise ValueError("trusted key registry contains a duplicate identity")
        result[identity] = RegistryKey(*identity, fingerprint, public_key, status)
        active += status == "active"
    if active != 1:
        raise ValueError("trusted key registry must contain exactly one active key")
    return result


def _text(row: dict[str, Any], name: str) -> str:
    value = row.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"trusted key registry {name} must be a non-empty string")
    return value
