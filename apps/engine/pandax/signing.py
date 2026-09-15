"""Environment-aware Ed25519 signing providers and public-key registries."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, runtime_checkable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

REGISTRY_SCHEMA = "actis/signing-key-registry/v1"
_KMS_VERSION = re.compile(
    r"^(projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+)"
    r"/cryptoKeyVersions/([^/]+)$"
)
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$")


class SigningConfigurationError(ValueError):
    """Signing custody configuration is missing, unsafe, or inconsistent."""


class SigningProviderError(RuntimeError):
    """The configured signing provider could not complete a safe operation."""


@dataclass(frozen=True, slots=True)
class SigningIdentity:
    provider: str
    algorithm: str
    key_id: str
    key_version: str
    public_key_fingerprint: str

    def as_manifest(self) -> dict[str, str]:
        return asdict(self)


@runtime_checkable
class Signer(Protocol):
    @property
    def identity(self) -> SigningIdentity: ...

    def sign(self, payload: bytes) -> bytes: ...

    def public_key_pem(self) -> bytes: ...


def public_key_fingerprint_pem(pem: bytes) -> str:
    try:
        key = serialization.load_pem_public_key(pem)
    except (TypeError, ValueError) as exc:
        raise SigningConfigurationError("registry public key is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SigningConfigurationError("registry public key must be Ed25519")
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


class PrivateKeySigner:
    """In-process signer used only by file and deployment-secret providers."""

    def __init__(self, key: Ed25519PrivateKey, provider: str, key_id: str, version: str):
        _validate_identity(provider, key_id, version)
        self._key = key
        self._public_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._identity = SigningIdentity(
            provider=provider,
            algorithm="Ed25519",
            key_id=key_id,
            key_version=version,
            public_key_fingerprint=public_key_fingerprint_pem(self._public_pem),
        )

    @property
    def identity(self) -> SigningIdentity:
        return self._identity

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload)

    def public_key_pem(self) -> bytes:
        return self._public_pem


def file_signer(path: Path, key_id: str = "development", version: str = "1") -> Signer:
    path = Path(path)
    if path.exists():
        key = _load_private_key(path.read_bytes())
    else:
        key = Ed25519PrivateKey.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        try:
            path.chmod(0o600)
        except OSError:
            pass
    return PrivateKeySigner(key, "file", key_id, version)


def secret_signer(encoded: str, key_id: str, version: str) -> Signer:
    try:
        pem = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SigningConfigurationError("PANDAX_SIGNING_KEY_B64 is not valid base64") from exc
    return PrivateKeySigner(_load_private_key(pem), "secret", key_id, version)


def _load_private_key(pem: bytes) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (TypeError, ValueError) as exc:
        raise SigningConfigurationError("signing key is not a usable unencrypted PKCS#8 key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningConfigurationError("signing key must be Ed25519")
    return key


@dataclass(frozen=True, slots=True)
class RegistryKey:
    provider: str
    algorithm: str
    key_id: str
    key_version: str
    public_key_fingerprint: str
    public_key_pem: str
    status: str
    activated_at: str | None = None
    retired_at: str | None = None
    revoked_at: str | None = None

    @property
    def identity(self) -> tuple[str, str, str]:
        return self.provider, self.key_id, self.key_version

    def public_key(self) -> Ed25519PublicKey:
        key = serialization.load_pem_public_key(self.public_key_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise SigningConfigurationError("registry public key must be Ed25519")
        return key


@dataclass(frozen=True, slots=True)
class SigningKeyRegistry:
    keys: tuple[RegistryKey, ...]
    schema: str = REGISTRY_SCHEMA

    def as_dict(self) -> dict[str, Any]:
        return {"schema": self.schema, "keys": [asdict(key) for key in self.keys]}

    def find(self, provider: str, key_id: str, version: str) -> RegistryKey | None:
        return next((key for key in self.keys if key.identity == (provider, key_id, version)), None)


def registry_for_signer(signer: Signer) -> SigningKeyRegistry:
    identity = signer.identity
    return SigningKeyRegistry(
        keys=(
            RegistryKey(
                provider=identity.provider,
                algorithm=identity.algorithm,
                key_id=identity.key_id,
                key_version=identity.key_version,
                public_key_fingerprint=identity.public_key_fingerprint,
                public_key_pem=signer.public_key_pem().decode("ascii"),
                status="active",
            ),
        )
    )


def load_registry_b64(encoded: str) -> SigningKeyRegistry:
    try:
        raw = base64.b64decode(encoded, validate=True)
        document = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SigningConfigurationError("PANDAX_SIGNING_KEY_REGISTRY_B64 is invalid") from exc
    return parse_registry(document)


def parse_registry(document: Any) -> SigningKeyRegistry:
    if not isinstance(document, dict) or document.get("schema") != REGISTRY_SCHEMA:
        raise SigningConfigurationError(f"registry schema must be {REGISTRY_SCHEMA}")
    if set(document) != {"schema", "keys"}:
        raise SigningConfigurationError("registry must contain only schema and keys")
    rows = document.get("keys")
    if not isinstance(rows, list) or not rows:
        raise SigningConfigurationError("signing-key registry must contain keys")
    keys: list[RegistryKey] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise SigningConfigurationError("registry key entry must be an object")
        required = {
            "provider", "algorithm", "key_id", "key_version",
            "public_key_fingerprint", "public_key_pem", "status",
        }
        if not required.issubset(row):
            raise SigningConfigurationError("registry key entry is incomplete")
        unknown = set(row) - required - {"activated_at", "retired_at", "revoked_at"}
        if unknown:
            raise SigningConfigurationError(f"registry key entry has unknown fields: {sorted(unknown)}")
        if not all(isinstance(row[field], str) and row[field] for field in required):
            raise SigningConfigurationError("registry key values must be non-empty strings")
        for field in ("activated_at", "retired_at", "revoked_at"):
            if field in row and row[field] is not None and not isinstance(row[field], str):
                raise SigningConfigurationError(f"registry {field} must be a string or null")
        key = RegistryKey(**row)
        _validate_identity(key.provider, key.key_id, key.key_version)
        if key.algorithm != "Ed25519":
            raise SigningConfigurationError("registry algorithm must be Ed25519")
        if key.status not in {"active", "historical", "revoked"}:
            raise SigningConfigurationError("registry status must be active, historical, or revoked")
        fingerprint = public_key_fingerprint_pem(key.public_key_pem.encode("ascii"))
        if fingerprint != key.public_key_fingerprint:
            raise SigningConfigurationError("registry public-key fingerprint does not match")
        if key.identity in seen:
            raise SigningConfigurationError("registry contains a duplicate key identity")
        seen.add(key.identity)
        keys.append(key)
    if sum(key.status == "active" for key in keys) != 1:
        raise SigningConfigurationError("registry must contain exactly one active key")
    return SigningKeyRegistry(tuple(keys))


class GoogleCloudKmsSigner:
    """Exact-version raw Ed25519 signer backed by Google Cloud KMS."""

    def __init__(self, key_version: str, registry: SigningKeyRegistry, client: Any = None):
        match = _KMS_VERSION.fullmatch(key_version)
        if not match:
            raise SigningConfigurationError("PANDAX_GCP_KMS_KEY_VERSION must name an exact key version")
        key_id, version = match.groups()
        entry = registry.find("google-cloud-kms", key_id, version)
        if entry is None or entry.status != "active":
            raise SigningConfigurationError("active KMS key version is absent from signing-key registry")
        self._entry = entry
        self._key_version = key_version
        self._client = client or _google_kms_client()
        self._validate_remote_key()

    @property
    def identity(self) -> SigningIdentity:
        return SigningIdentity(
            provider=self._entry.provider,
            algorithm=self._entry.algorithm,
            key_id=self._entry.key_id,
            key_version=self._entry.key_version,
            public_key_fingerprint=self._entry.public_key_fingerprint,
        )

    def public_key_pem(self) -> bytes:
        return self._entry.public_key_pem.encode("ascii")

    def _validate_remote_key(self) -> None:
        try:
            version = self._client.get_crypto_key_version(
                request={"name": self._key_version}, timeout=10
            )
        except Exception as exc:
            raise SigningProviderError("Google Cloud KMS key validation failed") from exc
        if _enum_name(version.state) != "ENABLED":
            raise SigningConfigurationError("Google Cloud KMS key version must be enabled")
        if _enum_name(version.algorithm) != "EC_SIGN_ED25519":
            raise SigningConfigurationError("Google Cloud KMS key algorithm must be EC_SIGN_ED25519")
        try:
            public = self._client.get_public_key(
                request={"name": self._key_version}, timeout=10
            )
        except Exception as exc:
            raise SigningProviderError("Google Cloud KMS public-key retrieval failed") from exc
        pem = public.pem.encode("ascii")
        pem_crc32c = getattr(public, "pem_crc32c", None)
        if pem_crc32c is not None and int(pem_crc32c.value) != _crc32c(pem):
            raise SigningProviderError("Google Cloud KMS public-key integrity check failed")
        if public_key_fingerprint_pem(pem) != self._entry.public_key_fingerprint:
            raise SigningConfigurationError("Google Cloud KMS public key does not match registry")

    def sign(self, payload: bytes) -> bytes:
        try:
            checksum = _crc32c(payload)
            response = self._client.asymmetric_sign(
                request={
                    "name": self._key_version,
                    "data": payload,
                    "data_crc32c": _int64_value(checksum),
                },
                timeout=10,
            )
            if not response.verified_data_crc32c:
                raise SigningProviderError("Google Cloud KMS rejected request integrity")
            signature = bytes(response.signature)
            if int(response.signature_crc32c.value) != _crc32c(signature):
                raise SigningProviderError("Google Cloud KMS signature integrity check failed")
            return signature
        except SigningProviderError:
            raise
        except Exception as exc:
            raise SigningProviderError("Google Cloud KMS signing failed") from exc


def configured_signer(
    default_file: Path,
    environ: Mapping[str, str] | None = None,
    kms_client: Any = None,
) -> Signer:
    env = os.environ if environ is None else environ
    environment = env.get("PANDAX_ENVIRONMENT", "development").strip().lower()
    if environment not in {"development", "test", "staging", "beta", "production"}:
        raise SigningConfigurationError("PANDAX_ENVIRONMENT is invalid")
    provider = env.get("PANDAX_SIGNER_PROVIDER", "").strip().lower()
    if not provider:
        if environment in {"development", "test"}:
            provider = "file"
        else:
            raise SigningConfigurationError(f"PANDAX_SIGNER_PROVIDER is required for {environment}")

    if provider == "file":
        if environment not in {"development", "test"}:
            raise SigningConfigurationError("file signing is allowed only in development and test")
        path = Path(env.get("PANDAX_SIGNING_KEY", str(default_file)))
        return file_signer(
            path,
            env.get("PANDAX_SIGNING_KEY_ID", "development"),
            env.get("PANDAX_SIGNING_KEY_VERSION", "1"),
        )

    if provider == "secret":
        if environment not in {"staging", "beta"}:
            raise SigningConfigurationError("secret signing is allowed only in staging and beta")
        return secret_signer(
            _required(env, "PANDAX_SIGNING_KEY_B64"),
            _required(env, "PANDAX_SIGNING_KEY_ID"),
            _required(env, "PANDAX_SIGNING_KEY_VERSION"),
        )

    if provider == "google-cloud-kms":
        if environment != "production":
            raise SigningConfigurationError("Google Cloud KMS signing is production-only")
        registry = load_registry_b64(_required(env, "PANDAX_SIGNING_KEY_REGISTRY_B64"))
        return GoogleCloudKmsSigner(
            _required(env, "PANDAX_GCP_KMS_KEY_VERSION"), registry, client=kms_client
        )

    raise SigningConfigurationError("PANDAX_SIGNER_PROVIDER must be file, secret, or google-cloud-kms")


def configured_registry(signer: Signer, environ: Mapping[str, str] | None = None) -> SigningKeyRegistry:
    env = os.environ if environ is None else environ
    encoded = env.get("PANDAX_SIGNING_KEY_REGISTRY_B64", "").strip()
    registry = load_registry_b64(encoded) if encoded else registry_for_signer(signer)
    entry = registry.find(
        signer.identity.provider, signer.identity.key_id, signer.identity.key_version
    )
    if entry is None or entry.status != "active":
        raise SigningConfigurationError("configured signer is not the registry active key")
    if entry.public_key_fingerprint != signer.identity.public_key_fingerprint:
        raise SigningConfigurationError("configured signer does not match registry public key")
    return registry


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise SigningConfigurationError(f"{name} is required")
    return value


def _validate_identity(provider: str, key_id: str, version: str) -> None:
    if provider not in {"file", "secret", "google-cloud-kms"}:
        raise SigningConfigurationError("unsupported signing provider")
    if not _SAFE_ID.fullmatch(key_id) or not _SAFE_ID.fullmatch(version):
        raise SigningConfigurationError("signing key ID and version must be non-empty safe identifiers")


def _enum_name(value: Any) -> str:
    name = getattr(value, "name", None)
    return str(name or value).rsplit(".", 1)[-1]


def _google_kms_client() -> Any:
    try:
        from google.cloud import kms_v1
    except ImportError as exc:
        raise SigningConfigurationError(
            "Google Cloud KMS support is not installed; install the kms extra"
        ) from exc
    return kms_v1.KeyManagementServiceClient()


def _crc32c(value: bytes) -> int:
    try:
        import google_crc32c
    except ImportError as exc:
        raise SigningConfigurationError(
            "Google Cloud KMS support is not installed; install the kms extra"
        ) from exc
    return google_crc32c.value(value)


def _int64_value(value: int) -> Any:
    try:
        from google.protobuf.wrappers_pb2 import Int64Value
    except ImportError as exc:
        raise SigningConfigurationError(
            "Google Cloud KMS support is not installed; install the kms extra"
        ) from exc
    return Int64Value(value=value)
