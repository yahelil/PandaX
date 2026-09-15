"""Fail-closed OIDC bearer authentication and organization authorization."""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import os
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Protocol

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


class Role(str, Enum):
    ORG_ADMIN = "org_admin"
    COMPLIANCE_OPERATOR = "compliance_operator"
    AUTHORIZED_APPROVER = "authorized_approver"
    SECURITY_REVIEWER = "security_reviewer"
    VIEWER = "viewer"


@dataclass(frozen=True)
class Principal:
    subject: str
    organization_id: str
    roles: frozenset[Role]
    reauthenticated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    session_id: str | None = None


@dataclass(frozen=True)
class AuthenticatedIdentity:
    """Provider-neutral verified identity; it carries no application authority."""

    subject: str
    organization_hint: str | None
    session_id: str
    reauthenticated_at: datetime
    issued_at: datetime


@dataclass(frozen=True)
class OIDCSettings:
    issuer: str
    audience: str
    jwks_uri: str
    organization_claim: str = "org_id"
    clock_skew_seconds: int = 30
    jwks_cache_seconds: int = 300

    def __post_init__(self) -> None:
        if not self.issuer or not self.audience or not self.jwks_uri:
            raise ValueError("OIDC issuer, audience and JWKS URI are required")
        if self.clock_skew_seconds < 0 or self.jwks_cache_seconds < 0:
            raise ValueError("OIDC time settings cannot be negative")

    @classmethod
    def from_env(cls, prefix: str = "PANDAX_OIDC_") -> "OIDCSettings":
        values = {
            name: os.environ.get(f"{prefix}{name.upper()}", "").strip()
            for name in ("issuer", "audience", "jwks_uri")
        }
        return cls(**values)


class AuthenticationError(ValueError):
    """Token cannot establish an authenticated principal."""


class SigningKeyNotFound(AuthenticationError):
    """Token key id is absent from the current JWKS."""


JWKSLoader = Callable[[str], Awaitable[Mapping[str, Any]]]
SignatureVerifier = Callable[
    [bytes, bytes, Mapping[str, Any], Mapping[str, Any]], None
]
Clock = Callable[[], float]


class AuthorizationIdentity(Protocol):
    organization_id: str | None
    roles: frozenset[Any]
    reauthenticated_at: datetime | None

_bearer = HTTPBearer(auto_error=False)


class OIDCAuthenticator:
    """Validate OIDC access tokens without accepting authorization claims."""

    def __init__(
        self,
        settings: OIDCSettings,
        *,
        jwks_loader: JWKSLoader | None = None,
        verifier: SignatureVerifier | None = None,
        clock: Clock = time.time,
    ) -> None:
        self.settings = settings
        self._jwks_loader = jwks_loader or _load_remote_jwks
        self._verifier = verifier or _verify_asymmetric
        self._clock = clock
        self._jwks: Mapping[str, Any] | None = None
        self._jwks_loaded_at = 0.0
        self._jwks_lock = asyncio.Lock()

    async def authenticate(self, token: str) -> AuthenticatedIdentity:
        header, claims, signing_input, signature = _decode_token(token)
        if header.get("alg") not in {"ES256", "RS256"}:
            raise AuthenticationError("unsupported signing algorithm")

        jwks = await self._get_jwks()
        try:
            self._verifier(signing_input, signature, header, jwks)
        except SigningKeyNotFound:
            jwks = await self._get_jwks(force=True)
            self._verifier(signing_input, signature, header, jwks)
        except AuthenticationError:
            raise
        except Exception as exc:
            raise AuthenticationError("signature verification failed") from exc

        return _identity_from_claims(claims, self.settings, self._clock())

    async def __call__(
        self,
        credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
    ) -> AuthenticatedIdentity:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise _unauthorized()
        try:
            return await self.authenticate(credentials.credentials)
        except AuthenticationError as exc:
            raise _unauthorized() from exc

    async def _get_jwks(self, *, force: bool = False) -> Mapping[str, Any]:
        now = self._clock()
        fresh = (
            self._jwks is not None
            and now - self._jwks_loaded_at < self.settings.jwks_cache_seconds
        )
        if fresh and not force:
            return self._jwks  # type: ignore[return-value]

        async with self._jwks_lock:
            now = self._clock()
            fresh = (
                self._jwks is not None
                and now - self._jwks_loaded_at < self.settings.jwks_cache_seconds
            )
            if fresh and not force:
                return self._jwks  # type: ignore[return-value]
            try:
                jwks = await self._jwks_loader(self.settings.jwks_uri)
            except Exception as exc:
                raise AuthenticationError("signing keys unavailable") from exc
            if not isinstance(jwks, Mapping) or not isinstance(jwks.get("keys"), list):
                raise AuthenticationError("invalid JWKS")
            self._jwks = jwks
            self._jwks_loaded_at = now
            return jwks


def require_roles(
    principal_dependency: Callable[..., Principal],
    *allowed: Role,
) -> Callable[..., Awaitable[Principal]]:
    if not allowed:
        raise ValueError("at least one role is required")
    accepted = frozenset(allowed)

    async def guard(principal: Principal = Depends(principal_dependency)) -> Principal:
        authorize_request(principal, principal.organization_id, accepted)
        return principal

    return guard


def require_organization(
    principal_dependency: Callable[..., Principal],
) -> Callable[..., Awaitable[Principal]]:
    async def guard(
        organization_id: str,
        principal: Principal = Depends(principal_dependency),
    ) -> Principal:
        authorize_request(principal, organization_id, frozenset(Role))
        return principal

    return guard


async def _load_remote_jwks(uri: str) -> Mapping[str, Any]:
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
        response = await client.get(uri)
        response.raise_for_status()
        payload = response.json()
    if not isinstance(payload, Mapping):
        raise AuthenticationError("invalid JWKS")
    return payload


def _verify_asymmetric(
    signing_input: bytes,
    signature: bytes,
    header: Mapping[str, Any],
    jwks: Mapping[str, Any],
) -> None:
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise AuthenticationError("missing key id")
    candidates = [key for key in jwks.get("keys", []) if key.get("kid") == kid]
    if not candidates:
        raise SigningKeyNotFound("signing key not found")
    if len(candidates) != 1:
        raise AuthenticationError("ambiguous signing key")
    key = candidates[0]
    algorithm = header["alg"]
    if key.get("use", "sig") != "sig":
        raise AuthenticationError("invalid signing key")
    if key.get("alg", algorithm) != algorithm:
        raise AuthenticationError("signing algorithm mismatch")
    try:
        if algorithm == "RS256" and key.get("kty") == "RSA":
            public_key = rsa.RSAPublicNumbers(
                _decode_int(key["e"]), _decode_int(key["n"])
            ).public_key()
            public_key.verify(
                signature, signing_input, padding.PKCS1v15(), hashes.SHA256()
            )
        elif (
            algorithm == "ES256"
            and key.get("kty") == "EC"
            and key.get("crv") == "P-256"
            and len(signature) == 64
        ):
            public_key = ec.EllipticCurvePublicNumbers(
                _decode_int(key["x"]),
                _decode_int(key["y"]),
                ec.SECP256R1(),
            ).public_key()
            public_key.verify(
                encode_dss_signature(
                    int.from_bytes(signature[:32], "big"),
                    int.from_bytes(signature[32:], "big"),
                ),
                signing_input,
                ec.ECDSA(hashes.SHA256()),
            )
        else:
            raise AuthenticationError("invalid signing key")
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise AuthenticationError("invalid signing key") from exc
    except Exception as exc:
        raise AuthenticationError("invalid signature") from exc


def _identity_from_claims(
    claims: Mapping[str, Any], settings: OIDCSettings, now: float
) -> AuthenticatedIdentity:
    if claims.get("iss") != settings.issuer:
        raise AuthenticationError("issuer mismatch")
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    if not isinstance(audiences, Sequence) or settings.audience not in audiences:
        raise AuthenticationError("audience mismatch")

    expiry = _numeric_date(claims.get("exp"), "expiry")
    if expiry <= now - settings.clock_skew_seconds:
        raise AuthenticationError("token expired")
    if "nbf" in claims:
        not_before = _numeric_date(claims["nbf"], "not-before")
        if not_before > now + settings.clock_skew_seconds:
            raise AuthenticationError("token not active")

    issued_at = _numeric_date(claims.get("iat"), "issued-at")
    if issued_at > now + settings.clock_skew_seconds:
        raise AuthenticationError("token issued in the future")

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise AuthenticationError("missing subject")
    if claims.get("role") != "authenticated" or claims.get("is_anonymous") is not False:
        raise AuthenticationError("interactive authenticated user required")
    if claims.get("aal") != "aal2":
        raise AuthenticationError("multi-factor authentication required")

    raw_methods = claims.get("amr")
    if not isinstance(raw_methods, Sequence) or isinstance(raw_methods, (str, bytes, bytearray)):
        raise AuthenticationError("invalid authentication methods")
    totp_times: list[float] = []
    for entry in raw_methods:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("method"), str):
            raise AuthenticationError("invalid authentication methods")
        if entry["method"] == "totp":
            timestamp = _numeric_date(entry.get("timestamp"), "authentication time")
            if timestamp > now + settings.clock_skew_seconds:
                raise AuthenticationError("authentication time is in the future")
            totp_times.append(timestamp)
    if not totp_times:
        raise AuthenticationError("TOTP authentication required")

    session_id = claims.get("session_id")
    if not isinstance(session_id, str) or not session_id.strip():
        raise AuthenticationError("missing session")
    organization_hint = claims.get(settings.organization_claim)
    if organization_hint is not None and (
        not isinstance(organization_hint, str) or not organization_hint.strip()
    ):
        raise AuthenticationError("invalid organization hint")
    return AuthenticatedIdentity(
        subject=subject.strip(),
        organization_hint=organization_hint.strip() if organization_hint else None,
        session_id=session_id.strip(),
        reauthenticated_at=datetime.fromtimestamp(max(totp_times), timezone.utc),
        issued_at=datetime.fromtimestamp(issued_at, timezone.utc),
    )


def authorize_request(
    principal: AuthorizationIdentity,
    organization_id: str,
    allowed_roles: frozenset[Any],
    *,
    sensitive: bool = False,
    now: datetime | None = None,
    reauthentication_window: timedelta = timedelta(minutes=15),
) -> None:
    """Apply the shared fail-closed tenant, role, and reauthentication policy."""

    if not organization_id or principal.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="organization not found")
    actual = {
        role.value if isinstance(role, Enum) else str(role) for role in principal.roles
    }
    accepted = {
        role.value if isinstance(role, Enum) else str(role) for role in allowed_roles
    }
    if not actual.intersection(accepted):
        raise HTTPException(status_code=403, detail="insufficient role")
    if not sensitive:
        return
    require_recent_reauthentication(
        principal,
        now=now,
        reauthentication_window=reauthentication_window,
    )


def require_recent_reauthentication(
    principal: AuthorizationIdentity,
    *,
    now: datetime | None = None,
    reauthentication_window: timedelta = timedelta(minutes=15),
) -> None:
    """Reject sensitive actions without a recent MFA authentication."""

    checked_at = now or datetime.now(timezone.utc)
    reauthenticated_at = principal.reauthenticated_at
    if (
        reauthenticated_at is None
        or reauthenticated_at.tzinfo is None
        or checked_at - reauthenticated_at.astimezone(timezone.utc)
        > reauthentication_window
        or reauthenticated_at.astimezone(timezone.utc) > checked_at + timedelta(seconds=30)
    ):
        raise HTTPException(
            status_code=401,
            detail="recent reauthentication required",
            headers={"WWW-Authenticate": 'Bearer error="insufficient_authentication"'},
        )


def _decode_token(
    token: str,
) -> tuple[Mapping[str, Any], Mapping[str, Any], bytes, bytes]:
    if not isinstance(token, str) or not token:
        raise AuthenticationError("missing token")
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise AuthenticationError("malformed token")
    try:
        header = json.loads(_decode_segment(parts[0]))
        claims = json.loads(_decode_segment(parts[1]))
        signature = _decode_segment(parts[2])
    except (UnicodeDecodeError, json.JSONDecodeError, binascii.Error) as exc:
        raise AuthenticationError("malformed token") from exc
    if not isinstance(header, Mapping) or not isinstance(claims, Mapping):
        raise AuthenticationError("malformed token")
    return header, claims, f"{parts[0]}.{parts[1]}".encode("ascii"), signature


def _decode_segment(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def _decode_int(value: str) -> int:
    if not isinstance(value, str) or not value:
        raise ValueError("invalid RSA integer")
    return int.from_bytes(_decode_segment(value), "big")


def _numeric_date(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AuthenticationError(f"invalid {name}")
    return float(value)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail="Invalid or missing access token",
        headers={"WWW-Authenticate": "Bearer"},
    )
