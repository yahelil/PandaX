from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from pandax.auth import (
    AuthenticatedIdentity,
    AuthenticationError,
    OIDCAuthenticator,
    OIDCSettings,
    Principal,
    Role,
    authorize_request,
    require_organization,
    require_roles,
)

NOW = 1_800_000_000.0


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@pytest.fixture
def key_pair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kid": "active-key",
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "n": encode(public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")),
                "e": encode(public.e.to_bytes((public.e.bit_length() + 7) // 8, "big")),
            }
        ]
    }
    return private, jwks


@pytest.fixture
def settings() -> OIDCSettings:
    return OIDCSettings(
        issuer="https://identity.example.test/",
        audience="actis-api",
        jwks_uri="https://identity.example.test/.well-known/jwks.json",
        clock_skew_seconds=0,
    )


@pytest.fixture
def make_token(key_pair, settings):
    private, _ = key_pair

    def make(**overrides):
        header = {"alg": "RS256", "typ": "JWT", "kid": "active-key"}
        claims = {
            "iss": settings.issuer,
            "aud": settings.audience,
            "sub": "user-123",
            "org_id": "org-acme",
            "role": "authenticated",
            "is_anonymous": False,
            "aal": "aal2",
            "amr": [
                {"method": "password", "timestamp": NOW - 60},
                {"method": "totp", "timestamp": NOW - 30},
            ],
            "session_id": "session-123",
            "iat": NOW - 30,
            "exp": NOW + 300,
        }
        claims.update(overrides)
        encoded_header = encode(json.dumps(header, separators=(",", ":")).encode())
        encoded_claims = encode(json.dumps(claims, separators=(",", ":")).encode())
        signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
        signature = private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input.decode()}.{encode(signature)}"

    return make


@pytest.fixture
def authenticator(settings, key_pair):
    _, jwks = key_pair

    async def load(uri):
        assert uri == settings.jwks_uri
        return jwks

    return OIDCAuthenticator(settings, jwks_loader=load, clock=lambda: NOW)


def run(awaitable):
    return asyncio.run(awaitable)


def test_valid_token_returns_provider_neutral_identity(authenticator, make_token):
    identity = run(authenticator.authenticate(make_token(roles=["org_admin"])))

    assert identity == AuthenticatedIdentity(
        subject="user-123",
        organization_hint="org-acme",
        session_id="session-123",
        reauthenticated_at=datetime.fromtimestamp(NOW - 30, timezone.utc),
        issued_at=datetime.fromtimestamp(NOW - 30, timezone.utc),
    )


def test_accepts_supabase_es256_signing_keys(settings):
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kid": "ec-key",
                "kty": "EC",
                "use": "sig",
                "alg": "ES256",
                "crv": "P-256",
                "x": encode(public.x.to_bytes(32, "big")),
                "y": encode(public.y.to_bytes(32, "big")),
            }
        ]
    }
    header = encode(b'{"alg":"ES256","kid":"ec-key"}')
    claims = encode(
        json.dumps(
            {
                "iss": settings.issuer,
                "aud": settings.audience,
                "sub": "user-123",
                "role": "authenticated",
                "is_anonymous": False,
                "aal": "aal2",
                "amr": [{"method": "totp", "timestamp": NOW}],
                "session_id": "session-123",
                "iat": NOW,
                "exp": NOW + 300,
            },
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{claims}".encode()
    r, s = decode_dss_signature(private.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    token = f"{signing_input.decode()}.{encode(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    async def load(_uri):
        return jwks

    auth = OIDCAuthenticator(settings, jwks_loader=load, clock=lambda: NOW)
    assert run(auth.authenticate(token)).subject == "user-123"


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://attacker.example/"},
        {"aud": "another-api"},
        {"exp": NOW},
        {"aal": "aal1"},
        {"amr": [{"method": "password", "timestamp": NOW - 30}]},
        {"role": "service_role"},
        {"is_anonymous": True},
    ],
    ids=[
        "wrong-issuer", "wrong-audience", "expired", "no-mfa", "no-totp",
        "service-role", "anonymous",
    ],
)
def test_rejects_invalid_required_claims(authenticator, make_token, overrides):
    with pytest.raises(AuthenticationError):
        run(authenticator.authenticate(make_token(**overrides)))


def test_rejects_malformed_and_invalid_signature(authenticator, make_token):
    with pytest.raises(AuthenticationError):
        run(authenticator.authenticate("not.a.jwt.with.extra.parts"))

    token = make_token()
    damaged = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")
    with pytest.raises(AuthenticationError):
        run(authenticator.authenticate(damaged))


def test_dependency_rejects_missing_and_wrong_scheme(authenticator):
    for credentials in (
        None,
        HTTPAuthorizationCredentials(scheme="Basic", credentials="secret"),
    ):
        with pytest.raises(HTTPException) as raised:
            run(authenticator(credentials))
        assert raised.value.status_code == 401
        assert raised.value.headers == {"WWW-Authenticate": "Bearer"}


def test_dependency_converts_token_errors_to_401(authenticator):
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="broken")

    with pytest.raises(HTTPException) as raised:
        run(authenticator(credentials))

    assert raised.value.status_code == 401


def test_dependency_returns_valid_principal(authenticator, make_token):
    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials=make_token()
    )

    assert run(authenticator(credentials)).subject == "user-123"


def test_organization_guard_enforces_exact_scope(authenticator):
    principal = Principal("user-123", "org-acme", frozenset({Role.ORG_ADMIN}))
    guard = require_organization(lambda: principal)

    assert run(guard("org-acme", principal)) is principal
    with pytest.raises(HTTPException) as raised:
        run(guard("org-other", principal))
    assert raised.value.status_code == 404


def test_role_guard_allows_any_declared_role(authenticator):
    principal = Principal("user-123", "org-acme", frozenset({Role.SECURITY_REVIEWER}))
    guard = require_roles(lambda: principal, Role.ORG_ADMIN, Role.SECURITY_REVIEWER)

    assert run(guard(principal)) is principal


def test_role_guard_denies_wrong_role(authenticator):
    principal = Principal("user-123", "org-acme", frozenset({Role.VIEWER}))
    guard = require_roles(lambda: principal, Role.AUTHORIZED_APPROVER)

    with pytest.raises(HTTPException) as raised:
        run(guard(principal))
    assert raised.value.status_code == 403


def test_custom_verifier_loader_and_clock_are_injectable(settings):
    calls = []

    async def load(uri):
        calls.append(("load", uri))
        return {"keys": []}

    def verify(signing_input, signature, header, jwks):
        calls.append(("verify", header["kid"], jwks))

    header = encode(b'{"alg":"RS256","kid":"test"}')
    claims = encode(
        json.dumps(
            {
                "iss": settings.issuer,
                "aud": settings.audience,
                "sub": "subject",
                "org_id": "organization",
                "roles": ["org_admin"],
                "role": "authenticated",
                "is_anonymous": False,
                "aal": "aal2",
                "amr": [{"method": "totp", "timestamp": NOW}],
                "session_id": "session",
                "iat": NOW,
                "exp": NOW + 1,
            }
        ).encode()
    )
    token = f"{header}.{claims}.{encode(b'signature')}"
    auth = OIDCAuthenticator(
        settings, jwks_loader=load, verifier=verify, clock=lambda: NOW
    )

    identity = run(auth.authenticate(token))

    assert identity.organization_hint == "organization"
    assert not hasattr(identity, "roles")
    assert [call[0] for call in calls] == ["load", "verify"]


def test_sensitive_authorization_requires_recent_reauthentication():
    stale = Principal(
        "user-123",
        "org-acme",
        frozenset({Role.ORG_ADMIN}),
        reauthenticated_at=datetime.fromtimestamp(NOW - 901, timezone.utc),
    )
    with pytest.raises(HTTPException) as raised:
        authorize_request(
            stale,
            "org-acme",
            frozenset({Role.ORG_ADMIN}),
            sensitive=True,
            now=datetime.fromtimestamp(NOW, timezone.utc),
            reauthentication_window=timedelta(minutes=15),
        )
    assert raised.value.status_code == 401
    assert raised.value.detail == "recent reauthentication required"
