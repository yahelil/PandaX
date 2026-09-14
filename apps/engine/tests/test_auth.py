from __future__ import annotations

import asyncio
import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from pandax.auth import (
    AuthenticationError,
    OIDCAuthenticator,
    OIDCSettings,
    Principal,
    Role,
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
            "roles": ["viewer", "security_reviewer"],
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


def test_valid_token_returns_typed_principal(authenticator, make_token):
    principal = run(authenticator.authenticate(make_token()))

    assert principal == Principal(
        subject="user-123",
        organization_id="org-acme",
        roles=frozenset({Role.VIEWER, Role.SECURITY_REVIEWER}),
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://attacker.example/"},
        {"aud": "another-api"},
        {"exp": NOW},
    ],
    ids=["wrong-issuer", "wrong-audience", "expired"],
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
    guard = require_organization(authenticator)

    assert run(guard("org-acme", principal)) is principal
    with pytest.raises(HTTPException) as raised:
        run(guard("org-other", principal))
    assert raised.value.status_code == 403


def test_role_guard_allows_any_declared_role(authenticator):
    principal = Principal("user-123", "org-acme", frozenset({Role.SECURITY_REVIEWER}))
    guard = require_roles(
        authenticator, Role.ORG_ADMIN, Role.SECURITY_REVIEWER
    )

    assert run(guard(principal)) is principal


def test_role_guard_denies_wrong_role(authenticator):
    principal = Principal("user-123", "org-acme", frozenset({Role.VIEWER}))
    guard = require_roles(authenticator, Role.AUTHORIZED_APPROVER)

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
                "roles": ["compliance_operator", "unknown-role"],
                "exp": NOW + 1,
            }
        ).encode()
    )
    token = f"{header}.{claims}.{encode(b'signature')}"
    auth = OIDCAuthenticator(
        settings, jwks_loader=load, verifier=verify, clock=lambda: NOW
    )

    principal = run(auth.authenticate(token))

    assert principal.roles == frozenset({Role.COMPLIANCE_OPERATOR})
    assert [call[0] for call in calls] == ["load", "verify"]
