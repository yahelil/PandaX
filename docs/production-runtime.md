# Actis production runtime

The React dashboard and FastAPI engine share product and release vocabulary but
remain separately deployable. Dashboard screens depend on typed data adapters;
the production adapter calls the `/v1` API while the demo adapter retains the
same screen contract with deterministic fixture data.

## Database

Set `PANDAX_DATABASE_URL` to a PostgreSQL SQLAlchemy URL, then apply migrations:

```bash
uv run alembic upgrade head
```

The API never creates tables for a configured production database. Without
`PANDAX_DATABASE_URL`, local development uses
`$PANDAX_DATA_DIR/portfolio.sqlite3` and creates the portfolio schema on first
use. SQLite is a local convenience, not the production datastore.

## Authentication

Portfolio endpoints validate asymmetric Supabase OIDC access tokens. Configure:

- `PANDAX_OIDC_ISSUER`
- `PANDAX_OIDC_AUDIENCE`
- `PANDAX_OIDC_JWKS_URI`

The verifier accepts signed `ES256` or `RS256` keys from JWKS and requires an
interactive `authenticated` user, `aal2`, a TOTP authentication method, a
session ID, and standard issuer, audience, issued-at, and expiry claims. Disable
public and anonymous sign-up in Supabase, invite users through a trusted admin,
and require TOTP enrollment before beta access.

Tokens establish identity only. An organization path parameter or
`X-Organization-ID` header selects the tenant; a signed `org_id` claim is only a
fallback hint. The API then resolves an exact active, unexpired, non-revoked,
non-removed membership in PostgreSQL. Token role claims are ignored. Known
application roles are `org_admin`, `compliance_operator`,
`authorized_approver`, `security_reviewer`, and `viewer`.

Missing OIDC configuration returns `503`; missing or invalid credentials return
`401`; missing membership and cross-organization reads are hidden as `404` on
tenant routes; unauthorized operations return `403`. Sensitive writes require
the TOTP authentication timestamp to be no older than 15 minutes and otherwise
return `401` with `insufficient_authentication`.

Organization admins and compliance operators can change product and release
records. All known roles can read records in their own organization.
Memberships can be invited, active, disabled, revoked, removed, or time-limited;
removed memberships cannot be restored. Admin audit events record the verified
subject for every mutation in an append-only, per-organization SHA-256 chain.

Apply `alembic upgrade head` before deploying this version. Rollback requires
draining writes, deploying the prior application, then running
`alembic downgrade 20260915_0010`.

The identity adapter is provider-neutral. A later Entra or Okta OIDC/SAML bridge
must return the same verified subject, session, and MFA timestamps; it must not
grant organization roles from provider claims.

When the dashboard and API use different origins, set `PANDAX_CORS_ORIGINS` to
a comma-separated allowlist such as `https://dashboard.actis.example.com`.
Wildcards, credentials in origins, paths, and non-local HTTP origins are rejected.
Leave it empty when a same-origin reverse proxy serves both applications.

## Local commands

```bash
uv sync --extra dev
uv run alembic upgrade head
uv run uvicorn pandax.server:api --app-dir apps/engine --reload
npm run demo
```

Use `.env.example` as a configuration inventory. Never store real database
passwords, tokens, or private keys in tracked environment files.
