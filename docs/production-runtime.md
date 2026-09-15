# Actis production runtime

The React dashboard and FastAPI engine share product and release vocabulary but
remain separately deployable. Dashboard screens depend on typed data adapters;
the production adapter calls the `/v1` API while the demo adapter retains the
same screen contract with deterministic fixture data.

## Database

Use separate EU-primary Supabase Free projects for `staging` and `beta`; never
reuse their database URL, password, or service role. Set `PANDAX_ENVIRONMENT`
and provide `PANDAX_DATABASE_URL` through the deployment secret manager, then
apply migrations:

```bash
uv run alembic upgrade head
```

The API never creates tables for a configured managed database. `staging`,
`beta`, and `production` fail before serving if the URL is missing or is not
PostgreSQL. Without `PANDAX_DATABASE_URL`, local development uses
`$PANDAX_DATA_DIR/portfolio.sqlite3` and creates the portfolio schema on first
use. SQLite is a local convenience, not the production datastore.

Application connections use a three-connection pool with two bounded overflow
connections, a five-second acquisition/connect timeout, pre-ping, five-minute
recycling, and server-side statement, lock, and idle-transaction timeouts.
Prepared statements are disabled for transaction-pooler compatibility. Each
Render service therefore consumes at most five database connections.

Set `PANDAX_DATABASE_HARD_STOP_MB=100` in staging and `250` in private beta.
These reservations enforce the 350 MB aggregate policy without borrowing.
At 70% the readiness response reports `warning`; at 80% background monitoring
growth stops and responses report `restricted`; at 100% new `/v1` mutations
return `507` while reads remain available. Never raise a stop above 350 MB.

`GET /health/live` reports process liveness without touching the database.
`GET /health/ready` checks database connectivity, the Alembic revision, capacity,
and evidence-storage readiness; a database or storage failure, unapplied migration,
or the hard stop returns `503`.

Alembic takes a PostgreSQL advisory lock, so a second migration fails before
changing schema. Promote with expand/migrate/contract ordering: migrate staging,
run smoke tests, drain beta writes, back up, migrate beta, then deploy. A failed
migration leaves the prior revision available; deploy the prior application and
rehearse `alembic downgrade` before relying on that rollback.

The operations owner stores encrypted logical backups on the company backup
machine, never in Render or the repository. A restore rehearsal uses a fresh
database and verifies both the Alembic revision and representative tenant data:

```bash
pg_dump --format=custom --no-owner --no-privileges \
  --file actis-$(date +%Y%m%dT%H%M%S).dump "$PANDAX_DATABASE_URL"
pg_restore --no-owner --no-privileges \
  --dbname "$PANDAX_RESTORE_DATABASE_URL" actis-YYYYMMDDTHHMMSS.dump
```

Do not print either URL, enable shell tracing, or restore over a live database.
Card d08 owns scheduled backups, encryption/media handling, and recurring drills.

## Evidence storage

Create a private `actis-evidence` bucket in each separate staging and private-beta
Supabase project. Configure `PANDAX_STORAGE_URL`, `PANDAX_STORAGE_SECRET_KEY`, and
`PANDAX_STORAGE_BUCKET` with that environment's secret manager. The API checks that
the bucket is reachable and private before serving. Managed environments reject the
local adapter; no evidence depends on the Render filesystem.

The server uploads analysis inputs and deterministic ZIP exports directly to private
Storage and proxies authorized downloads. It never returns object keys, service
credentials, or unrestricted bucket URLs. Every read verifies the PostgreSQL digest.
Application limits are 25 MB for Collector packages, 50 MB for other objects,
200 MB active storage per organization, and 800 MB per Supabase project.

Sealed evidence is retained until the latest of its configured organization policy,
120 months, or release support end. A legal hold blocks every deletion path. After
retention, an authorized deletion records a digest-bound receipt and a 30-day backup
expiry. Restore database metadata and bucket objects together, verify every stored
SHA-256, then run the independent verifier against an exported ZIP before reopening
traffic. Card d08 owns recurring company-machine backups and full restore drills.

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
`alembic downgrade 20260915_0011`.

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
