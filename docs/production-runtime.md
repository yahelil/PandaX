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

## Scheduled release monitoring

Managed Render services do not run an in-process release-monitoring timer. One
cron-only Cloudflare Worker wakes the API hourly and waits for a single bounded
batch at `POST /internal/jobs/release-monitoring`. The API claims at most 25 due
releases through PostgreSQL; leases make overlapping invocations safe, and the
80% database-capacity stop is applied before any work is claimed.

Generate a different random value of at least 32 characters for staging and beta.
Store it as `PANDAX_SCHEDULER_SECRET` in both the Render service and the Worker's
encrypted secrets. Set the Worker's `PANDAX_API_URL` variable to the HTTPS Render
origin. Never place the secret in Wrangler configuration, logs, or Git. The Worker
has no public HTTP handler, performs no retry, and uses only the hourly cron in
`apps/release-monitoring-worker/wrangler.jsonc`.

A run loads `sbom.cdx.json` from the latest completed release evidence bundle,
refreshes OSV, CISA KEV, and EPSS, and upserts only observed findings. Human
decisions and findings not returned by a refresh are retained. Source or evidence
failures record degraded/failed monitoring history rather than implying a clean
release. Verify staging by invoking one scheduled event, checking the PostgreSQL
monitoring event, restarting Render, and confirming the same status and finding
history remain visible.

## Evidence signing custody

Every sealing path uses the same provider-neutral Ed25519 signer. Development
and tests default to a generated file under `~/.pandax`. Staging and private beta
reject file signing and require `PANDAX_SIGNER_PROVIDER=secret`, an explicit key
ID/version, and a base64 PKCS#8 Ed25519 key supplied by the deployment secret
manager. The key is decoded in memory and is never written to the Render
filesystem. Keep the source key outside Git and delete any temporary provisioning
copy only after its public key and recovery copy have been verified.

Production rejects both file and secret signers. Install the optional client and
configure an exact enabled Ed25519 key version:

```bash
uv sync --extra kms
PANDAX_ENVIRONMENT=production
PANDAX_SIGNER_PROVIDER=google-cloud-kms
PANDAX_GCP_KMS_KEY_VERSION=projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY/cryptoKeyVersions/VERSION
```

Application Default Credentials belong in the deployment secret manager. Bind
the runtime identity on that one CryptoKey only, with
`cloudkms.cryptoKeyVersions.get`, `cloudkms.cryptoKeyVersions.viewPublicKey`, and
`cloudkms.cryptoKeyVersions.useToSign`. Do not grant key creation, update,
disable, destroy, IAM administration, or project-wide KMS roles. Use an
`ASYMMETRIC_SIGN` / `EC_SIGN_ED25519` key; choose `HSM` protection at production
provisioning if approved. PandaX submits canonical manifest bytes as raw Ed25519
data and verifies the returned signature locally before publishing it.

`PANDAX_SIGNING_KEY_REGISTRY_B64` is base64 JSON conforming to
`actis/signing-key-registry/v1`. It contains public PEM keys only, exactly one
`active` entry, and any `historical` or `revoked` versions. Production readiness
requires its active fingerprint to match the exact KMS version. The public copy
is available at `GET /.well-known/actis-signing-keys.json`; distribute or archive
that response through an authenticated channel before relying on it as trust.

### Planned rotation drill

1. Preserve current registry and a pre-rotation evidence bundle on the encrypted
   company backup machine. Never destroy the old KMS version.
2. Create an approved new `EC_SIGN_ED25519` version without changing runtime IAM.
3. Retrieve its public key while enabled, verify its fingerprint independently,
   add it as `active`, and change the old entry to `historical`.
4. Update registry secret and exact KMS version in one deployment. Readiness must
   pass before traffic is restored; it never falls back to another or local key.
5. Seal and verify a new bundle, then verify the preserved old bundle with the
   same registry and `actis-verify --trusted-key-registry REGISTRY`.
6. Roll back by restoring both prior configuration values together. Record the
   registry digest, deployment revision, bundle IDs, and verification results.

### Compromise, revocation, and recovery drill

1. Stop sealing work. Preserve the affected public key and change its registry
   status to `revoked` before disabling it; Google exposes asymmetric public keys
   only while their versions are enabled.
2. Rotate to a clean version. Disable the compromised version; never destroy it
   because historical signatures still need its public identity.
3. Confirm affected bundles remain internally valid but return `untrusted` with
   the revoked registry. Confirm new bundles are trusted.
4. For accidental disable, re-enable the preserved version during its recovery
   window, cross-check its fingerprint, restore matching configuration, and
   repeat both verification checks.

KMS failures abort before any manifest, signature, or bundled public key is
published. Readiness returns `503` when production custody is unavailable.
Enable Cloud KMS Data Access audit logs for signing and retain Admin Activity
logs for key/IAM changes. Correlate them with PandaX `evidence.sign` logs by run
ID, key ID/version, payload SHA-256, outcome, and latency. Logs must never contain
credentials, private keys, raw manifests, or signatures.

At each production release, test provider outage, registry mismatch, rotation,
revoked-key verification, rollback, and accidental-disable recovery. Private
beta performs the equivalent two-secret rotation locally and creates no Google
Cloud resource or cost.

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

Apply `alembic upgrade head` before deploying this version. Current head
`20260915_0015` is additive and remains compatible with the immediately prior
application; normal application rollback therefore does not downgrade schema.
Use [the beta release runbook](beta-release.md) for the exact rollback sequence.

The identity adapter is provider-neutral. A later Entra or Okta OIDC/SAML bridge
must return the same verified subject, session, and MFA timestamps; it must not
grant organization roles from provider claims.

When the dashboard and API use different origins, set `PANDAX_CORS_ORIGINS` to
a comma-separated allowlist such as `https://dashboard.actis.example.com`.
Wildcards, credentials in origins, paths, and non-local HTTP origins are rejected.
Leave it empty when a same-origin reverse proxy serves both applications.

## Notification delivery

The in-app inbox is always the fallback. Connected Resend, signed-webhook, and
Jira integrations add idempotent PostgreSQL outbox jobs; they never replace the
inbox record. Set `PANDAX_NOTIFICATION_DAILY_LIMIT` (default 500 per organization)
and `PANDAX_NOTIFICATION_DELIVERY_SECONDS` (default 30). Capacity hard stops pause
the worker without discarding queued work. Attempts use bounded exponential retry;
permanent failures and exhausted retries remain visible as dead letters through
`GET /v1/organizations/{organization_id}/notifications/deliveries`.

Admins configure integrations through the organization settings API. Credentials
remain in the deployment secret manager. For each stored secret reference, inject
a JSON string map under `PANDAX_NOTIFICATION_SECRET_<HASH>`, where `<HASH>` is the
uppercase first 16 characters of its SHA-256 digest. Resend needs `api_key`; a
webhook needs `endpoint_url` and a random `signing_secret` of at least 32
characters; Jira needs `email` and `api_token`. For example, calculate the variable
name for `vault://actis/acme/email` without printing its value:

```bash
python -c "import hashlib; print('PANDAX_NOTIFICATION_SECRET_' + hashlib.sha256(b'vault://actis/acme/email').hexdigest()[:16].upper())"
```

Webhook messages carry an idempotency key plus `X-Actis-Timestamp` and an HMAC
SHA-256 `X-Actis-Signature`; receivers must check all three. HTTPS, public literal
addresses, and a 10-second timeout are enforced. Keep network egress allowlisted
because DNS names can change after validation.

Resend and webhook failures retry on timeouts, rate limits, and server errors.
Jira requests are not automatically retried after an indeterminate network/server
failure because Jira cannot guarantee idempotent issue creation; reconcile the
project, then use the admin retry endpoint. No live recipient is contacted until
an integration is explicitly marked connected and its external secret is present.

## Local commands

```bash
uv sync --extra dev
uv run alembic upgrade head
uv run uvicorn pandax.server:api --app-dir apps/engine --reload
npm run demo
```

Use `.env.example` as a configuration inventory. Never store real database
passwords, tokens, or private keys in tracked environment files.
