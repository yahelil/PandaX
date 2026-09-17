# Beta container release

This is the single runbook and dependency inventory for the Render beta API.
Render Free does not support pre-deploy commands, so migrations are deliberately
separate from web startup. Auto-deploy is disabled in `render.yaml`.

## Runtime inventory

| Item | Exact version/source | Integrity | Purpose and use |
|---|---|---|---|
| Python | `python:3.12.14-slim-bookworm@sha256:782412…2254` | OCI manifest digest | FastAPI runtime |
| Python packages | `uv.lock` revision 3; installed by uv 0.12.8 with `uv sync --locked` | Package hashes in `uv.lock` | Complete runtime dependency graph |
| FastAPI | 0.141.1 | `uv.lock` hash | HTTP API in `pandax.server` |
| Uvicorn | 0.52.4 | `uv.lock` hash | One-process ASGI server bound to `$PORT` |
| SQLAlchemy / Alembic / psycopg | 2.0.52 / 1.20.0 / 3.3.5 | `uv.lock` hashes | PostgreSQL state and schema migrations |
| Typst Python binding | 0.15.0 | `uv.lock` hash | PDF/A-2b generation in `stages/dossier.py` |
| Syft | 1.51.1, official Anchore archive | SHA-256 in `tools/bootstrap.py` | Hosted artifact-to-CycloneDX scan |
| veraPDF | 1.30.2, official greenfield installer | Installer and CLI JAR SHA-256 | Standards-aware PDF/A-2b validation in `pdfa.py` |
| Eclipse Temurin JRE | `21.0.11_10-jre-jammy@sha256:d63bd…dc13` | OCI manifest digest; copied from build stage | Runs veraPDF CLI |
| PostgreSQL | External beta Supabase project | TLS connection; readiness and Alembic revision checks | Durable relational/audit state |
| Supabase Storage | External private `actis-evidence` bucket | Authenticated API; bucket privacy readiness check; object SHA-256 | Uploaded inputs and sealed evidence bundles |
| Supabase OIDC/JWKS | Configured beta issuer/audience/JWKS URL | ES256/RS256 signature and claim validation | Interactive user authentication |
| OSV, CISA KEV, EPSS | HTTPS APIs/feeds with bounded client timeouts | Response validation and evidence provenance | Vulnerability and exploitation context |
| Cloudflare scheduler | External cron-only worker plus 32+ character shared secret | Authenticated internal endpoint | Hourly release-monitoring wake-up |

No system PDF utility is required: Typst produces PDF/A-2b and veraPDF validates
it. Container build and `tools/container_smoke.py` exercise the real dossier
compiler seam and validator, plus a real Syft scan.

## Required beta configuration

`render.yaml` contains safe non-secret values and prompts for all installation-
specific values. Use separate beta values from `.env.example`; never pass secrets
as Docker `ARG` instructions. Render provides `RENDER_GIT_COMMIT` automatically.
`GET /health/build` exposes only application version, Git SHA, derived release ID,
and optional build timestamp.

## Controlled release

1. Select an exact commit and wait for its CI container job to pass.
2. Build/tag the candidate image from that commit. Record its repository digest.
3. Create an encrypted logical PostgreSQL backup on the company backup machine;
   retain its non-secret backup reference.
4. Run the migration from the exact candidate image with the beta environment
   injected at runtime (never at build time):

   ```text
   python tools/beta_release.py --backup-reference <backup-reference>
   ```

   The guard refuses non-beta, missing mandatory configuration, non-PostgreSQL,
   absent backup reference, or a final schema other than `20260917_0016`.
5. Manually deploy that exact Git commit in Render. Do not enable branch auto-deploy.
6. Wait for `/health/ready`, then run HTTPS authentication, database, storage,
   scan, document, restart-persistence, and secret-redaction smoke tests.
7. Record Git SHA, image digest, Render deploy ID, release ID, configuration
   version, backup reference, and schema revision in the release ticket.

## Rollback

Migration `20260915_0015` adds only the isolated
`organization_trust_key_challenges` table, so the immediately previous
application revision remains schema-compatible. For rollback:

1. Stop beta mutations and scheduled monitoring.
2. Record current deploy ID and schema revision.
3. Redeploy the previous immutable Git commit/image using Render rollback.
4. Verify `/health/live`, `/health/build`, and `/health/ready`; run API smoke tests.
5. Re-enable beta traffic and scheduler.

Do not downgrade merely to roll back this application revision. If a later
backward-incompatible migration exists, restore the matched database and object-
storage backup together in a fresh beta project, verify hashes, switch secrets,
then deploy the matched application image.
