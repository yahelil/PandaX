# Staging deployment and acceptance

Staging is the release gate for the private beta. It uses the `actis-api-staging`
Render Free service, the `actis-staging` Cloudflare Pages Free project, and a
dedicated EU Supabase Free project. Never reuse its database, storage, users,
signing material, or credentials in beta.

`render.yaml` is the only Render service definition. It declares the isolated
staging and beta services, disables automatic deploys, uses Frankfurt Free Docker
instances without disks, and checks `/health/ready`. Do not create a manual
service or enable a paid pre-deploy command.

## Controlled staging release

1. Select an exact commit whose engine, dashboard, and container CI jobs passed.
2. Record the commit. Build the candidate container from that commit.
3. Back up the staging database and private storage. Keep the backup reference,
   not credentials, in the release record.
4. From the exact candidate checkout or image, enter the staging database secret
   directly into the process environment and run `uv run alembic upgrade head`.
   Do not put the value in command history, chat, logs, Git, or documentation.
5. Confirm the database is at schema `20260915_0015`.
6. Manually deploy the exact commit to `actis-api-staging`. Keep auto-deploy off.
7. Verify `/health/live`, `/health/build`, and `/health/ready`. Readiness must show
   PostgreSQL, private Supabase Storage, signing, schema, and capacity ready.

The staging environment uses a 100 MB database hard stop and notification daily
limit of 80. Render supplies the Git commit metadata. All `sync: false` values
must be entered directly in Render and must be unique to staging.

## Dashboard

Create or connect only the `actis-staging` Cloudflare Pages Free project:

- repository: `yahelil/PandaX`
- root directory: `/`
- build command: `npm ci && npm run build:dashboard`
- output directory: `apps/dashboard/dist`
- custom domain: `staging.pandax.online`

Set `VITE_ACTIS_MODE=production` and the matching public API URL, organization
ID, Supabase URL and publishable key, OIDC issuer/client ID, redirect URI, logout
URI, and scopes. Every
`VITE_*` value is public browser configuration; never place a password, token,
service-role key, signing key, or other secret there. Set API CORS to the single
dashboard origin. Verify valid TLS and that HTTP redirects to HTTPS.

## Acceptance gate

Use one internal staging user. Enter its email and authentication details directly
in the provider UI and enroll TOTP when required. Then:

1. Create one organization, product, and release.
2. Upload `fixtures/example-sbom.cdx.json` and wait for analysis to finish.
3. Export the evidence ZIP. In a separate clean checkout, verify it with:

   ```text
   uv run actis-verify evidence.zip --trusted-key-registry staging-registry.json
   ```

4. Record only deployed Git SHA, analysis job ID, export SHA-256, verification
   result, and schema revision.
5. Restart the Render service and recheck readiness.
6. Confirm the release and job remain available. Export again and confirm its
   SHA-256 is identical.

Do not sync or deploy `actis-api-beta`, create the beta dashboard, or invite users
until every staging check passes.

## Rollback

Stop staging writes and scheduled monitoring, record the failed deploy and schema,
then restore the previous successful Render deploy. Schema `20260915_0015` is
additive and compatible with the immediately prior application; do not downgrade
only to roll back that application revision. If a later migration is incompatible,
restore matched database and storage backups into a fresh isolated staging project
before switching credentials.

For the complete runtime, signer, storage, and recovery requirements, see
`docs/production-runtime.md`. For the gated beta release, see
`docs/beta-release.md`.
