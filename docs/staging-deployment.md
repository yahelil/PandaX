# Staging and private-beta deployment

## Decision

Deploy the React dashboard to two Cloudflare Pages Free projects and the FastAPI
container to two Render Free web services. Each environment has its own EU-primary
Supabase Free project for PostgreSQL, invite-only Auth, and private Storage. Render
runs in Frankfurt. Expected platform cost is **$0/month** with no payment method;
services suspend instead of incurring overage. Free Render services cold-start and
share 750 monthly instance hours, so staging is suspended first if usage approaches
the allowance.

This keeps the existing modular monolith and avoids Kubernetes, microservices,
persistent Render disks, R2, paid pre-deploy commands, and multiple regions. The
container runs migrations at startup because Render pre-deploy commands are paid.
PostgreSQL's advisory migration lock makes concurrent startup safe.

## Isolated resources

| Environment | Dashboard | API | Data/Auth/Storage | Database stop |
|---|---|---|---|---:|
| Staging | `actis-staging` Pages project | `actis-api-staging` Render service | dedicated Supabase project and `actis-evidence` private bucket | 100 MB |
| Private beta | `actis-beta` Pages project | `actis-api-beta` Render service | dedicated Supabase project and `actis-evidence` private bucket | 250 MB |

Never copy database URLs, service keys, signing keys, or OIDC projects between the
two rows. Store every secret only in the provider dashboards. Do not add a payment
method or enable R2, Supabase Pro/PITR, Render paid compute, or automatic upgrades.

## Provisioning order

1. Create two Supabase Free projects in the nearest available EU region. Disable
   public and anonymous sign-up, require TOTP MFA, and create a private
   `actis-evidence` bucket in each project.
2. Create independent Ed25519 beta signing keys and public registries. Keep the
   recovery copies outside the repository and providers.
3. In Render, apply `render.yaml` as a Blueprint from the private repository. The
   initial Blueprint contains only `actis-api-staging`; enter each `sync: false`
   value from the staging Supabase/signing environment. Confirm the service remains
   `Free`, uses no disk, and exposes `/health/ready` as the health check. The
   container is non-root and binds Render's `PORT` on `0.0.0.0`. After staging
   passes the acceptance drill, add `actis-api-beta` to the same Blueprint with its
   isolated beta values and sync it. Never create either service manually.
4. Create `actis-staging` and `actis-beta` Cloudflare Pages projects. Use repository
   root `/`, build command `npm ci && npm run build:dashboard`, and output directory
   `apps/dashboard/dist`. Set `VITE_ACTIS_MODE=production` plus the matching public
   API URL, organization ID, Supabase issuer/client ID, redirect URI, logout URI,
   and scopes. No token or private value belongs in `VITE_*`.
5. Add `staging.pandax.online` and `app.pandax.online` through each Pages project's
   **Custom domains** flow. Cloudflare supplies TLS. Enable **Always Use HTTPS** for
   the zone and verify plain HTTP redirects before sharing either URL.
6. Set each API's `PANDAX_CORS_ORIGINS` to its one matching Pages origin and redeploy.
   Do not invite private-beta customers yet.

The complete environment-variable inventory and signer/storage requirements are in
`.env.example` and `docs/production-runtime.md`.

## Acceptance drill

Run staging first. Invite only the internal staging user, enroll TOTP, create one
organization/product/release, upload `fixtures/example-sbom.cdx.json`, and wait for
the analysis job to finish. Export its evidence ZIP and verify it on a separate
checkout with:

```bash
uv run actis-verify evidence.zip --trusted-key-registry staging-registry.json
```

Record the job ID, export SHA-256, deployed commit, and verification result without
recording tokens or keys. Restart the Render service, then confirm `/health/ready`,
the same release/job, and the same export digest. Only after this passes, deploy the
private-beta environment and repeat the health, login, and empty-tenant smoke checks.

## Rollback and emergency shutdown

- Failed application deploy: restore Render's previous successful deploy. If a
  migration was applied, drain writes and run the documented Alembic downgrade only
  after confirming the old application supports it.
- Dashboard failure: roll Cloudflare Pages back to the previous deployment.
- Suspected key/data exposure: suspend both Render services, disable Pages access,
  revoke affected credentials, preserve audit evidence, and follow the signing or
  storage recovery runbook in `docs/production-runtime.md`.
- Quota warning: suspend staging first. At a hard stop, keep reads/exports available
  and reject new mutations; never upgrade automatically.
