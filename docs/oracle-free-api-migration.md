# Zero-cost live API migration to Oracle Always Free

The live `actis.pandax.online` dashboard used `actis-api-staging.onrender.com`.
Render Free sleeps after idle time, delaying the next visit. The replacement API
runs on an Oracle Always Free VM in Israel Central (Jerusalem); the Render
service remains available for rollback with automatic deploys disabled.

The VM uses `VM.Standard.A1.Flex` with 2 OCPUs, 12 GB RAM, and a 46.6 GiB
Ubuntu 24.04 ARM64 boot volume. Keep the account on Free Tier, stay within
[Oracle's Always Free limits](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm),
and do not enable paid resources. Oracle may reclaim idle Always Free VMs.

## VM configuration

- The Docker image is built from the tested Git commit on the VM. The API
  container restarts automatically and binds port 10000 to `127.0.0.1` only.
- Render's staging `.env` was copied over SSH, stripped of Render's quoting on
  two signing keys, and stored at `/etc/actis-api.env`, owned by root with mode
  600. Never put this file, the SSH private key, or values in Git or chat.
- Ubuntu's Caddy service uses [deploy/oracle/Caddyfile](../deploy/oracle/Caddyfile)
  to serve `https://actis-api.pandax.online` and reverse proxy to the API.
  The VM's security list and persistent host firewall allow inbound TCP 80 and
  443. SSH remains on 22; the API port is not public.
- The existing Cloudflare Free DNS zone has a proxied A record for
  `actis-api.pandax.online`. Cloudflare's [free Universal SSL](https://developers.cloudflare.com/ssl/edge-certificates/universal-ssl/)
  covers this first-level subdomain. Certificate issuance may require setting
  the record to DNS only temporarily, then restoring Proxied.
- Cloudflare Zero Trust was not activated because its checkout required
  authorization for usage charges.

Check `/health/live`, `/health/build`, and `/health/ready` through the public
hostname before deployment. Confirm CORS for `https://actis.pandax.online` and
that unauthenticated portfolio requests return 401. The database and storage
stay shared with Render; do not run migrations just for the hosting move.

## Dashboard cutover

Cloudflare Pages project `actis-staging` builds `main` automatically. Set its
production `VITE_ACTIS_API_URL` to `https://actis-api.pandax.online`, then deploy
the tested dashboard commit. Check a fresh authenticated session: Home,
products, releases, findings, and one safe mutation. Measure first load and a
second visit after 20 minutes idle. The dashboard now shows base portfolio data
before analysis jobs and other secondary requests finish.

If the hourly `actis-release-monitoring` Worker is deployed later, set its
`PANDAX_API_URL` to the new hostname and configure the scheduler secret. It was
not deployed in the Cloudflare account during this migration.

## Rollback

Restore the previous Pages `VITE_ACTIS_API_URL` value,
`https://actis-api-staging.onrender.com`, and redeploy the prior Pages build.
The existing database and storage require no data copy. Keep Render on its Free
plan and automatic deploys off while it serves as fallback.
