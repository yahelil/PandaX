# Zero-cost beta API migration to Oracle Always Free

The beta API on Render Free sleeps after 15 minutes without traffic. Its next
request can spend about a minute waking it. The dashboard can reveal portfolio
data before secondary sync finishes, but it cannot serve a cold API in seconds.

Move **only the beta API** to an Oracle Always Free `VM.Standard.A1.Flex` instance
in the account's EU home region. Keep Render as the fallback until the new API
passes the beta smoke tests. Oracle can reclaim idle Always Free instances and
may have no A1 capacity; this route improves normal availability but has no
uptime guarantee.

References: [Render Free limits](https://render.com/docs/free),
[Oracle Always Free limits](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm),
and [Cloudflare Tunnel setup](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel/).

## Prerequisites

- Oracle Free Tier account with an A1 instance available in its home region.
- `VM.Standard.A1.Flex`, at most 2 OCPUs and 12 GB RAM across all A1 instances,
  with an Always Free eligible Ubuntu image and boot volume.
- Existing Cloudflare zone and Pages dashboard; an outbound Cloudflare Tunnel
  publishes the API without opening an inbound API port on the VM.
- Existing beta database, private storage, OIDC provider, signing keys, and
  scheduler secret. Copy their values directly between the providers' secret
  stores; never place them in Git, shell history, or chat.

## Cutover

1. Provision the A1 VM, install Docker, and allow SSH only from the operator's
   IP. Do not open the API port to the Internet.
2. Clone the exact tested Git commit on the VM. Build the existing Dockerfile
   for `linux/arm64`; the bootstrap pins and verifies the ARM64 Syft binary.
   Run the container with the current beta environment variables, a restart
   policy, and port 10000 bound to `127.0.0.1` only. Keep the same Supabase
   database and storage; do not run migrations merely for this move.
3. Create a remotely managed Cloudflare Tunnel on the VM. Route a dedicated
   HTTPS API hostname to `http://localhost:10000`. Store its token on the VM,
   outside Git. Keep authentication and the beta dashboard origin in
   `PANDAX_CORS_ORIGINS`.
4. Verify `/health/live`, `/health/build`, and `/health/ready` through the new
   hostname. Run the beta authentication, portfolio, scan, document, storage,
   persistence, and secret-redaction smoke tests from `docs/beta-release.md`.
5. Rebuild Cloudflare Pages with `VITE_ACTIS_API_URL` set to the new hostname.
   Check a fresh browser session: Home, product, release, findings, and a
   mutation. Measure first load and a second load after 20 minutes idle.
6. Point the existing hourly release-monitoring Worker at the new hostname.
   Verify one scheduled run. Keep the old Render service available for rollback
   until these checks pass, then retire it to preserve free instance hours.

## Rollback

Restore the previous Pages `VITE_ACTIS_API_URL` and Worker `PANDAX_API_URL`,
redeploy the prior Pages build, and confirm the Render API is ready. The database
and storage stay shared during cutover, so no data copy or restore is required.

Do not switch traffic if the A1 image build, readiness, or smoke tests fail.
