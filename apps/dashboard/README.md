# Actis dashboard

Production React application for Actis by PandaX. Demo mode uses the same routes,
components, domain types, and service boundary as the production client, backed by
browser-local fixtures. Uploaded SBOMs are the exception: their versioned Package
URLs are sent to OSV.dev for live advisory matching, and resulting findings remain
in the local demo state.

## Run demo

From repository root:

```powershell
npm install
uv run actis serve
```

Open `http://127.0.0.1:4175`. Source changes hot-reload automatically. Demo changes persist across reloads. Use **Reset demo
data** in Settings to restore the presentation baseline.

## Checks

```powershell
npm run typecheck:dashboard
npm run test:dashboard
npm run build:dashboard
npm run test:e2e --workspace @pandax/dashboard
```

## Production portfolio data

Demo builds explicitly set `VITE_ACTIS_MODE=demo`. Production builds must set
`VITE_ACTIS_MODE=production`, `VITE_ACTIS_API_URL`,
`VITE_ACTIS_ORGANIZATION_ID`, `VITE_ACTIS_OIDC_ISSUER`, and
`VITE_ACTIS_OIDC_CLIENT_ID`. Optional variables configure redirect URI, post-logout
redirect URI, scopes, and custom organization/role claim names.

The dashboard uses OIDC Authorization Code with PKCE, restores and refreshes the
browser session, and signs out through the provider's discovery metadata. No bearer
token belongs in a `VITE_*` variable: Vite embeds those values in public browser
assets. Missing production configuration fails closed and never loads fixture data.

The production adapter hydrates organization, products, releases, Home operations,
findings, compliance, documents, team, integrations, and settings from `/v1`.
Portfolio, finding, document-approval, notification, settings, and SBOM-analysis
mutations are API-first and enter the client read model only after success. Adapter
initialization and mutation failures are exposed through `adapterStatus`.

Collector packages and consented raw product artifacts use the typed production
analysis endpoint. Inputs are validated, retained behind the storage adapter, and
processed by the release-scoped worker without exposing storage references to the
browser.

The browser E2E runner uses the existing `playwright-core` dependency and an
installed Edge, Chrome, or Chromium executable. Set `ACTIS_E2E_BROWSER` when the
browser is installed at a non-standard path.
