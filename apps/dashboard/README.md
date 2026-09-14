# Actis dashboard

Production React application for Actis by PandaX. Demo mode uses the same routes,
components, domain types, and service boundary as the production client, backed by
deterministic browser-local fixtures.

## Run demo

From repository root:

```powershell
npm install
npm run demo
```

Open the printed local URL. Demo changes persist across reloads. Use **Reset demo
data** in Settings to restore the presentation baseline.

## Checks

```powershell
npm run typecheck:dashboard
npm run test:dashboard
npm run build:dashboard
npm run test:e2e --workspace @pandax/dashboard
```

## Production portfolio data

Set `VITE_ACTIS_API_URL` and `VITE_ACTIS_ORGANIZATION_ID`, then install a runtime
token provider before the application module executes:

```ts
window.__ACTIS_GET_BEARER_TOKEN__ = () => oidcSession.getAccessToken();
```

No bearer token belongs in a `VITE_*` variable: Vite embeds those values in public
browser assets. Production deployment should serve the app through the FastAPI BFF,
which establishes the OIDC session and supplies a short-lived token provider. If any
production setting or provider is absent, Actis stays in deterministic fixture mode.

The production adapter hydrates organization, products, releases, Home operations,
findings, compliance, documents, team, integrations, and settings from `/v1`.
Portfolio, finding, document-approval, notification, settings, and SBOM-analysis
mutations are API-first and enter the client read model only after success. Adapter
initialization and mutation failures are exposed through `adapterStatus`.

Collector packages and raw product artifacts remain demo-only until the backend has
a signed-package format, consent audit model, retention policy enforcement, and
secure object-storage reference contract. Production never sends those inputs to
the legacy path-based scan endpoint.

The browser E2E runner uses the existing `playwright-core` dependency and an
installed Edge, Chrome, or Chromium executable. Set `ACTIS_E2E_BROWSER` when the
browser is installed at a non-standard path.
