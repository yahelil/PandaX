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

The production adapter hydrates organization, product, and release data from `/v1`
while retaining fixtures for findings, compliance, documents, settings, and analysis.
Portfolio creates are API-first and enter the local read model only after success.
Adapter initialization and mutation failures are exposed through `adapterStatus`.
