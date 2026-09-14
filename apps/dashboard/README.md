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

Production API integration replaces the fixture adapter behind the existing data
interface; screens must not import fixture data directly.
