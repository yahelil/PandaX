# Actis production runtime

The React dashboard and FastAPI engine share product and release vocabulary but
remain separately deployable. Dashboard screens depend on typed data adapters;
the production adapter calls the `/v1` API while the demo adapter retains the
same screen contract with deterministic fixture data.

## Database

Set `PANDAX_DATABASE_URL` to a PostgreSQL SQLAlchemy URL, then apply migrations:

```bash
uv run alembic upgrade head
```

The API never creates tables for a configured production database. Without
`PANDAX_DATABASE_URL`, local development uses
`$PANDAX_DATA_DIR/portfolio.sqlite3` and creates the portfolio schema on first
use. SQLite is a local convenience, not the production datastore.

## Authentication

Portfolio endpoints validate RS256 OIDC access tokens. Configure:

- `PANDAX_OIDC_ISSUER`
- `PANDAX_OIDC_AUDIENCE`
- `PANDAX_OIDC_JWKS_URI`

Tokens must contain `sub`, `org_id`, `exp`, and a `roles` string or array. Known
roles are `org_admin`, `compliance_operator`, `authorized_approver`,
`security_reviewer`, and `viewer`. Missing OIDC configuration returns `503`;
missing or invalid credentials return `401`; cross-organization reads are
hidden as `404`; unauthorized mutations return `403`.

Organization admins and compliance operators can change product and release
records. All known roles can read records in their own organization. Audit
events record the authenticated subject for every mutation.

## Local commands

```bash
uv sync --extra dev
uv run alembic upgrade head
uv run uvicorn pandax.server:api --app-dir apps/engine --reload
npm run demo
```

Use `.env.example` as a configuration inventory. Never store real database
passwords, tokens, or private keys in tracked environment files.
