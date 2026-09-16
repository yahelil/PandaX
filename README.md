# Actis by PandaX

Actis turns a product artifact or JSON SBOM into a signed, independently verifiable EU Cyber Resilience Act evidence bundle. It inventories software, checks vulnerability sources, records triage and reporting clocks, and produces reviewable documents. It does not submit reports on a manufacturer’s behalf.

Private-beta behavior is bounded by the [scope and acceptance gates](docs/private-beta-scope.md). Provider ownership, access, and billing follow the [zero-cost delivery policy](docs/private-beta-delivery.md).

## Get started

Run these commands from the repository root:

```bash
uv sync --extra dev
uv run actis scan-sbom fixtures/example-sbom.cdx.json
```

To scan the SmartHub demo artifact, install the pinned Syft scanner first:

```bash
uv run python tools/bootstrap.py
uv run actis scan fixtures/smarthub-sh100-v2.3.1.zip
```

Results and caches stay in the ignored `workspace/` folder. Install dashboard dependencies with `npm ci`, then run `uv run actis serve` to open the product workspace at http://127.0.0.1:4175.

The customer-facing [Windows x64 Collector](docs/windows-collector.md) creates a
minimized package signed by an explicitly configured customer key, previews the
exact upload, and sends it only after approval.

## Find your way

| Folder | Contents |
|---|---|
| `apps/` | Engine, dashboard, verifier, and demos |
| `docs/` | Product context, specifications, guides, and [published results](docs/published/README.md) |
| `fixtures/` | Reproducible sample inputs and evidence fixtures |
| `tools/` | Setup, evaluation, and review helpers |
| `alembic/` | Database migrations |

The root configuration files remain here because package managers, migrations, and the [GitHub Action](docs/github-action.md) use them directly.

Read the [full technical guide](docs/technical-guide.md) for pipeline checks, limits, and architecture. The [release scenario guide](docs/release-scenarios.md), [verifier](apps/verifier/README.md), and [dashboard handoff](docs/actis-dashboard-handoff/README.md) cover their respective workflows.
