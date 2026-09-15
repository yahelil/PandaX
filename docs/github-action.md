# Actis by PandaX GitHub Action

Actis can analyze an existing CycloneDX or SPDX JSON SBOM during CI. It emits:

- a sealed evidence bundle;
- a compact JSON summary for automation;
- SARIF 2.1.0 for GitHub code scanning.

The JSON and SARIF files are derived after sealing and intentionally written outside the evidence bundle. Adding them to the bundle after sealing would invalidate verification.

## Pilot usage

Until Actis has a published, licensed release, check out the private action at
an exact audited commit:

```yaml
name: Actis

on:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Checkout Actis
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          repository: yahelil/PandaX
          ref: <PANDAX_COMMIT_SHA>
          token: ${{ secrets.PANDAX_REPOSITORY_TOKEN }}
          path: .pandax-action
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.12"
      - id: pandax
        uses: ./.pandax-action
        with:
          sbom: path/to/bom.cdx.json
          output: pandax-results
      - uses: github/codeql-action/upload-sarif@c20e34f438d671fc35777cc9820dd7adf8252874 # v3
        if: always() && hashFiles('pandax.sarif') != ''
        with:
          sarif_file: ${{ steps.pandax.outputs.sarif }}
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
        if: always()
        with:
          name: pandax-evidence
          path: |
            ${{ steps.pandax.outputs.evidence-bundle }}
            ${{ steps.pandax.outputs.summary }}
```

Give `PANDAX_REPOSITORY_TOKEN` read-only access to PandaX. Replace the private
checkout with a direct immutable action reference after distribution terms and
release signing are established.

## Local equivalent

```bash
pip install .
actis --version
actis scan-sbom path/to/bom.cdx.json \
  --out pandax-results \
  --json-output pandax-summary.json \
  --sarif-output pandax.sarif
```

Exit codes:

- `0`: pipeline completed without a CISA KEV signal;
- `1`: pipeline or report generation failed;
- `2`: pipeline completed and a CISA KEV signal requires urgent manufacturer review.

KEV is not automatic CRA Article 14 reportability. Product containment, reliable exploitation evidence, manufacturer awareness, and human review remain separate decisions.
