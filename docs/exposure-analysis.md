# Product exposure analysis

Finding a vulnerable component in a product does not prove that an attacker can
use it. The component may have been removed during the build, its vulnerable
feature may be disabled, or it may not be exposed to a network. The opposite is
also possible: runtime evidence may show that the component is loaded, executed,
or exposed.

PandaX can combine four kinds of evidence:

1. The component and dependency relationships declared by the SBOM.
2. Reviewed build inclusion and build-flag states.
3. Reviewed feature configuration and network exposure.
4. Approved runtime observations from the telemetry feature.

The company reviewer prepares the small exposure-context JSON file and validates
it before scanning:

```powershell
actis exposure validate .\exposure-context.json
actis scan .\product.zip --exposure-context .\exposure-context.json
```

For scheduled monitoring, add `--exposure-context` to `actis monitor add`.
SBOM uploads can include the context as the `exposure_context` form field.

Start with [the example context](exposure-context-example.json).

## What PandaX reports

For every matching vulnerability, `exposure-assessments.json` reports one of:

- `evidence_supports_reachable`
- `evidence_supports_not_reachable`
- `conflicting_evidence`
- `insufficient_evidence`

It also records the declared dependency path, positive and negative evidence,
reviewed build flags, configuration facts, and approved runtime observations.
Each reviewed build flag states whether that exact flag value supports
reachability, supports non-reachability, or is neutral. Context entries that do
not match the SBOM, or match a component without a vulnerability finding, are
listed separately rather than ignored.
The original context is represented by a SHA-256 receipt; only its strict,
minimal form is retained in the signed bundle.

These labels are review aids, not final decisions. PandaX does not automatically
change VEX reachability, declare exploitation, determine CRA reportability, or
start a statutory deadline. The authorized company reviewer remains responsible
for the final product-specific decision.

Raw configuration files, logs, commands, environment variables, and secrets are
not accepted. Evidence references must be short identifiers that point to the
company's separately controlled records.
