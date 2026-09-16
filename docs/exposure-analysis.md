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

Every scan writes this assessment, even when no exposure context or telemetry is
available. Missing evidence therefore produces an explicit
`insufficient_evidence` result instead of silently omitting reachability analysis.

Each assessment also contains a deterministic advisory `recommendation` with a
reachability value (`reachable`, `not_reachable`, or `review`), confidence,
stable reason codes, limitations, and a suggested VEX state. Exact reviewed
evidence that the component was excluded, the vulnerable feature was disabled,
or a build flag supports non-reachability can produce a high-confidence
`not_reachable` recommendation. Network non-exposure alone cannot. Approved
execution or network-exposure telemetry and explicit reachability build flags
can produce a high-confidence `reachable` recommendation. Conflicting or
insufficient evidence always recommends review.

It also records the declared dependency path, positive and negative evidence,
reviewed build flags, configuration facts, and approved runtime observations.
Each reviewed build flag states whether that exact flag value supports
reachability, supports non-reachability, or is neutral. Context entries that do
not match the SBOM, or match a component without a vulnerability finding, are
listed separately rather than ignored.
The original context is represented by a SHA-256 receipt; only its strict,
minimal form is retained in the signed bundle.

These labels and recommendations are review aids, not final decisions. PandaX
does not automatically apply the suggested VEX state, change final reachability,
declare exploitation, determine CRA reportability, or start a statutory deadline.
The authorized company reviewer remains responsible for the final
product-specific decision.

## Hosted review and VEX export

Completed hosted analyses project the signed bundle's findings and advisory
recommendations into the release findings workspace. The **Low-noise review**
view shows undecided, high-confidence `not_reachable` recommendations. A
Security Reviewer or Organization Admin may approve up to 100 selected findings
after supplying a rationale and explicitly confirming the decision. The service
validates every finding and version atomically, then writes a separate immutable
decision and audit entry for each finding.

Reviewed release state is available as CycloneDX 1.6 VEX from:

```text
GET /v1/organizations/{organization_id}/products/{product_id}/releases/{release_id}/findings/vex
```

The export is generated from current hosted decisions; it does not modify the
original signed scan bundle. Only an approved `not_affected` decision with a
standards-mapped justification reduces risk in the VEX output. Unreviewed,
conflicting, deferred, or otherwise incomplete findings remain `in_triage`.

Raw configuration files, logs, commands, environment variables, and secrets are
not accepted. Evidence references must be short identifiers that point to the
company's separately controlled records.
