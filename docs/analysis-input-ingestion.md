# Analysis input ingestion

Actis accepts release-bound analysis inputs through authenticated organization,
product, and release routes. The existing SBOM route remains compatible. Collector
packages and raw artifacts use:

`POST /v1/organizations/{organization_id}/products/{product_id}/releases/{release_id}/analysis-jobs/inputs`

Send multipart fields `input_type` (`collector` or `raw_artifact`), `file`, and an
`Idempotency-Key` header. Raw artifacts additionally require
`raw_artifact_consent=true`.

## Collector contract

A Collector input is a ZIP with `actis-collector-manifest.json` at its root. The
manifest schema is versioned and bound to the route scope:

```json
{
  "schema": "actis.collector/v1",
  "product_id": "product-1",
  "release_id": "release-1",
  "generated_at": "2026-09-14T10:00:00Z",
  "collector": {"name": "Actis Collector", "version": "1.2.0"},
  "provenance": {"source": "ci://camera/release", "build_id": "build-1042"},
  "sbom_path": "evidence/sbom.cdx.json",
  "files": [
    {"path": "evidence/sbom.cdx.json", "sha256": "<lowercase SHA-256>"}
  ]
}
```

Every non-manifest ZIP entry must be declared exactly once. Validation rejects
absolute, traversal, backslash, non-normalized, duplicate, encrypted, and symlink
entries. It verifies every declared digest before creating a job. Limits are 25 MiB
compressed, 256 entries, 100 MiB uncompressed, and a 100:1 per-entry compression
ratio. The embedded SBOM is previewed deterministically and dispatched through the
existing analysis worker.

## Raw artifact contract

Raw ingestion is fail-closed. An organization administrator must first enable
`security.allow_raw_artifacts`. Each upload then requires explicit consent by an
authorized operator. Allowed filename/media-type pairs are `.zip`/
`application/zip`, `.tar`/`application/x-tar`, `.tar.gz` or `.tgz`/
`application/gzip`, and `.bin` or `.img`/`application/octet-stream`; maximum size
is 50 MiB.

Accepted raw inputs retain consent actor/time, digest, media type, size, and expiry
as immutable analysis audit events and job metadata. Until a production artifact
analysis worker is configured, the job is returned as `unsupported` with an
explicit explanation. It is never given fabricated findings and cannot be started.

## Storage and retention

Input bytes are not stored in relational rows. The database keeps a content digest,
opaque object reference, metadata, and retention deadline. Production runtime uses
the rooted local storage adapter at `PANDAX_ANALYSIS_INPUT_DIR`; otherwise it uses
`$PANDAX_DATA_DIR/analysis-objects` (or the local runtime data directory). Writes are
atomic and reads re-verify SHA-256 before dispatch. The storage protocol is the seam
for a future managed object-store adapter.

The retention deadline comes from organization
`security.evidence_retention_months`. Expiry records policy intent; a deployment
retention worker must remove expired objects and their references.

## Security invariants

- Authentication, organization scope, and analysis edit roles are checked before
  settings lookup or file validation.
- Reusing an idempotency key returns the same job only for the same input type and
  digest; any material change conflicts.
- API responses never expose storage object keys.
- Missing or digest-mismatched retained objects fail the running job closed.
- Legacy unauthenticated filesystem-path scan endpoints are not used.

