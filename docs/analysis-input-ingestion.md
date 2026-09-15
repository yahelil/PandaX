# Analysis input ingestion

Actis accepts release-bound analysis inputs through authenticated organization,
product, and release routes. The existing SBOM route remains compatible. Collector
packages and raw artifacts use:

`POST /v1/organizations/{organization_id}/products/{product_id}/releases/{release_id}/analysis-jobs/inputs`

Send multipart fields `input_type` (`collector` or `raw_artifact`), `file`, and an
`Idempotency-Key` header. Raw artifacts additionally require
`raw_artifact_consent=true`.

## Collector contract

New customer-side Collector uploads are signed `actis/manifest/v1` ZIP bundles.
The signed manifest carries `organization_id`, `product_id`, `release_id`,
`collector` (`name` and `version`), `sbom_path` (`sbom.cdx.json`), source digest,
and rules version as append-compatible fields. Payload is limited to the SBOM,
`collection-summary.json`, `coverage.json`, and the required `ledger.jsonl`.
The signed bundle also contains `manifest.json`, `manifest.sig`, and `pubkey.pem`.
The upload is accepted only when the v1 inventory, ledger, and signature pass and
the signer matches an **active**, organization-enrolled public Ed25519 key.
Unsigned packages are rejected in staging, beta, and production. Existing
`actis.collector/v1` jobs remain readable as historical inputs.

Enroll a customer key before uploading. An organization administrator with recent
MFA posts the public key and name to `/trust-keys/challenges`, signs the returned
challenge locally, and posts `challenge_id`, public key, name, and signature to
`/trust-keys`. The challenge expires after five minutes and can be used once.
The private key is never sent to Actis. The local `actis key enrollment-proof`
command requires the JSON challenge and an explicit `--signing-key` path.

The original hash-only contract below is retained for development and historical
readability; it is not a beta upload format.

A legacy Collector input is a ZIP with `actis-collector-manifest.json` at its root. The
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
entries. It verifies every declared digest before creating a job. Limits are 25 MB
compressed, 256 entries, 100 MiB uncompressed, and a 100:1 per-entry compression
ratio. The embedded SBOM is previewed deterministically and dispatched through the
existing analysis worker.

## Raw artifact contract

Raw ingestion is fail-closed. An organization administrator must first enable
`security.allow_raw_artifacts`. Each upload then requires explicit consent by an
authorized operator. Allowed filename/media-type pairs are `.zip`/
`application/zip`, `.tar`/`application/x-tar`, `.tar.gz` or `.tgz`/
`application/gzip`, and `.bin` or `.img`/`application/octet-stream`; maximum size
is 50 MB.

Accepted raw inputs retain consent actor/time, digest, media type, size, and expiry
as immutable analysis audit events and job metadata. Until a production artifact
analysis worker is configured, the job is returned as `unsupported` with an
explicit explanation. It is never given fabricated findings and cannot be started.

## Storage and retention

Input bytes are not stored in relational rows. The database keeps a content digest,
opaque object reference, metadata, and retention deadline. Development and tests use
the rooted local adapter at `PANDAX_ANALYSIS_INPUT_DIR` or
`$PANDAX_DATA_DIR/analysis-objects`. Managed environments require the private
Supabase Storage adapter and cannot fall back to local disk. Writes are atomic or
idempotent and reads re-verify SHA-256 before dispatch.

The input retention deadline comes from organization
`security.evidence_retention_months`. Completed sealed bundles are retained until
the latest of that deadline, ten years, or release support end. See the
[production runtime](production-runtime.md#evidence-storage) for bundle quotas,
export, hold, deletion, and recovery.

## Security invariants

- Authentication, organization scope, and analysis edit roles are checked before
  settings lookup or file validation.
- Reusing an idempotency key returns the same job only for the same input type and
  digest; any material change conflicts.
- API responses never expose storage object keys.
- Missing or digest-mismatched retained objects fail the running job closed.
- Legacy unauthenticated filesystem-path scan endpoints are not used.

