# Actis evidence bundle format v1

This document freezes the interoperable `actis/manifest/v1` evidence format.
Readers continue to accept the pre-beta `pandax/manifest/v1` identifier only so
historical evidence remains verifiable; new writers must emit the Actis identifier.

## Bundle contents

A bundle is either a directory or a ZIP whose entries are relative POSIX paths.
These root files are required:

| File | Purpose |
|---|---|
| `manifest.json` | Signed inventory and ledger commitment. |
| `manifest.sig` | Lowercase hexadecimal encoding of the 64-byte Ed25519 signature over canonical `manifest.json` (128 hex characters). |
| `pubkey.pem` | SubjectPublicKeyInfo PEM Ed25519 public key for internal signature inspection only. |
| `ledger.jsonl` | UTF-8 JSON Lines hash chain; it must also appear in `manifest.files`. |

Every other regular file is evidence and is required to appear exactly once in
`manifest.files`. No unlisted file is allowed. Directories are structural and
need not be listed. Symbolic links, encrypted ZIP entries, absolute paths,
backslashes, empty/`.`/`..` path components, duplicate or case-colliding paths,
more than 20,000 files, more than 512 MiB uncompressed content, and paths deeper
than 24 components are rejected.

## Canonical JSON and hashes

Signatures and record hashes use the following deterministic encoding:

1. Parse JSON as UTF-8 and reject duplicate object keys and non-standard numbers
   (`NaN`, `Infinity`, and `-Infinity`).
2. Recursively sort object keys by Unicode code point.
3. Emit no insignificant whitespace: separators are `,` and `:`.
4. Emit non-ASCII characters directly as UTF-8; use JSON escaping for control
   characters, quotation marks, and reverse solidus.

In Python this is
`json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")`.
SHA-256 digests are 64 lowercase hexadecimal characters. File digests cover
the file's exact bytes. The pretty-printed bytes of `manifest.json` are not
signed directly: parse the JSON, canonicalize the value above, then verify the
signature over those canonical bytes.

## Manifest

The JSON object uses schema identifier `actis/manifest/v1` and the normative
schema [manifest-v1.schema.json](schemas/manifest-v1.schema.json).

Required fields are:

| Field | Meaning |
|---|---|
| `schema` | Exactly `actis/manifest/v1` for new bundles. |
| `run_id` | Producer-assigned non-empty run or snapshot identifier. |
| `created` | UTC RFC 3339 timestamp for sealing the bundle. |
| `product` | Product identity metadata supplied or derived by the producer. |
| `tool_versions` | Map from tool/source name to its recorded version. |
| `ledger_root` | `record_hash` of the final ledger record. |
| `ledger_sha256` | SHA-256 of the exact `ledger.jsonl` bytes. |
| `ledger_records` | Number of non-empty records in `ledger.jsonl`. |
| `files` | Array of `{path, sha256}` entries for every non-control file, including `ledger.jsonl`. |

`signature_note` is optional, informational signed text. Other manifest fields
are allowed for forward-compatible metadata: v1 readers must preserve them when
canonicalizing and checking the signature, but may otherwise ignore them.
Control files (`manifest.json`, `manifest.sig`, and `pubkey.pem`) must not appear
in `files`, because the manifest cannot commit to itself or its derived seal.

## Ledger chain

Each non-empty line in `ledger.jsonl` is one JSON object described by
[ledger-record-v1.schema.json](schemas/ledger-record-v1.schema.json). Records
are ordered and `seq` starts at `0` and increases by one. The first `prev_hash`
is 64 zeroes. Every later `prev_hash` equals the preceding `record_hash`.

To calculate `record_hash`, remove only the record's own `record_hash` field,
canonicalize the remaining object, and take its SHA-256 digest. The manifest's
`ledger_root` equals the last record's `record_hash`; an empty ledger is not a
valid v1 bundle. Each input/output reference contains a safe relative POSIX path
and the SHA-256 of that file. Verifiers re-hash every recorded output that is
present in the bundle.

Additional record fields are permitted and are covered by `record_hash`.
`params_sha256` commits to the canonical JSON parameters used by the stage;
the parameter document itself need not be included.

## External trust and verification result

The bundled `pubkey.pem` proves only that the manifest and bundled key agree.
Trust requires the recipient to obtain an expected Ed25519 public key through a
separate authenticated channel and confirm its SHA-256 fingerprint (over the
DER SubjectPublicKeyInfo bytes). A private signing key never belongs in a bundle
or in hosted Actis. The producer refuses to seal a directory containing a PEM
private-key block instead of silently omitting a key that might later be copied.

Machine-readable output uses `actis/verification-result/v1`, specified by
[verification-result-v1.schema.json](schemas/verification-result-v1.schema.json).
Overall statuses are:

- `trusted`: integrity and bundled signature pass, and the external key verifies.
- `untrusted`: integrity and bundled signature pass, but no external key was
  configured or the supplied external key does not verify.
- `invalid`: required content exists but a digest, chain link, internal
  signature, or file inventory does not match.
- `incomplete`: a required item is missing or malformed, or its schema is not supported.

Verifier process exit codes are `0` for `trusted`, or for an intact signature in
explicit `--inspect-only` mode; `1` for `untrusted`, `invalid`, `incomplete`, or
unsupported evidence; and `2` for invalid CLI arguments or unusable trusted-key
configuration. A machine-readable trusted-key configuration error uses
`actis/verifier-error/v1`, specified by
[verifier-error-v1.schema.json](schemas/verifier-error-v1.schema.json).
Inspection success never changes `signer_trust` to `trusted`.

## Compatibility and migration policy

Actis v1 is append-compatible: producers may add signed manifest or ledger fields,
and v1 readers ignore fields they do not interpret while still including them
in canonical hashes and signatures. Producers must not remove or change a
required field, algorithm, encoding rule, path rule, or control filename under
the v1 identifier.

A breaking change requires a new manifest schema identifier and fixtures. The
pre-beta `pandax/manifest/v1` identifier is read-only legacy compatibility; it
must never be produced as Actis v1 or silently rewritten. A
reader must reject an unknown schema as `incomplete`/unsupported; it must never
guess, silently reinterpret, or rewrite a signed bundle. New writers remain
covered by the independent-reader compatibility test. New readers must continue
to verify the immutable public-safe v1 fixtures in `fixtures/evidence-v1`.

Key rotation and revocation add trust policy around the external key; they do
not mutate historical v1 bundles or change their cryptographic validity.
