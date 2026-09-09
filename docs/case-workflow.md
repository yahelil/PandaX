# Local regulatory cases

Storage: `PANDAX_DATA_DIR/cases.sqlite3`, default `out/.pandax/cases.sqlite3`.
SQLite migrations preserve the original remediation database. Back up this file
with the application stopped. Scan directories remain read-only inputs.

`GET /api/cases` lists cases; `GET /api/cases/{id}` returns durable detail.
Create with `POST /api/cases`; other commands use
`POST /api/cases/{id}/{action}`. Explicit historical import uses
`POST /api/cases/import-draft` with source_run_id, cve, optional purl,
draft_file (`filings/<name>.json`), and named operator.

Every mutation requires a unique `request_id`. Existing-case mutations require
the last read integer `expected_version`. Retry the identical body and request ID
after an uncertain response. HTTP 409 means conflicting content or stale state;
reload and review before issuing a new request. HTTP 422 means invalid input;
HTTP 404 means a missing case/run/finding. Legacy mutation clients must add these
fields. The original CaseStore methods remain internal compatibility helpers;
all application writes go through CaseService.

CLI: `pandax case list`, `pandax case show CASE_ID`, and
`pandax case apply ACTION --case-id CASE_ID --input command.json`.
Omit `--case-id` for create/import-draft. JSON command files retain request IDs
for retries. Actions initially include create, import-draft, observe-release,
and confirm-measure. Incomplete or historical drafts are never approvals.

Unknown legacy product identity stays blank until evidence supplies it. Cases
remain readable even if a referenced source bundle is temporarily unavailable.

Review commands: `record-awareness` accepts occurred_at/detected_at/aware_at,
evidence, and reason (required for corrections). `record-decision` accepts
reportability (under_review/reportable/not_reportable), evidence and reason.
`revise` accepts a payload object and reason. `approve` requires revision,
report_hash and approved_at. All require operator and authority_attestation.
Factual timestamps require Z or an explicit offset. Approvals authorize only
the exact latest revision; new content never inherits an earlier approval.

`prepare-report` takes stage early_warning/notification/final_report and a
fields object, plus operator/authority_attestation. Preparation is not submission.
Awareness starts 24h/72h clocks; actual measure availability starts the vulnerability
14-day final clock. Missing dates remain pending. Corrections record old/new clocks;
review does not change factual trigger dates. See ENISA's CRA SRP FAQ (2026-09-08).

`create-incident` (POST `/api/cases/create-incident`) accepts title, product_name,
product_version, severity, impact, operator and authority_attestation; a source
run is optional. `assess-incident` updates severity/impact/mitigation/root_cause
with evidence and reason. Incidents have no required CVE. Their final clock stays
pending until notification submission, then adds one calendar month in UTC,
clamping to the last day for short months. Vulnerability measure dates never
drive incident clocks. Submission records supply this trigger, not draft dates.

## Field definitions and packs

Source: https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2
ENISA glossary 1.1 (2026-09-05), retrieved 2026-09-08. Internal definition version:
`enisa-1.1-2026-09-05/pandax-1`. All 38 glossary rows map to stable internal keys
and source row IDs; `GET /api/case-fields/{type}/{stage}` exposes applicable fields.
The glossary's AEV awareness field is marked for a future portal release; retain
factual awareness in PandaX regardless of portal availability. Incident awareness
currently appears in the portal under its detection label; do not conflate the
two factual timestamps locally.

Field inputs are strings or `{ "value": null, "available": false }` for an
explicit unavailable-information attestation. Provenance is server-owned;
carried values keep their origin and prior revision number. Unknown applicability
of a conditional field blocks readiness until the operator supplies information
or attests it unavailable. Drafts may remain incomplete, but only a complete,
approved latest revision is ready. Placeholders never satisfy a required field.

Export: `GET /api/cases/{id}/export?format=html|json|checklist&revision=N` or
`pandax case export CASE_ID --format html --destination pack.html`.
CLI export refuses to overwrite an existing file. HTML escapes supplied values;
JSON is PandaX internal interchange, not an SRP API schema. Packs are prepared
artifacts, never proof of submission. Older approved revisions remain readable
but cannot be presented as the latest ready pack.

## Submissions, receipts and snapshots

`record-submission` requires operator/authority_attestation, revision, report_hash,
result (`submitted` or `failed`), submitted_at, and explicit simulated boolean.
Success requires platform_reference; failure requires failure_reason. The exact
revision must be complete and approved before the recorded submission time.
Failure does not satisfy any obligation. A retry uses a new request ID; replaying
the same ID returns the original response even after later events.

`attach-receipt` takes submission_id, filename, content_base64, acknowledged_at,
operator/authority_attestation and optional sha256 to verify. Receipt bytes (up
to 5 MiB) and metadata commit together. Acknowledgement cannot predate submission.
Downloads use `/api/cases/{id}/receipts/{receipt_id}` and verify stored hashes.

`amend` takes submission_id, reason, fields and operator/authority_attestation.
It creates a new unapproved revision linked to that successful submission.
Editing an amendment retains the link. Earlier payloads, approvals, attempts
and receipts are immutable. Notification amendments cannot postpone an incident's
original final deadline.

Set `simulated: true` at case creation for a rehearsal case. Its events, report
packs and attempts stay labeled. It cannot record real submissions. A simulated
attempt on a real case remains visible but satisfies no real obligation and
cannot start a real incident final clock. Amendments preserve simulation mode.

`snapshot` takes revision plus operator/authority_attestation. It creates a ZIP
containing case history, the selected report pack, receipts, ledger and signed
manifest. The immutable ZIP and digest commit together in SQLite; request replay
does not generate another snapshot. Download through
`/api/cases/{id}/snapshots/{snapshot_id}` or
`pandax case download-snapshot CASE_ID SNAPSHOT_ID output.zip`.
Scans and snapshots use the installation key selected by `PANDAX_SIGNING_KEY`
(default `~/.pandax/dev_signing_key.pem`). External signer trust is established
only when verification receives the corresponding public key separately through
`PANDAX_TRUSTED_KEY` or `--trusted-key`. No original scan is rewritten and no
network submission is performed. Snapshot temporary files are cleaned after
generation.
