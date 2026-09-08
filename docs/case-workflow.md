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
