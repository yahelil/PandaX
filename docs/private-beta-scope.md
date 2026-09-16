# Actis private-beta scope and acceptance gates

**Approval state:** pending founder signature. This document defines the build
scope; it does not authorize a pilot or production launch.

## Scope and constraints

The private beta is an invite-only, zero-cost, pre-production evaluation of one
complete workflow: a manufacturer collects authorized product evidence locally,
signs a minimized evidence package with its own key, uploads that package,
reviews traceable findings and CRA workflow drafts, records accountable human
decisions, exports a report, and verifies the copied package offline.

- Supabase Auth supplies invitation-only identity and mandatory TOTP MFA.
  Application PostgreSQL remains authoritative for organizations, memberships,
  roles, permissions, and authorization decisions.
- Roles are `org_admin`, `compliance_operator`, `authorized_approver`, and
  `read_only_auditor`. Every read and mutation is tenant-scoped and deny-by-default.
- Heavy analysis and customer private signing keys stay local. Hosted Actis
  accepts minimized evidence and public trust material only.
- Normal pilot data is allowed only after versioned acknowledgement. Secrets,
  credentials, private keys, unnecessary personal data, and irrelevant sensitive
  material are prohibited.
- Actis never notifies downstream end users and never automatically emits a
  risk-reducing VEX conclusion. Exact matches may be `affected`; risk reduction
  requires named review and evidence.
- The beta is EU-primary but makes no EU-only, SLA, certification, legal-advice,
  or automatic-compliance promise.

## Supported Collector matrix

All inputs are processed locally. The first customer Collector release is
Windows x64 only. macOS, Linux, and specialist firmware/container extraction
are later releases; their availability is not a beta acceptance requirement.

| Input | Windows | macOS | Linux | Contract |
|---|---|---|---|---|
| Directory | Windows x64 first | Later | Later | Safe recursive inventory; never execute contents. |
| ZIP/TAR archive | Windows x64 first | Later | Later | Reject traversal, links, duplicates, bombs, and limit violations. |
| CycloneDX JSON 1.2/1.6 | Windows x64 first | Later | Later | Normalize to the internal CycloneDX 1.6 component model. |
| SPDX JSON 2.2/2.3 | Windows x64 first | Later | Later | Normalize without inventing missing package identity. |
| Container image | Later | Later | Later | Raw layers stay customer-side. |
| SquashFS/UBIFS firmware | Later | Later | Later | Sandboxed extraction needs a later specialist release. |

Release packages require detached checksums/signatures and installation tests.
Native OS code signing is not a beta promise. Public executable names are
`actis-collector` and `actis-verify`; the hosted/engine command is `actis`.

## Core workflow completion

A pilot release counts as complete only when the same release has an auditable
record of all of these steps:

1. invited user signs in with TOTP MFA and an active organization membership;
2. product and release identity are recorded;
3. the Collector processes a supported input locally without executing it;
4. the customer key signs an `actis/manifest/v1` minimized package;
5. hosted ingestion verifies inventory, integrity, signer policy, and tenancy;
6. findings and source coverage are reviewed, with unknowns left explicit;
7. any risk-reducing or regulatory decision has a named authorized reviewer;
8. a versioned report/evidence snapshot is exported; and
9. `actis-verify` validates the copied package offline with a separately obtained
   public key.

Workflow completion rate is completed pilot releases divided by attempted pilot
releases. Failed attempts remain in the denominator and in the defect record.

## Locked gates

| Gate | Required evidence |
|---|---|
| G1 — Ownership and zero cost | Company-owned accounts/recovery paths and individual least-privilege access are verified; no billing method, R2, paid plan, paid add-on, PITR, or automatic upgrade is active. |
| G2 — Identity and isolation | Invite/MFA/session/revocation/recent-reauth tests and a two-organization read/write/enumeration matrix pass across every repository and API. |
| G3 — Durable data | Clean/forward/rollback/concurrent migrations, private storage, digest/media checks, quota stops, retention/hold/export/deletion, backup, and full restore pass with no Render filesystem dependency. |
| G4 — Evidence and trust | Golden v1 and legacy fixtures, tamper/offline checks, proof of possession, rotation/revocation, regulatory version activation/rollback, and audit provenance pass; no customer private key reaches the server. |
| G5 — Collector and analysis safety | Required platform/input packages pass; hostile traversal/link/duplicate/bomb/malformed/time/size cases fail safely; reachability never auto-reduces risk. |
| G6 — Product workflow | Product/release/fleet, signed passive device check-in, replay/stale/cross-tenant, review/approval, and CSV/API round trips pass; no remote device command exists. |
| G7 — Delivery surfaces | Signed webhook retry/idempotency/dead-letter, Jira/GitHub/CSV/VEX fixtures, notification tenancy/quotas, report reconciliation, deterministic PDF/CSV, and accessibility pass. No downstream end user is addressable. |
| G8 — Qualification and operations | Chromium/Firefox/WebKit core workflow and MFA, cold start, provider/email/quota failures, release rollback, backup failure/full restore, and seven-day internal alpha pass with no critical security/data-loss defect. |
| G9 — Pilot exit and decision | At least 3 pilot organizations, 10 real releases, 80% workflow completion, 2 returning organizations, zero critical security/data-loss defects, no open beta blocker, and a signed founder approve/reject record. |

Capacity controls warn administrators at 70%, block optional/background growth
at 80%, and fail closed at the hard stop: 25 MB per Collector package, 50 MB per
other object, 200 MB active storage per application organization, 800 MB
aggregate Supabase Storage and 350 MB aggregate PostgreSQL per Supabase
organization across all projects, and 80 Resend messages/day or 2,000/month. If
staging and private beta share one Supabase organization, staging/private-beta
hard-stop allocations are 200/600 MB for Storage and 100/250 MB for PostgreSQL.
Unused staging allocation is not borrowed by private beta. Staging is suspended
first if combined Render Free allowance is threatened.

## Card-to-gate traceability

The identifiers below are the decision-pack card runbooks; each required beta
card must also satisfy its own Done statement and prerequisites.

| Card | Acceptance gate(s) |
|---|---|
| 03 — Tenant isolation, RBAC, SSO boundary, admin audit | G2 |
| 04 — Customer-controlled evidence signing and trust | G4 |
| 05 — Private-beta data handling and pilot terms | G2, G3 |
| 06 — Internal alpha and failure-mode tests | G8 |
| 07 — SECURITY.md and trust documentation | G1, G4 |
| 08 — Public standalone verifier | G4, G5 |
| 09 — Regulatory rules and reviewed content | G4 |
| 10 — Customer-side Collector | G5 |
| 11 — Product, release, and fleet portfolio | G6 |
| 12 — Firmware formats and device ecosystems | G5 |
| 13 — Reachability and VEX noise reduction | G5, G6 |
| 14 — Notifications and escalation | G7 |
| 15 — External integrations | G7 |
| 16 — Analytics and reporting | G7 |
| 17 — End-to-end qualification suite | G8 |
| 18 — Private pilots | G9 |
| 19 — Closed-beta decision | G9 |
| d01 — Company delivery accounts and zero-cost guardrails | G1 |
| d02 — PostgreSQL and migration safety | G3 |
| d03 — Durable evidence storage | G3 |
| d04 — Beta key custody and production KMS gate | G4 |
| d05 — Staging and private-beta environments | G1, G8 |
| d06 — Test/release/deploy/rollback automation | G8 |
| d07 — Staging integration validation | G8 |
| d08 — Hardening, monitoring, backup, and recovery | G8 |
| d09 — Deployment readiness and recovery drills | G9 |
| Deferred — Distributed queues and workers | Not a beta gate; reconsider only after measured beta load and paid-infrastructure approval. |

## Explicit deferrals

The beta excludes managed KMS/HSM, enterprise SSO rollout, paid storage or
compute, native OS code signing, strict EU-only residency, distributed cloud
workers/queues, production SLA, billing/commercial packaging, public launch,
automatic regulatory submission, a regulator/auditor portal, qualified eIDAS
seals, and downstream-end-user notifications. Reconsider only after the beta
exit record identifies a measured need and company ownership/budget approval.

## Founder approval record

Card 02 remains incomplete until a founder records an explicit approve/reject
decision against the exact repository commit and SHA-256 of this file. A PR
approval without that binding is not the required signature.

Required record fields: founder name, decision (`APPROVED` or `REJECTED`), UTC
timestamp, repository/commit, document path, document SHA-256, and any conditions.
The immutable record must be a signed repository document, signed commit, or
signed tag containing every field. An authenticated Trello comment may link to
that record, but is not itself immutable and does not satisfy this gate.
