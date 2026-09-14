# Actis dashboard continuation ledger

This ledger records implementation completed after the original handoff. The code-local production slices are complete and verified; target-environment rollout and independent validation remain release activities, not fixture-backed demo work.

## Completed

- [x] Connect SBOM, Collector packages, consented raw artifacts, runtime telemetry, and exposure context to the production analysis API and existing engine pipeline.
- [x] Validate provenance, Product/Release binding, archive safety, media types, schemas, payload sizes, digests, and raw-artifact policy/consent.
- [x] Retain every evidence type behind storage adapters without exposing internal object keys, paths, or original filenames.
- [x] Hydrate analysis history and resume polling for running jobs after reload.
- [x] Preserve intentional idempotency, changed-digest confirmation, immutable snapshots, and failure-safe completion state.
- [x] Enroll successful analyses in OSV, CISA KEV, and EPSS monitoring and expose cadence, last/next check, source health, and manual Check now.
- [x] Implement operator-first Home, prioritized actions, contextual setup, recent changes, Product/Release insights, and the agreed four-role interface.
- [x] Implement persisted findings decisions/remediation, compliance lifecycles, documents/approvals/self-filing, search/notifications, settings, and privacy-safe analytics.
- [x] Add explicit CORS allowlisting, browser security headers, API no-store policy, HTTPS HSTS, and a zero-high-severity dependency audit gate.
- [x] Split non-home routes into lazy chunks while preserving the shell, focus management, and navigation state.
- [x] Cover primary workflows, light/dark contrast, keyboard skip navigation, accessible names, duplicate IDs, responsive overflow, runtime errors, and performance budgets in browser automation.

## Verified on 2026-09-14

- [x] Complete Python suite with the real pinned scanner: 548 passed, 22 expected skips.
- [x] Dashboard unit/integration suite: 134 passed.
- [x] Dashboard TypeScript typecheck passed.
- [x] Production/demo build passed; initial JavaScript reduced from about 499 kB (136 kB gzip) to 377 kB (110 kB gzip).
- [x] Edge end-to-end release flow passed across Home, Products, Product/Release workspaces, analysis, Findings, Compliance, Documents, and Settings.
- [x] Automated responsive, accessibility-basics, contrast, and performance budgets passed.
- [x] Complete npm dependency audit reported zero vulnerabilities.

## Target-environment release work

- [ ] Deploy the dashboard/API/workers with managed PostgreSQL, object storage, secrets, backups, and observable queues; run migrations and a restore drill.
- [ ] Validate real identity-provider claims, logout/refresh behavior, role mappings, tenant isolation, notification delivery, scheduler concurrency, and source credentials.
- [ ] Execute the remaining exhaustive failure/outage/RBAC/back-navigation E2E matrix against staging.
- [ ] Run WCAG 2.2 AA tooling plus manual keyboard, 200% zoom, and screen-reader walkthroughs in supported browsers.
- [ ] Measure LCP, INP, and CLS under production network/device conditions and tune against the plan targets.
- [ ] Complete independent threat modeling, penetration testing, and privacy/compliance review.
- [ ] Perform customer cutover while keeping legacy runs/cases isolated in the gated internal archive; do not migrate or delete them implicitly.

## Recommended next slice

Provision a production-like staging environment and exercise one complete real-identity, real-storage release-analysis-to-CRA-reporting workflow. This resolves the largest remaining uncertainty before customer cutover.
