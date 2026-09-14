# Actis dashboard continuation ledger

This ledger records the continuation work on `actis-dashboard-implementation`, based on `origin/actis-dashboard`. It supplements `PLAN.md`; unchecked items below must not be treated as production-complete.

## Completed on this branch

- [x] Connect Collector packages and consented raw artifacts to the production analysis API and existing engine pipeline.
- [x] Validate Collector provenance, Product/Release binding, archive safety, payload digests, and raw-artifact policy/consent.
- [x] Hydrate analysis history from production services and resume polling for running jobs after a page reload.
- [x] Use a unique idempotency key for each intentional analysis session while preserving safe retry behavior.
- [x] Require explicit confirmation before a changed release digest creates another immutable analysis snapshot; record the old and new digests in audit history.
- [x] Enroll successful analyses of active or supported releases in the standard hourly OSV, CISA KEV, and EPSS monitoring policy.
- [x] Replace the greeting-led Home with the agreed operator-first hierarchy, clickable work counters, five recent changes, and contextual empty states.
- [x] Add the five-step first-run setup checklist.
- [x] Align the user-facing role model to Organization Admin, Compliance Operator, Authorized Approver, and Read-only Auditor. Legacy `security_reviewer` and `viewer` API values are mapped at the adapter boundary.
- [x] Add conditional finding distribution and immutable-analysis history insights to Product and Release overviews.
- [x] Extend browser smoke coverage with basic accessible-name/duplicate-ID checks and horizontal-overflow checks at 768, 1024, 1440, and 1920 px.

## Verified

- [x] Dashboard TypeScript project builds without errors.
- [x] Dashboard unit/integration suite: 127 tests passed.
- [x] Engine and standalone-verifier suites: 533 tests passed, 32 skipped.
- [x] Production demo build completed and Edge end-to-end smoke passed.
- [x] Home and Product workspaces inspected in the in-app browser; accepted visual reference and current 1440 px capture inspected at native resolution.

## Remaining production work

- [ ] Add optional runtime telemetry/exposure evidence to the new multipart analysis-job API, including secure retention, validation, pipeline forwarding, and monitoring-policy reuse. The older engine pipeline already supports these inputs; the dashboard production seam does not yet expose them.
- [ ] Add the complete PLAN.md workflow E2E matrix. Current automated coverage is a smoke/regression layer, not every multi-step workflow listed in the plan.
- [ ] Run and remediate formal WCAG 2.2 AA tooling plus manual keyboard, zoom, and screen-reader walkthroughs. The current checks cover structural basics only.
- [ ] Measure and tune LCP, INP, and CLS against the stated targets in a production-like deployment.
- [ ] Validate the real identity-provider claims, secrets, object storage, worker process, notification delivery, and monitoring scheduler in the target environment.
- [ ] Perform customer deployment and immediate dashboard cutover, then verify that the legacy runs/cases area remains gated and untouched. This requires the target infrastructure and release authority.

## Recommended next slice

Implement runtime telemetry/exposure upload as a separately retained, release-bound evidence object and pass it to `pipeline.run_sbom`. Reuse the same validated evidence when auto-enrolling monitoring, without exposing file paths or original filenames in analytics.
