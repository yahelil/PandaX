# Actis implementation handoff

## Purpose

This document gives a new engineer the product decisions, implementation plan, current state, and remaining work needed to continue Actis without repeating the original discovery interview.

The original questions and answers were stored only in the Codex task conversation titled **Redesign dashboard UX**. They were not previously committed as a standalone file. The wording below is normalized for clarity; it preserves the resulting decisions rather than pretending every sentence is a verbatim transcript.

## Start here

- Repository: this PandaX repository.
- Implementation branch: `actis-dashboard`.
- Do not create a branch whose name contains `codex`.
- Full product/UI plan: [`PLAN.md`](PLAN.md).
- Authoritative backend contract: [`CRA-Compliance-API-Spec-Final.docx`](../../CRA-Compliance-API-Spec-Final.docx).
- Historical draft only: [`CRA-Compliance-API-Spec.docx`](../../CRA-Compliance-API-Spec.docx).
- PNGs in [`assets/`](assets/) are visual references for density, spacing, tone, and existing branding. They are not the final information architecture.

## Source-of-truth order

When sources disagree, use this order:

1. Explicit decisions in this handoff.
2. `PLAN.md`.
3. `CRA-Compliance-API-Spec-Final.docx`.
4. Current implementation and tests.
5. Original prototype PNGs.
6. Historical API draft.

## Product decision log — questions and answers

### Product goal and audience

**Q: Who is the dashboard primarily for?**  
**A:** A manufacturer-side compliance operator. Product-security and compliance leadership are important presentation and oversight audiences, but the everyday UX is operator-first.

**Q: What must Home answer first?**  
**A:** “What needs action now, why, by when, and who owns it?” It is an operational inbox, not an analytics billboard.

**Q: Should the design represent only the current PoC or the intended final product?**  
**A:** Design the final product. Build the first demo inside the same production architecture so it can evolve rather than be discarded.

### Information architecture

**Q: Do we need all prototype sidebar tabs?**  
**A:** No. Primary navigation is exactly:

- Home
- Products
- Findings
- Compliance
- Settings, fixed at the bottom

Remove top-level Devices, Risk Analysis, Reports, Documents, Team, Cases, Deadlines, Monitoring, and Evidence. Their valid functions move into the Product/Release workspace, Findings, Compliance, or Settings.

**Q: What is the core domain hierarchy?**  
**A:** Organization → Product → Release. Analyses, findings, compliance work, documents/evidence, and monitoring belong to a release or roll up to its product.

**Q: Should “Devices” remain the primary inventory concept?**  
**A:** No. The prototype mixes hardware, software, and components. Replace it with a Product portfolio and Release hierarchy. Deployed-device fleet management may later exist as optional evidence functionality, not as primary navigation.

**Q: Should Risk Analysis be separate from Findings?**  
**A:** No. Merge it into Findings. Global Findings is the actionable queue; each Product/Release Overview may show a compact aggregated risk summary.

**Q: Should Documents and Reports be separate global pages?**  
**A:** No. Product/Release Documents contains reports, conformity documents, SBOM/VEX, and evidence records. Cross-product reporting cases and missing evidence appear in Compliance.

**Q: How should global scope work?**  
**A:** Persistent Product/Release scope in the header. Default is All products. Selecting a product enables All releases or a specific release. Scope persists across Home, Findings, and Compliance and is encoded in the URL.

**Q: What should global search cover?**  
**A:** Products, releases, findings, cases, and documents, grouped by category with deep links.

### Home

**Q: Keep the greeting, CRA marketing banner, inventory totals, and large activity feed?**  
**A:** No. Established organizations see:

1. Compact monitoring status: active state, hourly cadence, last successful check, next check, and source health.
2. Three action-needed counters: deadlines at risk; findings awaiting review/action; incomplete or stale evidence.
3. Prioritized action queue with reason, Product/Release, deadline, owner, and next action.
4. Five meaningful Recent Changes, including monitoring-generated changes.

**Q: What does first-run Home show?**  
**A:** A setup checklist: create product, register release, analyze release, review initial findings, assign authorized approver, and configure notifications.

**Q: Should Home have a permanent global “Start assessment” button?**  
**A:** No. Analysis is initiated from Product or Release context. Home may guide first-run setup but does not own the analysis action.

### Products and Releases

**Q: What should Products look like?**  
**A:** A realistic dense table with Product, active release, readiness, actionable findings, next deadline, monitoring health/last check, and owner. Support practical sorting/filtering. One page-level primary action: Create product.

**Q: What tabs exist inside a Product workspace?**  
**A:** Overview, Releases, Findings, Compliance, Documents.

**Q: Should Product and Release use separate unrelated experiences?**  
**A:** No. Use one consistent workspace supporting product overview scope, All releases, and a specific Release scope.

**Q: What should Overview emphasize?**  
**A:** Readiness status and blockers, monitoring health, top actions, and only useful contextual charts. Show finding distribution and historical trend only when data is sufficient.

### Release analysis and monitoring

**Q: What should the workflow be called?**  
**A:** Never “Start assessment.” Use **Analyze new release** from Product context and **Run new analysis** from an existing Release.

**Q: What does release analysis mean?**  
**A:** Establish or update a release component baseline from Collector evidence, SBOM, or artifact; generate coverage and immutable analysis evidence; create or update release-scoped findings; enroll eligible active releases in hourly monitoring.

**Q: Modal or full-page flow?**  
**A:** Full-page wizard:

1. Register release identity/version/build.
2. Provide Collector evidence package or SBOM; raw artifact is secondary and requires explicit data-handling consent; runtime telemetry is optional.
3. Validate and preview digest, format, component count, skipped/unsupported content, and coverage limitations.
4. Review inherited CRA rules/capabilities and start analysis.

**Q: Keep “Assessment Profile”?**  
**A:** No. CRA ruleset is inherited and read-only. The product is CRA-only.

**Q: Should rerunning overwrite evidence?**  
**A:** No. Every successful analysis creates an immutable snapshot. A changed artifact digest requires explicit confirmation and remains traceable.

**Q: How should analysis progress behave?**  
**A:** A resumable progress/result page. Keep technical execution detail collapsed unless needed.

**Q: Is monitoring the same action as analysis?**  
**A:** No. Analysis changes the release baseline. Monitoring refreshes vulnerability intelligence against the existing baseline and never changes release contents.

**Q: Automatic or manual monitoring?**  
**A:** Hourly automatic monitoring for active supported releases. A Product/Release page may expose a secondary release-scoped **Check now**. No global manual refresh control.

**Q: What happens when a source fails?**  
**A:** Preserve prior findings and mark monitoring degraded/stale. Never make findings disappear because a source is unavailable.

### Findings and prioritization

**Q: What is the default Findings view?**  
**A:** Needs review/action, ranked by actionability rather than CVSS alone.

**Q: What quick views are required?**  
**A:** All findings; Critical + High; KEV/actively exploited; Reachable; Unreviewed; Needs remediation.

**Q: Should Actis show one combined risk score/status?**  
**A:** No. Keep security facts separate and explainable: severity, KEV/EPSS, coverage, affectedness, reachability, human decision, remediation, reportability, deadlines, and evidence quality.

**Q: How are priority bands defined?**  
**A:**

- Urgent: overdue or due within 24 hours; or actively exploited plus confirmed affected/reachable with required action outstanding.
- High: due within 72 hours; new/changed high-actionability finding; approval blocker; or material monitoring failure.
- Normal: other unresolved decision, remediation, evidence, or document work.
- Low: non-urgent scheduled work. Informational changes stay outside the default action queue.

Tie-break by deadline, risk drivers, then most recent change.

**Q: What actions belong in the Findings table?**  
**A:** One Review action per row. Affectedness, reportability, approval, remediation, and evidence decisions belong on the Finding detail page. Safe bulk actions are assignment, notification acknowledgement, and export.

**Q: What does Finding detail include?**  
**A:** Risk assessment, affectedness/reachability/KEV evidence, human decision, remediation, reportability, supporting evidence, audit history, and ownership.

### Compliance, documents, and filing

**Q: Is Compliance a generic multi-framework module?**  
**A:** No. It is CRA-only. Remove Regulation selector/filter.

**Q: What is the Compliance page?**  
**A:** Cross-product CRA action center containing readiness, deadlines, missing evidence/documents, open regulatory/reporting cases, requirements needing action, approvals, and self-filing/receipt work. Filters: Product, Release, Status, action type, owner, time horizon. Default sort: Priority.

**Q: Show an “83% compliant” score?**  
**A:** No aggregate compliance percentage. Readiness is one of Ready, Needs attention, or Incomplete evidence, always with explicit blockers. “Not applicable” is allowed only for an individually reviewed requirement with a recorded reason.

**Q: Card gallery or grouped document tables?**  
**A:** Grouped tables: CRA reporting packs; conformity documents; SBOM/VEX security exports; evidence bundles and verification records.

**Q: How do document revisions and approvals work?**  
**A:** Analysis/workflow changes create versioned drafts. Operators add missing evidence and request review. An Authorized Approver approves an exact revision. Document detail shows provenance, revision history, approval, audit timeline, integrity, and trust verification.

**Q: Does Actis submit directly to regulators?**  
**A:** No. Current scope is self-filing: download approved pack/checklist, then manually record external submission time/reference/receipt/failure/amendment. Never imply automatic submission. Keep the data model compatible with future managed filing.

### Ownership, roles, and Settings

**Q: Should Actis become a full ticketing system?**  
**A:** No. Use lightweight ownership: Product default owner can prefill work; findings/cases may be assigned to one member; urgent unassigned work stays visible. Ownership never grants approval authority.

**Q: What user-facing roles are intended?**  
**A:** Four fixed roles: Organization Admin, Compliance Operator, Authorized Approver, Read-only Auditor.

**Q: What Settings sections are required?**  
**A:** Organization; Team & Access; Integrations/source health; Notifications; Security/retention; Appearance.

### Visual system and usability

**Q: Keep the prototype’s general visual tone?**  
**A:** Yes, as a visual reference only: calm, credible compliance workspace, dense but readable. Correct the information architecture, action hierarchy, and inconsistent controls.

**Q: Light or Dark?**  
**A:** Both, polished. Follow system initially and persist an explicit override.

**Q: Branding?**  
**A:** Actis by PandaX. Reuse supplied Actis and PandaX marks. Logos must visually merge with the background—no white rectangular boxes.

**Q: How many primary buttons?**  
**A:** One primary CTA per screen, in the page header or wizard footer. Secondary actions are labeled. Destructive actions live in detail-page overflow with confirmation. Remove unexplained ellipsis menus and checkboxes with no real bulk action.

**Q: What typography and colors?**  
**A:** Archivo for brand/display, Inter for UI, IBM Plex Mono only for identifiers/digests/timers. Use the exact Light/Dark foundations and semantic tokens defined in `PLAN.md`; semantic colors always include text or icon labels.

**Q: Responsive/accessibility target?**  
**A:** Full desktop/tablet support from 768 px upward. Mobile supports monitoring, alerts, search, and light review; complex editing may recommend a larger screen. Meet WCAG 2.2 AA, 44 px targets, visible focus, keyboard access, semantic tables/forms, reduced motion, zoom/text scaling, screen-reader announcements, and non-color status cues.

### Delivery and architecture

**Q: Is the demo a disposable prototype?**  
**A:** Absolutely not. It must live inside the same React + TypeScript application, routes, components, types, design tokens, and service boundaries used for production.

**Q: What can be mocked initially?**  
**A:** Backend-dependent behavior may use realistic typed fixtures behind adapters/services. Replace adapters vertical slice by vertical slice without rewriting screens.

**Q: What demo states must exist?**  
**A:** Several realistic Products/Releases: healthy/compliant; urgent finding; approaching CRA deadline; incomplete evidence; degraded monitoring. No Lorem ipsum.

**Q: What is the delivery sequence?**  
**A:** Demo first → QA → demo checkpoint commit → automatically continue production. Production order: Product/Release persistence; auth/RBAC; SBOM/Collector input and analysis; monitoring; findings decisions; compliance/cases; documents/approvals/self-filing; Home aggregation; search/notifications; Settings; privacy-safe analytics; automated/E2E/accessibility testing.

**Q: Launch behind a beta flag?**  
**A:** No. The new customer-facing dashboard replaces the old one when production-ready. Preserve legacy runs/cases without importing or deleting them; keep old execution/test demonstrations in a gated internal archive/demo area.

**Q: What analytics may be collected?**  
**A:** Privacy-safe UX events only: route, filter/search success, wizard completion/drop-off, action completion time, and errors. Never capture organization/product names, SBOM contents, finding text, evidence/documents, or uploaded filenames.

## Client showcase/video decisions — do not confuse with app architecture

These decisions apply to the client-facing 15-second video, not to general dashboard behavior:

- Audience: product-security and compliance leadership.
- Silent; no music, voiceover, or captions outside the dashboard.
- Light mode, 1920×1080, fast-paced, directional flow—not a dashboard walkthrough.
- Cursor visible at all times and visibly clicking the exact controls used.
- Story: Products → Home Hub → register new release `v1.8.0` → select/upload → skip processing → new critical alert → review finding → Documents → hover Download → end card.
- Vulnerability: CVE-2021-44228 (Log4Shell), `log4j-core 2.14.1`, Critical, CISA KEV, component present; reachability may be shown as not assessed.
- Show a prominent 24-hour reporting clock beginning at `24:00:00` and counting down.
- Document name exactly `CRA 24-hour Early Warning`; show that it is downloadable but do not open it.
- End card: Actis logo and PandaX logo side by side, equal visual size, integrated into the background; only the word `Actis`; no slogan, “by PandaX,” multiplication sign, or “draft.”
- Client-facing screens must not disclose implementation tools/frameworks/vendors.
- Current final video: `output\video\actis-client-demo-v2.mp4` in the active worktree.
- `pandax-poc-showcase.mp4` is an older pre-redesign video and is not the requested deliverable.

## Current implementation state

The demo checkpoint and all code-local production slices are complete. Target-environment rollout and independent validation remain; current status is maintained in `COMPLETION.md`.

Implemented:

- React + TypeScript dashboard architecture with fixture and production adapters.
- Demo-ready shell, routing, scope control, Light/Dark themes, populated workflows.
- Database migrations `0001` through `0009`.
- Organization/Product/Release persistence.
- OIDC sessions and backend RBAC enforcement.
- SBOM ingestion and analysis path.
- Monitoring repository, worker, and release-scoped Check now.
- Findings decisions and remediation workflow.
- Compliance/case lifecycle.
- Documents, approvals, and self-filing records.
- Home aggregation, categorized search, and notifications.
- Organization/team/integration settings.
- Privacy-safe dashboard analytics.
- Resumable SBOM, Collector, raw-artifact, runtime-telemetry, and exposure-evidence analysis.
- Monitoring health detail, strict browser/API security policy, route-level loading, and automated release gates.

Key commits:

- Demo checkpoint: `765dc64`
- Secure analysis input: `c33f57a`
- OIDC sessions: `a082cce`
- Document lifecycle: `f15ead8`
- Compliance lifecycle UI: `d7a97e0`
- Production settings: `5f58e8d`
- Privacy-safe analytics: `ed94db5`
- Latest integration: `12f2139`
- Final client video: `8cc5d92`
- Runtime evidence: `0b666cb`
- Monitoring health: `8ab42ed`
- Release gates: `b65b4af`
- Route performance: `043e344`
- Security hardening: `552b31e`

Verification on 2026-09-14:

- Dashboard: 134/134 tests passed, typecheck passed, production/demo builds passed, browser E2E passed.
- Python engine/verifier: 548 tests passed, 22 expected skips, including the real pinned scanner path.
- Complete npm dependency audit: zero vulnerabilities.

## Remaining target-environment work

1. Provision production-like staging with managed PostgreSQL, object storage, secrets, workers, queues, backups, and observability.
2. Validate the real identity provider, tenant/role claims, notification delivery, monitoring credentials, and scheduler concurrency.
3. Run the exhaustive failure/outage/RBAC/back-navigation matrix against staging.
4. Complete manual WCAG 2.2 AA, supported-browser, screen-reader, 200% zoom, and production Web Vitals validation.
5. Conduct independent security/privacy review, restore drill, customer cutover, and gated legacy-archive verification.

## Recommended next execution order

1. Provision production-like staging and apply migrations.
2. Connect real OIDC, storage, worker, notification, and monitoring services.
3. Run the complete workflow, security, accessibility, recovery, and performance validation matrix.
4. Pilot with customer-like data and resolve operational findings.
5. Cut over the customer dashboard while preserving the gated legacy archive.

## Guardrails

- Do not sacrifice the adapter/service boundary to make fixtures easier.
- Do not rewrite stable UI when connecting production APIs unless backend constraints genuinely require it.
- Do not introduce a generic multi-regulation selector.
- Do not introduce aggregate compliance or opaque risk scores.
- Do not let source failure erase previous findings.
- Do not imply automated regulatory submission.
- Do not expose implementation tools in client-facing UI or video.
- Preserve unrelated user changes and commit each completed slice separately using conventional commit messages.

## Suggested skills for the next agent

- `domain-modeling` — validate Product/Release/Analysis/Finding/Case/Document boundaries and role vocabulary.
- `codebase-design` — keep fixture/production adapters and backend seams deep and replaceable.
- `tdd` — close remaining production slices with integration tests first.
- `design:design-system` — audit tokens and component consistency before final polish.
- `design:accessibility-review` — complete WCAG 2.2 AA review and remediation.
- `diagnosing-bugs` — use only for concrete runtime/E2E failures discovered during QA.

## Definition of done

The project is complete only when every production workflow in `PLAN.md` uses real persistence/services, all promised input paths work, analysis is resumable, role semantics match, the responsive/accessibility/E2E matrix passes, and the customer deployment/cutover is verified. A polished fixture-backed demo alone is not completion.
