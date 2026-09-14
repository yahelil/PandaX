# Actis by PandaX Dashboard Redesign

## Summary

Replace prototype’s page-centric dashboard with a CRA-specific operations workspace for manufacturer compliance operators.

Core hierarchy:

```text
Organization
└── Product
    └── Release
        ├── Immutable analyses
        ├── Findings
        ├── Compliance work
        ├── Documents and evidence
        └── Hourly monitoring
```

Attached PNGs remain visual references for brand, spacing, and tone—not information architecture. Final API specification governs; draft is historical.

Primary navigation:

- Home
- Products
- Findings
- Compliance
- Settings at sidebar bottom

Remove top-level Devices, Risk Analysis, Reports, Documents, Team, Cases, Deadlines, Monitoring, and Evidence. Brand product as “Actis by PandaX.”

## Information Architecture and Screens

### Shared shell

- Persistent Product / Release scope in header: default “All products”; product selection reveals “All releases” or specific release. Scope persists across Home, Findings, and Compliance and is encoded in the URL.
- Compact categorized global search across products, releases, findings, cases, and documents.
- Bell shows action-required alerts only.
- Profile menu contains theme selection and account actions.
- Desktop uses labeled sidebar; tablet uses collapsible drawer. Preserve navigation and filter state when moving between pages.

### Home

Established organizations see, in order:

1. Compact monitoring strip: active state, hourly cadence, last successful check, next check, and source health. No global manual refresh.
2. Three clickable counters filtering the work queue:
   - Deadlines at risk
   - Findings awaiting review/action
   - Incomplete or stale evidence
3. Prioritized action table with reason, Product/Release, deadline, owner, and next action.
4. Five meaningful Recent Changes, including monitoring-generated changes.

Remove greeting-led layout, CRA marketing banner, vanity totals, duplicated deadline panel, and large routine activity feed.

First-run Home replaces these with a setup checklist and contextual empty states:

- Create product
- Register release
- Analyze release
- Review initial findings
- Assign authorized approver and notification settings

### Products

- Replace mixed Devices page with dense Products table.
- Columns: Product, active release, readiness status, actionable findings, next deadline, monitoring health/last check, owner.
- One page-level primary action: `Create product`.
- Product creation captures only identity, manufacturer, CRA classification state, support period, and default owner.
- Every Product workspace uses five tabs:
  - Overview
  - Releases
  - Findings
  - Compliance
  - Documents
- Product supports “All releases” and individual release scope within one consistent workspace.

Product/Release Overview contains readiness status and blockers, monitoring state, top actions, and minimal contextual charts: compact finding distribution and historical trend only when sufficient data exists.

### Release analysis

Use `Analyze release`, never `Start assessment`.

Meaning:

- Establish or update the release’s component baseline from Collector evidence, SBOM, or artifact.
- Generate coverage and immutable analysis evidence.
- Create/update release-scoped findings.
- Enroll active supported releases in hourly monitoring.

Full-page wizard:

1. Register release identity/version/build.
2. Provide evidence:
   - Primary: Collector evidence package or SBOM.
   - Secondary: raw artifact upload with explicit data-handling notice and consent.
   - Optional runtime telemetry/exposure evidence.
3. Validate and preview digest, detected format, component counts, unsupported/skipped content, and coverage limitations.
4. Review and start. Show inherited CRA ruleset and available capabilities read-only.

Remove Assessment Profile choice and decorative modal illustration. Analysis progress gets a resumable page; technical execution details remain collapsed.

A new successful analysis creates an immutable snapshot. Never overwrite prior evidence. Changed artifact digests require explicit confirmation and remain traceable.

### Monitoring

- Runs automatically every hour for active, supported releases.
- Successful release analysis enrolls eligible releases automatically.
- Product/Release page exposes secondary `Check now`, which refreshes vulnerability intelligence for that release only.
- Monitoring never changes release contents; only analysis does.
- Source outage preserves prior findings and changes health to degraded/stale.
- Monitoring changes feed Findings, Compliance actions, notifications, and Recent Changes.

### Findings

Merge Risk Analysis into Findings.

Default view: `Needs review/action`, ranked by actionability rather than CVSS alone. Quick views:

- All findings
- Critical + High
- KEV / actively exploited
- Reachable
- Unreviewed
- Needs remediation

Display security facts separately: severity, KEV/EPSS, coverage, affectedness, reachability, human decision, remediation, and reportability. Never compress them into one opaque risk score or workflow status.

Priority bands are explainable:

- Urgent: overdue/≤24-hour deadline, or actively exploited and confirmed affected/reachable without required action.
- High: due within 72 hours, new/changed high-actionability finding, required approval blocker, or material monitoring failure.
- Normal: other unresolved decisions, remediation, evidence, or document work.
- Low: non-urgent scheduled work; informational changes remain outside default action queue.

Tie-break by deadline, risk drivers, then most recent change.

Rows navigate to a dedicated Finding page. Table exposes one `Review` action; affectedness, reportability, approval, and remediation decisions occur only on detail pages. Safe bulk actions are limited to assignment, notification acknowledgement, and export.

### Compliance

Cross-product CRA action center, defaulting to all products and Priority sort.

Aggregate:

- Readiness
- Deadlines
- Missing evidence/documents
- Open regulatory/reporting cases
- Requirements needing action
- Approvals
- Self-filing and missing-receipt tasks

Filters: Product, Release, Status, action type, owner, and time horizon. Remove Regulation filter because product is CRA-only.

Readiness uses status plus explicit blockers:

- Ready
- Needs attention
- Incomplete evidence

No compliance percentage. “Not applicable” is allowed only for individual reviewed requirements with recorded reason.

### Documents and self-filing

Product/Release Documents tab uses grouped tables, not report cards:

- CRA reporting packs
- Conformity documents
- Security exports such as SBOM/VEX
- Evidence bundles and verification records

Analysis/workflow changes create versioned drafts automatically. Operators complete missing evidence, request review, and authorized approvers approve an exact revision. Downloads are secondary actions on document detail.

Support customer self-filing only:

- Download approved pack and filing checklist.
- Record external submission time, reference, receipt, failure, or amendment.
- Never imply automatic submission.
- Keep managed filing absent from current UI; preserve API/domain compatibility for later addition.

Document detail includes source provenance, revision history, approval, audit timeline, evidence integrity, and trust verification. No separate Evidence tab.

### Settings and roles

Settings sections:

- Organization
- Team and four fixed roles
- Integrations/source health
- Notifications
- Security/retention
- Appearance

Roles:

- Organization Admin
- Compliance Operator
- Authorized Approver
- Read-only Auditor

Products have default owners; actionable findings/cases may be assigned to one member. Ownership does not grant approval permission.

## Visual and Interaction System

- Calm compliance workspace in both Light and Dark themes.
- Reuse existing brand assets and bundled fonts: Archivo for brand/display, Inter for UI, IBM Plex Mono only for identifiers, digests, and timers.
- Light foundation: `#1852C4` brand, `#0F1720` primary text, `#53606D` secondary text, white/light-slate surfaces, `#D9E1E8` borders.
- Dark foundation: `#0B1220` background, `#111A2B` surfaces, `#172238` raised surfaces, `#2B3950` borders, `#F4F7FA` text, `#B1BBC7` secondary text, `#8FB2F5` accent.
- Semantic colors communicate state only and always include text/icon labels.
- Minimal shadows, no decorative gradients, consistent 4/8px spacing, 48px table rows, one SVG icon family.
- One primary CTA per screen, placed in page header or final wizard footer. Secondary actions remain labeled; destructive actions live in detail-page overflow with confirmation.
- Remove unexplained ellipsis menus and checkboxes without available bulk actions.
- Theme follows system initially and persists explicit user override.
- Meet WCAG 2.2 AA: contrast, keyboard operation, visible focus, semantic tables/forms, 44px targets, screen-reader announcements, reduced motion, zoom/text scaling, and non-color status cues.
- Full desktop/tablet support from 768px upward. Mobile supports monitoring status, alerts, search, and light review; complex editing recommends a larger screen.

## Implementation and Public Interfaces

### Frontend

Create a React + TypeScript application under `apps/dashboard/` using Vite and React Router. Use native fetch, semantic HTML, CSS custom-property tokens, and minimal dependencies.

Build clickable high-fidelity prototype in this same application using typed fixtures. Prototype includes populated/empty Home, Products, Product/Release workspace, analysis wizard/progress/error states, Findings/detail, Compliance, Documents, and Settings. Production work replaces fixture adapters by vertical slice instead of rebuilding UI.

### Backend/API additions

Continue the final specification’s `/v1` Product, Release, Scan, Finding Decision, Monitoring, Case, Document, Approval, and Submission Attempt resources. Add organization-level read models required by the UI:

- `GET /v1/organizations/{id}/action-items`
- `GET /v1/organizations/{id}/compliance-overview`
- `GET /v1/organizations/{id}/monitoring-overview`
- `GET /v1/organizations/{id}/activity`
- `GET /v1/search`
- `GET /v1/notifications`
- Notification acknowledgement endpoint

Shared types:

```ts
type ReadinessStatus = "ready" | "needs_attention" | "incomplete_evidence";
type PriorityBand = "urgent" | "high" | "normal" | "low";
type MonitoringHealth = "healthy" | "degraded" | "failed" | "inactive";

interface ActionItem {
  id: string;
  type: string;
  priority: PriorityBand;
  reasons: string[];
  productId: string;
  releaseId?: string;
  title: string;
  status: string;
  dueAt?: string;
  ownerId?: string;
  targetUrl: string;
  updatedAt: string;
}
```

Backend calculates priority/readiness so CLI, notifications, and UI cannot disagree. Every resource action enforces fixed-role authorization and emits audit history.

### Delivery order

1. Design tokens, React shell, routes, scope control, typed fixtures, clickable prototype.
2. Organization/Product/Release persistence and four-role authorization.
3. Release evidence upload, validation, analysis history, and monitoring.
4. Findings queue/detail and human decision workflow.
5. Compliance action center, cases, documents, approval, and self-filing evidence.
6. Home aggregation, notifications, search, Recent Changes, Settings, and privacy-safe analytics.

Start implementation from latest `main`; commit each completed slice using conventional commits.

## Verification and Release

Automated and end-to-end scenarios:

- First-run checklist through first successful release analysis.
- Privacy-first evidence upload, validation warnings, failure recovery, async progress, and immutable rerun history.
- Hourly monitoring and release-scoped `Check now`.
- New KEV/reachability change creates prioritized Finding, action item, Recent Change, and alert.
- Source outage preserves findings and exposes degraded/stale health.
- Medium actionable finding ranks above Critical confirmed-not-affected finding.
- Compliance readiness never becomes Ready with partial/stale coverage or missing required evidence.
- Document draft → evidence completion → authorized approval → self-file → receipt/amendment history.
- Role restrictions and lightweight ownership.
- Global scope/search deep links and browser back-state restoration.
- Light/dark visual regression at 768, 1024, 1440, and wide desktop.
- WCAG 2.2 AA automated checks plus manual keyboard and screen-reader walkthrough.
- Core Web Vitals targets: LCP ≤2.5s, INP ≤200ms, CLS ≤0.1.

Release immediately replaces customer-facing dashboard; no beta flag. Existing runs/cases receive no migration and remain untouched in gated internal demo/archive mode. Test fixtures, saved-run selector, execution console, bundle verification demonstrations, and tamper simulation also move there.

Collect privacy-safe UX events after launch: routes, filter/search success, wizard completion/drop-off, action completion time, and errors. Never capture organization/product names, SBOM contents, finding text, evidence, documents, or uploaded filenames.

## Assumptions

- `CRA-Compliance-API-Spec-Final.docx` is authoritative; initial draft is historical.
- CRA-only product: no framework selector or generic multi-regulation UI.
- Self-filing is current scope; managed filing is later.
- Product/Release is primary domain; deployed-device fleet management remains future optional evidence functionality.
- No aggregate compliance score, opaque risk score, severity-only default, or separate Evidence/Monitoring/Risk page.
- Immediate replacement uses a fresh production data model while preserving legacy data without importing or deleting it.
