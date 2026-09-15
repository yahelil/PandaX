# PoC acceptance checklist

One row per acceptance card: what it must produce, how a reader decides pass or
fail, and who owns the failure.

Scope: documentation only. This checklist records outcomes. It does not
adjudicate vulnerabilities, interpret the CRA, or grant security approval.

Card ids `01`–`19` are the execution positions on the project board. Evidence
filenames use the same ids — see `evidence-index.md`.

---

## How a card is judged

Each card is **Pass**, **Fail**, or **Blocked**. There is no partial pass.

| State | Meaning |
|---|---|
| **Pass** | Expected output exists, evidence is filed and named per `evidence-index.md`, and any simulated artifact carries its banner |
| **Fail** | Expected output missing, evidence missing or unlabelled, or the check did not hold. The named owner picks it up |
| **Blocked** | Cannot be attempted yet. Records what it waits on |

"Owner on failure" is who investigates — not who is at fault.

### Board status is not an acceptance result

A card marked Done on the board means its owner considers the work merged. It
does not mean acceptance evidence has been filed here. The two columns are
tracked separately and only the **Acceptance** column decides this checklist.

Six Done cards (05, 11, 14, 15, 16, 17) carry an owner-reported commit and test
run in their card description; those are recorded in `evidence-index.md` as
**owner-reported** and still require an independent run under card 19. Five Done
cards (01, 02, 03, 06, 09) carry no recorded verification at all — their
acceptance evidence must be produced from scratch.

---

## Standing rules

These apply to every card regardless of its content.

1. **Evidence or it did not happen.** A pass with no filed artifact is a Fail.
2. **Simulated artifacts are labelled**, per `evidence-index.md`. An unlabelled
   simulated artifact fails its card even if the output is correct.
3. **A clean scan is not proof of coverage.** No card may be written so that
   passing it claims completeness. Findings read "this run observed X".
4. **Nothing confidential is committed** — no firmware images, credentials,
   keys or personal data. See `firmware-intake.md`.
5. **Logs are verbatim.** Editing output to make a check pass voids the card.
6. **Firmware cards require a completed intake record** before the run.
7. **No live submissions.** Filings and receipts are local and simulated.

---

## Acceptance matrix

| Card | Title | Owner | G / S | Board | Acceptance |
|---|---|---|---|---|---|
| 01 | CLI clock and verdict before final report | Yaheli | Genuine | Done | ⬜ pending |
| 02 | External trust anchor for evidence | Guy | Genuine | Done | ⬜ pending |
| 03 | SquashFS / UBIFS ingest via Docker unblob | Simon | Genuine | Done | ⬜ pending |
| 04 | This checklist and the evidence index | Eden | Genuine | To Do | ⬜ pending |
| 05 | Durable cases, events, decisions, clocks | Yaheli | Genuine | Done | ⬜ pending |
| 06 | External verification and key substitution | Guy | Genuine | Done | ⬜ pending |
| 07 | Pinned firmware fixtures and test matrix | Simon | Genuine | To Do | ⬜ pending |
| 08 | Setup checker and founder quickstart | Eden | Genuine | To Do | ⬜ pending |
| 09 | Coverage, affectedness, reachability | Guy | Genuine | Done | ⬜ pending |
| 10 | veraPDF PDF/A-2b validation | Simon | Genuine | To Do | ⬜ pending |
| 11 | Awareness, attestation, authorised sign-off | Yaheli | Both | Done | ⬜ pending |
| 12 | curl / OpenSSL benchmark misses | Guy | Genuine | To Do | ⬜ pending |
| 13 | PDF corpus validation and rendering | Simon | Genuine | To Do | ⬜ pending |
| 14 | Article 14 vulnerability workflow | Yaheli | Both | Done | ⬜ pending |
| 15 | Article 14 severe-incident workflow | Yaheli | Both | Done | ⬜ pending |
| 16 | ENISA SRP fields and manual checklist | Yaheli | **Simulated** | Done | ⬜ pending |
| 17 | Receipts, amendments, failures | Yaheli | **Simulated** | Done | ⬜ pending |
| 18 | Deduplicated cases from advisory refresh | Yaheli | Both | To Do | ⬜ pending |
| 19 | Real-device acceptance run | Eden | Both | To Do | ⬜ pending |

Owners: Yaheli 8 · Guy 4 · Simon 4 · Eden 3.
`G / S` marks whether the card's evidence is a genuine observation, a simulated
PoC artifact, or a run that produces both. Cards marked **Simulated** produce
nothing that was sent to any authority.

---

## Per-card checks

Each pass condition below is the card's own acceptance clause, restated so a
second person can apply it without reading the board.

### 01 — CLI clock and verdict before final report · Yaheli

- **Expected output** — `actis clock` and `actis verdict` output for the
  pending, known and overdue fixtures; one historical bundle re-read.
- **Pass** — all three fixtures run without `KeyError` when `final_report` is
  absent; pending measure availability is shown rather than assumed; a
  pre-change bundle still loads.
- **Fail** — any `KeyError`, a fabricated final-report date, or accelerated demo
  time appearing in persisted evidence.
- **Evidence** — `results/logs/01__clock-fixtures__<date>.txt`, plus
  `pytest apps/engine/tests/test_cli_clock.py`.
- **Owner on failure** — Yaheli.

### 02 — External trust anchor for evidence · Guy

- **Expected output** — three verification runs over one sealed bundle: correct
  trusted key, wrong key, no key.
- **Pass** — correct key returns trusted; wrong key and missing key both fail
  trusted verification. A missing trusted key must never return trusted
  VERIFIED. Integrity-only inspection stays available and is reported as
  distinct from trust.
- **Fail** — any path where a bundled key satisfies trust, or where absent trust
  configuration still reports VERIFIED.
- **Evidence** — `results/logs/02__trust-matrix__<date>.txt`, from
  `actis verify` and `actis-verify <bundle> --trusted-key <key>` /
  `--inspect-only`; plus `pytest apps/engine/tests/test_trusted_verification.py`.
- **Owner on failure** — Guy.

### 03 — SquashFS / UBIFS ingest via Docker unblob · Simon

- **Expected output** — extraction reports for one SquashFS and one UBIFS
  fixture; failure output for an unsafe path and for each exceeded limit;
  failure output with Docker unavailable.
- **Pass** — both fixtures extract and feed the existing inventory stage; unsafe
  paths and the 1 GiB / 10 GiB / 100000 file / 10 minute limits fail with a
  readable reason; missing Docker explains the remedy instead of raising; ZIP
  and TAR ingest unchanged. Source digest, tool version and extraction report
  are recorded.
- **Fail** — a silent or partial extraction that reports success.
- **Evidence** — `results/logs/03__extraction-matrix__<date>.txt`, plus
  `pytest apps/engine/tests/test_firmware.py apps/engine/tests/test_firmware_integration.py apps/engine/tests/test_ingest.py`.
- **Owner on failure** — Simon.

### 04 — This checklist and the evidence index · Eden

- **Expected output** — `checklist.md`, `evidence-index.md`,
  `firmware-intake.md` under `docs/poc-acceptance/`.
- **Pass** — all 19 cards appear with a pass condition a second person can
  apply unaided and a named owner; every card is marked genuine, simulated or
  both; no pass condition implies complete coverage; the firmware intake
  checklist covers source, permission, format, SHA256 and an independently
  agreed expected inventory; no confidential firmware or credentials committed.
- **Fail** — any card without a pass condition or owner, or any wording that
  reads a clean scan as complete coverage.
- **Evidence** — this branch and its review.
- **Owner on failure** — Eden.

### 05 — Durable cases, events, decisions, clocks · Yaheli

- **Expected output** — a case surviving a restart with deadlines intact; a
  repeated request; a rolled-back transaction; a stale update; one pre-change
  scan re-opened.
- **Pass** — restart preserves all state and deadlines; a repeated request adds
  no duplicate event; rollback and stale-update rejection are exercised; old
  scans still load; original scan bundles remain immutable.
- **Fail** — duplicated events, a deadline recomputed on restart, or a mutated
  source bundle.
- **Evidence** — owner-reported `775de05`; re-run
  `pytest apps/engine/tests/test_cases.py apps/engine/tests/test_case_service.py apps/engine/tests/test_cli_clock.py`.
- **Owner on failure** — Yaheli.

### 06 — External verification and key substitution · Guy

- **Expected output** — a standalone verifier run from an environment without
  PandaX installed, over an exported bundle, using a separately supplied key;
  plus tampering, missing and malformed manifest, wrong key, and a fully
  re-sealed bundle signed by a substituted signer.
- **Pass** — the attacker-resealed bundle fails trusted verification even though
  every internal digest and chain link is internally consistent; the trusted
  export verifies from a fresh environment. Commands and results recorded.
- **Fail** — a re-sealed bundle reported as trusted, or integrity-only
  inspection presented as trusted verification.
- **Evidence** — `results/logs/06__standalone-verify__<date>.txt` from
  `actis-verify` in a clean virtualenv, plus
  `pytest apps/verifier/tests/`.
- **Note** — the card names `tools/verify_bundle.py`; the verifier shipped as
  `apps/verifier` (`actis-verify`). Confirm with Guy that this is the intended
  location before recording the card as passed.
- **Owner on failure** — Guy.

### 07 — Pinned firmware fixtures and test matrix · Simon

- **Expected output** — a pinned official OpenWrt device image with URL, SHA256
  and an independently produced expected inventory; a UBIFS fixture; a
  success/failure matrix over Docker availability, path containment, limits and
  partial, unsupported and encrypted images.
- **Pass** — a fresh environment reproduces both the extraction and the
  inventory; the recorded SHA256 matches on re-download; ZIP and TAR
  regressions pass; an unknown or partial extraction can never present as
  successful. Manifests, scripts and results are committed; binaries are not.
- **Fail** — a fixture that only reproduces on the author's machine, or a
  committed image.
- **Evidence** — `results/manifests/openwrt-<release>.md` and
  `results/logs/07__fixture-matrix__<date>.txt`.
- **Limit** — Track A public fixtures do not substitute for the unseen-image
  acceptance in card 19.
- **Owner on failure** — Simon.

### 08 — Setup checker and founder quickstart · Eden

- **Expected output** — `tools/poc_preflight.py`, its tests, and
  `docs/poc-acceptance/founder-quickstart.md`.
- **Pass** — `python tools/poc_preflight.py [--firmware] [--pdf]` prints
  PASS/FAIL per required check with a short fix instruction; exit 0 only when
  the requested checks pass, otherwise 1. Missing executable, non-zero exit and
  a 10-second timeout produce readable errors, never a traceback. Tests pass on
  a machine with neither Docker nor veraPDF installed, and unrequested optional
  tools never fail default mode. Paths containing spaces are covered. Real
  results from a developer machine are documented.
- **Fail** — a traceback on a missing tool, or an optional tool failing a run
  that did not request it.
- **Evidence** — `results/logs/08__preflight-real-machine__<date>.txt`, plus
  `pytest tools/test_poc_preflight.py`.
- **Owner on failure** — Eden.

### 09 — Coverage, affectedness, reachability · Guy

- **Expected output** — findings carrying explicit coverage metadata
  (unscanned, unsupported, unknown or failed, completed); one run with a feed
  failure; one empty generic query; one pre-change bundle re-rendered.
- **Pass** — a feed failure or an empty generic query never renders as clean;
  "no findings" reads as no findings in the sources actually checked;
  unaffected requires advisory-specific evidence; KEV alone never sets VEX
  exploitable; old bundles render with coverage unknown; native advisory links
  resolve to `source_url`.
- **Fail** — any path where absent data reads as a clean result.
- **Evidence** — `results/screenshots/09__coverage-states__<date>.png` and
  `pytest apps/engine/tests/test_vulnerability_coverage.py`.
- **Owner on failure** — Guy.

### 10 — veraPDF PDF/A-2b validation · Simon

- **Expected output** — validator results for a valid PDF, a deliberately
  invalid PDF, a missing validator and a timeout; validator version and profile
  retained alongside each generated document.
- **Pass** — the valid sample passes 2b, the invalid sample fails, and a missing
  validator or timeout fails clearly rather than passing by default. Every
  generated PDF is checked before sealing, and validation evidence enters the
  normal manifest collection. A failed validation prevents a completed
  validated bundle while diagnostics are retained.
- **Fail** — a sealed bundle containing an unvalidated or failing PDF.
- **Evidence** — `results/logs/10__verapdf-matrix__<date>.txt` with the pinned veraPDF
  version and the explicit 2b profile.
- **Owner on failure** — Simon.

### 11 — Awareness, attestation, authorised sign-off · Yaheli

- **Expected output** — an approval bound to an exact report revision hash; an
  edit after approval; a missing attestation; a corrected awareness date; a
  restart.
- **Pass** — editing an approved report invalidates the approval and creates a
  new revision; a missing attestation blocks approval; an awareness correction
  appends history and recalculates without silently resetting the clock;
  approved content is immutable; timestamps are stored in UTC from
  timezone-aware input. Occurrence, detection and awareness stay separate.
- **Fail** — an approval surviving an edit, or a clock reset with no history.
- **Evidence** — owner-reported `f2f33cd`; re-run
  `pytest apps/engine/tests/test_cases.py apps/engine/tests/test_case_service.py apps/engine/tests/test_case_review.py`.
- **Owner on failure** — Yaheli.

### 12 — curl / OpenSSL benchmark misses · Guy

- **Expected output** — a frozen independent benchmark run, the negative-control
  set, and boundary cases for CVE-2023-38546 (fixed 8.4.0), CVE-2023-46218
  (fixed 8.5.0), CVE-2014-0224 and CVE-2014-0195 (fixed 1.0.1h).
- **Pass** — 76/76 on the frozen benchmark with all 34 negative controls
  retained, reached by source-aware discovery from verified upstream identity
  and versioned vendor advisories — not by seven output overrides. Distro
  revision and backport evidence is respected; raw evidence, ranges, retrieval
  time and conflicting sources are preserved; component affectedness stays
  separate from product reachability. Remaining curated coverage is documented.
- **Fail** — any expected result edited to make the benchmark pass, or a lost
  negative control.
- **Evidence** — `results/logs/12__benchmark-76__<date>.txt` from `tools/evaluate.py`
  and `tools/evaluate_reference.py`.
- **Owner on failure** — Guy.

### 13 — PDF corpus validation and rendering · Simon

- **Expected output** — every generated document type plus stress fixtures with
  long tables and missing-input notices; machine-readable veraPDF results;
  rendered pages inspected for clipping and readability; one deliberately
  invalid PDF.
- **Pass** — every corpus PDF passes 2b and visual QA, the invalid PDF fails,
  and **one command validates an entire output directory** so Eden can run it
  over the final case exports in card 19. Regulatory content is unchanged; only
  Typst, rendering or validation defects are fixed.
- **Fail** — a clipped or unreadable page passing on the 2b result alone, or no
  reusable whole-directory command delivered.
- **Evidence** — `results/logs/13__corpus-validation__<date>.txt` and
  `results/screenshots/13__render-qa__<date>.png`.
- **Handoff** — the whole-directory command is a prerequisite for card 19.
- **Owner on failure** — Simon.

### 14 — Article 14 vulnerability workflow · Yaheli

- **Expected output** — one reviewed lifecycle from evidence through early
  warning, notification and final report; pending, known and overdue timing;
  backdated awareness; a restart.
- **Pass** — 24h and 72h deadlines derive from recorded awareness and the final
  deadline from actual corrective or mitigating measure availability plus 14
  days; a missing trigger stays pending rather than assuming a date; no KEV-only
  automatic product exploitability or reportability claim; revisions are
  prepared, never auto-submitted.
- **Fail** — a deadline computed from a date that was never recorded.
- **Evidence** — owner-reported `8c55645`; re-run
  `pytest apps/engine/tests/test_case_workflow.py apps/engine/tests/test_case_review.py apps/engine/tests/test_case_service.py apps/engine/tests/test_cases.py`.
- **Labelling** — the clock logic is genuine; every filing it produces is
  simulated and must carry the banner.
- **Owner on failure** — Yaheli.

### 15 — Article 14 severe-incident workflow · Yaheli

- **Expected output** — an incident case with severity and impact assessment,
  awareness evidence, mitigation and root cause; month-end, leap-year and
  timezone cases; a full incident demo and a restart.
- **Pass** — both case types coexist without conflated fields or deadlines; the
  incident final deadline is one calendar month after notification submission
  and does not reuse the vulnerability +14-day clock; unknown trigger dates are
  retained as unknown.
- **Fail** — a vulnerability clock applied to an incident, or an invented
  trigger date.
- **Evidence** — owner-reported `6153d2b`; re-run
  `pytest apps/engine/tests/test_case_incident.py apps/engine/tests/test_case_workflow.py apps/engine/tests/test_case_review.py apps/engine/tests/test_case_service.py apps/engine/tests/test_cases.py`.
- **Owner on failure** — Yaheli.

### 16 — ENISA SRP fields and manual checklist · Yaheli

- **Expected output** — a readable submission pack and internal JSON for both
  case types at every stage, with the manual SRP entry checklist.
- **Pass** — field-by-field fixture checks pass for both types and all stages;
  required, conditional, optional and carried-forward fields are distinguished;
  an incomplete pack can never show ready; readiness requires both the required
  fields and an approved revision; input placeholders never become attested
  facts; statutory clocks stay independent of any portal reminder counter.
  Field definitions are versioned against the official ENISA glossary with
  source and retrieval date recorded.
- **Fail** — an invented SRP API or schema, or any automatic submission.
- **Evidence** — owner-reported `230002d`; re-run
  `pytest apps/engine/tests/test_case_fields.py`; export via `actis case export`.
- **Labelling** — **fully simulated.** Nothing here reaches ENISA.
- **Owner on failure** — Yaheli.

### 17 — Receipts, amendments, failures · Yaheli

- **Expected output** — recorded submission attempts with approved revision
  hash, timestamp, platform reference and receipt digest; a failure; a retry; an
  amendment; a restart.
- **Pass** — prepared, operator-recorded submitted and acknowledged are
  distinct states; a failure does not satisfy an obligation; an amendment
  preserves and links the prior submission, requires fresh approval and
  produces a new immutable snapshot; approved payload cannot change under an
  existing receipt. Every simulated receipt is explicitly labelled.
- **Fail** — an unlabelled receipt, or a payload mutated under a recorded
  receipt.
- **Evidence** — owner-reported `3a77979` (164 passed, 10 deselected); re-run
  `pytest -m "not slow" apps/engine/tests/`.
- **Labelling** — **fully simulated.** No receipt here originates from ENISA or
  a CSIRT.
- **Owner on failure** — Yaheli.

### 18 — Deduplicated cases from advisory refresh · Yaheli

- **Expected output** — a watched product and release inventory; an hourly
  refresh, a manual "Refresh now", and one catch-up on restart; a simulated
  source outage; a deterministic labelled replay.
- **Pass** — one advisory yields exactly one case across repeated refreshes and
  restarts; new evidence appends to the existing case rather than opening a
  second; a source outage preserves prior results and shows stale coverage
  instead of clearing findings; the background loop stops with the app; review
  never resets actual awareness; real and simulated events remain
  distinguishable.
- **Fail** — a duplicate case, or an outage that clears findings.
- **Evidence** — `results/logs/18__refresh-dedup__<date>.txt` and
  `results/screenshots/18__stale-coverage__<date>.png`.
- **Owner on failure** — Yaheli.

### 19 — Real-device acceptance run · Eden

> **2026-09-13 scoped acceptance:** Yaheli approved a reduced PoC gate using the
> repository's CycloneDX SBOM fixture instead of Track A/B firmware. The SBOM
> pipeline, case/restart behavior, simulated advisory and incident paths, three
> generated PDFs, evidence seal, and external-key verification passed. This
> closes card 19 only for the CycloneDX SBOM PoC; it does **not** claim raw
> firmware or real-device validation. Evidence: [execution log](results/logs/19__lean-sbom-validation__2026-09-13.txt)
> and [manifest summary](results/manifests/19__lean-sbom-validation__2026-09-13.md).

- **Expected output** — the Track A OpenWrt rehearsal, then the Track B unseen
  image run; a real scan; separately labelled simulated advisory and incident;
  review, clocks, restart, exports, a simulated receipt and an amendment; the
  owners' verifier and veraPDF commands; every artifact filed in
  `docs/poc-acceptance/results/`.
- **Pass** — every card in this checklist has actual pass/fail evidence; all
  PDFs validate; exported snapshots verify with a separately supplied key;
  unknown coverage stays visible in the output. A missing user firmware image is
  a Fail, never a pass by omission.
- **Fail** — any card left without evidence, or an image-specific fix applied
  during the run. If code needs a fix, the owner fixes it generally and Yaheli
  selects **another** unseen image for the final blind gate.
- **Prerequisites** — all development cards merged, and cards 04 and 08 ready.
  Card 13 must have delivered the whole-directory PDF validation command.
- **Boundary** — Eden operates the checklist and reports failures to the
  responsible owner. Eden does not debug source, adjudicate vulnerabilities or
  approve security or legal correctness; Yaheli owns final technical acceptance.
- **Owner on failure** — the card owner named above for whichever check failed.

---

## Acceptance of this checklist

- [x] All 19 cards appear as rows
- [x] Every row has a pass condition a second person can apply unaided
- [x] Every row names an owner
- [x] Every row is marked genuine, simulated, or both
- [x] No row's pass condition implies complete coverage
- [x] Firmware cards reference `firmware-intake.md`
- [x] No confidential firmware or credentials committed
