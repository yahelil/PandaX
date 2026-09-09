# Evidence index

Where acceptance evidence lives, what each artifact must contain, and how a
reader tells a genuine finding from a simulated one.

Scope: documentation only. Recording evidence here is not vulnerability
adjudication, legal interpretation or security approval.

---

## Layout

```
docs/poc-acceptance/
  checklist.md                 pass/fail per card, and the owner of each failure
  evidence-index.md            this file
  firmware-intake.md           public and unseen firmware intake
  results/
    logs/                      command output, verbatim
    screenshots/               UI state a reader cannot reproduce from a log
    manifests/                 expected inventories agreed before a run
```

`results/` is the evidence root named by card 19. Nothing outside it is
acceptance evidence.

## Naming

```
<card>__<subject>__<YYYY-MM-DD>.<ext>
```

`card` is the two-digit execution position `01`–`19`, so evidence sorts by card
and a reader goes from a failed check to its artifact without searching:

```
results/logs/03__extraction-matrix__2026-09-10.txt
results/screenshots/09__coverage-states__2026-09-10.png
results/manifests/openwrt-23.05.5.md
```

## What each artifact must carry

| Type | Must include |
|---|---|
| **Log** | Exact command, working directory, UTC start time, tool versions, full unedited output, exit code |
| **Screenshot** | Full window including any status or mode banner; no cropping that removes a SIMULATED label |
| **Manifest** | Source of the answer key, who produced it, timestamp preceding the run — see `firmware-intake.md` |

Logs go in verbatim. If output must be shortened, mark the cut with `[… N lines
omitted …]` and keep the original alongside. Never edit a log to make a check
pass — a failing log is the evidence that the check failed.

---

## Genuine findings versus simulated events

The PoC produces both. A reader must never have to guess which is which.

### Genuine — observed, independently checkable

| Artifact | Why it is genuine |
|---|---|
| Component inventory from a real image | Derived from the artifact; SHA256 ties it to the file |
| CVE matches from live feeds | Reproducible against OSV, KEV and EPSS at the recorded time |
| Hashes, seals, signatures | Verifiable by a third party without this system |
| Test results | Re-runnable from the recorded command |

### Simulated — constructed for the PoC, never sent anywhere

| Artifact | Why it is simulated |
|---|---|
| Article 14 filings (24h / 72h / final) | Manual SRP; no live submission to any authority |
| Submission receipts | Generated locally; no authority issued them |
| Authority acknowledgements | Do not exist; represented only |
| Incident timelines and clock starts | Triggered manually, not by a real disclosure |

Cards 16 and 17 are **fully simulated**. Cards 11, 14, 15, 18 and 19 produce
both: genuine clock, persistence and scan behaviour, and simulated filings and
receipts. Every other card is genuine.

### Labelling rule

Every simulated artifact carries a banner as the **first line** of the file, or
visible in the frame of a screenshot:

```
SIMULATED — generated locally for the proof of concept.
Not submitted to any authority. No receipt here originates from ENISA or a CSIRT.
```

A simulated artifact with no banner is a failed check, whatever it shows. If one
file mixes both kinds, the simulated portion is labelled inline where it starts.

**Nothing in this repository has been submitted to a regulator.** No live
submissions, no production services.

---

## Owner-reported evidence carried over from the board

Six cards record a commit and a test run in their card description. These are
**owner-reported**: they were produced by the card owner on the owner's machine
and have not been independently re-run for acceptance. They are a starting
point for card 19, not a substitute for it.

| Card | Commit | Owner-reported result |
|---|---|---|
| 05 | `775de05` | 34 passed — migrations, rollback, restart, replay, stale writes, API/CLI |
| 11 | `f2f33cd` | 21 passed — corrections, attestation validation, exact-hash approval, invalidation |
| 14 | `8c55645` | 22 passed — pending/known/overdue deadlines, reviewed reportability, restart |
| 15 | `6153d2b` | 26 passed — incident intake, coexistence, month-end and leap-year, restart |
| 16 | `230002d` | 35 passed — both types, all stages, glossary requirements, carry-forward |
| 17 | `3a77979` | 164 passed, 10 deselected — receipts, amendments, retries, snapshots |

Cards **01, 02, 03, 06 and 09** are marked Done on the board with **no recorded
verification**. Their acceptance evidence must be produced from scratch during
card 19.

---

## What passing evidence does not prove

Evidence recorded here shows what a run **observed** under the conditions
recorded with it. It does not establish that an image is free of
vulnerabilities, and a clean result is not proof of complete coverage:
undetected components, vulnerabilities with no published advisory, backported
vendor fixes and runtime-only issues all fall outside it.

Write findings as "this run observed X", never "the product contains only X".

---

## Card index

One row per card. `Status` is the acceptance result, not the board column — see
`checklist.md` for the distinction. Paths are filled in as evidence is filed.

| Card | Expected output | Evidence path | G / S | Owner | Status |
|---|---|---|---|---|---|
| 01 | Clock and verdict output for pending, known, overdue; one historical bundle | `results/logs/01__clock-fixtures__<date>.txt` | Genuine | Yaheli | ⬜ pending |
| 02 | Verification runs with correct, wrong and missing trusted key | `results/logs/02__trust-matrix__<date>.txt` | Genuine | Guy | ⬜ pending |
| 03 | SquashFS and UBIFS extraction reports; limit and unsafe-path failures | `results/logs/03__extraction-matrix__<date>.txt` | Genuine | Simon | ⬜ pending |
| 04 | This checklist, index and intake document | branch `eden-poc-guide` | — | Eden | ⬜ pending |
| 05 | Restart, replay, rollback and stale-update runs | `results/logs/05__persistence__<date>.txt` | Genuine | Yaheli | ⬜ pending |
| 06 | Standalone verifier from a clean environment; re-sealed bundle rejected | `results/logs/06__standalone-verify__<date>.txt` | Genuine | Guy | ⬜ pending |
| 07 | Pinned OpenWrt manifest, UBIFS fixture, extraction matrix | `results/manifests/openwrt-<release>.md`, `results/logs/07__fixture-matrix__<date>.txt` | Genuine | Simon | ⬜ pending |
| 08 | Preflight checker output on a real developer machine | `results/logs/08__preflight-real-machine__<date>.txt` | Genuine | Eden | ⬜ pending |
| 09 | Coverage states rendered; feed failure and empty query never clean | `results/screenshots/09__coverage-states__<date>.png` | Genuine | Guy | ⬜ pending |
| 10 | veraPDF results for valid, invalid, missing validator and timeout | `results/logs/10__verapdf-matrix__<date>.txt` | Genuine | Simon | ⬜ pending |
| 11 | Approval invalidation, missing attestation, awareness correction | `results/logs/11__review-signoff__<date>.txt` | Both | Yaheli | ⬜ pending |
| 12 | Frozen benchmark 76/76 with 34 negative controls retained | `results/logs/12__benchmark-76__<date>.txt` | Genuine | Guy | ⬜ pending |
| 13 | Whole-corpus validation plus rendered-page QA | `results/logs/13__corpus-validation__<date>.txt`, `results/screenshots/13__render-qa__<date>.png` | Genuine | Simon | ⬜ pending |
| 14 | One reviewed vulnerability lifecycle with derived deadlines | `results/logs/14__vuln-lifecycle__<date>.txt` | Both | Yaheli | ⬜ pending |
| 15 | One incident lifecycle; month-end, leap-year and timezone cases | `results/logs/15__incident-lifecycle__<date>.txt` | Both | Yaheli | ⬜ pending |
| 16 | Submission pack and internal JSON for both types, all stages | `results/logs/16__srp-fields__<date>.txt` | **Simulated** | Yaheli | ⬜ pending |
| 17 | Submission, failure, retry, receipt, amendment, restart | `results/logs/17__receipts__<date>.txt` | **Simulated** | Yaheli | ⬜ pending |
| 18 | Refresh, restart catch-up, dedup and a simulated source outage | `results/logs/18__refresh-dedup__<date>.txt`, `results/screenshots/18__stale-coverage__<date>.png` | Both | Yaheli | ⬜ pending |
| 19 | Track A rehearsal and Track B unseen run, end to end | `results/` (whole tree) | Both | Eden | ⬜ pending |

Firmware cards **03, 07 and 19** additionally require a completed intake record
per `firmware-intake.md` before the run.
