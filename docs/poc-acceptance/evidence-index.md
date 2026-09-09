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
  evidence/
    screenshots/               UI state a reader cannot reproduce from a log
    logs/                      command output, verbatim
    manifests/                 expected inventories agreed before a run
```

## Naming

```
<card-id>__<subject>__<YYYY-MM-DD>.<ext>
```

`card-id` is the board id, so evidence sorts by card and a reader can go from a
failed check to its artifact without searching. Example:

```
evidence/logs/C07__openwrt-2310-scan__2026-09-09.txt
evidence/screenshots/C07__verdict-screen__2026-09-09.png
evidence/manifests/openwrt-2310.md
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
| Article 14 filings (24h / 72h / 14d) | Manual SRP; no live submission to any authority |
| Submission receipts | Generated locally; no authority issued them |
| Authority acknowledgements | Do not exist; represented only |
| Incident timelines and clock starts | Triggered manually, not by a real disclosure |

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

## What passing evidence does not prove

Evidence recorded here shows what a run **observed** under the conditions
recorded with it. It does not establish that an image is free of
vulnerabilities, and a clean result is not proof of complete coverage:
undetected components, vulnerabilities with no published advisory, backported
vendor fixes and runtime-only issues all fall outside it.

Write findings as "this run observed X", never "the product contains only X".

---

## Card index

One row per card. Populated as cards are accepted.

| Card | Expected output | Evidence path | Genuine / Simulated | Owner on failure | Status |
|---|---|---|---|---|---|
| _pending card list_ | | | | | |

> **Blocked.** The 19 acceptance cards are on the project board and are not in
> this repository. Rows are added once the card ids, titles and owners are
> supplied — see the Blocked note in `checklist.md`.
