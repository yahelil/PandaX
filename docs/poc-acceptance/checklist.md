# PoC acceptance checklist

One row per acceptance card: what it must produce, how a reader decides pass or
fail, and who owns the failure.

Scope: documentation only. This checklist records outcomes. It does not
adjudicate vulnerabilities, interpret the CRA, or grant security approval.

---

## > BLOCKED — awaiting the card list

The 19 acceptance cards live on the project board and are not in this
repository. The table below is deliberately empty: inventing card titles would
produce a document that reads as authoritative and is not.

To unblock, supply for each of the 19 cards:

| Field | Example |
|---|---|
| Card id | `C07` |
| Title | Unseen firmware run end to end |
| Expected output | Sealed bundle + verdict screen for one Track B image |
| Owner | Person accountable if the check fails |
| Genuine or simulated | Genuine scan / simulated filing / both |

A board export, a paste of the card titles, or a screenshot of the board is
enough. The conventions in this file and in `evidence-index.md` are already
settled and do not change when the rows arrive.

---

## How a card is judged

Each card is **Pass**, **Fail**, or **Blocked**. There is no partial pass.

| State | Meaning |
|---|---|
| **Pass** | Expected output exists, evidence is filed and named per `evidence-index.md`, and any simulated artifact carries its banner |
| **Fail** | Expected output missing, evidence missing or unlabelled, or the check did not hold. The named owner picks it up |
| **Blocked** | Cannot be attempted yet. Records what it waits on |

"Owner on failure" is who investigates — not who is at fault.

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

## Cards

| Card | Expected output | Pass condition | Genuine / Simulated | Owner on failure | Status |
|---|---|---|---|---|---|
| _pending card list_ | | | | | |

---

## Acceptance of this checklist

This document is complete when:

- [ ] All 19 cards appear as rows
- [ ] Every row has a pass condition a second person can apply unaided
- [ ] Every row names an owner
- [ ] Every row is marked genuine, simulated, or both
- [ ] No row's pass condition implies complete coverage
- [ ] Firmware cards reference `firmware-intake.md`
- [ ] No confidential firmware or credentials committed
