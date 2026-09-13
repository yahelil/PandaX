# Firmware intake — public reference and unseen image

Intake rules for the two firmware tracks used in PoC acceptance. A completed
intake record is a prerequisite for any acceptance run involving firmware.

Scope: intake and provenance only. This document does not adjudicate
vulnerabilities, interpret the CRA, or grant security approval.

---

## Why two tracks

| Track | Image | Answer key | What it demonstrates |
|---|---|---|---|
| **A — Public reference** | Known public release, pinned | Published in advance | Repeatability against a fixed baseline |
| **B — Unseen** | Not chosen until run time | Agreed independently, before the run | That results do not depend on prior tuning |

Track A shows the pipeline is stable. Track B is the one that carries
credibility, and it only carries it if the anti-tuning rules below hold.

## Which cards use this

A completed intake record is a prerequisite for every card below. Pass and fail
conditions for each are in `checklist.md`.

| Card | Owner | Use of this document |
|---|---|---|
| **03** | Simon | Builds the ingest path. Records source digest, tool version and extraction report for each fixture it extracts |
| **07** | Simon | Pins the Track A image — an official OpenWrt device release with URL, SHA256 and an independently produced expected inventory — plus a UBIFS fixture. Commits manifests and scripts, never binaries |
| **19** | Eden | Runs Track A as rehearsal, then draws and runs the Track B unseen image. Files every intake record and result under `results/` |

Track A is pinned once, in card 07, and reused. Track B is drawn at run time in
card 19 and never before.

---

## Anti-tuning rules (Track B)

These rules are what make an unseen result meaningful. Breaking any one of them
turns Track B into a second Track A.

1. **Do not select the image in advance.** The candidate pool may be defined
   ahead of time (for example, "any current stable release for a target we do
   not already test"). The specific image is drawn at run time.
2. **Do not tune on it.** No engine, matcher, feed or threshold change after
   seeing its output. Changes prompted by a Track B run land as follow-up work
   and need a fresh unseen image to re-demonstrate.
3. **Record the choice before running.** Commit the intake record — including
   SHA256 and the agreed expected inventory — before the first run.
4. **One attempt, recorded either way.** A disappointing result is a result.
   Re-drawing after a bad run is tuning. If a run is voided, record why.
5. **The expected inventory comes from someone other than the run operator**,
   and from a source independent of this system (vendor manifest, build
   manifest, package database) — never from an SBOM this pipeline produced.

---

## Intake record

Complete for every image, both tracks. One block per image.

```yaml
image_id:                 # short slug, reused in evidence filenames
track:                    # A (public reference) | B (unseen)
project:
device_or_target:
release_version:          # exact release string, never "latest"
source_url:
source_is_official:       # yes | no — official project mirror?
permission_to_use:        # licence or terms permitting analysis + publication
licence:
redistribution:           # may the image be committed?  Expected: NO
format:                   # e.g. squashfs-sysupgrade.bin, rootfs tar.gz
size_bytes:
sha256:                   # of the file as downloaded, before extraction
downloaded_at:            # ISO 8601, UTC
obtained_by:
expected_inventory:
  source:                 # where the answer key came from
  produced_by:            # must differ from run_operator
  agreed_at:              # ISO 8601 — must precede run_started_at
  path:                   # results/manifests/<image_id>.md
run_started_at:
run_operator:
```

### SHA256

Hash the file exactly as downloaded, before extraction:

```bash
shasum -a 256 <file>
```

Re-verify before each run and record the result. A mismatch voids the run: the
artifact is not what the record says it is.

---

## What must never be committed

- Firmware images or extracted filesystems
- Anything under NDA, customer-supplied, or pre-release
- Credentials, keys, tokens or private URLs recovered from an image
- Personal data recovered from an image

Commit the **record**, not the artifact. Images live outside the repository;
the SHA256 is what ties the record to the file.

If a run surfaces a credential or personal data inside a public image, stop, do
not commit the finding verbatim, and hand it to the intake owner.

---

## Pass / fail

| Check | Pass condition | Owner on failure |
|---|---|---|
| Intake record complete | No blank fields | Intake owner |
| SHA256 recorded pre-run and re-verified at run | Both values match | Run operator |
| Permission to use confirmed | Licence permits analysis and publication | Intake owner |
| Expected inventory agreed before the run, by a second person | `agreed_at` precedes `run_started_at`; `produced_by` differs from `run_operator` | Intake owner |
| Track B not chosen or tuned in advance | Draw timestamp follows pool definition; no engine change between draw and run | Run operator |
| Nothing confidential committed | Repository clean | Intake owner |

---

## Limits of a passing run

A pass here means **the intake was sound** — not that the firmware is secure.

A clean or complete-looking result does **not** establish complete coverage.
Inventory and advisory matching are bounded by what the analyser can see and by
what the feeds carry. Components the analyser does not detect, vulnerabilities
with no published advisory, backported vendor fixes, and runtime-only issues are
all outside what a run of this kind can speak to. This is inventory and
advisory matching — not runtime exploitation testing, and not independent
scanner validation.

Record results as "what this run observed", never as "what the image contains".
