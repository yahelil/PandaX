# Founder quickstart

Getting from a fresh machine to a scan you can show someone, and capturing the
evidence while you do it.

Read this alongside `checklist.md`, which decides what counts as a pass, and
`evidence-index.md`, which decides where the evidence goes.

---

## Verification status

Every command below is marked. This matters: a quickstart that presents an
unrun command as a working one wastes the reader's afternoon.

| Mark | Meaning |
|---|---|
| **verified** | Run on a real machine; the actual output is recorded here |
| **pending** | Documented from the repository, not yet run for this guide |

Nothing moves from pending to verified without a filed log under
`results/logs/`. Card 19 is where the pending commands get run.

---

## Step 1 · Preflight — **verified**

Check the machine before installing anything:

```bash
python tools/poc_preflight.py             # Python, pandax package, Syft
python tools/poc_preflight.py --firmware  # also Docker CLI and daemon
python tools/poc_preflight.py --pdf       # also veraPDF
```

| Flag | Adds | Needed for |
|---|---|---|
| *(none)* | Python >= 3.10, `pandax` installed, Syft in `.tools/` or on PATH | every run |
| `--firmware` | Docker CLI on PATH, daemon reachable via `docker info` | firmware ingest (cards 03, 07, 19) |
| `--pdf` | veraPDF on PATH, or `--verapdf PATH` | PDF/A validation (cards 10, 13) |

`--verapdf PATH` names the executable explicitly instead of searching PATH.

Exit code is 0 only when every **requested** check passes, otherwise 1. An
optional tool you did not ask about is not a check and cannot fail the run — a
machine with no Docker passes a default run, because a default run does not use
Docker.

The checker is read-only. It never installs a tool, starts a service, runs a
scan or reads a signing key. Each probe is a version or status query that fails
after 10 seconds rather than hanging.

**Actual output**, macOS 15.2 / Python 3.14.3, 2026-09-10, on a clone that had
not been set up yet:

```
$ python3 tools/poc_preflight.py
PandaX PoC preflight

PASS  Python          3.14.3
FAIL  pandax package  not installed
                      -> install the engine:  uv sync
FAIL  Syft            not found in .tools/ or on PATH
                      -> run:  uv run python tools/bootstrap.py

2 of 3 checks failed.
$ echo $?
1
```

With `--firmware` on the same machine, Docker CLI was installed but the daemon
was not running:

```
FAIL  Docker          daemon unreachable (exited 1)
                      -> start Docker Desktop in Linux-container mode
```

That is the checker working. Two failing checks on an unbootstrapped clone is
the correct answer; step 2 is what fixes them.

### Tests

```bash
uv run pytest tools/test_poc_preflight.py
```

**Verified** — 21 passed (pytest 9.1.1, Python 3.14.3, 2026-09-10). Every
external tool is mocked, so the suite passes on a machine with neither Docker
nor veraPDF installed.

---

## Step 2 · Setup — **pending**

From `README.md`:

```bash
uv sync --extra dev
uv run python tools/bootstrap.py     # pinned, digest-verified downloads
```

`bootstrap.py` installs the pinned Syft into `.tools/`. Re-run the preflight
afterwards; all three default checks should pass.

Starting from an existing SBOM instead of an artifact skips Syft and the
bootstrap step entirely.

---

## Step 3 · First scan — **pending**

```bash
uv run pandax scan fixtures/smarthub-sh100-v2.3.1.zip
```

Or from an SBOM:

```bash
uv run pandax scan-sbom fixtures/example-sbom.cdx.json
```

`README.md` states the demo artifact should yield 11 components, ~102
vulnerabilities, 4 actively exploited, 4 Article 14 clocks and a sealed bundle
under `out/run-<timestamp>/`, and that the first run takes ~45s while the OSV
cache fills.

Treat those numbers as the repository's claim until a filed log shows them.
Recording what a run **observed** is the whole job here — see the coverage limits
in `evidence-index.md`.

---

## Step 4 · Proving it worked — **pending**

```bash
uv run pandax verdict                                       # blockers, clocks, actions
uv run pandax key export-public trusted-pandax-key.pem
uv run pandax verify --trusted-key trusted-pandax-key.pem   # integrity, signature, trust
uv run pandax tamper --target sbom.cdx.json                 # flips one byte
uv run pandax verify --trusted-key trusted-pandax-key.pem   # must now fail, naming S2_SBOM
uv run pandax clock --speed 1800                            # compressed 24h/72h/final
uv run pandax serve                                         # local dashboard
```

The tamper step is the one worth capturing: a seal that never fails proves
nothing.

Two commands belong to other owners and are needed for card 19:

- **Standalone verifier** (card 06, Guy) — `pandax-verify <bundle> --trusted-key <key>`,
  run from an environment without PandaX installed. `--inspect-only` checks
  integrity without claiming the signer is trusted; the two are not the same
  result and must not be recorded as if they were.
- **Whole-directory PDF validation** (card 13, Simon) — one command over a
  finished export. Not yet delivered; card 19 cannot complete without it.

---

## Capturing evidence

Naming, required contents and the simulated-artifact banner are defined in
`evidence-index.md`. In short:

```
results/logs/<card>__<subject>__<YYYY-MM-DD>.txt
results/screenshots/<card>__<subject>__<YYYY-MM-DD>.png
```

**Logs.** Capture the command and its output together, and keep it verbatim:

```bash
{ date -u +"%Y-%m-%dT%H:%M:%SZ"; pwd; echo "$ <command>"; <command> 2>&1; echo "exit: $?"; } \
  | tee results/logs/19__scan__$(date +%F).txt
```

A failing log is evidence that the check failed. Editing output to make a check
pass voids the card.

**Screenshots.** Capture the full window, including any status or mode banner. A
crop that removes a `SIMULATED` label fails the card no matter what it shows.

**What never gets committed.** No firmware images, credentials, keys or personal
data — see `firmware-intake.md`. Commit the record, not the artifact.

---

## When something fails

Report it to the card owner named in `checklist.md`. Operating the checklist is
not debugging: do not fix engine code, adjudicate a vulnerability or approve
security or legal correctness. If a run needs an image-specific fix, the owner
fixes it generally and Yaheli selects another unseen image for the final gate.
