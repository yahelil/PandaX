# Firmware regression fixtures (card 07 / #60)

The fixture pins and independent oracles live in
`fixtures/firmware/manifest.json`. The OpenWrt fixture is the official generic
x86/64 device's SquashFS rootfs image, not a combined boot disk. Its 150-package
oracle combines the separately published 127-package target manifest with the
23 generic-device packages and dependencies. Device additions were derived from
`profiles.json` and the target/base `Packages.manifest` files, not PandaX output.
All source URLs and digests are pinned in the fixture manifest; image, target
manifest, profile and target package-index hashes match official `sha256sums`.
UBIFS uses ONEKEY's release-pinned
`banana.ubifs`, with all four file hashes taken from upstream Git LFS pointers.
Expected inventory is never generated from PandaX output.

## Reproduce from a fresh checkout

Run at the repository root with Python 3.10+ and Docker running Linux containers:

```sh
python -m venv .venv
# Activate .venv (Windows: .venv\Scripts\Activate.ps1; Linux: source .venv/bin/activate)
python -m pip install -e ".[dev]"
python -c "from tools.bootstrap import install_syft; install_syft()"
docker pull ghcr.io/onekey-sec/unblob@sha256:0779adc4fc7751c601eaaa2eaae1ad04279a8afadecb36af4315752b72f5e2f9
```

PowerShell:

```powershell
$env:PANDAX_FIRMWARE_INTEGRATION = '1'
$env:PANDAX_FIRMWARE_CACHE = "$PWD/.cache/firmware-fresh"
python -m pytest apps/engine/tests/test_firmware_integration.py apps/engine/tests/test_firmware_fixtures.py apps/engine/tests/test_firmware.py apps/engine/tests/test_ingest.py -q --basetemp .cache/firmware-check --junitxml=.cache/firmware-check.xml
```

Linux/macOS use the same pytest arguments prefixed with
`PANDAX_FIRMWARE_INTEGRATION=1 PANDAX_FIRMWARE_CACHE="$PWD/.cache/firmware-fresh"`.
Use a previously unused cache directory to exercise fresh downloads. Successful
downloads are SHA256-checked before caching; cached bytes are rechecked on every
use. The 64 MiB download ceiling covers these fixtures. No firmware binaries or
generated SBOMs belong in Git. Network is needed for setup/downloads, but the
extraction containers remain offline and no firmware is executed.

The production extraction defaults still apply; see `firmware-ingestion.md`
for Docker RAM and host disk requirements. Deliberately low-limit tests override
only their own job. Explicit integration opt-in fails when Docker/image/Syft is
missing; default test runs skip the real-container module.

## Acceptance matrix

| Case | Check | Evidence level |
| --- | --- | --- |
| OpenWrt SquashFS | S1 ingestion -> real Syft -> native enrichment -> CycloneDX 1.6; exact 150-package oracle, file/source hashes, evidence ledger links | Real downloaded image and tools |
| UBIFS success | Exact file set, all four SHA256 values, 32 extracted bytes | Real upstream image/container |
| Output quota | UBIFS 4 KiB / OpenWrt 1 MiB fail without publishing root | Real kernel tmpfs quotas |
| File-entry quota | UBIFS with two-entry ceiling fails without publishing root | Real kernel inode quota |
| Unknown/truncated/partial | Unknown bytes, truncated UBIFS, UBIFS with unknown prefix never publish inventory | Real input bytes; Docker where format gate accepts input |
| Encrypted | Worker encryption report selects `encrypted`; host stops ingestion | Deterministic report/transport tests; no claim of real encrypted-firmware decryption/detection coverage |
| Real timeout | One-second limit stops extraction; the exact job container is gone | Real Docker process and cleanup |
| Docker absent/failing, timeout, OOM | Actionable error; container cleanup attempted; no successful inventory | Deterministic subprocess tests |
| Paths/links | Traversal, Windows aliases, case collisions, links refused | Deterministic transport tests |
| Limits/provenance | Input size, output bytes/files, disk space, source changes, missing/mismatched reports | Deterministic boundary tests |
| ZIP/TAR | Existing extraction/safety tests and no Docker fallback | Real small generated archives |
| Fixture integrity | Corrupt cache re-fetched; wrong digest, oversized and interrupted downloads never cached | Offline downloader tests |

Existing safety tests are reused in `test_firmware.py` and `test_ingest.py`.
The only production correction moves empty-destination removal inside the existing
bounded Windows publication retry. Transient and persistent locks on both removal
and rename are covered. Advisory rules are unchanged. Public fixtures are
regression inputs only; final unseen-image acceptance remains a separate gate.

## Validation record — 2026-09-10

Base: GitHub `main` at `133a5ec`; branch: `simon-firmware-fixtures`.
No published GitHub release existed when the base was fetched.
Windows 11, Python 3.12.10, Docker Linux Engine 29.7.2, unblob 26.6.4 (pinned
image), Syft 1.51.1 (installed with the digest-verifying bootstrap helper).

A new dependency-only virtual environment was created in
`.cache/card07-clean-env`. The engine was loaded via `PYTHONPATH=apps/engine`;
this permits the standalone verifier test to replace PYTHONPATH and prove that
it works without the engine. An editable engine installation in the original
virtual environment had violated that existing test's isolation assumption;
no verifier code was changed.

With `PANDAX_FIRMWARE_INTEGRATION=1`, a previously empty fixture cache and all
bootstrap prerequisites installed, the complete repository command
`python -m pytest -q --tb=short` passed **304 tests, no skips or deselections**.
This includes all ten real network end-to-end tests and nine firmware
integration cases. Two existing FastAPI/Starlette deprecation warnings remain.
Local machine-readable results: `.cache/card07-full.xml`.

The OpenWrt run extracted **1,069 files / 13,483,094 bytes**, matched all
**150 native packages** exactly, and produced a CycloneDX 1.6 SBOM with 218
components after Syft and native enrichment. Every extracted-file hash and the
S1 -> S2 ledger references were checked. UBIFS matched all four independent
hashes and 32 bytes. Tiny byte/inode quotas, truncated/unknown/partial inputs,
and a real timeout failed without publishing an extracted root.

Initial real testing exposed a Windows empty-directory removal outside the
publication retry and an incomplete target-only inventory oracle. Both were
corrected before the successful full run; inventory expectations were expanded
only after independent upstream profile/dependency validation.

A final warm-cache firmware/download/archive safety pass, including two added
download-failure checks, passed **87 tests** in 57.52 seconds, with no skips.
Results are recorded in `.cache/card07-warm.xml`.
Public regression success does not replace final unseen-image acceptance.
