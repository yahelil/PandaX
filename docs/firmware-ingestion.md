# Firmware ingestion (card 03 / #26)

Branch: `simon-firmware`, based on `main`. CLI/server files and
`docs/poc-acceptance/` are deliberately untouched to avoid overlap with cards
01, 02, and 04. No new host Python dependencies are needed.

## Setup and use

Install Docker Desktop on Windows and select Linux containers (or use Docker
Engine on Linux). Pull this exact official unblob 26.6.4 image once:

```sh
docker pull ghcr.io/onekey-sec/unblob@sha256:0779adc4fc7751c601eaaa2eaae1ad04279a8afadecb36af4315752b72f5e2f9
actis scan /path/to/firmware.bin
```

The existing `/api/scan` accepts `{"artifact": "/absolute/path/to/firmware.bin"}`
(use escaped backslashes or forward slashes for Windows paths). The dashboard
artifact dropdown is unchanged; new firmware suffixes are not listed there.
The image is not pulled implicitly during scanning. Extraction itself has no
network access, so setup requires connectivity but firmware jobs do not.

## Change limits without changing code

Set environment variables before starting the CLI or dashboard process. They
are read for every firmware extraction. Values must be positive integers:

| Variable | Default | Meaning |
| --- | ---: | --- |
| `PANDAX_FIRMWARE_MAX_INPUT_BYTES` | 1073741824 | 1 GiB original image |
| `PANDAX_FIRMWARE_MAX_OUTPUT_BYTES` | 10737418240 | 10 GiB extraction working space |
| `PANDAX_FIRMWARE_MAX_FILES` | 100000 | Working filesystem entry ceiling |
| `PANDAX_FIRMWARE_TIMEOUT_SECONDS` | 600 | Entire container job, including output transfer |

PowerShell example:

```powershell
$env:PANDAX_FIRMWARE_MAX_OUTPUT_BYTES = '21474836480'
$env:PANDAX_FIRMWARE_MAX_FILES = '200000'
actis scan 'C:/firmware/device.bin'
```

ZIP/TAR keep their existing 512 MiB / 20,000-entry / depth-24 rules. Firmware
uses a Linux tmpfs with a hard size and inode ceiling while extraction runs.
The working-space limit includes intermediate unblob files and filesystem
overhead; the inode ceiling includes directories and links as well as files.
These intentionally conservative bounds can trigger before the final inventory
reaches the nominal limit. The adapter also checks transferred bytes/files.
Both `/work` and the fixed 64 MiB `/tmp` are checked after extraction, requiring
more than max(4 MiB, 1%) free bytes and max(1, 1%) free inodes. Carved inputs
are retained so their cleanup cannot hide working-space exhaustion. The pinned
UBI/UBIFS commands run through a Python wrapper that turns reported ENOSPC into
failure even when ubireader exits zero. These checks reject known truncation
modes; free-space margins are not a proof against every possible extractor bug.

The container memory cap is the output limit plus 512 MiB, with swap disabled.
This is a cap, not a reservation: small images do not require 10.5 GiB RAM.
Approaching the default 10 GiB tmpfs ceiling does require roughly 10.5 GiB of
available Docker VM RAM; lower the output limit on smaller machines. Exit 137
reports a possible memory kill with actionable guidance. Maximum-size images
have not been validated on this machine.

Host disk must have room for both the transport TAR and extracted files. A
preflight requires twice the output ceiling plus TAR/diagnostic overhead
(about 20.4 GiB at defaults). Concurrent jobs can still exhaust disk after this
check; write errors stop inventory. Temporary cleanup is best effort, so a
Windows file lock may leave `.firmware-*` scratch files to remove later.

## Contract and evidence

`ingest.extract(src, dest)` still returns `(file_count, uncompressed_bytes)`.
Firmware output is normalized to one root at `run/extracted/`, so existing Syft
and native inventory receive `etc/` and `usr/` at the paths they already expect.
Root selection uses unblob's filesystem chunk and extraction-task reports.
Multiple filesystem chunks are unsupported, even if only one looks relevant.
Before Docker starts, a bounded signature scan accepts embedded SquashFS/UBI/
UBIFS or gzip, bzip2, xz, zstd, and common LZMA headers. This only identifies
candidates; unblob validates the format and root. Unrecognized proprietary
wrappers are unsupported. ZIP/TAR continue using their existing extraction path.

Firmware produces `firmware-extraction.json`, `unblob-report.json`, and
`firmware-extraction.log`. Successful ingestion links all three into the
existing evidence ledger, adds unblob's version to tool versions, and retains
the existing original-input and extracted-file hashing. The status report
records the pinned container digest, source digest, limits, handler, selected
root, and links. Link metadata is retained, but links are never created or
followed on the host; inventory covers regular-file contents. Files with names
that cannot be represented safely on Windows are refused on all hosts,
including colon/backslash names and reserved devices. Absolute or escaping
symlinks and special files (devices, FIFOs, sockets) make the filesystem
unsupported. Empty directories and executable bits are not transferred;
hardlinks become independent regular files and count against the byte ceiling.
Handler, root and link metadata are assertions from the sandboxed extractor;
the host independently verifies source and transferred-file hashes and totals.
Problem/unknown-region examples are capped at 100 with full counts. Oversized
JSON diagnostics cause an explicit failure instead of a successful inventory.

Only `completed` results reach inventory. Detected encryption, extraction
warnings/errors, unknown regions outside the root, recursion truncation, unsafe
paths, multiple roots, and empty roots stop the scan. Unknown formats remain
`unsupported`; absence of recognizable data does not prove encryption.
Firmware is never booted or executed. Input and worker mounts are read-only;
the container root is read-only, its network and capabilities are disabled, and
extraction space is `noexec`. Host output is validated before publishing the
root. A timeout removes the container, not just the Docker client.
Publishing retries transient Windows file locks for at most 1.5 seconds;
persistent permission errors still fail without publishing a root.

Failed jobs retain a status/reason and available diagnostics; a process crash,
timeout, or resource exhaustion may prevent unblob from finishing its JSON
report. They do not produce a sealed successful scan. Container scratch space is removed; temporary host cleanup is best effort. This is a local PoC, not a claim of
complete filesystem or vulnerability coverage.

## Checks

```sh
python -m pytest apps/engine/tests/test_ingest.py apps/engine/tests/test_scenarios.py apps/engine/tests/test_firmware.py -q
```

Real tests require Docker and the pinned image above. Explicitly opting in
fails if prerequisites are missing; the default suite skips these tests:

```powershell
$env:PANDAX_FIRMWARE_INTEGRATION = '1'
python -m pytest apps/engine/tests/test_firmware_integration.py -q
```

On Linux use `PANDAX_FIRMWARE_INTEGRATION=1 python -m pytest
apps/engine/tests/test_firmware_integration.py -q` on one line.

The pinned public fixtures are downloaded into ignored `.cache/firmware/`:

- OpenWrt 23.05.5 x86/64 SquashFS rootfs firmware image, SHA-256
  `478601ab0f5176372e6e0079614240dd25049c74167572ca9bc1b91e9261fe17`.
  Inventory expectations come from its independent official package manifest
  (busybox `1.36.1-1`, dnsmasq `2.90-2`).
- ONEKEY unblob 26.6.4 `banana.ubifs`, SHA-256
  `87b05f653d717736b766a9cca10b75656cc14c1d9442c61fdc514cc275a8a634`.
  Verify its four regular files and upstream expected content hashes.
- Repeat UBIFS with a 4 KiB and OpenWrt with a 1 MiB working-space ceiling; both must fail
  without publishing an extracted root.

No firmware binaries are committed and no unseen acceptance image is selected.
Container integration passing is required before marking the Trello card Done.

## Recorded validation â€” 2026-09-08

Windows 11, Docker Desktop 4.90.0 / Linux Engine 29.7.2, pinned unblob 26.6.4:
`PANDAX_FIRMWARE_INTEGRATION=1 python -m pytest -m 'not slow' -q` passed
**164 tests**, including all four real-container cases. The ten pre-existing
`slow` tests were excluded. Both fixture download digests were verified.
No PandaX extraction containers remained running after the suite.

References: [Docker tmpfs limits](https://docs.docker.com/engine/storage/tmpfs/),
[unblob 26.6.4](https://github.com/onekey-sec/unblob/tree/26.6.4),
[OpenWrt checksums](https://downloads.openwrt.org/releases/23.05.5/targets/x86/64/sha256sums),
[OpenWrt package manifest](https://downloads.openwrt.org/releases/23.05.5/targets/x86/64/openwrt-23.05.5-x86-64.manifest).


## QA corrections — 2026-09-09

Accepted Opus review findings: candidate gating without rejecting the tested
gzip wrapper, deprecated Windows-name API removal, explicit memory/disk
requirements and disk preflight, both scratch filesystems checked with margins,
retained carved chunks, UBIFS ENOSPC propagation, bounded report diagnostics,
consistent unsupported statuses, and regression checks on the trust boundary.
Cleanup errors no longer mask the original container failure; failed reports
have zero published-file totals.

A transport read failure still fails the job and preserves stderr; a partially
written TAR cannot safely be repaired by appending a new status member. The
host records failure and never publishes that root. No canary-file heuristic
was added: a surviving canary cannot prove all extracted files are complete.
The existing `.cache/` ignore entry was verified. CLI/server and assignments
01/02/04 remain untouched by these corrections.

Correction validation: **232 passed, 10 pre-existing slow tests excluded**, with
`PANDAX_FIRMWARE_INTEGRATION=1 python -m pytest -m "not slow" -q`. All four
real-container tests passed. The UBIFS quota raw report confirms the wrapper
returned exit 1 for an original exit-zero ENOSPC diagnostic.

Opus 5 correction re-review was attempted but returned a session-limit error
before model execution (reset reported 13:50 Asia/Jerusalem on September 9).
A clean independent correction verdict is pending; no pass is claimed.
