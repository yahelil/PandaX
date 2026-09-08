# Firmware ingestion (card 03 / #26)

Branch: `simon-firmware`, based on `main`. CLI/server files and
`docs/poc-acceptance/` are deliberately untouched to avoid overlap with cards
01, 02, and 04. No new host Python dependencies are needed.

## Setup and use

Install Docker Desktop on Windows and select Linux containers (or use Docker
Engine on Linux). Pull this exact official unblob 26.6.4 image once:

```sh
docker pull ghcr.io/onekey-sec/unblob@sha256:0779adc4fc7751c601eaaa2eaae1ad04279a8afadecb36af4315752b72f5e2f9
pandax scan /path/to/firmware.bin
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
pandax scan 'C:/firmware/device.bin'
```

ZIP/TAR keep their existing 512 MiB / 20,000-entry / depth-24 rules. Firmware
uses a Linux tmpfs with a hard size and inode ceiling while extraction runs.
The working-space limit includes intermediate unblob files and filesystem
overhead; the inode ceiling includes directories and links as well as files.
These intentionally conservative bounds can trigger before the final inventory
reaches the nominal limit. The adapter also checks transferred bytes/files.
Docker needs sufficient available memory/swap for the job; the container's
memory cap is the output limit plus 512 MiB (a cap, not a reservation).

## Contract and evidence

`ingest.extract(src, dest)` still returns `(file_count, uncompressed_bytes)`.
Firmware output is normalized to one root at `run/extracted/`, so existing Syft
and native inventory receive `etc/` and `usr/` at the paths they already expect.
Root selection uses unblob's filesystem chunk and extraction-task reports.
Multiple filesystem chunks are unsupported, even if only one looks relevant.

Firmware produces `firmware-extraction.json`, `unblob-report.json`, and
`firmware-extraction.log`. Successful ingestion links all three into the
existing evidence ledger, adds unblob's version to tool versions, and retains
the existing original-input and extracted-file hashing. The status report
records the pinned container digest, source digest, limits, handler, selected
root, and links. Link metadata is retained, but links are never created or
followed on the host; inventory covers regular-file contents. Files with names
that cannot be represented safely on Windows are refused on all hosts.

Only `completed` results reach inventory. Detected encryption, extraction
warnings/errors, unknown regions outside the root, recursion truncation, unsafe
paths, multiple roots, and empty roots stop the scan. Unknown formats remain
`unsupported`; absence of recognizable data does not prove encryption.
Firmware is never booted or executed. Input and worker mounts are read-only;
the container root is read-only, its network and capabilities are disabled, and
extraction space is `noexec`. Host output is validated before publishing the
root. A timeout removes the container, not just the Docker client.

Failed jobs retain a status/reason and available diagnostics; a process crash,
timeout, or resource exhaustion may prevent unblob from finishing its JSON
report. They do not produce a sealed successful scan. Temporary host files and
container scratch space are removed. This is a local PoC, not a claim of
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
- Repeat UBIFS extraction with an 8 KiB working-space ceiling; it must fail
  without publishing an extracted root.

No firmware binaries are committed and no unseen acceptance image is selected.
Container integration passing is required before marking the Trello card Done.

References: [Docker tmpfs limits](https://docs.docker.com/engine/storage/tmpfs/),
[unblob 26.6.4](https://github.com/onekey-sec/unblob/tree/26.6.4),
[OpenWrt checksums](https://downloads.openwrt.org/releases/23.05.5/targets/x86/64/sha256sums),
[OpenWrt package manifest](https://downloads.openwrt.org/releases/23.05.5/targets/x86/64/openwrt-23.05.5-x86-64.manifest).
