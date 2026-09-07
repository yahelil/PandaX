# Public release comparison scenarios

Start the dashboard with `uv run pandax serve`, select a **Release comparison**,
and press **Run pipeline**. The four pairs and eight individual releases appear
even on a fresh checkout. Official artifacts download on demand and are checked
against committed SHA-256 digests before use. Run `uv run python tools/bootstrap.py`
once to install the pinned Syft scanner. Python 3.10+ is required.

The **Saved results** selector keeps previous comparisons accessible, including
failures. **Inspect run** opens either release's SBOM, findings, reports and seal.
Expand **Evidence / applicability** to see the vendor source and triage conditions.

## Independent answer key and actual comparison

- [Release-by-release PDF answer key](../output/pdf/PandaX_Independent_Expected_Results.pdf):
  plain-language CVE names, expected findings and exclusions, and an observation column.
- [Latest independent comparison report](../output/validation/PandaX_Comparison_Report.md):
  actual results, missed findings, triage limitations and links to individual run evidence.
- [CSV comparison](../output/validation/pandax-reference-comparison.csv) and
  [JSON evidence summary](../output/validation/pandax-reference-comparison.json).

The public-source expectations live in `docs/expected-results-baseline.json`,
separate from the scanner's matching rules and built-in scenario checks. The
PDF builder reads only this reference. It does not read scan output.

To repeat the comparison, pull the desired code, install its dependencies and
restart `pandax serve`, then run `python tools/evaluate_reference.py`. This uses
the dashboard HTTP API for all 14 reference inputs and four comparison actions.
Exit 1 means at least one independent check failed; raw errors remain in the
report. The engine itself is not modified by the evaluator. The reference is
a selected CVE test set, not a complete vulnerability census.

| Comparison / CLI id | Before → after | Input and expected result |
| --- | --- | --- |
| `openwrt-libubox` | 19.07.0 → 19.07.1 | Official x86/64 firmware rootfs; CVE-2020-7248 affected → fixed in the libubox/libblobmsg-json packages. |
| `curl-socks5` | 8.3.0 → 8.4.0 | Official curl source distribution, including the CLI and libcurl; CVE-2023-38545 affected → fixed. |
| `openwrt-dnsmasq` | 19.07.5 → 19.07.6 | Official rootfs: dnsmasq 2.80-16.1 → 2.80-16.2. CVE-2020-25684 and CVE-2020-25686 affected → fixed. Five vendor-excluded DNSSEC CVEs remain visibly excluded in both standard-package releases. |
| `openssl-heartbleed` | 1.0.1f → 1.0.1g | Official OpenSSL source distribution, including `apps/s_server.c` and libssl; CVE-2014-0160 affected → fixed. |

CLI equivalents:

```sh
uv run pandax compare list
uv run pandax compare openwrt-libubox
uv run pandax compare curl-socks5
uv run pandax compare openwrt-dnsmasq
uv run pandax compare openssl-heartbleed
```

A comparison exits 0 when its checks pass and 1 when they fail. The existing
`pandax scan` command retains exit 2 for a KEV hit. A comparison passing means
its specified expectations were met, not that either release is secure.

## What is measured

The downloaded archive, its extracted regular files, and their hashes are
recorded. For pinned archives, links are inventoried in `archive-links.json`
without creating or following them. Arbitrary archives retain the original
link-refusal policy. No archived program is executed.

Syft still produces the SBOM. An additional native adapter reads OpenWrt's
`usr/lib/opkg/status` (including full revision and dependency fields) and
curl/OpenSSL version headers and source files. The opkg adapter requires an
OpenWrt distro marker. The resulting CycloneDX dependencies show declared
consumers such as ubus, rpcd and uhttpd; these are not runtime call graphs.

OSV remains the existing feed for supported PURLs. `native-assessments.json`
adds a **bounded, vendor-advisory rule set for the requested native CVEs and
observed release versions**. This is not a general-purpose native vulnerability
feed or an independent scanner validation. Unknown native revisions remain
`unknown`. `findings.osv.json` contains OSV findings; `findings.matched.json`
combines both sources, and the VEX identifies the correct advisory source.
`verify --online` rechecks only OSV-origin findings.

The comparison oracle lives separately from matching. A missing component,
unknown revision, unexpected finding, broken seal, download error or scan error
fails the relevant checks. A failure on the first release does not prevent
attempting the second. Failed comparisons are also saved and sealed. Fixture
labels and expected outcomes are never inputs to native vulnerability matching.

Each release has a signed `release-checks.json`. A separate signed comparison
bundle records both input manifest hashes and individual CVE outcomes. The
underlying run directories are needed to independently recheck all source files;
copying only the comparison JSON does not copy those inputs.

## Applicability and limits

- **Firmware:** these are real vendor root filesystems in tar format, including
  binaries and package databases. Direct squashfs/UBIFS image extraction, booting
  firmware, and emulation are still unsupported.
- **curl/OpenSSL:** these fixtures inspect official **source releases**. They
  inventory the programs and their libraries but do not compile them, inspect a
  deployed process, or execute an exploit. Fix evidence combines identified
  component revisions with the vendor's fixed-release advisory.
- **curl:** record SOCKS5 remote DNS selection, proxy environment variables,
  hostname length, handshake timing, and buffer size. In the CLI, rate limiting
  below 65541 bytes/s can reduce the otherwise 100 KiB buffer. A matching version
  alone does not establish reachable heap overflow.
- **dnsmasq:** the official standard rootfs uses `dnsmasq`, not `dnsmasq-full`.
  The vendor excludes CVE-2020-25681/25682/25683/25685/25687 for the standard and
  dhcpv6 variants. These five rows are exclusions, not five demonstrated fixes.
  The adapter also handles `dnsmasq-full` metadata, but the bundled default
  firmware pair does not test a DNSSEC-enabled full-package deployment.
- **Heartbleed:** deployed build flags (including `OPENSSL_NO_HEARTBEATS`) and
  TLS/DTLS reachability require separate review. Source presence is insufficient
  for a deployment-level exploitability conclusion.
- No runtime reachability is inferred and no manufacturer compliance metadata
  is invented. Existing KEV triage policy remains unchanged.

## Sources and artifact pins

Catalog: `apps/engine/pandax/data/scenarios.json`. OpenWrt hashes match the
vendor's x86/64 release indexes. curl and OpenSSL archives were downloaded from
their official release endpoints and their exact retrieved bytes pinned.

- [OpenWrt libubox advisory](https://openwrt.org/advisory/2020-01-31-2)
- [curl SOCKS5 advisory](https://curl.se/docs/CVE-2023-38545.html)
- [OpenWrt dnsmasq advisory](https://openwrt.org/advisory/2021-01-19-1)
- [OpenSSL Heartbleed advisory](https://www.openssl.org/news/secadv/20140407.txt)
- [OpenWrt 19.07.0 artifacts](https://downloads.openwrt.org/releases/19.07.0/targets/x86/64/)
- [OpenWrt 19.07.1 artifacts](https://downloads.openwrt.org/releases/19.07.1/targets/x86/64/)
- [OpenWrt 19.07.5 artifacts](https://downloads.openwrt.org/releases/19.07.5/targets/x86/64/)
- [OpenWrt 19.07.6 artifacts](https://downloads.openwrt.org/releases/19.07.6/targets/x86/64/)
