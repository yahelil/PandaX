# Public release comparison scenarios

Start the dashboard with `uv run actis serve`, select a **Release comparison**,
and press **Run pipeline**. The five pairs and ten individual releases appear
even on a fresh checkout. Official artifacts download on demand and are checked
against committed SHA-256 digests before use. Run `uv run python tools/bootstrap.py`
once to install the pinned Syft scanner. Python 3.10+ is required.

The **Saved results** selector keeps previous comparisons accessible, including
failures. **Inspect run** opens either release's SBOM, findings, reports and seal.
Expand **Evidence / applicability** to see the vendor source and triage conditions.

## Independent answer key and actual comparison

- [Release-by-release PDF answer key](published/pdf/PandaX_Independent_Expected_Results.pdf):
  plain-language CVE names, expected findings and exclusions, and an observation column.
- [Latest independent comparison report](published/validation/PandaX_Comparison_Report.md):
  actual results, missed findings, triage limitations and links to individual run evidence.
- [CSV comparison](published/validation/pandax-reference-comparison.csv) and
  [JSON evidence summary](published/validation/pandax-reference-comparison.json).

The public-source expectations live in `docs/expected-results-baseline.json`,
separate from the scanner's matching rules and built-in scenario checks. The
PDF builder reads only this reference. It does not read scan output.

To repeat the comparison, pull the desired code, install its dependencies and
restart `actis serve`, then run `python tools/evaluate_reference.py`. This uses
the dashboard HTTP API for all 14 reference inputs and four comparison actions.
Exit 1 means at least one independent check failed; raw errors remain in the
report. The engine itself is not modified by the evaluator. The reference is
a selected CVE test set, not a complete vulnerability census.
Fresh reports are saved under `workspace/generated/validation/`; the links above
point to the committed snapshot until selected files are published again.

| Comparison / CLI id | Before → after | Input and expected result |
| --- | --- | --- |
| `tomcat-partial-put` | 9.0.98 → 9.0.99 | Official Apache Tomcat server binaries; CVE-2025-24813 affected → vendor-patched. Requires Catalina's exact Maven identity and revision in the scanned SBOM. |
| `openwrt-libubox` | 19.07.0 → 19.07.1 | Official x86/64 firmware rootfs; CVE-2020-7248 affected → fixed in the libubox/libblobmsg-json packages. |
| `curl-socks5` | 8.3.0 → 8.4.0 | Official curl source distribution, including the CLI and libcurl; CVE-2023-38545 affected → fixed. |
| `openwrt-dnsmasq` | 19.07.5 → 19.07.6 | Official rootfs: dnsmasq 2.80-16.1 → 2.80-16.2. CVE-2020-25684 and CVE-2020-25686 affected → fixed. Five vendor-excluded DNSSEC CVEs remain visibly excluded in both standard-package releases. |
| `openssl-heartbleed` | 1.0.1f → 1.0.1g | Official OpenSSL source distribution, including `apps/s_server.c` and libssl; CVE-2014-0160 affected → fixed. |

CLI equivalents:

```sh
uv run actis compare list
uv run actis compare tomcat-partial-put
uv run actis compare openwrt-libubox
uv run actis compare curl-socks5
uv run actis compare openwrt-dnsmasq
uv run actis compare openssl-heartbleed
```

A comparison exits 0 when its checks pass and 1 when they fail. The existing
`actis scan` command retains exit 2 for a KEV hit. A comparison passing means
its specified expectations were met, not that either release is secure.

## Real application example: Tomcat file uploads

Choose **Apache Tomcat — file upload / session RCE — 9.0.98 → 9.0.99** in the
dashboard's product artifact selector, then run the pipeline. The two release
runs and signed comparison become available under **Selected run**. The comparison's
**Inspect run** buttons open each release's full inventory and findings.

This uses Apache's complete binary distributions, including Catalina, Jasper,
connectors, configuration and example webapps. A realistic deployment is a Java
web application accepting file uploads and persisting sessions on disk.
The vulnerable version is 9.0.98; 9.0.99 is Apache's first 9.x release containing
the [CVE-2025-24813 fix](https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.99).
The [actual upstream patch](https://github.com/apache/tomcat/commit/eb61aade8f8daccaecabf07d428b877975622f72)
replaces path-derived temporary filenames with generated names and deletes the
temporary file after request processing.

The answer key requires OSV to report the CVE for the identified
`pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.98` and to omit it for the
identified `@9.0.99`. Missing, wrong or mixed component revisions fail the check;
an empty inventory cannot pass. Scenario expectations never add or suppress
scanner findings. Other CVEs may remain on both releases.

Syft 1.51.1 gives the bundled Catalina JAR an OSGi-derived coordinate that OSV
does not recognize. PandaX resolves these two exact binaries using SHA-256 pins
in `data/package-identities.json`, independently of the scenario answer key.
Both were byte-for-byte identical to the corresponding Maven Central JARs.
The unmodified scanner output is retained as `sbom.syft.json`; the normalized
component records its original PURL, verified hash and publisher URL. Unknown
binaries keep Syft's identity. Other Tomcat libraries may have the same unresolved
identity problem, so this pair does not establish complete Tomcat CVE coverage.

Verified on 2026-09-08 with Syft 1.51.1 and live OSV: 39 components in each
release; 31 → 30 findings and 1 → 0 KEV findings. The target CVE was present only
in 9.0.98. Both release seals and the comparison seal passed verification.
Feed totals can change; the regression expectation concerns this specific CVE.

RCE additionally depends on writable Default Servlet, partial PUT, file-backed
sessions and an application library usable for deserialization. Default Servlet
writes are disabled by default. These archives are inventoried, not launched;
the comparison does not establish runtime exploitability. The patch URL and
vendor advisory are retained in each signed release check.

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
Tomcat archives were also verified against Apache's published `.tar.gz.sha512`
files before their SHA-256 pins were committed.

- [OpenWrt libubox advisory](https://openwrt.org/advisory/2020-01-31-2)
- [curl SOCKS5 advisory](https://curl.se/docs/CVE-2023-38545.html)
- [OpenWrt dnsmasq advisory](https://openwrt.org/advisory/2021-01-19-1)
- [OpenSSL Heartbleed advisory](https://www.openssl.org/news/secadv/20140407.txt)
- [OpenWrt 19.07.0 artifacts](https://downloads.openwrt.org/releases/19.07.0/targets/x86/64/)
- [OpenWrt 19.07.1 artifacts](https://downloads.openwrt.org/releases/19.07.1/targets/x86/64/)
- [OpenWrt 19.07.5 artifacts](https://downloads.openwrt.org/releases/19.07.5/targets/x86/64/)
- [OpenWrt 19.07.6 artifacts](https://downloads.openwrt.org/releases/19.07.6/targets/x86/64/)

## Developer handoff package

[Developer review ZIP](published/share/PandaX_Developer_Review_2026-09-07.zip) contains an offline per-input index, the independent answer-key PDF, an observed-results PDF, all 76 reference checks, all 407 reported finding rows, the seven misses, raw API evidence, and output artifacts from 26 scan/comparison bundles. Vendor input/extracted trees are omitted; included output hashes and original manifest signatures were verified. See the ZIP's START_HERE.md for scope and reproduction instructions.

[Root-cause investigation](published/validation/PandaX_Root_Cause_Report.md) traces the misses to exact-identity OSV query coverage and missing native rules. Fresh diagnostic probes also expose conflicting OSV data for the vendor-fixed curl 8.4.0 control. This handoff does not modify scanner rules or the independent baseline.
