# PandaX: independent reference vs actual results

Tested GitHub revision **`d7f7890`**, after pulling `origin/main` and restarting the dashboard at `http://127.0.0.1:8000`. Tests used its HTTP scan, SBOM-upload, event-stream, summary and seal-verification endpoints. This is a test of the freshly pulled local dashboard, not a separately verified hosted deployment.

Run: **20260907T122801Z** to **2026-09-07T12:29:49.044175+00:00**.

**69/76 named checks match; 7 expected findings are missing.** All 14/14 input scans completed, with 14 verified seals. The four built-in comparison actions also completed and passed.

Positive checks: **35/42 found**. Negative checks: **34/34 correctly absent**. These figures measure only the independent reference's selected CVEs, not overall scanner accuracy or complete release security.

The expected values were frozen before execution. No scanner rules were changed to make these checks pass. The answer key remains independent; this report contains the observed results.

## Missing findings

| Input | PDF expects | PandaX result | Public evidence |
|---|---|---|---|
| curl / libcurl 8.3.0 | CVE-2023-38546 - Cookie injection via duplicated handle | Missing; correct libcurl version was inventoried | [Advisory](https://curl.se/docs/CVE-2023-38546.html) |
| curl / libcurl 8.3.0 | CVE-2023-46218 - Mixed-case cookie PSL bypass | Missing; correct libcurl version was inventoried | [Advisory](https://curl.se/docs/CVE-2023-46218.html) |
| curl / libcurl 8.4.0 | CVE-2023-46218 - Mixed-case cookie PSL bypass | Missing; correct libcurl version was inventoried | [Advisory](https://curl.se/docs/CVE-2023-46218.html) |
| OpenSSL 1.0.1f / s_server | CVE-2014-0224 - CCS man-in-the-middle weakness | Missing; correct libssl version was inventoried | [Advisory](https://openssl-library.org/news/secadv/20140605.txt) |
| OpenSSL 1.0.1f / s_server | CVE-2014-0195 - DTLS fragment buffer overflow | Missing; correct libssl version was inventoried | [Advisory](https://openssl-library.org/news/secadv/20140605.txt) |
| OpenSSL 1.0.1g / s_server | CVE-2014-0224 - CCS man-in-the-middle weakness | Missing; correct libssl version was inventoried | [Advisory](https://openssl-library.org/news/secadv/20140605.txt) |
| OpenSSL 1.0.1g / s_server | CVE-2014-0195 - DTLS fragment buffer overflow | Missing; correct libssl version was inventoried | [Advisory](https://openssl-library.org/news/secadv/20140605.txt) |

The current native supplement covers CVE-2023-38545 for libcurl and CVE-2014-0160 for libssl. It does not cover the additional reference CVEs above, and the live OSV results did not fill the gap. The built-in comparisons test those narrow demo CVEs, so their PASS result can coexist with these missed findings.

## Every tested input

| Input | Positive checks found | Negative checks correct | Total reported finding rows | Named-check result |
|---|---:|---:|---:|---|
| OpenWrt 19.07.0 | 3/3 | 5/5 | 4 | MATCH |
| OpenWrt 19.07.1 | 2/2 | 6/6 | 2 | MATCH |
| OpenWrt 19.07.5 | 2/2 | 6/6 | 2 | MATCH |
| OpenWrt 19.07.6 | 0/0 | 8/8 | 0 | MATCH |
| curl / libcurl 8.3.0 | 1/3 | 1/1 | 1 | DIFFERENCES |
| curl / libcurl 8.4.0 | 0/1 | 3/3 | 0 | DIFFERENCES |
| OpenSSL 1.0.1f / s_server | 1/3 | 0/0 | 1 | DIFFERENCES |
| OpenSSL 1.0.1g / s_server | 0/2 | 1/1 | 0 | DIFFERENCES |
| SmartHub 2.3.1 / directory | 10/10 | 0/0 | 102 | MATCH |
| SmartHub 2.3.1 / zip | 10/10 | 0/0 | 102 | MATCH |
| Struts 2.5.12 / full libraries | 3/3 | 0/0 | 160 | MATCH |
| Struts 2.5.12 / min libraries | 2/2 | 1/1 | 22 | MATCH |
| Struts 2.5.33 / min libraries | 0/0 | 3/3 | 9 | MATCH |
| Example web application 1.0.0 / SBOM | 1/1 | 0/0 | 2 | MATCH |

A dashboard finding row is a component/CVE pair; the reference counts named CVE checks. For example, OpenWrt 19.07.0 reports four rows covering three unique CVEs because the libubox issue is attached to both libubox and libblobmsg-json. That is not an extra independent CVE. Additional findings outside the reference are retained in the JSON report and are **ungraded**, not assumed false positives.

## Triage and evidence differences

1. **Pillow / WebP exposure is not established.** Both SmartHub inputs report CVE-2023-4863 on Pillow and set VEX state `exploitable` from KEV membership. The input has a Pillow dependency declaration, but the observed inventory does not establish an installed libwebp build. The reference requires wheel/native-library evidence. This is unsupported exposure certainty, not proof that the CVE is a false positive. [Pillow maintainer notes](https://pillow.readthedocs.io/en/stable/releasenotes/10.0.1.html).

2. **The VEX label and reachability explanation differ.** OpenSSL 1.0.1f receives VEX state `exploitable` for Heartbleed from KEV membership, while the same entry explicitly says build flags and runtime reachability remain unknown. The component-level match is supported; deployed exploitability is not established by this source scan. [OpenSSL advisory](https://openssl-library.org/news/secadv/20140407.txt).

3. **Absence is not always explicit fix evidence.** The named negative checks are absent as expected. However, curl CVE-2023-38546 on 8.4.0 and CVE-2023-38039 on both releases have no corresponding native assessment. Their absence alone does not show PandaX knew the fix boundary. The primary demo CVEs do have explicit fixed assessments. [curl cookie advisory](https://curl.se/docs/CVE-2023-38546.html), [curl header advisory](https://curl.se/docs/CVE-2023-38039.html).

4. **The new SBOM sample behaves correctly for missing identity.** It retains both jQuery 3.4.0 and internal-device-agent 1.0.0, finds the named jQuery CVE, and records one component as not scanned because the internal component lacks a versioned PURL. Its zero finding count must not be interpreted as a clean security assessment.

The ten named SmartHub positive checks were detected in both directory and ZIP scans, with the expected historical fix versions. All selected inventory checks were present. No exploit or runtime application test was performed.

## Built-in comparison actions

| Action | Actual built-in verdict | Evidence |
|---|---|---|
| openwrt-libubox | PASS | [Dashboard response](http://127.0.0.1:8000/api/run/run-20260907-152932-039998-51715e/summary) |
| curl-socks5 | PASS | [Dashboard response](http://127.0.0.1:8000/api/run/run-20260907-152938-723530-3988ea/summary) |
| openwrt-dnsmasq | PASS | [Dashboard response](http://127.0.0.1:8000/api/run/run-20260907-152944-056644-4a1570/summary) |
| openssl-heartbleed | PASS | [Dashboard response](http://127.0.0.1:8000/api/run/run-20260907-152949-026762-232ccb/summary) |

## Reproduce or inspect

- [Independent answer key](../pdf/PandaX_Independent_Expected_Results.pdf)
- [Every expected/observed CVE row (CSV)](pandax-reference-comparison.csv)
- [Machine-readable results, VEX states and run IDs](pandax-reference-comparison.json)
- [Public-source baseline](../../docs/expected-results-baseline.json)

Start the dashboard from the desired GitHub revision, then run `python tools/evaluate_reference.py`. The evaluator exits 1 when named checks fail; this run intentionally exited 1 for the seven misses. A KEV warning by itself is not treated as an execution failure.

Raw API summaries, event streams and verification responses remain locally under `out/reference-validation/20260907T122801Z`; signed pipeline bundles remain in `out/run-*`. The JSON/CSV report is committed, while bulky raw scan artifacts remain local.

Frozen baseline SHA-256: `350ecb90a9201358d5bbcf8778df8a0893c59753c67c3e57286b28b1c92b5fe9`.
Tested PDF SHA-256: `a1509425fba5ca3cbbf423f81287e7f933c0295f4fe7e645bff189e2ed1f07d1`.

## Software checks

The pulled repository suite passed: **90 tests**, with two dependency deprecation warnings. The independent comparator passed **6 focused tests** for missed findings, false positives, missing inventory, failed runs and component identity. These passing software tests do not erase the seven live reference mismatches.
