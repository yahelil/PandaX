# PandaX: independent reference vs actual results

Tested the working tree based on **`fdab758`**, after pulling `origin/main` and restarting the dashboard at `http://127.0.0.1:8000`. Tests used its HTTP scan, SBOM-upload, event-stream, summary and seal-verification endpoints. This is a test of the freshly pulled local dashboard, not a separately verified hosted deployment.

Run: **20260909T140653Z** to **2026-09-09T14:22:22.537713+00:00**.

**76/76 named checks match; 0 expected findings are missing.** All 14/14 input scans completed and passed integrity and bundled-signature verification. External signer trust was not configured for this benchmark, so none is described as trusted. The four built-in comparison actions also completed and passed.

Positive checks: **42/42 found**. Negative checks: **34/34 correctly absent**. These figures measure only the independent reference's selected CVEs, not overall scanner accuracy or complete release security.

The expected values were frozen before execution. No scanner rules were changed to make these checks pass. The answer key remains independent; this report contains the observed results.

## Missing findings

| Input | PDF expects | PandaX result | Public evidence |
|---|---|---|---|

The native advisory catalogue now covers the selected curl and OpenSSL boundaries in this reference. Decisions require a digest-verified official release, retain vendor evidence and retrieval records, and do not claim runtime reachability. This remains curated coverage rather than a complete native vulnerability database.

## Every tested input

| Input | Positive checks found | Negative checks correct | Total reported finding rows | Named-check result |
|---|---:|---:|---:|---|
| OpenWrt 19.07.0 | 3/3 | 5/5 | 4 | MATCH |
| OpenWrt 19.07.1 | 2/2 | 6/6 | 2 | MATCH |
| OpenWrt 19.07.5 | 2/2 | 6/6 | 2 | MATCH |
| OpenWrt 19.07.6 | 0/0 | 8/8 | 0 | MATCH |
| curl / libcurl 8.3.0 | 3/3 | 1/1 | 3 | MATCH |
| curl / libcurl 8.4.0 | 1/1 | 3/3 | 1 | MATCH |
| OpenSSL 1.0.1f / s_server | 3/3 | 0/0 | 3 | MATCH |
| OpenSSL 1.0.1g / s_server | 2/2 | 1/1 | 2 | MATCH |
| SmartHub 2.3.1 / directory | 10/10 | 0/0 | 102 | MATCH |
| SmartHub 2.3.1 / zip | 10/10 | 0/0 | 102 | MATCH |
| Struts 2.5.12 / full libraries | 3/3 | 0/0 | 160 | MATCH |
| Struts 2.5.12 / min libraries | 2/2 | 1/1 | 22 | MATCH |
| Struts 2.5.33 / min libraries | 0/0 | 3/3 | 9 | MATCH |
| Example web application 1.0.0 / SBOM | 1/1 | 0/0 | 2 | MATCH |

A dashboard finding row is a component/CVE pair; the reference counts named CVE checks. For example, OpenWrt 19.07.0 reports four rows covering three unique CVEs because the libubox issue is attached to both libubox and libblobmsg-json. That is not an extra independent CVE. Additional findings outside the reference are retained in the JSON report and are **ungraded**, not assumed false positives.

## Triage and evidence notes

1. **Pillow / WebP exposure is not established.** Both SmartHub inputs report CVE-2023-4863 on Pillow, but KEV membership is kept separate from product reachability. The VEX state remains `in_triage` because the observed inventory does not establish an installed libwebp build or a reachable vulnerable path. [Pillow maintainer notes](https://pillow.readthedocs.io/en/stable/releasenotes/10.0.1.html).

2. **OpenSSL affectedness is not runtime exploitability.** OpenSSL 1.0.1f is affected by Heartbleed at the component-version level, while build flags and deployed reachability remain unassessed. The VEX state is therefore `in_triage`, even though CISA KEV makes review urgent. [OpenSSL advisory](https://openssl-library.org/news/secadv/20140407.txt).

3. **Fix evidence is explicit for curated rules.** The curl 8.4.0 decision for CVE-2023-38546 records the official vendor fix boundary and retains the disagreeing OSV range as a conflict. CVE-2023-38039 remains a named negative control outside the curated native catalogue, so its absence must not be broadened into a complete-security claim. [curl cookie advisory](https://curl.se/docs/CVE-2023-38546.html), [curl header advisory](https://curl.se/docs/CVE-2023-38039.html).

4. **The new SBOM sample behaves correctly for missing identity.** It retains both jQuery 3.4.0 and internal-device-agent 1.0.0, finds the named jQuery CVE, and records one component as not scanned because the internal component lacks a versioned PURL. Its zero finding count must not be interpreted as a clean security assessment.

The ten named SmartHub positive checks were detected in both directory and ZIP scans, with the expected historical fix versions. All selected inventory checks were present. No exploit or runtime application test was performed.

## Built-in comparison actions

| Action | Actual built-in verdict | Evidence |
|---|---|---|
| openwrt-libubox | PASS | [Dashboard response](http://127.0.0.1:8000/api/run/run-20260909-171643-395909-72ef1a/summary) |
| curl-socks5 | PASS | [Dashboard response](http://127.0.0.1:8000/api/run/run-20260909-171948-476224-212126/summary) |
| openwrt-dnsmasq | PASS | [Dashboard response](http://127.0.0.1:8000/api/run/run-20260909-172039-483347-abe681/summary) |
| openssl-heartbleed | PASS | [Dashboard response](http://127.0.0.1:8000/api/run/run-20260909-172222-284221-f2e401/summary) |

## Reproduce or inspect

- [Independent answer key](../pdf/PandaX_Independent_Expected_Results.pdf)
- [Every expected/observed CVE row (CSV)](pandax-reference-comparison.csv)
- [Machine-readable results, VEX states and run IDs](pandax-reference-comparison.json)
- [Public-source baseline](../../docs/expected-results-baseline.json)

Start the dashboard from the desired GitHub revision, configure its trusted public key, then run `python tools/evaluate_reference.py`. The evaluator exits 1 when a named check, execution, inventory check, or trusted seal verification fails. A KEV warning by itself is not treated as an execution failure.

Raw API summaries, event streams and verification responses remain locally under `out\reference-validation\20260909T140653Z`; signed pipeline bundles remain in `out/run-*`. The JSON/CSV report is committed, while bulky raw scan artifacts remain local.

Frozen baseline SHA-256: `3c2c337fbf76ae62564842dc3364d9f604edae5abc03067c2cd0d43a80b810db`.
Tested PDF SHA-256: `a1509425fba5ca3cbbf423f81287e7f933c0295f4fe7e645bff189e2ed1f07d1`.
