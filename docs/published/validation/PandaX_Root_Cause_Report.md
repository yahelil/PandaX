# Why PandaX missed seven expected findings

Diagnosis date: 7 September 2026. Tested engine: `d7f78903473a0efb3ed3830b4b5b2e470d7ae8ad`.

**Four CVEs account for seven release/CVE misses. The components were identified correctly. The discovery query returned no candidates, and the native supplement has no rules for these CVEs. There is no evidence that triage discarded them or that a local version comparison rejected a returned match.**

## Answers to the three questions

| Question | Evidence-based answer |
|---|---|
| Are they reported somewhere PandaX does not check? | Yes: the official curl and OpenSSL advisories describe them, but the scanner does not generally ingest those advisory catalogs. All four also exist as individual records in OSV, which PandaX already uses. Record existence does not mean a package query can find it. |
| Did PandaX check for them? | It submitted the identified components to OSV. It did not evaluate these four CVEs individually: OSV returned no candidate IDs, and the bounded native rules contain only the original curl SOCKS5 and OpenSSL Heartbleed demo CVEs. |
| Did it check and match incorrectly? | The primary fault is discovery/coverage through the chosen identifiers, before CVE-level evaluation. Inventory is correct. No matching-stage output contains the missed CVEs. This is not an observed triage suppression or incorrect local version-range decision. |

## Each miss

| Release | Missing CVE | Why it was missed | Vendor fix / applicability |
|---|---|---|---|
| libcurl 8.3.0 | CVE-2023-38546 | Exact generic PURL query returned no IDs; no native rule. OSV Git query does discover the record. | Fixed 8.4.0. Duplicated easy-handle cookie API path; not reachable through curl CLI alone. [curl advisory](https://curl.se/docs/CVE-2023-38546.html) |
| libcurl 8.3.0 | CVE-2023-46218 | Exact generic PURL query returned no IDs; no native rule. OSV Git query does discover the record. | Fixed 8.5.0. Cookie handling and PSL support matter. [curl advisory](https://curl.se/docs/CVE-2023-46218.html) |
| libcurl 8.4.0 | CVE-2023-46218 | Same discovery gap; upgrading to 8.4.0 fixes the demo SOCKS5 CVE but not this one. | Fixed 8.5.0. [curl advisory](https://curl.se/docs/CVE-2023-46218.html) |
| libssl 1.0.1f | CVE-2014-0224 | Exact PURL query returned no IDs; no native rule. OSV direct record has no affected entries; Git query also fails to discover it. | Fixed 1.0.1h. TLS MITM requires vulnerable peers. [OpenSSL advisory](https://openssl-library.org/news/secadv/20140605.txt) |
| libssl 1.0.1g | CVE-2014-0224 | Same coverage gap. Heartbleed's 1.0.1g fix does not fix this CVE. | Fixed 1.0.1h. [OpenSSL advisory](https://openssl-library.org/news/secadv/20140605.txt) |
| libssl 1.0.1f | CVE-2014-0195 | Exact PURL query returned no IDs; no native rule. OSV direct record has no affected entries; Git query also fails to discover it. | Fixed 1.0.1h. DTLS use is required. [OpenSSL advisory](https://openssl-library.org/news/secadv/20140605.txt) |
| libssl 1.0.1g | CVE-2014-0195 | Same coverage gap. No DTLS-specific assessment was produced. | Fixed 1.0.1h. DTLS use is required. [OpenSSL advisory](https://openssl-library.org/news/secadv/20140605.txt) |

These are missing affected-library findings. The test does not establish that a deployed application reaches every vulnerable code path.

## Trace through the code

1. `apps/engine/pandax/native.py` builds inventory for libcurl/curl and libssl/openssl-s_server with the correct release versions and `pkg:generic/...` PURLs.
2. `stages/sbom.py:is_matchable_purl` accepts a syntactically usable versioned PURL. Its `matchable` flag does not establish actual feed coverage for that identity.
3. `feeds.py:Feeds.query_purls` calls OSV `/v1/querybatch` with those PURLs. `stages/match.py:run` fetches details only for returned IDs. It has no general vendor-catalog or NVD/CPE fallback.
4. `native.py:assess` supplements libcurl with **CVE-2023-38545 only**, and libssl with **CVE-2014-0160 only**. The four missed CVEs have no entries.
5. Triage enriches existing findings with KEV/EPSS; it does not independently discover the missing CVEs.

[Matching code at the tested revision](https://github.com/yahelil/PandaX/blob/d7f78903473a0efb3ed3830b4b5b2e470d7ae8ad/apps/engine/pandax/stages/match.py), [feed adapter](https://github.com/yahelil/PandaX/blob/d7f78903473a0efb3ed3830b4b5b2e470d7ae8ad/apps/engine/pandax/feeds.py), [native rules](https://github.com/yahelil/PandaX/blob/d7f78903473a0efb3ed3830b4b5b2e470d7ae8ad/apps/engine/pandax/native.py).

## Preserved scan evidence and fresh diagnostic probes

The original four native scan bundles each contain `findings.osv.json = []`; their native assessments contain one demo-CVE determination each. Their event streams show OSV queries completed. The exact HTTP request/response bodies were not recorded by the original scanner, so the separate replay below is fresh diagnostic evidence, not a claim that its bytes were captured during the original scan.

`root-cause-evidence/exact-purl-replay.json` records a fresh HTTP 200 replay for these eight identities. All eight returned empty results:

```
pkg:generic/libcurl@8.3.0
pkg:generic/curl@8.3.0
pkg:generic/libcurl@8.4.0
pkg:generic/curl@8.4.0
pkg:generic/libssl@1.0.1f
pkg:generic/openssl-s_server@1.0.1f
pkg:generic/libssl@1.0.1g
pkg:generic/openssl-s_server@1.0.1g
```

Alternative queries use OSV's documented `GIT` ecosystem with official repository URLs and release tags. They are experiments outside PandaX, not observed scanner results. [OSV query API](https://google.github.io/osv.dev/post-v1-query/).

| Diagnostic query | HTTP | Records | Relevant result |
|---|---:|---:|---|
| curl repository / curl-8_3_0 | 200 | 80 | Both missed curl CVEs returned |
| curl repository / curl-8_4_0 | 200 | 78 | Both curl CVEs returned, including a vendor-fixed control; see below |
| OpenSSL repository / OpenSSL_1_0_1f | 200 | 29 | Neither missed OpenSSL CVE returned |
| OpenSSL repository / OpenSSL_1_0_1g | 200 | 29 | Neither missed OpenSSL CVE returned |

All four queries completed without remaining pagination tokens. Direct OSV CVE lookups returned HTTP 200 for all four missed CVEs. The curl records have Git ranges with no package identity; the two OpenSSL records have **no affected entries at all**. Those OpenSSL records therefore do not supply affected-package/range data for this query path. This does not establish that every possible alias or distribution feed lacks coverage.

## Additional feed discrepancy: do not blindly add Git matches

The fresh OSV Git query returns CVE-2023-38546 for `curl-8_4_0`. The captured direct OSV record explicitly lists that tag among affected versions. Its converted Git fixed commit also differs from the fix commit cited by curl. The vendor advisory says **8.4.0 is not affected**. This is a conflict in the captured OSV data, not a PandaX false positive in the original test (PandaX did not issue this query).

Use the vendor's 8.4.0 fixed control when developing a fallback. Preserve conflicting sources and prefer verified upstream fix evidence; do not silently replace one coverage gap with an incorrect positive. We have established the conflicting data, not the internal cause of OSV's conversion. [Vendor boundary](https://curl.se/docs/CVE-2023-38546.html), [current OSV record](https://api.osv.dev/v1/vulns/CVE-2023-38546).

## Developer actions and acceptance checks

| Priority | Change | Acceptance evidence |
|---|---|---|
| P1 | Add source-aware discovery for native components: upstream repository identity plus curated vendor advisories; use distro advisories/revisions for backports. | All seven missed checks become affected-library findings with source and fix evidence. Preserve all 34 named negative controls. OpenSSL coverage cannot rely on this Git fallback alone. |
| P1 | Make query coverage explicit in UI/export: queried, supported identity, no candidate returned, unknown coverage, native rule assessed. | A zero-hit generic query does not imply the release is clean. Keep the raw request, response, source timestamp and decision trace. |
| P1 | Reconcile conflicting fix data and test release boundaries. | CVE-2023-38546 remains fixed at 8.4.0 despite the captured OSV conflict; CVE-2023-46218 remains affected at 8.4.0 and fixed at 8.5.0. OpenSSL fixes at 1.0.1h. |
| P2 | Separate affected component from proven application reachability in VEX. | KEV membership alone does not set deployed exploitability. Handle libcurl API-only paths, DTLS use and Heartbleed build flags explicitly. |
| P2 | Keep built-in demo checks separate from independent coverage acceptance. | A built-in PASS states its named CVEs and cannot be read as whole-release clearance. Run the frozen 76 checks as an external regression gate. |

A small immediate extension to native rules can address these specific omissions, but it remains curated coverage. Production coverage needs a maintained discovery strategy. This investigation changes diagnostics and reports only; no scanner fix has been applied or claimed.
