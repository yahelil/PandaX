# Actis technical guide

For a short overview and quickstart, see the [repository README](../README.md).

Turns a product artifact **or an existing JSON SBOM** into a signed,
independently verifiable EU Cyber Resilience Act evidence bundle: SBOM → CVE
matching → actively-exploited triage → Article 14 filings → Annex VII technical
documentation, sealed so a regulator can prove nothing was edited afterwards.

This POC exists to answer one question: **is the automated compliance engine
actually buildable?** The answer is yes, and everything below is runnable.

Private-beta behavior is bounded by the [scope and acceptance gates](private-beta-scope.md).
Provider ownership, access, and billing are governed by the
[zero-cost delivery policy](private-beta-delivery.md).

```
artifact.zip                         existing-sbom.json
   │                                      │
   ├─ S1 INGEST  unpack safely            ├─ S1 INGEST  skipped and recorded
   └─ S2 SBOM    Syft → CDX 1.6           └─ S2 SBOM    detect + normalise
                    │                              │
                    └──────────────┬───────────────┘
                                   ├─ S3 MATCH     OSV.dev, exact purl matching
                                   ├─ S4 TRIAGE    CISA KEV + EPSS → CDX VEX
                                   ├─ S5 CLOCK     Art.14 24h / 72h / 14d filings
                                   ├─ S6 DOSSIER   Annex VII + Annex V, PDF/A-2b
                                   └─ SEAL         hash chain + Ed25519 signature
```

---

## Tomcat, OpenWrt, curl and OpenSSL release comparisons

The dashboard selector includes five downloadable release comparisons and all
ten individual releases. Run `uv run actis compare list` for CLI ids.
Comparisons show passes, failures, package-variant exclusions and vendor evidence;
failed downloads/scans remain visible and do not stop the other release being tested.
See [the scenario guide](release-scenarios.md) for instructions and limitations.
Tomcat uses official server binaries before and after the CVE-2025-24813 patch
(9.0.98 → 9.0.99), including bundled libraries, configuration and example webapps.
OpenWrt uses official firmware rootfs archives; curl/OpenSSL use official source
releases. These are inventory/advisory tests, not runtime exploit tests.

## Quickstart

For CI/CD integration, JSON output, and SARIF, see the [Actis GitHub Action guide](github-action.md).

```bash
uv sync --extra dev
uv run python tools/bootstrap.py           # pinned, digest-verified downloads
uv run actis scan fixtures/smarthub-sh100-v2.3.1.zip
```

To start from an SBOM, Syft and the bootstrap step are not required:

```bash
uv sync --extra dev
uv run actis scan-sbom fixtures/example-sbom.cdx.json
```

Actis detects the document from its contents; the user does not need to choose
a format. The accepted inputs are **CycloneDX 1.2/1.6 JSON** and **SPDX 2.2/2.3
JSON**. CycloneDX 1.2 and SPDX are upgraded to the pipeline's CycloneDX 1.6
component model. The
unaltered upload is retained under `input/`, while the normalised inventory is
written as `sbom.cdx.json`; both are covered by the evidence seal.

Vulnerability matching requires a versioned Package URL (`purl`), such as
`pkg:npm/jquery@3.4.0`. Components without one are preserved in the SBOM,
dashboard and dossier, but are clearly counted as **not scanned**. Actis does
not guess an identifier from a name because that can attach vulnerabilities to
the wrong package. A run is refused only when none of the components can be
matched safely.

For imported SBOMs, product name and version come from CycloneDX
`metadata.component` or a single SPDX `documentDescribes` package. Manufacturer
identity, intended purpose, risk tier and other attestations are not inferred;
the dossier marks them `MANUFACTURER INPUT REQUIRED`.

The demo product, *PandaX SmartHub SH-100 v2.3.1*, is deliberately built so that
each ecosystem contributes one **real** CISA KEV vulnerability:

| Source in the artifact | Component | CVE | |
|---|---|---|---|
| `app/package-lock.json` | jquery 3.4.0 | CVE-2020-11023 | npm |
| `services/requirements.txt` | pillow 8.1.0 | CVE-2023-4863 | PyPI |
| `lib/log4j-core-2.14.1.jar` | log4j-core 2.14.1 | **CVE-2021-44228** (Log4Shell) | Maven, real binary |

Expect: 11 components, ~102 vulnerabilities, **4 actively exploited**, 4 Article
14 clocks armed, two PDFs, and a sealed bundle in `workspace/runs/run-<timestamp>/`.

> The first run takes ~45s because it fetches and caches every OSV advisory
> into `workspace/cache/`. Subsequent runs take a few seconds.

---

## Proving it actually worked

Every claim this POC makes has a command that checks it. None of these require
trusting Actis.

**0 · The one-screen answer**

```bash
uv run actis verdict
```
Answers the three questions behind a scan — can this product go on the EU market
(blockers, each with the article that blocks it), what is due and when (Article 14
clocks), and what to actually do about it. The last one collapses ~100 CVE rows
into ~10 package upgrades, which is the whole backlog.

**1 · The seal holds**

```bash
uv run actis key export-public trusted-pandax-key.pem
uv run actis verify --trusted-key trusted-pandax-key.pem
```
Recomputes every file digest, re-derives every chain link, and checks the
Ed25519 signature against the public key supplied outside the bundle. Integrity,
signature validity and signer trust are reported separately.

**2 · The seal actually catches tampering** — the important one

```bash
uv run actis tamper --target sbom.cdx.json   # flips ONE byte; file stays valid JSON
uv run actis verify --trusted-key trusted-pandax-key.pem
# now fails, naming S2_SBOM as the source
```

**3 · The findings reproduce against the live feed**

```bash
uv run actis verify --trusted-key trusted-pandax-key.pem --online
# re-queries OSV.dev and compares the advisory set
```

**4 · The statutory clocks**

```bash
uv run actis clock --speed 1800  # 24h/72h/14d countdowns, time compressed for demo
```

**5 · Check the outputs yourself, without this tool**

```bash
python -c "import json,pathlib;d=json.loads(next(pathlib.Path('workspace/runs').glob('run-*/sbom.cdx.json')).read_text());print(d['specVersion'], 'vulnerabilities' in d)"
#  -> 1.6 False        (CycloneDX 1.6, and the zero-CVE invariant holds)

curl -s -X POST https://api.osv.dev/v1/querybatch \
  -d '{"queries":[{"package":{"purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}}]}'
#  -> the same advisories the pipeline recorded

curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  | grep -c CVE-2021-44228
#  -> confirms Log4Shell really is in the KEV catalogue
```

Reproduce a ledger hash with nothing but the standard library:

```bash
python -c "
import hashlib, json
rec = json.loads(open('workspace/runs/run-XXXX/ledger.jsonl').readline())
body = {k: v for k, v in rec.items() if k != 'record_hash'}
print(hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest())
print(rec['record_hash'])"
```

**6 · Tests**

```bash
uv run pytest -q                    # complete suite
uv run pytest -q -m "not slow"      # skip the network/Syft end-to-end ones
```
Covers zip-slip and decompression-bomb refusal, chain and signature tamper
detection (including a re-linked forged chain), Annex VII/V completeness,
Article 14 field mapping, and a full end-to-end run asserting the three KEV CVEs.

**7 · The dashboards**

Run the Actis product workspace with Vite hot reload:

```bash
uv run actis serve       # http://127.0.0.1:4175
```

The legacy engine inspection dashboard remains available only when explicitly invoked:

```bash
uv run uvicorn pandax.server:api --host 127.0.0.1 --port 8000
```

Same event stream as the CLI, over SSE — the browser view is not a
reimplementation. Six views, each backed by the sealed bundle's own files:

The runner offers **Product artifact** and **SBOM file** modes. In SBOM mode,
choose a JSON file and press **Run pipeline**; the dashboard uploads it, reports
the detected format and matchable/skipped component counts, then streams the
same S3-through-SEAL execution shown by `actis scan-sbom`.

| View | Shows |
|---|---|
| `#overview` | Live pipeline console, four stat cards, KEV table, statutory timeline |
| `#artifacts` | Every SBOM component, its ecosystem and finding count |
| `#vulns` | All findings, filterable by KEV / severity / fixability |
| `#article14` | Per-incident 24h / 72h / 14d clocks, linked to the filing drafts |
| `#reports` | The Annex VII PDF, the DoC, SBOM, VEX and signed manifest |
| `#audit` | The hash chain record by record, plus Verify and Tamper buttons |

The **Annex VII Completeness** ring is not a marketing score: it is the share of
the 22 Annex VII and Annex V entries this run can actually evidence
(derived + attested). The remainder are the fields flagged
MANUFACTURER INPUT REQUIRED.

---

## Does it actually detect real vulnerabilities?

The demo fixture is circular — its components were picked *because* they carry
known-exploited CVEs, so detecting them proves little. `tools/evaluate.py` scans
real Apache-published artifacts instead, with ground truth from Apache's own
security advisories and an independent scanner as the control.

```bash
uv run python tools/evaluate.py     # digest-pinned; installs grype for the cross-check
```

The targets are chosen so that detection has to follow the artifact's **actual
contents**. The first two are the same product at the same version, packaged
differently — a scanner that guesses from name and version cannot tell them
apart, and will fail one of them.

| Target | Contents | Findings | KEV | Agreement with Grype |
|---|---|---|---|---|
| Struts 2.5.12 full (93 jars) | includes `struts2-rest-plugin` | 158 | 5 | **157/157 CVEs (100%)** |
| Struts 2.5.12 min (8 jars) | same version, no REST plugin | 22 | 2 | **22/22 (100%)** |
| Struts 2.5.33 min (Dec 2023) | the differential control | 9 | 0 | **9/9 (100%)** |

Ground-truth checks, all passing:

- **CVE-2018-11776** (S2-057, KEV) found in both 2.5.12 packages — `struts2-core` is in both.
- **CVE-2017-9805** (S2-052, KEV) found in the full package, and **correctly absent
  from the minimal one**, because `struts2-rest-plugin` is not bundled there.
  Reporting it would have been a false positive.
- Neither CVE appears in 2.5.33, where both were fixed years earlier.

Grype is a genuinely independent control: a different tool, from a different
vendor, matching against Anchore's NVD/GitHub-derived database rather than
OSV.dev. The two agree on every CVE across all three artifacts.

> Two caveats on that table. Grype's JSON lists only the artifacts it matched,
> not its full catalogue, so its component count is not comparable to the SBOM's.
> And the engine reports one extra advisory on the full distribution —
> `GHSA-r7wm-3cxj-wff9` against jackson-core 2.6.1 — which has no CVE assigned
> yet, so it is a real finding that a CVE-keyed comparison simply cannot see.

**What this does not prove:** all three targets are Java jar bundles. Firmware
images (squashfs/ubifs) are still unpacked, and no npm/PyPI application has been
evaluated this way.

---

## What makes the output trustworthy

Each stage appends a record to `ledger.jsonl` naming its tool, version, inputs
and outputs with SHA-256 digests, chained by `prev_hash`. For imported runs the
ledger explicitly records that ingest was skipped, identifies the source SBOM
format/version, and links the original upload to the normalised CycloneDX file.
The chain head is committed in `manifest.json`, which is signed with Ed25519.

Changing any file breaks its digest. Editing a ledger record breaks that link.
Re-linking the whole chain to hide the edit still fails, because the head no
longer matches the signed manifest. Trusted verification additionally checks
the signature against a public key supplied separately from the bundle:

```powershell
actis key export-public trusted-pandax-key.pem
$env:PANDAX_TRUSTED_KEY = "C:\secure-config\trusted-pandax-key.pem"
actis verify workspace\runs\run-example
```

Use `actis verify RUN --trusted-key KEY.pem` for a one-off trusted check, or
`actis verify RUN --inspect-only` to inspect an old bundle without claiming
that its signer is trusted. See [trusted verification](trusted-verification.md)
for provisioning and status meanings.

### Continuous monitoring

Register an artifact or SBOM once, then let Actis recheck it on a saved schedule:

```powershell
uv run actis monitor add "Product release" .\product.zip --every-minutes 360
uv run actis monitor watch
```

`actis monitor list` shows source freshness and the next check. `actis monitor
alerts` reports new, changed, reappearing, and no-longer-detected findings plus
source failures and recoveries. Repeated identical results do not create new
alerts. If a required source cannot be checked, Actis records monitoring as
incomplete and does not treat missing results as resolved vulnerabilities.

### Approved runtime evidence

A software file or SBOM shows which components are included, but it cannot show
whether a component is actually loaded, used, enabled, or exposed on a real
device. PandaX can now attach a small approved telemetry summary to a scan:

```powershell
uv run actis telemetry validate .\runtime-telemetry.json
uv run actis scan .\product.zip --telemetry .\runtime-telemetry.json
uv run actis monitor add "Product release" .\product.zip --telemetry .\runtime-telemetry.json
```

Start with [the example telemetry file](runtime-telemetry-example.json).
The JSON uses schema `pandax/runtime-telemetry/v1`. It names the exact product
and version, records the authorized company reviewer and approval time, and
contains component PURLs with one of these signals: `component_loaded`,
`component_executed`, `network_exposed`, `feature_enabled`, or `not_observed`.
An optional device reference must already be converted to a SHA-256 value.
Hostnames, IP addresses, serial numbers, environment variables, command lines,
and raw logs are rejected. The original source is represented by its digest;
only the checked, minimal form is placed in the signed evidence bundle.

Runtime signals remain **evidence for company review**. They do not automatically
declare a component reachable, make a vulnerability reportable, or start a CRA
deadline. `telemetry-assessments.json` clearly marks matched and unmatched
observations and every decision that still needs a person.

### Vendor advisories and backported fixes

Generic feeds can incorrectly flag a distribution package when its vendor has
backported a security fix without changing the upstream version. An authorized
security curator can install reviewed, exact-package vendor decisions:

```powershell
uv run actis advisory validate .\vendor-intelligence.json
uv run actis advisory install .\vendor-intelligence.json
uv run actis advisory status
```

Actis matches these decisions only to an exact, versioned Package URL. It keeps
the official source, complete vendor revision, patch reference, review record,
and any conflicting generic-feed result in the signed bundle. See
[vendor advisories and backports](vendor-intelligence.md) and the
[example catalogue](vendor-intelligence-example.json).

### Product exposure analysis

Actis can combine reviewed build flags, feature configuration, network
exposure, SBOM dependency paths, and approved runtime observations:

```powershell
uv run actis exposure validate .\exposure-context.json
uv run actis scan .\product.zip --exposure-context .\exposure-context.json
```

The result explains whether the supplied evidence supports reachability,
supports non-reachability, conflicts, or remains insufficient. It does not make
the final decision or start a CRA deadline. See the [exposure analysis guide](exposure-analysis.md)
and [example context](exposure-context-example.json).

Vulnerability results keep [coverage, affectedness, KEV signals and product
reachability](vulnerability-coverage.md) separate. A completed source with
no result is shown as “no finding in checked sources,” never as proof that the
product is clean. The [native advisory coverage](native-advisory-coverage.md)
page lists the exact curl and OpenSSL release boundaries that are currently
reviewed, explains source priority, and identifies what remains unknown.

Evidence recipients can instead install the independent offline verifier from
[`apps/verifier`](../apps/verifier/README.md). It accepts a folder or ZIP and does
not import the Actis product:

```powershell
actis-verify evidence.zip --trusted-key trusted-actis-key.pem
```

> External-key verification establishes that the bundle came from the
> pre-approved PandaX signing installation. It does not prove **legal identity**;
> that requires an appropriate identity-backed or eIDAS-qualified seal.

### Honest documents

Annex VII entries are labelled **machine-derived**, **manufacturer-attested**, or
**MANUFACTURER INPUT REQUIRED** (rendered as a red box). Photographs (item 1(c)),
Annex II user instructions (1(d)), architecture (2(a)) and Annex I Part I test
reports are never invented — a tool that fabricates a technical file sells
exposure, not compliance.

The Declaration of Conformity is automatically **blocked** while any actively
exploited vulnerability remains, per Annex I Part I(2)(a) ("without known
exploitable vulnerabilities").

---

## What was cut from the architecture blueprint, and why

| Proposed | Verdict | Reason |
|---|---|---|
| Firecracker microVM sandbox | replaced | Syft parses, never executes — kernel isolation defends a threat that does not occur. Replaced with zip-slip / bomb / depth limits, each with a test. |
| Temporal.io cluster | replaced | A durable workflow engine to track three timestamps. A JSON state file gives the same statutory guarantee. |
| LIEF binary reachability | cut | Sound reachability is a research problem. A wrong `not_affected` is mis-sold compliance, so nothing is suppressed. |
| CSAF 2.0 | → CycloneDX VEX | CRA mandates a machine-readable SBOM, not a VEX format. One format family, half the work. |
| pyHanko PAdES-B-LTA + KMS | deferred | Qualified signatures need an eIDAS trust service; self-signed PAdES proves no more than Ed25519. |
| S3 Object Lock WORM | → local hash chain | Object Lock is a config flag. The interesting part is the Merkle anchor, built locally so it can be demonstrated breaking. |
| ENISA browser extension | cut | The single reporting platform is not live until 11 Sept 2026. Filings are generated with every field traced to its Article 14 sub-paragraph. |
| NVD feed | → EPSS | NVD needs a key and duplicates OSV. EPSS adds exploitation signal instead. |

---

## Known gaps

1. No reachability analysis — non-KEV findings are `in_triage`, never `not_affected`.
2. Externally trusted Ed25519 verification identifies the configured signing
   installation, not a legal person (an identity-backed/eIDAS seal is still needed).
3. PDF/A-2b is requested via Typst, not independently validated with veraPDF.
4. Filings are generated, not submitted — the ENISA platform is not live.
5. Squashfs/UBIFS images are not unpacked. The added OpenWrt scenarios use official rootfs tar archives; see the scenario guide.
6. Risk-tier classification is manufacturer-declared, not derived.
7. SBOM import currently accepts CycloneDX 1.2/1.6 and SPDX 2.2/2.3 JSON only;
   packages without versioned purls remain visible but cannot be OSV-matched.

---

## Layout

```
apps/engine/pandax/
  cli.py  pipeline.py  events.py  evidence.py  feeds.py  context.py
  render_cli.py  server.py        # two renderers, one event stream
  stages/{ingest,sbom,match,triage,clock,dossier}.py  # generate or import at S2
  templates/*.typ  web/           # Typst dossier, dashboard
apps/verifier/                     # independent offline evidence verifier
tools/bootstrap.py                # digest-pinned syft + log4j, builds the artifact
fixtures/smarthub-sh100/          # the demo product
workspace/                        # ignored runs, caches, tools, and builds
docs/published/                   # committed historical results
```

Legal text driving the code is quoted in the module docstrings: Annex VII
(8 items), Annex V (8 items), Annex I Part I(2)(a) and Part II(1), and
Article 14(2)(a)–(c), all from Regulation (EU) 2024/2847.
