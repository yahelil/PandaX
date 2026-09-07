# PandaX — CRA Compliance-in-a-Box (proof of concept)

Turns a product artifact into a **signed, independently verifiable** EU Cyber
Resilience Act evidence bundle: SBOM → CVE matching → actively-exploited triage
→ Article 14 filings → Annex VII technical documentation, sealed so a regulator
can prove nothing was edited afterwards.

This POC exists to answer one question: **is the automated compliance engine
actually buildable?** The answer is yes, and everything below is runnable.

```
artifact.zip
   │
   ├─ S1 INGEST    zip-slip / bomb / depth limits, SHA-256 every file
   ├─ S2 SBOM      Syft → CycloneDX 1.6            [asserts: no CVE data in SBOM]
   ├─ S3 MATCH     OSV.dev, exact Package-URL matching
   ├─ S4 TRIAGE    ∩ CISA KEV + EPSS → CycloneDX VEX
   ├─ S5 CLOCK     KEV hit ⇒ Art.14 24h / 72h / 14d filings
   ├─ S6 DOSSIER   Typst → Annex VII + Annex V, PDF/A-2b
   └─ SEAL         hash-chained ledger + Ed25519 signature
```

---

## OpenWrt, curl and OpenSSL release comparisons

The dashboard selector includes four downloadable release comparisons and all
eight individual releases. Run `uv run pandax compare list` for CLI ids.
Comparisons show passes, failures, package-variant exclusions and vendor evidence;
failed downloads/scans remain visible and do not stop the other release being tested.
See [the scenario guide](docs/release-scenarios.md) for instructions and limitations.
OpenWrt uses official firmware rootfs archives; curl/OpenSSL use official source
releases. These are inventory/advisory tests, not runtime exploit tests.

## Quickstart

```bash
uv sync --extra dev
uv run python tools/bootstrap.py           # pinned, digest-verified downloads
uv run pandax scan fixtures/smarthub-sh100-v2.3.1.zip
```

The demo product, *PandaX SmartHub SH-100 v2.3.1*, is deliberately built so that
each ecosystem contributes one **real** CISA KEV vulnerability:

| Source in the artifact | Component | CVE | |
|---|---|---|---|
| `app/package-lock.json` | jquery 3.4.0 | CVE-2020-11023 | npm |
| `services/requirements.txt` | pillow 8.1.0 | CVE-2023-4863 | PyPI |
| `lib/log4j-core-2.14.1.jar` | log4j-core 2.14.1 | **CVE-2021-44228** (Log4Shell) | Maven, real binary |

Expect: 11 components, ~102 vulnerabilities, **4 actively exploited**, 4 Article
14 clocks armed, two PDFs, and a sealed bundle in `out/run-<timestamp>/`.

> The first run takes ~45s because it fetches and caches every OSV advisory
> into `.cache/`. Subsequent runs take a few seconds.

---

## Proving it actually worked

Every claim this POC makes has a command that checks it. None of these require
trusting PandaX.

**1 · The seal holds**

```bash
uv run pandax verify
```
Recomputes every file digest, re-derives every chain link, and checks the
Ed25519 signature. Seven checks, all green.

**2 · The seal actually catches tampering** — the important one

```bash
uv run pandax tamper --target sbom.cdx.json   # flips ONE byte; file stays valid JSON
uv run pandax verify                          # now fails, naming S2_SBOM as the source
```

**3 · The findings reproduce against the live feed**

```bash
uv run pandax verify --online     # re-queries OSV.dev and compares the advisory set
```

**4 · The statutory clocks**

```bash
uv run pandax clock --speed 1800  # 24h/72h/14d countdowns, time compressed for demo
```

**5 · Check the outputs yourself, without this tool**

```bash
python -c "import json;d=json.load(open('out/run-*/sbom.cdx.json'));print(d['specVersion'], 'vulnerabilities' in d)"
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
rec = json.loads(open('out/run-XXXX/ledger.jsonl').readline())
body = {k: v for k, v in rec.items() if k != 'record_hash'}
print(hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest())
print(rec['record_hash'])"
```

**6 · Tests**

```bash
uv run pytest -q                    # 56 tests
uv run pytest -q -m "not slow"      # skip the network/Syft end-to-end ones
```
Covers zip-slip and decompression-bomb refusal, chain and signature tamper
detection (including a re-linked forged chain), Annex VII/V completeness,
Article 14 field mapping, and a full end-to-end run asserting the three KEV CVEs.

**7 · The dashboard**

```bash
uv run pandax serve      # http://127.0.0.1:8000
```

Same event stream as the CLI, over SSE — the browser view is not a
reimplementation. Six views, each backed by the sealed bundle's own files:

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
and outputs with SHA-256 digests, chained by `prev_hash`. The chain head is
committed in `manifest.json`, which is signed with Ed25519.

Changing any file breaks its digest. Editing a ledger record breaks that link.
Re-linking the whole chain to hide the edit still fails, because the head no
longer matches the signed manifest. `pandax verify` reports which of those
happened.

> The signing key is generated locally and proves **integrity, not legal
> identity**. A production deployment needs an eIDAS qualified electronic seal.

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
2. Ed25519 proves integrity, not legal identity (eIDAS seal needed).
3. PDF/A-2b is requested via Typst, not independently validated with veraPDF.
4. Filings are generated, not submitted — the ENISA platform is not live.
5. Squashfs/UBIFS images are not unpacked. The added OpenWrt scenarios use official rootfs tar archives; see the scenario guide.
6. Risk-tier classification is manufacturer-declared, not derived.

---

## Layout

```
apps/engine/pandax/
  cli.py  pipeline.py  events.py  evidence.py  feeds.py  context.py
  render_cli.py  server.py        # two renderers, one event stream
  stages/{ingest,sbom,match,triage,clock,dossier}.py
  templates/*.typ  web/           # Typst dossier, dashboard
tools/bootstrap.py                # digest-pinned syft + log4j, builds the artifact
fixtures/smarthub-sh100/          # the demo product
```

Legal text driving the code is quoted in the module docstrings: Annex VII
(8 items), Annex V (8 items), Annex I Part I(2)(a) and Part II(1), and
Article 14(2)(a)–(c), all from Regulation (EU) 2024/2847.
