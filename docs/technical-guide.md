# Actis Technical Guide

For an executive summary and quickstart, see the [repository README](../README.md).

Actis turns a product artifact or an existing JSON SBOM into a signed, independently verifiable EU Cyber Resilience Act (CRA, Regulation (EU) 2024/2847) evidence bundle:
**SBOM -> CVE matching -> Actively-exploited triage -> Article 14 statutory filings -> Annex VII technical documentation**, cryptographically sealed so an auditor or regulator can verify nothing was edited after generation.

This guide details the pipeline architecture, verification mechanics, regulatory mappings, evaluation benchmarks, and system boundaries.

---

## 1. Pipeline Architecture

The engine accepts either a raw product archive (ZIP, tar, JAR) or an existing machine-readable SBOM, executing a deterministic multi-stage workflow:

```
artifact.zip                         existing-sbom.json
   │                                      │
   ├─ S1 INGEST  unpack safely            ├─ S1 INGEST  skipped and recorded
   └─ S2 SBOM    Syft → CDX 1.6           └─ S2 SBOM    detect + normalise
                    │                              │
                    └──────────────┬───────────────┘
                                   ├─ S3 MATCH     OSV.dev, exact purl matching
                                   ├─ S4 TRIAGE    CISA KEV + EPSS → CDX VEX
                                   ├─ S5 CLOCK     Art. 14 24h / 72h / 14d filings
                                   ├─ S6 DOSSIER   Annex VII + Annex V, PDF/A-2b
                                   └─ SEAL         SHA-256 ledger + Ed25519 signature
```

### Stage Details

1. **S1 Ingest**: Safely unpacks product archives. Enforces decompression bomb limits, zip-slip path traversal guards, and maximum recursion depth. For SBOM-only runs, this stage is skipped and explicitly logged in the audit ledger.
2. **S2 SBOM Normalisation**:
   - For artifacts: Invokes the pinned Syft scanner to inventory software components into CycloneDX 1.6.
   - For imported SBOMs: Accepts CycloneDX 1.2/1.6 JSON and SPDX 2.2/2.3 JSON. Upgrades imported documents to CycloneDX 1.6 while preserving the unaltered original upload in the signed bundle.
3. **S3 Match**: Queries OSV.dev using exact, versioned Package URLs (`purl`, e.g., `pkg:npm/jquery@3.4.0`). Components lacking a versioned PURL are retained in the inventory and clearly reported as unmatchable; Actis never guesses package identity from raw names.
4. **S4 Triage**: Cross-references findings against CISA KEV (Known Exploited Vulnerabilities) and EPSS (Exploit Prediction Scoring System) scores, generating an exportable CycloneDX 1.6 VEX document.
5. **S5 Clock**: Evaluates Article 14 reporting triggers. If actively exploited vulnerabilities or severe incidents are detected, statutory countdowns are initialized: 24-hour early warning, 72-hour vulnerability notification, and 14-day final reporting drafts.
6. **S6 Dossier & Seal**: Renders Annex VII Technical Documentation and Annex V EU Declaration of Conformity (DoC) into archival PDF/A-2b format via Typst. The entire run is committed to a SHA-256 append-only ledger (`ledger.jsonl`) and anchored by an Ed25519-signed `manifest.json`.

---

## 2. Quickstart

### Prerequisites
- Python >= 3.10
- `uv` package manager
- Node.js >= 18 (for the web workspace)

### Running an SBOM Scan
Syft and binary bootstrap are not required when starting from an existing SBOM:

```bash
uv sync --extra dev
uv run actis scan-sbom fixtures/example-sbom.cdx.json
```

### Running an Artifact Scan
To scan compiled software archives or firmware:

```bash
uv sync --extra dev
uv run python tools/bootstrap.py           # Installs pinned Syft binary and dependencies
uv run actis scan fixtures/smarthub-sh100-v2.3.1.zip
```

> **Note on Initial Run**: The initial scan takes ~45 seconds while caching advisory data into `workspace/cache/`. Subsequent runs complete in seconds.

### The SmartHub SH-100 Demo Fixture
The included demo product, *PandaX SmartHub SH-100 v2.3.1*, contains deliberate, real-world vulnerable components across three distinct package ecosystems:

| Source Path in Artifact | Component | Target CVE | Ecosystem |
|---|---|---|---|
| `app/package-lock.json` | jquery 3.4.0 | CVE-2020-11023 | npm |
| `services/requirements.txt` | pillow 8.1.0 | CVE-2023-4863 | PyPI |
| `lib/log4j-core-2.14.1.jar` | log4j-core 2.14.1 | CVE-2021-44228 (Log4Shell) | Maven |

A standard demo scan produces: 11 components, ~102 vulnerabilities, 4 actively exploited KEV findings, 4 Article 14 clocks armed, 2 compliance PDFs, and an Ed25519-sealed evidence bundle in `workspace/runs/run-<timestamp>/`.

---

## 3. Cryptographic Trust and Verification

Every claim made by Actis is verifiable independently without trusting the engine itself.

### The Hash Chain Ledger
Each pipeline stage appends an immutable entry to `ledger.jsonl` containing:
- Stage name and tool version
- SHA-256 digests of all inputs and outputs
- `prev_hash` chaining each record to the preceding step

The head of this chain is recorded in `manifest.json` and signed with an Ed25519 private key.

### Verification Commands

**1. One-Screen Market Readiness Verdict**
```bash
uv run actis verdict
```
Summarizes market entry blockers (mapped to CRA articles), active reporting clocks, and deduplicated package upgrade recommendations.

**2. Verify Evidence Integrity and Signatures**
```bash
uv run actis key export-public trusted-pandax-key.pem
uv run actis verify --trusted-key trusted-pandax-key.pem
```
Recomputes all file digests, re-evaluates the hash chain, and validates the Ed25519 digital signature against the trusted public key.

**3. Test Anti-Tampering Detection**
```bash
uv run actis tamper --target sbom.cdx.json
uv run actis verify --trusted-key trusted-pandax-key.pem
```
Flipping a single byte in any output breaks the file digest, which breaks the ledger hash chain, causing verification to fail and pinpointing the exact modified stage.

**4. Verify Against Live Upstream Feeds**
```bash
uv run actis verify --trusted-key trusted-pandax-key.pem --online
```
Re-queries OSV.dev and CISA KEV to prove the recorded advisory set matches upstream data.

**5. Independent Offline Verifier**
Auditors and regulators can inspect evidence bundles without installing Actis:
```bash
# Available under apps/verifier
actis-verify evidence.zip --trusted-key trusted-actis-key.pem
```

---

## 4. Regulatory Compliance and Honest Reporting

Actis adheres strictly to the legal text of Regulation (EU) 2024/2847.

### Honest Documentation
- **No Fabricated Evidence**: Annex VII items are classified as **machine-derived**, **manufacturer-attested**, or **MANUFACTURER INPUT REQUIRED** (highlighted in red boxes). Product photographs (item 1(c)), user instructions (item 1(d)), system architecture (item 2(a)), and security test reports are never synthesized.
- **Automated DoC Blocker**: The Annex V Declaration of Conformity is automatically blocked while unresolved actively exploited vulnerabilities remain, fulfilling Annex I Part I(2)(a) requirements ("without known exploitable vulnerabilities").

### Statutory Reporting Clocks (Article 14)
When an actively exploited vulnerability or severe incident is detected, Actis arms statutory countdowns:
- **24-Hour Early Warning**: Prepares initial alert drafts indicating suspected malicious exploitation or cross-border impact.
- **72-Hour Vulnerability Notification**: Drafts incident assessments, initial remediation steps, and sensitivity markings.
- **14-Day Final Report**: Compiles full root-cause analysis, patch links, and proof of corrective measures.

To simulate statutory clocks under accelerated time:
```bash
uv run actis clock --speed 1800
```

---

## 5. Context-Aware Analysis and Continuous Monitoring

### Continuous Monitoring
Register an artifact or SBOM once to monitor for newly disclosed vulnerabilities:
```powershell
uv run actis monitor add "Product release" .\product.zip --every-minutes 360
uv run actis monitor watch
```
- `actis monitor list`: Inspects source freshness and scheduled check windows.
- `actis monitor alerts`: Emits alerts for new, modified, or resolved advisories. Failed upstream checks are marked incomplete rather than assuming vulnerabilities were resolved.

### Approved Runtime Telemetry
Software inventories show what is packaged, but not what is executed in production. Actis accepts audited runtime observations (`pandax/runtime-telemetry/v1`):
```powershell
uv run actis telemetry validate .\runtime-telemetry.json
uv run actis scan .\product.zip --telemetry .\runtime-telemetry.json
```
Signals include `component_loaded`, `component_executed`, `network_exposed`, and `feature_enabled`. Raw logs, hostnames, IPs, and unhashed identifiers are rejected to prevent sensitive data leakage.

### Vendor Advisories and Backported Fixes
Distribution packages (Debian, Ubuntu, Alpine, RHEL) frequently backport security patches without bumping upstream version numbers. Generic scanners trigger false positives on these packages. Authorized security teams can register reviewed vendor intelligence:
```powershell
uv run actis advisory validate .\vendor-intelligence.json
uv run actis advisory install .\vendor-intelligence.json
uv run actis advisory status
```
Actis binds decisions to exact Package URLs and preserves conflicting upstream advisories in the audit ledger for reviewer verification.

### Product Exposure Analysis
Combines build configurations, exposed ports, dependency chains, and runtime telemetry:
```powershell
uv run actis exposure validate .\exposure-context.json
uv run actis scan .\product.zip --exposure-context .\exposure-context.json
```
Documents whether evidence supports reachability, non-reachability, or remains inconclusive.

---

## 6. Empirical Validation and Real-World Scenarios

### Validation Against Ground-Truth CVEs
To evaluate vulnerability detection without synthetic demo bias, `tools/evaluate.py` scans real Apache Struts distributions against published vendor security bulletins, with Grype as an independent control:

```bash
uv run python tools/evaluate.py
```

| Target Distribution | Scope | Findings | KEV | Grype Agreement |
|---|---|---|---|---|
| Struts 2.5.12 Full (93 JARs) | Includes `struts2-rest-plugin` | 158 | 5 | 157/157 CVEs (100%) |
| Struts 2.5.12 Minimal (8 JARs) | Excludes `struts2-rest-plugin` | 22 | 2 | 22/22 (100%) |
| Struts 2.5.33 Minimal (Dec 2023) | Differential control release | 9 | 0 | 9/9 (100%) |

**Key Ground-Truth Verifications:**
- **CVE-2018-11776** (KEV) is present in both 2.5.12 packages (`struts2-core` is common to both).
- **CVE-2017-9805** (KEV) is detected in the full package and **correctly absent from the minimal package**, because `struts2-rest-plugin` is omitted.
- Neither vulnerability appears in 2.5.33, where both were patched upstream.

### Real-World Release Scenarios
Actis supports five pre-configured release scenarios covering real server binaries, firmware images, and source releases:
```bash
uv run actis compare list
```
Includes pre- and post-patch comparisons for **Apache Tomcat** (CVE-2025-24813), **OpenWrt** rootfs images, **curl**, and **OpenSSL**. See the [Release Scenarios Guide](release-scenarios.md).

---

## 7. Architectural Decisions and Scope Trade-offs

| Proposed Architecture Component | Decision | Technical Rationale |
|---|---|---|
| Firecracker microVM Sandbox | Replaced | Syft parses package metadata and never executes binaries; kernel virtualization defends against non-existent threats. Replaced with strict zip-slip and decompression limits. |
| Temporal.io Cluster | Replaced | A heavyweight distributed workflow engine is unnecessary for tracking three statutory timestamps. A structured JSON state file guarantees durability without operational complexity. |
| LIEF Binary Reachability Analysis | Cut | Sound static reachability analysis remains an unsolved research problem. Speculative `not_affected` statuses risk non-compliance. |
| CSAF 2.0 | Replaced with CycloneDX VEX | CRA mandates machine-readable SBOMs; using CycloneDX for both SBOM and VEX unifies the data model. |
| pyHanko PAdES-B-LTA + Cloud KMS | Deferred | Qualified digital signatures require eIDAS trust providers; local self-signed PAdES provides no greater legal certainty than Ed25519. |
| S3 Object Lock (WORM) | Replaced with Local Hash Ledger | Cloud WORM storage is a deployment flag; a local cryptographic hash chain allows offline proof of tamper resistance. |
| ENISA Browser Extension / Auto-Submit | Cut | The ENISA single reporting platform is scheduled for late 2026. Filings are generated with field-level Article 14 citations for manual sign-off. |
| NVD API Feeds | Replaced with OSV.dev + EPSS | NVD API rate limits and key requirements introduce failure points. OSV provides exact PURL queries; EPSS provides exploit probability. |

---

## 8. Known Limitations and Boundaries

1. **Reachability Analysis**: Non-KEV findings default to `in_triage`; automated reachability suppression is intentionally not performed.
2. **Legal Identity**: Ed25519 bundle signatures authenticate the signing installation and configuration, not a natural or legal person.
3. **PDF Validation**: PDF/A-2b output is generated via Typst compilation; external veraPDF validation is not embedded.
4. **Archive Support**: Firmware rootfs tarballs, ZIPs, and JARs are unpacked; raw squashfs and UBIFS partition images require extraction prior to scanning.
5. **CRA Risk Classification**: Product risk tiering is declared by the manufacturer through the CRA wizard or configuration, not derived automatically from code.

---

## 9. Codebase Layout

```text
apps/engine/pandax/
  ├── cli.py                     # Typer CLI commands (scan, verify, clock, verdict)
  ├── pipeline.py                # Core sequential pipeline execution
  ├── events.py                  # SSE event streaming interface
  ├── evidence.py                # Ledger hashing and Ed25519 signing
  ├── feeds.py                   # OSV.dev, CISA KEV, and EPSS feed client
  ├── stages/
  │   ├── ingest.py              # Archive validation and decompression limits
  │   ├── sbom.py                # Syft invocation and CycloneDX/SPDX normalization
  │   ├── match.py               # Exact purl vulnerability matching
  │   ├── triage.py             # KEV and EPSS exploitability classification
  │   ├── clock.py               # Article 14 statutory filing timers
  │   └── dossier.py             # Typst PDF/A compilation
  ├── templates/*.typ            # Annex VII and Annex V Typst templates
  └── server.py                  # FastAPI server for local dashboard integration
apps/dashboard/                  # Production React + Vite web workspace
apps/verifier/                   # Independent zero-dependency offline bundle verifier
fixtures/                        # Reference SBOMs and SmartHub SH-100 demo package
tools/bootstrap.py               # Pinned Syft binary downloader and test builder
workspace/                       # Local execution outputs, ledger runs, and cache
```

---

## 10. Further Documentation

- [Release Scenarios Guide](release-scenarios.md) — Comparison tests across Apache Tomcat, OpenWrt, curl, and OpenSSL
- [Windows Collector Guide](windows-collector.md) — Customer-side minimal artifact collection
- [Private Beta Scope & Gates](private-beta-scope.md) — Acceptance gates and operational boundaries
- [Zero-Cost Delivery Policy](private-beta-delivery.md) — Access terms and provider boundaries
