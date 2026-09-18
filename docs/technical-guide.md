# Actis Technical Guide

This guide explains how Actis works under the hood—how it ingests software, matches vulnerabilities, calculates CRA deadlines, and seals evidence bundles.

For quick setup and web dashboard instructions, see the [main README](../README.md).

---

## 1. How the Pipeline Works

Actis takes a product archive (ZIP, tar, JAR) or an existing SBOM, and runs it through six automated stages:

```
artifact.zip                         existing-sbom.json
   │                                      │
   ├─ S1 INGEST  unpack safely            ├─ S1 INGEST  skipped & recorded
   └─ S2 SBOM    Syft → CDX 1.6           └─ S2 SBOM    detect & normalise
                    │                              │
                    └──────────────┬───────────────┘
                                   ├─ S3 MATCH     OSV.dev (exact purl)
                                   ├─ S4 TRIAGE    CISA KEV + EPSS → CDX VEX
                                   ├─ S5 CLOCK     Article 14 statutory timers
                                   ├─ S6 DOSSIER   Annex VII & V (PDF/A-2b)
                                   └─ SEAL         SHA-256 ledger + Ed25519 signature
```

### Stage Summary

- **S1 Ingest**: Safely unpacks archives with protection against zip-slips and decompression bombs. Skipped when an SBOM is provided directly.
- **S2 SBOM Normalisation**: Uses Syft for binaries, or normalises imported CycloneDX (1.2/1.6) and SPDX (2.2/2.3) files into CycloneDX 1.6.
- **S3 Vulnerability Match**: Queries OSV.dev using exact Package URLs (`purl`). Packages without versioned PURLs are flagged as unmatchable rather than guessed.
- **S4 Triage**: Flags actively exploited vulnerabilities using CISA KEV and EPSS scores, producing a CycloneDX VEX file.
- **S5 Clocks**: Arms statutory Article 14 reporting countdowns (24h, 72h, 14d) when reportable vulnerabilities exist.
- **S6 Dossier & Seal**: Compiles Annex VII technical documentation and Annex V Declarations of Conformity into PDF/A-2b. Signs the entire run with Ed25519 and a SHA-256 audit ledger.

---

## 2. Running Scans

### Scan an Existing SBOM
Fastest option—no scanner downloads needed:
```bash
uv sync --extra dev
uv run actis scan-sbom fixtures/example-sbom.cdx.json
```

### Scan a Binary or Firmware Archive
Downloads pinned Syft on first run, then inventories and scans the artifact:
```bash
uv sync --extra dev
uv run python tools/bootstrap.py
uv run actis scan fixtures/smarthub-sh100-v2.3.1.zip
```

### SmartHub SH-100 Sample Package
The included *SmartHub SH-100 v2.3.1* package contains real, known-exploited CVEs across three ecosystems:
- **npm**: `jquery 3.4.0` (CVE-2020-11023)
- **PyPI**: `pillow 8.1.0` (CVE-2023-4863)
- **Maven**: `log4j-core 2.14.1` (CVE-2021-44228 / Log4Shell)

A test scan produces 11 components, ~102 vulnerabilities, 4 KEV findings, 4 active Article 14 clocks, 2 PDF files, and a signed bundle in `workspace/runs/`.

---

## 3. Verifying Evidence & Anti-Tamper

Every run creates an append-only hash chain (`ledger.jsonl`) signed with Ed25519 (`manifest.json`). You can verify everything independently:

```bash
# Get an instant one-screen summary of blockers and upgrade actions
uv run actis verdict

# Verify file integrity and the Ed25519 signature
uv run actis key export-public trusted-pandax-key.pem
uv run actis verify --trusted-key trusted-pandax-key.pem

# Simulate tampering: flip 1 byte in the SBOM and re-verify (catches the exact stage)
uv run actis tamper --target sbom.cdx.json
uv run actis verify --trusted-key trusted-pandax-key.pem

# Offline verification for auditors (zero Actis dependency)
actis-verify evidence.zip --trusted-key trusted-actis-key.pem
```

---

## 4. CRA Compliance & Statutory Clocks

Actis maps directly to Regulation (EU) 2024/2847 requirements:

### Honest Documentation (No Fabrication)
- **Annex VII Technical Files**: Sections are clearly marked as **machine-derived**, **manufacturer-attested**, or **MANUFACTURER INPUT REQUIRED** (red box). Photographs, instructions, and architecture diagrams are never invented.
- **Blocked DoC**: If any actively exploited vulnerability remains unfixed, the Annex V Declaration of Conformity is automatically blocked per Annex I Part I(2)(a).

### Article 14 Notification Timers
When an actively exploited vulnerability is detected, Actis starts three legal timers:
1. **24 Hours**: Early warning draft (suspected exploitation or cross-border impact).
2. **72 Hours**: Incident notification draft (severity, remediation, sensitivity markings).
3. **14 Days**: Final report draft (root cause analysis and corrective proof).

You can simulate these countdowns in fast-forward with:
```bash
uv run actis clock --speed 1800
```

---

## 5. Extra Context & Capabilities

### Continuous Monitoring
Schedule automatic rechecks as new vulnerabilities are published:
```bash
uv run actis monitor add "Product release" ./product.zip --every-minutes 360
uv run actis monitor watch
```

### Approved Runtime Telemetry
Attach verified runtime observations (`component_loaded`, `network_exposed`, etc.) to distinguish packaged code from running code without collecting private hostnames or raw logs:
```bash
uv run actis scan ./product.zip --telemetry ./runtime-telemetry.json
```

### Vendor Intelligence & Backports
Distribution packages (Debian, Ubuntu, Alpine) often backport security fixes without changing version numbers. You can apply reviewed vendor patches to eliminate false positives:
```bash
uv run actis advisory install ./vendor-intelligence.json
```

### Product Exposure Analysis
Combine build flags, open ports, and dependency paths to evaluate whether a vulnerable library is reachable:
```bash
uv run actis scan ./product.zip --exposure-context ./exposure-context.json
```

---

## 6. Real-World Evaluation

We evaluated Actis against real Apache releases with published advisories, using Grype as an independent control:

| Target | Components | Findings | KEV | Agreement with Grype |
|---|---|---|---|---|
| Struts 2.5.12 Full (93 JARs) | Includes REST plugin | 158 | 5 | 157/157 CVEs (100%) |
| Struts 2.5.12 Minimal (8 JARs) | Excludes REST plugin | 22 | 2 | 22/22 (100%) |
| Struts 2.5.33 Minimal (Dec 2023) | Differential control | 9 | 0 | 9/9 (100%) |

You can also run pre-built release comparisons across **Apache Tomcat** (CVE-2025-24813), **OpenWrt**, **curl**, and **OpenSSL**:
```bash
uv run actis compare list
```

---

## 7. Architecture Decisions

| Component | Choice | Why? |
|---|---|---|
| Sandbox | Limits, not Firecracker | Syft parses metadata without executing code. Zip-slip and size limits provide the necessary protection without VM overhead. |
| Workflow Engine | State file, not Temporal | Tracking three legal timestamps does not require a distributed cluster. A structured state file gives the same durability. |
| Reachability | Conservative triage | Static reachability is prone to false negatives. Unverified findings remain `in_triage` rather than guessing `not_affected`. |
| VEX Format | CycloneDX VEX | CRA requires machine-readable SBOMs. Using CycloneDX for both SBOM and VEX unifies the toolchain. |
| Signatures | Ed25519 | Lightweight, widely supported, and independently verifiable offline. |
| Advisory Feeds | OSV.dev + EPSS | Eliminates NVD rate limits while adding real-world exploit probability data. |

---

## 8. What Actis Does Not Do

To remain legally sound, Actis sets clear boundaries:
- It does **not** invent missing test reports, photos, or architecture diagrams.
- It does **not** guess package names when a versioned PURL is missing.
- It does **not** automatically submit Article 14 reports to ENISA without human sign-off.
- It verifies the signing system's key, not a legal individual's identity (eIDAS seal).

---

## 9. Related Guides

- [Release Scenarios Guide](release-scenarios.md) — Pre- and post-patch comparisons
- [Windows Collector Guide](windows-collector.md) — Minimal customer-side artifact collection
- [Private Beta Scope](private-beta-scope.md) — Acceptance gates and delivery policies
