# Actis by PandaX
### Automated, Verifiable EU Cyber Resilience Act (CRA) Compliance

Actis turns your software builds and SBOMs into **signed, tamper-evident CRA evidence bundles**—ready for auditors, regulators, and customers.

[![Live Dashboard](https://img.shields.io/badge/Live_Dashboard-actis.pandax.online-7c3aed?style=for-the-badge&logo=rocket&logoColor=white)](https://actis.pandax.online)
[![Website](https://img.shields.io/badge/Website-pandax.online-0284c7?style=for-the-badge&logo=googlechrome&logoColor=white)](https://pandax.online)
[![Technical Guide](https://img.shields.io/badge/Docs-Technical_Guide-10b981?style=for-the-badge&logo=bookstack&logoColor=white)](docs/technical-guide.md)


---

## ⚡ What it Does

- 🔍 **Identifies Real Risk:** Matches exact package URLs against OSV.dev and CISA KEV (Known Exploited Vulnerabilities).
- ⏱️ **Statutory Reporting Clocks:** Automatically tracks mandatory CRA Article 14 deadlines (24h early warning, 72h notification, 14d report).
- 📄 **Generates Technical Dossiers:** Produces Annex VII technical files and Annex V Declarations of Conformity.
- 🔒 **Cryptographically Sealed:** Records every step into a SHA-256 ledger signed with Ed25519 so anyone can verify it offline.

---

## 🖥️ The Dashboard

You can explore the live multi-product workspace at [**actis.pandax.online**](https://actis.pandax.online), or fire up the full local UI in two commands:

```bash
npm ci
uv run actis serve
```
👉 Open **[http://127.0.0.1:4175](http://127.0.0.1:4175)**

**What you can do in the UI:**
- **Live Pipeline:** Drop in an artifact or SBOM and watch the scan, triage, and cryptographic sealing stream in real time.
- **CRA Assessment Wizard:** Walk through a guided flow to classify your product’s CRA risk tier and requirements.
- **Active Clocks:** Monitor live countdown timers for reportable vulnerabilities.
- **One-Click Audit:** Visually inspect the Merkle hash chain and test tamper detection with a single click.

---

## 🚀 Quickstart (CLI)

Need quick terminal results or CI integration? Actis works with whatever you have:

### If you already have an SBOM:
```bash
uv sync --extra dev
uv run actis scan-sbom fixtures/example-sbom.cdx.json
```

### If you have a binary, JAR, or firmware ZIP:
```bash
uv sync --extra dev
uv run python tools/bootstrap.py           # First-time: downloads pinned Syft
uv run actis scan fixtures/smarthub-sh100-v2.3.1.zip
```

### Check your EU market readiness:
```bash
uv run actis verdict
```
*Gives you a clean, one-screen summary of current blockers and package upgrade recommendations.*

---

## 🛡️ Zero Compliance Theater

- **No Hallucinations:** Architecture diagrams, hardware photos, and test results are never fabricated. Missing items are honestly marked `MANUFACTURER INPUT REQUIRED`.
- **No Secret Submissions:** Article 14 reports are drafted with legal citations, but never submitted to ENISA without your sign-off.
- **Standalone Verification:** Anyone (including regulators) can verify bundles using the zero-dependency [`apps/verifier`](apps/verifier/README.md) without installing Actis.
