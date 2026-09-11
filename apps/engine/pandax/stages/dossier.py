"""S6 DOSSIER - the Annex VII technical documentation and Annex V declaration.

Structure follows Regulation (EU) 2024/2847 exactly: Annex VII has eight
numbered items, Annex V has eight. Each entry carries its `ref` and one of
three provenance states:

  derived         computed by this pipeline from the artifact or supplied SBOM
  attested        supplied by the manufacturer in product.yaml
  required_input  neither - rendered as a red MANUFACTURER INPUT REQUIRED box

That third state is the point. A tool that silently invents Annex VII item 1(c)
or item 6 is not selling compliance, it is selling exposure. A dossier that
visibly separates machine-generated evidence from manufacturer attestation is
both more honest and more useful to the notified body reading it.
"""

from __future__ import annotations

import datetime as dt
import json
import shutil
from pathlib import Path

from .. import events as ev
from .. import pdfa
from ..context import RunContext
from ..evidence import sha256_file

STAGE = "S6 DOSSIER"

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"

DERIVED, ATTESTED, REQUIRED = "derived", "attested", "required_input"
NEEDS_INPUT = "MANUFACTURER INPUT REQUIRED"


def _entry(ref: str, title: str, status: str, value: str, note: str = "") -> dict:
    return {
        "ref": ref,
        "title": title,
        "status": status,
        "value": value,
        "note": note,
    }


def _attest(ref: str, title: str, value, note: str = "") -> dict:
    """Attested if the manufacturer supplied it, otherwise flagged as required."""
    text = str(value).strip() if value else ""
    if not text:
        return _entry(ref, title, REQUIRED, NEEDS_INPUT, note)
    return _entry(ref, title, ATTESTED, text, note)


def build_dossier(ctx: RunContext) -> dict:
    product = ctx.product.get("product", {})
    manufacturer = ctx.product.get("manufacturer", {})
    handling = ctx.product.get("vulnerability_handling", {})
    sbom_origin = (
        "generated from the product artifact with Syft"
        if ctx.input_type == "artifact"
        else f"imported from {ctx.sbom_source_format} {ctx.sbom_source_version} and normalised"
    )

    ecosystems: dict[str, int] = {}
    for comp in ctx.components:
        eco = (
            comp["purl"].split("/")[0].replace("pkg:", "")
            if comp["purl"]
            else "unidentified"
        )
        ecosystems[eco] = ecosystems.get(eco, 0) + 1

    by_severity: dict[str, int] = {}
    for finding in ctx.findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

    kev_rows = [
        {
            "cve": f.cve,
            "component": f"{f.component} {f.version}",
            "severity": f.severity,
            "epss": f"{f.epss:.5f}",
            "kev_since": f.kev_date_added,
            "fix": f.fixed_version or NEEDS_INPUT,
        }
        for f in sorted(ctx.kev_findings, key=lambda f: -f.epss)
    ]
    other_rows = [
        {
            "cve": f.cve,
            "component": f"{f.component} {f.version}",
            "severity": f.severity,
            "epss": f"{f.epss:.5f}",
            "fix": f.fixed_version or "-",
        }
        for f in sorted(ctx.findings, key=lambda f: (f.severity, f.component))
        if not f.kev
    ]

    versions_line = ", ".join(
        f"{c['name']} {c['version']}" for c in ctx.components[:40]
    )

    # --- Annex VII: content of the technical documentation -------------------
    annex_vii = [
        {
            "item": "1",
            "title": "General description of the product with digital elements",
            "entries": [
                _attest("1(a)", "Intended purpose", product.get("intended_purpose")),
                _entry(
                    "1(b)",
                    "Versions of software affecting compliance",
                    DERIVED,
                    f"Product version {product.get('version', 'unknown')}. "
                    f"{len(ctx.components)} software components inventoried: "
                    f"{versions_line}",
                    f"Derived from the CycloneDX 1.6 SBOM attached at item 8; {sbom_origin}.",
                ),
                _entry(
                    "1(c)",
                    "Photographs or illustrations of external features, marking "
                    "and internal layout (hardware products)",
                    REQUIRED,
                    NEEDS_INPUT,
                    "Cannot be derived from a software artifact.",
                ),
                _entry(
                    "1(d)",
                    "User information and instructions as set out in Annex II",
                    REQUIRED,
                    NEEDS_INPUT,
                    "Annex II user documentation is authored by the manufacturer.",
                ),
            ],
        },
        {
            "item": "2",
            "title": "Design, development, production and vulnerability handling",
            "entries": [
                _entry(
                    "2(a)",
                    "Design and development information, system architecture",
                    REQUIRED,
                    NEEDS_INPUT,
                    "Architecture description is not recoverable from a build "
                    "artifact and must be authored.",
                ),
                _entry(
                    "2(b)",
                    "Vulnerability handling processes, including the SBOM, the "
                    "coordinated vulnerability disclosure policy, evidence of a "
                    "reporting contact address, and secure update distribution",
                    DERIVED,
                    (
                        f"SBOM: CycloneDX 1.6, {len(ctx.components)} components "
                        f"({', '.join(f'{k}={v}' for k, v in sorted(ecosystems.items()))}). "
                        f"CVD policy: {handling.get('cvd_policy_url') or NEEDS_INPUT}. "
                        f"Reporting contact: {handling.get('contact_address') or NEEDS_INPUT}. "
                        f"security.txt: {handling.get('security_txt_url') or NEEDS_INPUT}. "
                        f"Secure update distribution: "
                        f"{handling.get('secure_update_mechanism') or NEEDS_INPUT}"
                    ),
                    f"SBOM {sbom_origin}; policy URLs and update mechanism "
                    "are attested by the manufacturer when supplied.",
                ),
                _entry(
                    "2(c)",
                    "Production and monitoring processes and their validation",
                    REQUIRED,
                    NEEDS_INPUT,
                    "Continuous SBOM re-scanning covers part of monitoring; the "
                    "production process description must be authored.",
                ),
            ],
        },
        {
            "item": "3",
            "title": "Assessment of the cybersecurity risks (Article 13)",
            "entries": [
                _entry(
                    "3",
                    "Risk assessment, including applicability of Annex I Part I",
                    DERIVED,
                    (
                        f"{len(ctx.findings)} known vulnerabilities affect "
                        f"{len({f.purl for f in ctx.findings})} of "
                        f"{len(ctx.components)} components. "
                        f"{len(ctx.kev_findings)} are listed in the CISA KEV "
                        "catalogue as actively exploited. Annex I Part I(2)(a) "
                        "requires products to be made available without known "
                        "exploitable vulnerabilities; the actively exploited "
                        "findings below are therefore blocking for placement on "
                        "the market until remediated."
                    ),
                    "Automated component-level assessment. Product-level threat "
                    "modelling remains a manufacturer responsibility.",
                ),
            ],
        },
        {
            "item": "4",
            "title": "Information used to determine the support period (Art.13(8))",
            "entries": [
                _attest(
                    "4",
                    "Support period and its rationale",
                    (
                        f"{product.get('support_period_months')} months. "
                        f"{product.get('support_period_rationale', '')}"
                        if product.get("support_period_months")
                        else ""
                    ),
                ),
            ],
        },
        {
            "item": "5",
            "title": "Harmonised standards, common specifications or certification",
            "entries": [
                _entry(
                    "5",
                    "Standards applied, or description of solutions adopted",
                    DERIVED,
                    (
                        "No harmonised standards for Regulation (EU) 2024/2847 have "
                        "been cited in the Official Journal of the European Union as "
                        "at the date of this document. Conformity is therefore "
                        "demonstrated by describing the solutions adopted: automated "
                        f"CycloneDX 1.6 SBOM processing ({sbom_origin}), continuous vulnerability "
                        "monitoring against OSV.dev and the CISA KEV catalogue, and "
                        "the secure update mechanism described at item 2(b)."
                    ),
                    "Manufacturer must re-verify once harmonised standards are "
                    "published.",
                ),
            ],
        },
        {
            "item": "6",
            "title": "Reports of the tests carried out to verify conformity",
            "entries": [
                _entry(
                    "6",
                    "Automated vulnerability-handling test evidence",
                    DERIVED,
                    (
                        f"Run {ctx.run_id}: composition analysis over "
                        f"{ctx.matchable_components} of {len(ctx.components)} "
                        "components with usable package URLs against OSV.dev, "
                        f"CISA KEV and FIRST EPSS. Results attached as "
                        "findings.cdx-vex.json (CycloneDX 1.6 VEX). Every input "
                        "and output is hash-chained in ledger.jsonl and sealed by "
                        "an Ed25519 signature over manifest.json."
                    ),
                    "Covers Annex I Part II vulnerability handling only. Testing "
                    "against Annex I Part I product properties (authentication, "
                    "encryption, attack surface) is NOT covered and must be "
                    "supplied by the manufacturer.",
                ),
                _entry(
                    "6b",
                    "Test reports for Annex I Part I product properties",
                    REQUIRED,
                    NEEDS_INPUT,
                    "Penetration testing and secure-configuration evidence.",
                ),
            ],
        },
        {
            "item": "7",
            "title": "Copy of the EU declaration of conformity",
            "entries": [
                _entry(
                    "7",
                    "EU declaration of conformity (Annex V)",
                    DERIVED,
                    "Attached as a separate document: EU_Declaration_of_Conformity.pdf",
                ),
            ],
        },
        {
            "item": "8",
            "title": "Software bill of materials",
            "entries": [
                _entry(
                    "8",
                    "SBOM, available on reasoned request from a market "
                    "surveillance authority",
                    DERIVED,
                    (
                        f"sbom.cdx.json - CycloneDX 1.6, {len(ctx.components)} "
                        "components, covering top-level and transitive "
                        "dependencies across "
                        f"{', '.join(sorted(ecosystems))}."
                    ),
                ),
            ],
        },
    ]

    # --- Annex V: EU declaration of conformity -------------------------------
    annex_v = [
        _attest(
            "1",
            "Name, type and unique identification of the product",
            f"{product.get('name', '')} - {product.get('type', '')} "
            f"(ID {product.get('unique_id', '')}, version {product.get('version', '')})"
            if product.get("name")
            else "",
        ),
        _attest(
            "2",
            "Name and address of the manufacturer",
            f"{manufacturer.get('legal_name', '')}, {manufacturer.get('address', '')}"
            if manufacturer.get("legal_name")
            else "",
        ),
        _entry(
            "3",
            "Statement of sole responsibility",
            DERIVED,
            "This EU declaration of conformity is issued under the sole "
            "responsibility of the manufacturer.",
        ),
        _attest(
            "4",
            "Object of the declaration",
            f"{product.get('name', '')} version {product.get('version', '')}, "
            f"identified by {product.get('unique_id', '')}"
            if product.get("name")
            else "",
        ),
        _entry(
            "5",
            "Conformity statement",
            DERIVED if not ctx.kev_findings else REQUIRED,
            (
                "The object of the declaration described above is in conformity "
                "with Regulation (EU) 2024/2847 of the European Parliament and of "
                "the Council on horizontal cybersecurity requirements for products "
                "with digital elements."
                if not ctx.kev_findings
                else (
                    f"CANNOT BE DECLARED. {len(ctx.kev_findings)} actively "
                    "exploited vulnerabilities are present. Annex I Part I(2)(a) "
                    "requires the product to be made available without known "
                    "exploitable vulnerabilities. Remediate before signing."
                )
            ),
            "Blocked automatically while actively exploited vulnerabilities "
            "remain unremediated.",
        ),
        _entry(
            "6",
            "References to harmonised standards or common specifications",
            DERIVED,
            "None cited in the Official Journal for Regulation (EU) 2024/2847 as "
            "at the date of issue. See technical documentation item 5.",
        ),
        _entry(
            "7",
            "Notified body, conformity assessment procedure and certificate",
            DERIVED,
            (
                f"Not applicable. The product is classified as "
                f"{product.get('risk_tier', 'default')} tier and follows "
                f"{product.get('conformity_route', 'Annex VIII Part I (Module A)')}, "
                "which requires no notified body."
            ),
            "Classification is manufacturer-declared, not derived by this tool.",
        ),
        _attest(
            "8",
            "Additional information",
            (
                f"Conformity assessment: {product.get('conformity_route', '')}. "
                f"Support period: {product.get('support_period_months', '?')} months. "
                f"Coordinated vulnerability disclosure policy: "
                f"{handling.get('cvd_policy_url') or NEEDS_INPUT}. "
                f"Vulnerability reporting contact: "
                f"{handling.get('contact_address') or NEEDS_INPUT}."
            )
            if manufacturer.get("legal_name")
            else "",
            "Annex V item 8 is followed by the signature block below.",
        ),
    ]

    counts = {DERIVED: 0, ATTESTED: 0, REQUIRED: 0}
    for section in annex_vii:
        for entry in section["entries"]:
            counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    for entry in annex_v:
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1

    support_months = product.get("support_period_months")
    return {
        "generated": dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "run_id": ctx.run_id,
        "regulation": "Regulation (EU) 2024/2847 (Cyber Resilience Act)",
        # Article 28(3) requires the DoC to identify the Union legal acts with
        # their publication references; Annex VI shows the citation form.
        "regulation_reference": {
            "title": "Regulation (EU) 2024/2847 of the European Parliament and of "
            "the Council of 23 October 2024 on horizontal cybersecurity "
            "requirements for products with digital elements",
            "oj": "OJ L, 2024/2847, 20.11.2024",
            "eli": "http://data.europa.eu/eli/reg/2024/2847/oj",
        },
        # Annex VIII Part I(4.2) and Article 13(13): kept at the disposal of the
        # market surveillance authorities for 10 years or the support period,
        # whichever is longer.
        "retention": {
            "years": 10,
            "support_period_months": support_months or 0,
            "statement": (
                "This declaration and the technical documentation are kept at the "
                "disposal of the market surveillance authorities for 10 years "
                "after the product with digital elements has been placed on the "
                "market, or for the support period"
                + (f" of {support_months} months" if support_months else "")
                + ", whichever is longer."
            ),
        },
        # Article 30(1): for products in the form of software the CE marking is
        # affixed to the declaration of conformity or the accompanying website.
        "ce_marking": {
            "applies": True,
            "notified_body_number": "",  # Module A involves no notified body
            "placement": (
                "Affixed to this EU declaration of conformity in accordance with "
                "Article 30(1). Where the product is hardware, the CE marking "
                "must also be affixed visibly, legibly and indelibly to the "
                "product itself, at a height of at least 5 mm."
            ),
            "form": (
                "The CE marking must take the form set out in Annex II to "
                "Regulation (EC) No 765/2008, per Article 29."
            ),
            # The graphic form of the CE marking is prescribed by law. Drawing an
            # approximation would risk affixing a non-conforming mark, so the
            # official artwork is supplied by the manufacturer or left blank.
            "artwork": str(ctx.product.get("manufacturer", {}).get("ce_marking_file", "")),
        },
        "doc_url": str(handling.get("declaration_url", "")),
        "product": {
            "name": str(product.get("name", "")),
            "type": str(product.get("type", "")),
            "version": str(product.get("version", "")),
            "unique_id": str(product.get("unique_id", "")),
            "risk_tier": str(product.get("risk_tier", "")),
            "conformity_route": str(product.get("conformity_route", "")),
        },
        "manufacturer": {
            "legal_name": str(manufacturer.get("legal_name", "")),
            "address": str(manufacturer.get("address", "")),
            "signatory_name": str(manufacturer.get("signatory_name", "")),
            "signatory_function": str(manufacturer.get("signatory_function", "")),
            "place_of_issue": str(manufacturer.get("place_of_issue", "")),
        },
        "summary": {
            "components": len(ctx.components),
            "input_type": ctx.input_type,
            "sbom_source_format": ctx.sbom_source_format,
            "sbom_source_version": ctx.sbom_source_version,
            "matchable_components": ctx.matchable_components,
            "skipped_components": ctx.skipped_components,
            "ecosystems": ", ".join(
                f"{k}={v}" for k, v in sorted(ecosystems.items())
            ),
            "vulnerabilities": len(ctx.findings),
            "actively_exploited": len(ctx.kev_findings),
            "by_severity": ", ".join(
                f"{k}={by_severity[k]}"
                for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
                if k in by_severity
            ),
            "derived": counts[DERIVED],
            "attested": counts[ATTESTED],
            "required_input": counts[REQUIRED],
            "sbom_sha256": sha256_file(ctx.sbom_path) if ctx.sbom_path else "",
            "vex_sha256": sha256_file(ctx.path("findings.cdx-vex.json")),
        },
        "kev_rows": kev_rows,
        "other_rows": other_rows[:60],
        "other_rows_truncated": max(0, len(other_rows) - 60),
        "annex_vii": annex_vii,
        "annex_v": annex_v,
    }


def _compile(typ_path: Path, pdf_path: Path, root: Path) -> str:
    """Compile a Typst template to PDF/A-2b. Returns '' on success, else the error."""
    import typst

    try:
        typst.compile(
            str(typ_path),
            output=str(pdf_path),
            root=str(root),
            pdf_standards=["a-2b"],
        )
        return ""
    except Exception as exc:  # typst raises a plain RuntimeError with the diagnostic
        return str(exc)


def run(ctx: RunContext) -> ev.Stream:
    yield ev.start(STAGE, "assembling Annex VII technical documentation")

    data = build_dossier(ctx)
    data_path = ctx.path("dossier.json")
    data_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    summary = data["summary"]
    yield ev.log(
        STAGE,
        f"Annex VII: 8 items, Annex V: 8 items - "
        f"{summary['derived']} derived, {summary['attested']} attested, "
        f"{summary['required_input']} require manufacturer input",
    )
    if summary["required_input"]:
        yield ev.log(
            STAGE,
            f"{summary['required_input']} fields flagged MANUFACTURER INPUT "
            "REQUIRED - not fabricated",
            ev.WARN,
        )
    if ctx.kev_findings:
        yield ev.alert(
            STAGE,
            "EU Declaration of Conformity BLOCKED - Annex I Part I(2)(a): "
            "product has known exploitable vulnerabilities",
        )

    # Templates are copied beside the data so Typst's root confinement is trivial.
    outputs = [data_path]
    reports = ctx.path("pdf-validation")
    reports.mkdir(parents=True, exist_ok=True)
    failures = []
    for template, pdf_name, label in (
        ("annex_vii.typ", "AnnexVII_Technical_Documentation.pdf", "Annex VII"),
        ("annex_v_doc.typ", "EU_Declaration_of_Conformity.pdf", "Annex V DoC"),
        # Art.13(20): the manufacturer must supply either a copy of the full
        # declaration or this simplified one, with the address of the full text.
        (
            "annex_vi_simplified.typ",
            "Simplified_EU_Declaration_of_Conformity.pdf",
            "Annex VI simplified DoC",
        ),
    ):
        src = TEMPLATES / template
        local = ctx.run_dir / template
        shutil.copy2(src, local)
        outputs.append(local)
        pdf_path = ctx.path(pdf_name)
        error = _compile(local, pdf_path, ctx.run_dir)
        if error:
            (reports / f"{pdf_path.stem}.compile.txt").write_text(error, encoding="utf-8")
            failures.append(f"{label}: compilation failed")
            yield ev.log(STAGE, f"{label} PDF failed: {error.splitlines()[0]}", ev.WARN)
            continue
        outputs.append(pdf_path)
        result = pdfa.validate_pdf(pdf_path, reports)
        if not result["compliant"]:
            failures.append(f"{label}: {result['error']}")
            yield ev.log(STAGE, f"{label} PDF/A-2b validation failed: {result['error']}", ev.WARN)
            continue
        ctx.tool_versions["verapdf"] = result["validator_version"]
        size = pdf_path.stat().st_size
        yield ev.artifact(
            STAGE,
            ctx.ledger.rel(pdf_path),
            sha256_file(pdf_path),
            f"{label}, PDF/A-2b, {size:,} bytes",
        )

    ctx.tool_versions["typst"] = _typst_version()
    outputs.extend(sorted(reports.iterdir()))

    ctx.ledger.append(
        stage="S6_DOSSIER",
        tool="typst",
        tool_version=ctx.tool_versions["typst"],
        inputs=[
            ctx.ledger.ref(ctx.path("findings.cdx-vex.json")),
            ctx.ledger.ref(ctx.sbom_path) if ctx.sbom_path else ctx.ledger.ref(data_path),
        ],
        outputs=[ctx.ledger.ref(p) for p in outputs],
        params={"pdf_standard": "a-2b", "annexes": ["VII", "V", "VI"],
                "validator": "verapdf", "validator_version": pdfa.VERSION,
                "validation_passed": not failures},
    )
    if failures:
        raise RuntimeError("Dossier not sealed: " + "; ".join(failures)
                           + f". Diagnostics: {reports}")
    yield ev.done(STAGE, "technical dossier and declaration generated")


def _typst_version() -> str:
    try:
        from importlib.metadata import version

        return version("typst")
    except Exception:
        return "unknown"
