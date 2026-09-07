"""S3 MATCH - resolve SBOM components to known vulnerabilities via OSV.dev.

Matching is by Package URL, which is exact: pkg:npm/jquery@3.4.0 either falls
inside an advisory's affected range or it does not. That is what keeps this
free of the name-collision false positives that plague CPE-based matching.
"""

from __future__ import annotations

import json

from .. import events as ev
from ..context import CACHE_DIR, Finding, RunContext
from ..evidence import sha256_file
from ..feeds import Feeds, severity_from_vector

STAGE = "S3 MATCH"


def _cvss_vector(advisory: dict) -> str:
    for entry in advisory.get("severity") or []:
        if entry.get("type", "").startswith("CVSS") and entry.get("score"):
            return entry["score"]
    return ""


def _fixed_version(advisory: dict, purl: str) -> str:
    """First 'fixed' event OSV records for this package, if any."""
    base = purl.split("@")[0]
    for affected in advisory.get("affected") or []:
        pkg_purl = (affected.get("package") or {}).get("purl", "")
        if pkg_purl and not base.startswith(pkg_purl.split("@")[0]):
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    return str(event["fixed"])
    return ""


def run(ctx: RunContext, feeds: Feeds | None = None) -> ev.Stream:
    yield ev.start(STAGE, "matching components against OSV.dev")

    owned = feeds is None
    feeds = feeds or Feeds(CACHE_DIR)
    ctx.tool_versions["osv"] = "api.osv.dev/v1"

    purls = [c["purl"] for c in ctx.components]
    by_purl = {c["purl"]: c for c in ctx.components}
    yield ev.log(STAGE, f"POST /v1/querybatch with {len(purls)} package URLs")

    try:
        hits = feeds.query_purls(purls)
        affected = {p: ids for p, ids in hits.items() if ids}
        yield ev.metric(STAGE, "components affected", f"{len(affected)}/{len(purls)}")

        unique_ids = sorted({vid for ids in hits.values() for vid in ids})
        yield ev.log(STAGE, f"resolving {len(unique_ids)} advisories (cached on disk)")

        advisories = {vid: feeds.vuln_detail(vid) for vid in unique_ids}

        findings: list[Finding] = []
        for purl, ids in hits.items():
            comp = by_purl[purl]
            for vid in ids:
                adv = advisories[vid]
                cves = [a for a in adv.get("aliases", []) if a.startswith("CVE-")]
                vector = _cvss_vector(adv)
                for cve in cves or [vid]:
                    findings.append(
                        Finding(
                            cve=cve,
                            osv_id=vid,
                            purl=purl,
                            component=comp["name"],
                            version=comp["version"],
                            summary=(adv.get("summary") or "").strip(),
                            cvss_vector=vector,
                            severity=severity_from_vector(vector),
                            fixed_version=_fixed_version(adv, purl),
                            bom_ref=comp.get("bom_ref", purl),
                        )
                    )
    finally:
        if owned:
            feeds.close()

    # Native vendor rules are recorded separately; OSV output keeps its meaning.
    osv_path = ctx.path("findings.osv.json")
    osv_path.write_text(json.dumps([f.as_dict() for f in findings], indent=2), encoding="utf-8")
    from ..native import assess, findings as native_findings
    assessments = assess(ctx.native_inventory)
    vendor_path = ctx.path("native-assessments.json")
    vendor_path.write_text(json.dumps(assessments, indent=2), encoding="utf-8")
    findings.extend(native_findings(assessments))
    yield ev.log(STAGE, f"vendor supplement: {len(assessments)} native determinations (bounded CVE coverage)")

    # One row per (CVE, component): the same CVE can hit several components.
    unique: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        unique.setdefault((finding.cve, finding.purl), finding)
    ctx.findings = sorted(
        unique.values(), key=lambda f: (f.component, f.cve), reverse=False
    )

    out_path = ctx.path("findings.matched.json")
    out_path.write_text(
        json.dumps([f.as_dict() for f in ctx.findings], indent=2), encoding="utf-8"
    )

    by_severity: dict[str, int] = {}
    for finding in ctx.findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

    yield ev.metric(STAGE, "vulnerabilities", len(ctx.findings))
    yield ev.metric(
        STAGE,
        "by severity",
        ", ".join(
            f"{k}={by_severity[k]}"
            for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
            if k in by_severity
        ),
    )
    yield ev.artifact(STAGE, ctx.ledger.rel(out_path), sha256_file(out_path))

    ctx.ledger.append(
        stage="S3_MATCH",
        tool="osv.dev",
        tool_version="v1",
        inputs=([ctx.ledger.ref(ctx.sbom_path)] if ctx.sbom_path else []) +
               [ctx.ledger.ref(ctx.path("native-inventory.json"))],
        outputs=[ctx.ledger.ref(out_path), ctx.ledger.ref(osv_path), ctx.ledger.ref(vendor_path)],
        params={"endpoint": "https://api.osv.dev/v1/querybatch", "purls": len(purls),
                "native_rules": "pandax.native/1", "native_coverage": "requested CVEs only"},
    )
    yield ev.done(STAGE, f"{len(ctx.findings)} vulnerabilities matched")
