"""S4 TRIAGE - separate "known vulnerable" from "actively exploited".

This is the stage that decides whether a manufacturer has a paperwork problem
or a 24-hour statutory deadline. CRA Article 14(1) is triggered by an
"actively exploited vulnerability", and CISA KEV is the closest public,
machine-readable expression of that fact.

Output is a CycloneDX 1.6 VEX document, kept deliberately separate from the
SBOM: the component inventory is fixed at release, exploitation status changes
daily.

Known gap, stated rather than papered over: without reachability analysis
nothing here is marked `not_affected`. Non-KEV findings stay `in_triage`,
awaiting human judgement. A wrong suppression is worse than no suppression -
it is mis-sold compliance.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid

from .. import events as ev
from ..context import CACHE_DIR, RunContext
from ..evidence import sha256_file
from ..feeds import EPSS_URL, KEV_URL, FeedError, Feeds

STAGE = "S4 TRIAGE"
TRIAGE_COVERAGE_SCHEMA = "pandax/triage-source-coverage/v1"


class TriageCoverageError(RuntimeError):
    """A mandatory exploitation source failed, so the run cannot seal."""

# CycloneDX severity vocabulary is lowercase.
CDX_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "unknown",
}


def _method(vector: str) -> str:
    if vector.startswith("CVSS:3.1"):
        return "CVSSv31"
    if vector.startswith("CVSS:3"):
        return "CVSSv3"
    if vector.startswith("CVSS:4"):
        return "CVSSv4"
    return "other"


def build_vex(ctx: RunContext) -> dict:
    """CycloneDX 1.6 VEX: one entry per finding, pointing at SBOM bom-refs."""
    vulnerabilities = []
    for finding in ctx.findings:
        ratings = []
        if finding.cvss_vector:
            ratings.append(
                {
                    "source": {"name": "OSV"},
                    "method": _method(finding.cvss_vector),
                    "vector": finding.cvss_vector,
                    "severity": CDX_SEVERITY.get(finding.severity, "unknown"),
                }
            )
        if finding.epss:
            ratings.append(
                {
                    "source": {"name": "FIRST EPSS"},
                    "method": "other",
                    "score": round(finding.epss, 6),
                }
            )

        if finding.reachability == "reachable" and finding.reachability_evidence.strip():
            analysis = {
                "state": "exploitable",
                "detail": (
                    "Product-specific evidence records the affected component as reachable: "
                    + finding.reachability_evidence.strip()
                    + "."
                    + (
                        " The CVE is also listed in the CISA Known Exploited "
                        "Vulnerabilities catalogue."
                        if finding.kev
                        else ""
                    )
                ),
            }
        else:
            kev_detail = (
                "The CVE is listed in the CISA Known Exploited Vulnerabilities "
                "catalogue, which is an urgent exploitation signal but does not "
                "by itself prove reachability in this product. "
                if finding.kev
                else ""
            )
            telemetry_detail = (
                f" Approved runtime evidence contains {len(finding.runtime_evidence)} "
                "observation(s), but PandaX has not converted those observations into "
                "a reachability or reporting decision."
                if finding.runtime_evidence
                else ""
            )
            analysis = {
                "state": "in_triage",
                "detail": (
                    kev_detail
                    + "The component is recorded as "
                    + f"{finding.affectedness or 'unknown'} and product reachability is "
                    + f"{finding.reachability or 'unknown'}. No not_affected "
                    "determination is asserted."
                    + telemetry_detail
                    + " Requires manufacturer review."
                ),
            }

        entry = {
            "bom-ref": f"vuln-{finding.cve}-{finding.purl}",
            "id": finding.cve,
            "source": {
                "name": finding.source,
                "url": finding.source_url or f"https://osv.dev/vulnerability/{finding.osv_id}",
            },
            "description": finding.summary,
            "affects": [{"ref": finding.bom_ref}],
            "analysis": analysis,
            "properties": [
                {"name": "pandax:coverage-status", "value": finding.coverage_status},
                {"name": "pandax:affectedness", "value": finding.affectedness},
                {"name": "pandax:kev-signal", "value": str(finding.kev).lower()},
                {"name": "pandax:kev-check-status", "value": finding.kev_check_status},
                {"name": "pandax:reachability", "value": finding.reachability},
                {
                    "name": "pandax:runtime-evidence-status",
                    "value": finding.runtime_evidence_status,
                },
            ],
        }
        if finding.applicability:
            entry["analysis"]["detail"] += " " + finding.applicability
        if ratings:
            entry["ratings"] = ratings
        if finding.fixed_version:
            entry["recommendation"] = (
                f"Upgrade {finding.component} to {finding.fixed_version} or later."
            )
        vulnerabilities.append(entry)

    product = ctx.product.get("product", {})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": dt.datetime.now(dt.timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "pandax",
                        "version": "0.1.0",
                    }
                ]
            },
            "component": {
                "type": "device",
                "name": str(product.get("name", "product")),
                "version": str(product.get("version", "0.0.0")),
            },
        },
        "vulnerabilities": vulnerabilities,
    }


def run(ctx: RunContext, feeds: Feeds | None = None) -> ev.Stream:
    yield ev.start(STAGE, "checking CISA KEV and EPSS")

    owned = feeds is None
    feeds = feeds or Feeds(CACHE_DIR)
    checked_at = ev.now_iso()
    kev_error = ""
    epss_error = ""
    kev: dict = {}
    epss: dict[str, float] = {}
    try:
        try:
            kev = feeds.kev()
        except FeedError as exc:
            kev_error = str(exc)
            yield ev.log(STAGE, f"CISA KEV check failed: {kev_error}", ev.ALERT_LVL)
        else:
            yield ev.log(
                STAGE,
                f"CISA KEV: {len(kev):,} entries (released {feeds.kev_released()[:10]})",
            )
        try:
            epss = feeds.epss({f.cve for f in ctx.findings})
        except FeedError as exc:
            epss_error = str(exc)
    finally:
        if owned:
            feeds.close()

    ctx.tool_versions["cisa_kev"] = feeds.kev_released()[:10] or "unknown"
    ctx.tool_versions["epss"] = "first.org/data/v1"
    kev_status = "failed" if kev_error else "completed"
    epss_status = (
        "failed"
        if epss_error
        else getattr(feeds, "last_epss_status", "completed")
    )
    epss_errors = list(getattr(feeds, "last_epss_errors", []))
    if epss_error:
        epss_errors.append(epss_error)

    for finding in ctx.findings:
        finding.epss = epss.get(finding.cve, 0.0)
        finding.kev = False
        finding.kev_date_added = ""
        finding.kev_action = ""
        finding.kev_check_status = kev_status
        finding.kev_source_url = KEV_URL
        finding.kev_checked_at = checked_at
        finding.epss_check_status = epss_status
        finding.epss_source_url = EPSS_URL
        finding.epss_checked_at = checked_at
        entry = kev.get(finding.cve)
        if entry:
            finding.kev = True
            finding.kev_date_added = entry.get("dateAdded", "")
            finding.kev_action = entry.get("requiredAction", "")

    hits = ctx.kev_findings
    yield ev.metric(STAGE, "EPSS scores resolved", len(epss))

    if hits:
        yield ev.alert(
            STAGE,
            f">> {len(hits)} ACTIVELY EXPLOITED - CRA Art.14 applies",
            count=len(hits),
        )
        yield ev.table(
            STAGE,
            "Actively exploited",
            ["CVE ID", "Package", "Version", "EPSS", "Severity"],
            [
                [
                    f.cve,
                    f.component,
                    f.version,
                    f"{f.epss:.5f}",
                    f.severity,
                ]
                for f in sorted(hits, key=lambda f: -f.epss)
            ],
            ev.ALERT_LVL,
        )
    else:
        yield ev.log(STAGE, "no actively exploited vulnerabilities found", ev.GOOD)

    vex = build_vex(ctx)
    vex_path = ctx.path("findings.cdx-vex.json")
    vex_path.write_text(json.dumps(vex, indent=2), encoding="utf-8")

    triage_coverage = {
        "schema": TRIAGE_COVERAGE_SCHEMA,
        "generated": checked_at,
        "checks": [
            {
                "source": "CISA Known Exploited Vulnerabilities",
                "source_url": KEV_URL,
                "status": kev_status,
                "checked_at": checked_at,
                "query": {"kind": "catalogue", "value": "all entries"},
                "result_count": len(kev),
                "reason": kev_error or "Catalogue loaded successfully.",
            },
            {
                "source": "FIRST EPSS",
                "source_url": EPSS_URL,
                "status": epss_status,
                "checked_at": checked_at,
                "query": {
                    "kind": "cve set",
                    "value": sorted({finding.cve for finding in ctx.findings}),
                },
                "result_count": len(epss),
                "reason": (
                    "; ".join(epss_errors)
                    if epss_errors
                    else (
                        "No CVEs required an EPSS query."
                        if epss_status == "unscanned"
                        else "EPSS query completed."
                    )
                ),
            },
        ],
    }
    triage_coverage_path = ctx.path("triage-coverage.json")
    triage_coverage_path.write_text(
        json.dumps(triage_coverage, indent=2), encoding="utf-8"
    )

    # The enriched set is a NEW file: S3 owns findings.osv.json and its
    # recorded digest must stay valid, so nothing here overwrites it.
    findings_path = ctx.path("findings.json")
    findings_path.write_text(
        json.dumps([f.as_dict() for f in ctx.findings], indent=2), encoding="utf-8"
    )

    states: dict[str, int] = {}
    for entry in vex["vulnerabilities"]:
        state = entry["analysis"]["state"]
        states[state] = states.get(state, 0) + 1
    yield ev.metric(
        STAGE, "VEX states", ", ".join(f"{k}={v}" for k, v in sorted(states.items()))
    )
    yield ev.artifact(
        STAGE, ctx.ledger.rel(vex_path), sha256_file(vex_path), "CycloneDX 1.6 VEX"
    )

    ctx.ledger.append(
        stage="S4_TRIAGE",
        tool="cisa-kev+epss",
        tool_version=ctx.tool_versions["cisa_kev"],
        inputs=[ctx.ledger.ref(ctx.path("findings.matched.json"))]
        + (
            [ctx.ledger.ref(ctx.telemetry_assessments_path)]
            if ctx.telemetry_assessments_path is not None
            else []
        ),
        outputs=[
            ctx.ledger.ref(vex_path),
            ctx.ledger.ref(findings_path),
            ctx.ledger.ref(triage_coverage_path),
        ],
        params={
            "kev_entries": len(kev),
            "epss_resolved": len(epss),
            "coverage_schema": TRIAGE_COVERAGE_SCHEMA,
        },
    )
    if kev_error:
        raise TriageCoverageError(kev_error)
    yield ev.done(
        STAGE,
        f"{len(hits)} actively exploited, {len(ctx.findings) - len(hits)} in triage",
        ev.ALERT_LVL if hits else ev.GOOD,
    )
