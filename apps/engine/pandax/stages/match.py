"""S3 MATCH - resolve SBOM components to known vulnerabilities via OSV.dev.

Matching is by Package URL, which is exact: pkg:npm/jquery@3.4.0 either falls
inside an advisory's affected range or it does not. That is what keeps this
free of the name-collision false positives that plague CPE-based matching.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from .. import events as ev
from ..context import CACHE_DIR, Finding, RunContext
from ..evidence import sha256_file
from ..feeds import Feeds, FeedError, OSV_BATCH_URL, severity_from_vector
from .sbom import is_matchable_purl

STAGE = "S3 MATCH"
OSV_DETAIL_WORKERS = 8
COVERAGE_SCHEMA = "pandax/vulnerability-coverage/v1"
OSV_UNSUPPORTED_PURL_TYPES = {"generic", "opkg"}


class CoverageError(RuntimeError):
    """Primary vulnerability coverage was incomplete, so the run cannot seal."""


def _purl_type(purl: str) -> str:
    return purl[4:].split("/", 1)[0].casefold() if purl.startswith("pkg:") else ""


def _osv_supported(purl: str) -> bool:
    """Product policy: generic/distro PURLs need source-specific assessment."""
    return is_matchable_purl(purl) and _purl_type(purl) not in OSV_UNSUPPORTED_PURL_TYPES


def _coverage_entry(
    component: dict,
    *,
    source: str,
    source_url: str,
    status: str,
    checked_at: str,
    reason: str,
    query_value: str = "",
    result_count: int = 0,
    determinations: list[dict] | None = None,
) -> dict:
    return {
        "component_ref": component.get(
            "bom_ref", component.get("bom-ref", component.get("purl", ""))
        ),
        "component": component.get("name", ""),
        "version": component.get("version", ""),
        "purl": component.get("purl", ""),
        "source": source,
        "source_url": source_url,
        "status": status,
        "checked_at": checked_at,
        "query": {"kind": "purl", "value": query_value},
        "result_count": result_count,
        "reason": reason,
        "determinations": determinations or [],
    }


def _write_coverage(ctx: RunContext, checked_at: str, checks: list[dict]):
    summary: dict[str, int] = {}
    for check in checks:
        status = check["status"]
        summary[status] = summary.get(status, 0) + 1
    payload = {
        "schema": COVERAGE_SCHEMA,
        "generated": checked_at,
        "checks": checks,
        "summary": summary,
        "meaning": (
            "A completed check means only that the named source answered the recorded "
            "query. It is not a claim that the component or product is vulnerability-free."
        ),
    }
    path = ctx.path("coverage.json")
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    ctx.vulnerability_coverage = checks
    return path


def _cvss_vector(advisory: dict) -> str:
    for entry in advisory.get("severity") or []:
        if entry.get("type", "").startswith("CVSS") and entry.get("score"):
            return entry["score"]
    return ""


def _fixed_version(advisory: dict, purl: str) -> str:
    """First released version OSV records as fixing this package, if any.

    GIT ranges are skipped: their `fixed` events are commit hashes, not
    versions. Telling a manufacturer to "upgrade to 2444cddab2f8..." is worse
    than saying nothing, and a hash also sorts above real versions when
    picking the highest fix.
    """
    base = purl.split("@")[0]
    for affected in advisory.get("affected") or []:
        pkg_purl = (affected.get("package") or {}).get("purl", "")
        if pkg_purl and base != pkg_purl.split("@")[0]:
            continue
        for rng in affected.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue
            for event in rng.get("events") or []:
                if "fixed" in event:
                    return str(event["fixed"])
    return ""


def run(ctx: RunContext, feeds: Feeds | None = None) -> ev.Stream:
    yield ev.start(STAGE, "matching components against OSV.dev")

    owned = feeds is None
    feeds = feeds or Feeds(CACHE_DIR)
    ctx.tool_versions["osv"] = "api.osv.dev/v1"
    checked_at = ev.now_iso()

    matchable = [c for c in ctx.components if is_matchable_purl(c.get("purl"))]
    osv_components = [c for c in matchable if _osv_supported(c["purl"])]
    purls = list(dict.fromkeys(c["purl"] for c in osv_components))
    by_purl: dict[str, list[dict]] = {}
    for component in osv_components:
        by_purl.setdefault(component["purl"], []).append(component)
    yield ev.log(STAGE, f"POST /v1/querybatch with {len(purls)} package URLs")
    if ctx.skipped_components:
        yield ev.log(
            STAGE,
            f"{ctx.skipped_components} component(s) have no usable versioned purl and were skipped",
            ev.WARN,
        )

    hits: dict[str, list[str]] = {}
    query_error = ""
    malformed_results: dict[str, str] = {}
    advisories: dict[str, dict] = {}
    detail_errors: dict[str, str] = {}
    try:
        if purls:
            try:
                raw_hits = feeds.query_purls(purls)
                if not isinstance(raw_hits, dict):
                    raise FeedError("OSV querybatch returned a non-object result")
                for purl in purls:
                    if purl not in raw_hits:
                        malformed_results[purl] = "OSV response omitted this package query"
                        continue
                    ids = raw_hits[purl]
                    if not isinstance(ids, list) or not all(
                        isinstance(item, str) and item for item in ids
                    ):
                        malformed_results[purl] = (
                            "OSV response contained malformed vulnerability identifiers"
                        )
                        continue
                    hits[purl] = list(dict.fromkeys(ids))
            except FeedError as exc:
                query_error = str(exc)

        unique_ids = sorted({vid for ids in hits.values() for vid in ids})
        yield ev.metric(
            STAGE,
            "components with OSV results",
            f"{sum(bool(ids) for ids in hits.values())}/{len(purls)}",
        )
        yield ev.log(STAGE, f"resolving {len(unique_ids)} advisories (cached on disk)")

        def resolve(osv_id: str) -> tuple[str, dict | None, str]:
            try:
                advisory = feeds.vuln_detail(osv_id)
                if not isinstance(advisory, dict):
                    raise FeedError(f"OSV detail {osv_id} was not an object")
                return osv_id, advisory, ""
            except (FeedError, OSError, TypeError, ValueError, KeyError) as exc:
                return osv_id, None, str(exc)

        if unique_ids and not query_error:
            with ThreadPoolExecutor(
                max_workers=min(OSV_DETAIL_WORKERS, len(unique_ids))
            ) as executor:
                for osv_id, advisory, error in executor.map(resolve, unique_ids):
                    if error:
                        detail_errors[osv_id] = error
                    elif advisory is not None:
                        advisories[osv_id] = advisory

        findings: list[Finding] = []
        for purl, ids in hits.items():
            for comp in by_purl[purl]:
                for vid in ids:
                    if vid not in advisories:
                        continue
                    adv = advisories[vid]
                    try:
                        aliases = adv.get("aliases") or []
                        if not isinstance(aliases, list) or not all(
                            isinstance(alias, str) for alias in aliases
                        ):
                            raise ValueError("aliases must be a list of strings")
                        cves = [alias for alias in aliases if alias.startswith("CVE-")]
                        vector = _cvss_vector(adv)
                        fixed_version = _fixed_version(adv, purl)
                    except (AttributeError, TypeError, ValueError) as exc:
                        detail_errors[vid] = f"OSV detail {vid} is malformed: {exc}"
                        continue
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
                                fixed_version=fixed_version,
                                bom_ref=comp.get("bom_ref", purl),
                                source="OSV",
                                source_url=f"https://osv.dev/vulnerability/{vid}",
                                coverage_status="completed",
                                affectedness="affected",
                                affectedness_evidence=(
                                    f"OSV returned {vid} for the exact versioned Package URL."
                                ),
                                reachability="not_assessed",
                                query_source="OSV.dev",
                                query_value=purl,
                                source_retrieved_at=checked_at,
                            )
                        )
    finally:
        if owned:
            feeds.close()

    coverage: list[dict] = []
    for component in ctx.components:
        purl = component.get("purl", "")
        if not is_matchable_purl(purl):
            coverage.append(
                _coverage_entry(
                    component,
                    source="OSV.dev",
                    source_url=OSV_BATCH_URL,
                    status="unscanned",
                    checked_at=checked_at,
                    reason="No usable versioned Package URL was available.",
                )
            )
        elif not _osv_supported(purl):
            coverage.append(
                _coverage_entry(
                    component,
                    source="OSV.dev",
                    source_url=OSV_BATCH_URL,
                    status="unsupported",
                    checked_at=checked_at,
                    query_value=purl,
                    reason=(
                        "This package type needs source-specific advisory evidence; "
                        "an empty generic OSV query would not prove it clean."
                    ),
                )
            )
        elif query_error:
            coverage.append(
                _coverage_entry(
                    component,
                    source="OSV.dev",
                    source_url=OSV_BATCH_URL,
                    status="failed",
                    checked_at=checked_at,
                    query_value=purl,
                    reason=query_error,
                )
            )
        elif purl in malformed_results:
            coverage.append(
                _coverage_entry(
                    component,
                    source="OSV.dev",
                    source_url=OSV_BATCH_URL,
                    status="unknown",
                    checked_at=checked_at,
                    query_value=purl,
                    reason=malformed_results[purl],
                )
            )
        else:
            ids = hits.get(purl, [])
            failures = [detail_errors[item] for item in ids if item in detail_errors]
            coverage.append(
                _coverage_entry(
                    component,
                    source="OSV.dev",
                    source_url=OSV_BATCH_URL,
                    status="failed" if failures else "completed",
                    checked_at=checked_at,
                    query_value=purl,
                    result_count=len(ids),
                    reason=(
                        "; ".join(failures)
                        if failures
                        else (
                            f"OSV returned {len(ids)} advisory result(s) for this exact query."
                            if ids
                            else "No findings were returned by this checked source."
                        )
                    ),
                )
            )

    # Native vendor rules are recorded separately; OSV output keeps its meaning.
    osv_path = ctx.path("findings.osv.json")
    osv_path.write_text(json.dumps([f.as_dict() for f in findings], indent=2), encoding="utf-8")
    from ..native import advisory_catalog, assess, findings as native_findings
    native_catalog = advisory_catalog()
    ctx.tool_versions["pandax_native_advisories"] = native_catalog["catalog_version"]
    native_catalog_path = ctx.path("native-advisory-sources.json")
    native_catalog_path.write_text(
        json.dumps(native_catalog, indent=2), encoding="utf-8"
    )
    assessments = assess(ctx.native_inventory)
    vendor_path = ctx.path("native-assessments.json")
    vendor_path.write_text(json.dumps(assessments, indent=2), encoding="utf-8")
    native_rows: dict[str, list[dict]] = {}
    for assessment in assessments:
        native_rows.setdefault(assessment["purl"], []).append(assessment)
    for component in ctx.native_inventory.get("components", []):
        rows = native_rows.get(component.get("purl", ""), [])
        determinations = [
            {
                "cve": row["cve"],
                "affectedness": row["state"],
                "source_url": row.get("source_url", row.get("source", "")),
                "source_retrieved_at": row.get("source_retrieved_at", ""),
                "evidence": row.get("affectedness_evidence", row.get("detail", "")),
                "ruleset": row.get("ruleset", ""),
                "source_records": row.get("source_records", []),
                "conflicting_sources": row.get("conflicting_sources", []),
            }
            for row in rows
        ]
        coverage.append(
            _coverage_entry(
                component,
                source="PandaX native advisory rules",
                source_url=rows[0].get("source_url", rows[0].get("source", "")) if rows else "",
                status="completed" if rows else "unsupported",
                checked_at=checked_at,
                query_value=component.get("purl", ""),
                result_count=len(rows),
                reason=(
                    "Recorded source-specific advisory determinations."
                    if rows and any(row["state"] != "unknown" for row in rows)
                    else "Rules were evaluated, but affectedness remains unknown."
                    if rows
                    else "No source-specific advisory rule covers this native component."
                ),
                determinations=determinations,
            )
        )
    native_matches = native_findings(assessments)
    findings.extend(native_matches)
    yield ev.log(STAGE, f"vendor supplement: {len(assessments)} native determinations (bounded CVE coverage)")

    # Installation-wide vendor intelligence is reviewed by the deployment's
    # security curator. It is exact-PURL only, so a backport decision for one
    # distribution revision cannot leak onto a similarly named package.
    from ..vendor_intelligence import assess as assess_vendor, load_active

    vendor_outputs = []
    vendor_catalog, active_vendor_path = load_active()
    if vendor_catalog is not None:
        vendor_catalog_path = ctx.path("vendor-intelligence.json")
        vendor_catalog_path.write_text(
            json.dumps(vendor_catalog, indent=2), encoding="utf-8"
        )
        findings, vendor_assessments, superseded = assess_vendor(
            ctx.components, findings, vendor_catalog
        )
        vendor_assessments_path = ctx.path("vendor-assessments.json")
        vendor_assessments_path.write_text(
            json.dumps(
                {
                    "schema": "pandax/vendor-assessments/v1",
                    "catalog_version": vendor_catalog["catalog_version"],
                    "catalog_sha256": sha256_file(active_vendor_path),
                    "matched_entries": len(vendor_assessments),
                    "assessments": vendor_assessments,
                    "notice": (
                        "Decisions apply only to the exact Package URLs shown. "
                        "Affectedness does not establish runtime reachability."
                    ),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        superseded_path = ctx.path("vendor-superseded-findings.json")
        superseded_path.write_text(
            json.dumps(
                {
                    "schema": "pandax/vendor-superseded-findings/v1",
                    "catalog_version": vendor_catalog["catalog_version"],
                    "count": len(superseded),
                    "findings": superseded,
                    "notice": (
                        "These generic-feed findings were not deleted silently. "
                        "A reviewed exact-package vendor decision took precedence."
                    ),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        vendor_outputs = [
            vendor_catalog_path,
            vendor_assessments_path,
            superseded_path,
        ]
        rows_by_purl: dict[str, list[dict]] = {}
        for assessment in vendor_assessments:
            rows_by_purl.setdefault(assessment["purl"], []).append(assessment)
        components_by_purl = {
            component.get("purl", ""): component for component in ctx.components
        }
        for purl, rows in rows_by_purl.items():
            component = components_by_purl[purl]
            coverage.append(
                _coverage_entry(
                    component,
                    source="Curated vendor intelligence",
                    source_url=rows[0]["source"]["url"],
                    status="completed",
                    checked_at=checked_at,
                    query_value=purl,
                    result_count=len(rows),
                    reason=(
                        "Reviewed exact-package vendor decisions were applied. "
                        "Full vendor revisions, backports, and conflicts are preserved."
                    ),
                    determinations=[
                        {
                            "cve": row["cve"],
                            "affectedness": row["selected_state"],
                            "decision": row["decision"],
                            "source_url": row["source"]["url"],
                            "source_retrieved_at": row["source"]["retrieved_at"],
                            "evidence": row["source"]["statement"],
                            "review": row["review"],
                            "backport": row.get("backport"),
                            "conflicting_sources": row["conflicts"],
                        }
                        for row in rows
                    ],
                )
            )
        ctx.tool_versions["pandax_vendor_intelligence"] = vendor_catalog[
            "catalog_version"
        ]
        yield ev.log(
            STAGE,
            f"curated vendor intelligence: {len(vendor_assessments)} exact-package "
            f"decision(s), {len(superseded)} generic finding(s) superseded",
        )

    coverage_path = _write_coverage(ctx, checked_at, coverage)

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
    yield ev.artifact(
        STAGE,
        ctx.ledger.rel(coverage_path),
        sha256_file(coverage_path),
        "Per-component, per-source vulnerability coverage",
    )

    ledger_inputs = [ctx.ledger.ref(ctx.sbom_path)] if ctx.sbom_path else []
    native_inventory_path = ctx.path("native-inventory.json")
    if native_inventory_path.exists():
        ledger_inputs.append(ctx.ledger.ref(native_inventory_path))

    ctx.ledger.append(
        stage="S3_MATCH",
        tool="osv.dev",
        tool_version="v1",
        inputs=ledger_inputs,
        outputs=[
            ctx.ledger.ref(out_path),
            ctx.ledger.ref(osv_path),
            ctx.ledger.ref(vendor_path),
            ctx.ledger.ref(native_catalog_path),
            ctx.ledger.ref(coverage_path),
        ] + [ctx.ledger.ref(path) for path in vendor_outputs],
        params={"endpoint": "https://api.osv.dev/v1/querybatch", "purls": len(purls),
                "native_rules": native_catalog["catalog_version"],
                "native_coverage": "versioned curated advisories only",
                "vendor_catalog": (
                    vendor_catalog["catalog_version"] if vendor_catalog else "not installed"
                ),
                "vendor_matching": "exact Package URL only",
                "coverage_schema": COVERAGE_SCHEMA},
    )

    blocking = [check for check in coverage if check["status"] in {"failed", "unknown"}]
    if blocking:
        reasons = "; ".join(dict.fromkeys(check["reason"] for check in blocking))
        yield ev.log(
            STAGE,
            "vulnerability coverage is incomplete; the run will not be sealed",
            ev.ALERT_LVL,
        )
        raise CoverageError(reasons)
    yield ev.done(STAGE, f"{len(ctx.findings)} vulnerabilities matched")
