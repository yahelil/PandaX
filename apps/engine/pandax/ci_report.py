"""Machine-readable CI reports derived from a sealed PandaX evidence bundle."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import __version__

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


def _findings(run_dir: Path) -> list[dict[str, Any]]:
    value = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError("findings.json must contain a JSON array of objects")
    return value


def _status(findings: list[dict[str, Any]]) -> str:
    if any(item.get("kev") for item in findings):
        return "urgent_review"
    if findings:
        return "review_required"
    return "no_known_vulnerabilities"


def build_summary(run_dir: Path, pipeline_summary: dict[str, Any]) -> dict[str, Any]:
    """Build stable JSON for CI without changing the sealed bundle."""
    findings = _findings(run_dir)
    return {
        "schema_version": "1.0",
        "tool": {"name": "PandaX", "version": __version__},
        "run": {
            "id": pipeline_summary.get("run_id", ""),
            "evidence_bundle": str(run_dir),
            "input_type": pipeline_summary.get("input_type", ""),
            "sbom_format": pipeline_summary.get("sbom_format", ""),
            "sbom_version": pipeline_summary.get("sbom_version", ""),
        },
        "result": {
            "status": _status(findings),
            "components": int(pipeline_summary.get("components", 0)),
            "matchable_components": int(pipeline_summary.get("matchable_components", 0)),
            "skipped_components": int(pipeline_summary.get("skipped_components", 0)),
            "findings": len(findings),
            "kev_signals": sum(1 for item in findings if item.get("kev")),
            "article_14_clocks": int(pipeline_summary.get("incidents", 0)),
            "coverage": pipeline_summary.get("coverage_summary", {}),
        },
        "limitations": [
            "No known finding is not proof that a product is vulnerability-free.",
            "CISA KEV is an urgency signal, not automatic CRA Article 14 reportability.",
            "Manufacturer review remains required for affectedness, reachability, and reporting decisions.",
        ],
    }


def _rule_id(finding: dict[str, Any]) -> str:
    return str(finding.get("cve") or finding.get("osv_id") or "PANDAX-VULNERABILITY")


def _sarif_level(finding: dict[str, Any]) -> str:
    severity = str(finding.get("severity", "")).upper()
    if severity in {"CRITICAL", "HIGH"}:
        return "error"
    if severity == "MEDIUM":
        return "warning"
    return "note"


def build_sarif(run_dir: Path) -> dict[str, Any]:
    """Map vulnerability findings to SARIF 2.1.0 for code-scanning consumers."""
    findings = _findings(run_dir)
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for finding in findings:
        rule_id = _rule_id(finding)
        source_url = str(finding.get("source_url", ""))
        rule: dict[str, Any] = {
            "id": rule_id,
            "shortDescription": {"text": str(finding.get("summary") or rule_id)},
            "properties": {"tags": ["security", "vulnerability", "CRA-review"]},
        }
        if source_url.startswith(("https://", "http://")):
            rule["helpUri"] = source_url
        rules.setdefault(rule_id, rule)

        component = str(finding.get("component", "unknown component"))
        version = str(finding.get("version", "unknown version"))
        purl = str(finding.get("purl", ""))
        identity = "\0".join((rule_id, purl, version)).encode("utf-8")
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(finding),
                "message": {"text": f"{rule_id} reported for {component} {version}; manufacturer review required."},
                "logicalLocations": [
                    {"fullyQualifiedName": purl or f"{component}@{version}", "kind": "package"}
                ],
                "partialFingerprints": {
                    "pandaxFinding/v1": hashlib.sha256(identity).hexdigest()
                },
                "properties": {
                    "severity": str(finding.get("severity", "UNKNOWN")),
                    "component": component,
                    "version": version,
                    "purl": purl,
                    "affectedness": str(finding.get("affectedness", "unknown")),
                    "reachability": str(finding.get("reachability", "unknown")),
                    "cisaKev": bool(finding.get("kev")),
                    "source": str(finding.get("source", "")),
                    "sourceRetrievedAt": str(finding.get("source_retrieved_at", "")),
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PandaX",
                        "version": __version__,
                        "informationUri": "https://pandax.online/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _write_json_outside_bundle(target: Path, run_dir: Path, value: dict[str, Any]) -> None:
    resolved_target = target.resolve()
    resolved_run = run_dir.resolve()
    if resolved_target == resolved_run or resolved_run in resolved_target.parents:
        raise ValueError("CI report output must be outside the sealed evidence bundle")
    resolved_target.parent.mkdir(parents=True, exist_ok=True)
    resolved_target.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def write_reports(
    run_dir: Path,
    pipeline_summary: dict[str, Any],
    *,
    json_output: Path | None = None,
    sarif_output: Path | None = None,
) -> None:
    if json_output is not None:
        _write_json_outside_bundle(json_output, run_dir, build_summary(run_dir, pipeline_summary))
    if sarif_output is not None:
        _write_json_outside_bundle(sarif_output, run_dir, build_sarif(run_dir))
