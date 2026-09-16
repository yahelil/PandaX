"""Evidence-backed product exposure analysis without automatic legal verdicts."""

from __future__ import annotations

import datetime as dt
import json
import re
from collections import deque
from pathlib import Path
from typing import Any

from . import events as ev
from .context import Finding, RunContext
from .evidence import sha256_file


SCHEMA = "pandax/exposure-context/v1"
STAGE = "EXPOSURE ANALYSIS"
MAX_BYTES = 1024 * 1024
MAX_COMPONENTS = 5_000
COMPILED_STATES = {"included", "excluded", "unknown"}
FEATURE_STATES = {"enabled", "disabled", "unknown"}
NETWORK_STATES = {"exposed", "not_exposed", "unknown"}
FLAG_STATES = {"enabled", "disabled", "unknown"}
FLAG_EFFECTS = {"supports_reachable", "supports_not_reachable", "neutral"}
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
_FLAG_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:+-]{0,159}$")


class ExposureError(ValueError):
    """Reviewed exposure context is unsafe, malformed, or for another release."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExposureError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ExposureError(f"{label} must be an object")
    return value


def _only(value: dict[str, Any], allowed: set[str], label: str) -> None:
    extras = sorted(set(value) - allowed)
    if extras:
        raise ExposureError(
            f"{label} contains unsupported fields: {', '.join(extras)}. "
            "Raw configuration files, logs, commands, and secrets are not accepted."
        )


def _text(value: Any, label: str, limit: int = 500) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExposureError(f"{label} is required")
    result = value.strip()
    if len(result) > limit:
        raise ExposureError(f"{label} is longer than {limit} characters")
    return result


def _timestamp(value: Any, label: str) -> str:
    text = _text(value, label, 40)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExposureError(f"{label} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ExposureError(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _state(value: Any, allowed: set[str], label: str) -> str:
    result = _text(value, label, 40)
    if result not in allowed:
        raise ExposureError(f"{label} must be one of: {', '.join(sorted(allowed))}")
    return result


def _evidence_ref(value: Any, label: str) -> str:
    result = _text(value, label, 160)
    if not _REFERENCE.fullmatch(result):
        raise ExposureError(
            f"{label} must be a short evidence identifier, not raw data"
        )
    return result


def load(path: Path) -> dict[str, Any]:
    """Strictly validate and normalize reviewed build/configuration facts."""
    source = Path(path)
    if not source.exists() or not source.is_file():
        raise ExposureError(f"exposure context not found: {source}")
    if source.stat().st_size > MAX_BYTES:
        raise ExposureError("exposure context exceeds the 1 MiB limit")
    try:
        root = json.loads(
            source.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except UnicodeDecodeError as exc:
        raise ExposureError("exposure context must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise ExposureError(f"exposure context is not valid JSON: {exc.msg}") from exc

    document = _object(root, "exposure context")
    _only(document, {"schema", "product", "approval", "components"}, "exposure context")
    if document.get("schema") != SCHEMA:
        raise ExposureError(f"exposure context schema must be {SCHEMA}")

    product = _object(document.get("product"), "product")
    _only(product, {"name", "version", "unique_id"}, "product")
    normal_product = {
        "name": _text(product.get("name"), "product.name", 160),
        "version": _text(product.get("version"), "product.version", 80),
    }
    if product.get("unique_id") is not None:
        normal_product["unique_id"] = _text(
            product["unique_id"], "product.unique_id", 160
        )

    approval = _object(document.get("approval"), "approval")
    _only(approval, {"reviewer", "reviewed_at", "authority_attestation"}, "approval")
    if approval.get("authority_attestation") is not True:
        raise ExposureError(
            "approval.authority_attestation must be true and supplied by an "
            "authorized company reviewer"
        )
    normal_approval = {
        "reviewer": _text(approval.get("reviewer"), "approval.reviewer", 160),
        "reviewed_at": _timestamp(approval.get("reviewed_at"), "approval.reviewed_at"),
        "authority_attestation": True,
    }

    components = document.get("components")
    if not isinstance(components, list):
        raise ExposureError("components must be a list")
    if len(components) > MAX_COMPONENTS:
        raise ExposureError(f"exposure context has more than {MAX_COMPONENTS} components")
    seen: set[str] = set()
    normal_components: list[dict[str, Any]] = []
    for index, raw in enumerate(components):
        label = f"components[{index}]"
        item = _object(raw, label)
        _only(
            item,
            {
                "purl", "observed_at", "compiled_state", "feature_state",
                "network_exposure", "evidence_ref", "build_flags",
            },
            label,
        )
        purl = _text(item.get("purl"), f"{label}.purl", 1000)
        if not purl.startswith("pkg:") or "@" not in purl:
            raise ExposureError(f"{label}.purl must be an exact, versioned Package URL")
        if purl in seen:
            raise ExposureError(f"duplicate exposure context for {purl}")
        seen.add(purl)
        flags = item.get("build_flags", [])
        if not isinstance(flags, list):
            raise ExposureError(f"{label}.build_flags must be a list")
        if len(flags) > 200:
            raise ExposureError(f"{label}.build_flags has more than 200 entries")
        normal_flags = []
        flag_names: set[str] = set()
        for flag_index, raw_flag in enumerate(flags):
            flag_label = f"{label}.build_flags[{flag_index}]"
            flag = _object(raw_flag, flag_label)
            _only(flag, {"name", "state", "effect", "evidence_ref"}, flag_label)
            flag_name = _text(flag.get("name"), f"{flag_label}.name", 160)
            if not _FLAG_NAME.fullmatch(flag_name):
                raise ExposureError(
                    f"{flag_label}.name must be a build-flag identifier, not raw data"
                )
            if flag_name.casefold() in flag_names:
                raise ExposureError(f"duplicate build flag {flag_name} for {purl}")
            flag_names.add(flag_name.casefold())
            flag_state = _state(
                flag.get("state"), FLAG_STATES, f"{flag_label}.state"
            )
            flag_effect = _state(
                flag.get("effect"), FLAG_EFFECTS, f"{flag_label}.effect"
            )
            if flag_state == "unknown" and flag_effect != "neutral":
                raise ExposureError(
                    f"{flag_label}.effect must be neutral when the flag state is unknown"
                )
            normal_flags.append(
                {
                    "name": flag_name,
                    "state": flag_state,
                    "effect": flag_effect,
                    "evidence_ref": _evidence_ref(
                        flag.get("evidence_ref"), f"{flag_label}.evidence_ref"
                    ),
                }
            )
        normal_components.append(
            {
                "purl": purl,
                "observed_at": _timestamp(
                    item.get("observed_at"), f"{label}.observed_at"
                ),
                "compiled_state": _state(
                    item.get("compiled_state"), COMPILED_STATES, f"{label}.compiled_state"
                ),
                "feature_state": _state(
                    item.get("feature_state"), FEATURE_STATES, f"{label}.feature_state"
                ),
                "network_exposure": _state(
                    item.get("network_exposure"),
                    NETWORK_STATES,
                    f"{label}.network_exposure",
                ),
                "evidence_ref": _evidence_ref(
                    item.get("evidence_ref"), f"{label}.evidence_ref"
                ),
                "build_flags": normal_flags,
            }
        )

    reviewed_at = dt.datetime.fromisoformat(
        normal_approval["reviewed_at"].replace("Z", "+00:00")
    )
    if any(
        dt.datetime.fromisoformat(item["observed_at"].replace("Z", "+00:00"))
        > reviewed_at
        for item in normal_components
    ):
        raise ExposureError(
            "approval.reviewed_at cannot be earlier than evidence it approves"
        )
    return {
        "schema": SCHEMA,
        "product": normal_product,
        "approval": normal_approval,
        "components": normal_components,
    }


def summary(path: Path) -> dict[str, Any]:
    document = load(path)
    return {
        "valid": True,
        "schema": document["schema"],
        "product": document["product"],
        "reviewed_by": document["approval"]["reviewer"],
        "reviewed_at": document["approval"]["reviewed_at"],
        "components": len(document["components"]),
    }


def _check_product(document: dict[str, Any], actual: dict[str, Any]) -> None:
    supplied = document["product"]
    for field in ("name", "version"):
        expected = str(actual.get(field, "")).strip()
        if not expected:
            raise ExposureError(
                "the scan has no reliable product name and version, so exposure "
                "evidence cannot be connected to the correct release"
            )
        if supplied[field].casefold() != expected.casefold():
            raise ExposureError(
                f"exposure context is for {supplied['name']} {supplied['version']}, "
                f"not {actual.get('name')} {actual.get('version')}"
            )
    expected_id = str(actual.get("unique_id", "")).strip()
    supplied_id = str(supplied.get("unique_id", "")).strip()
    if expected_id and supplied_id and expected_id.casefold() != supplied_id.casefold():
        raise ExposureError("exposure context product.unique_id does not match this product")


def _dependency_path(ctx: RunContext, target: str) -> list[str]:
    """Find a declared SBOM path from the product root to the component."""
    root = str(((ctx.sbom.get("metadata") or {}).get("component") or {}).get("bom-ref", ""))
    if not root or not target:
        return []
    graph = {
        str(row.get("ref", "")): [str(value) for value in row.get("dependsOn", [])]
        for row in ctx.sbom.get("dependencies", [])
        if isinstance(row, dict)
    }
    names = {
        str(component.get("bom-ref", component.get("bom_ref", ""))): str(
            component.get("name", component.get("bom-ref", ""))
        )
        for component in ctx.sbom.get("components", [])
    }
    root_component = (ctx.sbom.get("metadata") or {}).get("component") or {}
    names[root] = str(root_component.get("name", root))
    queue = deque([(root, [root])])
    visited = {root}
    while queue:
        current, path = queue.popleft()
        if current == target:
            return [names.get(ref, ref) for ref in path]
        for child in graph.get(current, []):
            if child not in visited:
                visited.add(child)
                queue.append((child, [*path, child]))
    return []


def _assess_finding(
    ctx: RunContext,
    finding: Finding,
    reviewed: dict[str, Any] | None,
) -> dict[str, Any]:
    positive: list[str] = []
    negative: list[str] = []
    positive_codes: list[str] = []
    negative_codes: list[str] = []
    limitations: list[str] = []
    if reviewed:
        if reviewed["compiled_state"] == "excluded":
            negative.append("reviewed build evidence says the component was excluded")
            negative_codes.append("component_excluded")
        elif reviewed["compiled_state"] == "included":
            positive.append("reviewed build evidence says the component was included")
            positive_codes.append("component_included")
        if reviewed["feature_state"] == "disabled":
            negative.append("reviewed configuration evidence says the feature is disabled")
            negative_codes.append("vulnerable_feature_disabled")
        elif reviewed["feature_state"] == "enabled":
            positive.append("reviewed configuration evidence says the feature is enabled")
            positive_codes.append("vulnerable_feature_enabled")
        if reviewed["network_exposure"] == "not_exposed":
            negative.append("reviewed configuration evidence says it is not network-exposed")
            negative_codes.append("network_not_exposed")
        elif reviewed["network_exposure"] == "exposed":
            positive.append("reviewed configuration evidence says it is network-exposed")
            positive_codes.append("network_exposed")
        for flag in reviewed["build_flags"]:
            description = (
                f"reviewed build flag {flag['name']} is {flag['state']}"
            )
            if flag["effect"] == "supports_reachable":
                positive.append(description + " and supports reachability")
                positive_codes.append("build_flag_supports_reachable")
            elif flag["effect"] == "supports_not_reachable":
                negative.append(description + " and supports non-reachability")
                negative_codes.append("build_flag_supports_not_reachable")
    else:
        limitations.append("No exact release-bound reviewed exposure context was supplied.")
    runtime_signals = {item.get("signal") for item in finding.runtime_evidence}
    if "component_executed" in runtime_signals:
        positive.append("approved runtime telemetry observed the component executing")
        positive_codes.append("runtime_component_executed")
    if "network_exposed" in runtime_signals:
        positive.append("approved runtime telemetry observed network exposure")
        positive_codes.append("runtime_network_exposed")
    if "component_loaded" in runtime_signals:
        positive.append("approved runtime telemetry observed the component loaded")
        positive_codes.append("runtime_component_loaded")
    dependency_path = _dependency_path(ctx, finding.bom_ref)
    if dependency_path:
        limitations.append(
            "The SBOM dependency path proves declared inclusion only, not execution."
        )
    else:
        limitations.append("No product-root dependency path was established by the SBOM.")

    decisive_negative_codes = {
        "component_excluded",
        "vulnerable_feature_disabled",
        "build_flag_supports_not_reachable",
    }
    decisive_negative = bool(decisive_negative_codes & set(negative_codes))
    direct_network_conflict = bool(
        reviewed
        and reviewed["network_exposure"] == "not_exposed"
        and "network_exposed" in runtime_signals
    )
    strong_positive_codes = {
        "runtime_component_executed",
        "runtime_network_exposed",
        "network_exposed",
        "build_flag_supports_reachable",
    }
    strong_positive = bool(strong_positive_codes & set(positive_codes))
    if (decisive_negative and strong_positive) or direct_network_conflict:
        status = "conflicting_evidence"
        recommendation = {
            "reachability": "review",
            "confidence": "low",
            "reason_codes": sorted(set(positive_codes + negative_codes)),
            "limitations": [
                *limitations,
                "Positive and negative evidence conflict; no reachability conclusion is safe.",
            ],
            "review_required": True,
            "recommended_vex": {"state": "in_triage"},
        }
    elif decisive_negative:
        status = "evidence_supports_not_reachable"
        justification = (
            "code_not_present"
            if "component_excluded" in negative_codes
            else "code_not_reachable"
        )
        recommendation = {
            "reachability": "not_reachable",
            "confidence": "high",
            "reason_codes": sorted(set(negative_codes)),
            "limitations": limitations,
            "review_required": True,
            "recommended_vex": {
                "state": "not_affected",
                "justification": justification,
            },
        }
    elif strong_positive:
        status = "evidence_supports_reachable"
        recommendation = {
            "reachability": "reachable",
            "confidence": "high",
            "reason_codes": sorted(set(positive_codes)),
            "limitations": limitations,
            "review_required": True,
            "recommended_vex": {"state": "exploitable"},
        }
    else:
        status = "insufficient_evidence"
        reason_codes = sorted(set(positive_codes + negative_codes))
        if not reason_codes:
            reason_codes = ["no_reachability_evidence"]
        recommendation = {
            "reachability": "review",
            "confidence": "low",
            "reason_codes": reason_codes,
            "limitations": [
                *limitations,
                "Available evidence does not establish reachability or non-reachability.",
            ],
            "review_required": True,
            "recommended_vex": {"state": "in_triage"},
        }
    return {
        "cve": finding.cve,
        "purl": finding.purl,
        "component_ref": finding.bom_ref,
        "status": status,
        "review_required": True,
        "positive_evidence": positive,
        "negative_evidence": negative,
        "dependency_path": dependency_path,
        "dependency_path_meaning": (
            "Declared inclusion path only; it does not prove execution or exposure."
            if dependency_path
            else "No product-root dependency path was established by the SBOM."
        ),
        "reviewed_context": reviewed,
        "runtime_observations": finding.runtime_evidence,
        "decision": "not_made_automatically",
        "recommendation": recommendation,
    }


def run(ctx: RunContext, context_path: Path | None = None) -> ev.Stream:
    """Combine build, configuration, dependency, and runtime evidence."""
    document: dict[str, Any] | None = None
    source: Path | None = None
    if context_path is not None:
        source = Path(context_path).resolve()
        document = load(source)
        _check_product(document, ctx.product.get("product", {}))

    yield ev.start(STAGE, "combining build, configuration, dependency and runtime evidence")
    reviewed_by_purl = {
        item["purl"]: item for item in (document or {}).get("components", [])
    }
    assessments = [
        _assess_finding(ctx, finding, reviewed_by_purl.get(finding.purl))
        for finding in ctx.findings
    ]
    by_key = {(item["cve"], item["purl"]): item for item in assessments}
    for finding in ctx.findings:
        assessment = by_key[(finding.cve, finding.purl)]
        finding.exposure_assessment = assessment["status"]
        finding.exposure_evidence = {
            "positive": assessment["positive_evidence"],
            "negative": assessment["negative_evidence"],
            "dependency_path": assessment["dependency_path"],
            "recommendation": assessment["recommendation"],
        }

    outputs: list[Path] = []
    if document is not None and source is not None:
        normalized_path = ctx.path("exposure-context.json")
        normalized_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        receipt_path = ctx.path("exposure-context-source.json")
        receipt_path.write_text(
            json.dumps(
                {
                    "schema": "pandax/exposure-context-source/v1",
                    "sha256": sha256_file(source),
                    "bytes": source.stat().st_size,
                    "original_source_retained": False,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        outputs.extend([normalized_path, receipt_path])
    assessment_path = ctx.path("exposure-assessments.json")
    sbom_purls = {str(component.get("purl", "")) for component in ctx.components}
    finding_purls = {finding.purl for finding in ctx.findings}
    assessment_path.write_text(
        json.dumps(
            {
                "schema": "pandax/exposure-assessments/v1",
                "product": ctx.product.get("product", {}),
                "approval": (document or {}).get("approval"),
                "assessments": assessments,
                "summary": {
                    status: sum(1 for item in assessments if item["status"] == status)
                    for status in (
                        "evidence_supports_reachable",
                        "evidence_supports_not_reachable",
                        "conflicting_evidence",
                        "insufficient_evidence",
                    )
                },
                "context_scope": {
                    "not_present_in_sbom": sorted(set(reviewed_by_purl) - sbom_purls),
                    "present_without_a_finding": sorted(
                        (set(reviewed_by_purl) & sbom_purls) - finding_purls
                    ),
                },
                "notice": (
                    "These are evidence summaries, not final reachability or CRA "
                    "reportability decisions. An authorized company reviewer must decide."
                ),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    outputs.append(assessment_path)
    ctx.exposure_assessments_path = assessment_path
    inputs = [ctx.ledger.ref(ctx.path("findings.matched.json"))]
    if ctx.sbom_path is not None:
        inputs.append(ctx.ledger.ref(ctx.sbom_path))
    if ctx.telemetry_assessments_path is not None:
        inputs.append(ctx.ledger.ref(ctx.telemetry_assessments_path))
    ctx.ledger.append(
        stage="EXPOSURE_ANALYSIS",
        tool="pandax.exposure",
        tool_version="1",
        inputs=inputs,
        outputs=[ctx.ledger.ref(path) for path in outputs],
        params={
            "reviewed_context_supplied": document is not None,
            "automatic_reachability_decision": False,
        },
    )
    counts = {
        status: sum(1 for item in assessments if item["status"] == status)
        for status in {
            "evidence_supports_reachable",
            "evidence_supports_not_reachable",
            "conflicting_evidence",
            "insufficient_evidence",
        }
    }
    yield ev.metric(
        STAGE,
        "evidence summaries",
        ", ".join(f"{key}={value}" for key, value in sorted(counts.items()) if value),
    )
    yield ev.artifact(
        STAGE,
        ctx.ledger.rel(assessment_path),
        sha256_file(assessment_path),
        "review-required exposure analysis",
    )
    yield ev.done(STAGE, "exposure evidence prepared for company review", ev.GOOD)
