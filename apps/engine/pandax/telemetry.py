"""Approved, privacy-minimised runtime evidence for a PandaX scan.

The input is deliberately a small derived record rather than a device log.  It
can inform a manufacturer's review, but it never changes reachability or CRA
reportability automatically.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any

from . import events as ev
from .context import RunContext
from .evidence import sha256_file


SCHEMA = "pandax/runtime-telemetry/v1"
STAGE = "RUNTIME TELEMETRY"
MAX_BYTES = 1024 * 1024
MAX_OBSERVATIONS = 5_000
SIGNALS = {
    "component_loaded",
    "component_executed",
    "network_exposed",
    "feature_enabled",
    "not_observed",
}
_HASH = re.compile(r"^[0-9a-f]{64}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$")


class TelemetryError(ValueError):
    """The supplied runtime evidence is unsafe, malformed, or for another release."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TelemetryError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TelemetryError(f"{label} must be an object")
    return value


def _only(value: dict[str, Any], allowed: set[str], label: str) -> None:
    extra = sorted(set(value) - allowed)
    if extra:
        raise TelemetryError(
            f"{label} contains unsupported fields: {', '.join(extra)}. "
            "Raw logs and extra device data are not accepted."
        )


def _text(value: Any, label: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TelemetryError(f"{label} is required")
    cleaned = value.strip()
    if len(cleaned) > limit:
        raise TelemetryError(f"{label} is longer than {limit} characters")
    return cleaned


def _timestamp(value: Any, label: str) -> str:
    text = _text(value, label, 40)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TelemetryError(f"{label} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise TelemetryError(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def load(path: Path) -> dict[str, Any]:
    """Load and strictly normalise an approved telemetry summary."""
    source = Path(path)
    if not source.exists() or not source.is_file():
        raise TelemetryError(f"telemetry file not found: {source}")
    if source.stat().st_size > MAX_BYTES:
        raise TelemetryError("telemetry file exceeds the 1 MiB limit")
    try:
        document = json.loads(
            source.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except UnicodeDecodeError as exc:
        raise TelemetryError("telemetry must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise TelemetryError(f"telemetry is not valid JSON: {exc.msg}") from exc

    root = _object(document, "telemetry")
    _only(root, {"schema", "product", "approval", "observations"}, "telemetry")
    if root.get("schema") != SCHEMA:
        raise TelemetryError(f"telemetry schema must be {SCHEMA}")

    product = _object(root.get("product"), "product")
    _only(product, {"name", "version", "unique_id"}, "product")
    normal_product = {
        "name": _text(product.get("name"), "product.name", 160),
        "version": _text(product.get("version"), "product.version", 80),
    }
    if product.get("unique_id") is not None:
        normal_product["unique_id"] = _text(
            product["unique_id"], "product.unique_id", 160
        )

    approval = _object(root.get("approval"), "approval")
    _only(
        approval,
        {"operator", "approved_at", "authority_attestation"},
        "approval",
    )
    if approval.get("authority_attestation") is not True:
        raise TelemetryError(
            "approval.authority_attestation must be true and supplied by an "
            "authorized company reviewer"
        )
    normal_approval = {
        "operator": _text(approval.get("operator"), "approval.operator", 160),
        "approved_at": _timestamp(approval.get("approved_at"), "approval.approved_at"),
        "authority_attestation": True,
    }

    observations = root.get("observations")
    if not isinstance(observations, list):
        raise TelemetryError("observations must be a list")
    if len(observations) > MAX_OBSERVATIONS:
        raise TelemetryError(f"telemetry has more than {MAX_OBSERVATIONS} observations")
    normal_observations: list[dict[str, Any]] = []
    for index, raw in enumerate(observations):
        label = f"observations[{index}]"
        item = _object(raw, label)
        _only(
            item,
            {"purl", "signal", "observed_at", "device_ref_hash", "evidence_ref"},
            label,
        )
        signal = _text(item.get("signal"), f"{label}.signal", 40)
        if signal not in SIGNALS:
            raise TelemetryError(
                f"{label}.signal must be one of: {', '.join(sorted(SIGNALS))}"
            )
        normal: dict[str, Any] = {
            "purl": _text(item.get("purl"), f"{label}.purl", 500),
            "signal": signal,
            "observed_at": _timestamp(item.get("observed_at"), f"{label}.observed_at"),
        }
        if item.get("device_ref_hash") is not None:
            device_hash = _text(
                item["device_ref_hash"], f"{label}.device_ref_hash", 64
            ).lower()
            if not _HASH.fullmatch(device_hash):
                raise TelemetryError(
                    f"{label}.device_ref_hash must be a lowercase SHA-256 value; "
                    "do not send a hostname, serial number, or IP address"
                )
            normal["device_ref_hash"] = device_hash
        if item.get("evidence_ref") is not None:
            reference = _text(item["evidence_ref"], f"{label}.evidence_ref", 120)
            if not _REFERENCE.fullmatch(reference):
                raise TelemetryError(
                    f"{label}.evidence_ref must be a short identifier, not raw log data"
                )
            normal["evidence_ref"] = reference
        normal_observations.append(normal)

    approved_at = dt.datetime.fromisoformat(
        normal_approval["approved_at"].replace("Z", "+00:00")
    )
    if any(
        dt.datetime.fromisoformat(item["observed_at"].replace("Z", "+00:00"))
        > approved_at
        for item in normal_observations
    ):
        raise TelemetryError(
            "approval.approved_at cannot be earlier than an observation it approves"
        )

    return {
        "schema": SCHEMA,
        "product": normal_product,
        "approval": normal_approval,
        "observations": normal_observations,
    }


def _check_product(document: dict[str, Any], actual: dict[str, Any]) -> None:
    supplied = document["product"]
    required = {"name": actual.get("name"), "version": actual.get("version")}
    missing = [key for key, value in required.items() if value in (None, "")]
    if missing:
        raise TelemetryError(
            "the scan has no reliable product name and version, so telemetry cannot "
            "be connected to the correct release"
        )
    for field, expected in required.items():
        if str(supplied[field]).casefold() != str(expected).strip().casefold():
            raise TelemetryError(
                f"telemetry is for {supplied['name']} {supplied['version']}, not "
                f"{required['name']} {required['version']}"
            )
    expected_id = str(actual.get("unique_id", "")).strip()
    supplied_id = str(supplied.get("unique_id", "")).strip()
    if expected_id and supplied_id and expected_id.casefold() != supplied_id.casefold():
        raise TelemetryError("telemetry product.unique_id does not match this product")


def apply(ctx: RunContext, path: Path) -> ev.Stream:
    """Attach approved observations to matching findings without making a verdict."""
    source = Path(path).resolve()
    document = load(source)
    _check_product(document, ctx.product.get("product", {}))

    yield ev.start(STAGE, "checking approved runtime evidence")
    by_purl: dict[str, list[dict[str, Any]]] = {}
    for observation in document["observations"]:
        by_purl.setdefault(observation["purl"], []).append(observation)

    matched_observations = 0
    findings_with_evidence = 0
    finding_purls = {finding.purl for finding in ctx.findings}
    assessments = []
    for finding in ctx.findings:
        observations = [dict(item) for item in by_purl.get(finding.purl, [])]
        finding.runtime_evidence = observations
        finding.runtime_evidence_status = (
            "available_for_review" if observations else "not_supplied"
        )
        matched_observations += len(observations)
        if observations:
            findings_with_evidence += 1
        assessments.append(
            {
                "cve": finding.cve,
                "purl": finding.purl,
                "status": finding.runtime_evidence_status,
                "review_required": bool(observations),
                "signals": sorted({item["signal"] for item in observations}),
                "observation_count": len(observations),
                "decision": "not_made_automatically",
            }
        )

    unmatched = [
        dict(item)
        for item in document["observations"]
        if item["purl"] not in finding_purls
    ]
    normalised_path = ctx.path("runtime-telemetry.json")
    normalised_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    source_receipt_path = ctx.path("telemetry-source.json")
    source_receipt_path.write_text(
        json.dumps(
            {
                "schema": "pandax/telemetry-source/v1",
                "sha256": sha256_file(source),
                "bytes": source.stat().st_size,
                "original_source_retained": False,
                "notice": (
                    "The original submission was not copied into the bundle. "
                    "runtime-telemetry.json contains only its checked, minimal fields."
                ),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    assessment_path = ctx.path("telemetry-assessments.json")
    assessment_path.write_text(
        json.dumps(
            {
                "schema": "pandax/telemetry-assessments/v1",
                "product": document["product"],
                "approval": document["approval"],
                "findings": assessments,
                "unmatched_observations": unmatched,
                "notice": (
                    "Runtime telemetry is supporting evidence. An authorized company "
                    "reviewer must decide reachability, affectedness, and reportability."
                ),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    ctx.runtime_telemetry_path = normalised_path
    ctx.telemetry_assessments_path = assessment_path
    ctx.ledger.append(
        stage="RUNTIME_TELEMETRY",
        tool="pandax.telemetry",
        tool_version="1",
        inputs=[ctx.ledger.ref(ctx.path("findings.matched.json"))],
        outputs=[
            ctx.ledger.ref(source_receipt_path),
            ctx.ledger.ref(normalised_path),
            ctx.ledger.ref(assessment_path),
        ],
        params={
            "source_sha256": sha256_file(source),
            "source_was_copied": False,
            "observations": len(document["observations"]),
            "matched_observations": matched_observations,
        },
    )

    yield ev.metric(STAGE, "findings with runtime evidence", findings_with_evidence)
    if unmatched:
        yield ev.log(
            STAGE,
            f"{len(unmatched)} observation(s) did not match a vulnerable component",
            ev.WARN,
        )
    yield ev.artifact(
        STAGE,
        ctx.ledger.rel(assessment_path),
        sha256_file(assessment_path),
        "review-required runtime evidence",
    )
    yield ev.done(
        STAGE,
        "approved telemetry attached as evidence; no legal decision was made",
        ev.GOOD,
    )


def summary(path: Path) -> dict[str, Any]:
    """Return a safe validation summary for CLI/API callers."""
    document = load(path)
    return {
        "valid": True,
        "schema": document["schema"],
        "product": document["product"],
        "approved_by": document["approval"]["operator"],
        "approved_at": document["approval"]["approved_at"],
        "observations": len(document["observations"]),
        "signals": sorted({item["signal"] for item in document["observations"]}),
    }
