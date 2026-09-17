"""The release report: what was found, what was decided, and what is covered.

Pure over records. Nothing here opens a database or writes to storage, so the
same report can be built from a repository, from a fixture, or from a test with
no fixture at all. Callers supply the records and the clock.

The bytes this produces are the bytes that get stored and served. The hash is
taken over exactly those bytes rather than over a re-encoding of the same
values, because a download whose hash describes a different encoding is worse
than no hash at all.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Mapping, Sequence

from . import __version__
from .evidence import sha256_bytes

SCHEMA_VERSION = "1.0"
CONTENT_TYPE = "application/json"

# Report order, worst first. Anything unrecognised sorts after these rather
# than raising: a report that refuses to render because a new severity
# appeared is less useful than one that shows it at the end.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "unknown")
DECISIONS = ("affected", "not_affected", "accepted_risk", "deferred")
REMEDIATION_STATES = ("not_planned", "planned", "in_progress", "completed", "verified")
FINDING_STATES = ("needs_review", "open", "in_progress", "resolved")
REACHABILITY_STATES = ("reachable", "not_reachable", "unknown")


@dataclass(frozen=True, slots=True)
class ReleaseReport:
    """A rendered report, with everything its caller needs to store it."""

    document: Mapping[str, Any]
    content: bytes
    content_hash: str
    size_bytes: int
    filename: str
    content_type: str = CONTENT_TYPE


def _moment(value: datetime | date | None) -> str | None:
    return value.isoformat() if value is not None else None


def _rank(value: str, order: Sequence[str]) -> int:
    try:
        return order.index(value)
    except ValueError:
        return len(order)


def _tally(values: Sequence[str], order: Sequence[str]) -> dict[str, int]:
    """Count into a fixed shape, so a reader can diff two reports field by field."""
    counted = Counter(values)
    tally = {key: counted.pop(key, 0) for key in order}
    for key in sorted(counted):          # anything the vocabulary did not know about
        tally[key] = counted[key]
    return tally


def _finding(record: Any) -> dict[str, Any]:
    return {
        "id": record.id,
        "reference_id": record.reference_id,
        "cve": record.cve,
        "title": record.title,
        "description": record.description,
        "component": record.component,
        "component_version": record.component_version,
        "purl": record.purl,
        "severity": record.severity,
        "cvss": record.cvss,
        "epss": record.epss,
        "known_exploited": record.kev,
        "reachability": record.reachability,
        "reachability_limitations": list(record.reachability_limitations),
        "status": record.status,
        "decision": record.current_decision,
        "decision_rationale": record.decision_rationale,
        "decided_at": _moment(record.decided_at),
        "remediation_status": record.remediation_status,
        "remediation_plan": record.remediation_plan,
        "remediation_due_date": _moment(record.remediation_due_date),
        "verification_evidence_count": len(record.verification_evidence),
        "source": record.source,
        "first_seen_at": _moment(record.first_seen_at),
        "last_seen_at": _moment(record.last_seen_at),
    }


def _ordering(entry: Mapping[str, Any]) -> tuple[Any, ...]:
    """Worst first, then stable. Two runs over the same data must agree."""
    return (
        _rank(str(entry["severity"]), SEVERITY_ORDER),
        not entry["known_exploited"],
        -(entry["cvss"] or 0.0),
        str(entry["cve"] or ""),
        str(entry["component"]),
        str(entry["id"]),
    )


def _coverage(monitoring: Any | None) -> dict[str, Any]:
    """What the monitoring configuration says it watches, and what it admits it does not."""
    if monitoring is None:
        return {
            "monitored": False,
            "reason": "No release monitoring is configured for this release.",
        }
    return {
        "monitored": True,
        "enabled": monitoring.enabled,
        "health": monitoring.health,
        "sources": list(monitoring.enabled_sources),
        "cadence_minutes": monitoring.cadence_minutes,
        "last_check_at": _moment(monitoring.last_check_at),
        "last_success_at": _moment(monitoring.last_success_at),
        "next_check_at": _moment(monitoring.next_check_at),
        "consecutive_failures": monitoring.consecutive_failures,
        "detail": dict(monitoring.coverage),
        "limitations": list(monitoring.limitations),
    }


def _summary(entries: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "total": len(entries),
        "known_exploited": sum(1 for item in entries if item["known_exploited"]),
        "awaiting_decision": sum(1 for item in entries if item["decision"] is None),
        "by_severity": _tally([str(item["severity"]) for item in entries], SEVERITY_ORDER),
        "by_status": _tally([str(item["status"]) for item in entries], FINDING_STATES),
        "by_reachability": _tally(
            [str(item["reachability"]) for item in entries], REACHABILITY_STATES
        ),
        "by_decision": _tally(
            [str(item["decision"]) for item in entries if item["decision"] is not None],
            DECISIONS,
        ),
        "by_remediation_status": _tally(
            [str(item["remediation_status"]) for item in entries], REMEDIATION_STATES
        ),
    }


def build_release_report(
    *,
    organization_id: str,
    product_id: str,
    release_id: str,
    findings: Sequence[Any],
    monitoring: Any | None = None,
    generated_at: datetime,
    product_name: str | None = None,
    release_version: str | None = None,
    product_identifier: str | None = None,
    manufacturer: str | None = None,
    cra_class: str | None = None,
) -> Mapping[str, Any]:
    """Assemble the report. The clock is an argument so two callers agree."""
    entries = sorted((_finding(item) for item in findings), key=_ordering)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "PandaX", "version": __version__},
        "generated_at": _moment(generated_at),
        "subject": {
            "organization_id": organization_id,
            "product_id": product_id,
            "product_name": product_name,
            "release_id": release_id,
            "release_version": release_version,
            "product_identifier": product_identifier,
            "manufacturer": manufacturer,
            "cra_class": cra_class,
        },
        "coverage": _coverage(monitoring),
        "summary": _summary(entries),
        "findings": entries,
        # This document reports what is recorded. It does not assess conformity.
        "notice": (
            "This report states the findings and decisions recorded against this "
            "release at the time of generation. It is not a conformity assessment "
            "and it does not issue an opinion, a certificate or a verdict."
        ),
    }


def render_release_report(
    document: Mapping[str, Any], *, filename: str
) -> ReleaseReport:
    """Render to the exact bytes that will be stored, hashed and served.

    Sorted keys and a fixed indent, so the same document always renders to the
    same bytes while staying readable to whoever opens the file.
    """
    content = (
        json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
        + "\n"
    ).encode("utf-8")
    return ReleaseReport(
        document=document,
        content=content,
        content_hash=sha256_bytes(content),
        size_bytes=len(content),
        filename=filename,
    )


def report_filename(release_id: str, *, revision: int) -> str:
    """A name that sorts, and that says which revision produced it."""
    safe = "".join(char if char.isalnum() or char in "-_" else "-" for char in release_id)
    return f"release-report-{safe}-r{revision}.json"
