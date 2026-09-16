from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timezone
from typing import Any, Mapping

from pandax.evidence import sha256_bytes
from pandax.release_report import (
    build_release_report, render_release_report, report_filename,
)

NOW = datetime(2026, 9, 16, 9, 30, tzinfo=timezone.utc)


@dataclass(frozen=True)
class Finding:
    """The fields the report reads, and only those."""

    id: str = "f-1"
    reference_id: str = "PX-1"
    cve: str | None = "CVE-2024-0001"
    title: str = "Heap overflow"
    component: str = "curl"
    component_version: str = "8.3.0"
    purl: str | None = "pkg:generic/curl@8.3.0"
    severity: str = "high"
    cvss: float | None = 7.5
    epss: float | None = 0.12
    kev: bool = False
    reachability: str = "reachable"
    reachability_limitations: tuple[str, ...] = ()
    status: str = "open"
    current_decision: str | None = None
    decision_rationale: str | None = None
    decided_at: datetime | None = None
    remediation_status: str = "planned"
    remediation_plan: str | None = None
    remediation_due_date: date | None = None
    verification_evidence: tuple[Mapping[str, Any], ...] = ()
    source: str = "osv"
    first_seen_at: datetime = NOW
    last_seen_at: datetime = NOW


@dataclass(frozen=True)
class Monitoring:
    enabled: bool = True
    health: str = "healthy"
    enabled_sources: tuple[str, ...] = ("osv", "kev")
    cadence_minutes: int = 1440
    last_check_at: datetime | None = NOW
    last_success_at: datetime | None = NOW
    next_check_at: datetime | None = None
    consecutive_failures: int = 0
    coverage: Mapping[str, Any] = field(default_factory=lambda: {"status": "complete"})
    limitations: tuple[str, ...] = ()


def report(findings=(), monitoring=None, **kwargs):
    return build_release_report(
        organization_id="org-acme", product_id="prod-gw", release_id="4.2.1",
        findings=findings, monitoring=monitoring, generated_at=NOW, **kwargs,
    )


def test_renders_the_same_bytes_every_time():
    """Two runs over the same records must agree, or the hash means nothing."""
    findings = [Finding(id="f-2", cve="CVE-2024-0002"), Finding()]
    first = render_release_report(report(findings), filename="r.json")
    second = render_release_report(report(list(reversed(findings))), filename="r.json")
    assert first.content == second.content
    assert first.content_hash == second.content_hash


def test_the_hash_describes_the_bytes_that_get_served():
    rendered = render_release_report(report([Finding()]), filename="r.json")
    assert rendered.content_hash == sha256_bytes(rendered.content)
    assert rendered.size_bytes == len(rendered.content)
    assert json.loads(rendered.content)["subject"]["release_id"] == "4.2.1"


def test_worst_findings_come_first():
    findings = [
        Finding(id="low", severity="low", cvss=2.0),
        Finding(id="critical", severity="critical", cvss=9.8),
        Finding(id="high-kev", severity="high", cvss=7.0, kev=True),
        Finding(id="high-plain", severity="high", cvss=7.0),
    ]
    order = [item["id"] for item in report(findings)["findings"]]
    assert order == ["critical", "high-kev", "high-plain", "low"]


def test_an_unfamiliar_severity_is_shown_last_rather_than_refused():
    findings = [Finding(id="odd", severity="moderate"), Finding(id="known", severity="low")]
    built = report(findings)
    assert [item["id"] for item in built["findings"]] == ["known", "odd"]
    assert built["summary"]["by_severity"]["moderate"] == 1


def test_the_tally_keeps_its_shape_when_a_bucket_is_empty():
    """A reader diffing two reports should not have to handle missing keys."""
    built = report([Finding(severity="high")])
    assert built["summary"]["by_severity"] == {
        "critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 0,
    }
    assert set(built["summary"]["by_remediation_status"]) == {
        "not_planned", "planned", "in_progress", "completed", "verified",
    }


def test_counts_what_needs_attention():
    findings = [
        Finding(id="a", kev=True),
        Finding(id="b", current_decision="not_affected", decided_at=NOW),
        Finding(id="c"),
    ]
    summary = report(findings)["summary"]
    assert summary["total"] == 3
    assert summary["known_exploited"] == 1
    assert summary["awaiting_decision"] == 2
    assert summary["by_decision"]["not_affected"] == 1


def test_an_empty_release_reports_zero_rather_than_nothing():
    built = report([])
    assert built["summary"]["total"] == 0
    assert built["findings"] == []
    assert built["summary"]["by_severity"]["critical"] == 0


def test_coverage_says_so_when_nothing_is_monitored():
    coverage = report([], monitoring=None)["coverage"]
    assert coverage["monitored"] is False
    assert "No release monitoring" in coverage["reason"]


def test_coverage_carries_the_limitations_rather_than_hiding_them():
    monitoring = Monitoring(
        health="degraded", consecutive_failures=2,
        limitations=("EPSS unavailable", "vendor feed stale"),
    )
    coverage = report([], monitoring=monitoring)["coverage"]
    assert coverage["monitored"] is True
    assert coverage["health"] == "degraded"
    assert coverage["consecutive_failures"] == 2
    assert coverage["limitations"] == ["EPSS unavailable", "vendor feed stale"]
    assert coverage["sources"] == ["osv", "kev"]


def test_a_finding_carries_its_own_limitations():
    finding = Finding(reachability_limitations=("no runtime telemetry",))
    entry = report([finding])["findings"][0]
    assert entry["reachability_limitations"] == ["no runtime telemetry"]


def test_dates_are_iso_strings_so_the_file_is_readable():
    finding = Finding(
        decided_at=NOW, remediation_due_date=date(2026, 10, 1),
        current_decision="affected",
    )
    entry = report([finding])["findings"][0]
    assert entry["decided_at"] == "2026-09-16T09:30:00+00:00"
    assert entry["remediation_due_date"] == "2026-10-01"


def test_the_report_refuses_to_issue_a_verdict():
    notice = report([])["notice"]
    assert "not a conformity assessment" in notice
    assert "verdict" in notice


def test_verification_evidence_is_counted_not_copied():
    """The report says how much proof exists without inlining somebody's payload."""
    finding = Finding(verification_evidence=({"kind": "test"}, {"kind": "scan"}))
    entry = report([finding])["findings"][0]
    assert entry["verification_evidence_count"] == 2
    assert "verification_evidence" not in entry


def test_the_filename_says_which_revision_made_it():
    assert report_filename("4.2.1", revision=3) == "release-report-4-2-1-r3.json"


def test_a_release_id_cannot_escape_the_filename():
    assert "/" not in report_filename("../../etc/passwd", revision=1)
    assert report_filename("a/b", revision=1) == "release-report-a-b-r1.json"


def test_product_and_release_names_ride_along_when_known():
    built = report([], product_name="Gateway controller", release_version="4.2.1")
    assert built["subject"]["product_name"] == "Gateway controller"
    assert built["subject"]["release_version"] == "4.2.1"
    assert report([])["subject"]["product_name"] is None


def test_reordering_a_finding_does_not_change_the_hash():
    """Guards the ordering: the store must not see a new revision for no change."""
    base = Finding(id="x")
    other = replace(base, id="y", cve="CVE-2024-9999")
    one = render_release_report(report([base, other]), filename="r.json")
    two = render_release_report(report([other, base]), filename="r.json")
    assert one.content_hash == two.content_hash


def test_the_report_only_reads_fields_the_real_records_have():
    """The stubs above are a convenience. This is the contract.

    Without it the report drifts from FindingRecord silently and only fails in
    production, where the records come from the database rather than a test.
    """
    import dataclasses
    import inspect
    import re

    from pandax import release_report
    from pandax.findings import FindingRecord
    from pandax.release_monitoring import ReleaseMonitoringRecord

    def reads(function, name):
        return set(re.findall(rf"{name}\.([a-z_]+)", inspect.getsource(function)))

    def fields(cls):
        return {item.name for item in dataclasses.fields(cls)}

    finding_reads = reads(release_report._finding, "record")
    monitoring_reads = reads(release_report._coverage, "monitoring")

    assert finding_reads, "the check itself must still find attribute reads"
    assert finding_reads <= fields(FindingRecord)
    assert monitoring_reads <= fields(ReleaseMonitoringRecord)
    # and the stubs must not omit anything the report actually reads
    assert finding_reads <= fields(Finding)
    assert monitoring_reads <= fields(Monitoring)
