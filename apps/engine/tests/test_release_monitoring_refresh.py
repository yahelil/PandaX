import io
import json
import zipfile
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from pandax.release_monitoring import MonitoringClaim, MonitoringRunFailed
from pandax.release_monitoring_refresh import durable_release_monitoring_runner


NOW = datetime(2026, 9, 16, 9, 0, tzinfo=timezone.utc)


def claim(**changes):
    values = {
        "id": "claim-1",
        "organization_id": "org-acme",
        "product_id": "product-camera",
        "release_id": "release-1",
        "trigger": "scheduled",
        "actor_id": "monitoring-scheduler",
        "enabled_sources": ("osv", "cisa_kev", "epss"),
        "cadence_minutes": 60,
        "claimed_at": NOW,
        "expires_at": NOW,
    }
    values.update(changes)
    return MonitoringClaim(**values)


def evidence_bundle():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            "sbom.cdx.json",
            json.dumps(
                {
                    "components": [
                        {
                            "name": "demo-lib",
                            "version": "1.0.0",
                            "purl": "pkg:npm/demo-lib@1.0.0",
                            "bom-ref": "component-1",
                        }
                    ]
                }
            ),
        )
    return buffer.getvalue()


class AnalysisRepository:
    def __init__(self, content=evidence_bundle()):
        self.content = content
        self.requests = []

    def list(self, organization_id, product_id, release_id):
        self.requests.append((organization_id, product_id, release_id))
        return [
            SimpleNamespace(
                id="analysis-1", status="completed", completed_at=NOW
            )
        ]

    def export_evidence(self, organization_id, product_id, release_id, job_id):
        assert (organization_id, product_id, release_id, job_id) == (
            "org-acme",
            "product-camera",
            "release-1",
            "analysis-1",
        )
        return self.content, "evidence.zip"


class FindingRepository:
    def __init__(self):
        self.calls = []

    def upsert_from_analysis(self, *args, **kwargs):
        self.calls.append((args, kwargs))


class Feeds:
    last_epss_status = "completed"

    def __init__(self, *, fail_osv=False, fail_kev=False):
        self.fail_osv = fail_osv
        self.fail_kev = fail_kev
        self.closed = False

    def query_purls(self, purls):
        if self.fail_osv:
            raise RuntimeError("offline")
        return {purls[0]: ["GHSA-demo"]}

    def vuln_detail(self, advisory_id):
        return {
            "id": advisory_id,
            "aliases": ["CVE-2026-0001"],
            "summary": "Demo vulnerability",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H"}],
            "affected": [],
        }

    def kev(self):
        if self.fail_kev:
            raise RuntimeError("offline")
        return {"CVE-2026-0001": {"dateAdded": "2026-09-01"}}

    def epss(self, cves):
        assert cves == {"CVE-2026-0001"}
        return {"CVE-2026-0001": 0.42}

    def close(self):
        self.closed = True


def test_refresh_loads_tenant_scoped_evidence_and_projects_findings():
    analyses = AnalysisRepository()
    findings = FindingRepository()
    feeds = Feeds()
    runner = durable_release_monitoring_runner(
        analyses, findings, feeds_factory=lambda: feeds, now=lambda: NOW
    )

    result = runner(claim())

    assert analyses.requests == [("org-acme", "product-camera", "release-1")]
    assert result.coverage["baseline_analysis_id"] == "analysis-1"
    assert result.coverage["findings_observed"] == 1
    assert result.limitations == ()
    args, kwargs = findings.calls[0]
    assert args[:4] == (
        "org-acme",
        "product-camera",
        "release-1",
        "monitoring:claim-1",
    )
    observation = args[4][0]
    assert observation.cve == "CVE-2026-0001"
    assert observation.kev is True
    assert observation.epss == 0.42
    assert observation.provenance["bom_ref"] == "component-1"
    assert kwargs["actor_id"] == "monitoring-scheduler"
    assert feeds.closed is True


@pytest.mark.parametrize("source", ["osv", "kev"])
def test_source_failure_retains_existing_findings(source):
    findings = FindingRepository()
    feeds = Feeds(fail_osv=source == "osv", fail_kev=source == "kev")
    runner = durable_release_monitoring_runner(
        AnalysisRepository(), findings, feeds_factory=lambda: feeds, now=lambda: NOW
    )

    with pytest.raises(MonitoringRunFailed, match="refresh failed"):
        runner(claim())

    assert findings.calls == []
    assert feeds.closed is True


def test_missing_durable_baseline_fails_closed():
    analyses = AnalysisRepository()
    analyses.list = lambda *_args: []
    findings = FindingRepository()
    runner = durable_release_monitoring_runner(
        analyses, findings, feeds_factory=Feeds, now=lambda: NOW
    )

    with pytest.raises(MonitoringRunFailed, match="no completed analysis baseline"):
        runner(claim())

    assert findings.calls == []
