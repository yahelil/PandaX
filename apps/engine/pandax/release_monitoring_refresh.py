"""Refresh release findings from durable evidence and public advisory feeds."""

from __future__ import annotations

import io
import json
import zipfile
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from .analysis_jobs import AnalysisJobRepository
from .context import CACHE_DIR
from .feeds import EPSS_URL, KEV_URL, Feeds
from .findings import FindingRepository, observation_from_scan_finding
from .release_monitoring import (
    MonitoringClaim,
    MonitoringObservation,
    MonitoringRunFailed,
    ReleaseMonitoringRunner,
)
from .stages.match import findings_from_advisories
from .stages.sbom import is_matchable_purl


def durable_release_monitoring_runner(
    analysis_repository: AnalysisJobRepository,
    finding_repository: FindingRepository,
    *,
    feeds_factory: Callable[[], Any] = lambda: Feeds(CACHE_DIR),
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> ReleaseMonitoringRunner:
    """Build a runner that never depends on process-local release state."""

    def run(claim: MonitoringClaim) -> MonitoringObservation:
        required = {"osv", "cisa_kev", "epss"}
        if not required.issubset(claim.enabled_sources):
            raise MonitoringRunFailed(
                "durable monitoring requires OSV, CISA KEV, and EPSS",
                ("Restore the default release monitoring sources and retry.",),
            )

        job = _latest_completed_job(analysis_repository, claim)
        components = _release_inventory(analysis_repository, claim, job.id)
        checked_at = now().astimezone(timezone.utc).isoformat(timespec="seconds")
        feeds = feeds_factory()
        try:
            purls = list(dict.fromkeys(item["purl"] for item in components))
            try:
                hits = feeds.query_purls(purls)
                if not isinstance(hits, Mapping):
                    raise ValueError("OSV returned an invalid response")
                normalized_hits = {
                    purl: [str(item) for item in hits.get(purl, [])]
                    for purl in purls
                }
                advisory_ids = sorted(
                    {item for rows in normalized_hits.values() for item in rows}
                )
                advisories = {item: feeds.vuln_detail(item) for item in advisory_ids}
            except Exception as exc:
                raise MonitoringRunFailed(
                    "OSV advisory refresh failed",
                    ("Last-known findings were retained; OSV coverage is stale.",),
                ) from exc

            findings = findings_from_advisories(
                components, normalized_hits, advisories, checked_at
            )
            try:
                kev = feeds.kev()
                if not isinstance(kev, Mapping):
                    raise ValueError("CISA KEV returned an invalid response")
            except Exception as exc:
                raise MonitoringRunFailed(
                    "CISA KEV refresh failed",
                    ("Last-known findings were retained; exploitation coverage is stale.",),
                ) from exc

            limitations: list[str] = []
            try:
                epss = feeds.epss({finding.cve for finding in findings})
            except Exception:
                epss = {}
                limitations.append(
                    "FIRST EPSS enrichment failed; vulnerability matches remain valid."
                )
            epss_status = str(getattr(feeds, "last_epss_status", "completed"))
            if epss_status == "failed":
                limitations.append("FIRST EPSS enrichment was incomplete.")

            for finding in findings:
                finding.kev = finding.cve in kev
                finding.kev_check_status = "completed"
                finding.kev_source_url = KEV_URL
                finding.kev_checked_at = checked_at
                finding.epss = float(epss.get(finding.cve, 0.0))
                finding.epss_check_status = epss_status
                finding.epss_source_url = EPSS_URL
                finding.epss_checked_at = checked_at

            observations = [
                observation_from_scan_finding(
                    finding.as_dict(), f"monitoring:{claim.id}"
                )
                for finding in findings
            ]
            finding_repository.upsert_from_analysis(
                claim.organization_id,
                claim.product_id,
                claim.release_id,
                f"monitoring:{claim.id}",
                observations,
                actor_id=claim.actor_id,
                seen_at=now(),
            )
            coverage = {
                "status": "partial" if limitations else "complete",
                "checked_at": checked_at,
                "baseline_analysis_id": job.id,
                "components_checked": len(components),
                "findings_observed": len(findings),
                "sources": {
                    "osv": "completed",
                    "cisa_kev": "completed",
                    "epss": epss_status,
                },
            }
            return MonitoringObservation(
                coverage=coverage,
                limitations=tuple(dict.fromkeys(limitations)),
                message="Durable release advisory refresh completed",
            )
        finally:
            feeds.close()

    return run


def _latest_completed_job(repository: AnalysisJobRepository, claim: MonitoringClaim):
    try:
        completed = [
            job
            for job in repository.list(
                claim.organization_id, claim.product_id, claim.release_id
            )
            if job.status == "completed" and job.completed_at is not None
        ]
    except Exception as exc:
        raise MonitoringRunFailed(
            "release analysis baseline is unavailable",
            ("No release findings were changed.",),
        ) from exc
    if not completed:
        raise MonitoringRunFailed(
            "release has no completed analysis baseline",
            ("Complete an analysis before enabling release monitoring.",),
        )
    return max(completed, key=lambda job: (job.completed_at, job.id))


def _release_inventory(
    repository: AnalysisJobRepository, claim: MonitoringClaim, job_id: str
) -> list[dict[str, str]]:
    try:
        content, _ = repository.export_evidence(
            claim.organization_id, claim.product_id, claim.release_id, job_id
        )
        with zipfile.ZipFile(io.BytesIO(content)) as bundle:
            document = json.loads(bundle.read("sbom.cdx.json"))
    except Exception as exc:
        raise MonitoringRunFailed(
            "retained release SBOM is unavailable",
            ("No release findings were changed.",),
        ) from exc
    raw_components = (
        document.get("components") if isinstance(document, Mapping) else None
    )
    if not isinstance(raw_components, list):
        raise MonitoringRunFailed("retained release SBOM has no component inventory")
    inventory = [
        {
            "name": str(item.get("name") or ""),
            "version": str(item.get("version") or ""),
            "purl": str(item.get("purl") or ""),
            "bom_ref": str(
                item.get("bom-ref")
                or item.get("bom_ref")
                or item.get("purl")
                or ""
            ),
        }
        for item in raw_components
        if isinstance(item, Mapping) and is_matchable_purl(item.get("purl"))
    ]
    if not inventory:
        raise MonitoringRunFailed(
            "retained release SBOM has no matchable versioned package URLs"
        )
    return inventory
