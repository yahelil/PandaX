"""Generate a release report, put the bytes in private storage, record the revision.

The builder in `release_report` stays pure. This is the seam where it meets the
repositories and the object store, so the wiring is testable on its own and the
report itself never learns what a database is.

Regenerating a release whose findings have not moved returns the revision that
already exists. The report renders deterministically, so an unchanged release
hashes to what is already stored, and a new revision would claim a change that
did not happen.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from .documents import DocumentRepository
from .release_report import (
    ReleaseReport, build_release_report, render_release_report, report_filename,
)

REPORT_KIND = "evidence"
REPORT_FORMAT = "json"
REPORT_SUFFIX = ".json"
REPORT_NAME = "Release report"


class ReportStorage(Protocol):
    def put_document(
        self, organization_id: str, document_id: str, content: bytes, suffix: str
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class GeneratedReleaseReport:
    document_id: str
    revision: int
    report: ReleaseReport
    storage_locator: str
    created: bool          # False when an identical report was already stored


def _monitoring_for(monitoring: Any, organization_id: str, product_id: str, release_id: str) -> Any | None:
    """Absent monitoring is a fact about the release, not an error."""
    if monitoring is None:
        return None
    try:
        return monitoring.get(organization_id, product_id, release_id)
    except Exception:
        # The repository raises its own not-found type; anything else here would
        # still mean "we cannot describe coverage", which the report can say.
        return None


def _existing_report(documents: DocumentRepository, organization_id: str, product_id: str, release_id: str):
    for record in documents.list_documents(
        organization_id, product_id=product_id, release_id=release_id, kind=REPORT_KIND
    ):
        if record.name == REPORT_NAME:
            return record
    return None


def generate_release_report(
    *,
    organization_id: str,
    product_id: str,
    release_id: str,
    findings: Any,
    documents: DocumentRepository,
    storage: ReportStorage,
    actor_id: str,
    monitoring: Any | None = None,
    now: datetime | None = None,
    product_name: str | None = None,
    release_version: str | None = None,
) -> GeneratedReleaseReport:
    generated_at = now or datetime.now(timezone.utc)
    records = findings.list(
        organization_id,
        product_id=product_id,
        release_id=release_id,
        action_required=False,          # a report covers the release, not a worklist
    )
    document = build_release_report(
        organization_id=organization_id,
        product_id=product_id,
        release_id=release_id,
        findings=records,
        monitoring=_monitoring_for(monitoring, organization_id, product_id, release_id),
        generated_at=generated_at,
        product_name=product_name,
        release_version=release_version,
    )

    existing = _existing_report(documents, organization_id, product_id, release_id)
    next_revision = 1 if existing is None else existing.current_revision + 1
    rendered = render_release_report(
        document, filename=report_filename(release_id, revision=next_revision)
    )

    if existing is not None and existing.current.content_hash == rendered.content_hash:
        current = existing.current
        return GeneratedReleaseReport(
            existing.id, current.revision, rendered, current.storage_locator, created=False
        )

    stored = storage.put_document(organization_id, _scope(existing, release_id), rendered.content, REPORT_SUFFIX)
    provenance = {
        "generator": "release_report",
        "schema_version": document["schema_version"],
        "generated_at": document["generated_at"],
        "finding_count": document["summary"]["total"],
        "coverage_monitored": document["coverage"]["monitored"],
    }

    if existing is None:
        detail = documents.create_document(
            organization_id, product_id, name=REPORT_NAME, kind=REPORT_KIND,
            format=REPORT_FORMAT, content_hash=rendered.content_hash,
            storage_locator=stored.object_key, size_bytes=rendered.size_bytes,
            provenance=provenance, actor_id=actor_id, release_id=release_id,
        )
        return GeneratedReleaseReport(
            detail.document.id, 1, rendered, stored.object_key, created=True
        )

    revision = documents.add_revision(
        organization_id, existing.id,
        expected_current_revision=existing.current_revision,
        format=REPORT_FORMAT, content_hash=rendered.content_hash,
        storage_locator=stored.object_key, size_bytes=rendered.size_bytes,
        provenance=provenance, actor_id=actor_id,
    )
    return GeneratedReleaseReport(
        existing.id, revision.revision, rendered, stored.object_key, created=True
    )


def _scope(existing: Any, release_id: str) -> str:
    """Object keys are content-addressed; this only groups them somewhere sensible."""
    return existing.id if existing is not None else release_id
