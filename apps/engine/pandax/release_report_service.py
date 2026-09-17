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
from .release_report_pdf import render_release_report_pdf

REPORT_KIND = "evidence"
REPORT_FORMAT = "json"
REPORT_SUFFIX = ".json"
REPORT_NAME = "Release report"
PDF_REPORT_NAME = "Product release security report"


class ReportStorage(Protocol):
    def put_document(
        self, organization_id: str, document_id: str, content: bytes, suffix: str
    ) -> Any: ...

    def get(self, object_key: str, expected_sha256: str) -> bytes: ...


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
    product_identifier: str | None = None,
    manufacturer: str | None = None,
    cra_class: str | None = None,
) -> GeneratedReleaseReport:
    generated_at = now or datetime.now(timezone.utc)
    records = findings.list(
        organization_id,
        product_id=product_id,
        release_id=release_id,
        action_required=False,          # a report covers the release, not a worklist
    )
    existing = _existing_report(documents, organization_id, product_id, release_id)
    previous_generated_at = None
    if existing is not None:
        value = existing.current.provenance.get("generated_at")
        if isinstance(value, str):
            try:
                previous_generated_at = datetime.fromisoformat(value)
            except ValueError:
                pass
    document = build_release_report(
        organization_id=organization_id,
        product_id=product_id,
        release_id=release_id,
        findings=records,
        monitoring=_monitoring_for(monitoring, organization_id, product_id, release_id),
        generated_at=generated_at,
        product_name=product_name,
        release_version=release_version,
        product_identifier=product_identifier,
        manufacturer=manufacturer,
        cra_class=cra_class,
    )

    next_revision = 1 if existing is None else existing.current_revision + 1
    if existing is not None and previous_generated_at is not None:
        previous_document = build_release_report(
            organization_id=organization_id,
            product_id=product_id,
            release_id=release_id,
            findings=records,
            monitoring=_monitoring_for(monitoring, organization_id, product_id, release_id),
            generated_at=previous_generated_at,
            product_name=product_name,
            release_version=release_version,
            product_identifier=product_identifier,
            manufacturer=manufacturer,
            cra_class=cra_class,
        )
        previous_rendered = render_release_report(
            previous_document, filename=report_filename(release_id, revision=existing.current_revision)
        )
        if previous_rendered.content_hash == existing.current.content_hash:
            return GeneratedReleaseReport(
                existing.id, existing.current_revision, previous_rendered,
                existing.current.storage_locator, created=False,
            )
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


def generate_release_pdf(
    *,
    organization_id: str,
    product_id: str,
    release_id: str,
    findings: Any,
    documents: DocumentRepository,
    storage: ReportStorage,
    actor_id: str,
    monitoring: Any | None = None,
    product_name: str | None = None,
    release_version: str | None = None,
    product_identifier: str | None = None,
    manufacturer: str | None = None,
    cra_class: str | None = None,
) -> GeneratedReleaseReport:
    """Snapshot reviewed findings, then retain a PDF tied to that snapshot."""
    source = generate_release_report(
        organization_id=organization_id, product_id=product_id, release_id=release_id,
        findings=findings, documents=documents, storage=storage, actor_id=actor_id,
        monitoring=monitoring, product_name=product_name, release_version=release_version,
        product_identifier=product_identifier, manufacturer=manufacturer, cra_class=cra_class,
    )
    existing = next((record for record in documents.list_documents(
        organization_id, product_id=product_id, release_id=release_id, kind=REPORT_KIND,
    ) if record.name == PDF_REPORT_NAME), None)
    revision = 1 if existing is None else existing.current_revision + 1
    filename = f"release-security-report-{release_id}-r{revision}.pdf"
    if existing is not None and existing.current.provenance.get("source_report_hash") == source.report.content_hash:
        current = existing.current
        content = storage.get(current.storage_locator, current.content_hash)
        report = ReleaseReport(
            document=source.report.document, content=content,
            content_hash=current.content_hash, size_bytes=len(content),
            filename=f"release-security-report-{release_id}-r{current.revision}.pdf",
            content_type="application/pdf",
        )
        return GeneratedReleaseReport(existing.id, current.revision, report, current.storage_locator, False)

    report = render_release_report_pdf(source.report.document, filename=filename)
    stored = storage.put_document(organization_id, _scope(existing, release_id), report.content, ".pdf")
    provenance = {
        "generator": "release_report_pdf", "source_report_hash": source.report.content_hash,
        "source_document_id": source.document_id, "source_revision": source.revision,
        "generated_at": source.report.document["generated_at"],
        "finding_count": source.report.document["summary"]["total"],
        "incomplete": source.report.document["summary"]["awaiting_decision"] > 0,
    }
    if existing is None:
        detail = documents.create_document(
            organization_id, product_id, name=PDF_REPORT_NAME, kind=REPORT_KIND,
            format="pdf_a_2b", content_hash=report.content_hash,
            storage_locator=stored.object_key, size_bytes=report.size_bytes,
            provenance=provenance, actor_id=actor_id, release_id=release_id,
        )
        return GeneratedReleaseReport(detail.document.id, 1, report, stored.object_key, True)
    saved = documents.add_revision(
        organization_id, existing.id, expected_current_revision=existing.current_revision,
        format="pdf_a_2b", content_hash=report.content_hash,
        storage_locator=stored.object_key, size_bytes=report.size_bytes,
        provenance=provenance, actor_id=actor_id,
    )
    return GeneratedReleaseReport(existing.id, saved.revision, report, stored.object_key, True)
