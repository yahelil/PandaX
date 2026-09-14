"""Tenant-scoped immutable regulatory document revisions and workflow history."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Mapping
from uuid import uuid4

from sqlalchemy import (
    JSON, CheckConstraint, Column, DateTime, Engine, ForeignKeyConstraint, Integer,
    MetaData, String, Table, UniqueConstraint, insert, select, update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .portfolio import portfolio_metadata, products, releases


class DocumentError(RuntimeError):
    pass


class DocumentNotFound(DocumentError):
    pass


class DocumentConflict(DocumentError):
    pass


class DocumentValidationError(DocumentError):
    pass


DOCUMENT_KINDS = frozenset({"cra_reporting_pack", "conformity", "sbom", "vex", "evidence", "verification"})
DOCUMENT_FORMATS = frozenset({"pdf_a_2b", "cyclonedx_json", "csaf_vex", "zip", "json"})
DOCUMENT_STATUSES = frozenset({"draft", "pending", "approved", "rejected", "superseded"})
EVENT_STATUS = {
    "revision_created": "draft",
    "approval_requested": "pending",
    "approved": "approved",
    "rejected": "rejected",
    "superseded": "superseded",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _col(name: str, length_or_type: Any, *args: Any, **kwargs: Any) -> Column[Any]:
    value_type = String(length_or_type) if isinstance(length_or_type, int) else length_or_type
    return Column(name, value_type, *args, **kwargs)


documents = Table(
    "regulatory_documents", portfolio_metadata,
    _col("id", 36, primary_key=True),
    _col("organization_id", 36, nullable=False),
    _col("product_id", 36, nullable=False),
    _col("release_id", 36, nullable=True),
    _col("case_id", 128, nullable=True),
    _col("kind", 40, nullable=False),
    _col("name", 240, nullable=False),
    _col("current_revision", Integer, nullable=False),
    _col("created_by", 128, nullable=False),
    _col("created_at", DateTime(timezone=True), nullable=False),
    _col("updated_at", DateTime(timezone=True), nullable=False),
    ForeignKeyConstraint(
        ["product_id", "organization_id"],
        [products.c.id, products.c.organization_id],
        name="fk_regulatory_documents_product_scope", ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["release_id", "product_id", "organization_id"],
        [releases.c.id, releases.c.product_id, releases.c.organization_id],
        name="fk_regulatory_documents_release_scope", ondelete="RESTRICT",
    ),
    UniqueConstraint("id", "organization_id", name="uq_regulatory_documents_id_org"),
    CheckConstraint("current_revision >= 1", name="current_revision_positive"),
    CheckConstraint("kind IN ('cra_reporting_pack','conformity','sbom','vex','evidence','verification')", name="kind"),
)

document_revisions = Table(
    "regulatory_document_revisions", portfolio_metadata,
    _col("id", 36, primary_key=True),
    _col("organization_id", 36, nullable=False),
    _col("document_id", 36, nullable=False),
    _col("revision", Integer, nullable=False),
    _col("format", 32, nullable=False),
    _col("content_hash", 64, nullable=False),
    _col("storage_locator", 500, nullable=False),
    _col("size_bytes", Integer, nullable=False),
    _col("provenance", JSON, nullable=False),
    _col("created_by", 128, nullable=False),
    _col("created_at", DateTime(timezone=True), nullable=False),
    ForeignKeyConstraint(
        ["document_id", "organization_id"],
        [documents.c.id, documents.c.organization_id],
        name="fk_regulatory_document_revisions_document_scope", ondelete="CASCADE",
    ),
    UniqueConstraint("document_id", "revision", "organization_id", name="uq_regulatory_document_revisions_scope"),
    CheckConstraint("revision >= 1", name="revision_positive"),
    CheckConstraint("size_bytes >= 0", name="size_nonnegative"),
    CheckConstraint("format IN ('pdf_a_2b','cyclonedx_json','csaf_vex','zip','json')", name="format"),
    CheckConstraint("length(content_hash) = 64", name="hash_length"),
)

document_events = Table(
    "regulatory_document_events", portfolio_metadata,
    _col("id", 36, primary_key=True),
    _col("organization_id", 36, nullable=False),
    _col("document_id", 36, nullable=False),
    _col("revision", Integer, nullable=False),
    _col("sequence", Integer, nullable=False),
    _col("event_type", 40, nullable=False),
    _col("actor_id", 128, nullable=False),
    _col("reason", 1000, nullable=True),
    _col("occurred_at", DateTime(timezone=True), nullable=False),
    _col("details", JSON, nullable=False),
    ForeignKeyConstraint(
        ["document_id", "revision", "organization_id"],
        [document_revisions.c.document_id, document_revisions.c.revision, document_revisions.c.organization_id],
        name="fk_regulatory_document_events_revision_scope", ondelete="CASCADE",
    ),
    UniqueConstraint("document_id", "sequence", name="uq_regulatory_document_events_sequence"),
    CheckConstraint("sequence >= 1", name="sequence_positive"),
    CheckConstraint("event_type IN ('revision_created','approval_requested','approved','rejected','superseded','self_filing_recorded')", name="type"),
)

self_filing_records = Table(
    "regulatory_self_filing_records", portfolio_metadata,
    _col("id", 36, primary_key=True),
    _col("organization_id", 36, nullable=False),
    _col("document_id", 36, nullable=False),
    _col("revision", Integer, nullable=False),
    _col("external_submission_reference", 240, nullable=False),
    _col("submitted_at", DateTime(timezone=True), nullable=False),
    _col("receipt_evidence_locator", 500, nullable=False),
    _col("receipt_content_hash", 64, nullable=True),
    _col("recorded_by", 128, nullable=False),
    _col("recorded_at", DateTime(timezone=True), nullable=False),
    ForeignKeyConstraint(
        ["document_id", "revision", "organization_id"],
        [document_revisions.c.document_id, document_revisions.c.revision, document_revisions.c.organization_id],
        name="fk_regulatory_self_filings_revision_scope", ondelete="RESTRICT",
    ),
    UniqueConstraint("organization_id", "external_submission_reference", name="uq_regulatory_self_filings_external_reference"),
    CheckConstraint("receipt_content_hash IS NULL OR length(receipt_content_hash) = 64", name="receipt_hash_length"),
)


@dataclass(frozen=True, slots=True)
class RevisionRecord:
    id: str
    organization_id: str
    document_id: str
    revision: int
    format: str
    content_hash: str
    storage_locator: str
    size_bytes: int
    provenance: Mapping[str, Any]
    created_by: str
    created_at: datetime
    status: str


@dataclass(frozen=True, slots=True)
class EventRecord:
    id: str
    organization_id: str
    document_id: str
    revision: int
    sequence: int
    event_type: str
    actor_id: str
    reason: str | None
    occurred_at: datetime
    details: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class SelfFilingRecord:
    id: str
    organization_id: str
    document_id: str
    revision: int
    external_submission_reference: str
    submitted_at: datetime
    receipt_evidence_locator: str
    receipt_content_hash: str | None
    recorded_by: str
    recorded_at: datetime
    record_type: str = "operator_recorded_external_submission"


@dataclass(frozen=True, slots=True)
class DocumentRecord:
    id: str
    organization_id: str
    product_id: str
    release_id: str | None
    case_id: str | None
    kind: str
    name: str
    current_revision: int
    created_by: str
    created_at: datetime
    updated_at: datetime
    status: str
    current: RevisionRecord


@dataclass(frozen=True, slots=True)
class DocumentDetail:
    document: DocumentRecord
    revisions: tuple[RevisionRecord, ...]
    audit: tuple[EventRecord, ...]
    approval_history: tuple[EventRecord, ...]
    self_filings: tuple[SelfFilingRecord, ...]


class DocumentRepository:
    """Own immutable revisions, append-only workflow events, and tenant scope."""

    def __init__(self, engine: Engine):
        self.engine = engine

    def create_schema(self) -> None:
        portfolio_metadata.create_all(self.engine)

    def create_document(
        self, organization_id: str, product_id: str, *, name: str, kind: str,
        format: str, content_hash: str, storage_locator: str, size_bytes: int,
        provenance: Mapping[str, Any], actor_id: str, release_id: str | None = None,
        case_id: str | None = None, document_id: str | None = None,
    ) -> DocumentDetail:
        now = _now()
        document_id = document_id or _id()
        document_values = {
            "id": document_id, "organization_id": _required(organization_id, "organization_id", 36),
            "product_id": _required(product_id, "product_id", 36), "release_id": release_id,
            "case_id": _optional(case_id, "case_id", 128), "kind": _choice(kind, DOCUMENT_KINDS, "kind"),
            "name": _required(name, "name", 240), "current_revision": 1,
            "created_by": _required(actor_id, "actor_id", 128), "created_at": now, "updated_at": now,
        }
        revision_values = self._revision_values(
            organization_id, document_id, 1, format, content_hash, storage_locator,
            size_bytes, provenance, actor_id, now,
        )
        with Session(self.engine) as session, session.begin():
            self._require_scope(session, organization_id, product_id, release_id)
            try:
                session.execute(insert(documents).values(**document_values))
                session.execute(insert(document_revisions).values(**revision_values))
                self._event(session, organization_id, document_id, 1, "revision_created", actor_id, details={"content_hash": revision_values["content_hash"]})
            except IntegrityError as exc:
                raise DocumentConflict("document could not be created") from exc
        return self.get_document(organization_id, document_id)

    def add_revision(
        self, organization_id: str, document_id: str, *, expected_current_revision: int,
        format: str, content_hash: str, storage_locator: str, size_bytes: int,
        provenance: Mapping[str, Any], actor_id: str,
    ) -> RevisionRecord:
        now = _now()
        with Session(self.engine) as session, session.begin():
            row = self._document_row(session, organization_id, document_id)
            if row is None:
                raise DocumentNotFound("document not found")
            current = int(row.current_revision)
            if current != expected_current_revision:
                raise DocumentConflict("document current revision changed")
            next_revision = current + 1
            values = self._revision_values(
                organization_id, document_id, next_revision, format, content_hash,
                storage_locator, size_bytes, provenance, actor_id, now,
            )
            try:
                self._event(session, organization_id, document_id, current, "superseded", actor_id, details={"superseded_by": next_revision})
                session.execute(insert(document_revisions).values(**values))
                self._event(session, organization_id, document_id, next_revision, "revision_created", actor_id, details={"content_hash": values["content_hash"]})
                changed = session.execute(
                    update(documents).where(
                        documents.c.organization_id == organization_id,
                        documents.c.id == document_id,
                        documents.c.current_revision == expected_current_revision,
                    ).values(current_revision=next_revision, updated_at=now)
                )
                if changed.rowcount != 1:
                    raise DocumentConflict("document current revision changed")
            except IntegrityError as exc:
                raise DocumentConflict("document revision already exists") from exc
        return self.get_revision(organization_id, document_id, next_revision)

    def request_approval(self, organization_id: str, document_id: str, revision: int, *, expected_status: str, actor_id: str, comment: str | None = None) -> RevisionRecord:
        return self._transition(
            organization_id, document_id, revision, expected_status, {"draft"},
            "approval_requested", actor_id,
            _optional(comment, "comment", 1000),
        )

    def approve(self, organization_id: str, document_id: str, revision: int, *, expected_status: str, actor_id: str, comment: str | None = None) -> RevisionRecord:
        return self._transition(organization_id, document_id, revision, expected_status, {"pending"}, "approved", actor_id, comment)

    def reject(self, organization_id: str, document_id: str, revision: int, *, expected_status: str, actor_id: str, reason: str) -> RevisionRecord:
        return self._transition(organization_id, document_id, revision, expected_status, {"pending"}, "rejected", actor_id, _required(reason, "reason", 1000))

    def record_self_filing(
        self, organization_id: str, document_id: str, revision: int, *,
        external_submission_reference: str, submitted_at: datetime,
        receipt_evidence_locator: str, receipt_content_hash: str | None,
        actor_id: str,
    ) -> SelfFilingRecord:
        if submitted_at.tzinfo is None:
            raise DocumentValidationError("submitted_at requires a timezone")
        locator = _locator(receipt_evidence_locator)
        receipt_hash = _hash(receipt_content_hash) if receipt_content_hash else None
        with Session(self.engine) as session, session.begin():
            revision_row = self._revision_row(session, organization_id, document_id, revision)
            if revision_row is None:
                raise DocumentNotFound("document revision not found")
            if self._status(session, document_id, revision) != "approved":
                raise DocumentConflict("self-filing record requires an approved revision")
            now = _now()
            values = {
                "id": _id(), "organization_id": organization_id, "document_id": document_id,
                "revision": revision,
                "external_submission_reference": _required(external_submission_reference, "external_submission_reference", 240),
                "submitted_at": submitted_at.astimezone(timezone.utc),
                "receipt_evidence_locator": locator, "receipt_content_hash": receipt_hash,
                "recorded_by": _required(actor_id, "actor_id", 128), "recorded_at": now,
            }
            try:
                session.execute(insert(self_filing_records).values(**values))
                self._event(session, organization_id, document_id, revision, "self_filing_recorded", actor_id, details={"external_submission_reference": values["external_submission_reference"], "record_type": "operator_recorded_external_submission"})
            except IntegrityError as exc:
                raise DocumentConflict("external submission reference already recorded") from exc
        return self._get_self_filing(organization_id, values["id"])

    def get_document(self, organization_id: str, document_id: str) -> DocumentDetail:
        with Session(self.engine) as session:
            row = self._document_row(session, organization_id, document_id)
            if row is None:
                raise DocumentNotFound("document not found")
            revision_rows = session.execute(select(document_revisions).where(
                document_revisions.c.organization_id == organization_id,
                document_revisions.c.document_id == document_id,
            ).order_by(document_revisions.c.revision.desc())).all()
            event_rows = session.execute(select(document_events).where(
                document_events.c.organization_id == organization_id,
                document_events.c.document_id == document_id,
            ).order_by(document_events.c.sequence.desc())).all()
            filing_rows = session.execute(select(self_filing_records).where(
                self_filing_records.c.organization_id == organization_id,
                self_filing_records.c.document_id == document_id,
            ).order_by(self_filing_records.c.recorded_at.desc())).all()
            revisions = tuple(self._revision_record(session, item) for item in revision_rows)
            events = tuple(_event_record(item) for item in event_rows)
            filings = tuple(_filing_record(item) for item in filing_rows)
            current = next(item for item in revisions if item.revision == row.current_revision)
            record = _document_record(row, current)
        approvals = tuple(item for item in events if item.event_type in {"approval_requested", "approved", "rejected"})
        return DocumentDetail(record, revisions, events, approvals, filings)

    def get_revision(self, organization_id: str, document_id: str, revision: int) -> RevisionRecord:
        with Session(self.engine) as session:
            row = self._revision_row(session, organization_id, document_id, revision)
            if row is None:
                raise DocumentNotFound("document revision not found")
            return self._revision_record(session, row)

    def download_metadata(self, organization_id: str, document_id: str, revision: int) -> Mapping[str, Any]:
        item = self.get_revision(organization_id, document_id, revision)
        document = self.get_document(organization_id, document_id).document
        extension = {"pdf_a_2b": "pdf", "cyclonedx_json": "json", "csaf_vex": "json", "zip": "zip", "json": "json"}[item.format]
        return {
            "document_id": document_id, "revision": revision, "filename": f"{document.name}-r{revision}.{extension}",
            "format": item.format, "content_hash": item.content_hash, "size_bytes": item.size_bytes,
            "storage_locator": item.storage_locator,
            "content_type": {"pdf_a_2b": "application/pdf", "zip": "application/zip"}.get(item.format, "application/json"),
            "download_type": "storage_metadata_only",
        }

    def list_documents(
        self, organization_id: str, *, product_id: str | None = None,
        release_id: str | None = None, kind: str | None = None,
        status: str | None = None, sort: str = "updated_desc",
    ) -> list[DocumentRecord]:
        if kind is not None:
            _choice(kind, DOCUMENT_KINDS, "kind")
        if status is not None:
            _choice(status, DOCUMENT_STATUSES, "status")
        if sort not in {"updated_desc", "created_desc", "name_asc", "kind_asc"}:
            raise DocumentValidationError("unsupported document sort")
        with Session(self.engine) as session:
            query = select(documents).where(documents.c.organization_id == organization_id)
            if product_id:
                query = query.where(documents.c.product_id == product_id)
            if release_id:
                query = query.where(documents.c.release_id == release_id)
            if kind:
                query = query.where(documents.c.kind == kind)
            rows = session.execute(query).all()
            records = []
            for row in rows:
                revision_row = self._revision_row(session, organization_id, row.id, row.current_revision)
                if revision_row is None:
                    continue
                record = _document_record(row, self._revision_record(session, revision_row))
                if status is None or record.status == status:
                    records.append(record)
        keys = {
            "updated_desc": lambda item: (-item.updated_at.timestamp(), item.id),
            "created_desc": lambda item: (-item.created_at.timestamp(), item.id),
            "name_asc": lambda item: (item.name.casefold(), item.id),
            "kind_asc": lambda item: (item.kind, item.name.casefold(), item.id),
        }
        return sorted(records, key=keys[sort])

    def _transition(
        self, organization_id: str, document_id: str, revision: int,
        expected_status: str, allowed: set[str], event_type: str, actor_id: str,
        reason: str | None = None,
    ) -> RevisionRecord:
        _choice(expected_status, DOCUMENT_STATUSES, "expected_status")
        with Session(self.engine) as session, session.begin():
            if self._revision_row(session, organization_id, document_id, revision) is None:
                raise DocumentNotFound("document revision not found")
            current = self._status(session, document_id, revision)
            if current != expected_status or current not in allowed:
                raise DocumentConflict(f"document status changed; current status is {current}")
            try:
                self._event(session, organization_id, document_id, revision, event_type, actor_id, reason=reason)
                session.execute(update(documents).where(
                    documents.c.organization_id == organization_id,
                    documents.c.id == document_id,
                ).values(updated_at=_now()))
            except IntegrityError as exc:
                raise DocumentConflict("document status changed") from exc
        return self.get_revision(organization_id, document_id, revision)

    def _revision_values(self, organization_id: str, document_id: str, revision: int, format: str, content_hash: str, storage_locator: str, size_bytes: int, provenance: Mapping[str, Any], actor_id: str, created_at: datetime) -> dict[str, Any]:
        if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes < 0:
            raise DocumentValidationError("size_bytes must be a non-negative integer")
        if not isinstance(provenance, Mapping):
            raise DocumentValidationError("provenance must be an object")
        return {
            "id": _id(), "organization_id": organization_id, "document_id": document_id,
            "revision": revision, "format": _choice(format, DOCUMENT_FORMATS, "format"),
            "content_hash": _hash(content_hash), "storage_locator": _locator(storage_locator),
            "size_bytes": size_bytes, "provenance": dict(provenance),
            "created_by": _required(actor_id, "actor_id", 128), "created_at": created_at,
        }

    def _require_scope(self, session: Session, organization_id: str, product_id: str, release_id: str | None) -> None:
        product = session.execute(select(products.c.id).where(products.c.organization_id == organization_id, products.c.id == product_id)).one_or_none()
        if product is None:
            raise DocumentNotFound("product not found")
        if release_id and session.execute(select(releases.c.id).where(
            releases.c.organization_id == organization_id,
            releases.c.product_id == product_id,
            releases.c.id == release_id,
        )).one_or_none() is None:
            raise DocumentNotFound("release not found")

    def _event(self, session: Session, organization_id: str, document_id: str, revision: int, event_type: str, actor_id: str, *, reason: str | None = None, details: Mapping[str, Any] | None = None) -> None:
        sequence = session.execute(select(document_events.c.sequence).where(
            document_events.c.document_id == document_id,
        ).order_by(document_events.c.sequence.desc()).limit(1)).scalar_one_or_none()
        session.execute(insert(document_events).values(
            id=_id(), organization_id=organization_id, document_id=document_id,
            revision=revision, sequence=(sequence or 0) + 1, event_type=event_type,
            actor_id=_required(actor_id, "actor_id", 128), reason=reason,
            occurred_at=_now(), details=dict(details or {}),
        ))

    def _document_row(self, session: Session, organization_id: str, document_id: str):
        return session.execute(select(documents).where(documents.c.organization_id == organization_id, documents.c.id == document_id)).one_or_none()

    def _revision_row(self, session: Session, organization_id: str, document_id: str, revision: int):
        return session.execute(select(document_revisions).where(
            document_revisions.c.organization_id == organization_id,
            document_revisions.c.document_id == document_id,
            document_revisions.c.revision == revision,
        )).one_or_none()

    def _status(self, session: Session, document_id: str, revision: int) -> str:
        event_type = session.execute(select(document_events.c.event_type).where(
            document_events.c.document_id == document_id,
            document_events.c.revision == revision,
            document_events.c.event_type.in_(tuple(EVENT_STATUS)),
        ).order_by(document_events.c.sequence.desc()).limit(1)).scalar_one()
        return EVENT_STATUS[event_type]

    def _revision_record(self, session: Session, row: Any) -> RevisionRecord:
        return RevisionRecord(
            id=row.id, organization_id=row.organization_id, document_id=row.document_id,
            revision=row.revision, format=row.format, content_hash=row.content_hash,
            storage_locator=row.storage_locator, size_bytes=row.size_bytes,
            provenance=dict(row.provenance), created_by=row.created_by,
            created_at=_aware(row.created_at), status=self._status(session, row.document_id, row.revision),
        )

    def _get_self_filing(self, organization_id: str, filing_id: str) -> SelfFilingRecord:
        with Session(self.engine) as session:
            row = session.execute(select(self_filing_records).where(
                self_filing_records.c.organization_id == organization_id,
                self_filing_records.c.id == filing_id,
            )).one_or_none()
        if row is None:
            raise DocumentNotFound("self-filing record not found")
        return _filing_record(row)


def _document_record(row: Any, current: RevisionRecord) -> DocumentRecord:
    return DocumentRecord(
        id=row.id, organization_id=row.organization_id, product_id=row.product_id,
        release_id=row.release_id, case_id=row.case_id, kind=row.kind, name=row.name,
        current_revision=row.current_revision, created_by=row.created_by,
        created_at=_aware(row.created_at), updated_at=_aware(row.updated_at),
        status=current.status, current=current,
    )


def _event_record(row: Any) -> EventRecord:
    return EventRecord(
        id=row.id, organization_id=row.organization_id, document_id=row.document_id,
        revision=row.revision, sequence=row.sequence, event_type=row.event_type,
        actor_id=row.actor_id, reason=row.reason, occurred_at=_aware(row.occurred_at),
        details=dict(row.details),
    )


def _filing_record(row: Any) -> SelfFilingRecord:
    return SelfFilingRecord(
        id=row.id, organization_id=row.organization_id, document_id=row.document_id,
        revision=row.revision, external_submission_reference=row.external_submission_reference,
        submitted_at=_aware(row.submitted_at), receipt_evidence_locator=row.receipt_evidence_locator,
        receipt_content_hash=row.receipt_content_hash, recorded_by=row.recorded_by,
        recorded_at=_aware(row.recorded_at),
    )


def _required(value: str, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DocumentValidationError(f"{field} is required")
    result = value.strip()
    if len(result) > maximum:
        raise DocumentValidationError(f"{field} is too long")
    return result


def _optional(value: str | None, field: str, maximum: int) -> str | None:
    return _required(value, field, maximum) if value is not None else None


def _choice(value: str, choices: frozenset[str], field: str) -> str:
    result = _required(value, field, 64)
    if result not in choices:
        raise DocumentValidationError(f"unsupported {field}")
    return result


def _hash(value: str) -> str:
    result = _required(value, "content_hash", 64).lower()
    if not SHA256_RE.fullmatch(result):
        raise DocumentValidationError("content_hash must be a SHA-256 hex digest")
    return result


def _locator(value: str) -> str:
    result = _required(value, "storage_locator", 500)
    if (
        "\\" in result or "://" in result or result.startswith(("/", "~"))
        or "//" in result or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", result)
    ):
        raise DocumentValidationError("storage_locator must be a relative storage key")
    path = PurePosixPath(result)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise DocumentValidationError("storage_locator contains an unsafe path segment")
    return path.as_posix()


def _id() -> str:
    return str(uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
