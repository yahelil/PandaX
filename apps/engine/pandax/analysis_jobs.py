"""Persisted, tenant-scoped release analysis jobs.

The repository is the lifecycle seam: it validates and retains an SBOM,
serializes state transitions, records every transition/pipeline event, and
projects the existing PandaX event stream into a stable result summary.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import tarfile
import tempfile
import unicodedata
import zipfile
from collections.abc import Callable, Iterable, Mapping
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    JSON,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKeyConstraint,
    Integer,
    Index,
    LargeBinary,
    String,
    Table,
    UniqueConstraint,
    delete,
    func,
    insert,
    select,
    text,
    update,
)
from sqlalchemy.engine import Engine, RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import events as pipeline_events
from . import exposure, pipeline, telemetry
from .analysis_storage import AnalysisInputStorage, AnalysisInputStorageError, MemoryAnalysisInputStorage
from .portfolio import portfolio_metadata, products, releases
from .stages import ingest as artifact_ingest
from .stages.sbom import SbomError, inspect_sbom
from .organization_settings import OrganizationSettingsRepository, SettingsValidationError
from .settings_api import _bundle_directory

MAX_SBOM_BYTES = 10 * 1024 * 1024
MAX_COLLECTOR_BYTES = 25_000_000
MAX_COLLECTOR_ENTRIES = 256
MAX_COLLECTOR_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
MAX_COLLECTOR_COMPRESSION_RATIO = 100
MAX_RAW_ARTIFACT_BYTES = 50_000_000
COLLECTOR_MANIFEST = "actis-collector-manifest.json"
ALLOWED_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "application/vnd.cyclonedx+json",
        "application/spdx+json",
    }
)
COLLECTOR_MEDIA_TYPES = frozenset({"application/zip", "application/x-zip-compressed"})
RAW_MEDIA_BY_EXTENSION = {
    ".zip": frozenset({"application/zip", "application/x-zip-compressed"}),
    ".tar": frozenset({"application/x-tar"}),
    ".tar.gz": frozenset({"application/gzip", "application/x-gzip"}),
    ".tgz": frozenset({"application/gzip", "application/x-gzip"}),
    ".bin": frozenset({"application/octet-stream"}),
    ".img": frozenset({"application/octet-stream"}),
}
HOSTED_ENVIRONMENTS = frozenset({"staging", "beta", "production"})
INPUT_TYPES = frozenset({"sbom", "collector", "raw_artifact"})
JOB_STATUSES = frozenset({"queued", "running", "completed", "failed", "unsupported"})
TERMINAL_STATUSES = frozenset({"completed", "failed", "unsupported"})
EVIDENCE_OBJECT_LIMIT_BYTES = 50_000_000
EVIDENCE_ORGANIZATION_LIMIT_BYTES = 200_000_000
EVIDENCE_PROJECT_LIMIT_BYTES = 800_000_000
BACKUP_RETENTION_DAYS = 30


class AnalysisJobError(RuntimeError):
    """Base error safe to translate at the HTTP seam."""


class AnalysisJobNotFound(AnalysisJobError):
    pass


class AnalysisJobConflict(AnalysisJobError):
    pass


class AnalysisJobValidationError(AnalysisJobError):
    pass


@dataclass(frozen=True, slots=True)
class SbomPreview:
    format: str
    version: str
    components: int
    matchable_components: int
    skipped_components: int
    product: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class AnalysisJobRecord:
    id: str
    organization_id: str
    product_id: str
    release_id: str
    idempotency_key: str
    input_type: str
    filename: str
    media_type: str
    size_bytes: int
    sha256: str
    input_format: str
    input_version: str
    preview: Mapping[str, Any]
    object_key: str | None
    retained_until: datetime | None
    input_metadata: Mapping[str, Any]
    consented_at: datetime | None
    consent_actor_id: str | None
    status: str
    stage: str
    progress: int
    result: Mapping[str, Any] | None
    error: str | None
    actor_id: str
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


@dataclass(frozen=True, slots=True)
class AnalysisJobEventRecord:
    id: str
    job_id: str
    sequence: int
    kind: str
    status: str
    stage: str
    progress: int
    message: str
    details: Mapping[str, Any]
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class EvidenceBundleRecord:
    id: str
    job_id: str
    organization_id: str
    object_key: str
    filename: str
    sha256: str
    size_bytes: int
    created_at: datetime
    retained_until: datetime
    state: str
    legal_hold: bool
    hold_reason: str | None
    held_at: datetime | None
    held_by: str | None
    deleted_at: datetime | None
    backup_expires_at: datetime | None
    deletion_receipt: Mapping[str, Any] | None


AnalysisRunner = Callable[..., Iterable[pipeline_events.Event]]


analysis_jobs = Table(
    "analysis_jobs",
    portfolio_metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("product_id", String(36), nullable=False),
    Column("release_id", String(36), nullable=False),
    Column("idempotency_key", String(128), nullable=False),
    Column("input_type", String(24), nullable=False, default="sbom"),
    Column("filename", String(255), nullable=False),
    Column("media_type", String(100), nullable=False),
    Column("size_bytes", Integer, nullable=False),
    Column("storage_size_bytes", Integer, nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("input_format", String(24), nullable=False),
    Column("input_version", String(24), nullable=False),
    Column("preview", JSON, nullable=False),
    Column("input_content", LargeBinary, nullable=True),
    Column("object_key", String(500), nullable=True),
    Column("retained_until", DateTime(timezone=True), nullable=True),
    Column("input_metadata", JSON, nullable=False, default=dict),
    Column("consented_at", DateTime(timezone=True), nullable=True),
    Column("consent_actor_id", String(128), nullable=True),
    Column("status", String(24), nullable=False),
    Column("stage", String(80), nullable=False),
    Column("progress", Integer, nullable=False),
    Column("result", JSON, nullable=True),
    Column("error", String(1000), nullable=True),
    Column("actor_id", String(128), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("started_at", DateTime(timezone=True), nullable=True),
    Column("completed_at", DateTime(timezone=True), nullable=True),
    ForeignKeyConstraint(
        ["release_id", "product_id", "organization_id"],
        [
            "portfolio_releases.id",
            "portfolio_releases.product_id",
            "portfolio_releases.organization_id",
        ],
        name="fk_analysis_jobs_release_scope",
        ondelete="CASCADE",
    ),
    UniqueConstraint(
        "organization_id",
        "release_id",
        "idempotency_key",
        name="uq_analysis_jobs_release_idempotency",
    ),
    CheckConstraint(
        "input_type IN ('sbom','collector','raw_artifact')",
        name="analysis_jobs_input_type",
    ),
    CheckConstraint(
        "input_content IS NOT NULL OR (object_key IS NOT NULL AND retained_until IS NOT NULL)",
        name="analysis_jobs_input_reference",
    ),
    CheckConstraint(
        "input_type != 'raw_artifact' OR (consented_at IS NOT NULL AND consent_actor_id IS NOT NULL)",
        name="analysis_jobs_raw_consent",
    ),
)
Index("ix_analysis_jobs_retention", analysis_jobs.c.retained_until)

analysis_job_events = Table(
    "analysis_job_events",
    portfolio_metadata,
    Column("id", String(36), primary_key=True),
    Column("job_id", String(36), nullable=False),
    Column("sequence", Integer, nullable=False),
    Column("kind", String(40), nullable=False),
    Column("status", String(24), nullable=False),
    Column("stage", String(80), nullable=False),
    Column("progress", Integer, nullable=False),
    Column("message", String(1000), nullable=False),
    Column("details", JSON, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    ForeignKeyConstraint(
        ["job_id"], ["analysis_jobs.id"], name="fk_analysis_job_events_job", ondelete="CASCADE"
    ),
    UniqueConstraint("job_id", "sequence", name="uq_analysis_job_events_sequence"),
)

evidence_bundles = Table(
    "evidence_bundles",
    portfolio_metadata,
    Column("id", String(36), primary_key=True),
    Column("job_id", String(36), nullable=False, unique=True),
    Column("organization_id", String(36), nullable=False),
    Column("object_key", String(500), nullable=False, unique=True),
    Column("filename", String(255), nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("size_bytes", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("retained_until", DateTime(timezone=True), nullable=False),
    Column("state", String(24), nullable=False),
    Column("legal_hold", Boolean, nullable=False, default=False),
    Column("hold_reason", String(500), nullable=True),
    Column("held_at", DateTime(timezone=True), nullable=True),
    Column("held_by", String(128), nullable=True),
    Column("deleted_at", DateTime(timezone=True), nullable=True),
    Column("backup_expires_at", DateTime(timezone=True), nullable=True),
    Column("deletion_receipt", JSON, nullable=True),
    ForeignKeyConstraint(
        ["job_id"], ["analysis_jobs.id"], name="fk_evidence_bundles_job", ondelete="CASCADE"
    ),
    CheckConstraint(
        "state IN ('active','deletion_pending','deleted')",
        name="state",
    ),
    CheckConstraint("size_bytes > 0", name="size"),
    CheckConstraint(
        "(legal_hold = false AND hold_reason IS NULL AND held_at IS NULL AND held_by IS NULL) "
        "OR (legal_hold = true AND hold_reason IS NOT NULL AND held_at IS NOT NULL AND held_by IS NOT NULL)",
        name="hold",
    ),
)
Index("ix_evidence_bundles_org_state", evidence_bundles.c.organization_id, evidence_bundles.c.state)
Index("ix_evidence_bundles_retention", evidence_bundles.c.retained_until)


def pipeline_runner(
    path: Path,
    *,
    telemetry_path: Path | None = None,
    exposure_context_path: Path | None = None,
) -> Iterable[pipeline_events.Event]:
    """Production adapter for the existing PandaX SBOM pipeline."""
    return pipeline.run_sbom(
        path,
        telemetry_path=telemetry_path,
        exposure_context_path=exposure_context_path,
    )


class AnalysisJobRepository:
    """Own validated inputs, deterministic transitions, and event history."""

    def __init__(self, engine: Engine, storage: AnalysisInputStorage | None = None):
        self.engine = engine
        self.storage = storage or MemoryAnalysisInputStorage()

    def create_schema(self) -> None:
        """Development/test convenience. Production uses Alembic."""
        portfolio_metadata.create_all(self.engine)
        if self.engine.dialect.name == "sqlite":
            self._install_sqlite_immutability()

    def create(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        *,
        filename: str,
        media_type: str,
        content: bytes,
        idempotency_key: str,
        actor_id: str,
        changed_digest_confirmed: bool = False,
        runtime_telemetry: tuple[str, str, bytes] | None = None,
        exposure_context: tuple[str, str, bytes] | None = None,
    ) -> AnalysisJobRecord:
        return self.create_input(
            organization_id, product_id, release_id, input_type="sbom",
            filename=filename, media_type=media_type, content=content,
            idempotency_key=idempotency_key, actor_id=actor_id,
            changed_digest_confirmed=changed_digest_confirmed,
            runtime_telemetry=runtime_telemetry,
            exposure_context=exposure_context,
        )

    def create_input(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        *,
        input_type: str,
        filename: str,
        media_type: str,
        content: bytes,
        idempotency_key: str,
        actor_id: str,
        raw_artifact_allowed: bool = False,
        raw_artifact_consent: bool = False,
        changed_digest_confirmed: bool = False,
        runtime_telemetry: tuple[str, str, bytes] | None = None,
        exposure_context: tuple[str, str, bytes] | None = None,
        retention_days: int = 3650,
    ) -> AnalysisJobRecord:
        clean_type = _choice(input_type, INPUT_TYPES, "input_type")
        clean_key = _required(idempotency_key, "idempotency_key", 128)
        clean_actor = _required(actor_id, "actor_id", 128)
        if not 1 <= retention_days <= 7300:
            raise AnalysisJobValidationError("retention_days must be between 1 and 7300")
        if clean_type == "collector" and _signed_collector_present(content):
            safe_name, clean_media, preview, input_format, input_version, metadata = _validate_signed_collector(
                filename, media_type, content, organization_id, product_id, release_id,
                actor_id, OrganizationSettingsRepository(self.engine),
            )
        else:
            if clean_type == "collector" and os.environ.get("PANDAX_ENVIRONMENT", "development").lower() in {
                "staging", "beta", "production"
            }:
                raise AnalysisJobValidationError("unsigned Collector packages are not accepted")
            safe_name, clean_media, preview, input_format, input_version, metadata = _validate_input(
                clean_type, filename, media_type, content,
                product_id=product_id, release_id=release_id,
                raw_artifact_allowed=raw_artifact_allowed,
                raw_artifact_consent=raw_artifact_consent,
            )
        digest = hashlib.sha256(content).hexdigest()
        supplemental = self._validate_supplemental_inputs(
            organization_id,
            product_id,
            release_id,
            runtime_telemetry=runtime_telemetry,
            exposure_context=exposure_context,
        )
        existing = self._idempotent_job(organization_id, product_id, release_id, clean_key)
        if existing is not None:
            if existing.sha256 != digest or existing.input_type != clean_type:
                label = "SBOM content" if clean_type == "sbom" else "analysis input"
                raise AnalysisJobConflict(f"idempotency key already used for different {label}")
            if _supplemental_digests(existing.input_metadata) != {
                key: value["sha256"] for key, value in supplemental.items()
            }:
                raise AnalysisJobConflict("idempotency key already used with different supplemental evidence")
            return existing
        previous_digest = self._latest_completed_digest(organization_id, product_id, release_id)
        digest_changed = previous_digest is not None and previous_digest != digest
        if digest_changed and not changed_digest_confirmed:
            raise AnalysisJobConflict("release contents changed; explicit digest confirmation is required")
        incoming_bytes = len(content) + sum(len(item["content"]) for item in supplemental.values())
        self._ensure_storage_capacity(organization_id, incoming_bytes)
        job_id = str(uuid4())
        stored_inputs = []
        try:
            stored = self.storage.put(organization_id, job_id, content)
            stored_inputs.append(stored)
            for kind, item in supplemental.items():
                item["stored"] = self.storage.put(organization_id, f"{job_id}-{kind}", item.pop("content"))
                stored_inputs.append(item["stored"])
        except AnalysisInputStorageError as exc:
            for stored_input in stored_inputs:
                self.storage.delete(stored_input.object_key)
            raise AnalysisJobError(str(exc)) from exc
        try:
            with self._transaction() as session:
                raced = session.execute(select(analysis_jobs).where(
                    (analysis_jobs.c.organization_id == organization_id)
                    & (analysis_jobs.c.release_id == release_id)
                    & (analysis_jobs.c.idempotency_key == clean_key)
                )).mappings().one_or_none()
                if raced is not None:
                    if raced["sha256"] != digest or raced.get("input_type", "sbom") != clean_type:
                        label = "SBOM content" if clean_type == "sbom" else "analysis input"
                        raise AnalysisJobConflict(f"idempotency key already used for different {label}")
                    if _supplemental_digests(raced.get("input_metadata") or {}) != {
                        key: value["sha256"] for key, value in supplemental.items()
                    }:
                        raise AnalysisJobConflict(
                            "idempotency key already used with different supplemental evidence"
                        )
                    for stored_input in stored_inputs:
                        self.storage.delete(stored_input.object_key)
                    return _job_record(raced)
                now = _utc_now()
                public_supplemental = {
                    kind: {
                        "filename": item["filename"],
                        "media_type": item["media_type"],
                        "object_key": item["stored"].object_key,
                        "sha256": item["stored"].sha256,
                        "size_bytes": item["stored"].size_bytes,
                        "retained_until": (now + timedelta(days=retention_days)).isoformat(),
                        "validation": item["validation"],
                    }
                    for kind, item in supplemental.items()
                }
                metadata = dict(metadata)
                if public_supplemental:
                    metadata["supplemental_evidence"] = public_supplemental
                values = {
                    "id": job_id, "organization_id": organization_id,
                    "product_id": product_id, "release_id": release_id,
                    "idempotency_key": clean_key, "input_type": clean_type,
                    "filename": safe_name, "media_type": clean_media,
                    "size_bytes": stored.size_bytes, "sha256": stored.sha256,
                    "storage_size_bytes": sum(item.size_bytes for item in stored_inputs),
                    "input_format": input_format, "input_version": input_version,
                    "preview": preview, "input_content": None,
                    "object_key": stored.object_key,
                    "retained_until": now + timedelta(days=retention_days),
                    "input_metadata": metadata,
                    "consented_at": now if clean_type == "raw_artifact" else None,
                    "consent_actor_id": clean_actor if clean_type == "raw_artifact" else None,
                    "status": "queued",
                    "stage": "Validation complete",
                    "progress": 0, "result": None,
                    "error": None,
                    "actor_id": clean_actor, "created_at": now, "updated_at": now,
                    "started_at": None, "completed_at": None,
                }
                session.execute(insert(analysis_jobs).values(**values))
                self._append_event(
                    session, job_id, kind="analysis.uploaded", status=values["status"],
                    stage=values["stage"], progress=0,
                    message=f"{input_format} input validated and retained",
                    details={"sha256": digest, "input_type": clean_type, "preview": preview},
                )
                if clean_type == "raw_artifact":
                    self._append_event(
                        session, job_id, kind="analysis.consent_recorded", status="queued",
                        stage=values["stage"], progress=0,
                        message="Explicit raw artifact processing consent recorded",
                        details={"actor_id": clean_actor, "consented_at": now.isoformat()},
                    )
                if digest_changed:
                    self._append_event(
                        session, job_id, kind="analysis.digest_confirmed", status="queued",
                        stage=values["stage"], progress=0,
                        message="Changed release contents explicitly confirmed",
                        details={"previous_sha256": previous_digest, "sha256": digest, "actor_id": clean_actor},
                    )
                if public_supplemental:
                    self._append_event(
                        session, job_id, kind="analysis.supplemental_evidence_received", status="queued",
                        stage=values["stage"], progress=0,
                        message="Optional runtime evidence validated and retained",
                        details={
                            kind: {"sha256": item["sha256"], "size_bytes": item["size_bytes"]}
                            for kind, item in public_supplemental.items()
                        },
                    )
                return _job_record(values)
        except Exception:
            for stored_input in stored_inputs:
                self.storage.delete(stored_input.object_key)
            raise

    def _validate_supplemental_inputs(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        *,
        runtime_telemetry: tuple[str, str, bytes] | None,
        exposure_context: tuple[str, str, bytes] | None,
    ) -> dict[str, dict[str, Any]]:
        supplied = {
            "runtime_telemetry": runtime_telemetry,
            "exposure_context": exposure_context,
        }
        if not any(supplied.values()):
            return {}
        identity = self._release_identity(organization_id, product_id, release_id)
        validated: dict[str, dict[str, Any]] = {}
        for kind, value in supplied.items():
            if value is None:
                continue
            filename, media_type, content = value
            safe_name = _safe_upload_filename(filename)
            clean_media = _clean_media_type(media_type)
            if clean_media not in ALLOWED_MEDIA_TYPES:
                raise AnalysisJobValidationError(f"{kind} must be JSON")
            module = telemetry if kind == "runtime_telemetry" else exposure
            if not content or len(content) > module.MAX_BYTES:
                raise AnalysisJobValidationError(f"{kind} exceeds its {module.MAX_BYTES // 1024} KiB limit")
            try:
                with _temporary_sbom(content, ".json") as path:
                    document = module.load(path)
                    validation = module.summary(path)
            except (telemetry.TelemetryError, exposure.ExposureError) as exc:
                raise AnalysisJobValidationError(str(exc)) from exc
            supplied_product = document["product"]
            matches = (
                supplied_product["name"].casefold() == identity["name"].casefold()
                and supplied_product["version"].casefold() == identity["version"].casefold()
            )
            supplied_id = str(supplied_product.get("unique_id", "")).strip()
            if supplied_id and supplied_id.casefold() != identity["identifier"].casefold():
                matches = False
            if not matches:
                raise AnalysisJobValidationError(f"{kind} does not match the selected product release")
            validated[kind] = {
                "filename": safe_name,
                "media_type": clean_media,
                "content": bytes(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "validation": validation,
            }
        return validated

    def _release_identity(
        self, organization_id: str, product_id: str, release_id: str,
    ) -> Mapping[str, str]:
        with Session(self.engine) as session:
            row = session.execute(
                select(products.c.name, products.c.identifier, releases.c.version)
                .select_from(releases.join(products, (
                    (releases.c.product_id == products.c.id)
                    & (releases.c.organization_id == products.c.organization_id)
                )))
                .where(
                    (releases.c.organization_id == organization_id)
                    & (releases.c.product_id == product_id)
                    & (releases.c.id == release_id)
                )
            ).mappings().one_or_none()
        if row is None:
            raise AnalysisJobNotFound("release not found")
        return row

    def _idempotent_job(
        self, organization_id: str, product_id: str, release_id: str, key: str,
    ) -> AnalysisJobRecord | None:
        with Session(self.engine) as session:
            if session.execute(select(releases.c.id).where(
                (releases.c.id == release_id) & (releases.c.product_id == product_id)
                & (releases.c.organization_id == organization_id)
            )).one_or_none() is None:
                raise AnalysisJobNotFound("release not found")
            row = session.execute(select(analysis_jobs).where(
                (analysis_jobs.c.organization_id == organization_id)
                & (analysis_jobs.c.release_id == release_id)
                & (analysis_jobs.c.idempotency_key == key)
            )).mappings().one_or_none()
        return _job_record(row) if row is not None else None

    def _latest_completed_digest(
        self, organization_id: str, product_id: str, release_id: str,
    ) -> str | None:
        with Session(self.engine) as session:
            return session.execute(
                select(analysis_jobs.c.sha256)
                .where(
                    (analysis_jobs.c.organization_id == organization_id)
                    & (analysis_jobs.c.product_id == product_id)
                    & (analysis_jobs.c.release_id == release_id)
                    & (analysis_jobs.c.status == "completed")
                )
                .order_by(analysis_jobs.c.completed_at.desc(), analysis_jobs.c.id.desc())
                .limit(1)
            ).scalar_one_or_none()

    def get(
        self, organization_id: str, product_id: str, release_id: str, job_id: str
    ) -> AnalysisJobRecord:
        with Session(self.engine) as session:
            row = self._job_row(session, organization_id, product_id, release_id, job_id)
        if row is None:
            raise AnalysisJobNotFound("analysis job not found")
        return _job_record(row)

    def list(
        self, organization_id: str, product_id: str, release_id: str
    ) -> list[AnalysisJobRecord]:
        with Session(self.engine) as session:
            if session.execute(
                select(releases.c.id).where(
                    (releases.c.id == release_id)
                    & (releases.c.product_id == product_id)
                    & (releases.c.organization_id == organization_id)
                )
            ).one_or_none() is None:
                raise AnalysisJobNotFound("release not found")
            rows = session.execute(
                select(analysis_jobs)
                .where(
                    (analysis_jobs.c.organization_id == organization_id)
                    & (analysis_jobs.c.product_id == product_id)
                    & (analysis_jobs.c.release_id == release_id)
                )
                .order_by(analysis_jobs.c.created_at.desc(), analysis_jobs.c.id.desc())
            ).mappings().all()
        return [_job_record(row) for row in rows]

    def events(
        self, organization_id: str, product_id: str, release_id: str, job_id: str
    ) -> list[AnalysisJobEventRecord]:
        self.get(organization_id, product_id, release_id, job_id)
        with Session(self.engine) as session:
            rows = session.execute(
                select(analysis_job_events)
                .where(analysis_job_events.c.job_id == job_id)
                .order_by(analysis_job_events.c.sequence)
            ).mappings().all()
        return [_event_record(row) for row in rows]

    def record_follow_up_failure(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        job_id: str,
        *,
        kind: str,
        message: str,
        details: Mapping[str, Any],
    ) -> None:
        """Append a safe audit event when post-analysis automation fails."""
        job = self.get(organization_id, product_id, release_id, job_id)
        if job.status != "completed":
            raise AnalysisJobConflict("follow-up failures require a completed analysis job")
        with self._transaction() as session:
            self._append_event(
                session,
                job_id,
                kind=_required(kind, "kind", 160),
                status=job.status,
                stage=job.stage,
                progress=job.progress,
                message=_required(message, "message", 500),
                details=dict(details),
            )

    def run(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        job_id: str,
        runner: AnalysisRunner,
    ) -> AnalysisJobRecord:
        """Worker convenience: claim a queued job and execute it synchronously."""
        self.start(organization_id, product_id, release_id, job_id)
        return self.execute(organization_id, product_id, release_id, job_id, runner)

    def start(
        self, organization_id: str, product_id: str, release_id: str, job_id: str
    ) -> AnalysisJobRecord:
        """Atomically claim a queued job before dispatching worker execution."""
        job, _ = self._start(organization_id, product_id, release_id, job_id)
        return job

    def execute(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        job_id: str,
        runner: AnalysisRunner,
    ) -> AnalysisJobRecord:
        """Worker entry point for a job previously claimed with :meth:`start`."""
        try:
            job, content = self._running_input(
                organization_id, product_id, release_id, job_id
            )
        except Exception as exc:
            self._fail(organization_id, product_id, release_id, job_id, str(exc))
            return self.get(organization_id, product_id, release_id, job_id)
        run_dir: str | None = None
        artifacts: list[dict[str, Any]] = []
        summary: dict[str, Any] = {}
        scratch: tempfile.TemporaryDirectory[str] | None = None
        if job.input_type == "collector":
            try:
                with zipfile.ZipFile(io.BytesIO(content)) as archive:
                    content = archive.read(str(job.input_metadata["sbom_path"]))
            except (KeyError, OSError, zipfile.BadZipFile) as exc:
                self._fail(organization_id, product_id, release_id, job_id, "retained Collector package is invalid")
                return self.get(organization_id, product_id, release_id, job_id)
        suffix = (
            str(job.input_metadata.get("extension", ".bin"))
            if job.input_type == "raw_artifact"
            else ".spdx.json" if job.input_format == "SPDX" else ".cdx.json"
        )

        try:
            if job.input_type == "raw_artifact":
                scratch = tempfile.TemporaryDirectory(prefix="actis-analysis-")
            with ExitStack() as stack:
                input_path = stack.enter_context(_temporary_sbom(content, suffix))
                supplemental = job.input_metadata.get("supplemental_evidence", {})
                runtime_path = self._supplemental_path(stack, supplemental, "runtime_telemetry")
                exposure_path = self._supplemental_path(stack, supplemental, "exposure_context")
                if job.input_type == "raw_artifact" and (runtime_path is not None or exposure_path is not None):
                    stream = pipeline.run(
                        input_path,
                        out_base=Path(scratch.name),
                        telemetry_path=runtime_path,
                        exposure_context_path=exposure_path,
                    )
                elif job.input_type == "raw_artifact":
                    stream = pipeline.run(input_path, out_base=Path(scratch.name))
                elif runtime_path is not None or exposure_path is not None:
                    stream = runner(
                        input_path,
                        telemetry_path=runtime_path,
                        exposure_context_path=exposure_path,
                    )
                else:
                    stream = runner(input_path)
                for item in stream:
                    progress = _event_progress(item, default=self.get(
                        organization_id, product_id, release_id, job_id
                    ).progress)
                    if item.kind == pipeline_events.ARTIFACT:
                        artifacts.append(
                            {
                                "name": str(item.data.get("path") or item.message),
                                "path": str(item.data.get("path") or item.message),
                                "sha256": str(item.data.get("sha256") or ""),
                            }
                        )
                    if item.data.get("run_dir"):
                        run_dir = str(item.data["run_dir"])
                    if item.kind == pipeline_events.RUN_DONE:
                        summary = {
                            key: item.data.get(key, 0)
                            for key in ("components", "matchable_components", "skipped_components", "findings", "kev", "incidents")
                        }
                        summary["coverage_summary"] = item.data.get("coverage_summary", {})
                    self._record_pipeline_event(
                        organization_id, product_id, release_id, job_id, item, progress
                    )
            result = {
                **summary,
                "input_format": job.input_format,
                "input_version": job.input_version,
                "evidence": artifacts,
            }
            if run_dir:
                bundle = self._store_evidence_bundle(job, Path(run_dir))
                result["bundle"] = {
                    "id": bundle.id,
                    "sha256": bundle.sha256,
                    "size_bytes": bundle.size_bytes,
                    "retained_until": bundle.retained_until.isoformat(),
                }
            self._finish(organization_id, product_id, release_id, job_id, result)
        except Exception as exc:
            self._fail(organization_id, product_id, release_id, job_id, str(exc))
        finally:
            if scratch is not None:
                scratch.cleanup()
        return self.get(organization_id, product_id, release_id, job_id)

    def fail_interrupted_jobs(self) -> int:
        """Close work lost when the single beta API process was restarted."""
        message = "Analysis was interrupted by a service restart. Upload the input again to retry."
        with self._transaction() as session:
            query = select(analysis_jobs).where(analysis_jobs.c.status == "running")
            if self.engine.dialect.name == "postgresql":
                query = query.with_for_update()
            rows = session.execute(query).mappings().all()
            now = _utc_now()
            for row in rows:
                session.execute(
                    update(analysis_jobs)
                    .where(analysis_jobs.c.id == row["id"])
                    .values(status="failed", stage="Failed", error=message,
                            completed_at=now, updated_at=now)
                )
                self._append_event(
                    session, row["id"], kind="analysis.failed", status="failed",
                    stage="Failed", progress=int(row["progress"]), message=message,
                    details={"reason": "service_restart", "retry_required": True},
                )
            return len(rows)

    def _supplemental_path(
        self,
        stack: ExitStack,
        supplemental: Any,
        kind: str,
    ) -> Path | None:
        if not isinstance(supplemental, Mapping) or not isinstance(supplemental.get(kind), Mapping):
            return None
        item = supplemental[kind]
        try:
            content = self.storage.get(str(item["object_key"]), str(item["sha256"]))
        except (KeyError, AnalysisInputStorageError) as exc:
            raise AnalysisJobError(f"retained {kind} evidence is unavailable") from exc
        return stack.enter_context(_temporary_sbom(content, ".json"))

    def evidence_content(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        job_id: str,
        digest: str,
    ) -> tuple[bytes, str]:
        job = self.get(organization_id, product_id, release_id, job_id)
        if job.status != "completed" or not job.result:
            raise AnalysisJobNotFound("evidence not found")
        for evidence in job.result.get("evidence", []):
            if evidence.get("sha256") != digest:
                continue
            content, _ = self.export_evidence(
                organization_id, product_id, release_id, job_id
            )
            try:
                with zipfile.ZipFile(io.BytesIO(content)) as archive:
                    item = archive.read(str(evidence.get("path", "")))
            except (KeyError, OSError, zipfile.BadZipFile) as exc:
                raise AnalysisJobNotFound("evidence not found") from exc
            if hashlib.sha256(item).hexdigest() != digest:
                raise AnalysisJobConflict("evidence digest mismatch")
            return item, Path(str(evidence.get("name", "evidence"))).name
        raise AnalysisJobNotFound("evidence not found")

    def export_evidence(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        job_id: str,
    ) -> tuple[bytes, str]:
        self.get(organization_id, product_id, release_id, job_id)
        bundle = self._bundle(organization_id, job_id)
        if bundle is None or bundle.state != "active":
            raise AnalysisJobNotFound("evidence bundle not found")
        try:
            content = self.storage.get(bundle.object_key, bundle.sha256)
        except AnalysisInputStorageError as exc:
            raise AnalysisJobError(str(exc)) from exc
        return content, bundle.filename

    def evidence_bundle(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        job_id: str,
    ) -> EvidenceBundleRecord:
        self.get(organization_id, product_id, release_id, job_id)
        bundle = self._bundle(organization_id, job_id)
        if bundle is None:
            raise AnalysisJobNotFound("evidence bundle not found")
        return bundle

    def set_evidence_hold(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        job_id: str,
        *,
        held: bool,
        reason: str,
        actor_id: str,
    ) -> EvidenceBundleRecord:
        self.get(organization_id, product_id, release_id, job_id)
        clean_actor = _required(actor_id, "actor_id", 128)
        clean_reason = _required(reason, "reason", 500)
        with self._transaction() as session:
            row = session.execute(
                select(evidence_bundles).where(
                    (evidence_bundles.c.organization_id == organization_id)
                    & (evidence_bundles.c.job_id == job_id)
                ).with_for_update()
            ).mappings().one_or_none()
            if row is None or row["state"] != "active":
                raise AnalysisJobNotFound("active evidence bundle not found")
            now = _utc_now()
            values = {
                "legal_hold": held,
                "hold_reason": clean_reason if held else None,
                "held_at": now if held else None,
                "held_by": clean_actor if held else None,
            }
            session.execute(update(evidence_bundles).where(evidence_bundles.c.id == row["id"]).values(**values))
            self._append_event(
                session,
                job_id,
                kind="evidence.hold_enabled" if held else "evidence.hold_released",
                status="completed",
                stage="Completed",
                progress=100,
                message="Evidence legal hold enabled" if held else "Evidence legal hold released",
                details={"reason": clean_reason, "actor_id": clean_actor},
            )
            return _bundle_record({**row, **values})

    def delete_evidence(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        job_id: str,
        *,
        reason: str,
        actor_id: str,
        now: datetime | None = None,
    ) -> Mapping[str, Any]:
        self.get(organization_id, product_id, release_id, job_id)
        clean_actor = _required(actor_id, "actor_id", 128)
        clean_reason = _required(reason, "reason", 500)
        deleted_at = _as_utc(now or _utc_now())
        with self._transaction() as session:
            row = session.execute(
                select(evidence_bundles).where(
                    (evidence_bundles.c.organization_id == organization_id)
                    & (evidence_bundles.c.job_id == job_id)
                ).with_for_update()
            ).mappings().one_or_none()
            if row is None:
                raise AnalysisJobNotFound("evidence bundle not found")
            if row["state"] == "deleted":
                return dict(row["deletion_receipt"] or {})
            if row["state"] != "active":
                raise AnalysisJobConflict("evidence deletion is already in progress")
            if row["legal_hold"]:
                raise AnalysisJobConflict("evidence is protected by legal hold")
            if deleted_at < _as_utc(row["retained_until"]):
                raise AnalysisJobConflict("evidence retention period has not ended")
            session.execute(
                update(evidence_bundles)
                .where(evidence_bundles.c.id == row["id"])
                .values(state="deletion_pending")
            )
        try:
            self.storage.delete(str(row["object_key"]))
        except AnalysisInputStorageError as exc:
            with self._transaction() as session:
                session.execute(
                    update(evidence_bundles)
                    .where(evidence_bundles.c.id == row["id"])
                    .values(state="active")
                )
            raise AnalysisJobError(str(exc)) from exc

        backup_expires_at = deleted_at + timedelta(days=BACKUP_RETENTION_DAYS)
        receipt = {
            "id": str(uuid4()),
            "bundle_id": row["id"],
            "organization_id": organization_id,
            "sha256": row["sha256"],
            "deleted_at": deleted_at.isoformat(),
            "actor_id": clean_actor,
            "reason": clean_reason,
            "backup_expires_at": backup_expires_at.isoformat(),
        }
        receipt["receipt_sha256"] = hashlib.sha256(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        with self._transaction() as session:
            session.execute(
                update(evidence_bundles)
                .where(evidence_bundles.c.id == row["id"])
                .values(
                    state="deleted",
                    deleted_at=deleted_at,
                    backup_expires_at=backup_expires_at,
                    deletion_receipt=receipt,
                )
            )
            self._append_event(
                session,
                job_id,
                kind="evidence.deleted",
                status="completed",
                stage="Completed",
                progress=100,
                message="Evidence deleted after retention",
                details={key: receipt[key] for key in ("id", "sha256", "deleted_at", "backup_expires_at", "receipt_sha256")},
            )
        return receipt

    def _store_evidence_bundle(
        self, job: AnalysisJobRecord, run_dir: Path
    ) -> EvidenceBundleRecord:
        existing = self._bundle(job.organization_id, job.id)
        if existing is not None:
            if existing.state == "active":
                return existing
            raise AnalysisJobConflict("evidence bundle already exists")

        content = _archive_bundle(run_dir)
        if not content or len(content) > EVIDENCE_OBJECT_LIMIT_BYTES:
            raise AnalysisJobValidationError("sealed evidence bundle exceeds the 50 MB storage limit")
        bundle_id = str(uuid4())
        filename = f"actis-evidence-{job.id}.zip"
        retained_until = self._bundle_retained_until(job)
        try:
            stored = self.storage.put_bundle(job.organization_id, bundle_id, content)
        except AnalysisInputStorageError as exc:
            raise AnalysisJobError(str(exc)) from exc

        values = {
            "id": bundle_id,
            "job_id": job.id,
            "organization_id": job.organization_id,
            "object_key": stored.object_key,
            "filename": filename,
            "sha256": stored.sha256,
            "size_bytes": stored.size_bytes,
            "created_at": _utc_now(),
            "retained_until": retained_until,
            "state": "active",
            "legal_hold": False,
            "hold_reason": None,
            "held_at": None,
            "held_by": None,
            "deleted_at": None,
            "backup_expires_at": None,
            "deletion_receipt": None,
        }
        try:
            with self._transaction() as session:
                if self.engine.dialect.name == "postgresql":
                    session.execute(text(
                        "SELECT pg_advisory_xact_lock(hashtext('actis'), "
                        "hashtext('evidence-storage-quota'))"
                    ))
                organization_used = self._stored_bytes(session, job.organization_id)
                project_used = self._stored_bytes(session)
                if organization_used + stored.size_bytes > EVIDENCE_ORGANIZATION_LIMIT_BYTES:
                    raise AnalysisJobConflict("organization evidence storage quota reached")
                if project_used + stored.size_bytes > EVIDENCE_PROJECT_LIMIT_BYTES:
                    raise AnalysisJobConflict("project evidence storage quota reached")
                session.execute(insert(evidence_bundles).values(**values))
                self._append_event(
                    session,
                    job.id,
                    kind="evidence.stored",
                    status="running",
                    stage="Storing evidence",
                    progress=99,
                    message="Sealed evidence bundle retained",
                    details={
                        "bundle_id": bundle_id,
                        "sha256": stored.sha256,
                        "size_bytes": stored.size_bytes,
                        "retained_until": retained_until.isoformat(),
                    },
                )
        except Exception:
            try:
                self.storage.delete(stored.object_key)
            except AnalysisInputStorageError:
                pass
            raise
        return _bundle_record(values)

    def _bundle_retained_until(self, job: AnalysisJobRecord) -> datetime:
        minimum = _as_utc(job.created_at) + timedelta(days=3650)
        configured = _as_utc(job.retained_until) if job.retained_until else minimum
        with Session(self.engine) as session:
            support_end = session.execute(
                select(releases.c.support_end).where(
                    (releases.c.id == job.release_id)
                    & (releases.c.product_id == job.product_id)
                    & (releases.c.organization_id == job.organization_id)
                )
            ).scalar_one()
        support_until = datetime.combine(
            support_end + timedelta(days=1), datetime.min.time(), timezone.utc
        )
        return max(minimum, configured, support_until)

    def _stored_bytes(self, session: Session, organization_id: str | None = None) -> int:
        input_query = select(func.coalesce(func.sum(analysis_jobs.c.storage_size_bytes), 0)).where(
            analysis_jobs.c.object_key.is_not(None)
        )
        bundle_query = select(func.coalesce(func.sum(evidence_bundles.c.size_bytes), 0)).where(
            evidence_bundles.c.state.in_(("active", "deletion_pending"))
        )
        if organization_id is not None:
            input_query = input_query.where(analysis_jobs.c.organization_id == organization_id)
            bundle_query = bundle_query.where(evidence_bundles.c.organization_id == organization_id)
        return int(session.scalar(input_query) or 0) + int(session.scalar(bundle_query) or 0)

    def _ensure_storage_capacity(self, organization_id: str, incoming_bytes: int) -> None:
        # ponytail: preflight reservation; add upload-reservation rows if beta upload concurrency grows.
        with Session(self.engine) as session:
            if self._stored_bytes(session, organization_id) + incoming_bytes > EVIDENCE_ORGANIZATION_LIMIT_BYTES:
                raise AnalysisJobConflict("organization evidence storage quota reached")
            if self._stored_bytes(session) + incoming_bytes > EVIDENCE_PROJECT_LIMIT_BYTES:
                raise AnalysisJobConflict("project evidence storage quota reached")

    def _bundle(self, organization_id: str, job_id: str) -> EvidenceBundleRecord | None:
        with Session(self.engine) as session:
            row = session.execute(
                select(evidence_bundles).where(
                    (evidence_bundles.c.organization_id == organization_id)
                    & (evidence_bundles.c.job_id == job_id)
                )
            ).mappings().one_or_none()
        return _bundle_record(row) if row is not None else None

    def _start(
        self, organization_id: str, product_id: str, release_id: str, job_id: str
    ) -> tuple[AnalysisJobRecord, bytes]:
        with self._transaction() as session:
            row = self._job_row(session, organization_id, product_id, release_id, job_id, lock=True)
            if row is None:
                raise AnalysisJobNotFound("analysis job not found")
            if row["status"] != "queued":
                raise AnalysisJobConflict("only queued analysis jobs can be run")
            now = _utc_now()
            session.execute(
                update(analysis_jobs)
                .where(analysis_jobs.c.id == job_id)
                .values(status="running", stage="Starting", progress=1, started_at=now, updated_at=now)
            )
            self._append_event(
                session, job_id, kind="analysis.started", status="running",
                stage="Starting", progress=1, message="Analysis started", details={}
            )
            values = dict(row)
            values.update(status="running", stage="Starting", progress=1, started_at=now, updated_at=now)
            return _job_record(values), self._input_content(row)

    def _running_input(
        self, organization_id: str, product_id: str, release_id: str, job_id: str
    ) -> tuple[AnalysisJobRecord, bytes]:
        with Session(self.engine) as session:
            row = self._job_row(
                session, organization_id, product_id, release_id, job_id
            )
        if row is None:
            raise AnalysisJobNotFound("analysis job not found")
        if row["status"] != "running":
            raise AnalysisJobConflict("analysis job is not running")
        return _job_record(row), self._input_content(row)

    def _input_content(self, row: Mapping[str, Any]) -> bytes:
        if row.get("object_key"):
            try:
                return self.storage.get(str(row["object_key"]), str(row["sha256"]))
            except AnalysisInputStorageError as exc:
                raise AnalysisJobError(str(exc)) from exc
        legacy = row.get("input_content")
        if legacy is None:
            raise AnalysisJobError("analysis input object reference is missing")
        content = bytes(legacy)
        if hashlib.sha256(content).hexdigest() != row["sha256"]:
            raise AnalysisJobError("analysis input digest mismatch")
        return content

    def _record_pipeline_event(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        job_id: str,
        item: pipeline_events.Event,
        progress: int,
    ) -> None:
        stage = item.stage or ("Completed" if item.kind == pipeline_events.RUN_DONE else "Running")
        with self._transaction() as session:
            row = self._job_row(session, organization_id, product_id, release_id, job_id, lock=True)
            if row is None or row["status"] != "running":
                raise AnalysisJobConflict("analysis job is not running")
            session.execute(
                update(analysis_jobs)
                .where(analysis_jobs.c.id == job_id)
                .values(stage=stage, progress=progress, updated_at=_utc_now())
            )
            self._append_event(
                session,
                job_id,
                kind=item.kind,
                status="running",
                stage=stage,
                progress=progress,
                message=item.message,
                details=_json_safe(item.data),
            )

    def _finish(
        self, organization_id: str, product_id: str, release_id: str, job_id: str,
        result: Mapping[str, Any]
    ) -> None:
        with self._transaction() as session:
            row = self._job_row(session, organization_id, product_id, release_id, job_id, lock=True)
            if row is None or row["status"] != "running":
                raise AnalysisJobConflict("analysis job is not running")
            now = _utc_now()
            session.execute(
                update(analysis_jobs)
                .where(analysis_jobs.c.id == job_id)
                .values(
                    status="completed", stage="Completed", progress=100,
                    result=_json_safe(result), completed_at=now, updated_at=now,
                )
            )
            # Commit the release lifecycle with the completed job. A later
            # monitoring callback may fail, but the product still has a usable
            # release and a stable active selection.
            product = session.execute(select(products).where(
                (products.c.id == product_id)
                & (products.c.organization_id == organization_id)
            ).with_for_update()).mappings().one()
            release = session.execute(select(releases).where(
                (releases.c.id == release_id)
                & (releases.c.product_id == product_id)
                & (releases.c.organization_id == organization_id)
            ).with_for_update()).mappings().one()
            if release["status"] == "draft":
                session.execute(update(releases).where(releases.c.id == release_id).values(
                    status="supported", updated_at=now,
                ))
            if product["active_release_id"] is None and release["status"] in {"draft", "supported", "active"}:
                session.execute(update(products).where(products.c.id == product_id).values(
                    active_release_id=release_id, updated_at=now,
                ))
                session.execute(update(releases).where(releases.c.id == release_id).values(
                    status="active", updated_at=now,
                ))
            self._append_event(
                session, job_id, kind="analysis.completed", status="completed",
                stage="Completed", progress=100, message="Analysis completed",
                details={"summary": {k: result.get(k, 0) for k in ("components", "findings", "kev", "incidents")}},
            )

    def _fail(
        self, organization_id: str, product_id: str, release_id: str, job_id: str,
        error_message: str
    ) -> None:
        message = (error_message.strip() or "Analysis failed")[:1000]
        with self._transaction() as session:
            row = self._job_row(session, organization_id, product_id, release_id, job_id, lock=True)
            if row is None:
                raise AnalysisJobNotFound("analysis job not found")
            if row["status"] != "running":
                return
            now = _utc_now()
            session.execute(
                update(analysis_jobs)
                .where(analysis_jobs.c.id == job_id)
                .values(
                    status="failed", stage="Failed", error=message,
                    completed_at=now, updated_at=now,
                )
            )
            self._append_event(
                session, job_id, kind="analysis.failed", status="failed",
                stage="Failed", progress=int(row["progress"]), message=message, details={},
            )

    def _job_row(
        self,
        session: Session,
        organization_id: str,
        product_id: str,
        release_id: str,
        job_id: str,
        *,
        lock: bool = False,
    ) -> RowMapping | None:
        statement = select(analysis_jobs).where(
            (analysis_jobs.c.id == job_id)
            & (analysis_jobs.c.organization_id == organization_id)
            & (analysis_jobs.c.product_id == product_id)
            & (analysis_jobs.c.release_id == release_id)
        )
        if lock:
            statement = statement.with_for_update()
        return session.execute(statement).mappings().one_or_none()

    def _append_event(
        self,
        session: Session,
        job_id: str,
        *,
        kind: str,
        status: str,
        stage: str,
        progress: int,
        message: str,
        details: Mapping[str, Any],
    ) -> None:
        sequence = session.scalar(
            select(func.coalesce(func.max(analysis_job_events.c.sequence), 0)).where(
                analysis_job_events.c.job_id == job_id
            )
        )
        session.execute(
            insert(analysis_job_events).values(
                id=str(uuid4()), job_id=job_id, sequence=int(sequence or 0) + 1,
                kind=kind[:40], status=status, stage=stage[:80], progress=max(0, min(100, progress)),
                message=message[:1000], details=_json_safe(details), occurred_at=_utc_now(),
            )
        )

    @contextmanager
    def _transaction(self) -> Iterator[Session]:
        with Session(self.engine) as session:
            try:
                with session.begin():
                    yield session
            except AnalysisJobError:
                raise
            except IntegrityError as exc:
                raise AnalysisJobConflict("analysis job conflict") from exc

    def _install_sqlite_immutability(self) -> None:
        statements = (
            "CREATE TRIGGER IF NOT EXISTS analysis_job_events_no_update "
            "BEFORE UPDATE ON analysis_job_events BEGIN SELECT RAISE(ABORT, 'analysis events are append-only'); END",
            "CREATE TRIGGER IF NOT EXISTS analysis_job_events_no_delete "
            "BEFORE DELETE ON analysis_job_events BEGIN SELECT RAISE(ABORT, 'analysis events are append-only'); END",
        )
        with self.engine.begin() as connection:
            for statement in statements:
                connection.exec_driver_sql(statement)


def _validate_sbom(content: bytes) -> SbomPreview:
    if not content:
        raise AnalysisJobValidationError("SBOM file is empty")
    if len(content) > MAX_SBOM_BYTES:
        raise AnalysisJobValidationError(
            f"SBOM exceeds {MAX_SBOM_BYTES // (1024 * 1024)} MiB limit"
        )
    try:
        json.loads(content.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AnalysisJobValidationError("SBOM must be valid UTF-8 JSON") from exc
    try:
        with _temporary_sbom(content, ".json") as path:
            inspected = inspect_sbom(path)
    except (SbomError, OSError, ValueError) as exc:
        raise AnalysisJobValidationError(str(exc)) from exc
    return SbomPreview(
        format=str(inspected["format"]),
        version=str(inspected["version"]),
        components=int(inspected["components"]),
        matchable_components=int(inspected["matchable_components"]),
        skipped_components=int(inspected["skipped_components"]),
        product=_json_safe(inspected.get("product", {})),
    )


def _validate_input(
    input_type: str,
    filename: str,
    media_type: str,
    content: bytes,
    *,
    product_id: str,
    release_id: str,
    raw_artifact_allowed: bool,
    raw_artifact_consent: bool,
) -> tuple[str, str, dict[str, Any], str, str, dict[str, Any]]:
    if input_type == "sbom":
        safe_name = _safe_filename(filename)
        clean_media = _media_type(media_type)
        inspected = _validate_sbom(content)
        return safe_name, clean_media, _preview_dict(inspected), inspected.format, inspected.version, {}
    if input_type == "collector":
        return _validate_collector(filename, media_type, content, product_id, release_id)
    return _validate_raw(
        filename, media_type, content,
        allowed=raw_artifact_allowed, consent=raw_artifact_consent,
    )


def _validate_collector(
    filename: str, media_type: str, content: bytes, product_id: str, release_id: str,
) -> tuple[str, str, dict[str, Any], str, str, dict[str, Any]]:
    safe_name = _safe_upload_filename(filename)
    if not safe_name.lower().endswith(".zip"):
        raise AnalysisJobValidationError("Collector filename must be a .zip file")
    clean_media = _clean_media_type(media_type)
    if clean_media not in COLLECTOR_MEDIA_TYPES:
        raise AnalysisJobValidationError("unsupported Collector media type")
    if not content or len(content) > MAX_COLLECTOR_BYTES:
        raise AnalysisJobValidationError("Collector package must be between 1 byte and 25 MB")
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:
        raise AnalysisJobValidationError("Collector package must be a valid ZIP archive") from exc
    with archive:
        entries = archive.infolist()
        if not entries or len(entries) > MAX_COLLECTOR_ENTRIES:
            raise AnalysisJobValidationError("Collector package entry count exceeds limit")
        canonical: dict[str, zipfile.ZipInfo] = {}
        total_size = 0
        for entry in entries:
            raw_path = entry.filename[:-1] if entry.is_dir() and entry.filename.endswith("/") else entry.filename
            path = _collector_path(raw_path)
            identity = path.casefold()
            if identity in canonical:
                raise AnalysisJobValidationError("Collector package contains duplicate paths")
            canonical[identity] = entry
            mode = (entry.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise AnalysisJobValidationError("Collector package cannot contain symbolic links")
            if mode not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise AnalysisJobValidationError("Collector package cannot contain non-regular entries")
            if entry.flag_bits & 0x1:
                raise AnalysisJobValidationError("Collector package cannot contain encrypted entries")
            if entry.is_dir():
                continue
            total_size += entry.file_size
            if total_size > MAX_COLLECTOR_UNCOMPRESSED_BYTES:
                raise AnalysisJobValidationError("Collector package uncompressed size exceeds 100 MiB")
            if entry.file_size and (not entry.compress_size or entry.file_size / entry.compress_size > MAX_COLLECTOR_COMPRESSION_RATIO):
                raise AnalysisJobValidationError("Collector package compression ratio exceeds limit")
        manifest_entry = canonical.get(COLLECTOR_MANIFEST.casefold())
        if manifest_entry is None or manifest_entry.is_dir() or manifest_entry.file_size > 1024 * 1024:
            raise AnalysisJobValidationError(f"Collector package requires {COLLECTOR_MANIFEST}")
        try:
            manifest = json.loads(archive.read(manifest_entry).decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError, RuntimeError, zipfile.BadZipFile) as exc:
            raise AnalysisJobValidationError("Collector manifest must be valid UTF-8 JSON") from exc
        if not isinstance(manifest, dict) or manifest.get("schema") != "actis.collector/v1":
            raise AnalysisJobValidationError("unsupported Collector manifest schema")
        if manifest.get("product_id") != product_id or manifest.get("release_id") != release_id:
            raise AnalysisJobValidationError("Collector manifest product/release binding mismatch")
        collector = _manifest_object(manifest, "collector")
        provenance = _manifest_object(manifest, "provenance")
        collector_name = _required(collector.get("name"), "collector.name", 120)
        collector_version = _required(collector.get("version"), "collector.version", 64)
        source = _required(provenance.get("source"), "provenance.source", 240)
        build_id = _required(provenance.get("build_id"), "provenance.build_id", 240)
        generated_at = _manifest_timestamp(manifest.get("generated_at"))
        declared = manifest.get("files")
        if not isinstance(declared, list):
            raise AnalysisJobValidationError("Collector manifest files must be an array")
        digests: dict[str, str] = {}
        for item in declared:
            if not isinstance(item, dict):
                raise AnalysisJobValidationError("Collector manifest file entry must be an object")
            path = _collector_path(item.get("path"))
            digest = item.get("sha256")
            if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                raise AnalysisJobValidationError("Collector manifest file sha256 is invalid")
            if path.casefold() in (key.casefold() for key in digests):
                raise AnalysisJobValidationError("Collector manifest contains duplicate paths")
            digests[path] = digest
        payload = {entry.filename for entry in entries if not entry.is_dir() and entry.filename != COLLECTOR_MANIFEST}
        if set(digests) != payload:
            raise AnalysisJobValidationError("Collector manifest must describe every payload entry exactly once")
        try:
            for path, expected in digests.items():
                if hashlib.sha256(archive.read(path)).hexdigest() != expected:
                    raise AnalysisJobValidationError(f"Collector payload digest mismatch: {path}")
        except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
            raise AnalysisJobValidationError("Collector payload cannot be read safely") from exc
        sbom_path = _collector_path(manifest.get("sbom_path"))
        if sbom_path not in digests:
            raise AnalysisJobValidationError("Collector sbom_path must reference a declared payload")
        try:
            inspected = _validate_sbom(archive.read(sbom_path))
        except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
            raise AnalysisJobValidationError("Collector SBOM cannot be read safely") from exc
    preview = _preview_dict(inspected)
    preview["collector"] = {"name": collector_name, "version": collector_version, "generated_at": generated_at}
    metadata = {
        "schema": "actis.collector/v1", "sbom_path": sbom_path,
        "collector": {"name": collector_name, "version": collector_version},
        "provenance": {"source": source, "build_id": build_id, "generated_at": generated_at},
        "entries": [{"path": path, "sha256": digest} for path, digest in sorted(digests.items())],
    }
    return safe_name, clean_media, preview, inspected.format, inspected.version, metadata


def _signed_collector_present(content: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            return "manifest.json" in archive.namelist()
    except (OSError, zipfile.BadZipFile):
        return False


def _validate_signed_collector(
    filename: str, media_type: str, content: bytes,
    organization_id: str, product_id: str, release_id: str,
    actor_id: str, trust_repository: OrganizationSettingsRepository,
) -> tuple[str, str, dict[str, Any], str, str, dict[str, Any]]:
    safe_name = _safe_upload_filename(filename)
    if not safe_name.lower().endswith(".zip") or _clean_media_type(media_type) not in COLLECTOR_MEDIA_TYPES:
        raise AnalysisJobValidationError("signed Collector input must be a ZIP")
    if not content or len(content) > MAX_COLLECTOR_BYTES:
        raise AnalysisJobValidationError("Collector package must be between 1 byte and 25 MB")
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_COLLECTOR_ENTRIES or sum(entry.file_size for entry in entries) > MAX_COLLECTOR_UNCOMPRESSED_BYTES:
                raise AnalysisJobValidationError("signed Collector package exceeds entry or uncompressed-size limit")
            if any(entry.file_size and (not entry.compress_size or entry.file_size / entry.compress_size > MAX_COLLECTOR_COMPRESSION_RATIO) for entry in entries):
                raise AnalysisJobValidationError("signed Collector package compression ratio exceeds limit")
        with _bundle_directory(content) as directory:
            manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
            if manifest.get("schema") != "actis/manifest/v1":
                raise AnalysisJobValidationError("signed Collector requires actis/manifest/v1")
            if any(manifest.get(field) != value for field, value in (
                ("organization_id", organization_id),
                ("product_id", product_id), ("release_id", release_id),
            )):
                raise AnalysisJobValidationError("signed Collector organization/product/release binding mismatch")
            collector = manifest.get("collector")
            if not isinstance(collector, dict) or collector.get("name") != "Actis Collector":
                raise AnalysisJobValidationError("signed Collector identity is missing")
            version = _required(collector.get("version"), "collector.version", 64)
            sbom_path = _collector_path(manifest.get("sbom_path"))
            allowed = {"ledger.jsonl", "sbom.cdx.json", "collection-summary.json", "coverage.json"}
            declared = {item.get("path") for item in manifest.get("files", []) if isinstance(item, dict)}
            if sbom_path != "sbom.cdx.json" or declared - allowed or not {"ledger.jsonl", sbom_path, "collection-summary.json", "coverage.json"} <= declared:
                raise AnalysisJobValidationError("signed Collector contains unsupported or missing payload files")
            verification = trust_repository.verify_registered_bundle(
                organization_id, directory, actor_id=actor_id,
            )
            if verification["status"] != "trusted" or verification["key_status"] != "active":
                raise AnalysisJobValidationError("Collector signer is not an active enrolled customer key")
            inspected = _validate_sbom((directory / sbom_path).read_bytes())
    except (SettingsValidationError, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        raise AnalysisJobValidationError(f"signed Collector package is invalid: {exc}") from exc
    preview = _preview_dict(inspected)
    preview["collector"] = {"name": "Actis Collector", "version": version, "generated_at": manifest["created"]}
    metadata = {
        "schema": "actis/manifest/v1", "sbom_path": sbom_path,
        "collector": collector,
        "trust": {key: verification[key] for key in (
            "status", "integrity_ok", "signature_valid", "signer_trust", "trust_source",
            "trust_policy", "key_id", "key_version", "trusted_key_fingerprint", "verified_at",
        )},
        "source_digest": manifest.get("source_digest"),
        "rules_version": manifest.get("rules_version"),
    }
    return safe_name, _clean_media_type(media_type), preview, inspected.format, inspected.version, metadata


def _validate_raw(
    filename: str, media_type: str, content: bytes, *, allowed: bool, consent: bool,
) -> tuple[str, str, dict[str, Any], str, str, dict[str, Any]]:
    if not allowed:
        raise AnalysisJobValidationError("raw artifact ingestion is disabled by organization policy")
    if not consent:
        raise AnalysisJobValidationError("explicit raw artifact processing consent is required")
    safe_name = _safe_upload_filename(filename)
    extension = next((suffix for suffix in sorted(RAW_MEDIA_BY_EXTENSION, key=len, reverse=True) if safe_name.lower().endswith(suffix)), None)
    if extension is None:
        raise AnalysisJobValidationError("unsupported raw artifact extension")
    if extension in {".bin", ".img"} and os.environ.get("PANDAX_ENVIRONMENT", "development").lower() in HOSTED_ENVIRONMENTS:
        raise AnalysisJobValidationError("hosted analysis supports ZIP and TAR archives; use the local Collector for firmware images")
    clean_media = _clean_media_type(media_type)
    if clean_media not in RAW_MEDIA_BY_EXTENSION[extension]:
        raise AnalysisJobValidationError("raw artifact media type does not match its extension")
    if not content or len(content) > MAX_RAW_ARTIFACT_BYTES:
        raise AnalysisJobValidationError("raw artifact must be between 1 byte and 50 MB")
    archive = (
        _inspect_raw_archive(content, extension)
        if extension in {".zip", ".tar", ".tar.gz", ".tgz"}
        else None
    )
    preview = {
        "format": "Raw artifact", "version": "1", "components": 0,
        "matchable_components": 0, "skipped_components": 0, "product": {},
        "analysis_support": None,
    }
    metadata: dict[str, Any] = {"extension": extension}
    if archive is not None:
        metadata["archive"] = archive
    return safe_name, clean_media, preview, "Raw artifact", "1", metadata


def _inspect_raw_archive(content: bytes, extension: str) -> dict[str, int]:
    """Reject unsafe archive structure before retaining or scheduling it.

    Extraction repeats the same fail-closed checks in the worker. This upload
    preflight is intentionally metadata-only: source code and other regular
    files are accepted without reading their contents.
    """
    if extension == ".zip":
        if not zipfile.is_zipfile(io.BytesIO(content)):
            raise AnalysisJobValidationError("raw artifact content is not a valid ZIP archive")
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                return _inspect_raw_zip(archive)
        except AnalysisJobValidationError:
            raise
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise AnalysisJobValidationError("raw artifact content is not a valid ZIP archive") from exc
    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as archive:
            return _inspect_raw_tar(archive)
    except (OSError, EOFError, tarfile.TarError) as exc:
        raise AnalysisJobValidationError("raw artifact content is not a valid TAR archive") from exc


def _raw_archive_path(value: str) -> str:
    if not value or "\x00" in value or "\\" in value or value.startswith("/") or (
        len(value) > 1 and value[1] == ":"
    ):
        raise AnalysisJobValidationError("raw artifact contains an unsafe archive path")
    path = PurePosixPath(value)
    if any(part in {"", ".", ".."} for part in path.parts) or len(path.parts) > artifact_ingest.MAX_DEPTH:
        raise AnalysisJobValidationError("raw artifact contains an unsafe archive path")
    return value.rstrip("/")


def _inspect_raw_zip(archive: zipfile.ZipFile) -> dict[str, int]:
    entries = archive.infolist()
    if not entries or len(entries) > artifact_ingest.MAX_ENTRIES:
        raise AnalysisJobValidationError("raw artifact archive entry count exceeds limit")
    seen: set[str] = set()
    files = total = 0
    for entry in entries:
        path = _raw_archive_path(entry.filename)
        identity = path.casefold()
        if identity in seen:
            raise AnalysisJobValidationError("raw artifact archive contains duplicate paths")
        seen.add(identity)
        mode = (entry.external_attr >> 16) & 0o170000
        if entry.flag_bits & 0x1 or mode not in {0, stat.S_IFREG, stat.S_IFDIR}:
            raise AnalysisJobValidationError("raw artifact archive contains a link, encrypted, or special entry")
        if entry.is_dir():
            continue
        total += entry.file_size
        files += 1
        if entry.file_size and (
            not entry.compress_size
            or entry.file_size / entry.compress_size > artifact_ingest.MAX_COMPRESSION_RATIO
        ):
            raise AnalysisJobValidationError("raw artifact archive compression ratio exceeds limit")
        if total > artifact_ingest.MAX_TOTAL_BYTES:
            raise AnalysisJobValidationError("raw artifact archive uncompressed size exceeds limit")
    if not files:
        raise AnalysisJobValidationError("raw artifact archive contains no regular files")
    return {"files": files, "uncompressed_bytes": total}


def _inspect_raw_tar(archive: tarfile.TarFile) -> dict[str, int]:
    seen: set[str] = set()
    files = total = 0
    for index, entry in enumerate(archive, 1):
        if index > artifact_ingest.MAX_ENTRIES:
            raise AnalysisJobValidationError("raw artifact archive entry count exceeds limit")
        path = _raw_archive_path(entry.name)
        identity = path.casefold()
        if identity in seen:
            raise AnalysisJobValidationError("raw artifact archive contains duplicate paths")
        seen.add(identity)
        if entry.issym() or entry.islnk():
            raise AnalysisJobValidationError("raw artifact archive contains a link entry")
        if entry.isdir():
            continue
        if not entry.isfile():
            raise AnalysisJobValidationError("raw artifact archive contains a special entry")
        files += 1
        total += entry.size
        if total > artifact_ingest.MAX_TOTAL_BYTES:
            raise AnalysisJobValidationError("raw artifact archive uncompressed size exceeds limit")
    if not files:
        raise AnalysisJobValidationError("raw artifact archive contains no regular files")
    return {"files": files, "uncompressed_bytes": total}


def _safe_upload_filename(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "/" in value or "\\" in value:
        raise AnalysisJobValidationError("unsafe analysis input filename")
    name = value.strip()
    if not name or len(name) > 255 or Path(name).name != name:
        raise AnalysisJobValidationError("unsafe analysis input filename")
    return name


def _collector_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise AnalysisJobValidationError("Collector path is unsafe")
    normalized = unicodedata.normalize("NFC", value)
    path = PurePosixPath(normalized)
    if normalized != value or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts) or path.as_posix() != normalized:
        raise AnalysisJobValidationError("Collector path is unsafe")
    return normalized


def _manifest_object(manifest: Mapping[str, Any], field: str) -> Mapping[str, Any]:
    value = manifest.get(field)
    if not isinstance(value, dict):
        raise AnalysisJobValidationError(f"Collector manifest {field} must be an object")
    return value


def _manifest_timestamp(value: Any) -> str:
    if not isinstance(value, str):
        raise AnalysisJobValidationError("Collector generated_at must be an ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AnalysisJobValidationError("Collector generated_at must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise AnalysisJobValidationError("Collector generated_at must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


def _archive_bundle(run_dir: Path) -> bytes:
    root = run_dir.resolve()
    if not root.is_dir():
        raise AnalysisJobError("sealed evidence bundle is unavailable")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise AnalysisJobError("sealed evidence bundle contains a symbolic link")
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
    return output.getvalue()


@contextmanager
def _temporary_sbom(content: bytes, suffix: str) -> Iterator[Path]:
    path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
            handle.write(content)
            path = Path(handle.name)
        yield path
    finally:
        if path is not None:
            path.unlink(missing_ok=True)


def _event_progress(item: pipeline_events.Event, *, default: int) -> int:
    if item.kind == pipeline_events.RUN_DONE:
        return 99
    if item.stage in pipeline_events.PIPELINE_STAGES:
        index = pipeline_events.PIPELINE_STAGES.index(item.stage)
        completed = 1 if item.kind in {pipeline_events.STAGE_DONE, pipeline_events.STAGE_SKIPPED} else 0
        return max(default, min(98, int(((index + completed) / len(pipeline_events.PIPELINE_STAGES)) * 98)))
    return default


def _safe_filename(value: str) -> str:
    if not value or "\x00" in value:
        raise AnalysisJobValidationError("filename is required")
    name = Path(value.replace("\\", "/")).name.strip()
    if not name or len(name) > 255 or not name.lower().endswith(".json"):
        raise AnalysisJobValidationError("SBOM filename must be a .json file")
    return name


def _media_type(value: str) -> str:
    media_type = _clean_media_type(value)
    if media_type not in ALLOWED_MEDIA_TYPES:
        raise AnalysisJobValidationError("unsupported SBOM media type")
    return media_type


def _clean_media_type(value: Any) -> str:
    if not isinstance(value, str):
        raise AnalysisJobValidationError("unsupported analysis input media type")
    return value.split(";", 1)[0].strip().lower()


def _choice(value: Any, choices: frozenset[str], field: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise AnalysisJobValidationError(f"invalid {field}")
    return value


def _required(value: Any, field: str, maximum: int) -> str:
    clean = value.strip() if isinstance(value, str) else ""
    if not clean or len(clean) > maximum:
        raise AnalysisJobValidationError(f"invalid {field}")
    return clean


def _preview_dict(value: SbomPreview) -> dict[str, Any]:
    return {
        "format": value.format,
        "version": value.version,
        "components": value.components,
        "matchable_components": value.matchable_components,
        "skipped_components": value.skipped_components,
        "product": dict(value.product),
    }


def _json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def _supplemental_digests(metadata: Mapping[str, Any]) -> dict[str, str]:
    supplemental = metadata.get("supplemental_evidence", {})
    if not isinstance(supplemental, Mapping):
        return {}
    return {
        str(kind): str(item["sha256"])
        for kind, item in supplemental.items()
        if isinstance(item, Mapping) and isinstance(item.get("sha256"), str)
    }


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _job_record(row: Mapping[str, Any]) -> AnalysisJobRecord:
    return AnalysisJobRecord(
        id=row["id"], organization_id=row["organization_id"], product_id=row["product_id"],
        release_id=row["release_id"], idempotency_key=row["idempotency_key"],
        input_type=row.get("input_type", "sbom"),
        filename=row["filename"], media_type=row["media_type"], size_bytes=row["size_bytes"],
        sha256=row["sha256"], input_format=row["input_format"], input_version=row["input_version"],
        preview=row["preview"], object_key=row.get("object_key"),
        retained_until=row.get("retained_until"), input_metadata=row.get("input_metadata") or {},
        consented_at=row.get("consented_at"), consent_actor_id=row.get("consent_actor_id"),
        status=row["status"], stage=row["stage"], progress=row["progress"],
        result=row.get("result"), error=row.get("error"), actor_id=row["actor_id"],
        created_at=row["created_at"], updated_at=row["updated_at"],
        started_at=row.get("started_at"), completed_at=row.get("completed_at"),
    )


def _bundle_record(row: Mapping[str, Any]) -> EvidenceBundleRecord:
    return EvidenceBundleRecord(
        id=row["id"],
        job_id=row["job_id"],
        organization_id=row["organization_id"],
        object_key=row["object_key"],
        filename=row["filename"],
        sha256=row["sha256"],
        size_bytes=row["size_bytes"],
        created_at=row["created_at"],
        retained_until=row["retained_until"],
        state=row["state"],
        legal_hold=bool(row["legal_hold"]),
        hold_reason=row.get("hold_reason"),
        held_at=row.get("held_at"),
        held_by=row.get("held_by"),
        deleted_at=row.get("deleted_at"),
        backup_expires_at=row.get("backup_expires_at"),
        deletion_receipt=row.get("deletion_receipt"),
    )


def _event_record(row: Mapping[str, Any]) -> AnalysisJobEventRecord:
    return AnalysisJobEventRecord(
        id=row["id"], job_id=row["job_id"], sequence=row["sequence"], kind=row["kind"],
        status=row["status"], stage=row["stage"], progress=row["progress"],
        message=row["message"], details=row["details"], occurred_at=row["occurred_at"],
    )
