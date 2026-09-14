"""Persisted, tenant-scoped release analysis jobs.

The repository is the lifecycle seam: it validates and retains an SBOM,
serializes state transitions, records every transition/pipeline event, and
projects the existing PandaX event stream into a stable result summary.
"""
from __future__ import annotations

import hashlib
import io
import json
import stat
import tarfile
import tempfile
import unicodedata
import zipfile
from collections.abc import Callable, Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator
from uuid import uuid4

from sqlalchemy import (
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
    event,
    func,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Engine, RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import events as pipeline_events
from . import pipeline
from .analysis_storage import AnalysisInputStorage, AnalysisInputStorageError, MemoryAnalysisInputStorage
from .portfolio import portfolio_metadata, releases
from .stages.sbom import SbomError, inspect_sbom

MAX_SBOM_BYTES = 10 * 1024 * 1024
MAX_COLLECTOR_BYTES = 25 * 1024 * 1024
MAX_COLLECTOR_ENTRIES = 256
MAX_COLLECTOR_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
MAX_COLLECTOR_COMPRESSION_RATIO = 100
MAX_RAW_ARTIFACT_BYTES = 50 * 1024 * 1024
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
INPUT_TYPES = frozenset({"sbom", "collector", "raw_artifact"})
JOB_STATUSES = frozenset({"queued", "running", "completed", "failed", "unsupported"})
TERMINAL_STATUSES = frozenset({"completed", "failed", "unsupported"})


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


AnalysisRunner = Callable[[Path], Iterable[pipeline_events.Event]]


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


def pipeline_runner(path: Path) -> Iterable[pipeline_events.Event]:
    """Production adapter for the existing PandaX SBOM pipeline."""
    return pipeline.run_sbom(path)


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
    ) -> AnalysisJobRecord:
        return self.create_input(
            organization_id, product_id, release_id, input_type="sbom",
            filename=filename, media_type=media_type, content=content,
            idempotency_key=idempotency_key, actor_id=actor_id,
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
        retention_days: int = 3650,
    ) -> AnalysisJobRecord:
        clean_type = _choice(input_type, INPUT_TYPES, "input_type")
        clean_key = _required(idempotency_key, "idempotency_key", 128)
        clean_actor = _required(actor_id, "actor_id", 128)
        if not 1 <= retention_days <= 7300:
            raise AnalysisJobValidationError("retention_days must be between 1 and 7300")
        safe_name, clean_media, preview, input_format, input_version, metadata = _validate_input(
            clean_type, filename, media_type, content,
            product_id=product_id, release_id=release_id,
            raw_artifact_allowed=raw_artifact_allowed,
            raw_artifact_consent=raw_artifact_consent,
        )
        digest = hashlib.sha256(content).hexdigest()
        existing = self._idempotent_job(organization_id, product_id, release_id, clean_key)
        if existing is not None:
            if existing.sha256 != digest or existing.input_type != clean_type:
                label = "SBOM content" if clean_type == "sbom" else "analysis input"
                raise AnalysisJobConflict(f"idempotency key already used for different {label}")
            return existing
        job_id = str(uuid4())
        try:
            stored = self.storage.put(organization_id, job_id, content)
        except AnalysisInputStorageError as exc:
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
                    self.storage.delete(stored.object_key)
                    return _job_record(raced)
                now = _utc_now()
                unsupported = clean_type == "raw_artifact"
                values = {
                    "id": job_id, "organization_id": organization_id,
                    "product_id": product_id, "release_id": release_id,
                    "idempotency_key": clean_key, "input_type": clean_type,
                    "filename": safe_name, "media_type": clean_media,
                    "size_bytes": stored.size_bytes, "sha256": stored.sha256,
                    "input_format": input_format, "input_version": input_version,
                    "preview": preview, "input_content": None,
                    "object_key": stored.object_key,
                    "retained_until": now + timedelta(days=retention_days),
                    "input_metadata": metadata,
                    "consented_at": now if clean_type == "raw_artifact" else None,
                    "consent_actor_id": clean_actor if clean_type == "raw_artifact" else None,
                    "status": "unsupported" if unsupported else "queued",
                    "stage": "Artifact worker unavailable" if unsupported else "Validation complete",
                    "progress": 0, "result": None,
                    "error": "Raw artifact retained and validated; no production artifact-analysis worker is configured." if unsupported else None,
                    "actor_id": clean_actor, "created_at": now, "updated_at": now,
                    "started_at": None, "completed_at": now if unsupported else None,
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
                        session, job_id, kind="analysis.consent_recorded", status="unsupported",
                        stage=values["stage"], progress=0,
                        message="Explicit raw artifact processing consent recorded",
                        details={"actor_id": clean_actor, "consented_at": now.isoformat()},
                    )
                return _job_record(values)
        except Exception:
            self.storage.delete(stored.object_key)
            raise

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
        if job.input_type == "collector":
            try:
                with zipfile.ZipFile(io.BytesIO(content)) as archive:
                    content = archive.read(str(job.input_metadata["sbom_path"]))
            except (KeyError, OSError, zipfile.BadZipFile) as exc:
                self._fail(organization_id, product_id, release_id, job_id, "retained Collector package is invalid")
                return self.get(organization_id, product_id, release_id, job_id)
        suffix = ".spdx.json" if job.input_format == "SPDX" else ".cdx.json"

        try:
            with _temporary_sbom(content, suffix) as sbom_path:
                for item in runner(sbom_path):
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
                            for key in ("components", "findings", "kev", "incidents")
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
                "_run_dir": run_dir,
            }
            self._finish(organization_id, product_id, release_id, job_id, result)
        except Exception as exc:
            self._fail(organization_id, product_id, release_id, job_id, str(exc))
        return self.get(organization_id, product_id, release_id, job_id)

    def evidence_path(
        self,
        organization_id: str,
        product_id: str,
        release_id: str,
        job_id: str,
        digest: str,
    ) -> tuple[Path, str]:
        job = self.get(organization_id, product_id, release_id, job_id)
        if job.status != "completed" or not job.result:
            raise AnalysisJobNotFound("evidence not found")
        run_dir = job.result.get("_run_dir")
        if not isinstance(run_dir, str) or not run_dir:
            raise AnalysisJobNotFound("evidence not found")
        for evidence in job.result.get("evidence", []):
            if evidence.get("sha256") != digest:
                continue
            root = Path(run_dir).resolve()
            candidate = (root / str(evidence.get("path", ""))).resolve()
            if root not in candidate.parents or not candidate.is_file():
                raise AnalysisJobNotFound("evidence not found")
            if hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
                raise AnalysisJobConflict("evidence digest mismatch")
            return candidate, Path(str(evidence.get("name", "evidence"))).name
        raise AnalysisJobNotFound("evidence not found")

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
        raise AnalysisJobValidationError("Collector package must be between 1 byte and 25 MiB")
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
    clean_media = _clean_media_type(media_type)
    if clean_media not in RAW_MEDIA_BY_EXTENSION[extension]:
        raise AnalysisJobValidationError("raw artifact media type does not match its extension")
    if not content or len(content) > MAX_RAW_ARTIFACT_BYTES:
        raise AnalysisJobValidationError("raw artifact must be between 1 byte and 50 MiB")
    if extension == ".zip" and not zipfile.is_zipfile(io.BytesIO(content)):
        raise AnalysisJobValidationError("raw artifact content is not a valid ZIP archive")
    if extension in {".tar", ".tar.gz", ".tgz"}:
        try:
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:*"):
                pass
        except (OSError, tarfile.TarError) as exc:
            raise AnalysisJobValidationError("raw artifact content is not a valid TAR archive") from exc
    preview = {
        "format": "Raw artifact", "version": "1", "components": 0,
        "matchable_components": 0, "skipped_components": 0, "product": {},
        "analysis_support": "pending_worker",
    }
    return safe_name, clean_media, preview, "Raw artifact", "1", {
        "extension": extension, "analysis_support": "pending_worker",
    }


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


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


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


def _event_record(row: Mapping[str, Any]) -> AnalysisJobEventRecord:
    return AnalysisJobEventRecord(
        id=row["id"], job_id=row["job_id"], sequence=row["sequence"], kind=row["kind"],
        status=row["status"], stage=row["stage"], progress=row["progress"],
        message=row["message"], details=row["details"], occurred_at=row["occurred_at"],
    )
