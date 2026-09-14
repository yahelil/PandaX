"""Persisted, tenant-scoped release analysis jobs.

The repository is the lifecycle seam: it validates and retains an SBOM,
serializes state transitions, records every transition/pipeline event, and
projects the existing PandaX event stream into a stable result summary.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
from collections.abc import Callable, Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    ForeignKeyConstraint,
    Integer,
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
from .portfolio import portfolio_metadata, releases
from .stages.sbom import SbomError, inspect_sbom

MAX_SBOM_BYTES = 10 * 1024 * 1024
ALLOWED_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "application/vnd.cyclonedx+json",
        "application/spdx+json",
    }
)
JOB_STATUSES = frozenset({"queued", "running", "completed", "failed"})
TERMINAL_STATUSES = frozenset({"completed", "failed"})


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
    filename: str
    media_type: str
    size_bytes: int
    sha256: str
    input_format: str
    input_version: str
    preview: Mapping[str, Any]
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
    Column("filename", String(255), nullable=False),
    Column("media_type", String(100), nullable=False),
    Column("size_bytes", Integer, nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("input_format", String(24), nullable=False),
    Column("input_version", String(24), nullable=False),
    Column("preview", JSON, nullable=False),
    Column("input_content", LargeBinary, nullable=False),
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
)

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

    def __init__(self, engine: Engine):
        self.engine = engine

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
        safe_filename = _safe_filename(filename)
        clean_media_type = _media_type(media_type)
        clean_key = _required(idempotency_key, "idempotency_key", 128)
        clean_actor = _required(actor_id, "actor_id", 128)
        preview = _validate_sbom(content)
        digest = hashlib.sha256(content).hexdigest()

        with self._transaction() as session:
            release = session.execute(
                select(releases.c.id).where(
                    (releases.c.id == release_id)
                    & (releases.c.product_id == product_id)
                    & (releases.c.organization_id == organization_id)
                )
            ).one_or_none()
            if release is None:
                raise AnalysisJobNotFound("release not found")

            existing = session.execute(
                select(analysis_jobs).where(
                    (analysis_jobs.c.organization_id == organization_id)
                    & (analysis_jobs.c.release_id == release_id)
                    & (analysis_jobs.c.idempotency_key == clean_key)
                )
            ).mappings().one_or_none()
            if existing is not None:
                if existing["sha256"] != digest:
                    raise AnalysisJobConflict(
                        "idempotency key already used for different SBOM content"
                    )
                return _job_record(existing)

            now = _utc_now()
            values = {
                "id": str(uuid4()),
                "organization_id": organization_id,
                "product_id": product_id,
                "release_id": release_id,
                "idempotency_key": clean_key,
                "filename": safe_filename,
                "media_type": clean_media_type,
                "size_bytes": len(content),
                "sha256": digest,
                "input_format": preview.format,
                "input_version": preview.version,
                "preview": _preview_dict(preview),
                "input_content": content,
                "status": "queued",
                "stage": "Validation complete",
                "progress": 0,
                "result": None,
                "error": None,
                "actor_id": clean_actor,
                "created_at": now,
                "updated_at": now,
                "started_at": None,
                "completed_at": None,
            }
            try:
                session.execute(insert(analysis_jobs).values(**values))
            except IntegrityError as exc:
                raise AnalysisJobConflict("analysis job already exists") from exc
            self._append_event(
                session,
                values["id"],
                kind="analysis.uploaded",
                status="queued",
                stage="Validation complete",
                progress=0,
                message=f"{preview.format} {preview.version} SBOM validated",
                details={"sha256": digest, "preview": values["preview"]},
            )
            return _job_record(values)

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
        job, content = self._running_input(
            organization_id, product_id, release_id, job_id
        )
        run_dir: str | None = None
        artifacts: list[dict[str, Any]] = []
        summary: dict[str, Any] = {}
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
            return _job_record(values), bytes(row["input_content"])

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
        return _job_record(row), bytes(row["input_content"])

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
    media_type = (value or "").split(";", 1)[0].strip().lower()
    if media_type not in ALLOWED_MEDIA_TYPES:
        raise AnalysisJobValidationError("unsupported SBOM media type")
    return media_type


def _required(value: str, field: str, maximum: int) -> str:
    clean = (value or "").strip()
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
        filename=row["filename"], media_type=row["media_type"], size_bytes=row["size_bytes"],
        sha256=row["sha256"], input_format=row["input_format"], input_version=row["input_version"],
        preview=row["preview"], status=row["status"], stage=row["stage"], progress=row["progress"],
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
