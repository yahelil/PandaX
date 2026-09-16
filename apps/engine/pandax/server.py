"""FastAPI dashboard - the second renderer of the same event stream.

The browser view is not a reimplementation of the CLI. Both consume the exact
same `Event` objects produced by pipeline.run(); this module just forwards them
over server-sent events instead of printing them.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import re
import shutil
import tempfile
import threading
import time
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Iterator
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse

from . import events as ev
from .cases import CaseStore
from .context import KEY_PATH, OUT_DIR, ROOT
from .evidence import TrustedKeyConfigurationError, verify_bundle
from .monitoring import MonitoringError, MonitoringStore
from .stages.sbom import is_matchable_purl

WEB = Path(__file__).resolve().parent / "web"
MAX_SBOM_BYTES = 50 * 1024 * 1024
MAX_TELEMETRY_BYTES = 1024 * 1024
MAX_EXPOSURE_CONTEXT_BYTES = 1024 * 1024
REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
logger = logging.getLogger(__name__)


def _advisory_service():
    from .advisory_watch import AdvisoryWatchService
    from .case_service import CaseService
    return AdvisoryWatchService(CaseService(runs_dir=OUT_DIR))


@asynccontextmanager
async def lifespan(app: FastAPI):
    from .advisory_watch import AdvisoryRefreshLoop
    from .portfolio_runtime import (
        MANAGED_ENVIRONMENTS,
        database_allows_background_growth,
        database_settings,
        get_analysis_repository,
        get_notification_delivery_worker,
        get_release_monitoring_repository,
        get_release_monitoring_runner,
        get_storage_status,
        runtime_environment,
    )
    from .notification_delivery import NotificationDeliveryLoop
    from .release_monitoring_worker import ReleaseMonitoringLoop

    from .runtime_metadata import build_metadata

    logger.info("service_start build=%s", json.dumps(build_metadata(), sort_keys=True))
    database_settings()  # Managed environments fail before serving if PostgreSQL is absent.
    get_storage_status()  # Managed environments require a reachable private object bucket.
    _signing_state()  # Managed signing policy is checked before accepting work.
    if runtime_environment() in MANAGED_ENVIRONMENTS:
        from .artifact_runtime import require_hosted_scanner
        from .document_runtime import require_hosted_document_tools
        require_hosted_scanner()
        require_hosted_document_tools()
    if runtime_environment() in {"staging", "beta"}:
        get_analysis_repository().fail_interrupted_jobs()
    interval = max(1, float(os.environ.get("PANDAX_ADVISORY_REFRESH_SECONDS", "3600")))
    loop = AdvisoryRefreshLoop(_advisory_service, interval)
    release_interval = max(
        1,
        float(os.environ.get("PANDAX_RELEASE_MONITORING_SECONDS", "60")),
    )
    release_loop = None
    if runtime_environment() not in {"staging", "beta", "production"}:
        release_loop = ReleaseMonitoringLoop(
            get_release_monitoring_repository,
            get_release_monitoring_runner(),
            interval_seconds=release_interval,
            growth_allowed=database_allows_background_growth,
        )
    delivery_loop = NotificationDeliveryLoop(
        get_notification_delivery_worker,
        interval_seconds=max(
            1, float(os.environ.get("PANDAX_NOTIFICATION_DELIVERY_SECONDS", "30"))
        ),
        growth_allowed=database_allows_background_growth,
    )
    app.state.advisory_refresh = loop
    app.state.release_monitoring = release_loop
    app.state.notification_delivery = delivery_loop
    loop.start()
    if release_loop:
        release_loop.start()
    delivery_loop.start()
    try:
        yield
    finally:
        delivery_loop.stop()
        if release_loop:
            release_loop.stop()
        loop.stop()


def _allowed_cors_origins(value: str | None = None) -> list[str]:
    origins: list[str] = []
    for raw_origin in (value if value is not None else os.environ.get("PANDAX_CORS_ORIGINS", "")).split(","):
        origin = raw_origin.strip().rstrip("/")
        if not origin:
            continue
        parsed = urlsplit(origin)
        local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if (
            origin == "*"
            or (parsed.scheme != "https" and not local_http)
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("PANDAX_CORS_ORIGINS must contain explicit HTTPS origins; HTTP is limited to localhost")
        if origin not in origins:
            origins.append(origin)
    return origins


api = FastAPI(title="PandaX CRA Compliance Engine", docs_url="/api/docs", lifespan=lifespan)

cors_origins = _allowed_cors_origins()
if cors_origins:
    api.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Accept", "Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID"],
        expose_headers=["Content-Disposition", "ETag", "X-Request-ID"],
        max_age=600,
    )


@api.middleware("http")
async def correlate_requests(request: Request, call_next):
    supplied = request.headers.get("X-Request-ID", "")
    request_id = supplied if REQUEST_ID.fullmatch(supplied) else uuid.uuid4().hex
    request.state.request_id = request_id
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception(
            "request_failed request_id=%s method=%s path=%s",
            request_id,
            request.method,
            request.url.path,
        )
        raise
    response.headers["X-Request-ID"] = request_id
    logger.info(
        "request_complete request_id=%s method=%s path=%s status=%s duration_ms=%.1f",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        (time.perf_counter() - started) * 1000,
    )
    return response


@api.middleware("http")
async def apply_browser_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    if request.url.path.startswith(("/api/", "/v1/")):
        response.headers["Cache-Control"] = "no-store"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@api.middleware("http")
async def enforce_database_capacity(request: Request, call_next):
    from .portfolio_runtime import (
        MANAGED_ENVIRONMENTS,
        get_database_status,
        runtime_environment,
    )

    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.url.path.startswith("/v1/"):
        try:
            managed = runtime_environment() in MANAGED_ENVIRONMENTS
            database = get_database_status() if managed else None
        except Exception:
            return JSONResponse(status_code=503, content={"detail": "database unavailable"})
        if database is not None and not database.ready:
            code = 507 if database.capacity == "full" else 503
            detail = "database capacity hard stop reached" if code == 507 else "database migration required"
            return JSONResponse(status_code=code, content={"detail": detail})
        response = await call_next(request)
        if database is not None and database.capacity in {"warning", "restricted"}:
            response.headers["X-Actis-Database-Capacity"] = database.capacity
        return response
    return await call_next(request)


@api.get("/health/live", include_in_schema=False)
def application_liveness() -> dict[str, str]:
    return {"status": "ok"}


@api.get("/health/build", include_in_schema=False)
def application_build() -> dict[str, str]:
    from .runtime_metadata import build_metadata

    return build_metadata()


@api.get("/health/ready", include_in_schema=False)
def database_readiness() -> dict[str, object]:
    from .portfolio_runtime import MANAGED_ENVIRONMENTS, get_database_status, get_storage_status, runtime_environment

    try:
        database = get_database_status()
    except Exception as exc:
        raise HTTPException(503, "database unavailable") from exc
    if not database.ready:
        detail = "database capacity hard stop reached" if database.capacity == "full" else "database migration required"
        raise HTTPException(503, detail)
    try:
        storage = get_storage_status()
    except Exception as exc:
        raise HTTPException(503, "evidence storage unavailable") from exc
    try:
        signer, registry = _signing_state()
    except Exception as exc:
        raise HTTPException(503, "signing custody unavailable") from exc
    scanner = None
    document_tools = None
    if runtime_environment() in MANAGED_ENVIRONMENTS:
        from .artifact_runtime import require_hosted_scanner
        from .document_runtime import require_hosted_document_tools
        try:
            scanner = require_hosted_scanner()
            document_tools = require_hosted_document_tools()
        except RuntimeError as exc:
            raise HTTPException(503, "required runtime tool unavailable") from exc
    return {
        **database.as_dict(),
        "storage": storage,
        "artifact_scanner": scanner,
        "document_tools": document_tools,
        "signing": {
            "provider": signer.identity.provider,
            "key_id": signer.identity.key_id,
            "key_version": signer.identity.key_version,
            "public_key_fingerprint": signer.identity.public_key_fingerprint,
            "registry_keys": len(registry.keys),
        },
    }


def _signing_state():
    from .signing import configured_registry, configured_signer

    signer = configured_signer(KEY_PATH)
    return signer, configured_registry(signer)


@api.get("/.well-known/actis-signing-keys.json", include_in_schema=False)
def signing_key_registry() -> dict[str, Any]:
    from .signing import configured_registry, configured_signer, load_registry_b64

    try:
        encoded = os.environ.get("PANDAX_SIGNING_KEY_REGISTRY_B64", "").strip()
        if encoded:
            return load_registry_b64(encoded).as_dict()
        signer = configured_signer(KEY_PATH)
        return configured_registry(signer).as_dict()
    except Exception as exc:
        raise HTTPException(503, "signing-key registry unavailable") from exc


def _case_store() -> CaseStore:
    data_dir = Path(os.environ.get("PANDAX_DATA_DIR", OUT_DIR / ".pandax"))
    return CaseStore(data_dir / "cases.sqlite3")


def _monitor_store() -> MonitoringStore:
    data_dir = Path(os.environ.get("PANDAX_DATA_DIR", OUT_DIR / ".pandax"))
    return MonitoringStore(data_dir / "monitoring.sqlite3")


def _run_json(run_id: str, name: str, default: Any) -> Any:
    target = (OUT_DIR / run_id).resolve()
    if not target.is_relative_to(OUT_DIR.resolve()) or not target.exists():
        raise HTTPException(404, f"run not found: {run_id}")
    path = target / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def _run_product(run_id: str) -> dict[str, str]:
    dossier = _run_json(run_id, "dossier.json", {})
    product = dossier.get("product") or _run_json(run_id, "manifest.json", {}).get("product", {})
    return {"name": str(product.get("name", "")), "version": str(product.get("version", ""))}


def _run_created(run_id: str) -> str:
    dossier = _run_json(run_id, "dossier.json", {})
    return str(dossier.get("generated") or _run_json(run_id, "manifest.json", {}).get("created", ""))


def _with_source_product(case: dict[str, Any]) -> dict[str, Any]:
    case["source_product"] = _run_product(case["source_run_id"])
    return case


class Job:
    """One pipeline run, fanned out to any number of SSE listeners.

    Each listener gets its own queue, registered under a lock alongside a
    snapshot of the history, so a browser that connects late sees the whole run
    exactly once - no gap, no duplicates.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.listeners: list[queue.Queue[dict[str, Any] | None]] = []
        self.history: list[dict[str, Any]] = []
        self.thread: threading.Thread | None = None
        self.finished = False
        self.error: str | None = None
        self.run_dir: str = ""
        self.input_type: str = "artifact"

    def subscribe(self) -> tuple[list[dict[str, Any]], queue.Queue]:
        with self.lock:
            backlog = list(self.history)
            listener: queue.Queue[dict[str, Any] | None] = queue.Queue()
            if self.finished:
                listener.put(None)
            else:
                self.listeners.append(listener)
            return backlog, listener

    def _emit(self, payload: dict[str, Any] | None) -> None:
        with self.lock:
            if payload is not None:
                self.history.append(payload)
            for listener in self.listeners:
                listener.put(payload)

    def unsubscribe(self, listener: queue.Queue) -> None:
        with self.lock:
            if listener in self.listeners:
                self.listeners.remove(listener)

    def start(
        self,
        artifact: Path | str,
        input_type: str = "artifact",
        cleanup_dir: Path | None = None,
        telemetry_path: Path | None = None,
        exposure_context_path: Path | None = None,
    ) -> None:
        from . import pipeline

        self.input_type = input_type

        def worker() -> None:
            try:
                options = {}
                if telemetry_path is not None:
                    options["telemetry_path"] = telemetry_path
                if exposure_context_path is not None:
                    options["exposure_context_path"] = exposure_context_path
                if input_type == "sbom":
                    stream = pipeline.run_sbom(Path(artifact), **options)
                else:
                    from .scenarios import download, run_scenario

                    value = str(artifact)
                    if value.startswith("scenario:"):
                        stream = run_scenario(value.removeprefix("scenario:"))
                    elif value.startswith("release:"):
                        self._emit(
                            ev.log(
                                "RUN", "Downloading / verifying official release"
                            ).as_dict()
                        )
                        stream = pipeline.run(
                            download(value.removeprefix("release:")),
                            **options,
                        )
                    else:
                        stream = pipeline.run(Path(artifact), **options)
                for event in stream:
                    payload = event.as_dict()
                    if "run_dir" in event.data:
                        self.run_dir = event.data["run_dir"]
                    self._emit(payload)
            except Exception as exc:  # surfaced to the browser, never swallowed
                self.error = f"{type(exc).__name__}: {exc}"
                self._emit(
                    ev.Event(
                        ev.RUN_DONE, "", self.error, ev.ALERT_LVL, {"failed": True}
                    ).as_dict()
                )
            finally:
                if cleanup_dir is not None:
                    shutil.rmtree(cleanup_dir, ignore_errors=True)
                self.finished = True
                self._emit(None)

        self.thread = threading.Thread(target=worker, daemon=True)
        self.thread.start()


CURRENT: Job | None = None
SCAN_LOCK = threading.Lock()


@api.get("/", response_class=HTMLResponse)
def index() -> str:
    return (WEB / "index.html").read_text(encoding="utf-8")


@api.get("/app.js")
def app_js() -> FileResponse:
    return FileResponse(WEB / "app.js", media_type="application/javascript")


@api.get("/style.css")
def style_css() -> FileResponse:
    return FileResponse(WEB / "style.css", media_type="text/css")


@api.get("/api/artifacts")
def artifacts() -> list[dict[str, Any]]:
    """Scannable artifacts found in fixtures/."""
    from .scenarios import SCENARIOS, RELEASES
    found = [dict(path='scenario:' + s['id'], name=s['name'] + ' — ' +
                  RELEASES[s['before']]['version'] + ' → ' + RELEASES[s['after']]['version'],
                  bytes=0, note='Runs two complete package analyses, then creates a signed before/after comparison. ' + s['note'],
                  group='Before/after comparisons — two analyses') for s in SCENARIOS.values()]
    found += [dict(path='release:' + r['id'], name=r['name'] + ' ' + r['version'],
                   bytes=0, note='Runs one complete analysis of this official software package. Download verified by SHA-256.',
                   group='Single software packages — one analysis') for r in RELEASES.values()]
    fixtures = ROOT / "fixtures"
    if fixtures.exists():
        for path in sorted(fixtures.iterdir()):
            if path.is_file() and path.suffix in {".zip", ".tgz", ".gz", ".tar"}:
                found.append(
                    {
                        "path": str(path),
                        "name": path.name,
                        "bytes": path.stat().st_size,
                    }
                )
            elif path.is_dir() and (path / "product.yaml").exists():
                found.append({"path": str(path), "name": path.name + "/", "bytes": 0})
    return found


@api.post("/api/scan")
def start_scan(body: dict[str, str]) -> dict[str, Any]:
    global CURRENT
    from .scenarios import SCENARIOS, RELEASES
    value = body.get('artifact', '')
    if value.startswith('scenario:'):
        if value.removeprefix('scenario:') not in SCENARIOS:
            raise HTTPException(400, 'unknown scenario')
        artifact = value
    elif value.startswith('release:'):
        if value.removeprefix('release:') not in RELEASES:
            raise HTTPException(400, 'unknown release')
        artifact = value
    else:
        artifact = Path(value)
        if not value or not artifact.exists():
            raise HTTPException(400, f'artifact not found: {value}')
    telemetry_path = None
    telemetry_value = str(body.get("telemetry", "")).strip()
    if telemetry_value:
        telemetry_path = Path(telemetry_value)
        try:
            from .telemetry import summary as telemetry_summary

            telemetry_summary(telemetry_path)
        except (OSError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc
        if value.startswith("scenario:"):
            raise HTTPException(
                400,
                "one telemetry file cannot be attached to a two-release comparison; "
                "scan the matching release directly",
            )
    exposure_context_path = None
    exposure_value = str(body.get("exposure_context", "")).strip()
    if exposure_value:
        exposure_context_path = Path(exposure_value)
        try:
            from .exposure import summary as exposure_summary

            exposure_summary(exposure_context_path)
        except (OSError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc
        if value.startswith("scenario:"):
            raise HTTPException(
                400,
                "one exposure context cannot be attached to a two-release comparison; "
                "scan the matching release directly",
            )
    with SCAN_LOCK:
        if CURRENT is not None and not CURRENT.finished:
            raise HTTPException(409, 'a scan is already running')
        CURRENT = Job()
        if telemetry_path is None and exposure_context_path is None:
            CURRENT.start(artifact)
        else:
            CURRENT.start(
                artifact,
                telemetry_path=telemetry_path,
                exposure_context_path=exposure_context_path,
            )
    return {
        'started': True,
        'artifact': str(artifact),
        'telemetry_attached': telemetry_path is not None,
        'exposure_context_attached': exposure_context_path is not None,
    }


@api.post("/api/scan/sbom")
async def start_sbom_scan(
    file: UploadFile = File(...),
    telemetry: UploadFile | None = File(None),
    exposure_context: UploadFile | None = File(None),
) -> dict[str, Any]:
    """Validate and start a run from an uploaded CycloneDX or SPDX JSON SBOM."""
    global CURRENT
    with SCAN_LOCK:
        if CURRENT is not None and not CURRENT.finished:
            raise HTTPException(409, "a scan is already running")

    upload_dir = Path(tempfile.mkdtemp(prefix="pandax-sbom-"))
    filename = Path(file.filename or "uploaded-sbom.json").name
    filename = re.sub(r"[^A-Za-z0-9._-]", "_", filename) or "uploaded-sbom.json"
    target = upload_dir / filename
    telemetry_target: Path | None = None
    exposure_target: Path | None = None
    size = 0
    started = False
    try:
        with open(target, "wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_SBOM_BYTES:
                    raise HTTPException(413, "SBOM upload exceeds the 50 MiB limit")
                out.write(chunk)

        from .stages.sbom import SbomError, inspect_sbom

        try:
            info = inspect_sbom(target)
        except SbomError as exc:
            raise HTTPException(400, str(exc)) from exc

        if telemetry is not None:
            telemetry_target = upload_dir / "runtime-telemetry.json"
            telemetry_size = 0
            with open(telemetry_target, "wb") as out:
                while chunk := await telemetry.read(256 * 1024):
                    telemetry_size += len(chunk)
                    if telemetry_size > MAX_TELEMETRY_BYTES:
                        raise HTTPException(
                            413, "telemetry upload exceeds the 1 MiB limit"
                        )
                    out.write(chunk)
            try:
                from .telemetry import summary as telemetry_summary

                telemetry_summary(telemetry_target)
            except (OSError, ValueError) as exc:
                raise HTTPException(400, str(exc)) from exc

        if exposure_context is not None:
            exposure_target = upload_dir / "exposure-context.json"
            exposure_size = 0
            with open(exposure_target, "wb") as out:
                while chunk := await exposure_context.read(256 * 1024):
                    exposure_size += len(chunk)
                    if exposure_size > MAX_EXPOSURE_CONTEXT_BYTES:
                        raise HTTPException(
                            413, "exposure context upload exceeds the 1 MiB limit"
                        )
                    out.write(chunk)
            try:
                from .exposure import summary as exposure_summary

                exposure_summary(exposure_target)
            except (OSError, ValueError) as exc:
                raise HTTPException(400, str(exc)) from exc

        with SCAN_LOCK:
            # A product scan may have started while this file was uploading and
            # being validated, so claim the single-run slot atomically here.
            if CURRENT is not None and not CURRENT.finished:
                raise HTTPException(409, "a scan is already running")
            CURRENT = Job()
            if telemetry_target is None and exposure_target is None:
                CURRENT.start(
                    target, input_type="sbom", cleanup_dir=upload_dir
                )
            else:
                CURRENT.start(
                    target,
                    input_type="sbom",
                    cleanup_dir=upload_dir,
                    telemetry_path=telemetry_target,
                    exposure_context_path=exposure_target,
                )
        started = True
        return {
            "started": True,
            "source_type": "sbom",
            "filename": filename,
            "telemetry_attached": telemetry_target is not None,
            "exposure_context_attached": exposure_target is not None,
            **info,
        }
    except Exception:
        if not started:
            shutil.rmtree(upload_dir, ignore_errors=True)
        raise
    finally:
        await file.close()
        if telemetry is not None:
            await telemetry.close()
        if exposure_context is not None:
            await exposure_context.close()


@api.post("/api/telemetry/validate")
def validate_telemetry(body: dict[str, str]) -> dict[str, Any]:
    """Validate a local telemetry summary without exposing its device rows."""
    try:
        from .telemetry import summary as telemetry_summary

        return telemetry_summary(Path(str(body.get("path", ""))))
    except (OSError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc


@api.post("/api/exposure/validate")
def validate_exposure_context(body: dict[str, str]) -> dict[str, Any]:
    """Validate reviewed exposure context without returning component details."""
    try:
        from .exposure import summary as exposure_summary

        return exposure_summary(Path(str(body.get("path", ""))))
    except (OSError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc


@api.get("/api/vendor-intelligence")
def vendor_intelligence_status() -> dict[str, Any]:
    """Show which administrator-curated catalogue future scans will use."""
    try:
        from .vendor_intelligence import load_active, summary

        document, path = load_active()
        if document is None:
            return {"installed": False}
        return {"installed": True, **summary(document)}
    except (OSError, ValueError) as exc:
        raise HTTPException(500, f"installed vendor catalogue is invalid: {exc}") from exc


@api.get("/api/job")
def job_status() -> dict[str, Any]:
    """Whether a run is in flight, so a reloaded page can re-attach to it."""
    if CURRENT is None:
        return {"exists": False, "running": False, "run_dir": ""}
    return {
        "exists": True,
        "running": not CURRENT.finished,
        "run_dir": CURRENT.run_dir,
        "events": len(CURRENT.history),
        "input_type": CURRENT.input_type,
    }


@api.get("/api/monitoring/policies")
def monitoring_policies() -> list[dict[str, Any]]:
    return _monitor_store().list_policies()


@api.post("/api/monitoring/policies")
def create_monitoring_policy(body: dict[str, Any]) -> dict[str, Any]:
    try:
        source = str(body.get("source", "")).strip()
        if not source:
            raise MonitoringError("monitoring source is required")
        return _monitor_store().add_policy(
            str(body.get("name", "")),
            Path(source),
            str(body.get("source_type", "artifact")),
            int(body.get("interval_minutes", 360)),
            Path(str(body["telemetry"])) if body.get("telemetry") else None,
            (
                Path(str(body["exposure_context"]))
                if body.get("exposure_context")
                else None
            ),
        )
    except (MonitoringError, TypeError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc


@api.post("/api/monitoring/policies/{policy_id}/run")
def run_monitoring_policy(policy_id: str) -> dict[str, Any]:
    try:
        return _monitor_store().run_policy(policy_id)
    except MonitoringError as exc:
        raise HTTPException(404, str(exc)) from exc


@api.post("/api/monitoring/run-due")
def run_due_monitoring() -> list[dict[str, Any]]:
    return _monitor_store().run_due()


@api.get("/api/monitoring/alerts")
def monitoring_alerts(policy_id: str | None = None) -> list[dict[str, Any]]:
    return _monitor_store().list_alerts(policy_id)


@api.get("/api/events")
def stream() -> StreamingResponse:
    """Server-sent events: the pipeline stream, verbatim."""
    job = CURRENT
    if job is None:
        raise HTTPException(404, "no scan has been started")

    backlog, listener = job.subscribe()

    def frame(payload: dict[str, Any]) -> str:
        return "data: " + json.dumps(payload) + "\n\n"

    def generate() -> Iterator[str]:
        try:
            for payload in backlog:
                yield frame(payload)
            while True:
                payload = listener.get()
                if payload is None:
                    yield "event: end\ndata: {}\n\n"
                    return
                yield frame(payload)
        finally:
            job.unsubscribe(listener)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@api.get("/api/runs")
def runs() -> list[dict[str, Any]]:
    if not OUT_DIR.exists():
        return []
    out = []
    for path in sorted(OUT_DIR.glob("run-*"), reverse=True):
        manifest = path / "manifest.json"
        if not manifest.exists():
            continue
        data = json.loads(manifest.read_text(encoding="utf-8"))
        source = path / "release-source.json"
        release = json.loads(source.read_text(encoding="utf-8")) if source.exists() else {}
        dossier_path = path / "dossier.json"
        dossier = json.loads(dossier_path.read_text(encoding="utf-8")) if dossier_path.exists() else {}
        comparison_path = path / "comparison.json"
        comparison = json.loads(comparison_path.read_text(encoding="utf-8")) if comparison_path.exists() else None
        input_type = dossier.get("summary", {}).get("input_type", "artifact")
        out.append(
            {
                "comparison_passed": comparison['passed'] if comparison else None,
                "result_type": "release_comparison" if comparison else
                               "sbom_analysis" if input_type == "sbom" else "package_analysis",
                "run_id": data.get("run_id"),
                "created": data.get("created"),
                "product": data.get("product", {}).get("name", "") or
                           (release.get("name", "") + " " + release.get("version", "")).strip(),
                "files": len(data.get("files", [])),
                "ledger_root": data.get("ledger_root", ""),
            }
        )
    return out


@api.get("/api/verify/{run_id}")
def verify(run_id: str) -> dict[str, Any]:
    target = OUT_DIR / run_id
    if not target.exists():
        raise HTTPException(404, f"run not found: {run_id}")
    configured = os.environ.get("PANDAX_TRUSTED_KEY")
    try:
        result = verify_bundle(target, Path(configured) if configured else None)
    except TrustedKeyConfigurationError as exc:
        raise HTTPException(503, f"trusted-key configuration error: {exc}") from exc
    return {"run_id": run_id, **result.as_dict()}


@api.post("/api/tamper/{run_id}")
def tamper(run_id: str, body: dict[str, str] | None = None) -> dict[str, Any]:
    """Flip one byte, so the dashboard can demonstrate the seal catching it."""
    import random

    target = (OUT_DIR / run_id).resolve()
    name = (body or {}).get("target", "sbom.cdx.json")
    victim = (target / name).resolve()
    if not victim.is_relative_to(target) or not victim.is_file():
        raise HTTPException(404, f"{name} not found in {run_id}")
    blob = bytearray(victim.read_bytes())
    candidates = [i for i, b in enumerate(blob) if chr(b).isdigit()]
    index = random.choice(candidates) if candidates else len(blob) // 2
    before = chr(blob[index])
    blob[index] = ord("9") if before != "9" else ord("8")
    victim.write_bytes(bytes(blob))
    return {"file": name, "offset": index, "before": before, "after": chr(blob[index])}


@api.get("/api/run/{run_id}/summary")
def summary(run_id: str) -> dict[str, Any]:
    """Everything the dashboard renders, in one call.

    The bundle's own files are the source of truth - nothing is recomputed here
    that the sealed run did not already record.
    """
    target = OUT_DIR / run_id
    if not target.exists():
        raise HTTPException(404, f"run not found: {run_id}")

    def load(name: str, default: Any) -> Any:
        path = target / name
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default

    findings = load("findings.json", [])
    incidents = load("incidents.json", [])
    dossier = load("dossier.json", {})
    manifest = load("manifest.json", {})
    sbom = load("sbom.cdx.json", {})
    coverage = load("coverage.json", {})
    triage_coverage = load("triage-coverage.json", {})

    # Historical bundles predate Card 09. Missing facts remain unknown rather
    # than being inferred from the presence or absence of a finding.
    for finding in findings:
        finding.setdefault("coverage_status", "unknown")
        finding.setdefault("affectedness", "unknown")
        finding.setdefault("affectedness_evidence", "")
        finding.setdefault("reachability", "unknown")
        finding.setdefault("reachability_evidence", "")
        finding.setdefault("exposure_assessment", "not_assessed")
        finding.setdefault("exposure_evidence", {})
        finding.setdefault("query_source", "")
        finding.setdefault("query_value", "")
        finding.setdefault("source_retrieved_at", "")
        finding.setdefault("kev_check_status", "unknown")
        finding.setdefault("kev_source_url", "")
        finding.setdefault("kev_checked_at", "")
        finding.setdefault("epss_check_status", "unknown")
        finding.setdefault("epss_source_url", "")
        finding.setdefault("epss_checked_at", "")
        if not finding.get("source_url") and finding.get("osv_id"):
            finding["source_url"] = (
                f"https://osv.dev/vulnerability/{finding['osv_id']}"
            )

    coverage_checks = coverage.get("checks", []) if isinstance(coverage, dict) else []
    checks_by_ref: dict[str, list[dict[str, Any]]] = {}
    checks_by_purl: dict[str, list[dict[str, Any]]] = {}
    for check in coverage_checks:
        if not isinstance(check, dict):
            continue
        checks_by_ref.setdefault(str(check.get("component_ref", "")), []).append(check)
        checks_by_purl.setdefault(str(check.get("purl", "")), []).append(check)

    def combined_coverage(checks: list[dict[str, Any]]) -> str:
        statuses = {str(check.get("status", "unknown")) for check in checks}
        for status in ("failed", "unknown", "completed", "unsupported", "unscanned"):
            if status in statuses:
                return status
        return "unknown"

    def combined_reachability(rows: list[dict[str, Any]]) -> str:
        states = {str(row.get("reachability", "unknown")) for row in rows}
        if "reachable" in states:
            return "reachable"
        if states == {"not_reachable"}:
            return "not_reachable"
        if "not_assessed" in states:
            return "not_assessed"
        return "unknown"

    components = [
        {
            "purl": c.get("purl", ""),
            "name": c.get("name", ""),
            "version": c.get("version", ""),
            "ecosystem": (
                c.get("purl", "").split("/")[0].replace("pkg:", "")
                if c.get("purl")
                else "unidentified"
            ),
            "type": c.get("type", "library"),
            "matchable": is_matchable_purl(c.get("purl")),
            "bom_ref": c.get("bom-ref", ""),
        }
        for c in sbom.get("components", [])
    ]
    # A component is "affected" if any finding cites its package URL.
    affected = {f["purl"] for f in findings}
    kev_purls = {f["purl"] for f in findings if f.get("kev")}
    finding_counts = Counter(f["purl"] for f in findings)
    for component in components:
        component_findings = [
            finding for finding in findings if finding.get("purl") == component["purl"]
        ]
        component_checks = checks_by_ref.get(component["bom_ref"])
        if component_checks is None:
            component_checks = checks_by_purl.get(component["purl"], [])
        component["findings"] = finding_counts[component["purl"]]
        component["affected"] = component["purl"] in affected
        component["kev"] = component["purl"] in kev_purls
        component["coverage_status"] = combined_coverage(component_checks)
        component["coverage_checks"] = component_checks
        affected_states = {
            str(finding.get("affectedness", "unknown"))
            for finding in component_findings
        }
        component["affectedness"] = (
            "affected" if "affected" in affected_states else "unknown"
        )
        component["reachability"] = combined_reachability(component_findings)

    ledger = [
        json.loads(line)
        for line in (target / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ] if (target / "ledger.jsonl").exists() else []

    from .verdict import build_verdict

    decision = build_verdict(findings, incidents, dossier)

    dossier_summary = dossier.get("summary", {})
    derived = dossier_summary.get("derived", 0)
    attested = dossier_summary.get("attested", 0)
    required = dossier_summary.get("required_input", 0)
    total_fields = derived + attested + required

    return {
        "run_id": run_id,
        "product": dossier.get("product", manifest.get("product", {})),
        "comparison": load("comparison.json", None),
        "release_checks": load("release-checks.json", None),
        "native_assessments": load("native-assessments.json", []),
        "vendor_assessments": load("vendor-assessments.json", {}),
        "vendor_superseded_findings": load("vendor-superseded-findings.json", {}),
        "exposure_assessments": load("exposure-assessments.json", {}),
        "coverage": coverage,
        "triage_coverage": triage_coverage,
        "manufacturer": dossier.get("manufacturer", {}),
        "generated": dossier.get("generated", manifest.get("created", "")),
        "stats": {
            "components": len(components),
            "input_type": dossier_summary.get("input_type", "artifact"),
            "sbom_source_format": dossier_summary.get("sbom_source_format", "CycloneDX"),
            "sbom_source_version": dossier_summary.get("sbom_source_version", "1.6"),
            "matchable_components": dossier_summary.get(
                "matchable_components", len(components)
            ),
            "skipped_components": dossier_summary.get("skipped_components", 0),
            "ecosystems": dossier_summary.get("ecosystems", ""),
            "findings": len(findings),
            "kev": sum(1 for f in findings if f.get("kev")),
            "incidents": len(incidents),
            "derived": derived,
            "attested": attested,
            "required_input": required,
            "total_fields": total_fields,
            # Annex VII/V completeness: the share of required entries this run
            # can actually evidence. Not a marketing "compliance score".
            "completeness": round(100 * (derived + attested) / total_fields)
            if total_fields
            else 0,
            "sealed_bundles": _sealed_bundle_count(),
            "ledger_records": len(ledger),
            "manifest_files": len(manifest.get("files", [])),
            "ledger_root": manifest.get("ledger_root", ""),
            "tool_versions": manifest.get("tool_versions", {}),
            "coverage_summary": (
                coverage.get("summary", {}) if isinstance(coverage, dict) else {}
            ),
        },
        "verdict": decision.as_dict(),
        "components": components,
        "findings": findings,
        "incidents": incidents,
        "ledger": ledger,
        "annex_vii": dossier.get("annex_vii", []),
        "annex_v": dossier.get("annex_v", []),
        "files": sorted(
            p.relative_to(target).as_posix()
            for p in target.rglob("*")
            if p.is_file() and "extracted" not in p.parts
        ),
    }


def _sealed_bundle_count() -> int:
    if not OUT_DIR.exists():
        return 0
    return sum(1 for p in OUT_DIR.glob("run-*") if (p / "manifest.json").exists())


@api.get("/api/run/{run_id}/file/{path:path}")
def get_file(run_id: str, path: str) -> FileResponse:
    target = (OUT_DIR / run_id / path).resolve()
    if not target.is_relative_to((OUT_DIR / run_id).resolve()) or not target.exists():
        raise HTTPException(404, "not found")
    media = "application/pdf" if target.suffix == ".pdf" else "text/plain"
    return FileResponse(target, media_type=media)


# Case routing stays isolated from scan and verification endpoints.
from .case_api import router as case_router

api.include_router(case_router)

# Portfolio routing crosses a repository dependency so API tests and later
# service deployments can replace storage without rewriting route handlers.
from .analysis_api import create_analysis_router
from .compliance_v1_api import create_compliance_v1_router
from .documents_api import create_documents_router
from .findings_api import create_findings_router
from .home_api import create_home_router
from .portfolio_api import create_portfolio_router
from .portfolio_runtime import (
    database_allows_background_growth,
    get_analysis_repository,
    enroll_completed_analysis,
    get_compliance_repository,
    get_document_repository,
    get_authenticated_principal,
    get_finding_repository,
    get_home_read_model,
    get_organization_settings_repository,
    get_portfolio_identity,
    get_portfolio_repository,
    get_release_monitoring_repository,
    get_release_monitoring_runner,
    get_search_notification_repository,
)
from .release_monitoring_api import create_release_monitoring_router
from .release_monitoring_scheduler_api import create_release_monitoring_scheduler_router
from .search_notifications_api import create_search_notifications_router
from .settings_api import create_settings_router
from .auth import Principal


@api.get("/v1/organizations/{organization_id}/session")
async def application_session(
    principal: Annotated[Principal, Depends(get_authenticated_principal)],
) -> dict[str, object]:
    """Return application authority resolved from the database membership."""

    return {
        "subject": principal.subject,
        "organization_id": principal.organization_id,
        "roles": sorted(role.value for role in principal.roles),
    }

api.include_router(
    create_portfolio_router(get_portfolio_repository, get_portfolio_identity)
)
api.include_router(
    create_analysis_router(
        get_analysis_repository,
        get_portfolio_identity,
        settings_repository_dependency=get_organization_settings_repository,
        completion_callback=enroll_completed_analysis,
    )
)
api.include_router(
    create_release_monitoring_router(
        get_release_monitoring_repository,
        get_release_monitoring_runner(),
        get_portfolio_identity,
    )
)
api.include_router(
    create_release_monitoring_scheduler_router(
        get_release_monitoring_repository,
        get_release_monitoring_runner(),
        database_allows_background_growth,
    )
)
api.include_router(
    create_findings_router(get_finding_repository, get_portfolio_identity)
)
api.include_router(
    create_compliance_v1_router(get_compliance_repository, get_portfolio_identity)
)
api.include_router(
    create_documents_router(get_document_repository, get_authenticated_principal)
)
api.include_router(
    create_search_notifications_router(
        get_search_notification_repository,
        get_portfolio_identity,
    )
)
api.include_router(
    create_home_router(get_home_read_model, get_portfolio_identity)
)
api.include_router(
    create_settings_router(
        get_organization_settings_repository,
        get_authenticated_principal,
    )
)
