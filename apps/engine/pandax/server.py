"""FastAPI dashboard - the second renderer of the same event stream.

The browser view is not a reimplementation of the CLI. Both consume the exact
same `Event` objects produced by pipeline.run(); this module just forwards them
over server-sent events instead of printing them.
"""

from __future__ import annotations

import json
import os
import queue
import re
import shutil
import tempfile
import threading
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse

from . import events as ev
from .cases import CaseError, CaseStore
from .stages.clock import parse_timestamp
from .context import OUT_DIR, ROOT
from .evidence import verify_run
from .stages.sbom import is_matchable_purl

WEB = Path(__file__).resolve().parent / "web"
MAX_SBOM_BYTES = 50 * 1024 * 1024

api = FastAPI(title="PandaX CRA Compliance Engine", docs_url="/api/docs")


def _case_store() -> CaseStore:
    data_dir = Path(os.environ.get("PANDAX_DATA_DIR", OUT_DIR / ".pandax"))
    return CaseStore(data_dir / "cases.sqlite3")


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
    ) -> None:
        from . import pipeline

        self.input_type = input_type

        def worker() -> None:
            try:
                if input_type == "sbom":
                    stream = pipeline.run_sbom(Path(artifact))
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
                        stream = pipeline.run(download(value.removeprefix("release:")))
                    else:
                        stream = pipeline.run(Path(artifact))
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
    with SCAN_LOCK:
        if CURRENT is not None and not CURRENT.finished:
            raise HTTPException(409, 'a scan is already running')
        CURRENT = Job()
        CURRENT.start(artifact)
    return {'started': True, 'artifact': str(artifact)}


@api.post("/api/scan/sbom")
async def start_sbom_scan(file: UploadFile = File(...)) -> dict[str, Any]:
    """Validate and start a run from an uploaded CycloneDX or SPDX JSON SBOM."""
    global CURRENT
    with SCAN_LOCK:
        if CURRENT is not None and not CURRENT.finished:
            raise HTTPException(409, "a scan is already running")

    upload_dir = Path(tempfile.mkdtemp(prefix="pandax-sbom-"))
    filename = Path(file.filename or "uploaded-sbom.json").name
    filename = re.sub(r"[^A-Za-z0-9._-]", "_", filename) or "uploaded-sbom.json"
    target = upload_dir / filename
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

        with SCAN_LOCK:
            # A product scan may have started while this file was uploading and
            # being validated, so claim the single-run slot atomically here.
            if CURRENT is not None and not CURRENT.finished:
                raise HTTPException(409, "a scan is already running")
            CURRENT = Job()
            CURRENT.start(target, input_type="sbom", cleanup_dir=upload_dir)
        started = True
        return {
            "started": True,
            "source_type": "sbom",
            "filename": filename,
            **info,
        }
    except Exception:
        if not started:
            shutil.rmtree(upload_dir, ignore_errors=True)
        raise
    finally:
        await file.close()


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
    checks = verify_run(target)
    return {
        "run_id": run_id,
        "ok": all(c.ok for c in checks),
        "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in checks],
    }


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
        }
        for c in sbom.get("components", [])
    ]
    # A component is "affected" if any finding cites its package URL.
    affected = {f["purl"] for f in findings}
    kev_purls = {f["purl"] for f in findings if f.get("kev")}
    finding_counts = Counter(f["purl"] for f in findings)
    for component in components:
        component["findings"] = finding_counts[component["purl"]]
        component["affected"] = component["purl"] in affected
        component["kev"] = component["purl"] in kev_purls

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
