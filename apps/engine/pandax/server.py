"""FastAPI dashboard - the second renderer of the same event stream.

The browser view is not a reimplementation of the CLI. Both consume the exact
same `Event` objects produced by pipeline.run(); this module just forwards them
over server-sent events instead of printing them.
"""

from __future__ import annotations

import json
import queue
import threading
from pathlib import Path
from typing import Any, Iterator

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse

from . import events as ev
from .context import OUT_DIR, ROOT
from .evidence import verify_run

WEB = Path(__file__).resolve().parent / "web"

api = FastAPI(title="PandaX CRA Compliance Engine", docs_url="/api/docs")


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

    def start(self, artifact: Path) -> None:
        from . import pipeline

        def worker() -> None:
            try:
                for event in pipeline.run(artifact):
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
                self.finished = True
                self._emit(None)

        self.thread = threading.Thread(target=worker, daemon=True)
        self.thread.start()


CURRENT: Job | None = None


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
    found = []
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
    if CURRENT is not None and not CURRENT.finished:
        raise HTTPException(409, "a scan is already running")
    artifact = Path(body.get("artifact", ""))
    if not artifact.exists():
        raise HTTPException(400, f"artifact not found: {artifact}")
    CURRENT = Job()
    CURRENT.start(artifact)
    return {"started": True, "artifact": str(artifact)}


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
        for payload in backlog:
            yield frame(payload)
        while True:
            payload = listener.get()
            if payload is None:
                yield "event: end\ndata: {}\n\n"
                return
            yield frame(payload)

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
        out.append(
            {
                "run_id": data.get("run_id"),
                "created": data.get("created"),
                "product": data.get("product", {}).get("name", ""),
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

    target = OUT_DIR / run_id
    name = (body or {}).get("target", "sbom.cdx.json")
    victim = target / name
    if not victim.exists():
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
    target = OUT_DIR / run_id
    if not target.exists():
        raise HTTPException(404, f"run not found: {run_id}")

    def load(name: str, default: Any) -> Any:
        path = target / name
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default

    findings = load("findings.json", [])
    return {
        "run_id": run_id,
        "dossier": load("dossier.json", {}),
        "incidents": load("incidents.json", []),
        "kev": [f for f in findings if f.get("kev")],
        "findings_total": len(findings),
        "files": sorted(
            p.relative_to(target).as_posix()
            for p in target.rglob("*")
            if p.is_file() and "extracted" not in p.parts
        ),
    }


@api.get("/api/run/{run_id}/file/{path:path}")
def get_file(run_id: str, path: str) -> FileResponse:
    target = (OUT_DIR / run_id / path).resolve()
    if not target.is_relative_to((OUT_DIR / run_id).resolve()) or not target.exists():
        raise HTTPException(404, "not found")
    media = "application/pdf" if target.suffix == ".pdf" else "text/plain"
    return FileResponse(target, media_type=media)
