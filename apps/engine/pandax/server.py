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

    def start(self, artifact: Path | str) -> None:
        from . import pipeline

        def worker() -> None:
            try:
                from .scenarios import download, run_scenario
                value = str(artifact)
                if value.startswith('scenario:'):
                    stream = run_scenario(value.removeprefix('scenario:'))
                elif value.startswith('release:'):
                    self._emit(ev.log('RUN', 'Downloading / verifying official release').as_dict())
                    stream = pipeline.run(download(value.removeprefix('release:')))
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
                  bytes=0, note=s['note'], group='Release comparisons') for s in SCENARIOS.values()]
    found += [dict(path='release:' + r['id'], name=r['name'] + ' ' + r['version'],
                   bytes=0, note='Single release scan. Official download verified by SHA-256.',
                   group='Individual releases') for r in RELEASES.values()]
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
        source = path / "release-source.json"
        release = json.loads(source.read_text(encoding="utf-8")) if source.exists() else {}
        comparison_path = path / "comparison.json"
        comparison = json.loads(comparison_path.read_text(encoding="utf-8")) if comparison_path.exists() else None
        out.append(
            {
                "comparison_passed": comparison['passed'] if comparison else None,
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
            "purl": c["purl"],
            "name": c.get("name", ""),
            "version": c.get("version", ""),
            "ecosystem": c["purl"].split("/")[0].replace("pkg:", ""),
            "type": c.get("type", "library"),
        }
        for c in sbom.get("components", [])
        if c.get("purl")
    ]
    # A component is "affected" if any finding cites its package URL.
    affected = {f["purl"] for f in findings}
    kev_purls = {f["purl"] for f in findings if f.get("kev")}
    for component in components:
        component["findings"] = sum(1 for f in findings if f["purl"] == component["purl"])
        component["affected"] = component["purl"] in affected
        component["kev"] = component["purl"] in kev_purls

    ledger = [
        json.loads(line)
        for line in (target / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ] if (target / "ledger.jsonl").exists() else []

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
