"""Durable scheduled monitoring around the existing PandaX scan pipeline.

Monitoring never turns a feed signal into a legal conclusion.  It records
what was checked, keeps one active row per finding, and emits alerts only when
the observable state changes.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Callable


Runner = Callable[[dict[str, Any], Path], Path]


class MonitoringError(ValueError):
    """A monitoring policy or execution request is invalid."""


def _utc_now(now: dt.datetime | None = None) -> str:
    value = now or dt.datetime.now(dt.timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _finding_key(finding: dict[str, Any]) -> str:
    identity = {
        "cve": str(finding.get("cve", "")),
        "purl": str(finding.get("purl", "")) or (
            str(finding.get("component", "")) + "@" + str(finding.get("version", ""))
        ),
    }
    return hashlib.sha256(_json(identity).encode()).hexdigest()


def _finding_digest(finding: dict[str, Any]) -> str:
    important = {
        key: finding.get(key)
        for key in (
            "cve", "purl", "component", "version", "severity", "fixed_version",
            "kev", "affectedness", "reachability", "source_url",
            "runtime_evidence_status", "runtime_evidence",
            "exposure_assessment", "exposure_evidence",
        )
    }
    return hashlib.sha256(_json(important).encode()).hexdigest()


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default
    except (OSError, json.JSONDecodeError):
        return default


def _source_checks(run_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name in ("coverage.json", "triage-coverage.json"):
        document = _read_json(run_dir / name, {})
        if isinstance(document, dict):
            rows.extend(row for row in document.get("checks", []) if isinstance(row, dict))
    return rows


def _coverage_state(checks: list[dict[str, Any]]) -> str:
    required_sources = {"OSV.dev", "CISA Known Exploited Vulnerabilities"}
    present_sources = {str(check.get("source", "")) for check in checks}
    if not required_sources.issubset(present_sources):
        return "incomplete"
    relevant = []
    for check in checks:
        status = str(check.get("status", "unknown")).lower()
        reason = str(check.get("reason", ""))
        # EPSS has nothing to query when no CVEs were found; that is not a gap.
        if status == "unscanned" and "No CVEs required" in reason:
            continue
        relevant.append(status)
    if any(status in {"failed", "unknown"} for status in relevant):
        return "incomplete"
    if any(status in {"unsupported", "unscanned"} for status in relevant):
        return "partial"
    return "complete"


def _source_key(check: dict[str, Any]) -> str:
    return "|".join((str(check.get("source", "unknown")), str(check.get("source_url", ""))))


def _source_statuses(checks: list[dict[str, Any]]) -> dict[str, str]:
    priority = {"failed": 4, "unknown": 3, "unsupported": 2, "unscanned": 1, "completed": 0}
    result: dict[str, str] = {}
    for check in checks:
        key = _source_key(check)
        status = str(check.get("status", "unknown")).lower()
        if priority.get(status, 3) >= priority.get(result.get(key, "completed"), 0):
            result[key] = status
    return result


class ScanExecutionError(RuntimeError):
    def __init__(self, message: str, run_dir: Path | None = None):
        super().__init__(message)
        self.run_dir = run_dir


def pipeline_runner(policy: dict[str, Any], out_base: Path) -> Path:
    """Run the normal scanner and return its evidence directory."""
    from . import pipeline
    from . import events as ev

    source = Path(policy["source_path"])
    telemetry_path = (
        Path(policy["telemetry_path"]) if policy.get("telemetry_path") else None
    )
    exposure_context_path = (
        Path(policy["exposure_context_path"])
        if policy.get("exposure_context_path")
        else None
    )
    optional = {}
    if telemetry_path is not None:
        optional["telemetry_path"] = telemetry_path
    if exposure_context_path is not None:
        optional["exposure_context_path"] = exposure_context_path
    stream = (
        pipeline.run_sbom(source, out_base=out_base, **optional)
        if policy["source_type"] == "sbom"
        else pipeline.run(source, out_base=out_base, **optional)
    )
    run_dir: Path | None = None
    try:
        for event in stream:
            if event.kind == ev.LOG and event.data.get("run_dir"):
                run_dir = Path(event.data["run_dir"])
    except Exception as exc:
        raise ScanExecutionError(f"{type(exc).__name__}: {exc}", run_dir) from exc
    if run_dir is None:
        raise ScanExecutionError("scan completed without producing an evidence directory")
    return run_dir


class MonitoringStore:
    """SQLite-backed monitoring policies, observations and transition alerts."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def _migrate(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS monitoring_policies (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    telemetry_path TEXT,
                    exposure_context_path TEXT,
                    interval_minutes INTEGER NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_started_at TEXT,
                    last_completed_at TEXT,
                    next_due_at TEXT NOT NULL,
                    last_run_id TEXT,
                    last_status TEXT NOT NULL DEFAULT 'never_run',
                    UNIQUE(source_path, source_type)
                );
                CREATE TABLE IF NOT EXISTS monitoring_runs (
                    id TEXT PRIMARY KEY,
                    policy_id TEXT NOT NULL REFERENCES monitoring_policies(id),
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    coverage_state TEXT NOT NULL,
                    scan_run_id TEXT,
                    error TEXT NOT NULL,
                    findings_count INTEGER NOT NULL,
                    source_checks_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS monitored_findings (
                    policy_id TEXT NOT NULL REFERENCES monitoring_policies(id),
                    finding_key TEXT NOT NULL,
                    finding_digest TEXT NOT NULL,
                    finding_json TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    active INTEGER NOT NULL,
                    PRIMARY KEY(policy_id, finding_key)
                );
                CREATE TABLE IF NOT EXISTS monitoring_source_states (
                    policy_id TEXT NOT NULL REFERENCES monitoring_policies(id),
                    source_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    checked_at TEXT NOT NULL,
                    PRIMARY KEY(policy_id, source_key)
                );
                CREATE TABLE IF NOT EXISTS monitoring_alerts (
                    id TEXT PRIMARY KEY,
                    policy_id TEXT NOT NULL REFERENCES monitoring_policies(id),
                    kind TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    acknowledged INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            columns = {
                row["name"]
                for row in db.execute("PRAGMA table_info(monitoring_policies)")
            }
            if "telemetry_path" not in columns:
                db.execute(
                    "ALTER TABLE monitoring_policies ADD COLUMN telemetry_path TEXT"
                )
            if "exposure_context_path" not in columns:
                db.execute(
                    "ALTER TABLE monitoring_policies ADD COLUMN exposure_context_path TEXT"
                )

    def add_policy(
        self,
        name: str,
        source: Path,
        source_type: str = "artifact",
        interval_minutes: int = 360,
        telemetry: Path | None = None,
        exposure_context: Path | None = None,
        now: dt.datetime | None = None,
    ) -> dict[str, Any]:
        if not name.strip():
            raise MonitoringError("policy name is required")
        if source_type not in {"artifact", "sbom"}:
            raise MonitoringError("source_type must be artifact or sbom")
        if interval_minutes < 1:
            raise MonitoringError("interval_minutes must be at least 1")
        resolved = Path(source).resolve()
        if not resolved.exists():
            raise MonitoringError(f"monitoring source not found: {resolved}")
        telemetry_resolved: Path | None = None
        if telemetry is not None:
            telemetry_resolved = Path(telemetry).resolve()
            try:
                from .telemetry import summary as telemetry_summary

                telemetry_summary(telemetry_resolved)
            except (OSError, ValueError) as exc:
                raise MonitoringError(str(exc)) from exc
        exposure_resolved: Path | None = None
        if exposure_context is not None:
            exposure_resolved = Path(exposure_context).resolve()
            try:
                from .exposure import summary as exposure_summary

                exposure_summary(exposure_resolved)
            except (OSError, ValueError) as exc:
                raise MonitoringError(str(exc)) from exc
        created = _utc_now(now)
        policy_id = "monitor-" + uuid.uuid4().hex[:12]
        try:
            with self._connect() as db:
                db.execute(
                    """INSERT INTO monitoring_policies
                       (id, name, source_path, source_type, telemetry_path,
                        exposure_context_path, interval_minutes,
                        created_at, updated_at, next_due_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (policy_id, name.strip(), str(resolved), source_type,
                     str(telemetry_resolved) if telemetry_resolved else None,
                     str(exposure_resolved) if exposure_resolved else None,
                     interval_minutes, created, created, created),
                )
        except sqlite3.IntegrityError as exc:
            raise MonitoringError("this source is already registered for monitoring") from exc
        return self.get_policy(policy_id)

    def get_policy(self, policy_id: str) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute("SELECT * FROM monitoring_policies WHERE id=?", (policy_id,)).fetchone()
            if not row:
                raise MonitoringError(f"monitoring policy not found: {policy_id}")
            result = dict(row)
            result["enabled"] = bool(result["enabled"])
            result["active_findings"] = db.execute(
                "SELECT COUNT(*) value FROM monitored_findings WHERE policy_id=? AND active=1",
                (policy_id,),
            ).fetchone()["value"]
            result["unacknowledged_alerts"] = db.execute(
                "SELECT COUNT(*) value FROM monitoring_alerts WHERE policy_id=? AND acknowledged=0",
                (policy_id,),
            ).fetchone()["value"]
            last_run = db.execute(
                "SELECT * FROM monitoring_runs WHERE policy_id=? ORDER BY started_at DESC, id DESC LIMIT 1",
                (policy_id,),
            ).fetchone()
            result["last_run"] = self._run_dict(last_run) if last_run else None
            return result

    def list_policies(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            ids = [row["id"] for row in db.execute(
                "SELECT id FROM monitoring_policies ORDER BY name COLLATE NOCASE, id"
            )]
        return [self.get_policy(policy_id) for policy_id in ids]

    def list_alerts(self, policy_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM monitoring_alerts"
        params: tuple[Any, ...] = ()
        if policy_id:
            query += " WHERE policy_id=?"
            params = (policy_id,)
        query += " ORDER BY created_at DESC, id DESC"
        with self._connect() as db:
            return [self._alert_dict(row) for row in db.execute(query, params)]

    def run_due(
        self,
        runner: Runner | None = None,
        now: dt.datetime | None = None,
    ) -> list[dict[str, Any]]:
        current = _utc_now(now)
        with self._connect() as db:
            ids = [row["id"] for row in db.execute(
                """SELECT id FROM monitoring_policies
                   WHERE enabled=1 AND next_due_at<=? ORDER BY next_due_at, id""",
                (current,),
            )]
        return [self.run_policy(policy_id, runner=runner, now=now) for policy_id in ids]

    def run_policy(
        self,
        policy_id: str,
        runner: Runner | None = None,
        now: dt.datetime | None = None,
    ) -> dict[str, Any]:
        policy = self.get_policy(policy_id)
        started = _utc_now(now)
        next_due = _utc_now(_parse(started) + dt.timedelta(minutes=policy["interval_minutes"]))
        monitor_run_id = "monitor-run-" + uuid.uuid4().hex[:12]
        with self._connect() as db:
            db.execute(
                "UPDATE monitoring_policies SET last_started_at=?, next_due_at=?, updated_at=? WHERE id=?",
                (started, next_due, started, policy_id),
            )

        source = Path(policy["source_path"])
        telemetry = Path(policy["telemetry_path"]) if policy.get("telemetry_path") else None
        exposure_context = (
            Path(policy["exposure_context_path"])
            if policy.get("exposure_context_path")
            else None
        )
        run_dir: Path | None = None
        try:
            if not source.exists():
                raise ScanExecutionError(f"monitoring source not found: {source}")
            if telemetry is not None and not telemetry.exists():
                raise ScanExecutionError(f"monitoring telemetry not found: {telemetry}")
            if exposure_context is not None and not exposure_context.exists():
                raise ScanExecutionError(
                    f"monitoring exposure context not found: {exposure_context}"
                )
            run_dir = (runner or pipeline_runner)(policy, self.path.parent / "monitoring-runs")
            findings = _read_json(run_dir / "findings.json", [])
            if not isinstance(findings, list):
                raise ScanExecutionError("scan findings are malformed", run_dir)
            checks = _source_checks(run_dir)
            coverage_state = _coverage_state(checks)
            status = "incomplete" if coverage_state == "incomplete" else "completed"
            error = "" if status == "completed" else "one or more vulnerability sources were not checked successfully"
        except Exception as exc:
            if isinstance(exc, ScanExecutionError) and exc.run_dir is not None:
                run_dir = exc.run_dir
            findings = []
            checks = _source_checks(run_dir) if run_dir else []
            coverage_state = "incomplete"
            # The normal pipeline deliberately stops when source coverage is
            # incomplete. Preserve that meaningful state when its evidence
            # files exist; reserve "failed" for scans that could not produce
            # source-health evidence at all.
            status = "incomplete" if checks else "failed"
            error = str(exc)

        completed = _utc_now(now)
        scan_run_id = run_dir.name if run_dir else None
        with self._connect() as db:
            previous_status = policy["last_status"]
            db.execute(
                """INSERT INTO monitoring_runs
                   (id, policy_id, started_at, completed_at, status, coverage_state,
                    scan_run_id, error, findings_count, source_checks_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (monitor_run_id, policy_id, started, completed, status, coverage_state,
                 scan_run_id, error, len(findings), _json(checks)),
            )
            db.execute(
                """UPDATE monitoring_policies SET last_completed_at=?, last_run_id=?,
                   last_status=?, updated_at=? WHERE id=?""",
                (completed, scan_run_id, status, completed, policy_id),
            )
            if status == "failed":
                if previous_status != "failed":
                    self._alert(db, policy_id, "monitoring_failed", completed, {"error": error})
            else:
                if status == "incomplete" and previous_status != "incomplete":
                    self._alert(
                        db, policy_id, "monitoring_incomplete", completed,
                        {"scan_run_id": scan_run_id, "reason": error},
                    )
                if status == "completed" and previous_status in {"failed", "incomplete"}:
                    self._alert(db, policy_id, "monitoring_recovered", completed, {"scan_run_id": scan_run_id})
                self._record_sources(db, policy_id, checks, completed)
                self._record_findings(
                    db, policy_id, findings, completed,
                    allow_resolution=coverage_state == "complete",
                )
        return self.get_run(monitor_run_id)

    def get_run(self, run_id: str) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute("SELECT * FROM monitoring_runs WHERE id=?", (run_id,)).fetchone()
            if not row:
                raise MonitoringError(f"monitoring run not found: {run_id}")
            return self._run_dict(row)

    def _record_sources(
        self, db: sqlite3.Connection, policy_id: str,
        checks: list[dict[str, Any]], checked_at: str,
    ) -> None:
        for key, status in _source_statuses(checks).items():
            previous = db.execute(
                "SELECT status FROM monitoring_source_states WHERE policy_id=? AND source_key=?",
                (policy_id, key),
            ).fetchone()
            previous_status = previous["status"] if previous else None
            bad = status in {"failed", "unknown"}
            was_bad = previous_status in {"failed", "unknown"}
            if bad and not was_bad:
                self._alert(db, policy_id, "source_failure", checked_at, {"source": key, "status": status})
            elif previous_status is not None and was_bad and not bad:
                self._alert(db, policy_id, "source_recovered", checked_at, {"source": key, "status": status})
            db.execute(
                """INSERT INTO monitoring_source_states
                   (policy_id, source_key, status, checked_at) VALUES (?, ?, ?, ?)
                   ON CONFLICT(policy_id, source_key) DO UPDATE SET
                   status=excluded.status, checked_at=excluded.checked_at""",
                (policy_id, key, status, checked_at),
            )

    def _record_findings(
        self, db: sqlite3.Connection, policy_id: str,
        findings: list[dict[str, Any]], observed_at: str,
        allow_resolution: bool,
    ) -> None:
        current: set[str] = set()
        for finding in findings:
            key = _finding_key(finding)
            digest = _finding_digest(finding)
            current.add(key)
            previous = db.execute(
                "SELECT * FROM monitored_findings WHERE policy_id=? AND finding_key=?",
                (policy_id, key),
            ).fetchone()
            if previous is None:
                db.execute(
                    """INSERT INTO monitored_findings
                       (policy_id, finding_key, finding_digest, finding_json,
                        first_seen_at, last_seen_at, active)
                       VALUES (?, ?, ?, ?, ?, ?, 1)""",
                    (policy_id, key, digest, _json(finding), observed_at, observed_at),
                )
                self._alert(db, policy_id, "new_finding", observed_at, finding)
            else:
                kind = None
                if not previous["active"]:
                    kind = "finding_reappeared"
                elif previous["finding_digest"] != digest:
                    kind = "finding_changed"
                db.execute(
                    """UPDATE monitored_findings SET finding_digest=?, finding_json=?,
                       last_seen_at=?, active=1 WHERE policy_id=? AND finding_key=?""",
                    (digest, _json(finding), observed_at, policy_id, key),
                )
                if kind:
                    self._alert(db, policy_id, kind, observed_at, finding)

        if not allow_resolution:
            return
        active = db.execute(
            "SELECT finding_key, finding_json FROM monitored_findings WHERE policy_id=? AND active=1",
            (policy_id,),
        ).fetchall()
        for previous in active:
            if previous["finding_key"] not in current:
                db.execute(
                    "UPDATE monitored_findings SET active=0 WHERE policy_id=? AND finding_key=?",
                    (policy_id, previous["finding_key"]),
                )
                self._alert(
                    db, policy_id, "finding_no_longer_detected", observed_at,
                    json.loads(previous["finding_json"]),
                )

    @staticmethod
    def _alert(
        db: sqlite3.Connection, policy_id: str, kind: str,
        created_at: str, payload: dict[str, Any],
    ) -> None:
        db.execute(
            "INSERT INTO monitoring_alerts (id, policy_id, kind, created_at, payload_json) VALUES (?, ?, ?, ?, ?)",
            ("alert-" + uuid.uuid4().hex[:12], policy_id, kind, created_at, _json(payload)),
        )

    @staticmethod
    def _run_dict(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["source_checks"] = json.loads(result.pop("source_checks_json"))
        return result

    @staticmethod
    def _alert_dict(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["acknowledged"] = bool(result["acknowledged"])
        result["payload"] = json.loads(result.pop("payload_json"))
        return result
