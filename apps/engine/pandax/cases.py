"""Durable remediation cases kept outside immutable scan bundles."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sqlite3
import uuid
from contextlib import nullcontext
from pathlib import Path
from .case_storage import Connection, migrate
from typing import Any

from .stages.clock import deadlines, parse_timestamp


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class CaseError(ValueError):
    pass


class CaseNotFound(CaseError):
    pass


class CaseConflict(CaseError):
    pass


class CaseStore:
    """Persist and advance remediation cases through one small interface."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, factory=Connection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _migrate(self) -> None:
        with self._connect() as db:
            migrate(db,
                """
                CREATE TABLE IF NOT EXISTS remediation_cases (
                    id TEXT PRIMARY KEY,
                    source_run_id TEXT NOT NULL,
                    cve TEXT NOT NULL,
                    component TEXT NOT NULL,
                    component_version TEXT NOT NULL,
                    purl TEXT NOT NULL,
                    finding_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    candidate_json TEXT,
                    measure_available_at TEXT,
                    final_deadline TEXT,
                    operator TEXT,
                    authority_attestation TEXT,
                    measure_details TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(source_run_id, cve, purl)
                );
                CREATE TABLE IF NOT EXISTS case_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL REFERENCES remediation_cases(id),
                    event_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    actor TEXT,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS report_revisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL REFERENCES remediation_cases(id),
                    revision INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    report_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    UNIQUE(case_id, revision)
                );
                """
            )

    def create(self, source_run_id: str, finding: dict[str, Any], db=None, simulated=False) -> dict[str, Any]:
        required = ("cve", "component", "version", "purl")
        if any(not finding.get(key) for key in required):
            raise CaseError("finding requires cve, component, version and purl")
        now = _utc_now()
        case_id = "case-" + uuid.uuid4().hex[:12]
        with (nullcontext(db) if db is not None else self._connect()) as db:
            existing = db.execute(
                "SELECT id FROM remediation_cases WHERE source_run_id=? AND cve=? AND purl=?",
                (source_run_id, finding["cve"], finding["purl"]),
            ).fetchone()
            if existing:
                return self.get(existing["id"], db)
            db.execute(
                """INSERT INTO remediation_cases
                   (id, source_run_id, cve, component, component_version, purl,
                    finding_json, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'detected', ?, ?)""",
                (
                    case_id, source_run_id, finding["cve"], finding["component"],
                    finding["version"], finding["purl"], _json(finding), now, now,
                ),
            )
            if simulated:
                db.execute('UPDATE remediation_cases SET state_json=? WHERE id=?', (_json({'simulated': True}), case_id))
            self._event(db, case_id, "finding_recorded", now, "PandaX", finding)
            return self.get(case_id, db)

    def observe_release(
        self,
        case_id: str,
        target_run_id: str,
        findings: list[dict[str, Any]],
        components: list[dict[str, Any]],
        db=None,
    ) -> dict[str, Any]:
        case = self.get(case_id, db)
        same_findings = [
            item for item in findings
            if item.get("cve") == case["cve"]
            and (item.get("purl") == case["purl"] or item.get("component") == case["component"])
        ]
        component_versions = sorted({
            str(item.get("version", "")) for item in components
            if str(item.get("name", "")).casefold() == case["component"].casefold()
            and item.get("version")
        })
        if same_findings:
            result = "still_detected"
            explanation = "The same vulnerability remains in the checked findings for this release."
        elif component_versions:
            result = "candidate_component_changed" if case["component_version"] not in component_versions else "candidate_no_finding"
            explanation = (
                "No matching finding in checked sources; component version(s) observed: "
                + ", ".join(component_versions)
                + ". Manufacturer confirmation is required."
            )
        else:
            result = "candidate_component_not_observed"
            explanation = (
                "No matching finding or identified component in this release. This may mean removal "
                "or incomplete identification; manufacturer confirmation is required."
            )
        candidate = {
            "result": result,
            "target_run_id": target_run_id,
            "observed_versions": component_versions,
            "coverage_statement": "No finding in checked sources" if not same_findings else "Finding remains in checked sources",
            "explanation": explanation,
        }
        now = _utc_now()
        status = "detected" if same_findings else "candidate_resolution"
        with (nullcontext(db) if db is not None else self._connect()) as db:
            db.execute(
                "UPDATE remediation_cases SET candidate_json=?, status=?, updated_at=? WHERE id=?",
                (_json(candidate), status, now, case_id),
            )
            self._event(db, case_id, "release_observed", now, "PandaX", candidate)
            return self.get(case_id, db)

    def confirm_measure(
        self,
        case_id: str,
        available_at: str,
        operator: str,
        authority_attestation: str,
        measure_details: str,
        db=None,
        create_report=True,
    ) -> dict[str, Any]:
        if not operator.strip():
            raise CaseError("named operator is required")
        if not authority_attestation.strip():
            raise CaseError("authority attestation is required")
        if not measure_details.strip():
            raise CaseError("measure details are required")
        try:
            availability = parse_timestamp(available_at)
        except (TypeError, ValueError) as exc:
            raise CaseError("measure availability must be an ISO 8601 timestamp") from exc
        final_deadline = deadlines(availability, availability)["final_report"]
        available_utc = availability.isoformat(timespec="seconds").replace("+00:00", "Z")
        now = _utc_now()
        with (nullcontext(db) if db is not None else self._connect()) as db:
            case = self.get(case_id, db)
            db.execute(
                """UPDATE remediation_cases SET status='measure_confirmed', measure_available_at=?,
                   final_deadline=?, operator=?, authority_attestation=?, measure_details=?, updated_at=?
                   WHERE id=?""",
                (available_utc, final_deadline, operator.strip(), authority_attestation.strip(), measure_details.strip(), now, case_id),
            )
            payload = {
                "measure_available_at": available_utc,
                "final_deadline": final_deadline,
                "authority_attestation": authority_attestation.strip(),
                "measure_details": measure_details.strip(),
            }
            self._event(db, case_id, "measure_confirmed", available_utc, operator.strip(), payload)
            updated = self.get(case_id, db)
            if not create_report:
                return updated
            report = self._report_payload(updated)
            report_json = _json(report)
            revision = db.execute(
                "SELECT COALESCE(MAX(revision), 0) + 1 value FROM report_revisions WHERE case_id=?",
                (case_id,),
            ).fetchone()["value"]
            db.execute(
                "INSERT INTO report_revisions (case_id, revision, created_at, report_hash, payload_json) VALUES (?, ?, ?, ?, ?)",
                (case_id, revision, now, hashlib.sha256(report_json.encode()).hexdigest(), report_json),
            )
            return self.get(case_id, db)

    def list(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            ids = [row["id"] for row in db.execute("SELECT id FROM remediation_cases ORDER BY updated_at DESC")]
            return [self.get(case_id, db) for case_id in ids]

    def get(self, case_id: str, db: sqlite3.Connection | None = None) -> dict[str, Any]:
        owns_connection = db is None
        db = db or self._connect()
        try:
            if owns_connection:
                db.execute('BEGIN')
            row = db.execute("SELECT * FROM remediation_cases WHERE id=?", (case_id,)).fetchone()
            if not row:
                raise CaseNotFound(f"case not found: {case_id}")
            result = dict(row)
            result['state'] = json.loads(result.pop('state_json'))
            result["finding"] = json.loads(result.pop("finding_json"))
            candidate_json = result.pop("candidate_json")
            result["candidate"] = json.loads(candidate_json) if candidate_json else None
            result["events"] = [
                {**dict(event), "payload": json.loads(event["payload_json"])}
                for event in db.execute("SELECT * FROM case_events WHERE case_id=? ORDER BY id", (case_id,))
            ]
            for event in result["events"]:
                event.pop("payload_json")
            revision = db.execute(
                "SELECT revision, created_at, report_hash, payload_json FROM report_revisions WHERE case_id=? ORDER BY revision DESC LIMIT 1",
                (case_id,),
            ).fetchone()
            result["report"] = (
                {**dict(revision), "payload": json.loads(revision["payload_json"])} if revision else None
            )
            if result["report"]:
                result["report"].pop("payload_json")
            return result
        finally:
            if owns_connection:
                db.close()

    def _event(
        self, db: sqlite3.Connection, case_id: str, event_type: str,
        occurred_at: str, actor: str, payload: dict[str, Any],
    ) -> None:
        state = db.execute('SELECT state_json FROM remediation_cases WHERE id=?', (case_id,)).fetchone()
        if state and json.loads(state['state_json']).get('simulated'):
            payload = {**payload, 'simulated': True}
        db.execute(
            "INSERT INTO case_events (case_id, event_type, occurred_at, recorded_at, actor, payload_json) VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, event_type, occurred_at, _utc_now(), actor, _json(payload)),
        )

    @staticmethod
    def _report_payload(case: dict[str, Any]) -> dict[str, Any]:
        return {
            "document_type": "CRA Article 14 actively exploited vulnerability final-report draft",
            "submission_status": "REVIEW REQUIRED - not submitted",
            "case_id": case["id"],
            "case_facts": case.get("state", {}),
            "source_run_id": case["source_run_id"],
            "vulnerability": {
                "cve": case["cve"],
                "component": case["component"],
                "version": case["component_version"],
                "severity": case["finding"].get("severity", "UNKNOWN"),
                "summary": case["finding"].get("summary", ""),
            },
            "candidate_resolution": case["candidate"],
            "manufacturer_confirmation": {
                "operator": case["operator"],
                "authority_attestation": case["authority_attestation"],
                "measure_details": case["measure_details"],
                "measure_available_at": case["measure_available_at"],
            },
            "final_report_deadline": case["final_deadline"],
            "next_action": "Manufacturer reviews and improves this draft before approval and manual submission.",
            "automation_limit": "PandaX detected and documented evidence; it did not patch or deploy the product.",
        }

