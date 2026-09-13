"""Persistent release inventories and deduplicated advisory refreshes."""
from __future__ import annotations

import hashlib
import json
import threading
from typing import Callable

from .case_service import CaseService
from .cases import CaseError, CaseNotFound, _json, _utc_now
from .context import CACHE_DIR
from .feeds import Feeds
from .stages.match import findings_from_advisories
from .stages.sbom import is_matchable_purl


def canonical_identity(advisory_id: str, advisory: dict) -> str:
    cves = sorted(alias.upper() for alias in advisory.get("aliases", []) if alias.upper().startswith("CVE-"))
    return cves[0] if cves else str(advisory.get("id") or advisory_id).upper()


class AdvisoryWatchService:
    def __init__(
        self,
        case_service: CaseService,
        feeds_factory: Callable[[], Feeds] | None = None,
        now: Callable[[], str] = _utc_now,
    ):
        self.cases = case_service
        self.feeds_factory = feeds_factory or (lambda: Feeds(CACHE_DIR))
        self.now = now

    def watch(self, run_id: str, simulated: bool = False) -> dict:
        if type(simulated) is not bool:
            raise CaseError("simulated must be a boolean")
        product, _ = self.cases.product(run_id)
        components = self.cases.run_json(run_id, "sbom.cdx.json", {}).get("components", [])
        inventory = sorted(
            (
                {
                    "name": str(component.get("name", "")),
                    "version": str(component.get("version", "")),
                    "purl": str(component.get("purl", "")),
                    "bom_ref": str(component.get("bom-ref") or component.get("bom_ref") or component.get("purl", "")),
                }
                for component in components
                if is_matchable_purl(component.get("purl"))
            ),
            key=lambda component: (component["purl"], component["name"]),
        )
        if not product["name"] or not product["version"]:
            raise CaseError("watched release requires identified product name and version")
        if not inventory:
            raise CaseError("watched release has no matchable versioned package URLs")
        release_identity = [product["name"].casefold(), product["version"].casefold(), simulated]
        watch_id = "watch-" + hashlib.sha256(_json(release_identity).encode()).hexdigest()[:12]
        now = self.now()
        with self.cases.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """INSERT OR IGNORE INTO advisory_watches
                   (id,run_id,product_name,product_version,inventory_json,simulated,created_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (watch_id, run_id, product["name"], product["version"], _json(inventory), simulated, now),
            )
        return self.get(watch_id)

    def list(self) -> list[dict]:
        with self.cases.store._connect() as db:
            db.execute("BEGIN")
            ids = [row["id"] for row in db.execute("SELECT id FROM advisory_watches ORDER BY created_at,id")]
            return [self._get(db, watch_id) for watch_id in ids]

    def get(self, watch_id: str) -> dict:
        with self.cases.store._connect() as db:
            db.execute("BEGIN")
            return self._get(db, watch_id)

    def _get(self, db, watch_id: str) -> dict:
        row = db.execute("SELECT * FROM advisory_watches WHERE id=?", (watch_id,)).fetchone()
        if not row:
            raise CaseNotFound(f"advisory watch not found: {watch_id}")
        result = dict(row)
        result["simulated"] = bool(result["simulated"])
        result["inventory"] = json.loads(result.pop("inventory_json"))
        result["coverage"] = json.loads(result.pop("coverage_json"))
        result["stale"] = bool(result["last_error"])
        result["case_count"] = db.execute(
            "SELECT COUNT(*) FROM advisory_cases WHERE watch_id=?", (watch_id,)
        ).fetchone()[0]
        result["evidence_count"] = db.execute(
            "SELECT COUNT(*) FROM advisory_evidence WHERE watch_id=?", (watch_id,)
        ).fetchone()[0]
        return result

    def refresh(self, watch_id: str | None = None, replay: dict | None = None) -> list[dict]:
        with self.cases.store._connect() as db:
            rows = list(db.execute(
                "SELECT * FROM advisory_watches" + (" WHERE id=?" if watch_id else "") + " ORDER BY id",
                (watch_id,) if watch_id else (),
            ))
        if watch_id and not rows:
            raise CaseNotFound(f"advisory watch not found: {watch_id}")
        if replay is not None and len(rows) != 1:
            raise CaseError("deterministic replay requires one watch_id")
        results = []
        for row in rows:
            try:
                if replay is not None and not bool(row["simulated"]):
                    raise CaseError("deterministic replay requires a simulated watch")
                self._refresh_one(dict(row), replay)
            except CaseError:
                raise
            except Exception as exc:
                self._mark_stale(row["id"], exc)
            results.append(self.get(row["id"]))
        return results

    def _refresh_one(self, watch: dict, replay: dict | None) -> None:
        inventory = json.loads(watch["inventory_json"])
        purls = [component["purl"] for component in inventory]
        observed_at = self.now()
        if replay is None:
            feeds = self.feeds_factory()
            try:
                raw_hits = feeds.query_purls(purls)
                hits, coverage = self._feed_result(raw_hits, feeds, purls)
                advisory_ids = sorted({item for ids in hits.values() for item in ids})
                advisories = {advisory_id: feeds.vuln_detail(advisory_id) for advisory_id in advisory_ids}
            finally:
                feeds.close()
            source = "live"
        else:
            if not isinstance(replay, dict) or not isinstance(replay.get("hits"), dict) or not isinstance(replay.get("advisories"), list):
                raise CaseError("replay requires hits object and advisories array")
            hits = {purl: sorted(map(str, replay["hits"].get(purl, []))) for purl in purls}
            advisories = {str(item.get("id")): item for item in replay["advisories"] if isinstance(item, dict) and item.get("id")}
            missing = {item for ids in hits.values() for item in ids} - advisories.keys()
            if missing:
                raise CaseError("replay is missing advisory detail: " + ", ".join(sorted(missing)))
            coverage = self._coverage(replay.get("coverage"), "replay")
            source = "simulated_replay"
        findings = findings_from_advisories(inventory, hits, advisories, observed_at)
        by_advisory: dict[str, list[dict]] = {}
        for finding in findings:
            by_advisory.setdefault(finding.osv_id, []).append(finding.as_dict())
        with self.cases.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for advisory_id in sorted(by_advisory):
                advisory = advisories[advisory_id]
                identity = canonical_identity(advisory_id, advisory)
                candidates = sorted(by_advisory[advisory_id], key=lambda item: (item["purl"], item["cve"]))
                known = db.execute(
                    "SELECT case_id FROM advisory_cases WHERE watch_id=? AND advisory_identity=?",
                    (watch["id"], identity),
                ).fetchone()
                if not known:
                    prior = db.execute(
                        """SELECT ac.advisory_identity,ac.case_id FROM advisory_evidence ae
                           JOIN advisory_cases ac ON ac.watch_id=ae.watch_id AND ac.advisory_identity=ae.advisory_identity
                           WHERE ae.watch_id=? AND json_extract(ae.payload_json,'$.source_advisory_id')=? LIMIT 1""",
                        (watch["id"], advisory_id),
                    ).fetchone()
                    if prior:
                        identity, known = prior["advisory_identity"], prior
                finding = {**candidates[0], "cve": identity}
                evidence = {
                    "advisory_identity": identity,
                    "source_advisory_id": advisory_id,
                    "affected_purls": sorted({item["purl"] for item in candidates}),
                    "advisory": advisory,
                    "coverage": coverage,
                    "source_type": source,
                    "simulated": bool(watch["simulated"]),
                }
                evidence_hash = hashlib.sha256(_json(evidence).encode()).hexdigest()
                inserted = db.execute(
                    "INSERT OR IGNORE INTO advisory_evidence VALUES(?,?,?,?,?)",
                    (watch["id"], identity, evidence_hash, observed_at, _json(evidence)),
                ).rowcount
                if known:
                    if inserted:
                        self.cases.store._event(db, known["case_id"], "advisory_evidence_added", observed_at, "PandaX advisory refresh", evidence)
                        db.execute("UPDATE remediation_cases SET version=version+1,updated_at=? WHERE id=?", (observed_at, known["case_id"]))
                    continue
                case = self.cases.store.create(watch["run_id"], finding, db=db, simulated=bool(watch["simulated"]))
                self.cases.link_run(db, case["id"], watch["run_id"], "source")
                db.execute("INSERT INTO advisory_cases VALUES(?,?,?)", (watch["id"], identity, case["id"]))
                state = dict(case["state"])
                state.setdefault("detected_at", observed_at)
                state.setdefault("aware_at", observed_at)
                state.setdefault("awareness_evidence", f"{source} advisory {identity}")
                state.setdefault("reportability", "under_review")
                state["advisory_watch_id"] = watch["id"]
                from .case_workflow import persist_clocks
                persist_clocks(self.cases, db, case, state)
                self.cases.store._event(db, case["id"], "advisory_detected", observed_at, "PandaX advisory refresh", evidence)
                event_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                db.execute("INSERT INTO awareness_evidence(case_id,event_id,payload_json) VALUES(?,?,?)", (case["id"], event_id, _json(evidence)))
                db.execute("UPDATE remediation_cases SET version=version+1,updated_at=? WHERE id=?", (observed_at, case["id"]))
            db.execute(
                """UPDATE advisory_watches SET last_attempt_at=?,last_success_at=?,stale_since=NULL,
                   last_error=NULL,coverage_json=? WHERE id=?""",
                (observed_at, observed_at, _json(coverage), watch["id"]),
            )

    @staticmethod
    def _feed_result(raw_hits, feeds, purls: list[str]) -> tuple[dict[str, list[str]], dict]:
        if isinstance(raw_hits, dict) and isinstance(raw_hits.get("results"), dict):
            hits = raw_hits["results"]
            metadata = raw_hits.get("coverage")
        elif isinstance(raw_hits, dict):
            hits = raw_hits
            metadata = raw_hits.get("coverage")
        else:
            raise ValueError("advisory feed returned invalid query results")
        if metadata is None:
            metadata = getattr(feeds, "coverage", None)
            metadata = metadata() if callable(metadata) else metadata
        normalized = {purl: sorted(map(str, hits.get(purl, []))) for purl in purls}
        return normalized, AdvisoryWatchService._coverage(metadata, "live")

    @staticmethod
    def _coverage(metadata, source: str) -> dict:
        if isinstance(metadata, dict):
            return {"source": source, "status": str(metadata.get("status", "reported")), **metadata}
        return {
            "source": source,
            "status": "bounded_unknown",
            "statement": "Advisory source returned no coverage metadata; retained results are not proof of absence.",
        }

    def _mark_stale(self, watch_id: str, exc: Exception) -> None:
        now = self.now()
        with self.cases.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """UPDATE advisory_watches SET last_attempt_at=?,stale_since=COALESCE(stale_since,?),
                   last_error=? WHERE id=?""",
                (now, now, f"{type(exc).__name__}: {exc}", watch_id),
            )


class AdvisoryRefreshLoop:
    def __init__(self, service_factory: Callable[[], AdvisoryWatchService], interval_seconds: float = 3600):
        self.service_factory = service_factory
        self.interval_seconds = interval_seconds
        self.stopped = threading.Event()
        self.lock = threading.Lock()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.stopped.clear()
        self.thread = threading.Thread(target=self._run, name="pandax-advisory-refresh", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        self.refresh_now()
        while not self.stopped.wait(self.interval_seconds):
            self.refresh_now()

    def refresh_now(self) -> list[dict]:
        with self.lock:
            return self.service_factory().refresh()

    def stop(self) -> None:
        self.stopped.set()
        if self.thread:
            self.thread.join(timeout=5)
            self.thread = None
