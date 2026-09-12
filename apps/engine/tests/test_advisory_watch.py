import json
import threading
import time

from pandax.advisory_watch import AdvisoryRefreshLoop, AdvisoryWatchService
from pandax.case_service import CaseService


ADVISORY = {
    "id": "GHSA-demo",
    "aliases": ["CVE-2026-1000"],
    "summary": "New remote execution evidence",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{
        "package": {"purl": "pkg:npm/demo@1.0.0"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.0.1"}]}],
    }],
}


class FakeFeeds:
    def __init__(self, advisory=None, fail=False):
        self.advisory = advisory or ADVISORY
        self.fail = fail
        self.closed = False

    def query_purls(self, purls):
        if self.fail:
            raise RuntimeError("source offline")
        return {purl: [self.advisory["id"]] for purl in purls}

    def vuln_detail(self, advisory_id):
        return self.advisory

    def close(self):
        self.closed = True


def setup_service(tmp_path, feed):
    run = tmp_path / "run-source"
    run.mkdir()
    (run / "dossier.json").write_text(json.dumps({
        "product": {"name": "Demo Device", "version": "1.0"},
        "generated": "2026-09-01T00:00:00Z",
    }))
    (run / "sbom.cdx.json").write_text(json.dumps({"components": [
        {"name": "demo", "version": "1.0.0", "purl": "pkg:npm/demo@1.0.0", "bom-ref": "demo-1"},
        {"name": "helper", "version": "2.0.0", "purl": "pkg:npm/helper@2.0.0", "bom-ref": "helper-2"},
    ]}))
    cases = CaseService(data_dir=tmp_path / "data", runs_dir=tmp_path)
    return AdvisoryWatchService(cases, lambda: feed, now=lambda: "2026-09-12T12:00:00Z")


def test_refresh_deduplicates_across_repeats_and_restart(tmp_path):
    feed = FakeFeeds()
    watcher = setup_service(tmp_path, feed)
    watch = watcher.watch("run-source")
    watcher.refresh(watch["id"])
    watcher.refresh(watch["id"])

    reopened = AdvisoryWatchService(
        CaseService(data_dir=tmp_path / "data", runs_dir=tmp_path),
        lambda: FakeFeeds(),
        now=lambda: "2026-09-13T12:00:00Z",
    )
    reopened.refresh(watch["id"])
    status = reopened.get(watch["id"])
    cases = reopened.cases.list()
    assert status["case_count"] == status["evidence_count"] == len(cases) == 1
    assert cases[0]["state"]["aware_at"] == "2026-09-12T12:00:00Z"
    assert cases[0]["state"]["reportability"] == "under_review"
    assert [event["event_type"] for event in cases[0]["events"]].count("advisory_detected") == 1


def test_new_evidence_appends_and_outage_preserves_results(tmp_path):
    feed = FakeFeeds()
    watcher = setup_service(tmp_path, feed)
    watch_id = watcher.watch("run-source")["id"]
    watcher.refresh(watch_id)
    case = watcher.cases.list()[0]
    feed.advisory = {**ADVISORY, "summary": "Expanded technical evidence"}
    watcher.refresh(watch_id)
    updated = watcher.cases.get(case["id"])
    assert updated["state"]["aware_at"] == case["state"]["aware_at"]
    assert [event["event_type"] for event in updated["events"]].count("advisory_evidence_added") == 1
    assert watcher.get(watch_id)["evidence_count"] == 2

    reviewed = watcher.cases.execute("record-decision", {
        "request_id": "review", "expected_version": updated["version"],
        "operator": "Yaheli", "authority_attestation": "Authorised",
        "reportability": "under_review", "reason": "Needs assessment", "evidence": "Reviewed advisory",
    }, case["id"])
    watcher.refresh(watch_id)
    assert watcher.cases.get(case["id"])["state"]["aware_at"] == reviewed["state"]["aware_at"]

    feed.fail = True
    watcher.refresh(watch_id)
    stale = watcher.get(watch_id)
    assert stale["stale"] is True
    assert stale["case_count"] == 1
    assert stale["evidence_count"] == 2
    assert stale["last_success_at"] == "2026-09-12T12:00:00Z"
    assert stale["coverage"]["status"] == "bounded_unknown"


def test_deterministic_replay_is_labeled_simulated(tmp_path):
    watcher = setup_service(tmp_path, FakeFeeds(fail=True))
    watch_id = watcher.watch("run-source", simulated=True)["id"]
    replay = {
        "hits": {"pkg:npm/demo@1.0.0": ["GHSA-demo"]},
        "advisories": [ADVISORY],
        "coverage": {"status": "complete_fixture", "fixture": "card-18"},
    }
    watcher.refresh(watch_id, replay)
    watcher.refresh(watch_id, replay)
    case = watcher.cases.list()[0]
    assert case["state"]["simulated"] is True
    assert len(watcher.cases.list()) == 1
    assert all(event["payload"]["simulated"] is True for event in case["events"])
    detected = next(event for event in case["events"] if event["event_type"] == "advisory_detected")
    assert detected["payload"]["source_type"] == "simulated_replay"


def test_background_loop_catches_up_and_stops():
    called = threading.Event()

    class Recorder:
        def __init__(self):
            self.calls = 0

        def refresh(self):
            self.calls += 1
            called.set()
            return []

    recorder = Recorder()
    loop = AdvisoryRefreshLoop(lambda: recorder, interval_seconds=0.01)
    loop.start()
    thread = loop.thread
    assert called.wait(1)
    time.sleep(0.03)
    loop.stop()
    count = recorder.calls
    time.sleep(0.03)
    assert count >= 2
    assert recorder.calls == count
    assert thread is not None and not thread.is_alive()
