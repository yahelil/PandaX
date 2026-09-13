from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from fastapi.testclient import TestClient

from pandax.monitoring import MonitoringStore, ScanExecutionError


NOW = dt.datetime(2026, 9, 11, 8, 0, tzinfo=dt.timezone.utc)


def _write_run(
    base: Path,
    name: str,
    findings: list[dict] | None = None,
    source_status: str = "completed",
) -> Path:
    run = base / name
    run.mkdir(parents=True)
    (run / "findings.json").write_text(json.dumps(findings or []), encoding="utf-8")
    (run / "coverage.json").write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "source": "OSV.dev",
                        "source_url": "https://api.osv.dev/v1/querybatch",
                        "status": source_status,
                        "checked_at": "2026-09-11T08:00:00Z",
                        "reason": "source failed" if source_status == "failed" else "checked",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (run / "triage-coverage.json").write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "source": "CISA Known Exploited Vulnerabilities",
                        "source_url": "https://www.cisa.gov/kev.json",
                        "status": "completed",
                        "checked_at": "2026-09-11T08:00:00Z",
                        "reason": "checked",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return run


def _finding(**changes) -> dict:
    result = {
        "cve": "CVE-2026-1000",
        "purl": "pkg:npm/example@1.0.0",
        "component": "example",
        "version": "1.0.0",
        "severity": "HIGH",
        "fixed_version": "1.0.1",
        "kev": False,
        "affectedness": "affected",
        "reachability": "unknown",
        "source_url": "https://osv.dev/vulnerability/CVE-2026-1000",
    }
    result.update(changes)
    return result


def test_due_schedule_and_saved_source_freshness(tmp_path):
    source = tmp_path / "product.zip"
    source.write_bytes(b"product")
    store = MonitoringStore(tmp_path / "data" / "monitoring.sqlite3")
    policy = store.add_policy("Product A", source, interval_minutes=60, now=NOW)
    bundle = _write_run(tmp_path, "run-first", [_finding()])

    results = store.run_due(runner=lambda policy, out: bundle, now=NOW)

    assert len(results) == 1
    assert results[0]["status"] == "completed"
    assert results[0]["coverage_state"] == "complete"
    assert results[0]["source_checks"][0]["checked_at"] == "2026-09-11T08:00:00Z"
    saved = store.get_policy(policy["id"])
    assert saved["next_due_at"] == "2026-09-11T09:00:00Z"
    assert store.run_due(runner=lambda policy, out: bundle, now=NOW) == []


def test_unchanged_findings_do_not_create_duplicate_alerts(tmp_path):
    source = tmp_path / "product.zip"
    source.write_bytes(b"product")
    store = MonitoringStore(tmp_path / "monitoring.sqlite3")
    policy = store.add_policy("Product A", source, now=NOW)
    first = _write_run(tmp_path, "run-first", [_finding()])
    second = _write_run(tmp_path, "run-second", [_finding()])

    store.run_policy(policy["id"], runner=lambda policy, out: first, now=NOW)
    store.run_policy(
        policy["id"], runner=lambda policy, out: second,
        now=NOW + dt.timedelta(hours=1),
    )

    assert [alert["kind"] for alert in store.list_alerts()] == ["new_finding"]
    assert store.get_policy(policy["id"])["active_findings"] == 1


def test_changed_resolved_and_reappearing_findings_are_each_alerted(tmp_path):
    source = tmp_path / "product.zip"
    source.write_bytes(b"product")
    store = MonitoringStore(tmp_path / "monitoring.sqlite3")
    policy = store.add_policy("Product A", source, now=NOW)
    bundles = [
        _write_run(tmp_path, "run-1", [_finding()]),
        _write_run(tmp_path, "run-2", [_finding(severity="CRITICAL")]),
        _write_run(tmp_path, "run-3", []),
        _write_run(tmp_path, "run-4", [_finding(severity="CRITICAL")]),
    ]
    for index, bundle in enumerate(bundles):
        store.run_policy(
            policy["id"], runner=lambda policy, out, bundle=bundle: bundle,
            now=NOW + dt.timedelta(hours=index),
        )

    kinds = [alert["kind"] for alert in reversed(store.list_alerts())]
    assert kinds == [
        "new_finding", "finding_changed", "finding_no_longer_detected",
        "finding_reappeared",
    ]


def test_incomplete_check_never_resolves_a_finding_or_repeats_failure_alert(tmp_path):
    source = tmp_path / "product.zip"
    source.write_bytes(b"product")
    store = MonitoringStore(tmp_path / "monitoring.sqlite3")
    policy = store.add_policy("Product A", source, now=NOW)
    complete = _write_run(tmp_path, "run-complete", [_finding()])
    failed_1 = _write_run(tmp_path, "run-failed-1", [], source_status="failed")
    failed_2 = _write_run(tmp_path, "run-failed-2", [], source_status="failed")
    recovered = _write_run(tmp_path, "run-recovered", [])

    for index, bundle in enumerate((complete, failed_1, failed_2)):
        store.run_policy(
            policy["id"], runner=lambda policy, out, bundle=bundle: bundle,
            now=NOW + dt.timedelta(hours=index),
        )
    assert store.get_policy(policy["id"])["active_findings"] == 1
    kinds = [alert["kind"] for alert in store.list_alerts()]
    assert kinds.count("source_failure") == 1
    assert kinds.count("monitoring_incomplete") == 1
    assert "finding_no_longer_detected" not in kinds

    store.run_policy(
        policy["id"], runner=lambda policy, out: recovered,
        now=NOW + dt.timedelta(hours=3),
    )
    recovered_kinds = [alert["kind"] for alert in store.list_alerts()]
    assert "source_recovered" in recovered_kinds
    assert "monitoring_recovered" in recovered_kinds
    assert "finding_no_longer_detected" in recovered_kinds


def test_pipeline_stop_with_source_evidence_is_reported_as_incomplete(tmp_path):
    source = tmp_path / "product.zip"
    source.write_bytes(b"product")
    store = MonitoringStore(tmp_path / "monitoring.sqlite3")
    policy = store.add_policy("Product A", source, now=NOW)
    partial_run = _write_run(tmp_path, "run-source-failed", [], source_status="failed")

    def stopped(policy, out):
        raise ScanExecutionError("OSV could not be refreshed", partial_run)

    result = store.run_policy(policy["id"], runner=stopped, now=NOW)

    assert result["status"] == "incomplete"
    assert result["coverage_state"] == "incomplete"
    assert {alert["kind"] for alert in store.list_alerts()} == {
        "monitoring_incomplete", "source_failure",
    }


def test_missing_registered_source_is_a_deduplicated_monitoring_failure(tmp_path):
    source = tmp_path / "product.zip"
    source.write_bytes(b"product")
    store = MonitoringStore(tmp_path / "monitoring.sqlite3")
    policy = store.add_policy("Product A", source, now=NOW)
    source.unlink()

    first = store.run_policy(policy["id"], now=NOW)
    second = store.run_policy(policy["id"], now=NOW + dt.timedelta(hours=1))

    assert first["status"] == second["status"] == "failed"
    assert [alert["kind"] for alert in store.list_alerts()] == ["monitoring_failed"]


def test_monitoring_api_registers_and_lists_policies(tmp_path, monkeypatch):
    from pandax import server

    source = tmp_path / "product.zip"
    source.write_bytes(b"product")
    store = MonitoringStore(tmp_path / "monitoring.sqlite3")
    monkeypatch.setattr(server, "_monitor_store", lambda: store)
    client = TestClient(server.api)

    created = client.post(
        "/api/monitoring/policies",
        json={"name": "Product A", "source": str(source), "interval_minutes": 30},
    )

    assert created.status_code == 200
    assert created.json()["next_due_at"]
    assert client.get("/api/monitoring/policies").json()[0]["name"] == "Product A"
    assert client.post("/api/monitoring/policies", json={"name": "missing"}).status_code == 400


def test_monitoring_cli_registers_and_lists_a_source(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from pandax import cli

    source = tmp_path / "product.zip"
    source.write_bytes(b"product")
    monkeypatch.setenv("PANDAX_DATA_DIR", str(tmp_path / "data"))
    runner = CliRunner()

    created = runner.invoke(
        cli.app,
        ["monitor", "add", "Product A", str(source), "--every-minutes", "30"],
    )
    listed = runner.invoke(cli.app, ["monitor", "list"])

    assert created.exit_code == 0, repr(created.exception)
    assert listed.exit_code == 0, repr(listed.exception)
    assert "Product A" in listed.stdout
    assert "next_due_at" in listed.stdout
