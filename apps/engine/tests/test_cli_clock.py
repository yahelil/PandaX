from __future__ import annotations

import datetime as dt
import json

import pytest
from rich.console import Console
from typer.testing import CliRunner

from pandax import cli
from pandax.stages import clock
from pandax.verdict import build_verdict


NOW = dt.datetime(2026, 9, 8, 12, tzinfo=dt.timezone.utc)


@pytest.fixture(autouse=True)
def fixed_time(monkeypatch):
    class FixedDatetime(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW.astimezone(tz) if tz else NOW.replace(tzinfo=None)

    monkeypatch.setattr(dt, "datetime", FixedDatetime)


@pytest.mark.parametrize("command", ["clock", "verdict"])
@pytest.mark.parametrize("final_date", ["missing", None])
def test_pending_final_report_cli(ctx, monkeypatch, command, final_date):
    list(clock.run(ctx))
    if final_date is None:
        ctx.incidents[0]["deadlines"]["final_report"] = None
        (ctx.run_dir / "incidents.json").write_text(json.dumps(ctx.incidents), encoding="utf-8")
    (ctx.run_dir / "dossier.json").write_text(
        json.dumps({"product": {}, "summary": {"required_input": 1}}), encoding="utf-8"
    )
    monkeypatch.setattr(cli, "console", Console(width=180, color_system=None))

    result = CliRunner().invoke(cli.app, [command, str(ctx.run_dir)])

    assert result.exit_code == (2 if command == "verdict" else 0), repr(result.exception)
    assert "Awaiting corrective measure availability" in " ".join(result.stdout.split())


@pytest.mark.parametrize("command", ["clock", "verdict"])
@pytest.mark.parametrize(
    "final_date,expected",
    [
        ("2026-09-09T15:30:00+03:00", "24h 30m"),
        ("2026-09-08T07:00:00Z", "OVERDUE"),
        ("2026-09-08T12:00:00Z", "OVERDUE"),
        ("2026-09-09T12:30:00", "24h 30m"),
    ],
)
def test_saved_final_report_cli(ctx, monkeypatch, command, final_date, expected):
    list(clock.run(ctx))
    # Historical bundles may contain a final deadline without a trigger field.
    ctx.incidents[0]["deadlines"]["final_report"] = final_date
    path = ctx.run_dir / "incidents.json"
    path.write_text(json.dumps(ctx.incidents), encoding="utf-8")
    (ctx.run_dir / "dossier.json").write_text('{"product": {}}', encoding="utf-8")
    before = path.read_bytes()
    monkeypatch.setattr(cli, "console", Console(width=180, color_system=None))

    result = CliRunner().invoke(cli.app, [command, str(ctx.run_dir)])

    assert result.exit_code == 0, repr(result.exception)
    assert expected in result.stdout
    assert "Awaiting" not in result.stdout
    assert path.read_bytes() == before


def test_deadlines_use_measure_availability_and_sort_pending_last():
    available = NOW + dt.timedelta(days=5)
    due = clock.deadlines(NOW, available)
    assert due["final_report"] == "2026-09-27T12:00:00Z"
    assert clock.remaining_seconds(due["final_report"], NOW) == 19 * 86400
    assert clock.remaining_seconds(None, NOW) is None
    incidents = [
        {"cve": "pending", "deadlines": clock.deadlines(NOW)},
        {"cve": "known", "deadlines": due},
    ]
    rows = build_verdict([], incidents, {}).as_dict()["deadlines"]
    assert rows[-1]["due"] is None
    assert rows[-2]["due"] == due["final_report"]
    # Offset spellings sort by actual instant, not by their strings.
    assert clock.deadline_sort_key("2026-09-08T14:00:00+03:00") < clock.deadline_sort_key(
        "2026-09-08T12:00:00Z"
    )


def test_demo_clock_does_not_modify_evidence(ctx, monkeypatch):
    ctx.clock_speed = 3600
    list(clock.run(ctx))
    incident = ctx.incidents[0]
    incident["aware_at"] = "2026-09-08T11:59:30Z"
    incident["deadlines"] = clock.deadlines(clock.parse_timestamp(incident["aware_at"]))
    (ctx.run_dir / "incidents.json").write_text(json.dumps(ctx.incidents), encoding="utf-8")
    before = {p: p.read_bytes() for p in ctx.run_dir.rglob("*") if p.is_file()}
    monkeypatch.setattr(cli, "console", Console(width=180, color_system=None))

    runner = CliRunner()
    real = runner.invoke(cli.app, ["clock", str(ctx.run_dir)])
    demo = runner.invoke(cli.app, ["clock", str(ctx.run_dir), "--speed", "3600"])

    assert real.exit_code == demo.exit_code == 0
    assert "OVERDUE" not in real.stdout
    assert "OVERDUE 6h" in demo.stdout
    assert "demo clock" in demo.stdout
    assert "Awaiting corrective measure availability" in " ".join(demo.stdout.split())
    assert {p: p.read_bytes() for p in ctx.run_dir.rglob("*") if p.is_file()} == before
    filing = json.loads((ctx.run_dir / "filings/CVE-2021-44228/early_warning.json").read_text())
    assert filing["due_by"] == "2026-09-09T12:00:00Z"


def test_empty_incident_list_supports_demo_clock(tmp_path):
    (tmp_path / "incidents.json").write_text("[]", encoding="utf-8")
    result = CliRunner().invoke(cli.app, ["clock", str(tmp_path), "--speed", "3600"])
    assert result.exit_code == 0, repr(result.exception)


@pytest.mark.parametrize("final_date", [None, "2026-09-09T12:00:00Z"])
def test_dashboard_summary_preserves_pending_and_known_dates(ctx, monkeypatch, final_date):
    from fastapi.testclient import TestClient
    from pandax import server

    list(clock.run(ctx))
    if final_date:
        ctx.incidents[0]["deadlines"]["final_report"] = final_date
        (ctx.run_dir / "incidents.json").write_text(json.dumps(ctx.incidents), encoding="utf-8")
    monkeypatch.setattr(server, "OUT_DIR", ctx.run_dir.parent)

    response = TestClient(server.api).get(f"/api/run/{ctx.run_dir.name}/summary")

    assert response.status_code == 200
    payload = response.json()
    final = [r for r in payload["verdict"]["deadlines"] if r["article"] == "Art.14(2)(c)"]
    assert final[0]["due"] == final_date
    assert payload["incidents"][0]["deadlines"].get("final_report") == final_date
