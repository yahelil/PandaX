from pathlib import Path
from subprocess import CompletedProcess

from typer.testing import CliRunner

from pandax import cli


def test_serve_launches_dashboard_workspace(monkeypatch, tmp_path: Path):
    dashboard = tmp_path / "apps" / "dashboard"
    dashboard.mkdir(parents=True)
    (dashboard / "package.json").write_text("{}", encoding="utf-8")
    calls = []

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli.shutil, "which", lambda name: "npm.cmd")
    monkeypatch.setattr(cli, "_is_port_in_use", lambda host, port: True)
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda command, **options: calls.append((command, options)) or CompletedProcess(command, 0),
    )

    result = CliRunner().invoke(cli.app, ["serve", "--host", "0.0.0.0", "--port", "4310"])

    assert result.exit_code == 0
    assert "Actis engine backend is already running" in result.output
    assert calls == [
        (
            ["npm.cmd", "run", "dev", "--workspace", "@pandax/dashboard", "--", "--host", "0.0.0.0", "--port", "4310"],
            {"cwd": tmp_path, "check": False},
        )
    ]


def test_serve_starts_backend_when_not_running(monkeypatch, tmp_path: Path):
    dashboard = tmp_path / "apps" / "dashboard"
    dashboard.mkdir(parents=True)
    (dashboard / "package.json").write_text("{}", encoding="utf-8")
    popen_calls = []
    run_calls = []

    class DummyProc:
        def __init__(self):
            self.terminated = False

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            return 0

    proc = DummyProc()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli.shutil, "which", lambda name: "npm.cmd")
    monkeypatch.setattr(cli, "_is_port_in_use", lambda host, port: False)
    monkeypatch.setattr(
        cli.subprocess,
        "Popen",
        lambda command, **options: popen_calls.append((command, options)) or proc,
    )
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda command, **options: run_calls.append((command, options)) or CompletedProcess(command, 0),
    )

    result = CliRunner().invoke(cli.app, ["serve", "--host", "0.0.0.0", "--port", "4310"])

    assert result.exit_code == 0
    assert "Starting Actis engine backend" in result.output
    assert len(popen_calls) == 1
    assert "uvicorn" in popen_calls[0][0]
    assert proc.terminated is True


def test_serve_reports_missing_npm(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)

    result = CliRunner().invoke(cli.app, ["serve"])

    assert result.exit_code == 1
    assert "npm was not found" in result.output
