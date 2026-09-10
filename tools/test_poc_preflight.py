"""Preflight checker tests.

Every external tool is mocked, so this file passes on a machine with neither
Docker nor veraPDF installed — which is the point: the checker exists to report
a missing tool, so its tests cannot require that tool to be present.

Run:  uv run pytest tools/test_poc_preflight.py
"""

import importlib.metadata
import shutil
import subprocess
from pathlib import Path

import poc_preflight


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


def responder(responses, calls=None):
    """Answer a probe by matching the executable name, not the whole path.

    tmp_path embeds the test name, so matching on the full path would let a
    directory called .../test_docker_.../syft answer as Docker.
    """
    def run(argv, **kwargs):
        if calls is not None:
            calls.append(argv)
        for key, value in responses.items():
            if key in Path(argv[0]).name:
                if isinstance(value, Exception):
                    raise value
                return value
        raise FileNotFoundError(argv[0])
    return run


def install_syft(monkeypatch, tmp_path, name="syft"):
    """Put a pinned syft where find_syft() looks for it."""
    tools = tmp_path / ".tools"
    tools.mkdir(parents=True, exist_ok=True)
    binary = tools / name
    binary.write_text("")
    monkeypatch.setattr(poc_preflight, "TOOLS_DIR", tools)
    return binary


def healthy(monkeypatch, tmp_path, calls=None, **extra):
    """A machine where the default checks all hold."""
    install_syft(monkeypatch, tmp_path)
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "0.1.0")
    responses = {"syft": completed(stdout="syft 1.51.1")}
    responses.update(extra)
    monkeypatch.setattr(subprocess, "run", responder(responses, calls))


def test_default_run_passes_and_exits_zero(monkeypatch, tmp_path, capsys):
    healthy(monkeypatch, tmp_path)

    assert poc_preflight.main([]) == 0

    out = capsys.readouterr().out
    assert "FAIL" not in out
    assert "All 3 checks passed." in out


def test_unrequested_optional_tools_are_never_probed(monkeypatch, tmp_path, capsys):
    """A machine with no Docker and no veraPDF still passes a default run."""
    calls = []
    healthy(monkeypatch, tmp_path, calls)
    monkeypatch.setattr(shutil, "which", lambda name: None)

    assert poc_preflight.main([]) == 0

    out = capsys.readouterr().out
    assert "Docker" not in out
    assert "veraPDF" not in out
    assert all(Path(argv[0]).name != "docker" for argv in calls)


def test_missing_syft_fails_with_the_bootstrap_remedy(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(poc_preflight, "TOOLS_DIR", tmp_path / "empty")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "0.1.0")

    assert poc_preflight.main([]) == 1

    out = capsys.readouterr().out
    assert "FAIL  Syft" in out
    assert "tools/bootstrap.py" in out


def test_syft_on_path_is_accepted_when_tools_dir_is_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(poc_preflight, "TOOLS_DIR", tmp_path / "empty")
    monkeypatch.setattr(shutil, "which",
                        lambda name: "/usr/local/bin/syft" if name == "syft" else None)
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "0.1.0")
    monkeypatch.setattr(subprocess, "run",
                        responder({"syft": completed(stdout="syft 1.51.1")}))

    assert poc_preflight.main([]) == 0


def test_missing_pandax_package_fails_readably(monkeypatch, tmp_path, capsys):
    install_syft(monkeypatch, tmp_path)
    monkeypatch.setattr(subprocess, "run",
                        responder({"syft": completed(stdout="syft 1.51.1")}))

    def absent(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", absent)

    assert poc_preflight.main([]) == 1

    out = capsys.readouterr().out
    assert "FAIL  pandax package" in out
    assert "uv sync" in out


def test_docker_missing_from_path_fails_only_under_firmware(monkeypatch, tmp_path, capsys):
    healthy(monkeypatch, tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name: None)

    assert poc_preflight.main(["--firmware"]) == 1

    out = capsys.readouterr().out
    assert "FAIL  Docker" in out
    assert "docker not on PATH" in out


def test_docker_daemon_unreachable_is_reported_as_such(monkeypatch, tmp_path, capsys):
    healthy(monkeypatch, tmp_path,
            **{"docker": completed(returncode=1, stderr="Cannot connect to the Docker daemon")})
    monkeypatch.setattr(shutil, "which",
                        lambda name: "/usr/bin/docker" if name == "docker" else None)

    assert poc_preflight.main(["--firmware"]) == 1

    out = capsys.readouterr().out
    assert "FAIL  Docker" in out
    assert "daemon unreachable (exited 1)" in out
    assert "Traceback" not in out


def test_docker_probe_never_pulls_an_image(monkeypatch, tmp_path):
    calls = []
    healthy(monkeypatch, tmp_path, calls,
            **{"docker": completed(stdout="27.1.1")})
    monkeypatch.setattr(shutil, "which",
                        lambda name: "/usr/bin/docker" if name == "docker" else None)

    assert poc_preflight.main(["--firmware"]) == 0

    docker_calls = [argv for argv in calls if Path(argv[0]).name == "docker"]
    assert docker_calls == [["/usr/bin/docker", "info", "--format", "{{.ServerVersion}}"]]


def test_verapdf_missing_fails_only_under_pdf(monkeypatch, tmp_path, capsys):
    healthy(monkeypatch, tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name: None)

    assert poc_preflight.main([]) == 0
    assert poc_preflight.main(["--pdf"]) == 1

    out = capsys.readouterr().out
    assert "FAIL  veraPDF" in out
    assert "--verapdf PATH" in out


def test_explicit_verapdf_path_that_does_not_exist_fails(monkeypatch, tmp_path, capsys):
    healthy(monkeypatch, tmp_path)
    missing = tmp_path / "nowhere" / "verapdf"

    assert poc_preflight.main(["--pdf", "--verapdf", str(missing)]) == 1

    assert f"not found: {missing}" in capsys.readouterr().out


def test_explicit_verapdf_path_is_used_instead_of_path_lookup(monkeypatch, tmp_path):
    calls = []
    healthy(monkeypatch, tmp_path, calls,
            **{"verapdf": completed(stdout="veraPDF 1.26.2")})
    monkeypatch.setattr(shutil, "which", lambda name: None)
    binary = tmp_path / "verapdf"
    binary.write_text("")

    assert poc_preflight.main(["--pdf", "--verapdf", str(binary)]) == 0
    assert [str(binary), "--version"] in calls


def test_a_tool_path_containing_spaces_is_passed_as_one_argument(monkeypatch, tmp_path):
    """Argument arrays, never shell=True: spaces are a path, not a separator."""
    calls = []
    spaced = tmp_path / "Program Files" / "veraPDF"
    spaced.mkdir(parents=True)
    binary = spaced / "verapdf.bat"
    binary.write_text("")
    healthy(monkeypatch, tmp_path, calls,
            **{"verapdf": completed(stdout="veraPDF 1.26.2")})
    monkeypatch.setattr(shutil, "which",
                        lambda name: str(binary) if name == "verapdf" else None)

    assert poc_preflight.main(["--pdf"]) == 0
    assert [str(binary), "--version"] in calls
    assert " " in str(binary)


def test_syft_installed_at_a_path_with_spaces_is_found(monkeypatch, tmp_path):
    root = tmp_path / "My Projects" / "PandaX"
    root.mkdir(parents=True)
    binary = install_syft(monkeypatch, root)
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "0.1.0")
    calls = []
    monkeypatch.setattr(subprocess, "run",
                        responder({"syft": completed(stdout="syft 1.51.1")}, calls))

    assert poc_preflight.main([]) == 0
    assert [str(binary), "--version"] in calls


def test_a_timeout_fails_the_check_without_a_traceback(monkeypatch, tmp_path, capsys):
    healthy(monkeypatch, tmp_path,
            **{"syft": subprocess.TimeoutExpired(cmd="syft", timeout=10)})

    assert poc_preflight.main([]) == 1

    out = capsys.readouterr().out
    assert "no answer within 10s" in out
    assert "Traceback" not in out


def test_probe_timeout_is_ten_seconds(monkeypatch):
    seen = {}

    def run(argv, **kwargs):
        seen.update(kwargs)
        return completed(stdout="ok")

    monkeypatch.setattr(subprocess, "run", run)
    poc_preflight.probe(["tool", "--version"])

    assert seen["timeout"] == 10
    assert seen.get("shell") is not True


def test_probe_reports_a_missing_executable_rather_than_raising(monkeypatch):
    monkeypatch.setattr(subprocess, "run", responder({}))

    result = poc_preflight.probe(["/nowhere/tool", "--version"])

    assert result.ok is False
    assert "not found" in result.error


def test_probe_reports_a_nonzero_exit(monkeypatch):
    monkeypatch.setattr(subprocess, "run",
                        responder({"tool": completed(returncode=3, stderr="broken")}))

    result = poc_preflight.probe(["tool", "--version"])

    assert result.ok is False
    assert result.error == "exited 3"


def test_probe_reports_an_unexecutable_file(monkeypatch):
    monkeypatch.setattr(subprocess, "run",
                        responder({"tool": PermissionError("denied")}))

    result = poc_preflight.probe(["tool", "--version"])

    assert result.ok is False
    assert "not executable" in result.error


def test_first_line_skips_leading_blank_lines():
    assert poc_preflight.first_line("\n\n  syft 1.51.1  \nextra") == "syft 1.51.1"
    assert poc_preflight.first_line("") == ""


def test_report_prints_a_fix_line_only_for_failures(capsys):
    poc_preflight.report([
        poc_preflight.Check("Python", True, "3.12.3"),
        poc_preflight.Check("Syft", False, "not found", "run bootstrap"),
    ])

    out = capsys.readouterr().out
    assert "PASS  Python" in out
    assert "-> run bootstrap" in out
    assert out.count("->") == 1
    assert "1 of 2 checks failed." in out


def test_python_older_than_3_10_fails(monkeypatch):
    monkeypatch.setattr(poc_preflight, "MIN_PYTHON", (99, 0))

    check = poc_preflight.check_python()

    assert check.ok is False
    assert "99.0 or newer is required" in check.fix
