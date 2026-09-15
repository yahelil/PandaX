"""Check that this machine can run the PoC, and change nothing while doing it.

Stdlib only, like tools/bootstrap.py: a checker that tells you your setup is
broken is useless if it cannot start until the setup works.

Read-only on purpose. This never installs a tool, starts a service, runs a scan
or reads a signing key. Every probe is a version or status query with a bounded
timeout, so a hung daemon fails the check instead of hanging the operator.

    python tools/poc_preflight.py [--firmware] [--pdf]

Default checks are what every run needs: Python, the Actis package, Syft.
Optional tools are checked only when their flag asks for them — a machine
without Docker still passes a default run, because a default run does not use
Docker.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = ROOT / ".tools"

# A probe that has not answered in ten seconds is a failed check, not a wait.
PROBE_TIMEOUT = 10

MIN_PYTHON = (3, 10)

BOOTSTRAP_FIX = "run:  uv run python tools/bootstrap.py"


@dataclass(frozen=True)
class Check:
    """One line of output: what was checked, whether it holds, how to fix it."""

    name: str
    ok: bool
    detail: str
    fix: str = ""


@dataclass(frozen=True)
class Probe:
    """The result of asking an external tool to describe itself."""

    ok: bool
    output: str = ""
    error: str = ""


def probe(argv: list[str], timeout: int = PROBE_TIMEOUT) -> Probe:
    """Run a read-only query and turn every failure mode into a readable line.

    Argument arrays only, never shell=True: a tool path containing spaces is a
    normal thing on Windows and macOS, not a quoting puzzle.
    """
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return Probe(False, error=f"{argv[0]} not found")
    except PermissionError:
        return Probe(False, error=f"{argv[0]} is not executable")
    except subprocess.TimeoutExpired:
        return Probe(False, error=f"no answer within {timeout}s")
    except OSError as exc:  # unreadable path, bad interpreter, exec format
        return Probe(False, error=f"could not run {argv[0]}: {exc}")

    text = (completed.stdout or "") + (completed.stderr or "")
    if completed.returncode != 0:
        return Probe(False, output=first_line(text),
                     error=f"exited {completed.returncode}")
    return Probe(True, output=first_line(text))


def first_line(text: str) -> str:
    """The first non-empty line, which is where these tools put their version."""
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


def check_python() -> Check:
    version = ".".join(str(part) for part in sys.version_info[:3])
    wanted = ".".join(str(part) for part in MIN_PYTHON)
    if sys.version_info >= MIN_PYTHON:
        return Check("Python", True, f"{version}")
    return Check("Python", False, f"{version}",
                 f"Python {wanted} or newer is required; this is {version}")


def check_actis() -> Check:
    try:
        version = importlib.metadata.version("actis")
    except importlib.metadata.PackageNotFoundError:
        return Check("Actis package", False, "not installed",
                     "install the engine:  uv sync")
    return Check("Actis package", True, version)


def find_syft() -> Path | None:
    """Prefer the pinned binary bootstrap.py installs; fall back to PATH."""
    for name in ("syft.exe", "syft"):
        candidate = TOOLS_DIR / name
        if candidate.exists():
            return candidate
    found = shutil.which("syft")
    return Path(found) if found else None


def check_syft() -> Check:
    binary = find_syft()
    if binary is None:
        return Check("Syft", False, "not found in .tools/ or on PATH",
                     BOOTSTRAP_FIX)
    result = probe([str(binary), "--version"])
    if not result.ok:
        return Check("Syft", False, f"{binary}: {result.error}", BOOTSTRAP_FIX)
    return Check("Syft", True, result.output or str(binary))


def check_docker() -> Check:
    """Ask whether the daemon is reachable. Never start it, never pull an image."""
    binary = shutil.which("docker")
    if binary is None:
        return Check("Docker", False, "docker not on PATH",
                     "install Docker Desktop and reopen this shell")
    result = probe([binary, "info", "--format", "{{.ServerVersion}}"])
    if not result.ok:
        return Check("Docker", False, f"daemon unreachable ({result.error})",
                     "start Docker Desktop in Linux-container mode")
    return Check("Docker", True, f"daemon {result.output}" if result.output
                 else "daemon reachable")


def find_verapdf(explicit: Path | None) -> Path | None:
    if explicit is not None:
        return explicit if explicit.exists() else None
    for name in ("verapdf", "verapdf.bat"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def check_verapdf(explicit: Path | None) -> Check:
    binary = find_verapdf(explicit)
    if binary is None:
        where = f"{explicit}" if explicit else "verapdf/verapdf.bat on PATH"
        return Check("veraPDF", False, f"not found: {where}",
                     "install veraPDF, or pass --verapdf PATH")
    result = probe([str(binary), "--version"])
    if not result.ok:
        return Check("veraPDF", False, f"{binary}: {result.error}",
                     "check the veraPDF installation, or pass --verapdf PATH")
    return Check("veraPDF", True, result.output or str(binary))


def run_checks(firmware: bool, pdf: bool, verapdf: Path | None) -> list[Check]:
    checks = [check_python(), check_actis(), check_syft()]
    if firmware:
        checks.append(check_docker())
    if pdf:
        checks.append(check_verapdf(verapdf))
    return checks


def report(checks: list[Check], stream=None) -> None:
    # Resolved per call, not as a default: a default argument would freeze
    # sys.stdout at import time and ignore any later redirection.
    stream = sys.stdout if stream is None else stream
    width = max(len(check.name) for check in checks)
    print("Actis by PandaX preflight", file=stream)
    print(file=stream)
    for check in checks:
        status = "PASS" if check.ok else "FAIL"
        print(f"{status}  {check.name:<{width}}  {check.detail}", file=stream)
        if not check.ok and check.fix:
            print(f"      {'':<{width}}  -> {check.fix}", file=stream)
    print(file=stream)
    failed = [check for check in checks if not check.ok]
    if failed:
        print(f"{len(failed)} of {len(checks)} checks failed.", file=stream)
    else:
        print(f"All {len(checks)} checks passed.", file=stream)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="poc_preflight",
        description="Read-only check that this machine can run the PoC. "
                    "Installs nothing and starts nothing.",
    )
    parser.add_argument("--firmware", action="store_true",
                        help="also check Docker CLI and daemon availability")
    parser.add_argument("--pdf", action="store_true",
                        help="also check for veraPDF")
    parser.add_argument("--verapdf", type=Path, default=None, metavar="PATH",
                        help="explicit veraPDF executable, instead of PATH lookup")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    checks = run_checks(
        args.firmware,
        args.pdf or args.verapdf is not None,
        args.verapdf,
    )
    report(checks)
    # Exit 0 only when every requested check passed. An unrequested optional
    # tool is not a check and cannot fail the run.
    return 0 if all(check.ok for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
