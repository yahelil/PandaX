"""Bounded Linux unblob jobs shared by artifact ingestion's CLI and HTTP callers."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from .evidence import sha256_file

# Official unblob 26.6.4 multi-platform image; upgrade the digest and tests together.
IMAGE = "ghcr.io/onekey-sec/unblob@sha256:0779adc4fc7751c601eaaa2eaae1ad04279a8afadecb36af4315752b72f5e2f9"
REPORT = "firmware-extraction.json"
RAW_REPORT = "unblob-report.json"
LOG = "firmware-extraction.log"
DIAGNOSTIC_BYTES = 16 * 1024 * 1024


class FirmwareError(ValueError):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Limits:
    max_input_bytes: int = 1024**3
    max_output_bytes: int = 10 * 1024**3
    max_files: int = 100_000
    timeout_seconds: int = 600

    def __post_init__(self):
        for name, value in asdict(self).items():
            if type(value) is not int or value <= 0:
                raise FirmwareError("failed", f"{name} must be a positive integer")

    @classmethod
    def from_env(cls) -> Limits:
        values = {}
        for name, default in asdict(cls()).items():
            key = "PANDAX_FIRMWARE_" + name.upper()
            try:
                values[name] = int(os.environ.get(key, default))
            except ValueError as exc:
                raise FirmwareError("failed", f"{key} must be a positive integer") from exc
        return cls(**values)


def check_input(src: Path, limits: Limits) -> None:
    if not src.is_file() or src.is_symlink():
        raise FirmwareError("failed", "firmware input must be a regular file, not a symlink")
    if src.stat().st_size > limits.max_input_bytes:
        raise FirmwareError("failed", f"firmware exceeds max_input_bytes={limits.max_input_bytes}")


def command(docker: str, src: Path, name: str, limits: Limits) -> list[str]:
    worker = Path(__file__).with_name("firmware_worker.py").resolve()
    # --mount CSV needs quoting independently of shell quoting (shell=False).
    def mount(path: Path, target: str) -> str:
        source = str(path.resolve()).replace('"', '""')
        return f'type=bind,"source={source}",target={target},readonly'

    return [docker, "run", "--rm", "--pull=never", "--name", name,
            "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--user=1000:1000",
            "--pids-limit=128", "--cpus=2",
            f"--memory={limits.max_output_bytes + 512 * 1024**2}",
            f"--memory-swap={limits.max_output_bytes + 512 * 1024**2}",
            "--tmpfs", f"/work:rw,noexec,nosuid,nodev,size={limits.max_output_bytes},nr_inodes={limits.max_files + 1},mode=1777",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864,nr_inodes=4096,mode=1777",
            "--mount", mount(src, "/input/firmware.bin"),
            "--mount", mount(worker, "/runner.py"),
            "--workdir=/work", "--env=PYTHONDONTWRITEBYTECODE=1",
            "--entrypoint=python", IMAGE, "/runner.py"]


def _run_container(docker: str, src: Path, archive: Path, log: Path, limits: Limits) -> None:
    name = "pandax-firmware-" + uuid.uuid4().hex
    # Include tar headers/padding and bounded JSON diagnostics in the transfer cap.
    transfer_limit = limits.max_output_bytes + limits.max_files * 4096 + 2 * DIAGNOSTIC_BYTES
    proc = None
    try:
        with archive.open("wb") as output, log.open("wb") as errors:
            proc = subprocess.Popen(command(docker, src, name, limits),
                                    stdin=subprocess.DEVNULL, stdout=output, stderr=errors)
            deadline = time.monotonic() + limits.timeout_seconds
            while proc.poll() is None:
                if time.monotonic() >= deadline:
                    raise FirmwareError("failed", f"firmware extraction exceeded {limits.timeout_seconds}s timeout")
                if archive.stat().st_size > transfer_limit or log.stat().st_size > DIAGNOSTIC_BYTES:
                    raise FirmwareError("failed", "firmware extraction exceeded transfer/diagnostic limit")
                time.sleep(0.05)
            if archive.stat().st_size > transfer_limit or log.stat().st_size > DIAGNOSTIC_BYTES:
                raise FirmwareError("failed", "firmware extraction exceeded transfer/diagnostic limit")
            if proc.returncode:
                raise FirmwareError("failed", "Docker/unblob failed; see firmware-extraction.log. "
                                    "Start Docker Desktop in Linux-container mode and pull the pinned image "
                                    "from docs/firmware-ingestion.md. Check memory and extraction limits.")
    finally:
        if proc is not None:
            try:
                # Killing the docker client alone would leave its container running.
                subprocess.run([docker, "rm", "-f", name], capture_output=True, timeout=15)
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=15)


def _target(root: Path, name: str) -> Path:
    parts = PurePosixPath(name).parts
    if (not parts or name.startswith("/") or "\\" in name or ":" in name
            or ".." in parts or len(parts) > 128):
        raise FirmwareError("failed", f"unsafe extraction path: {name!r}")
    # Refuse names Windows aliases or cannot represent, on every host.
    for part in parts:
        if (part.endswith((".", " ")) or PureWindowsPath(part).is_reserved()
                or any(ord(c) < 32 or c in '<>"|?*' for c in part)):
            raise FirmwareError("unsupported", f"filesystem path is not portable to Windows: {name!r}")
    target = root.joinpath(*parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise FirmwareError("failed", f"extraction path escapes root: {name!r}")
    return target


def _receive(archive: Path, staging: Path, evidence: Path, limits: Limits) -> tuple[dict, int, int]:
    """Never use extractall on container output: only accept bounded regular files."""
    count = total = 0
    seen: set[str] = set()
    spellings: dict[str, str] = {}
    report = None
    raw_seen = False
    with tarfile.open(archive, "r|") as tf:
        for index, member in enumerate(tf, 1):
            if index > limits.max_files + 2 or not member.isfile() or member.size < 0:
                raise FirmwareError("failed", "invalid entry or too many files in container output")
            key = member.name.casefold()
            if key in seen:
                raise FirmwareError("failed", f"duplicate/case-colliding extraction path: {member.name}")
            seen.add(key)
            if member.name in (REPORT, RAW_REPORT):
                if member.size > DIAGNOSTIC_BYTES:
                    raise FirmwareError("failed", "extraction report exceeds diagnostic limit")
                content = tf.extractfile(member).read()
                data = json.loads(content)
                if member.name == REPORT:
                    if not isinstance(data, dict) or data.get("status") not in {
                        "completed", "partial", "encrypted", "unsupported", "failed"
                    }:
                        raise FirmwareError("failed", "invalid extraction status report")
                    report = data
                else:
                    if not isinstance(data, list):
                        raise FirmwareError("failed", "invalid unblob report")
                    (evidence / RAW_REPORT).write_bytes(content)
                    raw_seen = True
                continue
            if not member.name.startswith("root/"):
                raise FirmwareError("failed", f"unexpected container output: {member.name}")
            target = _target(staging, member.name[5:])
            relative = target.relative_to(staging)
            for part in (relative, *relative.parents):
                spelling = part.as_posix()
                if spellings.setdefault(spelling.casefold(), spelling) != spelling:
                    raise FirmwareError("unsupported", f"case-colliding filesystem path: {member.name}")
            count += 1
            total += member.size
            if count > limits.max_files or total > limits.max_output_bytes:
                raise FirmwareError("failed", "extracted filesystem exceeds configured limits")
            target.parent.mkdir(parents=True, exist_ok=True)
            with tf.extractfile(member) as source, target.open("xb") as out:
                shutil.copyfileobj(source, out)
    if report is None or not raw_seen:
        raise FirmwareError("failed", "missing extraction reports")
    if report["status"] == "completed" and not count:
        raise FirmwareError("failed", "extractor returned an empty filesystem")
    if report["status"] == "completed" and (
        report.get("file_count") != count or report.get("uncompressed_bytes") != total
    ):
        raise FirmwareError("failed", "filesystem transfer does not match extractor totals")
    if report["status"] == "completed" and (
        report.get("unblob_version") != "26.6.4"
        or not isinstance(report.get("root"), str)
        or not (str(report.get("handler", "")).startswith("squashfs") or report.get("handler") == "ubifs")
    ):
        raise FirmwareError("failed", "missing or unexpected extractor provenance")
    return report, count, total


def extract(src: Path, dest: Path) -> tuple[int, int]:
    """Publish one complete, link-free root; always retain status/diagnostics."""
    src, dest = Path(src).absolute(), Path(dest).absolute()
    evidence = dest.parent
    evidence.mkdir(parents=True, exist_ok=True)
    report = {"status": "failed", "source": src.name, "image": IMAGE}
    try:
        limits = Limits.from_env()
        report["limits"] = asdict(limits)
        check_input(src, limits)
        report["source_sha256"] = sha256_file(src)
        if dest.is_symlink() or (dest.exists() and any(dest.iterdir())):
            raise FirmwareError("failed", "firmware destination must be empty")
        docker = shutil.which("docker")
        if not docker:
            raise FirmwareError("unsupported", "unsupported artifact format without Docker: install Docker "
                                "Desktop, enable Linux containers, and pull the pinned image "
                                "in docs/firmware-ingestion.md")
        with tempfile.TemporaryDirectory(prefix=".firmware-", dir=evidence) as temporary:
            scratch = Path(temporary)
            staging = scratch / "root"
            staging.mkdir()
            archive = scratch / "output.tar"
            _run_container(docker, src, archive, evidence / LOG, limits)
            result, count, total = _receive(archive, staging, evidence, limits)
            if sha256_file(src) != report["source_sha256"]:
                raise FirmwareError("failed", "firmware input changed during extraction")
            source_digest = report["source_sha256"]
            report.update(result)
            report.update(image=IMAGE, source=src.name, source_sha256=source_digest,
                          limits=asdict(limits), file_count=count, uncompressed_bytes=total)
            if report["status"] != "completed":
                raise FirmwareError(report["status"], report.get("reason", "incomplete firmware extraction"))
            if dest.exists():
                dest.rmdir()  # Only an empty destination is permitted.
            staging.replace(dest)
            return count, total
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as exc:
        report.update(status=getattr(exc, "status", "failed"), reason=str(exc))
        raise FirmwareError(report["status"], str(exc)) from exc
    finally:
        (evidence / REPORT).write_text(json.dumps(report, indent=2), encoding="utf-8")
