"""Standalone worker mounted read-only into the pinned unblob container.

Stdout is a TAR transport, stderr is diagnostics. No firmware links or special
files are created on the host, and nothing from the firmware is executed.
"""
from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import sys
import tarfile
from importlib.metadata import version
from pathlib import Path

MAX_DEPTH = 10
DIAGNOSTIC_BYTES = 16 * 1024 * 1024


class UnsupportedFilesystem(ValueError):
    pass


def check_space() -> None:
    for directory in ("/work", "/tmp"):
        space = os.statvfs(directory)
        margin = max(4 * 1024**2, space.f_blocks * space.f_frsize // 100)
        if space.f_bavail * space.f_frsize <= margin or space.f_favail <= max(1, space.f_files // 100):
            raise ValueError(f"extraction working-space or file-entry limit reached: {directory}")


def checked_extract(args: list[str]) -> int:
    """ubireader can swallow ENOSPC and exit zero; preserve that error as failure."""
    result = subprocess.run(args, capture_output=True)
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    diagnostics = result.stdout + result.stderr
    if b"No space left on device" in diagnostics or b"[Errno 28]" in diagnostics:
        return 1
    return result.returncode


def install_checked_extractors() -> None:
    # Pinned unblob Command API. Run Python explicitly: /work and /tmp stay noexec.
    from unblob.handlers.filesystem.ubi import UBIHandler, UBIFSHandler
    for handler in (UBIHandler, UBIFSHandler):
        command = handler.EXTRACTOR
        command._command_template = [sys.executable, "/runner.py", "--checked-extractor", *command._command_template]



def _reports(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _reports(child)
    elif isinstance(value, list):
        for child in value:
            yield from _reports(child)


def select_root(results: list[dict], work: Path, filesystem_handlers=()) -> tuple[dict, Path | None]:
    """Use unblob's chunk-to-subtask relationship, never guess by folder name."""
    reports = list(_reports(results))
    if any(r.get("is_encrypted") is True for r in reports):
        return {"status": "encrypted", "reason": "encrypted content detected; inventory was not run"}, None
    problems = [r for r in reports if r.get("severity") in ("WARNING", "ERROR")
                or r.get("__typename__", "").endswith("Problem")]
    if problems:
        return {"status": "partial", "reason": "unblob reported extraction problems; see unblob-report.json",
                "problem_count": len(problems), "problems": problems[:100]}, None
    if any(r.get("task", {}).get("depth", 0) >= MAX_DEPTH for r in results):
        return {"status": "partial", "reason": "unblob recursion limit reached"}, None

    chunks = {r["id"]: r for r in reports if r.get("__typename__") == "ChunkReport"
              and (r.get("handler_name", "").startswith("squashfs") or r.get("handler_name") == "ubifs")}
    other_filesystems = [r for r in reports if r.get("__typename__") == "ChunkReport"
                         and r.get("handler_name") in filesystem_handlers
                         and r.get("handler_name") != "ubi" and r.get("id") not in chunks]
    if other_filesystems:
        return {"status": "unsupported", "reason": "additional or unsupported filesystem format detected"}, None
    roots = {}
    for result in results:
        local_ids = {r["id"] for r in result.get("reports", [])
                     if r.get("__typename__") == "ChunkReport" and r.get("id") in chunks}
        for task in result.get("subtasks", []):
            if task.get("blob_id") not in local_ids:
                continue
            path = Path(task["path"])
            if path.is_symlink() or not path.resolve().is_relative_to(work.resolve()):
                return {"status": "failed", "reason": "filesystem root escapes extraction directory"}, None
            if path.is_dir():
                roots[path] = chunks[task["blob_id"]]["handler_name"]
    if len(roots) != 1:
        return {"status": "unsupported", "reason": f"expected one SquashFS/UBIFS root; found {len(roots)}",
                "root_count": len(roots), "roots": [str(p.relative_to(work)) for p in list(roots)[:100]]}, None
    root, handler = next(iter(roots.items()))
    # A chunk with no extracted directory may mean a second filesystem failed silently.
    if len(chunks) != 1:
        return {"status": "unsupported", "reason": "multiple filesystem chunks are not supported"}, None
    outside_unknown = [r for result in results
                       if not Path(result["task"]["path"]).is_relative_to(root)
                       for r in result.get("reports", []) if r.get("__typename__") == "UnknownChunkReport"]
    if outside_unknown:
        return {"status": "partial", "reason": "unrecognized container regions remain outside the filesystem",
                "unknown_region_count": len(outside_unknown), "unknown_regions": outside_unknown[:100]}, None
    return {"status": "completed", "root": root.relative_to(work).as_posix(), "handler": handler}, root


def files_and_links(root: Path) -> tuple[list[Path], list[dict]]:
    files, links = [], []
    def refuse_unreadable(error):
        raise error
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=refuse_unreadable):
        for name in sorted(dirs + names):
            path = Path(directory) / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                if not path.resolve().is_relative_to(root.resolve()):
                    raise UnsupportedFilesystem(f"link escapes filesystem: {path.relative_to(root)}")
                links.append({"path": path.relative_to(root).as_posix(), "target": os.readlink(path)})
            elif stat.S_ISREG(mode):
                files.append(path)
            elif not stat.S_ISDIR(mode):
                raise UnsupportedFilesystem(f"special file refused: {path.relative_to(root)}")
    return sorted(files), links


def main() -> None:
    # Redirect the OS descriptor too: subprocesses/multiprocessing must never
    # mix their logs into the binary TAR transport, even with spawn/forkserver.
    transport = os.fdopen(os.dup(sys.stdout.fileno()), "wb")
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    work = Path("/work")
    raw = "[]"
    files = []
    root = None
    report = {"status": "failed"}
    try:
        # Import only inside the container; the host needs no unblob dependency.
        from unblob.handlers import BUILTIN_HANDLERS
        from unblob.models import HandlerType
        from unblob.processing import ExtractionConfig, process_file

        report["unblob_version"] = version("unblob")
        config = ExtractionConfig(extract_root=work, randomness_depth=0,
                                  max_depth=MAX_DEPTH, process_num=1, keep_extracted_chunks=True)
        result = process_file(config, Path("/input/firmware.bin"))
        raw = result.to_json()
        check_space()
        filesystem_handlers = {h.NAME for h in BUILTIN_HANDLERS
                               if h.DOC and h.DOC.handler_type == HandlerType.FILESYSTEM}
        selection, root = select_root(json.loads(raw), work, filesystem_handlers)
        report.update(selection)
        if root is not None:
            files, report["links"] = files_and_links(root)
            if not files:
                raise ValueError("extracted filesystem contains no regular files")
            report["file_count"] = len(files)
            report["uncompressed_bytes"] = sum(path.stat().st_size for path in files)
            report["link_policy"] = "recorded, never created or followed on host"
    except Exception as exc:
        report.update(status="unsupported" if isinstance(exc, UnsupportedFilesystem) else "failed",
                      reason=f"{type(exc).__name__}: {exc}", file_count=0, uncompressed_bytes=0)
        files = []
    if len(raw.encode("utf-8")) > DIAGNOSTIC_BYTES:
        raw = json.dumps([{"diagnostic_truncated": True, "reason": "unblob report exceeds diagnostic limit"}])
        report.update(status="failed", reason="unblob report exceeds diagnostic limit", file_count=0, uncompressed_bytes=0)
        files = []
    if len(json.dumps(report).encode("utf-8")) > DIAGNOSTIC_BYTES:
        report = {"status": "failed", "reason": "extraction report exceeds diagnostic limit"}
        files = []
    with transport, tarfile.open(fileobj=transport, mode="w|") as output:
        for name, text in (("firmware-extraction.json", json.dumps(report)), ("unblob-report.json", raw)):
            data = text.encode("utf-8")
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            output.addfile(entry, io.BytesIO(data))
        for path in files:
            # Build headers ourselves: never turn a hardlink into a TAR link.
            entry = tarfile.TarInfo("root/" + path.relative_to(root).as_posix())
            entry.size = path.stat().st_size
            entry.mode = 0o644
            with path.open("rb") as source:
                output.addfile(entry, source)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--checked-extractor":
        sys.exit(checked_extract(sys.argv[2:]))
    install_checked_extractors()
    main()

# Multiprocessing spawn/forkserver imports the entry module under this name.
if __name__ == "__mp_main__":
    install_checked_extractors()
