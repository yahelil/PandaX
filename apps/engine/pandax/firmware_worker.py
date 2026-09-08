"""Standalone worker mounted read-only into the pinned unblob container.

Stdout is a TAR transport, stderr is diagnostics. No firmware links or special
files are created on the host, and nothing from the firmware is executed.
"""
from __future__ import annotations

import io
import json
import os
import stat
import sys
import tarfile
from importlib.metadata import version
from pathlib import Path

MAX_DEPTH = 10


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
                "problems": problems}, None
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
                "roots": [str(p.relative_to(work)) for p in roots]}, None
    root, handler = next(iter(roots.items()))
    # A chunk with no extracted directory may mean a second filesystem failed silently.
    if len(chunks) != 1:
        return {"status": "unsupported", "reason": "multiple filesystem chunks are not supported"}, None
    outside_unknown = [r for result in results
                       if not Path(result["task"]["path"]).is_relative_to(root)
                       for r in result.get("reports", []) if r.get("__typename__") == "UnknownChunkReport"]
    if outside_unknown:
        return {"status": "partial", "reason": "unrecognized container regions remain outside the filesystem",
                "unknown_regions": outside_unknown}, None
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
                    raise ValueError(f"link escapes filesystem: {path.relative_to(root)}")
                links.append({"path": path.relative_to(root).as_posix(), "target": os.readlink(path)})
            elif stat.S_ISREG(mode):
                files.append(path)
            elif not stat.S_ISDIR(mode):
                raise ValueError(f"special file refused: {path.relative_to(root)}")
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
                                  max_depth=MAX_DEPTH, process_num=1)
        result = process_file(config, Path("/input/firmware.bin"))
        raw = result.to_json()
        space = os.statvfs(work)
        # ubireader may exit zero after ENOSPC and leave empty/truncated files.
        # Treat a full working filesystem as incomplete even without tool errors.
        if space.f_bavail == 0 or space.f_favail == 0:
            raise ValueError("extraction working-space or file-entry limit reached")
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
        report.update(status="failed", reason=f"{type(exc).__name__}: {exc}")
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
    main()
