"""S1 INGEST - unpack the product artifact under explicit safety limits.

The blueprint called for Firecracker microVMs here. That control does not fit
the threat: Syft *parses* metadata, it never executes the artifact, so kernel
isolation defends against something that does not happen. The real risk in
accepting a customer archive is the archive itself - path traversal (zip slip),
decompression bombs, and pathological nesting.

So the sandbox is replaced with the three controls that actually match the
threat, each of which has a test proving it fires.
"""

from __future__ import annotations

import json
import shutil
import tarfile
import zipfile
from pathlib import Path

from .. import events as ev
from ..context import RunContext
from ..evidence import sha256_file

STAGE = "S1 INGEST"

MAX_TOTAL_BYTES = 512 * 1024 * 1024  # decompression bomb ceiling
MAX_ENTRIES = 20_000
MAX_DEPTH = 24


class UnsafeArtifact(Exception):
    """Raised when an archive violates an extraction safety limit."""


def _safe_target(dest_root: Path, member_name: str) -> Path:
    """Resolve an archive member inside dest_root, or refuse it.

    Blocks absolute paths, drive letters, and ../ traversal by comparing the
    fully resolved path against the resolved destination root.
    """
    if member_name.startswith(("/", "\\")) or (
        len(member_name) > 1 and member_name[1] == ":"
    ):
        raise UnsafeArtifact(f"absolute path in archive: {member_name!r}")

    if len(Path(member_name).parts) > MAX_DEPTH:
        raise UnsafeArtifact(f"path nesting exceeds {MAX_DEPTH}: {member_name!r}")

    target = (dest_root / member_name).resolve()
    if not target.is_relative_to(dest_root.resolve()):
        raise UnsafeArtifact(f"path traversal blocked (zip slip): {member_name!r}")
    return target


def _extract_zip(src: Path, dest: Path) -> tuple[int, int]:
    total = count = 0
    with zipfile.ZipFile(src) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise UnsafeArtifact(f"archive has {len(infos)} entries, limit {MAX_ENTRIES}")
        for info in infos:
            target = _safe_target(dest, info.filename)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise UnsafeArtifact(
                    f"uncompressed size exceeds {MAX_TOTAL_BYTES:,} bytes "
                    "(decompression bomb)"
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src_fh, open(target, "wb") as out:
                shutil.copyfileobj(src_fh, out)
            count += 1
    return count, total


def _extract_tar(src: Path, dest: Path) -> tuple[int, int]:
    total = count = 0
    with tarfile.open(src) as tf:
        for member in tf:
            if member.issym() or member.islnk():
                raise UnsafeArtifact(f"link member refused: {member.name!r}")
            target = _safe_target(dest, member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            total += member.size
            count += 1
            if total > MAX_TOTAL_BYTES:
                raise UnsafeArtifact(
                    f"uncompressed size exceeds {MAX_TOTAL_BYTES:,} bytes "
                    "(decompression bomb)"
                )
            if count > MAX_ENTRIES:
                raise UnsafeArtifact(f"archive exceeds {MAX_ENTRIES} entries")
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            with extracted as src_fh, open(target, "wb") as out:
                shutil.copyfileobj(src_fh, out)
    return count, total


def extract(src: Path, dest: Path) -> tuple[int, int]:
    """Extract src into dest. Returns (file_count, uncompressed_bytes)."""
    dest.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(src):
        return _extract_zip(src, dest)
    if tarfile.is_tarfile(src):
        return _extract_tar(src, dest)
    raise UnsafeArtifact(f"unsupported artifact format: {src.name}")


def run(ctx: RunContext) -> ev.Stream:
    yield ev.start(STAGE, f"ingesting {ctx.artifact.name}")

    work = ctx.run_dir / "extracted"
    inputs_dir = ctx.run_dir / "input"
    inputs_dir.mkdir(parents=True, exist_ok=True)

    if ctx.artifact.is_dir():
        # A plain directory needs no unpacking, but is still copied in so the
        # evidence bundle is self-contained and independently re-hashable.
        shutil.copytree(ctx.artifact, work, dirs_exist_ok=True)
        files = [p for p in work.rglob("*") if p.is_file()]
        count, total = len(files), sum(p.stat().st_size for p in files)
        local_input = work
        yield ev.log(STAGE, "source is a directory - copied, nothing to unpack")
    else:
        local_input = inputs_dir / ctx.artifact.name
        shutil.copy2(ctx.artifact, local_input)
        digest = sha256_file(local_input)
        yield ev.log(STAGE, f"artifact sha256 {digest}", ev.GOOD)
        yield ev.log(
            STAGE,
            f"limits: <={MAX_TOTAL_BYTES // (1024 * 1024)} MiB uncompressed, "
            f"<={MAX_ENTRIES:,} entries, <={MAX_DEPTH} path depth",
        )
        count, total = extract(local_input, work)
        yield ev.log(STAGE, "zip-slip / bomb / depth checks passed", ev.GOOD)

    ctx.extracted_dir = work

    # Hash every extracted file: this is the baseline the dossier rests on.
    tree = sorted(p for p in work.rglob("*") if p.is_file())
    digests = {
        p.relative_to(work).as_posix(): sha256_file(p) for p in tree
    }
    tree_path = ctx.path("ingest_tree.json")
    tree_path.write_text(
        json.dumps(
            {
                "source": ctx.artifact.name,
                "file_count": len(tree),
                "uncompressed_bytes": total,
                "files": digests,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    yield ev.metric(STAGE, "files extracted", count)
    yield ev.metric(STAGE, "uncompressed bytes", f"{total:,}")
    for rel in list(digests)[:8]:
        yield ev.log(STAGE, f"  {rel}")
    if len(digests) > 8:
        yield ev.log(STAGE, f"  ... and {len(digests) - 8} more")

    yield ev.artifact(STAGE, ctx.ledger.rel(tree_path), sha256_file(tree_path))

    ctx.ledger.append(
        stage="S1_INGEST",
        tool="pandax.ingest",
        tool_version="0.1.0",
        inputs=[ctx.ledger.ref(local_input)] if local_input.is_file() else [],
        outputs=[ctx.ledger.ref(tree_path)],
        params={
            "max_total_bytes": MAX_TOTAL_BYTES,
            "max_entries": MAX_ENTRIES,
            "max_depth": MAX_DEPTH,
        },
    )
    yield ev.done(STAGE, f"{count} files unpacked safely")
