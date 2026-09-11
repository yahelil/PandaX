"""S1 INGEST - bounded ZIP/TAR extraction and isolated Linux firmware extraction."""

from __future__ import annotations

import json
import shutil
import tarfile
import zipfile
from pathlib import Path

from .. import events as ev
from .. import firmware
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


def _extract_tar(src: Path, dest: Path, recorded_links: list | None = None) -> tuple[int, int]:
    total = count = 0
    with tarfile.open(src) as tf:
        for index, member in enumerate(tf, 1):
            if index > MAX_ENTRIES:
                raise UnsafeArtifact(f"archive exceeds {MAX_ENTRIES} entries")
            target = _safe_target(dest, member.name)
            if member.issym() or member.islnk():
                if recorded_links is not None:
                    # For digest-pinned public fixtures only. Record links as
                    # evidence, never create or follow them on the host.
                    recorded_links.append({"path": member.name, "target": member.linkname})
                    continue
                raise UnsafeArtifact(f"link member refused: {member.name!r}")
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
    try:
        return firmware.extract(src, dest)
    except firmware.FirmwareError as exc:
        raise UnsafeArtifact(f"{exc.status} firmware extraction: {exc}") from exc


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
        is_archive = zipfile.is_zipfile(ctx.artifact) or tarfile.is_tarfile(ctx.artifact)
        if not is_archive:
            # Refuse oversized firmware before making an input copy.
            try:
                firmware_limits = firmware.Limits.from_env()
                firmware.check_input(ctx.artifact, firmware_limits)
                firmware.check_format(ctx.artifact)
            except firmware.FirmwareError as exc:
                ctx.path(firmware.REPORT).write_text(
                    json.dumps({"status": exc.status, "reason": str(exc)}), encoding="utf-8")
                raise UnsafeArtifact(str(exc)) from exc
        local_input = inputs_dir / ctx.artifact.name
        shutil.copy2(ctx.artifact, local_input)
        digest = sha256_file(local_input)
        yield ev.log(STAGE, f"artifact sha256:{digest[:16]}... verified", ev.GOOD)
        yield ev.log(
            STAGE,
            (f"limits: <={MAX_TOTAL_BYTES // (1024 * 1024)} MiB uncompressed, "
             f"<={MAX_ENTRIES:,} entries, <={MAX_DEPTH} path depth")
            if is_archive else f"firmware limits: {firmware_limits}",
        )
        from ..scenarios import identify
        release = identify(local_input)
        if release is not None:
            links: list = []
            work.mkdir(parents=True, exist_ok=True)
            count, total = _extract_tar(local_input, work, links)
            release = {
                **release,
                'status': 'verified',
                'method': 'sha256',
                'project': release.get('project', 'unknown'),
                'verified_at': ev.now_iso(),
            }
            ctx.path("archive-links.json").write_text(json.dumps(links, indent=2), encoding="utf-8")
            ctx.path("release-source.json").write_text(json.dumps(release, indent=2), encoding="utf-8")
            yield ev.log(STAGE, f"verified official {release['kind']}; {len(links)} links recorded, not created")
        else:
            count, total = extract(local_input, work)
        yield ev.log(STAGE, "extraction safety checks passed", ev.GOOD)

    ctx.extracted_dir = work
    extraction_params = {"max_total_bytes": MAX_TOTAL_BYTES,
                         "max_entries": MAX_ENTRIES, "max_depth": MAX_DEPTH}
    firmware_report = ctx.path(firmware.REPORT)
    if firmware_report.exists():
        extraction = json.loads(firmware_report.read_text(encoding="utf-8"))
        extraction_params = extraction["limits"]
        ctx.tool_versions["unblob"] = extraction["unblob_version"]
        yield ev.log(STAGE, f"firmware: {extraction['handler']}; one filesystem root accepted", ev.GOOD)

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
        outputs=[ctx.ledger.ref(tree_path)] + [ctx.ledger.ref(ctx.path(n)) for n in
                 ("archive-links.json", "release-source.json", firmware.REPORT,
                  firmware.RAW_REPORT, firmware.LOG) if ctx.path(n).exists()],
        params=extraction_params,
    )
    yield ev.done(STAGE, f"{count} files unpacked safely")
