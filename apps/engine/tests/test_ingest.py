"""S1 safety limits. These replace the blueprint's Firecracker sandbox, so each
one has a test proving it actually fires."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from pandax.stages import ingest
from pandax.stages.ingest import UnsafeArtifact


def test_extracts_a_normal_archive(tmp_path: Path, make_zip):
    src = make_zip(
        tmp_path / "ok.zip",
        {"app/index.js": b"console.log(1)", "services/requirements.txt": b"flask==2.0"},
    )
    dest = tmp_path / "out"
    count, total = ingest.extract(src, dest)
    assert count == 2
    assert total == len(b"console.log(1)") + len(b"flask==2.0")
    assert (dest / "app" / "index.js").read_bytes() == b"console.log(1)"


@pytest.mark.parametrize(
    "name",
    [
        "../escaped.txt",
        "../../escaped.txt",
        "app/../../escaped.txt",
    ],
)
def test_zip_slip_is_blocked(tmp_path: Path, name: str, make_zip):
    src = make_zip(tmp_path / "evil.zip", {name: b"pwned"})
    with pytest.raises(UnsafeArtifact, match="zip slip"):
        ingest.extract(src, tmp_path / "out")
    assert not (tmp_path / "escaped.txt").exists()


def test_absolute_path_is_blocked(tmp_path: Path, make_zip):
    src = make_zip(tmp_path / "abs.zip", {"/etc/passwd": b"root"})
    with pytest.raises(UnsafeArtifact, match="absolute path"):
        ingest.extract(src, tmp_path / "out")


def test_windows_drive_path_is_blocked(tmp_path: Path, make_zip):
    src = make_zip(tmp_path / "drive.zip", {"C:/Windows/evil.dll": b"x"})
    with pytest.raises(UnsafeArtifact, match="absolute path"):
        ingest.extract(src, tmp_path / "out")


def test_deep_nesting_is_blocked(tmp_path: Path, make_zip):
    deep = "/".join(["d"] * (ingest.MAX_DEPTH + 2)) + "/f.txt"
    src = make_zip(tmp_path / "deep.zip", {deep: b"x"})
    with pytest.raises(UnsafeArtifact, match="nesting"):
        ingest.extract(src, tmp_path / "out")


def test_decompression_bomb_is_blocked(tmp_path: Path, monkeypatch):
    # A modest cap keeps the test fast while exercising the real code path.
    monkeypatch.setattr(ingest, "MAX_TOTAL_BYTES", 1024)
    src = tmp_path / "bomb.zip"
    with zipfile.ZipFile(src, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.bin", b"\0" * 50_000)  # compresses to almost nothing
    assert src.stat().st_size < 1024
    with pytest.raises(UnsafeArtifact, match="decompression bomb"):
        ingest.extract(src, tmp_path / "out")


def test_too_many_entries_is_blocked(tmp_path: Path, monkeypatch, make_zip):
    monkeypatch.setattr(ingest, "MAX_ENTRIES", 5)
    src = make_zip(tmp_path / "many.zip", {f"f{i}.txt": b"x" for i in range(10)})
    with pytest.raises(UnsafeArtifact, match="entries"):
        ingest.extract(src, tmp_path / "out")


def test_unknown_format_is_refused(tmp_path: Path):
    src = tmp_path / "not-an-archive.bin"
    src.write_bytes(b"just some bytes")
    with pytest.raises(UnsafeArtifact, match="unsupported"):
        ingest.extract(src, tmp_path / "out")
