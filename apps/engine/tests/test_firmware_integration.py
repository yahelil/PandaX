"""Opt-in real images; downloads are digest-pinned and kept outside Git."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.request import urlopen

import pytest

from pandax import firmware
from pandax.context import ROOT
from pandax.stages import ingest, sbom

pytestmark = pytest.mark.skipif(os.environ.get("PANDAX_FIRMWARE_INTEGRATION") != "1",
                               reason="set PANDAX_FIRMWARE_INTEGRATION=1 to run real Docker extraction")

MANIFEST = json.loads((ROOT / "fixtures/firmware/manifest.json").read_text())
OPENWRT, UBIFS = MANIFEST["openwrt"], MANIFEST["ubifs"]


def download_fixture(fixture: dict) -> Path:
    url, digest = fixture["url"], fixture["sha256"]
    cache = Path(os.environ.get("PANDAX_FIRMWARE_CACHE", ROOT / "workspace/cache/firmware"))
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / url.rsplit("/", 1)[-1]
    if target.exists() and firmware.sha256_file(target) == digest:
        return target
    with urlopen(url, timeout=60) as response:
        data = response.read(64 * 1024 * 1024 + 1)
    assert len(data) <= 64 * 1024 * 1024, "fixture exceeds download ceiling"
    assert hashlib.sha256(data).hexdigest() == digest, "fixture digest mismatch"
    target.write_bytes(data)
    return target


@pytest.fixture(scope="module", autouse=True)
def require_docker():
    assert shutil.which("docker"), "Docker is required for explicitly requested integration tests"
    for args, remedy in [
        (["docker", "info"], "Start Docker Desktop in Linux-container mode."),
        (["docker", "image", "inspect", firmware.IMAGE], f"Run: docker pull {firmware.IMAGE}"),
    ]:
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            pytest.fail(f"Firmware integration prerequisite failed: {exc}. {remedy}", pytrace=False)
        if result.returncode:
            pytest.fail(f"Firmware integration prerequisite failed: {result.stderr.strip()}. {remedy}",
                        pytrace=False)


def test_real_openwrt_squashfs_inventory(ctx):
    # Download/verify the independent oracle BEFORE running the scanner.
    oracle = OPENWRT["inventory_oracle"]
    expected = dict(line.split(" - ", 1) for line in
                    download_fixture(oracle).read_text().splitlines() if line)
    assert len(expected) == oracle["package_count"]
    # Generic-device drivers and dependencies from the separate official profile
    # and package indexes, frozen in the manifest independently of scan results.
    expected.update(OPENWRT["device_packages"])
    ctx.artifact = download_fixture(OPENWRT)
    ctx.components = []
    ctx.findings = []
    list(ingest.run(ctx))
    list(sbom.run(ctx))  # Real Syft plus native enrichment, no advisory queries.
    assert ctx.native_inventory["openwrt_release"] == OPENWRT["release"]
    actual = {c["name"]: c["version"] for c in ctx.native_inventory["components"]}
    assert actual == expected
    sbom_packages = {c["name"]: c["version"] for c in ctx.components
                     if c["purl"].startswith("pkg:opkg/openwrt/")}
    assert sbom_packages == expected
    assert ctx.sbom["specVersion"] == "1.6" and "vulnerabilities" not in ctx.sbom
    report = json.loads(ctx.path(firmware.REPORT).read_text())
    assert report["status"] == "completed"
    assert report["source_sha256"] == OPENWRT["sha256"]
    assert report["image"] == firmware.IMAGE
    tree = json.loads(ctx.path("ingest_tree.json").read_text())
    assert tree["file_count"] == report["file_count"] > 100
    for name, digest in tree["files"].items():
        assert firmware.sha256_file(ctx.extracted_dir / name) == digest
    records = ctx.ledger.records
    assert [r["stage"] for r in records] == ["S1_INGEST", "S2_SBOM"]
    assert records[0]["inputs"][0]["sha256"] == OPENWRT["sha256"]
    assert records[1]["inputs"][0] in records[0]["outputs"]
    for record in records:
        for output in record["outputs"]:
            assert firmware.sha256_file(ctx.path(output["path"])) == output["sha256"]


def test_real_ubifs_files(tmp_path):
    root = tmp_path / "extracted"
    count, total = firmware.extract(download_fixture(UBIFS), root)
    assert count == len(UBIFS["files"]) and total == UBIFS["uncompressed_bytes"]
    assert {p.relative_to(root).as_posix(): firmware.sha256_file(p)
            for p in root.rglob("*") if p.is_file()} == UBIFS["files"]


@pytest.mark.parametrize("fixture,ceiling", [(UBIFS, "4096"), (OPENWRT, "1048576")])
def test_real_container_output_ceiling(tmp_path, monkeypatch, fixture, ceiling):
    # A kernel-enforced tmpfs ceiling, not a mock or an after-extraction counter.
    monkeypatch.setenv("PANDAX_FIRMWARE_MAX_OUTPUT_BYTES", ceiling)
    with pytest.raises(firmware.FirmwareError):
        firmware.extract(download_fixture(fixture), tmp_path / "extracted")
    assert not (tmp_path / "extracted").exists()
    report = json.loads((tmp_path / firmware.REPORT).read_text())
    assert report["status"] == "failed"
    assert "working-space or file-entry limit reached" in report["reason"]


def test_real_container_file_ceiling(tmp_path, monkeypatch):
    monkeypatch.setenv("PANDAX_FIRMWARE_MAX_FILES", "2")
    with pytest.raises(firmware.FirmwareError):
        firmware.extract(download_fixture(UBIFS), tmp_path / "extracted")
    assert not (tmp_path / "extracted").exists()
    assert json.loads((tmp_path / firmware.REPORT).read_text())["status"] != "completed"


def test_real_timeout_removes_its_container(tmp_path, monkeypatch):
    names = []
    original = firmware.command
    def command(docker, src, name, limits):
        names.append(name)
        return original(docker, src, name, limits)
    monkeypatch.setattr(firmware, "command", command)
    monkeypatch.setenv("PANDAX_FIRMWARE_TIMEOUT_SECONDS", "1")
    with pytest.raises(firmware.FirmwareError, match="timeout"):
        firmware.extract(download_fixture(OPENWRT), tmp_path / "extracted")
    assert not (tmp_path / "extracted").exists()
    assert len(names) == 1
    remaining = subprocess.run(["docker", "ps", "-aq", "--filter", f"name={names[0]}"],
                               check=True, capture_output=True, text=True, timeout=30)
    assert not remaining.stdout.strip()
    assert json.loads((tmp_path / firmware.REPORT).read_text())["status"] == "failed"


@pytest.mark.parametrize("kind", ["unknown", "truncated", "partial"])
def test_real_bad_images_never_publish_inventory(tmp_path, kind):
    src = tmp_path / "bad.bin"
    if kind == "unknown":
        src.write_bytes(b"not a supported firmware image")
    elif kind == "truncated":
        src.write_bytes(download_fixture(UBIFS).read_bytes()[:64])
    else:
        # Preserve a valid root but introduce an unrecognized outer region.
        src.write_bytes(b"PandaX unknown wrapper\n" * 1024 + download_fixture(UBIFS).read_bytes())
    with pytest.raises(firmware.FirmwareError):
        firmware.extract(src, tmp_path / "extracted")
    assert not (tmp_path / "extracted").exists()
    report = json.loads((tmp_path / firmware.REPORT).read_text())
    assert report["status"] == ("partial" if kind == "partial" else "unsupported")
    assert report["file_count"] == report["uncompressed_bytes"] == 0
