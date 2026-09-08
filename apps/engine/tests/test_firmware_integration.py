"""Opt-in real images; downloads are digest-pinned and kept outside Git."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from urllib.request import urlopen

import pytest

from pandax import firmware
from pandax.native import inventory

pytestmark = pytest.mark.skipif(os.environ.get("PANDAX_FIRMWARE_INTEGRATION") != "1",
                               reason="set PANDAX_FIRMWARE_INTEGRATION=1 to run real Docker extraction")

OPENWRT = (
    "https://downloads.openwrt.org/releases/23.05.5/targets/x86/64/"
    "openwrt-23.05.5-x86-64-generic-squashfs-rootfs.img.gz",
    "478601ab0f5176372e6e0079614240dd25049c74167572ca9bc1b91e9261fe17",
)
# ONEKEY's UBIFS regression image at release 26.6.4 (Git LFS object hash).
UBIFS = (
    "https://media.githubusercontent.com/media/onekey-sec/unblob/"
    "1fcc7a0a584a70a96c31f5a276c20944d199a089/"
    "tests/integration/filesystem/ubi/ubifs/__input__/banana.ubifs",
    "87b05f653d717736b766a9cca10b75656cc14c1d9442c61fdc514cc275a8a634",
)


def download_fixture(url: str, digest: str) -> Path:
    cache = Path(__file__).resolve().parents[3] / ".cache/firmware"
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
    subprocess.run(["docker", "info"], check=True, capture_output=True, timeout=30)
    subprocess.run(["docker", "image", "inspect", firmware.IMAGE],
                   check=True, capture_output=True, timeout=30)


def test_real_openwrt_squashfs_inventory(tmp_path):
    root = tmp_path / "extracted"
    count, total = firmware.extract(download_fixture(*OPENWRT), root)
    assert count > 100 and total > 1024 * 1024
    data = inventory(root)
    assert data["openwrt_release"] == "23.05.5"
    components = {c["name"]: c["version"] for c in data["components"]}
    # Independent oracle: official openwrt-23.05.5-x86-64.manifest.
    assert components["busybox"] == "1.36.1-1"
    assert components["dnsmasq"] == "2.90-2"


def test_real_ubifs_files(tmp_path):
    root = tmp_path / "extracted"
    count, total = firmware.extract(download_fixture(*UBIFS), root)
    assert count == 4 and total == 32
    assert firmware.sha256_file(root / "banana1.txt") == "022d66975222661648a212f974a822fac4d349c0f7c13ef7e0ba3ac0e7d9f519"
    assert firmware.sha256_file(root / "banana2.txt") == "cec01facc588f339e757822825743d16fae68d80ddf9b5e9e08f2862644f7733"


def test_real_container_output_ceiling(tmp_path, monkeypatch):
    # A kernel-enforced tmpfs ceiling, not a mock or an after-extraction counter.
    monkeypatch.setenv("PANDAX_FIRMWARE_MAX_OUTPUT_BYTES", "8192")
    with pytest.raises(firmware.FirmwareError):
        firmware.extract(download_fixture(*UBIFS), tmp_path / "extracted")
    assert not (tmp_path / "extracted").exists()
