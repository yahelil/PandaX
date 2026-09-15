"""Fetch pinned external dependencies and build the demo artifact.

Stdlib only, on purpose: this runs before `uv sync`, and a setup script that
verifies supply-chain digests should not itself pull in a supply chain.

Everything downloaded here is pinned by SHA-256. A digest mismatch is fatal.
"""

from __future__ import annotations

import hashlib
import io
import os
import platform
import shutil
import stat
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / ".tools"
FIXTURE = ROOT / "fixtures" / "smarthub-sh100"
ARTIFACT = ROOT / "fixtures" / "smarthub-sh100-v2.3.1.zip"

SYFT_VERSION = "1.51.1"
# Digests taken from the official syft_1.51.1_checksums.txt on the GitHub release.
SYFT_BUILDS = {
    ("Windows", "AMD64"): (
        f"syft_{SYFT_VERSION}_windows_amd64.zip",
        "5e4bc3e6b6344b4625de0f7aa5351aaa72856d11d78462972de0a101ee2c1c8f",
        "syft.exe",
    ),
    ("Linux", "x86_64"): (
        f"syft_{SYFT_VERSION}_linux_amd64.tar.gz",
        "8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3",
        "syft",
    ),
    ("Darwin", "arm64"): (
        f"syft_{SYFT_VERSION}_darwin_arm64.tar.gz",
        "ac063af3b9874769deb7ea1e6d76841e68f9e3bb50cd654226fc977de65532c1",
        "syft",
    ),
}

LOG4J_URL = (
    "https://repo1.maven.org/maven2/org/apache/logging/log4j/"
    "log4j-core/2.14.1/log4j-core-2.14.1.jar"
)
LOG4J_SHA256 = "ade7402a70667a727635d5c4c29495f4ff96f061f12539763f6f123973b465b0"

# Windows consoles default to cp1252, which cannot encode the check marks.
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    OK, FAIL = "✓", "✗"
except Exception:  # pragma: no cover - redirected or ancient streams
    OK, FAIL = "[ok]", "[XX]"


def say(mark: str, label: str, detail: str = "") -> None:
    print(f"  {mark} {label:<34} {detail}")


def fetch(url: str, expect_sha256: str) -> bytes:
    print(f"\n  downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "pandax-bootstrap"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        blob = resp.read()
    got = hashlib.sha256(blob).hexdigest()
    if got != expect_sha256:
        say(FAIL, "digest mismatch", f"\n      expected {expect_sha256}\n      got      {got}")
        raise SystemExit("refusing to use an artifact that does not match its pinned digest")
    say(OK, "sha256 verified", f"{got[:16]}... ({len(blob):,} bytes)")
    return blob


def install_syft() -> Path:
    key = (platform.system(), platform.machine())
    if key not in SYFT_BUILDS:
        raise SystemExit(
            f"no pinned syft build for {key}. Add its digest from "
            f"syft_{SYFT_VERSION}_checksums.txt to SYFT_BUILDS."
        )
    asset, digest, binname = SYFT_BUILDS[key]
    dest = TOOLS / binname
    if dest.exists():
        say(OK, "syft already installed", str(dest.relative_to(ROOT)))
        return dest

    url = f"https://github.com/anchore/syft/releases/download/v{SYFT_VERSION}/{asset}"
    blob = fetch(url, digest)
    TOOLS.mkdir(parents=True, exist_ok=True)

    if asset.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            with zf.open(binname) as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out)
    else:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            member = tf.extractfile(binname)
            if member is None:
                raise SystemExit(f"{binname} not found inside {asset}")
            with open(dest, "wb") as out:
                shutil.copyfileobj(member, out)

    dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    say(OK, f"syft v{SYFT_VERSION} installed", str(dest.relative_to(ROOT)))
    return dest


def install_log4j() -> Path:
    dest = FIXTURE / "lib" / "log4j-core-2.14.1.jar"
    if dest.exists() and hashlib.sha256(dest.read_bytes()).hexdigest() == LOG4J_SHA256:
        say(OK, "log4j-core-2.14.1.jar present", str(dest.relative_to(ROOT)))
        return dest
    blob = fetch(LOG4J_URL, LOG4J_SHA256)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(blob)
    say(OK, "log4j-core-2.14.1.jar staged", "CVE-2021-44228 (Log4Shell), in CISA KEV")
    return dest


def build_artifact() -> Path:
    if ARTIFACT.exists():
        ARTIFACT.unlink()
    count = 0
    with zipfile.ZipFile(ARTIFACT, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(FIXTURE.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(FIXTURE).as_posix())
                count += 1
    digest = hashlib.sha256(ARTIFACT.read_bytes()).hexdigest()
    say(OK, f"artifact built ({count} files)", str(ARTIFACT.relative_to(ROOT)))
    say(" ", "artifact sha256", digest)
    return ARTIFACT


def main() -> int:
    print("\nActis by PandaX bootstrap - pinned, digest-verified dependencies")
    print("=" * 72)
    install_syft()
    install_log4j()
    build_artifact()
    print("=" * 72)
    print("\nReady.  Next:  uv run actis scan fixtures/smarthub-sh100-v2.3.1.zip\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
