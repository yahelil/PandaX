"""Required scanner dependency for hosted artifact analysis."""

from __future__ import annotations

import subprocess

from .context import syft_binary

PINNED_SYFT_VERSION = "1.51.1"


def require_hosted_scanner() -> dict[str, str]:
    try:
        binary = syft_binary()
        result = subprocess.run(
            [str(binary), "--version"], capture_output=True, text=True,
            timeout=15, check=True,
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("pinned Syft scanner is unavailable") from exc
    version = result.stdout.strip().removeprefix("syft ").split()[0:1]
    if version != [PINNED_SYFT_VERSION]:
        raise RuntimeError("pinned Syft scanner version does not match the beta image")
    return {"name": "syft", "version": PINNED_SYFT_VERSION}
