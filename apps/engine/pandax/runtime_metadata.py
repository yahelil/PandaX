"""Public, non-secret build identity for operations and rollback."""

from __future__ import annotations

import os

from . import __version__


def build_metadata() -> dict[str, str]:
    git_sha = os.environ.get("RENDER_GIT_COMMIT", "unknown")
    release_id = os.environ.get("PANDAX_RELEASE_ID", "").strip()
    if not release_id:
        environment = os.environ.get("PANDAX_ENVIRONMENT", "").strip()
        prefix = "staging" if environment == "staging" else "beta"
        release_id = f"{prefix}-{git_sha[:12]}" if git_sha != "unknown" else "unreleased"
    return {
        "application_version": __version__,
        "git_sha": git_sha,
        "release_id": release_id,
        "build_timestamp": os.environ.get("PANDAX_BUILD_TIMESTAMP", "unknown"),
    }
