from pathlib import Path
from subprocess import CompletedProcess

import pytest

from pandax import artifact_runtime


def test_hosted_scanner_requires_pinned_version(monkeypatch):
    monkeypatch.setattr(artifact_runtime, "syft_binary", lambda: Path("syft"))
    monkeypatch.setattr(
        artifact_runtime.subprocess, "run",
        lambda *args, **kwargs: CompletedProcess(args, 0, "syft 1.51.1\n", ""),
    )
    assert artifact_runtime.require_hosted_scanner() == {"name": "syft", "version": "1.51.1"}
    monkeypatch.setattr(
        artifact_runtime.subprocess, "run",
        lambda *args, **kwargs: CompletedProcess(args, 0, "syft 1.50.0\n", ""),
    )
    with pytest.raises(RuntimeError, match="version"):
        artifact_runtime.require_hosted_scanner()


def test_hosted_scanner_missing_fails_closed(monkeypatch):
    def missing():
        raise FileNotFoundError("syft")

    monkeypatch.setattr(artifact_runtime, "syft_binary", missing)
    with pytest.raises(RuntimeError, match="unavailable"):
        artifact_runtime.require_hosted_scanner()
