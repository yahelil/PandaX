"""Opaque analysis-input storage seam; relational rows retain metadata only."""
from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class AnalysisInputStorageError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class StoredAnalysisInput:
    object_key: str
    sha256: str
    size_bytes: int


class AnalysisInputStorage(Protocol):
    def put(self, organization_id: str, job_id: str, content: bytes) -> StoredAnalysisInput: ...
    def get(self, object_key: str, expected_sha256: str) -> bytes: ...
    def delete(self, object_key: str) -> None: ...


class MemoryAnalysisInputStorage:
    """Deterministic process-local adapter for tests."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put(self, organization_id: str, job_id: str, content: bytes) -> StoredAnalysisInput:
        digest = hashlib.sha256(content).hexdigest()
        key = f"analysis-inputs/{_segment(organization_id)}/{_segment(job_id)}/{digest}"
        self.objects[key] = bytes(content)
        return StoredAnalysisInput(key, digest, len(content))

    def get(self, object_key: str, expected_sha256: str) -> bytes:
        try:
            content = self.objects[object_key]
        except KeyError as exc:
            raise AnalysisInputStorageError("analysis input object not found") from exc
        if hashlib.sha256(content).hexdigest() != expected_sha256:
            raise AnalysisInputStorageError("analysis input digest mismatch")
        return bytes(content)

    def delete(self, object_key: str) -> None:
        self.objects.pop(object_key, None)


class LocalAnalysisInputStorage:
    """Local durable adapter with rooted keys and atomic writes."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, organization_id: str, job_id: str, content: bytes) -> StoredAnalysisInput:
        digest = hashlib.sha256(content).hexdigest()
        key = f"analysis-inputs/{_segment(organization_id)}/{_segment(job_id)}/{digest}"
        target = self._path(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(prefix=".upload-", dir=target.parent)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return StoredAnalysisInput(key, digest, len(content))

    def get(self, object_key: str, expected_sha256: str) -> bytes:
        path = self._path(object_key)
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise AnalysisInputStorageError("analysis input object unavailable") from exc
        if hashlib.sha256(content).hexdigest() != expected_sha256:
            raise AnalysisInputStorageError("analysis input digest mismatch")
        return content

    def delete(self, object_key: str) -> None:
        self._path(object_key).unlink(missing_ok=True)

    def _path(self, object_key: str) -> Path:
        candidate = (self.root / object_key).resolve()
        if self.root not in candidate.parents:
            raise AnalysisInputStorageError("unsafe analysis object key")
        return candidate


def _segment(value: str) -> str:
    clean = value.strip()
    if not clean or not re.fullmatch(r"[A-Za-z0-9._-]{1,160}", clean):
        raise AnalysisInputStorageError("invalid analysis storage scope")
    return clean
