"""Opaque analysis-input storage seam; relational rows retain metadata only."""
from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import quote

import httpx


class AnalysisInputStorageError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class StoredAnalysisInput:
    object_key: str
    sha256: str
    size_bytes: int


class AnalysisInputStorage(Protocol):
    def put(self, organization_id: str, job_id: str, content: bytes) -> StoredAnalysisInput: ...
    def put_bundle(self, organization_id: str, bundle_id: str, content: bytes) -> StoredAnalysisInput: ...
    def put_document(self, organization_id: str, document_id: str, content: bytes, suffix: str) -> StoredAnalysisInput: ...
    def get(self, object_key: str, expected_sha256: str) -> bytes: ...
    def delete(self, object_key: str) -> None: ...
    def check_ready(self) -> None: ...


class MemoryAnalysisInputStorage:
    """Deterministic process-local adapter for tests."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put(self, organization_id: str, job_id: str, content: bytes) -> StoredAnalysisInput:
        key, digest = _key("analysis-inputs", organization_id, job_id, content)
        self.objects[key] = bytes(content)
        return StoredAnalysisInput(key, digest, len(content))

    def put_bundle(self, organization_id: str, bundle_id: str, content: bytes) -> StoredAnalysisInput:
        key, digest = _key("evidence-bundles", organization_id, bundle_id, content, ".zip")
        self.objects[key] = bytes(content)
        return StoredAnalysisInput(key, digest, len(content))

    def put_document(self, organization_id: str, document_id: str, content: bytes, suffix: str) -> StoredAnalysisInput:
        key, digest = _key("documents", organization_id, document_id, content, _suffix(suffix))
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

    def check_ready(self) -> None:
        return None


class LocalAnalysisInputStorage:
    """Local durable adapter with rooted keys and atomic writes."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, organization_id: str, job_id: str, content: bytes) -> StoredAnalysisInput:
        key, digest = _key("analysis-inputs", organization_id, job_id, content)
        return self._put(key, digest, content)

    def put_bundle(self, organization_id: str, bundle_id: str, content: bytes) -> StoredAnalysisInput:
        key, digest = _key("evidence-bundles", organization_id, bundle_id, content, ".zip")
        return self._put(key, digest, content)

    def put_document(self, organization_id: str, document_id: str, content: bytes, suffix: str) -> StoredAnalysisInput:
        key, digest = _key("documents", organization_id, document_id, content, _suffix(suffix))
        return self._put(key, digest, content)

    def _put(self, key: str, digest: str, content: bytes) -> StoredAnalysisInput:
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

    def check_ready(self) -> None:
        if not self.root.is_dir():
            raise AnalysisInputStorageError("local analysis storage is unavailable")

    def _path(self, object_key: str) -> Path:
        candidate = (self.root / object_key).resolve()
        if self.root not in candidate.parents:
            raise AnalysisInputStorageError("unsafe analysis object key")
        return candidate


class SupabaseAnalysisInputStorage:
    """Private Supabase Storage adapter used only through the server boundary."""

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        bucket: str,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key.strip()
        self.bucket = _segment(bucket)
        self.client = client or httpx.Client(timeout=10)

    def put(self, organization_id: str, job_id: str, content: bytes) -> StoredAnalysisInput:
        key, digest = _key("analysis-inputs", organization_id, job_id, content)
        return self._upload(key, digest, content, "application/octet-stream")

    def put_bundle(self, organization_id: str, bundle_id: str, content: bytes) -> StoredAnalysisInput:
        key, digest = _key("evidence-bundles", organization_id, bundle_id, content, ".zip")
        return self._upload(key, digest, content, "application/zip")

    def put_document(self, organization_id: str, document_id: str, content: bytes, suffix: str) -> StoredAnalysisInput:
        key, digest = _key("documents", organization_id, document_id, content, _suffix(suffix))
        return self._upload(key, digest, content, "application/octet-stream")

    def get(self, object_key: str, expected_sha256: str) -> bytes:
        response = self._request(
            "GET",
            f"/storage/v1/object/authenticated/{quote(self.bucket)}/{quote(object_key, safe='/')}",
        )
        if response.status_code == 404:
            raise AnalysisInputStorageError("analysis object not found")
        self._success(response, "download")
        content = response.content
        if hashlib.sha256(content).hexdigest() != expected_sha256:
            raise AnalysisInputStorageError("analysis object digest mismatch")
        return content

    def delete(self, object_key: str) -> None:
        response = self._request(
            "DELETE",
            f"/storage/v1/object/{quote(self.bucket)}",
            json={"prefixes": [object_key]},
        )
        self._success(response, "delete")

    def check_ready(self) -> None:
        response = self._request("GET", f"/storage/v1/bucket/{quote(self.bucket)}")
        self._success(response, "readiness check")
        try:
            public = response.json()["public"]
        except (KeyError, TypeError, ValueError) as exc:
            raise AnalysisInputStorageError("storage readiness response is invalid") from exc
        if public is not False:
            raise AnalysisInputStorageError("managed evidence bucket must be private")

    def _upload(
        self, key: str, digest: str, content: bytes, media_type: str
    ) -> StoredAnalysisInput:
        response = self._request(
            "POST",
            f"/storage/v1/object/{quote(self.bucket)}/{quote(key, safe='/')}",
            content=content,
            headers={"content-type": media_type, "x-upsert": "false"},
        )
        if response.status_code in {400, 409}:
            try:
                existing = self.get(key, digest)
            except AnalysisInputStorageError:
                self._success(response, "upload")
            else:
                return StoredAnalysisInput(key, digest, len(existing))
        self._success(response, "upload")
        return StoredAnalysisInput(key, digest, len(content))

    def _request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        headers = {
            "apikey": self.api_key,
            "authorization": f"Bearer {self.api_key}",
            **dict(kwargs.pop("headers", {})),
        }
        try:
            return self.client.request(method, f"{self.endpoint}{path}", headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise AnalysisInputStorageError("managed evidence storage is unavailable") from exc

    @staticmethod
    def _success(response: httpx.Response, action: str) -> None:
        if not response.is_success:
            raise AnalysisInputStorageError(
                f"managed evidence storage {action} failed ({response.status_code})"
            )


def _suffix(value: str) -> str:
    """A file extension, or nothing. Keys are content-addressed, so this is a
    convenience for whoever looks in the bucket, never part of the identity."""
    clean = value.strip()
    if not clean:
        return ""
    if not re.fullmatch(r"\.[A-Za-z0-9]{1,12}", clean):
        raise AnalysisInputStorageError("invalid storage object suffix")
    return clean


def _segment(value: str) -> str:
    clean = value.strip()
    if not clean or not re.fullmatch(r"[A-Za-z0-9._-]{1,160}", clean):
        raise AnalysisInputStorageError("invalid analysis storage scope")
    return clean


def _key(
    namespace: str,
    organization_id: str,
    object_id: str,
    content: bytes,
    suffix: str = "",
) -> tuple[str, str]:
    digest = hashlib.sha256(content).hexdigest()
    return (
        f"{namespace}/{_segment(organization_id)}/{_segment(object_id)}/{digest}{suffix}",
        digest,
    )
