"""Read a stored document revision back as bytes.

`documents` deliberately holds metadata only, so this is the seam where a
revision row meets the object store. It stays out of that module for the same
reason the module says so itself: the repository should keep working in
deployments that have no bucket at all.

The digest is checked on the way out. A row that describes bytes we cannot
reproduce is a failure worth surfacing, not a download worth serving.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol


class DocumentContentUnavailable(RuntimeError):
    """The revision exists, but its bytes could not be produced."""


class ContentStorage(Protocol):
    def get(self, object_key: str, expected_sha256: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class DocumentContent:
    content: bytes
    content_type: str
    filename: str
    content_hash: str
    size_bytes: int


# A document name is free text up to 240 characters and it reaches the
# Content-Disposition header. Anything outside this set is replaced rather
# than escaped, because a quote or a newline in that header is a way to
# inject one of your own.
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(value: str, *, fallback: str = "document") -> str:
    """A filename a header can carry verbatim."""
    cleaned = _UNSAFE.sub("-", value).strip("-.")
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    if not cleaned or set(cleaned) <= {"-", "."}:
        return fallback
    return cleaned[:120]


def content_disposition(filename: str) -> str:
    return f'attachment; filename="{safe_filename(filename)}"'


def read_document_content(
    repository: Any,
    storage: ContentStorage,
    organization_id: str,
    document_id: str,
    revision: int,
) -> DocumentContent:
    """Fetch the bytes this revision describes, or say why not."""
    metadata = repository.download_metadata(organization_id, document_id, revision)
    locator = str(metadata["storage_locator"])
    expected = str(metadata["content_hash"])
    if not locator:
        raise DocumentContentUnavailable("this revision has no stored object")
    try:
        content = storage.get(locator, expected)
    except Exception as exc:                       # adapters raise their own types
        raise DocumentContentUnavailable("document content could not be read") from exc
    if len(content) != int(metadata["size_bytes"]):
        raise DocumentContentUnavailable("stored object does not match the recorded size")
    return DocumentContent(
        content=content,
        content_type=str(metadata["content_type"]),
        filename=safe_filename(str(metadata["filename"])),
        content_hash=expected,
        size_bytes=len(content),
    )
