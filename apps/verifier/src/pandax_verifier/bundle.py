from __future__ import annotations

import hashlib
import re
import stat
import zipfile
from abc import ABC, abstractmethod
from pathlib import Path, PurePosixPath
from typing import BinaryIO

MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 20_000
MAX_DEPTH = 24
_DRIVE_PATH = re.compile(r"^[A-Za-z]:")


class BundleError(ValueError):
    """The supplied bundle cannot be read safely."""


def normalize_bundle_path(value: str) -> str:
    if not value or "\x00" in value:
        raise BundleError("Bundle contains an empty or malformed path")
    if "\\" in value:
        raise BundleError(f"Bundle path uses a backslash: {value!r}")
    if "//" in value:
        raise BundleError(f"Bundle contains an empty path component: {value!r}")
    if value.startswith("/") or value.startswith("//") or _DRIVE_PATH.match(value):
        raise BundleError(f"Bundle contains an absolute path: {value!r}")

    path = PurePosixPath(value)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise BundleError(f"Bundle contains an unsafe path: {value!r}")
    if len(path.parts) > MAX_DEPTH:
        raise BundleError(f"Bundle path is deeper than {MAX_DEPTH} levels: {value!r}")
    return path.as_posix()


class BundleReader(ABC):
    source: Path

    def __enter__(self) -> "BundleReader":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        return None

    @abstractmethod
    def files(self) -> tuple[str, ...]:
        raise NotImplementedError

    @abstractmethod
    def open_file(self, name: str) -> BinaryIO:
        raise NotImplementedError

    def exists(self, name: str) -> bool:
        return name in self.files()

    def read_bytes(self, name: str) -> bytes:
        try:
            with self.open_file(name) as handle:
                return handle.read()
        except KeyError as exc:
            raise BundleError(f"Required file is missing: {name}") from exc
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise BundleError(f"Could not read {name}: {exc}") from exc

    def sha256(self, name: str) -> str:
        digest = hashlib.sha256()
        try:
            with self.open_file(name) as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        except KeyError as exc:
            raise BundleError(f"Required file is missing: {name}") from exc
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise BundleError(f"Could not read {name}: {exc}") from exc
        return digest.hexdigest()


class DirectoryBundle(BundleReader):
    def __init__(self, source: Path) -> None:
        self.source = source.resolve()
        found: dict[str, Path] = {}
        seen_casefolded: set[str] = set()
        total_bytes = 0

        try:
            paths = sorted(self.source.rglob("*"))
        except OSError as exc:
            raise BundleError(f"Could not inspect bundle directory: {exc}") from exc

        for path in paths:
            if path.is_symlink():
                raise BundleError(f"Bundle contains a symbolic link: {path.name}")
            if not path.is_file():
                continue
            try:
                relative = path.relative_to(self.source).as_posix()
                normalized = normalize_bundle_path(relative)
                size = path.stat().st_size
            except (OSError, ValueError) as exc:
                raise BundleError(f"Could not inspect bundle entry: {path}") from exc

            folded = normalized.casefold()
            if folded in seen_casefolded:
                raise BundleError(f"Bundle contains duplicate or case-colliding paths: {normalized}")
            seen_casefolded.add(folded)
            found[normalized] = path
            total_bytes += size

            if len(found) > MAX_ENTRIES:
                raise BundleError(f"Bundle contains more than {MAX_ENTRIES} files")
            if total_bytes > MAX_TOTAL_BYTES:
                raise BundleError(f"Bundle exceeds the {MAX_TOTAL_BYTES}-byte safety limit")

        self._files = found

    def files(self) -> tuple[str, ...]:
        return tuple(sorted(self._files))

    def open_file(self, name: str) -> BinaryIO:
        normalized = normalize_bundle_path(name)
        path = self._files[normalized]
        resolved = path.resolve()
        try:
            resolved.relative_to(self.source)
        except ValueError as exc:
            raise BundleError(f"Bundle entry escapes its directory: {name}") from exc
        return resolved.open("rb")


class ZipBundle(BundleReader):
    def __init__(self, source: Path) -> None:
        self.source = source.resolve()
        try:
            self._archive = zipfile.ZipFile(self.source, "r")
            infos = self._archive.infolist()
        except (OSError, zipfile.BadZipFile) as exc:
            raise BundleError(f"Could not open ZIP bundle: {exc}") from exc

        found: dict[str, zipfile.ZipInfo] = {}
        seen_casefolded: set[str] = set()
        total_bytes = 0

        try:
            for info in infos:
                normalized = normalize_bundle_path(info.filename.rstrip("/"))
                folded = normalized.casefold()
                if folded in seen_casefolded:
                    raise BundleError(
                        f"ZIP contains duplicate or case-colliding paths: {normalized}"
                    )
                seen_casefolded.add(folded)

                unix_mode = (info.external_attr >> 16) & 0o170000
                if unix_mode == stat.S_IFLNK:
                    raise BundleError(f"ZIP contains a symbolic link: {normalized}")
                if info.flag_bits & 0x1:
                    raise BundleError(f"ZIP contains an encrypted entry: {normalized}")
                if info.is_dir():
                    continue

                found[normalized] = info
                total_bytes += info.file_size
                if len(found) > MAX_ENTRIES:
                    raise BundleError(f"ZIP contains more than {MAX_ENTRIES} files")
                if total_bytes > MAX_TOTAL_BYTES:
                    raise BundleError(f"ZIP exceeds the {MAX_TOTAL_BYTES}-byte safety limit")
        except Exception:
            self._archive.close()
            raise

        self._files = found

    def close(self) -> None:
        self._archive.close()

    def files(self) -> tuple[str, ...]:
        return tuple(sorted(self._files))

    def open_file(self, name: str) -> BinaryIO:
        normalized = normalize_bundle_path(name)
        return self._archive.open(self._files[normalized], "r")


def open_bundle(source: str | Path) -> BundleReader:
    path = Path(source)
    if path.is_dir():
        return DirectoryBundle(path)
    if not path.is_file():
        raise BundleError(f"Bundle does not exist: {path}")
    if not zipfile.is_zipfile(path):
        raise BundleError("Bundle must be a directory or a valid ZIP file")
    return ZipBundle(path)
