"""Customer-side, inventory-only Collector packages for Windows x64."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .evidence import Ledger, sha256_file, verify_bundle, write_manifest
from .stages.ingest import MAX_DEPTH, MAX_ENTRIES, MAX_TOTAL_BYTES, UnsafeArtifact, extract
from .stages.sbom import SbomError, is_matchable_purl, normalise_document

COLLECTOR_VERSION = "0.1.0"
SYFT_VERSION = "1.51.1"
PACKAGE_FILES = {
    "manifest.json", "manifest.sig", "pubkey.pem", "ledger.jsonl",
    "sbom.cdx.json", "coverage.json", "collection-summary.json",
}
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class CollectorError(ValueError):
    pass


def _working_root(configured: Path | None = None) -> Path:
    root = configured or Path(os.environ.get("PANDAX_COLLECTOR_WORKSPACE", Path.home() / ".pandax" / "collector"))
    root = Path(root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _private_key(path: Path) -> Ed25519PrivateKey:
    path = Path(path).expanduser().resolve(strict=True)
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (TypeError, ValueError) as exc:
        raise CollectorError("customer signing key must be an unencrypted Ed25519 PEM") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise CollectorError("customer signing key must be Ed25519")
    return key


def _syft_binary(configured: Path | None = None) -> Path:
    candidates = []
    if configured:
        candidates.append(Path(configured))
    if os.environ.get("PANDAX_SYFT_BIN"):
        candidates.append(Path(os.environ["PANDAX_SYFT_BIN"]))
    if getattr(sys, "frozen", False):
        candidates.append(Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "syft.exe")
    candidates.append(Path(__file__).resolve().parents[3] / "workspace" / "tools" / "syft.exe")
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise CollectorError("pinned Windows Syft executable is missing")


def _is_link(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _check_tree(root: Path) -> tuple[int, int, str]:
    """Reject links, reparse points, unusual files and oversized directory trees."""
    count = total = 0
    digest = hashlib.sha256()
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        if _is_link(current_path):
            raise CollectorError("directory input contains a link or reparse point")
        if len(current_path.relative_to(root).parts) > MAX_DEPTH:
            raise CollectorError("directory input exceeds the depth limit")
        for name in sorted(directories + files):
            child = current_path / name
            if _is_link(child):
                raise CollectorError("directory input contains a link or reparse point")
            if not child.is_file() and not child.is_dir():
                raise CollectorError("directory input contains a special file")
        for name in sorted(files):
            path = current_path / name
            count += 1
            total += path.stat().st_size
            if count > MAX_ENTRIES or total > MAX_TOTAL_BYTES:
                raise CollectorError("directory input exceeds file or size limits")
            digest.update(path.relative_to(root).as_posix().encode("utf-8"))
            digest.update(bytes.fromhex(sha256_file(path)))
    return count, total, digest.hexdigest()


def _project_sbom(document: dict[str, Any]) -> tuple[dict[str, Any], int, int]:
    normalised, product, _, _ = normalise_document(document)
    components = []
    for item in normalised["components"]:
        component = {field: item[field] for field in ("type", "name", "version", "purl", "bom-ref") if field in item}
        components.append(component)
    matchable = sum(is_matchable_purl(item.get("purl")) for item in components)
    if not matchable:
        raise CollectorError("inconclusive inventory: no component has a usable versioned purl")
    minimal: dict[str, Any] = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "components": components,
    }
    product_name = product.get("product", {}).get("name")
    if product_name:
        minimal["metadata"] = {"component": {"type": "application", "name": product_name}}
    return minimal, matchable, len(components) - matchable


def _scan_syft(source: Path, syft: Path, output: Path) -> dict[str, Any]:
    version = subprocess.run([str(syft), "--version"], capture_output=True, text=True, timeout=60)
    if version.returncode or not version.stdout.strip().endswith(SYFT_VERSION):
        raise CollectorError("inconclusive inventory: Syft is not the pinned Windows release")
    environment = {key: value for key, value in os.environ.items()
                   if not any(marker in key.upper() for marker in ("TOKEN", "SECRET", "PASSWORD", "PRIVATE_KEY"))}
    environment["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
    result = subprocess.run(
        [str(syft), "scan", f"dir:{source}", "-o", f"cyclonedx-json@1.6={output}", "-q"],
        capture_output=True, text=True, timeout=900, env=environment,
    )
    if result.returncode or not output.is_file():
        raise CollectorError("inconclusive inventory: Syft could not complete the scan")
    try:
        document = json.loads(output.read_text(encoding="utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectorError("inconclusive inventory: Syft returned invalid JSON") from exc
    if not isinstance(document, dict):
        raise CollectorError("inconclusive inventory: Syft returned invalid JSON")
    return document


def _source_inventory(source: Path, work: Path, syft: Path | None) -> tuple[dict[str, Any], dict[str, Any], str]:
    source = source.expanduser().resolve(strict=True)
    if source.is_dir():
        count, total, digest = _check_tree(source)
        if count == 0:
            raise CollectorError("inconclusive inventory: input directory is empty")
        target = work / "syft.json"
        return _scan_syft(source, _syft_binary(syft), target), {"input_kind": "directory", "files_seen": count, "bytes_seen": total}, digest
    if source.stat().st_size > MAX_TOTAL_BYTES:
        raise CollectorError("input exceeds the size limit")
    digest = sha256_file(source)
    if source.suffix.lower() == ".json":
        try:
            document = json.loads(source.read_text(encoding="utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CollectorError("malformed JSON SBOM") from exc
        if not isinstance(document, dict):
            raise CollectorError("malformed JSON SBOM")
        return document, {"input_kind": "sbom", "files_seen": 1, "bytes_seen": source.stat().st_size}, digest
    if not (zipfile.is_zipfile(source) or tarfile.is_tarfile(source)):
        raise CollectorError("unsupported input; Windows beta accepts directories, ZIP/TAR and JSON SBOMs")
    extracted = work / "extracted"
    try:
        count, total = extract(source, extracted)
        _check_tree(extracted)
    except (UnsafeArtifact, OSError, zipfile.BadZipFile, tarfile.TarError) as exc:
        raise CollectorError(f"inconclusive extraction: {exc}") from exc
    if count == 0:
        raise CollectorError("inconclusive extraction: archive has no regular files")
    target = work / "syft.json"
    return _scan_syft(extracted, _syft_binary(syft), target), {"input_kind": "archive", "files_seen": count, "bytes_seen": total}, digest


def collect(
    source: Path, destination: Path, *, organization_id: str, product_id: str,
    release_id: str, signing_key: Path, syft: Path | None = None,
    workspace: Path | None = None,
) -> dict[str, Any]:
    """Produce a minimal, signed package. Source and working files stay local."""
    if not all(IDENTIFIER.fullmatch(value) for value in (organization_id, product_id, release_id)):
        raise CollectorError("organization, product and release IDs are required")
    source = Path(source).expanduser().resolve(strict=True)
    destination = Path(destination).expanduser().resolve()
    if source.is_dir() and destination.is_relative_to(source):
        raise CollectorError("package destination must be outside the scanned directory")
    key = _private_key(signing_key)
    with tempfile.TemporaryDirectory(prefix="collect-", dir=_working_root(workspace)) as temporary:
        work = Path(temporary)
        try:
            document, coverage, source_digest = _source_inventory(source, work, syft)
            sbom, matchable, skipped = _project_sbom(document)
        except SbomError as exc:
            raise CollectorError(f"inconclusive inventory: {exc}") from exc
        bundle = work / "package"
        bundle.mkdir()
        (bundle / "sbom.cdx.json").write_text(json.dumps(sbom, ensure_ascii=False, indent=2), encoding="utf-8")
        coverage.update({
            "schema": "actis/collector-coverage/v1",
            "status": "inconclusive" if skipped else "inventory_complete",
            "components": len(sbom["components"]), "matchable_components": matchable,
            "unmatchable_components": skipped,
            "extraction": "completed", "vulnerability_assessment": "not_performed",
        })
        summary = {
            "schema": "actis/collection-summary/v1", "status": coverage["status"],
            "limitations": ["Inventory only; hosted analysis has not run"] + ([f"{skipped} components lack a versioned purl"] if skipped else []),
            "tool": {"collector": COLLECTOR_VERSION, "syft": SYFT_VERSION if coverage["input_kind"] != "sbom" else "not_used"},
            "rules": {"identifier": "pandax-sbom-normalisation/1"},
        }
        (bundle / "coverage.json").write_text(json.dumps(coverage, indent=2), encoding="utf-8")
        (bundle / "collection-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        ledger = Ledger(bundle)
        ledger.append("COLLECT", "actis-collector", COLLECTOR_VERSION, [], [
            ledger.ref(bundle / "sbom.cdx.json"), ledger.ref(bundle / "coverage.json"),
            ledger.ref(bundle / "collection-summary.json"),
        ], {"source_sha256": source_digest, "input_kind": coverage["input_kind"]})
        try:
            manifest = write_manifest(bundle, f"collector-{uuid.uuid4()}", {}, summary["tool"], ledger, key, extensions={
                "organization_id": organization_id, "product_id": product_id,
                "release_id": release_id, "collector": {"name": "Actis Collector", "version": COLLECTOR_VERSION},
                "sbom_path": "sbom.cdx.json", "source_digest": source_digest,
                "rules_version": summary["rules"]["identifier"],
            })
        except ValueError as exc:
            raise CollectorError("package contains prohibited private-key material") from exc
        verified = verify_bundle(bundle, key.public_key())
        if not verified.ok:
            raise CollectorError("offline package verification failed")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(bundle.iterdir()):
                archive.write(path, path.name)
    if destination.stat().st_size > 25 * 1024 * 1024:
        destination.unlink()
        raise CollectorError("Collector package exceeds the hosted 25 MB limit")
    return {"package": str(destination), "sha256": sha256_file(destination),
            "files": sorted(PACKAGE_FILES), "summary": summary, "coverage": coverage,
            "manifest": {field: manifest[field] for field in ("organization_id", "product_id", "release_id", "collector")}}


def inspect_package(package: Path) -> dict[str, Any]:
    package = Path(package).expanduser().resolve(strict=True)
    if package.stat().st_size > 25 * 1024 * 1024:
        raise CollectorError("Collector package exceeds upload size limit")
    with zipfile.ZipFile(package) as archive:
        entries = archive.infolist()
        if {item.filename for item in entries} != PACKAGE_FILES or len(entries) != len(PACKAGE_FILES):
            raise CollectorError("Collector package contains missing or additional files")
        if any(item.is_dir() or item.file_size > 100 * 1024 * 1024 or
               (item.file_size and (not item.compress_size or item.file_size / item.compress_size > 100)) for item in entries):
            raise CollectorError("Collector package violates ZIP safety limits")
        with tempfile.TemporaryDirectory(prefix="verify-", dir=_working_root()) as temporary:
            root = Path(temporary)
            for item in entries:
                (root / item.filename).write_bytes(archive.read(item))
            verified = verify_bundle(root)
            if not verified.integrity_ok or not verified.signature_valid:
                raise CollectorError("Collector package integrity or signature is invalid")
            manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            summary = json.loads((root / "collection-summary.json").read_text(encoding="utf-8"))
            coverage = json.loads((root / "coverage.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != "actis/manifest/v1":
        raise CollectorError("unsupported Collector manifest")
    if not all(IDENTIFIER.fullmatch(str(manifest.get(field, "")))
               for field in ("organization_id", "product_id", "release_id")):
        raise CollectorError("Collector package has an invalid organization/product/release binding")
    identity = manifest.get("collector")
    if (not isinstance(identity, dict) or identity.get("name") != "Actis Collector"
            or identity.get("version") != COLLECTOR_VERSION
            or manifest.get("sbom_path") != "sbom.cdx.json"):
        raise CollectorError("Collector package identity is invalid")
    return {"package": str(package), "sha256": sha256_file(package),
            "files": sorted(PACKAGE_FILES), "manifest": {field: manifest.get(field) for field in ("organization_id", "product_id", "release_id", "collector")},
            "summary": summary, "coverage": coverage,
            "integrity_ok": verified.integrity_ok, "signature_valid": verified.signature_valid,
            "signer_trust": "verified by the hosted organization key registry at upload"}


def upload(package: Path, *, base_url: str, token: str, idempotency_key: str | None = None) -> dict[str, Any]:
    preview = inspect_package(package)
    if not token:
        raise CollectorError("a short-lived bearer token is required")
    if not base_url.startswith("https://") and not base_url.startswith(("http://localhost", "http://127.0.0.1")):
        raise CollectorError("hosted Collector upload requires HTTPS")
    binding = preview["manifest"]
    url = (base_url.rstrip("/") + "/v1/organizations/" + binding["organization_id"] +
           "/products/" + binding["product_id"] + "/releases/" + binding["release_id"] +
           "/analysis-jobs/inputs")
    key = idempotency_key or preview["sha256"]
    try:
        with Path(package).open("rb") as stream, httpx.Client(timeout=120) as client:
            response = client.post(url, headers={"Authorization": f"Bearer {token}", "Idempotency-Key": key},
                                   data={"input_type": "collector"},
                                   files={"file": (Path(package).name, stream, "application/zip")})
    except httpx.RequestError as exc:
        raise CollectorError("Collector upload could not reach the hosted endpoint; retry the same package") from exc
    if response.status_code not in {200, 201}:
        raise CollectorError(f"Collector upload rejected with HTTP {response.status_code}")
    return response.json()
