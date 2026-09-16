from __future__ import annotations

import io
import json
import stat
import tarfile
import zipfile
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from pandax import collector
from pandax.collector_cli import app
from pandax.evidence import verify_bundle


@pytest.fixture(autouse=True)
def local_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("PANDAX_COLLECTOR_WORKSPACE", str(tmp_path / "local-work"))


def key_file(root: Path) -> Path:
    key = Ed25519PrivateKey.generate()
    path = root / "customer-key.pem"
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return path


def sbom(kind: str) -> dict:
    if kind.startswith("CycloneDX"):
        return {"bomFormat": "CycloneDX", "specVersion": kind.split(" ")[1],
                "components": [{"type": "library", "name": "test-lib", "version": "1.0",
                                "purl": "pkg:generic/test-lib@1.0"}]}
    return {"spdxVersion": kind, "name": "Sample", "packages": [
        {"name": "test-lib", "versionInfo": "1.0", "SPDXID": "SPDXRef-test",
         "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:generic/test-lib@1.0"}],
         }], "creationInfo": {"created": "2026-09-15T00:00:00Z"}}


def collect(source: Path, tmp_path: Path, **changes):
    values = {"organization_id": "org-1", "product_id": "product-1",
              "release_id": "release-1", "signing_key": key_file(tmp_path),
              "workspace": tmp_path / "work"}
    values.update(changes)
    output = tmp_path / "customer-package.zip"
    return collector.collect(source, output, **values)


@pytest.mark.parametrize("kind", ["CycloneDX 1.2", "CycloneDX 1.6", "SPDX-2.2", "SPDX-2.3"])
def test_supported_json_inputs_export_only_minimized_signed_evidence(tmp_path, kind):
    source = tmp_path / "source.json"
    document = sbom(kind)
    document["unwanted_raw_property"] = "-----BEGIN PRIVATE KEY----- secret material"
    source.write_text(json.dumps(document), encoding="utf-8")
    preview = collect(source, tmp_path)
    assert preview["summary"]["status"] == "inventory_complete"
    assert set(preview["files"]) == collector.PACKAGE_FILES
    with zipfile.ZipFile(preview["package"]) as archive:
        assert set(archive.namelist()) == collector.PACKAGE_FILES
        payload = b"".join(archive.read(name) for name in archive.namelist())
        assert b"PRIVATE KEY" not in payload and b"unwanted_raw_property" not in payload
        assert b"source.json" not in payload
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["organization_id"] == "org-1" and manifest["release_id"] == "release-1"
    inspection = collector.inspect_package(Path(preview["package"]))
    assert inspection["integrity_ok"] and inspection["signature_valid"]


@pytest.mark.parametrize("kind", ["directory", "zip", "tar"])
def test_filesystem_and_archive_inputs_use_bounded_shared_core(tmp_path, monkeypatch, kind):
    monkeypatch.setattr(collector, "_scan_syft", lambda source, syft, output: sbom("CycloneDX 1.6"))
    syft = tmp_path / "syft.exe"
    syft.write_bytes(b"test stub")
    if kind == "directory":
        source = tmp_path / "raw"
        source.mkdir()
        (source / "component.txt").write_text("raw local content", encoding="utf-8")
    elif kind == "zip":
        source = tmp_path / "raw.zip"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("component.txt", "raw local content")
    else:
        source = tmp_path / "raw.tar"
        with tarfile.open(source, "w") as archive:
            data = b"raw local content"
            member = tarfile.TarInfo("component.txt")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    preview = collect(source, tmp_path, syft=syft)
    assert preview["coverage"]["input_kind"] == ("directory" if kind == "directory" else "archive")
    assert preview["coverage"]["files_seen"] == 1
    with zipfile.ZipFile(preview["package"]) as archive:
        assert b"raw local content" not in b"".join(archive.read(name) for name in archive.namelist())


def test_links_traversal_and_duplicate_archive_paths_are_refused(tmp_path):
    source = tmp_path / "bad.zip"
    for writer in (
        lambda archive: archive.writestr("../escape", "data"),
        lambda archive: (archive.writestr("same", "one"), archive.writestr("same", "two")),
        lambda archive: archive.writestr(zip_symlink("link"), "target"),
    ):
        with zipfile.ZipFile(source, "w") as archive:
            writer(archive)
        with pytest.raises(collector.CollectorError, match="inconclusive extraction"):
            collect(source, tmp_path)
    source_tar = tmp_path / "bad.tar"
    with tarfile.open(source_tar, "w") as archive:
        member = tarfile.TarInfo("link")
        member.type = tarfile.SYMTYPE
        member.linkname = "secret"
        archive.addfile(member)
    with pytest.raises(collector.CollectorError, match="inconclusive extraction"):
        collect(source_tar, tmp_path)


def zip_symlink(name: str) -> zipfile.ZipInfo:
    member = zipfile.ZipInfo(name)
    member.external_attr = (stat.S_IFLNK | 0o777) << 16
    return member


def test_malformed_and_partial_sboms_are_inconclusive(tmp_path):
    source = tmp_path / "source.json"
    source.write_text("{not json", encoding="utf-8")
    with pytest.raises(collector.CollectorError, match="malformed"):
        collect(source, tmp_path)
    source.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
                                  "components": [{"name": "unidentified"}]}), encoding="utf-8")
    with pytest.raises(collector.CollectorError, match="inconclusive"):
        collect(source, tmp_path)
    source.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
                                  "components": [{"name": "unidentified"}, sbom("CycloneDX 1.6")["components"][0]]}), encoding="utf-8")
    preview = collect(source, tmp_path)
    assert preview["coverage"]["status"] == "inconclusive"
    assert preview["summary"]["status"] == "inconclusive"


def test_collector_requires_explicit_customer_key_and_never_falls_back(tmp_path):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(sbom("CycloneDX 1.6")), encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        collector.collect(source, tmp_path / "out.zip", organization_id="org-1",
                          product_id="product-1", release_id="release-1",
                          signing_key=tmp_path / "missing.pem", workspace=tmp_path / "work")


def test_private_key_material_cannot_enter_package(tmp_path):
    source = tmp_path / "source.json"
    document = sbom("CycloneDX 1.6")
    document["components"][0]["name"] = "-----BEGIN PRIVATE KEY-----"
    source.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(collector.CollectorError, match="private-key"):
        collect(source, tmp_path)


def test_upload_preview_approval_and_retry_are_explicit(tmp_path, monkeypatch):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(sbom("CycloneDX 1.6")), encoding="utf-8")
    package = Path(collect(source, tmp_path)["package"])
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(201, json={"id": "job-1", "status": "queued"})

    real_client = httpx.Client
    monkeypatch.setattr(collector.httpx, "Client", lambda timeout: real_client(transport=httpx.MockTransport(handler), timeout=timeout))
    runner = CliRunner()
    denied = runner.invoke(app, ["upload", str(package), "--base-url", "http://localhost:8000"], input="n\n")
    assert denied.exit_code == 0 and not requests
    monkeypatch.setenv("PANDAX_ACCESS_TOKEN", "secret-token")
    accepted = runner.invoke(app, ["upload", str(package), "--base-url", "http://localhost:8000", "--approve-upload"])
    assert accepted.exit_code == 0 and "secret-token" not in accepted.output
    collector.upload(package, base_url="http://localhost:8000", token="secret-token")
    assert len(requests) == 2
    assert requests[0].headers["Idempotency-Key"] == requests[1].headers["Idempotency-Key"]
    assert requests[0].headers["Authorization"] == "Bearer secret-token"
