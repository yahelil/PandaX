from __future__ import annotations

import zipfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.collector_release import package, sign, verify


def test_windows_release_contains_collector_and_syft_and_has_detached_seal(tmp_path, monkeypatch):
    directory = tmp_path / "actis-collector"
    directory.mkdir()
    (directory / "actis-collector.exe").write_bytes(b"collector")
    (directory / "syft.exe").write_bytes(b"pinned syft")
    output = tmp_path / "actis-collector-windows-x64.zip"
    key = Ed25519PrivateKey.generate()
    monkeypatch.setenv("COLLECTOR_RELEASE_SIGNING_KEY_PEM", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii"))

    package(directory, output)
    sign(output)

    with zipfile.ZipFile(output) as archive:
        assert set(archive.namelist()) == {
            "actis-collector/actis-collector.exe", "actis-collector/syft.exe",
        }
    public_key = output.with_name(output.name + ".release-pubkey.pem")
    assert verify(output, public_key)
    output.write_bytes(output.read_bytes() + b"tampered")
    assert not verify(output, public_key)


def test_windows_release_refuses_missing_bundled_dependency(tmp_path):
    directory = tmp_path / "actis-collector"
    directory.mkdir()
    (directory / "actis-collector.exe").write_bytes(b"collector")
    with pytest.raises(ValueError, match="Syft"):
        package(directory, tmp_path / "release.zip")
