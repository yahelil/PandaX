"""Fixture integrity checks run without network, Docker, or Syft."""
import hashlib
import io

import pytest

import test_firmware_integration as fixtures


def test_fixture_cache_is_verified_and_corruption_is_replaced(tmp_path, monkeypatch):
    monkeypatch.setenv("PANDAX_FIRMWARE_CACHE", str(tmp_path))
    spec = {"url": "https://example.invalid/fixture.bin",
            "sha256": hashlib.sha256(b"verified").hexdigest()}
    target = tmp_path / "fixture.bin"
    target.write_bytes(b"corrupted")
    calls = []
    def fetch(*args, **kwargs):
        calls.append(args)
        return io.BytesIO(b"verified")
    monkeypatch.setattr(fixtures, "urlopen", fetch)
    assert fixtures.download_fixture(spec).read_bytes() == b"verified"
    assert fixtures.download_fixture(spec) == target
    assert len(calls) == 1


def test_wrong_download_digest_is_never_cached(tmp_path, monkeypatch):
    monkeypatch.setenv("PANDAX_FIRMWARE_CACHE", str(tmp_path))
    monkeypatch.setattr(fixtures, "urlopen", lambda *a, **k: io.BytesIO(b"wrong"))
    with pytest.raises(AssertionError, match="digest mismatch"):
        fixtures.download_fixture({"url": "https://example.invalid/fixture.bin", "sha256": "0" * 64})
    assert not list(tmp_path.iterdir())


def test_oversized_download_is_bounded_and_never_cached(tmp_path, monkeypatch):
    monkeypatch.setenv("PANDAX_FIRMWARE_CACHE", str(tmp_path))
    class LargeResponse(io.BytesIO):
        def read(self, size):
            assert size == 64 * 1024 * 1024 + 1
            return b"x" * size
    monkeypatch.setattr(fixtures, "urlopen", lambda *a, **k: LargeResponse())
    with pytest.raises(AssertionError, match="download ceiling"):
        fixtures.download_fixture({"url": "https://example.invalid/large.bin", "sha256": "0" * 64})
    assert not list(tmp_path.iterdir())


def test_interrupted_download_does_not_publish_partial_bytes(tmp_path, monkeypatch):
    monkeypatch.setenv("PANDAX_FIRMWARE_CACHE", str(tmp_path))
    class BrokenResponse(io.BytesIO):
        def read(self, size):
            raise OSError("connection interrupted")
    monkeypatch.setattr(fixtures, "urlopen", lambda *a, **k: BrokenResponse())
    with pytest.raises(OSError, match="interrupted"):
        fixtures.download_fixture({"url": "https://example.invalid/broken.bin", "sha256": "0" * 64})
    assert not list(tmp_path.iterdir())
