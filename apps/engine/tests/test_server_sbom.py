from __future__ import annotations

import json
import shutil

import pytest
from fastapi.testclient import TestClient

from pandax import server


@pytest.fixture(autouse=True)
def reset_job():
    server.CURRENT = None
    yield
    server.CURRENT = None


def valid_sbom() -> bytes:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}
            ],
        }
    ).encode()


def test_upload_preflights_and_starts_sbom_job(monkeypatch):
    captured = {}

    def start(self, artifact, input_type="artifact", cleanup_dir=None):
        captured.update(path=artifact, input_type=input_type)
        self.input_type = input_type
        self.finished = True
        if cleanup_dir:
            shutil.rmtree(cleanup_dir, ignore_errors=True)

    monkeypatch.setattr(server.Job, "start", start)
    response = TestClient(server.api).post(
        "/api/scan/sbom", files={"file": ("from-user.json", valid_sbom(), "application/json")}
    )

    assert response.status_code == 200
    assert response.json()["format"] == "CycloneDX"
    assert captured["input_type"] == "sbom"


def test_upload_rejects_invalid_json():
    response = TestClient(server.api).post(
        "/api/scan/sbom", files={"file": ("bad.json", b"not-json", "application/json")}
    )
    assert response.status_code == 400
    assert "invalid JSON" in response.json()["detail"]


def test_upload_enforces_size_limit(monkeypatch):
    monkeypatch.setattr(server, "MAX_SBOM_BYTES", 8)
    response = TestClient(server.api).post(
        "/api/scan/sbom", files={"file": ("large.json", b"123456789", "application/json")}
    )
    assert response.status_code == 413


def test_upload_rejects_concurrent_run():
    server.CURRENT = server.Job()
    response = TestClient(server.api).post(
        "/api/scan/sbom", files={"file": ("bom.json", valid_sbom(), "application/json")}
    )
    assert response.status_code == 409
