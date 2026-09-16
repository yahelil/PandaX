from __future__ import annotations

import sys

import pytest
from fastapi.testclient import TestClient

from pandax import document_runtime, runtime_metadata, server
from tools import beta_release


def test_build_endpoint_and_request_correlation(monkeypatch):
    monkeypatch.setenv("RENDER_GIT_COMMIT", "abc123")
    monkeypatch.setenv("PANDAX_RELEASE_ID", "beta-7")
    monkeypatch.setenv("PANDAX_BUILD_TIMESTAMP", "2026-09-16T12:00:00Z")
    client = TestClient(server.api)

    response = client.get("/health/build", headers={"X-Request-ID": "smoke-123"})

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "smoke-123"
    assert response.json() == {
        "application_version": "0.1.0",
        "git_sha": "abc123",
        "release_id": "beta-7",
        "build_timestamp": "2026-09-16T12:00:00Z",
    }
    generated = client.get("/health/live", headers={"X-Request-ID": "unsafe id"})
    assert generated.headers["X-Request-ID"] != "unsafe id"
    assert len(generated.headers["X-Request-ID"]) == 32


@pytest.mark.parametrize("environment", ["staging", "beta"])
def test_build_metadata_derives_environment_release_id(monkeypatch, environment):
    monkeypatch.setenv("RENDER_GIT_COMMIT", "abc123def456789")
    monkeypatch.setenv("PANDAX_ENVIRONMENT", environment)
    monkeypatch.delenv("PANDAX_RELEASE_ID", raising=False)

    assert runtime_metadata.build_metadata()["release_id"] == (
        f"{environment}-abc123def456"
    )


def test_document_runtime_compiles_and_validates_with_pinned_tools(monkeypatch):
    monkeypatch.setitem(sys.modules, "typst", object())
    monkeypatch.setattr(document_runtime, "version", lambda _: document_runtime.PINNED_TYPST_VERSION)
    monkeypatch.setattr(
        document_runtime,
        "_compile",
        lambda source, pdf, root: (pdf.write_bytes(b"%PDF-ready"), "")[1],
    )
    monkeypatch.setattr(
        document_runtime.pdfa,
        "validate_pdf",
        lambda pdf, report, timeout: {
            "compliant": pdf.read_bytes() == b"%PDF-ready",
            "validator_version": document_runtime.pdfa.VERSION,
        },
    )
    document_runtime.require_hosted_document_tools.cache_clear()
    assert document_runtime.require_hosted_document_tools() == {
        "typst": document_runtime.PINNED_TYPST_VERSION,
        "verapdf": document_runtime.pdfa.VERSION,
    }


def test_document_runtime_rejects_wrong_typst(monkeypatch):
    monkeypatch.setitem(sys.modules, "typst", object())
    monkeypatch.setattr(document_runtime, "version", lambda _: "0.0.0")
    document_runtime.require_hosted_document_tools.cache_clear()
    with pytest.raises(RuntimeError, match="Typst"):
        document_runtime.require_hosted_document_tools()


def test_beta_release_guard_requires_complete_beta_configuration(monkeypatch):
    monkeypatch.setenv("PANDAX_ENVIRONMENT", "development")
    with pytest.raises(RuntimeError, match="PANDAX_ENVIRONMENT=beta"):
        beta_release.validate_environment()

    monkeypatch.setenv("PANDAX_ENVIRONMENT", "beta")
    for name in beta_release.REQUIRED:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError, match="PANDAX_DATABASE_URL"):
        beta_release.validate_environment()

    for name in beta_release.REQUIRED:
        monkeypatch.setenv(name, "configured")
    monkeypatch.setenv(
        "PANDAX_DATABASE_URL", "postgresql://actis:secret@db.example/actis"
    )
    assert beta_release.validate_environment().startswith("postgresql+psycopg://")
