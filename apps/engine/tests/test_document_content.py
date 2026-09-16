from __future__ import annotations

import hashlib
from datetime import date

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool

from pandax.analysis_storage import MemoryAnalysisInputStorage
from pandax.auth import Principal, Role
from pandax.document_content import (
    DocumentContentUnavailable, content_disposition, read_document_content, safe_filename,
)
from pandax.documents import DocumentRepository
from pandax.documents_api import create_documents_router
from pandax.portfolio import PortfolioRepository, create_portfolio_engine

BODY = b'{"report": "release"}\n'
DIGEST = hashlib.sha256(BODY).hexdigest()


# --- the filename, which reaches a response header --------------------------


@pytest.mark.parametrize(
    "given, expected",
    [
        ("Release report-r1.json", "Release-report-r1.json"),
        ('evil"; filename="passwd', "evil-filename-passwd"),
        ("with\r\nx-injected: header", "with-x-injected-header"),
        ("../../etc/passwd", "etc-passwd"),
        ("שלום.json", "json"),
        ("...", "document"),
        ("", "document"),
    ],
)
def test_a_document_name_cannot_carry_anything_into_the_header(given, expected):
    assert safe_filename(given) == expected


def test_the_disposition_header_stays_one_header():
    """A name is free text up to 240 characters and it ends up in a header."""
    header = content_disposition('a"; filename="b\r\nx-evil: 1')
    assert header.count('"') == 2
    assert "\r" not in header and "\n" not in header
    assert header.startswith("attachment; filename=")


def test_a_long_name_is_cut_rather_than_sent_whole():
    assert len(safe_filename("a" * 400)) == 120


# --- reading the bytes back -------------------------------------------------


class Repo:
    def __init__(self, **overrides):
        self.metadata = {
            "storage_locator": "documents/org/doc/abc.json",
            "content_hash": DIGEST,
            "size_bytes": len(BODY),
            "content_type": "application/json",
            "filename": "Release report-r1.json",
            **overrides,
        }

    def download_metadata(self, *args):
        return self.metadata


@pytest.fixture
def storage():
    store = MemoryAnalysisInputStorage()
    store.objects["documents/org/doc/abc.json"] = BODY
    return store


def test_the_bytes_come_back_with_the_digest_checked(storage):
    content = read_document_content(Repo(), storage, "org", "doc", 1)
    assert content.content == BODY
    assert content.content_hash == DIGEST
    assert content.size_bytes == len(BODY)
    assert content.filename == "Release-report-r1.json"


def test_a_missing_object_is_refused_rather_than_served_empty(storage):
    with pytest.raises(DocumentContentUnavailable):
        read_document_content(Repo(storage_locator="documents/org/doc/gone"), storage, "org", "doc", 1)


def test_a_digest_that_does_not_match_is_refused(storage):
    """A row describing bytes we cannot reproduce is a failure, not a download."""
    with pytest.raises(DocumentContentUnavailable):
        read_document_content(Repo(content_hash="f" * 64), storage, "org", "doc", 1)


def test_a_size_that_does_not_match_is_refused(storage):
    with pytest.raises(DocumentContentUnavailable):
        read_document_content(Repo(size_bytes=999), storage, "org", "doc", 1)


def test_a_revision_with_no_object_says_so(storage):
    with pytest.raises(DocumentContentUnavailable, match="no stored object"):
        read_document_content(Repo(storage_locator=""), storage, "org", "doc", 1)


# --- the route --------------------------------------------------------------


def build_api(read_content=None):
    engine = create_portfolio_engine(
        "sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    portfolio.create_organization(
        name="Acme", legal_name="Acme GmbH", country="DE", registration_number="HRB-1",
        actor_id="admin", organization_id="org-acme",
    )
    portfolio.create_product(
        "org-acme", name="Gateway", identifier="GTW-1", manufacturer="Acme",
        cra_class="important_i", support_start=date(2026, 1, 1), support_end=date(2031, 1, 1),
        actor_id="admin", product_id="product-gateway",
    )
    portfolio.create_release(
        "org-acme", "product-gateway", version="1.0.0", channel="stable",
        release_date=date(2026, 1, 2), support_start=date(2026, 1, 2),
        support_end=date(2031, 1, 1), actor_id="admin", release_id="release-1",
    )
    repository = DocumentRepository(engine)
    repository.create_document(
        "org-acme", "product-gateway", name='Release "report"', kind="evidence",
        format="json", content_hash=DIGEST, storage_locator="documents/org/doc/abc.json",
        size_bytes=len(BODY), provenance={}, actor_id="operator",
        release_id="release-1", document_id="doc-1",
    )
    principal = Principal("operator", "org-acme", frozenset({Role.COMPLIANCE_OPERATOR}))
    app = FastAPI()
    app.include_router(
        create_documents_router(lambda: repository, lambda: principal, read_content=read_content)
    )
    return TestClient(app)


def reader(store):
    def read(repository, organization_id, document_id, revision):
        return read_document_content(repository, store, organization_id, document_id, revision)
    return read


URL = "/v1/organizations/org-acme/documents/doc-1/revisions/1/download"


def test_metadata_only_promises_bytes_when_something_can_serve_them():
    assert build_api().get(URL).json()["download_type"] == "storage_metadata_only"


def test_metadata_advertises_the_content_route_once_it_is_wired(storage):
    body = build_api(reader(storage)).get(URL).json()
    assert body["download_type"] == "content_available"
    assert body["content_hash"] == DIGEST


def test_the_content_route_serves_the_document_itself(storage):
    response = build_api(reader(storage)).get(f"{URL}/content")
    assert response.status_code == 200
    assert response.content == BODY
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["x-content-sha256"] == DIGEST
    assert response.headers["cache-control"] == "private, no-store"


def test_the_served_filename_is_sanitised(storage):
    """The document is literally named 'Release "report"'."""
    header = build_api(reader(storage)).get(f"{URL}/content").headers["content-disposition"]
    assert header == 'attachment; filename="Release-report-r1.json"'
    assert header.count('"') == 2


def test_the_route_is_absent_rather_than_lying_when_no_storage_is_wired():
    response = build_api().get(f"{URL}/content")
    assert response.status_code == 501


def test_an_unreadable_object_reports_unavailable_not_success(storage):
    storage.objects.clear()
    assert build_api(reader(storage)).get(f"{URL}/content").status_code == 503


def _client_for(principal, storage):
    engine = create_portfolio_engine(
        "sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    PortfolioRepository(engine).create_schema()
    repository = DocumentRepository(engine)
    app = FastAPI()
    app.include_router(
        create_documents_router(lambda: repository, lambda: principal, read_content=reader(storage))
    )
    return TestClient(app)


def test_another_tenant_is_told_nothing_about_this_one(storage):
    """404 rather than 403 here is deliberate: a 403 would confirm the org exists."""
    outsider = Principal("intruder", "org-other", frozenset({Role.COMPLIANCE_OPERATOR}))
    response = _client_for(outsider, storage).get(f"{URL}/content")
    assert response.status_code == 404
    assert "doc-1" not in response.text


def test_a_role_without_read_access_is_refused(storage):
    stranger = Principal("nobody", "org-acme", frozenset())
    assert _client_for(stranger, storage).get(f"{URL}/content").status_code == 403
