from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from datetime import date
from pathlib import Path

import pytest
from sqlalchemy import update
from sqlalchemy.exc import DatabaseError
from sqlalchemy.pool import StaticPool

from pandax import events as ev
from pandax.analysis_jobs import (
    MAX_SBOM_BYTES,
    AnalysisJobConflict,
    AnalysisJobNotFound,
    AnalysisJobRepository,
    AnalysisJobValidationError,
    analysis_job_events,
)
from pandax.portfolio import PortfolioRepository, create_portfolio_engine


def cyclonedx() -> bytes:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "http2-common",
                    "version": "4.4.16",
                    "purl": "pkg:maven/org.eclipse.jetty/http2-common@4.4.16",
                },
                {"type": "library", "name": "local-module", "version": "1"},
            ],
        }
    ).encode()


def spdx() -> bytes:
    return json.dumps(
        {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Smart Camera 2.1",
            "dataLicense": "CC0-1.0",
            "packages": [
                {
                    "SPDXID": "SPDXRef-jetty",
                    "name": "jetty-server",
                    "versionInfo": "11.0.17",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:maven/org.eclipse.jetty/jetty-server@11.0.17",
                        }
                    ],
                }
            ],
        }
    ).encode()


@pytest.fixture
def repositories() -> Iterator[tuple[PortfolioRepository, AnalysisJobRepository]]:
    engine = create_portfolio_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    portfolio = PortfolioRepository(engine)
    analysis = AnalysisJobRepository(engine)
    analysis.create_schema()
    yield portfolio, analysis
    engine.dispose()


@pytest.fixture
def scope(repositories) -> tuple[str, str, str]:
    portfolio, _ = repositories
    organization = portfolio.create_organization(
        name="Acme Devices",
        legal_name="Acme Devices GmbH",
        country="DE",
        registration_number="HRB-128991",
        actor_id="admin",
    )
    product = portfolio.create_product(
        organization.id,
        name="Home Hub",
        identifier="ACM-HUB-110",
        manufacturer="Acme Devices GmbH",
        cra_class="critical",
        support_start=date(2026, 1, 1),
        support_end=date(2030, 12, 31),
        actor_id="admin",
    )
    release = portfolio.create_release(
        organization.id,
        product.id,
        version="1.8.0",
        channel="stable",
        release_date=date(2026, 9, 2),
        support_start=date(2026, 9, 2),
        support_end=date(2030, 12, 31),
        actor_id="admin",
    )
    return organization.id, product.id, release.id


def create_job(repository, scope, **overrides):
    organization_id, product_id, release_id = scope
    values = {
        "filename": "home-hub.cdx.json",
        "media_type": "application/vnd.cyclonedx+json",
        "content": cyclonedx(),
        "idempotency_key": "upload-2026-09-14-001",
        "actor_id": "security-reviewer",
        **overrides,
    }
    return repository.create(organization_id, product_id, release_id, **values)


def test_validates_and_persists_cyclonedx_preview(repositories, scope):
    _, repository = repositories
    job = create_job(repository, scope, filename="../../home-hub.cdx.json")

    assert job.status == "queued"
    assert job.filename == "home-hub.cdx.json"
    assert job.preview == {
        "format": "CycloneDX",
        "version": "1.6",
        "components": 2,
        "matchable_components": 1,
        "skipped_components": 1,
        "product": {},
    }
    assert job.sha256 == hashlib.sha256(cyclonedx()).hexdigest()
    assert [item.kind for item in repository.events(*scope, job.id)] == [
        "analysis.uploaded"
    ]


def test_accepts_spdx_and_idempotent_replay(repositories, scope):
    _, repository = repositories
    job = create_job(
        repository,
        scope,
        filename="home-hub.spdx.json",
        media_type="application/spdx+json; charset=utf-8",
        content=spdx(),
    )
    replay = create_job(
        repository,
        scope,
        filename="renamed.spdx.json",
        media_type="application/spdx+json",
        content=spdx(),
    )

    assert job.input_format == "SPDX"
    assert job.input_version == "SPDX-2.3"
    assert replay.id == job.id
    assert len(repository.list(*scope)) == 1


def test_idempotency_key_rejects_different_content(repositories, scope):
    _, repository = repositories
    create_job(repository, scope)

    with pytest.raises(AnalysisJobConflict, match="different SBOM"):
        create_job(
            repository,
            scope,
            content=spdx(),
            filename="home-hub.spdx.json",
            media_type="application/spdx+json",
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"content": b""}, "empty"),
        ({"content": b"not-json"}, "valid UTF-8 JSON"),
        ({"content": b"x" * (MAX_SBOM_BYTES + 1)}, "limit"),
        ({"filename": "sbom.xml"}, ".json"),
        ({"media_type": "text/plain"}, "media type"),
    ],
)
def test_rejects_unsafe_or_invalid_uploads(repositories, scope, overrides, message):
    _, repository = repositories
    with pytest.raises(AnalysisJobValidationError, match=message):
        create_job(repository, scope, **overrides)


def test_scope_is_exact_even_for_empty_collection(repositories, scope):
    _, repository = repositories
    organization_id, _, release_id = scope

    with pytest.raises(AnalysisJobNotFound, match="release"):
        repository.list(organization_id, "wrong-product", release_id)


def test_run_projects_progress_result_and_downloadable_evidence(
    repositories, scope, tmp_path: Path
):
    _, repository = repositories
    job = create_job(repository, scope)
    evidence = tmp_path / "manifest.json"
    evidence.write_text('{"signed":true}', encoding="utf-8")
    digest = hashlib.sha256(evidence.read_bytes()).hexdigest()

    def runner(path: Path):
        assert path.read_bytes() == cyclonedx()
        yield ev.start("S2 SBOM", "Importing supplied SBOM")
        yield ev.done("S2 SBOM", "SBOM validated")
        yield ev.artifact("SEAL", "manifest.json", digest)
        yield ev.run_done(
            "Evidence bundle complete",
            run_dir=str(tmp_path),
            components=2,
            findings=3,
            kev=1,
            incidents=0,
            coverage_summary={"completed": 2},
        )

    completed = repository.run(*scope, job.id, runner)

    assert completed.status == "completed"
    assert completed.progress == 100
    assert completed.result["findings"] == 3
    path, name = repository.evidence_path(*scope, job.id, digest)
    assert path == evidence
    assert name == "manifest.json"
    history = repository.events(*scope, job.id)
    assert [item.sequence for item in history] == list(range(1, len(history) + 1))
    assert history[-1].kind == "analysis.completed"
    assert all(a.progress <= b.progress for a, b in zip(history, history[1:]))

    with pytest.raises(AnalysisJobConflict, match="only queued"):
        repository.run(*scope, job.id, runner)


def test_runner_failure_is_persisted_not_raised(repositories, scope):
    _, repository = repositories
    job = create_job(repository, scope)

    def runner(_path: Path):
        yield ev.start("S2 SBOM", "Starting")
        raise RuntimeError("advisory source unavailable")

    failed = repository.run(*scope, job.id, runner)

    assert failed.status == "failed"
    assert failed.error == "advisory source unavailable"
    assert repository.events(*scope, job.id)[-1].kind == "analysis.failed"


def test_event_rows_are_database_immutable(repositories, scope):
    _, repository = repositories
    job = create_job(repository, scope)

    with pytest.raises(DatabaseError, match="append-only"):
        with repository.engine.begin() as connection:
            connection.execute(
                update(analysis_job_events)
                .where(analysis_job_events.c.job_id == job.id)
                .values(message="tampered")
            )
