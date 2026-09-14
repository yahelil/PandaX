from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, update
from sqlalchemy.exc import DatabaseError

from pandax.findings import (
    FindingConflict,
    FindingNotFound,
    FindingObservation,
    FindingRepository,
    FindingValidationError,
    finding_audit_events,
    finding_decisions,
)
from pandax.portfolio import PortfolioRepository, create_portfolio_engine

NOW = datetime(2026, 9, 14, 9, 0, tzinfo=timezone.utc)


@pytest.fixture
def repository(tmp_path) -> FindingRepository:
    engine = create_portfolio_engine(f"sqlite:///{tmp_path / 'findings.db'}")
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    portfolio.create_organization(
        organization_id="org-acme", name="Acme", legal_name="Acme B.V.",
        country="NL", registration_number="NL-1", actor_id="admin",
    )
    portfolio.create_product(
        "org-acme", product_id="product-hub", name="Home Hub", identifier="HUB-100",
        manufacturer="Acme", cra_class="important_i", support_start=date(2026, 1, 1),
        support_end=date(2031, 1, 1), actor_id="admin",
    )
    portfolio.create_release(
        "org-acme", "product-hub", release_id="release-14", version="1.4",
        channel="stable", release_date=date(2026, 9, 1), support_start=date(2026, 9, 1),
        support_end=date(2031, 1, 1), actor_id="admin",
    )
    result = FindingRepository(engine)
    result.create_schema()
    return result


def observation(**changes) -> FindingObservation:
    values = {
        "reference_id": "CVE-2021-44228",
        "cve": "CVE-2021-44228",
        "component": "log4j-core",
        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        "version": "2.14.1",
        "title": "Remote code execution in Log4j",
        "description": "Attacker-controlled lookup can execute code.",
        "severity": "critical",
        "cvss": 10.0,
        "kev": True,
        "epss": 0.975,
        "reachability": "reachable",
        "reachability_evidence": {"paths": ["gateway -> logger"]},
        "reachability_limitations": ["Runtime feature flags were not observed"],
        "source": "osv",
        "provenance": {"advisory": "GHSA-jfh8-c2jp-5v3q", "feed_revision": "2026-09-14"},
    }
    values.update(changes)
    return FindingObservation(**values)


def ingest(repository, **changes):
    return repository.upsert_from_analysis(
        "org-acme", "product-hub", "release-14", "analysis-1",
        [observation(**changes)], actor_id="analyzer", seen_at=NOW,
    )[0]


def test_analysis_upsert_is_scoped_and_preserves_human_decision(repository):
    created = ingest(repository)
    reviewed = repository.decide(
        "org-acme", "product-hub", "release-14", created.id,
        decision="affected", rationale="Reachable from unauthenticated input",
        expected_version=created.version, actor_id="reviewer",
    )

    refreshed = repository.upsert_from_analysis(
        "org-acme", "product-hub", "release-14", "analysis-2",
        [observation(cvss=9.8, epss=0.99)], actor_id="analyzer",
        seen_at=NOW + timedelta(hours=1),
    )[0]

    assert refreshed.id == created.id
    assert refreshed.first_seen_at == NOW
    assert refreshed.last_seen_at == NOW + timedelta(hours=1)
    assert refreshed.cvss == 9.8
    assert refreshed.current_decision == "affected"
    assert refreshed.decision_rationale == reviewed.decision_rationale
    assert refreshed.status == "open"
    assert len(repository.decisions("org-acme", created.id)) == 1
    with pytest.raises(FindingNotFound):
        repository.get("org-other", "product-hub", "release-14", created.id)


def test_assignment_decision_remediation_and_optimistic_version(repository):
    created = ingest(repository)
    assigned = repository.assign(
        "org-acme", "product-hub", "release-14", created.id,
        assignee_id="alice", expected_version=1, actor_id="lead",
    )
    with pytest.raises(FindingConflict):
        repository.assign(
            "org-acme", "product-hub", "release-14", created.id,
            assignee_id="bob", expected_version=1, actor_id="lead",
        )
    decided = repository.decide(
        "org-acme", "product-hub", "release-14", created.id,
        decision="affected", rationale="Confirmed reachable execution path",
        expected_version=assigned.version, actor_id="reviewer",
    )
    remediated = repository.update_remediation(
        "org-acme", "product-hub", "release-14", created.id,
        plan="Upgrade log4j-core to 2.23.1 and run regression suite",
        status="verified", due_date=date(2026, 9, 15),
        verification_evidence=[{"kind": "test_run", "sha256": "a" * 64}],
        expected_version=decided.version, actor_id="operator",
    )

    assert remediated.assignee_id == "alice"
    assert remediated.status == "resolved"
    assert remediated.remediation_status == "verified"
    assert remediated.version == 4
    actions = [item.action for item in repository.audit_history("org-acme", created.id)]
    assert len(actions) == 4
    assert set(actions) == {
        "finding.discovered", "finding.assigned", "finding.decision_recorded",
        "finding.remediation_updated",
    }


def test_default_queue_filters_and_priority(repository):
    critical = ingest(repository)
    medium = repository.upsert_from_analysis(
        "org-acme", "product-hub", "release-14", "analysis-2",
        [observation(
            reference_id="CVE-2026-1000", cve="CVE-2026-1000", source_key="medium",
            severity="medium", cvss=6.5, kev=False, reachability="unknown",
        )], actor_id="analyzer", seen_at=NOW,
    )[0]
    repository.decide(
        "org-acme", "product-hub", "release-14", medium.id,
        decision="not_affected", rationale="Vulnerable code is excluded from build",
        expected_version=medium.version, actor_id="reviewer",
    )

    assert [item.id for item in repository.list("org-acme")] == [critical.id]
    assert len(repository.list("org-acme", action_required=False)) == 2
    assert repository.list("org-acme", severities=["medium"], action_required=False)[0].id == medium.id
    with pytest.raises(FindingValidationError):
        repository.list("org-acme", sort="random")


def test_history_is_append_only_and_validation_is_strict(repository):
    created = ingest(repository)
    repository.decide(
        "org-acme", "product-hub", "release-14", created.id,
        decision="deferred", rationale="Maintenance window approved for tomorrow",
        expected_version=created.version, actor_id="reviewer",
    )
    with pytest.raises(DatabaseError, match="append-only"):
        with repository.engine.begin() as connection:
            connection.execute(update(finding_decisions).values(rationale="rewritten"))
    with pytest.raises(DatabaseError, match="append-only"):
        with repository.engine.begin() as connection:
            connection.execute(delete(finding_audit_events))
    with pytest.raises(FindingValidationError):
        repository.update_remediation(
            "org-acme", "product-hub", "release-14", created.id,
            plan="Upgrade", status="verified", due_date=None,
            verification_evidence=[], expected_version=2, actor_id="operator",
        )
