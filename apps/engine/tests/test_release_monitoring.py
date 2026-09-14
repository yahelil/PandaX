from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import delete
from sqlalchemy.exc import DatabaseError

from pandax.portfolio import PortfolioRepository, create_portfolio_engine
from pandax.release_monitoring import (
    MonitoringObservation,
    ReleaseMonitoringConflict,
    ReleaseMonitoringNotFound,
    ReleaseMonitoringRepository,
    ReleaseMonitoringValidationError,
    advisory_watch_runner,
    monitoring_store_runner,
    release_monitoring_events,
)

NOW = datetime(2026, 9, 14, 9, 0, tzinfo=timezone.utc)


@pytest.fixture
def repository(tmp_path) -> ReleaseMonitoringRepository:
    engine = create_portfolio_engine(f"sqlite:///{tmp_path / 'monitoring.db'}")
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    portfolio.create_organization(
        organization_id="org-acme",
        name="Acme Technologies",
        legal_name="Acme Technologies B.V.",
        country="NL",
        registration_number="NL-123",
        actor_id="admin",
    )
    portfolio.create_product(
        "org-acme",
        product_id="product-camera",
        name="Smart Camera",
        identifier="CAM-100",
        manufacturer="Acme Technologies",
        cra_class="important_i",
        support_start=date(2026, 1, 1),
        support_end=date(2031, 1, 1),
        actor_id="admin",
    )
    portfolio.create_release(
        "org-acme",
        "product-camera",
        release_id="release-21",
        version="2.1",
        channel="stable",
        release_date=date(2026, 9, 1),
        support_start=date(2026, 9, 1),
        support_end=date(2031, 1, 1),
        actor_id="admin",
    )
    result = ReleaseMonitoringRepository(engine)
    result.create_schema()
    return result


def configure(repository: ReleaseMonitoringRepository, **changes):
    values = {
        "enabled_sources": ["osv", "cisa_kev", "epss"],
        "cadence_minutes": 60,
        "enabled": True,
        "actor_id": "reviewer",
        "now": NOW,
    }
    values.update(changes)
    return repository.configure(
        "org-acme", "product-camera", "release-21", **values
    )


def test_config_is_release_scoped_and_validated(repository):
    record = configure(repository)

    assert record.health == "degraded"
    assert record.next_check_at == NOW
    assert record.enabled_sources == ("osv", "cisa_kev", "epss")

    with pytest.raises(ReleaseMonitoringNotFound):
        repository.get("org-other", "product-camera", "release-21")
    with pytest.raises(ReleaseMonitoringValidationError):
        configure(repository, enabled_sources=["unknown"])
    with pytest.raises(ReleaseMonitoringValidationError):
        configure(repository, cadence_minutes=1)


def test_due_claim_is_exclusive_and_records_started_event(repository):
    configure(repository)

    claims = repository.claim_due(now=NOW, actor_id="scheduler")

    assert len(claims) == 1
    assert claims[0].trigger == "scheduled"
    assert repository.claim_due(now=NOW, actor_id="scheduler") == []
    with pytest.raises(ReleaseMonitoringConflict):
        repository.claim_now(
            "org-acme", "product-camera", "release-21", actor_id="reviewer", now=NOW
        )
    events = repository.events("org-acme", "product-camera", "release-21")
    assert [(item.sequence, item.event_type) for item in events] == [(1, "started")]


def test_expired_claim_can_be_recovered(repository):
    configure(repository)
    first = repository.claim_due(now=NOW, lease=timedelta(minutes=5))[0]

    recovered = repository.claim_due(now=NOW + timedelta(minutes=6))[0]

    assert recovered.id != first.id
    with pytest.raises(ReleaseMonitoringConflict):
        repository.complete_success(
            first, MonitoringObservation({"status": "complete"}), now=NOW
        )


def test_success_sets_health_schedule_coverage_and_append_only_events(repository):
    configure(repository)
    claim = repository.claim_due(now=NOW)[0]

    result = repository.complete_success(
        claim,
        MonitoringObservation(
            coverage={"status": "complete", "checked": 142},
            message="All enabled sources checked",
        ),
        now=NOW + timedelta(minutes=2),
    )

    assert result.health == "healthy"
    assert result.last_check_at == NOW + timedelta(minutes=2)
    assert result.last_success_at == NOW + timedelta(minutes=2)
    assert result.next_check_at == NOW + timedelta(minutes=62)
    assert result.coverage == {"status": "complete", "checked": 142}
    assert result.consecutive_failures == 0
    assert [(item.sequence, item.event_type) for item in repository.events(
        "org-acme", "product-camera", "release-21"
    )] == [(1, "started"), (2, "succeeded")]
    with pytest.raises(DatabaseError, match="append-only"):
        with repository.engine.begin() as connection:
            connection.execute(delete(release_monitoring_events))


def test_failure_preserves_last_known_coverage_and_escalates(repository):
    configure(repository)
    repository.run_now(
        "org-acme",
        "product-camera",
        "release-21",
        lambda claim: MonitoringObservation({"status": "complete", "components": 42}),
        actor_id="reviewer",
        now=NOW,
    )

    for attempt in range(1, 4):
        result = repository.run_now(
            "org-acme",
            "product-camera",
            "release-21",
            lambda claim: (_ for _ in ()).throw(RuntimeError("OSV unavailable")),
            actor_id="reviewer",
            now=NOW + timedelta(hours=attempt),
        )
        assert result.coverage == {"status": "complete", "components": 42}

    assert result.health == "failed"
    assert result.consecutive_failures == 3
    assert result.last_success_at == NOW
    assert "OSV unavailable" in result.limitations[0]
    assert len(repository.events("org-acme", "product-camera", "release-21")) == 8


def test_disabling_config_makes_it_inactive_and_not_due(repository):
    configure(repository)

    record = configure(repository, enabled=False, now=NOW + timedelta(minutes=1))

    assert record.health == "inactive"
    assert record.next_check_at is None
    assert repository.claim_due(now=NOW + timedelta(days=1)) == []
    with pytest.raises(ReleaseMonitoringConflict):
        repository.claim_now(
            "org-acme", "product-camera", "release-21", actor_id="reviewer"
        )


def test_existing_advisory_and_pipeline_adapters_project_results():
    class Watch:
        def refresh(self, watch_id):
            assert watch_id == "watch-release-21"
            return [{"coverage": {"status": "complete"}, "limitations": []}]

    watch_runner = advisory_watch_runner(
        Watch, lambda organization_id, product_id, release_id: f"watch-{release_id}"
    )
    claim = type("Claim", (), {
        "organization_id": "org-acme",
        "product_id": "product-camera",
        "release_id": "release-21",
    })()
    assert watch_runner(claim).coverage == {"status": "complete"}

    class Store:
        def run_policy(self, policy_id):
            assert policy_id == "policy-release-21"
            return {
                "status": "completed",
                "coverage_state": "complete",
                "source_checks": [{"source": "OSV.dev", "status": "completed"}],
            }

    pipeline_adapter = monitoring_store_runner(
        Store(), lambda organization_id, product_id, release_id: f"policy-{release_id}"
    )
    assert pipeline_adapter(claim).coverage["status"] == "complete"
