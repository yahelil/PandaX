from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from pandax.compliance import (
    CaseStoreImporter,
    ComplianceChanges,
    ComplianceConflict,
    ComplianceNotFound,
    ComplianceRepository,
    ComplianceValidationError,
)
from pandax.portfolio import PortfolioRepository, create_portfolio_engine


NOW = datetime(2026, 9, 14, 10, 0, tzinfo=timezone.utc)


@pytest.fixture()
def repository(tmp_path):
    engine = create_portfolio_engine(f"sqlite+pysqlite:///{tmp_path / 'compliance.sqlite3'}")
    portfolio = PortfolioRepository(engine)
    portfolio.create_schema()
    for organization_id in ("org-acme", "org-other"):
        portfolio.create_organization(
            organization_id=organization_id,
            name=organization_id,
            legal_name=f"{organization_id} GmbH",
            country="DE",
            registration_number=organization_id,
            actor_id="admin",
        )
    portfolio.create_product(
        "org-acme",
        product_id="product-camera",
        name="Smart Camera",
        identifier="CAM-200",
        manufacturer="Acme",
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
    result = ComplianceRepository(engine, clock=lambda: NOW)
    result.create_schema()
    return result


def create_reporting_item(repository, *, status="action_required", source_id="case-one"):
    return repository.create_item(
        "org-acme",
        item_id=f"item-{source_id}",
        product_id="product-camera",
        release_id="release-21",
        kind="reporting_case",
        title="24-hour early warning",
        description="Actively exploited vulnerability reporting case.",
        priority="critical",
        status=status,
        due_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
        owner_id="security-lead",
        source_type="case_store",
        source_id=source_id,
        reporting_stage="early_warning",
        actor_id="projector",
    )


def test_reporting_lifecycle_is_versioned_and_audited(repository):
    item = create_reporting_item(repository)
    item = repository.update_item(
        "org-acme", item.id, item.version,
        ComplianceChanges(status="in_progress"), "operator",
    )
    item = repository.update_item(
        "org-acme", item.id, item.version,
        ComplianceChanges(
            status="pending_approval",
            self_filing_record_id="snapshot-1",
            self_filing_record_url="/v1/cases/case-one/snapshots/snapshot-1",
        ),
        "operator",
    )
    item = repository.approve_item("org-acme", item.id, item.version, "approver")
    item = repository.update_item(
        "org-acme", item.id, item.version,
        ComplianceChanges(status="acknowledged"), "operator",
    )
    item = repository.update_item(
        "org-acme", item.id, item.version,
        ComplianceChanges(status="resolved"), "operator",
    )

    assert item.status == "resolved"
    assert item.readiness == "ready"
    assert item.version == 5
    assert item.approved_by == "approver"
    assert item.acknowledged_at == item.resolved_at == NOW
    events = repository.list_audit_events("org-acme", item.id)
    assert [event.action for event in events] == [
        "compliance.created", "compliance.updated", "compliance.updated",
        "compliance.approved", "compliance.updated", "compliance.updated",
    ]
    assert [event.item_version for event in events] == list(range(6))


def test_reporting_resolution_requires_acknowledgement_and_approval_action(repository):
    item = create_reporting_item(repository)

    with pytest.raises(ComplianceConflict, match="acknowledged"):
        repository.update_item(
            "org-acme", item.id, item.version,
            ComplianceChanges(status="resolved"), "operator",
        )
    with pytest.raises(ComplianceValidationError, match="approval action"):
        repository.update_item(
            "org-acme", item.id, item.version,
            ComplianceChanges(status="approved"), "operator",
        )


def test_optimistic_version_tenant_scope_and_filing_link_immutability(repository):
    item = create_reporting_item(repository)
    changed = repository.update_item(
        "org-acme", item.id, item.version,
        ComplianceChanges(owner_id="new-owner", self_filing_record_id="record-1"),
        "operator",
    )

    with pytest.raises(ComplianceConflict, match="stale"):
        repository.update_item(
            "org-acme", item.id, item.version,
            ComplianceChanges(owner_id="stale-owner"), "operator",
        )
    with pytest.raises(ComplianceConflict, match="immutable"):
        repository.update_item(
            "org-acme", item.id, changed.version,
            ComplianceChanges(self_filing_record_id="record-2"), "operator",
        )
    with pytest.raises(ComplianceNotFound):
        repository.get_item("org-other", item.id)
    with pytest.raises(ComplianceNotFound):
        repository.list_audit_events("org-other", item.id)


class FakeCaseStore:
    def __init__(self):
        self.calls = 0

    def list(self):
        self.calls += 1
        return [{
            "id": "case-cve-2026-1000",
            "status": "under_review",
            "approved": False,
            "report": {
                "revision": 2,
                "payload": {"stage": "notification"},
            },
            "deadlines": {
                "early_warning": "2026-09-14T09:00:00Z",
                "notification": "2026-09-16T09:00:00Z",
                "final_report": "2026-09-28T09:00:00Z",
            },
            "source_product": {"name": "Smart Camera", "version": "2.1"},
            "submissions": [],
            "snapshots": [{"id": "snapshot-2"}],
            "operator": "security-lead",
        }]


def test_case_projection_is_idempotent_and_never_overclaims_readiness(repository):
    store = FakeCaseStore()
    importer = CaseStoreImporter(
        store,
        organization_id="org-acme",
        target_resolver=lambda _case: ("product-camera", "release-21"),
    )

    first = repository.project_cases("org-acme", importer)
    second = repository.project_cases("org-acme", importer)

    assert [item.reporting_stage for item in first] == [
        "early_warning", "notification", "final_report",
    ]
    assert [item.status for item in first] == [
        "in_progress", "pending_approval", "in_progress",
    ]
    assert all(item.readiness != "ready" for item in first)
    assert [item.id for item in second] == [item.id for item in first]
    assert all(item.version == 0 for item in second)
    assert sum(len(repository.list_audit_events("org-acme", item.id)) for item in first) == 3
    assert first[0].priority == "critical"
    assert first[1].self_filing_record_id == "snapshot-2"


def test_default_queue_filters_resolved_and_supports_product_filters(repository):
    active = create_reporting_item(repository, source_id="active")
    repository.create_item(
        "org-acme",
        item_id="resolved-document",
        product_id="product-camera",
        kind="missing_document",
        title="Conformity document supplied",
        description="Approved declaration stored.",
        priority="low",
        status="resolved",
        source_type="document_service",
        source_id="document-1",
        actor_id="operator",
    )

    assert repository.list_items("org-acme") == [active]
    all_items = repository.list_items(
        "org-acme", action_only=False, product_id="product-camera",
    )
    assert {item.id for item in all_items} == {active.id, "resolved-document"}
