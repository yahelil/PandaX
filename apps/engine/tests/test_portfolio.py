from datetime import date, timezone

import pytest

from pandax.portfolio import (
    OrganizationChanges,
    PortfolioConflict,
    PortfolioNotFound,
    PortfolioRepository,
    PortfolioValidationError,
    ProductChanges,
    ReleaseChanges,
    create_portfolio_engine,
)


@pytest.fixture()
def repository(tmp_path):
    engine = create_portfolio_engine(f"sqlite+pysqlite:///{tmp_path / 'portfolio.sqlite3'}")
    repository = PortfolioRepository(engine)
    repository.create_schema()
    return repository


def create_organization(repository, suffix="one"):
    return repository.create_organization(
        name=f"Acme {suffix}",
        legal_name=f"Acme {suffix} GmbH",
        country="de",
        registration_number=f"HRB-{suffix}",
        timezone_name="Europe/Berlin",
        actor_id="user-admin",
    )


def create_product(repository, organization_id, **overrides):
    values = {
        "name": "Smart Camera",
        "identifier": "ACM-CAM-200",
        "manufacturer": "Acme Devices GmbH",
        "cra_class": "important_i",
        "classification_status": "confirmed",
        "support_start": date(2026, 1, 1),
        "support_end": date(2031, 12, 31),
        "owner_id": "user-product-security",
        "actor_id": "user-admin",
    }
    values.update(overrides)
    return repository.create_product(organization_id, **values)


def create_release(repository, organization_id, product_id, **overrides):
    values = {
        "version": "2.4.1",
        "channel": "stable",
        "status": "active",
        "release_date": date(2026, 8, 28),
        "support_start": date(2026, 8, 28),
        "support_end": date(2031, 12, 31),
        "owner_id": "user-product-security",
        "readiness": "ready",
        "monitoring_health": "healthy",
        "sbom_status": "validated",
        "actor_id": "user-admin",
    }
    values.update(overrides)
    return repository.create_release(organization_id, product_id, **values)


def test_portfolio_lifecycle_is_persisted_and_audited(repository):
    organization = create_organization(repository)
    product = create_product(repository, organization.id)
    release = create_release(repository, organization.id, product.id)
    active = repository.set_active_release(organization.id, product.id, release.id, "user-admin")

    assert repository.list_organizations() == [organization]
    assert repository.list_products(organization.id) == [active]
    assert repository.list_releases(organization.id, product.id) == [release]
    assert active.active_release_id == release.id
    assert organization.country == "DE"
    assert organization.created_at.tzinfo == timezone.utc

    actions = [event.action for event in repository.list_audit_events(organization.id)]
    assert actions == [
        "organization.created",
        "product.created",
        "release.created",
        "product.active_release_changed",
    ]


def test_tenant_scope_hides_products_and_releases(repository):
    first = create_organization(repository, "one")
    second = create_organization(repository, "two")
    product = create_product(repository, first.id)
    release = create_release(repository, first.id, product.id)

    assert repository.list_products(second.id) == []
    assert repository.list_releases(second.id, product.id) == []
    with pytest.raises(PortfolioNotFound, match="product not found"):
        repository.get_product(second.id, product.id)
    with pytest.raises(PortfolioNotFound, match="release not found"):
        repository.get_release(second.id, release.id)


def test_unique_identifiers_slugs_and_release_versions_are_transactional(repository):
    organization = create_organization(repository)
    product = create_product(repository, organization.id)
    baseline_events = len(repository.list_audit_events(organization.id))

    with pytest.raises(PortfolioConflict, match="identifier or slug"):
        create_product(repository, organization.id, name="Different name")
    assert len(repository.list_products(organization.id)) == 1
    assert len(repository.list_audit_events(organization.id)) == baseline_events

    create_release(repository, organization.id, product.id)
    release_events = len(repository.list_audit_events(organization.id))
    with pytest.raises(PortfolioConflict, match="release version"):
        create_release(repository, organization.id, product.id)
    assert len(repository.list_releases(organization.id, product.id)) == 1
    assert len(repository.list_audit_events(organization.id)) == release_events


def test_same_identifier_and_slug_are_allowed_in_different_organizations(repository):
    first = create_organization(repository, "one")
    second = create_organization(repository, "two")

    first_product = create_product(repository, first.id)
    second_product = create_product(repository, second.id)

    assert first_product.identifier == second_product.identifier
    assert first_product.slug == second_product.slug


def test_support_period_and_status_values_are_validated_before_write(repository):
    organization = create_organization(repository)
    with pytest.raises(PortfolioValidationError, match="support_end"):
        create_product(
            repository,
            organization.id,
            support_start=date(2030, 1, 1),
            support_end=date(2029, 1, 1),
        )
    with pytest.raises(PortfolioValidationError, match="cra_class"):
        create_product(repository, organization.id, cra_class="unclassified")
    assert repository.list_products(organization.id) == []


def test_active_release_must_belong_to_same_product_and_tenant(repository):
    organization = create_organization(repository)
    camera = create_product(repository, organization.id)
    lock = create_product(
        repository,
        organization.id,
        name="Smart Lock",
        identifier="ACM-LOCK-140",
        slug="smart-lock",
    )
    lock_release = create_release(repository, organization.id, lock.id)

    with pytest.raises(PortfolioValidationError, match="must belong"):
        repository.set_active_release(organization.id, camera.id, lock_release.id, "user-admin")
    assert repository.get_product(organization.id, camera.id).active_release_id is None


def test_updates_are_typed_scoped_and_audited(repository):
    organization = create_organization(repository)
    product = create_product(repository, organization.id)
    release = create_release(repository, organization.id, product.id)

    updated_organization = repository.update_organization(
        organization.id,
        OrganizationChanges(name="Acme Connected Products"),
        "user-admin",
    )
    updated_product = repository.update_product(
        organization.id,
        product.id,
        ProductChanges(readiness="needs_attention", clear_owner=True),
        "user-compliance",
    )
    updated_release = repository.update_release(
        organization.id,
        release.id,
        ReleaseChanges(monitoring_health="degraded", sbom_status="partial"),
        "user-compliance",
    )

    assert updated_organization.name == "Acme Connected Products"
    assert updated_product.readiness == "needs_attention"
    assert updated_product.owner_id is None
    assert updated_release.monitoring_health == "degraded"
    assert updated_release.sbom_status == "partial"
    assert [event.action for event in repository.list_audit_events(organization.id)][-3:] == [
        "organization.updated",
        "product.updated",
        "release.updated",
    ]


def test_conflicting_update_rolls_back_without_an_audit_event(repository):
    organization = create_organization(repository)
    first = create_product(repository, organization.id)
    second = create_product(
        repository,
        organization.id,
        name="Home Hub",
        identifier="ACM-HUB-110",
        slug="home-hub",
    )
    audit_count = len(repository.list_audit_events(organization.id))

    with pytest.raises(PortfolioConflict, match="product update conflicts"):
        repository.update_product(
            organization.id,
            second.id,
            ProductChanges(identifier=first.identifier),
            "user-admin",
        )

    assert repository.get_product(organization.id, second.id).identifier == "ACM-HUB-110"
    assert len(repository.list_audit_events(organization.id)) == audit_count
