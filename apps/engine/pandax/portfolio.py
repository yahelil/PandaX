"""Organization, product, and release persistence boundary.

The repository owns tenant scoping, lifecycle validation, active-release
integrity, transactions, and append-only audit recording. HTTP handlers should
not depend on SQLAlchemy tables or sessions directly.
"""
from __future__ import annotations

import re
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from typing import Any, Iterator, Mapping
from uuid import uuid4

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    Date,
    DateTime,
    Engine,
    ForeignKey,
    ForeignKeyConstraint,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    create_engine,
    delete,
    event,
    insert,
    select,
    update,
)
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


class PortfolioError(RuntimeError):
    """Base error safe for translation at an API boundary."""


class PortfolioNotFound(PortfolioError):
    pass


class PortfolioConflict(PortfolioError):
    pass


class PortfolioValidationError(PortfolioError):
    pass


@dataclass(frozen=True, slots=True)
class OrganizationRecord:
    id: str
    name: str
    legal_name: str
    country: str
    registration_number: str
    timezone: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ProductRecord:
    id: str
    organization_id: str
    slug: str
    identifier: str
    name: str
    manufacturer: str
    description: str
    cra_class: str
    classification_status: str
    support_start: date
    support_end: date
    owner_id: str | None
    readiness: str
    monitoring_health: str
    active_release_id: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ReleaseRecord:
    id: str
    organization_id: str
    product_id: str
    version: str
    channel: str
    status: str
    release_date: date
    support_start: date
    support_end: date
    owner_id: str | None
    readiness: str
    monitoring_health: str
    sbom_status: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class AuditEventRecord:
    id: str
    organization_id: str
    entity_type: str
    entity_id: str
    action: str
    actor_id: str
    occurred_at: datetime
    payload: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class OrganizationChanges:
    name: str | None = None
    legal_name: str | None = None
    country: str | None = None
    registration_number: str | None = None
    timezone: str | None = None


@dataclass(frozen=True, slots=True)
class ProductChanges:
    slug: str | None = None
    identifier: str | None = None
    name: str | None = None
    manufacturer: str | None = None
    description: str | None = None
    cra_class: str | None = None
    classification_status: str | None = None
    support_start: date | None = None
    support_end: date | None = None
    owner_id: str | None = None
    clear_owner: bool = False
    readiness: str | None = None
    monitoring_health: str | None = None


@dataclass(frozen=True, slots=True)
class ReleaseChanges:
    version: str | None = None
    channel: str | None = None
    status: str | None = None
    release_date: date | None = None
    support_start: date | None = None
    support_end: date | None = None
    owner_id: str | None = None
    clear_owner: bool = False
    readiness: str | None = None
    monitoring_health: str | None = None
    sbom_status: str | None = None


def _column(name: str, type_or_length: Any, *args: Any, **kwargs: Any):
    column_type = String(type_or_length) if isinstance(type_or_length, int) else type_or_length
    return Column(name, column_type, *args, **kwargs)


def _id_column():
    return _column("id", 36, primary_key=True)


def _required_string(name: str, length: int):
    return _column(name, length, nullable=False)


def _created_column():
    return _column("created_at", DateTime(timezone=True), nullable=False)


def _updated_column():
    return _column("updated_at", DateTime(timezone=True), nullable=False)


NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
portfolio_metadata = MetaData(naming_convention=NAMING_CONVENTION)

organizations = Table(
    "portfolio_organizations",
    portfolio_metadata,
    _id_column(),
    _required_string("name", 200),
    _required_string("legal_name", 240),
    _required_string("country", 2),
    _required_string("registration_number", 120),
    _required_string("timezone", 80),
    _created_column(),
    _updated_column(),
)

products = Table(
    "portfolio_products",
    portfolio_metadata,
    _id_column(),
    _column("organization_id", 36, ForeignKey("portfolio_organizations.id", ondelete="CASCADE"), nullable=False),
    _required_string("slug", 160),
    _required_string("identifier", 160),
    _required_string("name", 200),
    _required_string("manufacturer", 240),
    _column("description", 2000, nullable=False, default=""),
    _required_string("cra_class", 32),
    _required_string("classification_status", 32),
    _column("support_start", Date, nullable=False),
    _column("support_end", Date, nullable=False),
    _column("owner_id", 128, nullable=True),
    _required_string("readiness", 32),
    _required_string("monitoring_health", 32),
    _column("active_release_id", 36, nullable=True),
    _created_column(),
    _updated_column(),
    UniqueConstraint("organization_id", "slug", name="uq_portfolio_products_org_slug"),
    UniqueConstraint("organization_id", "identifier", name="uq_portfolio_products_org_identifier"),
    UniqueConstraint("id", "organization_id", name="uq_portfolio_products_id_org"),
    CheckConstraint("support_end >= support_start", name="support_period"),
)

releases = Table(
    "portfolio_releases",
    portfolio_metadata,
    _id_column(),
    _column("organization_id", 36, ForeignKey("portfolio_organizations.id", ondelete="CASCADE"), nullable=False),
    _column("product_id", 36, nullable=False),
    _required_string("version", 120),
    _required_string("channel", 24),
    _required_string("status", 32),
    _column("release_date", Date, nullable=False),
    _column("support_start", Date, nullable=False),
    _column("support_end", Date, nullable=False),
    _column("owner_id", 128, nullable=True),
    _required_string("readiness", 32),
    _required_string("monitoring_health", 32),
    _required_string("sbom_status", 32),
    _created_column(),
    _updated_column(),
    ForeignKeyConstraint(
        ["product_id", "organization_id"],
        ["portfolio_products.id", "portfolio_products.organization_id"],
        name="fk_portfolio_releases_product_org",
        ondelete="CASCADE",
    ),
    UniqueConstraint("product_id", "version", name="uq_portfolio_releases_product_version"),
    UniqueConstraint("id", "product_id", "organization_id", name="uq_portfolio_releases_id_product_org"),
    CheckConstraint("support_end >= support_start", name="support_period"),
)

# A composite FK proves that an active release belongs to the same product and
# tenant. use_alter breaks the products/releases DDL cycle on PostgreSQL.
products.append_constraint(
    ForeignKeyConstraint(
        ["active_release_id", "id", "organization_id"],
        ["portfolio_releases.id", "portfolio_releases.product_id", "portfolio_releases.organization_id"],
        name="fk_portfolio_products_active_release",
        use_alter=True,
        ondelete="RESTRICT",
    )
)

audit_events = Table(
    "portfolio_audit_events",
    portfolio_metadata,
    _id_column(),
    _column("organization_id", 36, ForeignKey("portfolio_organizations.id", ondelete="CASCADE"), nullable=False),
    _required_string("entity_type", 32),
    _required_string("entity_id", 36),
    _required_string("action", 64),
    _required_string("actor_id", 128),
    _column("occurred_at", DateTime(timezone=True), nullable=False),
    _column("payload", JSON, nullable=False),
)


CRA_CLASSES = frozenset({"default", "important_i", "important_ii", "critical"})
CLASSIFICATION_STATUSES = frozenset({"confirmed", "review_required"})
READINESS_STATUSES = frozenset({"ready", "needs_attention", "incomplete_evidence"})
MONITORING_STATUSES = frozenset({"healthy", "degraded", "failed", "inactive"})
RELEASE_CHANNELS = frozenset({"stable", "beta", "lts"})
RELEASE_STATUSES = frozenset({"draft", "active", "supported", "end_of_support"})
SBOM_STATUSES = frozenset({"missing", "partial", "validated"})


def create_portfolio_engine(url: str, **kwargs: Any) -> Engine:
    """Create a sync SQLAlchemy engine with SQLite FK parity for tests."""
    engine = create_engine(url, **kwargs)
    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    return engine


class PortfolioRepository:
    """Tenant-safe transactional persistence for portfolio identity and scope."""

    def __init__(self, engine: Engine):
        self.engine = engine

    def create_schema(self) -> None:
        """Development/test convenience. Production uses Alembic."""
        portfolio_metadata.create_all(self.engine)

    def create_organization(
        self, *, name: str, legal_name: str, country: str,
        registration_number: str, actor_id: str, timezone_name: str = "UTC",
        organization_id: str | None = None,
    ) -> OrganizationRecord:
        values = {
            "id": organization_id or _new_id(),
            "name": _required(name, "name"),
            "legal_name": _required(legal_name, "legal_name"),
            "country": _country(country),
            "registration_number": _required(registration_number, "registration_number"),
            "timezone": _required(timezone_name, "timezone"),
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
        }
        with self._transaction() as session:
            self._execute_insert(session, organizations, values, "organization already exists")
            self._audit(session, values["id"], "organization", values["id"], "organization.created", actor_id, values)
        return self.get_organization(values["id"])

    def get_organization(self, organization_id: str) -> OrganizationRecord:
        with Session(self.engine) as session:
            row = session.execute(select(organizations).where(organizations.c.id == organization_id)).mappings().one_or_none()
        if row is None:
            raise PortfolioNotFound("organization not found")
        return _organization_record(row)

    def list_organizations(self) -> list[OrganizationRecord]:
        with Session(self.engine) as session:
            rows = session.execute(select(organizations).order_by(organizations.c.name, organizations.c.id)).mappings().all()
        return [_organization_record(row) for row in rows]

    def update_organization(self, organization_id: str, changes: OrganizationChanges, actor_id: str) -> OrganizationRecord:
        values = _changes(changes)
        if "country" in values:
            values["country"] = _country(values["country"])
        values = {key: _required(value, key) for key, value in values.items()}
        self._update_scoped(organizations, organizations.c.id == organization_id, values, organization_id, "organization", organization_id, actor_id)
        return self.get_organization(organization_id)

    def create_product(
        self, organization_id: str, *, name: str, identifier: str,
        manufacturer: str, cra_class: str, support_start: date,
        support_end: date, actor_id: str, slug: str | None = None,
        description: str = "", classification_status: str = "review_required",
        owner_id: str | None = None, product_id: str | None = None,
        readiness: str = "incomplete_evidence", monitoring_health: str = "inactive",
    ) -> ProductRecord:
        self._validate_period(support_start, support_end)
        values = {
            "id": product_id or _new_id(),
            "organization_id": organization_id,
            "slug": _slug(slug or name),
            "identifier": _required(identifier, "identifier"),
            "name": _required(name, "name"),
            "manufacturer": _required(manufacturer, "manufacturer"),
            "description": description.strip(),
            "cra_class": _choice(cra_class, CRA_CLASSES, "cra_class"),
            "classification_status": _choice(classification_status, CLASSIFICATION_STATUSES, "classification_status"),
            "support_start": support_start,
            "support_end": support_end,
            "owner_id": owner_id,
            "readiness": _choice(readiness, READINESS_STATUSES, "readiness"),
            "monitoring_health": _choice(monitoring_health, MONITORING_STATUSES, "monitoring_health"),
            "active_release_id": None,
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
        }
        with self._transaction() as session:
            self._require_organization(session, organization_id)
            self._execute_insert(session, products, values, "product identifier or slug already exists")
            self._audit(session, organization_id, "product", values["id"], "product.created", actor_id, values)
        return self.get_product(organization_id, values["id"])

    def get_product(self, organization_id: str, product_id: str) -> ProductRecord:
        with Session(self.engine) as session:
            row = self._product_row(session, organization_id, product_id)
        if row is None:
            raise PortfolioNotFound("product not found")
        return _product_record(row)

    def list_products(self, organization_id: str) -> list[ProductRecord]:
        with Session(self.engine) as session:
            rows = session.execute(
                select(products).where(products.c.organization_id == organization_id).order_by(products.c.name, products.c.id)
            ).mappings().all()
        return [_product_record(row) for row in rows]

    def update_product(self, organization_id: str, product_id: str, changes: ProductChanges, actor_id: str) -> ProductRecord:
        current = self.get_product(organization_id, product_id)
        values = _changes(changes, excluded={"clear_owner"})
        if changes.clear_owner:
            values["owner_id"] = None
        if "slug" in values:
            values["slug"] = _slug(values["slug"])
        for field in ("identifier", "name", "manufacturer"):
            if field in values:
                values[field] = _required(values[field], field)
        if "cra_class" in values:
            values["cra_class"] = _choice(values["cra_class"], CRA_CLASSES, "cra_class")
        if "classification_status" in values:
            values["classification_status"] = _choice(values["classification_status"], CLASSIFICATION_STATUSES, "classification_status")
        if "readiness" in values:
            values["readiness"] = _choice(values["readiness"], READINESS_STATUSES, "readiness")
        if "monitoring_health" in values:
            values["monitoring_health"] = _choice(values["monitoring_health"], MONITORING_STATUSES, "monitoring_health")
        self._validate_period(values.get("support_start", current.support_start), values.get("support_end", current.support_end))
        self._update_scoped(products, (products.c.id == product_id) & (products.c.organization_id == organization_id), values, organization_id, "product", product_id, actor_id)
        return self.get_product(organization_id, product_id)

    def create_release(
        self, organization_id: str, product_id: str, *, version: str,
        channel: str, release_date: date, support_start: date,
        support_end: date, actor_id: str, owner_id: str | None = None,
        release_id: str | None = None, status: str = "draft",
        readiness: str = "incomplete_evidence", monitoring_health: str = "inactive",
        sbom_status: str = "missing",
    ) -> ReleaseRecord:
        self._validate_period(support_start, support_end)
        values = {
            "id": release_id or _new_id(),
            "organization_id": organization_id,
            "product_id": product_id,
            "version": _required(version, "version"),
            "channel": _choice(channel, RELEASE_CHANNELS, "channel"),
            "status": _choice(status, RELEASE_STATUSES, "status"),
            "release_date": release_date,
            "support_start": support_start,
            "support_end": support_end,
            "owner_id": owner_id,
            "readiness": _choice(readiness, READINESS_STATUSES, "readiness"),
            "monitoring_health": _choice(monitoring_health, MONITORING_STATUSES, "monitoring_health"),
            "sbom_status": _choice(sbom_status, SBOM_STATUSES, "sbom_status"),
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
        }
        with self._transaction() as session:
            if self._product_row(session, organization_id, product_id) is None:
                raise PortfolioNotFound("product not found")
            self._execute_insert(session, releases, values, "release version already exists for product")
            self._audit(session, organization_id, "release", values["id"], "release.created", actor_id, values)
        return self.get_release(organization_id, values["id"])

    def get_release(self, organization_id: str, release_id: str) -> ReleaseRecord:
        with Session(self.engine) as session:
            row = self._release_row(session, organization_id, release_id)
        if row is None:
            raise PortfolioNotFound("release not found")
        return _release_record(row)

    def list_releases(self, organization_id: str, product_id: str) -> list[ReleaseRecord]:
        with Session(self.engine) as session:
            rows = session.execute(
                select(releases).where(
                    (releases.c.organization_id == organization_id) & (releases.c.product_id == product_id)
                ).order_by(releases.c.release_date.desc(), releases.c.created_at.desc())
            ).mappings().all()
        return [_release_record(row) for row in rows]

    def update_release(self, organization_id: str, release_id: str, changes: ReleaseChanges, actor_id: str) -> ReleaseRecord:
        current = self.get_release(organization_id, release_id)
        values = _changes(changes, excluded={"clear_owner"})
        if changes.clear_owner:
            values["owner_id"] = None
        if "version" in values:
            values["version"] = _required(values["version"], "version")
        validators = {
            "channel": RELEASE_CHANNELS,
            "status": RELEASE_STATUSES,
            "readiness": READINESS_STATUSES,
            "monitoring_health": MONITORING_STATUSES,
            "sbom_status": SBOM_STATUSES,
        }
        for field, choices in validators.items():
            if field in values:
                values[field] = _choice(values[field], choices, field)
        self._validate_period(values.get("support_start", current.support_start), values.get("support_end", current.support_end))
        self._update_scoped(releases, (releases.c.id == release_id) & (releases.c.organization_id == organization_id), values, organization_id, "release", release_id, actor_id)
        return self.get_release(organization_id, release_id)

    def set_active_release(self, organization_id: str, product_id: str, release_id: str | None, actor_id: str) -> ProductRecord:
        with self._transaction() as session:
            product = self._product_row(session, organization_id, product_id)
            if product is None:
                raise PortfolioNotFound("product not found")
            if release_id is not None:
                release = self._release_row(session, organization_id, release_id)
                if release is None or release["product_id"] != product_id:
                    raise PortfolioValidationError("active release must belong to the product and organization")
            changed_at = _utc_now()
            session.execute(update(products).where((products.c.id == product_id) & (products.c.organization_id == organization_id)).values(active_release_id=release_id, updated_at=changed_at))
            self._audit(session, organization_id, "product", product_id, "product.active_release_changed", actor_id, {"active_release_id": release_id})
        return self.get_product(organization_id, product_id)

    def list_audit_events(
        self, organization_id: str, *, entity_type: str | None = None,
        entity_id: str | None = None,
    ) -> list[AuditEventRecord]:
        statement = select(audit_events).where(audit_events.c.organization_id == organization_id)
        if entity_type:
            statement = statement.where(audit_events.c.entity_type == entity_type)
        if entity_id:
            statement = statement.where(audit_events.c.entity_id == entity_id)
        with Session(self.engine) as session:
            rows = session.execute(statement.order_by(audit_events.c.occurred_at, audit_events.c.id)).mappings().all()
        return [_audit_record(row) for row in rows]

    @contextmanager
    def _transaction(self) -> Iterator[Session]:
        with Session(self.engine) as session:
            with session.begin():
                yield session

    @staticmethod
    def _execute_insert(session: Session, table: Table, values: Mapping[str, Any], message: str) -> None:
        try:
            session.execute(insert(table).values(**values))
            session.flush()
        except IntegrityError as exc:
            raise PortfolioConflict(message) from exc

    def _update_scoped(
        self, table: Table, condition: Any, values: dict[str, Any],
        organization_id: str, entity_type: str, entity_id: str, actor_id: str,
    ) -> None:
        if not values:
            return
        values["updated_at"] = _utc_now()
        with self._transaction() as session:
            try:
                result = session.execute(update(table).where(condition).values(**values))
                if result.rowcount != 1:
                    raise PortfolioNotFound(f"{entity_type} not found")
                self._audit(session, organization_id, entity_type, entity_id, f"{entity_type}.updated", actor_id, values)
            except IntegrityError as exc:
                raise PortfolioConflict(f"{entity_type} update conflicts with an existing record") from exc

    @staticmethod
    def _product_row(session: Session, organization_id: str, product_id: str) -> RowMapping | None:
        return session.execute(select(products).where((products.c.id == product_id) & (products.c.organization_id == organization_id))).mappings().one_or_none()

    @staticmethod
    def _release_row(session: Session, organization_id: str, release_id: str) -> RowMapping | None:
        return session.execute(select(releases).where((releases.c.id == release_id) & (releases.c.organization_id == organization_id))).mappings().one_or_none()

    @staticmethod
    def _require_organization(session: Session, organization_id: str) -> None:
        if session.execute(select(organizations.c.id).where(organizations.c.id == organization_id)).scalar_one_or_none() is None:
            raise PortfolioNotFound("organization not found")

    @staticmethod
    def _validate_period(start: date, end: date) -> None:
        if end < start:
            raise PortfolioValidationError("support_end must be on or after support_start")

    @staticmethod
    def _audit(
        session: Session, organization_id: str, entity_type: str,
        entity_id: str, action: str, actor_id: str, payload: Mapping[str, Any],
    ) -> None:
        session.execute(insert(audit_events).values(
            id=_new_id(), organization_id=organization_id,
            entity_type=entity_type, entity_id=entity_id,
            action=action, actor_id=_required(actor_id, "actor_id"),
            occurred_at=_utc_now(), payload=_json_payload(payload),
        ))


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return str(uuid4())


def _required(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PortfolioValidationError(f"{field} is required")
    return value.strip()


def _country(value: str) -> str:
    value = _required(value, "country").upper()
    if not re.fullmatch(r"[A-Z]{2}", value):
        raise PortfolioValidationError("country must be a two-letter code")
    return value


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", _required(value, "slug").lower()).strip("-")
    if not slug:
        raise PortfolioValidationError("slug must contain letters or digits")
    return slug


def _choice(value: str, choices: frozenset[str], field: str) -> str:
    if value not in choices:
        raise PortfolioValidationError(f"invalid {field}: {value}")
    return value


def _changes(changes: Any, excluded: set[str] | None = None) -> dict[str, Any]:
    excluded = excluded or set()
    return {key: value for key, value in asdict(changes).items() if key not in excluded and value is not None}


def _json_payload(values: Mapping[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in values.items():
        if isinstance(value, (date, datetime)):
            payload[key] = value.isoformat()
        else:
            payload[key] = value
    return payload


def _organization_record(row: Mapping[str, Any]) -> OrganizationRecord:
    return OrganizationRecord(**_record_values(OrganizationRecord, row))


def _product_record(row: Mapping[str, Any]) -> ProductRecord:
    return ProductRecord(**_record_values(ProductRecord, row))


def _release_record(row: Mapping[str, Any]) -> ReleaseRecord:
    return ReleaseRecord(**_record_values(ReleaseRecord, row))


def _audit_record(row: Mapping[str, Any]) -> AuditEventRecord:
    return AuditEventRecord(**_record_values(AuditEventRecord, row))


def _record_values(record_type: Any, row: Mapping[str, Any]) -> dict[str, Any]:
    values = {field: row[field] for field in record_type.__dataclass_fields__}
    for field, value in values.items():
        if isinstance(value, datetime) and value.tzinfo is None:
            values[field] = value.replace(tzinfo=timezone.utc)
    return values
