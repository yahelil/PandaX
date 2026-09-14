"""Typed HTTP interface for organization, product, and release portfolios.

Route handlers cross one repository seam and one identity seam. Slice 2 replaces
``local_identity`` with authenticated organization membership enforcement.
"""
from dataclasses import dataclass
from datetime import date, datetime
from typing import Annotated, Callable, Literal, TypeVar

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .portfolio import (
    OrganizationChanges,
    OrganizationRecord,
    PortfolioConflict,
    PortfolioError,
    PortfolioNotFound,
    PortfolioRepository,
    PortfolioValidationError,
    ProductChanges,
    ProductRecord,
    ReleaseChanges,
    ReleaseRecord,
)

CraClass = Literal["default", "important_i", "important_ii", "critical"]
ClassificationStatus = Literal["confirmed", "review_required"]
ReadinessStatus = Literal["ready", "needs_attention", "incomplete_evidence"]
MonitoringHealth = Literal["healthy", "degraded", "failed", "inactive"]
ReleaseChannel = Literal["stable", "beta", "lts"]
ReleaseStatus = Literal["draft", "active", "supported", "end_of_support"]
SbomStatus = Literal["missing", "partial", "validated"]


@dataclass(frozen=True, slots=True)
class PortfolioIdentity:
    """Minimal identity passed to every route; auth replaces this dependency."""

    actor_id: str


def local_identity() -> PortfolioIdentity:
    return PortfolioIdentity(actor_id="local-demo")


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class OrganizationCreate(ApiModel):
    name: str = Field(min_length=1, max_length=200)
    legal_name: str = Field(min_length=1, max_length=240)
    country: str = Field(pattern=r"^[A-Za-z]{2}$")
    registration_number: str = Field(min_length=1, max_length=120)
    timezone: str = Field(default="UTC", min_length=1, max_length=80)


class OrganizationUpdate(ApiModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    legal_name: str | None = Field(default=None, min_length=1, max_length=240)
    country: str | None = Field(default=None, pattern=r"^[A-Za-z]{2}$")
    registration_number: str | None = Field(default=None, min_length=1, max_length=120)
    timezone: str | None = Field(default=None, min_length=1, max_length=80)

    @model_validator(mode="after")
    def require_change(self) -> "OrganizationUpdate":
        if not self.model_fields_set:
            raise ValueError("at least one organization field is required")
        return self


class OrganizationResponse(ApiModel):
    id: str
    name: str
    legal_name: str
    country: str
    registration_number: str
    timezone: str
    created_at: datetime
    updated_at: datetime


class ProductCreate(ApiModel):
    name: str = Field(min_length=1, max_length=200)
    identifier: str = Field(min_length=1, max_length=160)
    manufacturer: str = Field(min_length=1, max_length=240)
    slug: str | None = Field(default=None, min_length=1, max_length=160)
    description: str = Field(default="", max_length=2000)
    cra_class: CraClass
    classification_status: ClassificationStatus = "review_required"
    support_start: date
    support_end: date
    owner_id: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def validate_support_period(self) -> "ProductCreate":
        if self.support_end < self.support_start:
            raise ValueError("support_end must be on or after support_start")
        return self


class ProductUpdate(ApiModel):
    slug: str | None = Field(default=None, min_length=1, max_length=160)
    identifier: str | None = Field(default=None, min_length=1, max_length=160)
    name: str | None = Field(default=None, min_length=1, max_length=200)
    manufacturer: str | None = Field(default=None, min_length=1, max_length=240)
    description: str | None = Field(default=None, max_length=2000)
    cra_class: CraClass | None = None
    classification_status: ClassificationStatus | None = None
    support_start: date | None = None
    support_end: date | None = None
    owner_id: str | None = Field(default=None, max_length=128)
    clear_owner: bool = False
    readiness: ReadinessStatus | None = None
    monitoring_health: MonitoringHealth | None = None
    active_release_id: str | None = None

    @model_validator(mode="after")
    def require_change(self) -> "ProductUpdate":
        if not self.model_fields_set:
            raise ValueError("at least one product field is required")
        if self.owner_id is not None and self.clear_owner:
            raise ValueError("owner_id and clear_owner cannot be used together")
        return self


class ProductResponse(ApiModel):
    id: str
    organization_id: str
    slug: str
    identifier: str
    name: str
    manufacturer: str
    description: str
    cra_class: CraClass
    classification_status: ClassificationStatus
    support_start: date
    support_end: date
    owner_id: str | None
    readiness: ReadinessStatus
    monitoring_health: MonitoringHealth
    active_release_id: str | None
    created_at: datetime
    updated_at: datetime
    # Read-model fields are populated by later aggregation slices.
    action_count: int = 0
    next_deadline: datetime | None = None
    tags: list[str] = Field(default_factory=list)


class ReleaseCreate(ApiModel):
    version: str = Field(min_length=1, max_length=120)
    channel: ReleaseChannel
    status: ReleaseStatus = "draft"
    release_date: date
    support_start: date
    support_end: date
    owner_id: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def validate_support_period(self) -> "ReleaseCreate":
        if self.support_end < self.support_start:
            raise ValueError("support_end must be on or after support_start")
        return self


class ReleaseUpdate(ApiModel):
    version: str | None = Field(default=None, min_length=1, max_length=120)
    channel: ReleaseChannel | None = None
    status: ReleaseStatus | None = None
    release_date: date | None = None
    support_start: date | None = None
    support_end: date | None = None
    owner_id: str | None = Field(default=None, max_length=128)
    clear_owner: bool = False
    readiness: ReadinessStatus | None = None
    monitoring_health: MonitoringHealth | None = None
    sbom_status: SbomStatus | None = None

    @model_validator(mode="after")
    def require_change(self) -> "ReleaseUpdate":
        if not self.model_fields_set:
            raise ValueError("at least one release field is required")
        if self.owner_id is not None and self.clear_owner:
            raise ValueError("owner_id and clear_owner cannot be used together")
        return self


class CoverageResponse(ApiModel):
    components: int = 0
    identified_components: int = 0
    advisory_sources_checked: int = 0
    advisory_sources_expected: int = 0
    limitations: list[str] = Field(default_factory=list)


class ReleaseResponse(ApiModel):
    id: str
    organization_id: str
    product_id: str
    version: str
    channel: ReleaseChannel
    status: ReleaseStatus
    release_date: date
    support_start: date
    support_end: date
    owner_id: str | None
    readiness: ReadinessStatus
    monitoring_health: MonitoringHealth
    sbom_status: SbomStatus
    created_at: datetime
    updated_at: datetime
    coverage: CoverageResponse = Field(default_factory=CoverageResponse)
    last_analysis_at: datetime | None = None
    last_monitoring_check_at: datetime | None = None


RepositoryDependency = Callable[[], PortfolioRepository]
IdentityDependency = Callable[[], PortfolioIdentity]
Result = TypeVar("Result")


def _call(operation: Callable[[], Result]) -> Result:
    try:
        return operation()
    except PortfolioNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except PortfolioConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except PortfolioValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    except PortfolioError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc


def create_portfolio_router(
    repository_dependency: RepositoryDependency,
    identity_dependency: IdentityDependency = local_identity,
) -> APIRouter:
    """Build tenant-scoped router with replaceable persistence and identity adapters."""

    router = APIRouter(prefix="/v1", tags=["portfolio"])
    Repository = Annotated[PortfolioRepository, Depends(repository_dependency)]
    Identity = Annotated[PortfolioIdentity, Depends(identity_dependency)]

    @router.get("/organizations", response_model=list[OrganizationResponse])
    def list_organizations(repository: Repository, _identity: Identity):
        return _call(repository.list_organizations)

    @router.post("/organizations", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
    def create_organization(body: OrganizationCreate, repository: Repository, identity: Identity):
        return _call(lambda: repository.create_organization(
            name=body.name,
            legal_name=body.legal_name,
            country=body.country,
            registration_number=body.registration_number,
            timezone_name=body.timezone,
            actor_id=identity.actor_id,
        ))

    @router.get("/organizations/{organization_id}", response_model=OrganizationResponse)
    def get_organization(organization_id: str, repository: Repository, _identity: Identity):
        return _call(lambda: repository.get_organization(organization_id))

    @router.patch("/organizations/{organization_id}", response_model=OrganizationResponse)
    def update_organization(body: OrganizationUpdate, organization_id: str, repository: Repository, identity: Identity):
        changes = OrganizationChanges(**body.model_dump(exclude_unset=True))
        return _call(lambda: repository.update_organization(organization_id, changes, identity.actor_id))

    @router.get("/organizations/{organization_id}/products", response_model=list[ProductResponse])
    def list_products(organization_id: str, repository: Repository, _identity: Identity):
        _call(lambda: repository.get_organization(organization_id))
        return _call(lambda: repository.list_products(organization_id))

    @router.post(
        "/organizations/{organization_id}/products",
        response_model=ProductResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_product(body: ProductCreate, organization_id: str, repository: Repository, identity: Identity):
        return _call(lambda: repository.create_product(
            organization_id,
            **body.model_dump(),
            actor_id=identity.actor_id,
        ))

    @router.get("/organizations/{organization_id}/products/{product_id}", response_model=ProductResponse)
    def get_product(organization_id: str, product_id: str, repository: Repository, _identity: Identity):
        return _call(lambda: repository.get_product(organization_id, product_id))

    @router.patch("/organizations/{organization_id}/products/{product_id}", response_model=ProductResponse)
    def update_product(
        body: ProductUpdate,
        organization_id: str,
        product_id: str,
        repository: Repository,
        identity: Identity,
    ):
        values = body.model_dump(exclude_unset=True, exclude={"active_release_id"})
        product = _call(lambda: repository.update_product(
            organization_id,
            product_id,
            ProductChanges(**values),
            identity.actor_id,
        ))
        if "active_release_id" in body.model_fields_set:
            product = _call(lambda: repository.set_active_release(
                organization_id,
                product_id,
                body.active_release_id,
                identity.actor_id,
            ))
        return product

    @router.get(
        "/organizations/{organization_id}/products/{product_id}/releases",
        response_model=list[ReleaseResponse],
    )
    def list_releases(organization_id: str, product_id: str, repository: Repository, _identity: Identity):
        _call(lambda: repository.get_product(organization_id, product_id))
        return _call(lambda: repository.list_releases(organization_id, product_id))

    @router.post(
        "/organizations/{organization_id}/products/{product_id}/releases",
        response_model=ReleaseResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_release(
        body: ReleaseCreate,
        organization_id: str,
        product_id: str,
        repository: Repository,
        identity: Identity,
    ):
        return _call(lambda: repository.create_release(
            organization_id,
            product_id,
            **body.model_dump(),
            actor_id=identity.actor_id,
        ))

    @router.get(
        "/organizations/{organization_id}/products/{product_id}/releases/{release_id}",
        response_model=ReleaseResponse,
    )
    def get_release(
        organization_id: str,
        product_id: str,
        release_id: str,
        repository: Repository,
        _identity: Identity,
    ):
        release = _call(lambda: repository.get_release(organization_id, release_id))
        if release.product_id != product_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "release not found")
        return release

    @router.patch(
        "/organizations/{organization_id}/products/{product_id}/releases/{release_id}",
        response_model=ReleaseResponse,
    )
    def update_release(
        body: ReleaseUpdate,
        organization_id: str,
        product_id: str,
        release_id: str,
        repository: Repository,
        identity: Identity,
    ):
        release = _call(lambda: repository.get_release(organization_id, release_id))
        if release.product_id != product_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "release not found")
        return _call(lambda: repository.update_release(
            organization_id,
            release_id,
            ReleaseChanges(**body.model_dump(exclude_unset=True)),
            identity.actor_id,
        ))

    return router
