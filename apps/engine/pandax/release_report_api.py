"""Generate and download a private findings report for a product release."""
from collections.abc import Callable

from fastapi import APIRouter, Depends, HTTPException, Response, status

from .auth import Principal, Role, authorize_request
from .document_content import content_disposition
from .documents import DocumentConflict, DocumentRepository
from .findings import FindingRepository
from .portfolio import PortfolioNotFound, PortfolioRepository
from .release_report_service import ReportStorage, generate_release_report
from .release_monitoring import ReleaseMonitoringRepository


REPORT_ROLES = frozenset({Role.ORG_ADMIN, Role.COMPLIANCE_OPERATOR, Role.SECURITY_REVIEWER})


def create_release_report_router(
    portfolio_dependency: Callable[[], PortfolioRepository],
    findings_dependency: Callable[[], FindingRepository],
    documents_dependency: Callable[[], DocumentRepository],
    storage_dependency: Callable[[], ReportStorage],
    identity_dependency: Callable[..., Principal],
    monitoring_dependency: Callable[[], ReleaseMonitoringRepository] | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["release reports"])

    @router.post(
        "/organizations/{organization_id}/products/{product_id}/releases/{release_id}/reports/findings",
    )
    def download_findings_report(
        organization_id: str,
        product_id: str,
        release_id: str,
        portfolio: PortfolioRepository = Depends(portfolio_dependency),
        findings: FindingRepository = Depends(findings_dependency),
        documents: DocumentRepository = Depends(documents_dependency),
        storage: ReportStorage = Depends(storage_dependency),
        principal: Principal = Depends(identity_dependency),
    ) -> Response:
        authorize_request(principal, organization_id, REPORT_ROLES, sensitive=True)
        try:
            product = portfolio.get_product(organization_id, product_id)
            release = portfolio.get_release(organization_id, release_id)
            if release.product_id != product_id:
                raise PortfolioNotFound("release not found in product")
            generated = generate_release_report(
                organization_id=organization_id,
                product_id=product_id,
                release_id=release_id,
                findings=findings,
                documents=documents,
                storage=storage,
                actor_id=principal.subject,
                monitoring=monitoring_dependency() if monitoring_dependency else None,
                product_name=product.name,
                release_version=release.version,
            )
        except PortfolioNotFound as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
        except DocumentConflict as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        except Exception as exc:
            # Storage and document persistence failures must not appear as a download.
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "findings report could not be generated") from exc
        report = generated.report
        return Response(
            content=report.content,
            media_type=report.content_type,
            headers={
                "content-disposition": content_disposition(report.filename),
                "content-length": str(report.size_bytes),
                "x-content-sha256": report.content_hash,
                "x-document-id": generated.document_id,
                "x-document-revision": str(generated.revision),
                "cache-control": "private, no-store",
            },
        )

    return router
