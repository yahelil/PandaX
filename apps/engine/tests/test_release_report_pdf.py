from datetime import datetime, timezone

from pandax.release_report import build_release_report
from pandax.release_report_pdf import render_release_report_pdf


def test_release_pdf_renders_without_a_finding_or_manufacturer_attestation():
    report = build_release_report(
        organization_id="org-a", product_id="product-a", release_id="release-1",
        product_name="Sensor A", release_version="1.0.0", findings=[],
        generated_at=datetime(2026, 9, 17, tzinfo=timezone.utc),
    )
    rendered = render_release_report_pdf(report, filename="report.pdf", validate=False)
    assert rendered.content.startswith(b"%PDF-")
    assert rendered.content_type == "application/pdf"
    assert rendered.size_bytes > 2000
