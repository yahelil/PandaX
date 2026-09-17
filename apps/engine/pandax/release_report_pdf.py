"""Render a reviewed release report as a validated PDF/A-2b document."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Mapping

from . import pdfa
from .evidence import sha256_bytes
from .release_report import ReleaseReport


TEMPLATE = Path(__file__).resolve().parent / "templates" / "release_security_report.typ"


def render_release_report_pdf(
    document: Mapping[str, Any], *, filename: str, validate: bool | None = None,
) -> ReleaseReport:
    import typst

    with tempfile.TemporaryDirectory(prefix="actis-release-pdf-") as directory:
        root = Path(directory)
        (root / "report.json").write_text(
            json.dumps(document, ensure_ascii=False, allow_nan=False), encoding="utf-8"
        )
        template = root / TEMPLATE.name
        shutil.copyfile(TEMPLATE, template)
        output = root / "report.pdf"
        typst.compile(str(template), output=str(output), root=str(root), pdf_standards=["a-2b"])
        should_validate = pdfa.is_available() if validate is None else validate
        if should_validate:
            validation = pdfa.validate_pdf(output, root / "validation")
            if not validation["compliant"]:
                raise RuntimeError(f"release report PDF/A validation failed: {validation['error']}")
        content = output.read_bytes()
    return ReleaseReport(
        document=document,
        content=content,
        content_hash=sha256_bytes(content),
        size_bytes=len(content),
        filename=filename,
        content_type="application/pdf",
    )
