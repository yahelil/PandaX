"""Fail-closed hosted document-tool verification."""

from __future__ import annotations

import tempfile
from functools import lru_cache
from importlib.metadata import version
from pathlib import Path

from . import pdfa
from .stages.dossier import _compile

PINNED_TYPST_VERSION = "0.15.0"


@lru_cache(maxsize=1)
def require_hosted_document_tools() -> dict[str, str]:
    """Compile and standards-validate a tiny PDF/A document once per process."""
    try:
        import typst  # noqa: F401 - importing the native binding is part of readiness

        installed = version("typst")
        if installed != PINNED_TYPST_VERSION:
            raise RuntimeError("pinned Typst version does not match the beta image")

        with tempfile.TemporaryDirectory(prefix="actis-document-ready-") as directory:
            root = Path(directory)
            source = root / "readiness.typ"
            document = root / "readiness.pdf"
            source.write_text("= Actis document readiness", encoding="utf-8")
            error = _compile(source, document, root)
            if error:
                raise RuntimeError("pinned Typst document compiler is unavailable")
            result = pdfa.validate_pdf(document, root / "validation", timeout=30)
        if not result["compliant"]:
            raise RuntimeError("pinned PDF/A document toolchain is unavailable")
        return {"typst": installed, "verapdf": str(result["validator_version"])}
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError("pinned document toolchain is unavailable") from exc
