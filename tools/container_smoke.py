"""Runtime-image smoke: non-root writes, real Syft, Typst, and veraPDF."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from pandax.context import syft_binary
from pandax.document_runtime import require_hosted_document_tools


def main() -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise SystemExit("runtime image must execute as non-root")
    with tempfile.TemporaryDirectory(prefix="actis-container-smoke-") as directory:
        root = Path(directory)
        source = root / "source"
        source.mkdir()
        (source / "requirements.txt").write_text("fastapi==0.141.1\n", encoding="utf-8")
        output = root / "sbom.cdx.json"
        subprocess.run(
            [
                str(syft_binary()),
                "scan",
                f"dir:{source}",
                "-o",
                f"cyclonedx-json@1.6={output}",
                "-q",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false"},
        )
        sbom = json.loads(output.read_text(encoding="utf-8"))
        if sbom.get("bomFormat") != "CycloneDX":
            raise SystemExit("Syft did not produce CycloneDX")
    print(json.dumps({"syft": "ok", **require_hosted_document_tools()}, sort_keys=True))


if __name__ == "__main__":
    main()
