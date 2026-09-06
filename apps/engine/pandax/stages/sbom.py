"""S2 SBOM - synthesise a CycloneDX 1.6 bill of materials with Syft.

CRA Annex I Part II(1) requires a "software bill of materials in a commonly
used and machine-readable format covering at the very least the top-level
dependencies". CycloneDX 1.6 satisfies that.

The blueprint's "Zero CVE invariant" - SBOMs record what is *in* the product,
vulnerability state lives in a separate, continuously-updated VEX feed - is
enforced here as an assertion rather than asserted in prose. If Syft ever
started emitting vulnerability data into the SBOM, this stage fails loudly.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .. import events as ev
from ..context import RunContext, syft_binary
from ..evidence import sha256_file

STAGE = "S2 SBOM"
CDX_VERSION = "1.6"


class SbomError(Exception):
    """Raised when SBOM synthesis fails or violates an invariant."""


def syft_version(binary: Path) -> str:
    out = subprocess.run(
        [str(binary), "--version"], capture_output=True, text=True, timeout=60
    )
    return out.stdout.strip().replace("syft ", "") or "unknown"


def run(ctx: RunContext) -> ev.Stream:
    yield ev.start(STAGE, f"synthesising CycloneDX {CDX_VERSION} SBOM")

    binary = syft_binary()
    version = syft_version(binary)
    ctx.tool_versions["syft"] = version
    yield ev.log(STAGE, f"syft {version} (pinned, digest-verified at bootstrap)")

    if ctx.extracted_dir is None:
        raise SbomError("ingest stage did not run")

    out_path = ctx.path("sbom.cdx.json")
    name = str(ctx.product.get("product", {}).get("name", "product")).replace(" ", "-")
    product_version = str(ctx.product.get("product", {}).get("version", "0.0.0"))

    cmd = [
        str(binary),
        "scan",
        f"dir:{ctx.extracted_dir}",
        "-o",
        f"cyclonedx-json@{CDX_VERSION}={out_path}",
        "--source-name",
        name,
        "--source-version",
        product_version,
        "-q",
    ]
    yield ev.log(STAGE, "syft scan dir:<extracted> -o cyclonedx-json@1.6")

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    if proc.returncode != 0 or not out_path.exists():
        raise SbomError(f"syft failed (exit {proc.returncode}): {proc.stderr.strip()}")

    sbom = json.loads(out_path.read_text(encoding="utf-8"))

    # --- invariants, checked not claimed ---
    spec = sbom.get("specVersion")
    if spec != CDX_VERSION:
        raise SbomError(f"expected CycloneDX {CDX_VERSION}, got {spec}")
    yield ev.log(STAGE, f"specVersion == {spec}", ev.GOOD)

    if "vulnerabilities" in sbom:
        raise SbomError(
            "Zero-CVE invariant violated: the SBOM carries vulnerability data. "
            "Component inventory and vulnerability state must stay decoupled."
        )
    yield ev.log(
        STAGE, "zero-CVE invariant holds - no vulnerability data in the SBOM", ev.GOOD
    )

    components = []
    for comp in sbom.get("components", []):
        purl = comp.get("purl")
        if not purl:
            continue
        components.append(
            {
                "purl": purl,
                "name": comp.get("name", ""),
                "version": comp.get("version", ""),
                "type": comp.get("type", "library"),
                "bom_ref": comp.get("bom-ref", purl),
            }
        )
    ctx.sbom = sbom
    ctx.sbom_path = out_path
    ctx.components = components

    ecosystems: dict[str, int] = {}
    for comp in components:
        eco = comp["purl"].split("/")[0].replace("pkg:", "")
        ecosystems[eco] = ecosystems.get(eco, 0) + 1

    yield ev.metric(STAGE, "components", len(components))
    yield ev.metric(
        STAGE,
        "ecosystems",
        ", ".join(f"{k}={v}" for k, v in sorted(ecosystems.items())),
    )
    for comp in components[:12]:
        yield ev.log(STAGE, f"  {comp['purl']}")
    if len(components) > 12:
        yield ev.log(STAGE, f"  ... and {len(components) - 12} more")

    yield ev.artifact(
        STAGE, ctx.ledger.rel(out_path), sha256_file(out_path), "CycloneDX 1.6"
    )

    ctx.ledger.append(
        stage="S2_SBOM",
        tool="syft",
        tool_version=version,
        inputs=[ctx.ledger.ref(ctx.path("ingest_tree.json"))],
        outputs=[ctx.ledger.ref(out_path)],
        params={"format": f"cyclonedx-json@{CDX_VERSION}", "source_name": name},
    )
    yield ev.done(STAGE, f"{len(components)} components inventoried")
