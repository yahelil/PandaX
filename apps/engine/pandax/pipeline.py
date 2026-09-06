"""The six-stage pipeline: artifact in, signed CRA evidence bundle out.

Stages are generators of Events. This module sequences them, owns the run
context, and closes the run by hash-chaining and signing everything produced.
It renders nothing - see render_cli.py and server.py.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import yaml

from . import events as ev
from .context import (
    CACHE_DIR,
    KEY_PATH,
    RunContext,
    new_run_dir,
)
from .evidence import Ledger, load_or_create_key, sha256_file, write_manifest
from .feeds import Feeds
from .stages import clock, dossier, ingest, match, sbom, triage

STAGE_SEAL = "SEAL"


def load_product_metadata(artifact: Path, extracted: Path | None) -> dict[str, Any]:
    """Manufacturer-attested metadata, read from product.yaml inside the artifact.

    Absent metadata is not invented. Downstream, every missing Annex field is
    rendered as MANUFACTURER INPUT REQUIRED rather than filled with a guess.
    """
    candidates = []
    if extracted is not None:
        candidates.append(extracted / "product.yaml")
    if artifact.is_dir():
        candidates.append(artifact / "product.yaml")
    for candidate in candidates:
        if candidate.exists():
            return yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
    return {}


def run(
    artifact: Path,
    out_base: Path | None = None,
    clock_speed: float = 1.0,
    offline: bool = False,
) -> ev.Stream:
    artifact = Path(artifact).resolve()
    if not artifact.exists():
        raise FileNotFoundError(f"artifact not found: {artifact}")

    run_dir, run_id = new_run_dir(out_base)
    ledger = Ledger(run_dir)
    ctx = RunContext(
        artifact=artifact,
        run_dir=run_dir,
        run_id=run_id,
        ledger=ledger,
        clock_speed=clock_speed,
    )
    ctx.tool_versions["pandax"] = "0.1.0"

    yield ev.log(
        "RUN",
        f"run {run_id} -> {run_dir}",
        ev.INFO,
        run_id=run_id,
        run_dir=str(run_dir),
        artifact=str(artifact),
    )

    feeds = Feeds(CACHE_DIR, offline=offline)
    try:
        yield from ingest.run(ctx)

        ctx.product = load_product_metadata(artifact, ctx.extracted_dir)
        product = ctx.product.get("product", {})
        if product:
            yield ev.log(
                "RUN",
                f"product.yaml: {product.get('name')} v{product.get('version')} "
                f"(tier: {product.get('risk_tier', 'unknown')})",
                ev.GOOD,
            )
        else:
            yield ev.log(
                "RUN",
                "no product.yaml found - Annex fields will be marked as required input",
                ev.WARN,
            )

        yield from sbom.run(ctx)
        yield from match.run(ctx, feeds)
        yield from triage.run(ctx, feeds)
        yield from clock.run(ctx)
        yield from dossier.run(ctx)
    finally:
        feeds.close()

    # --- seal the bundle -----------------------------------------------------
    yield ev.start(STAGE_SEAL, "hash-chaining and signing the evidence bundle")
    key = load_or_create_key(KEY_PATH)
    manifest = write_manifest(
        run_dir=run_dir,
        run_id=run_id,
        product=ctx.product.get("product", {}),
        tool_versions=ctx.tool_versions,
        ledger=ledger,
        key=key,
    )
    yield ev.log(STAGE_SEAL, f"ledger: {len(ledger.records)} chained records")
    yield ev.log(STAGE_SEAL, f"chain root: {manifest['ledger_root']}", ev.GOOD)
    yield ev.log(
        STAGE_SEAL, f"manifest covers {len(manifest['files'])} files", ev.GOOD
    )
    yield ev.log(STAGE_SEAL, f"signing key: {KEY_PATH}")
    yield ev.artifact(
        STAGE_SEAL, "manifest.json", sha256_file(run_dir / "manifest.json")
    )
    yield ev.done(STAGE_SEAL, "bundle sealed with Ed25519")

    yield ev.run_done(
        f"evidence bundle written to {run_dir}",
        ev.ALERT_LVL if ctx.kev_findings else ev.GOOD,
        run_dir=str(run_dir),
        run_id=run_id,
        components=len(ctx.components),
        findings=len(ctx.findings),
        kev=len(ctx.kev_findings),
        incidents=len(ctx.incidents),
    )


def cleanup_extracted(run_dir: Path) -> None:
    """Optional: drop the unpacked copy, keeping digests and outputs."""
    target = Path(run_dir) / "extracted"
    if target.exists():
        shutil.rmtree(target)
