"""The six-stage pipeline: artifact in, signed CRA evidence bundle out.

Stages are generators of Events. This module sequences them, owns the run
context, and closes the run by hash-chaining and signing everything produced.
It renders nothing - see render_cli.py and server.py.
"""

from __future__ import annotations

import shutil
import json
from pathlib import Path
from typing import Any

import yaml

from . import events as ev
from .context import (
    CACHE_DIR,
    KEY_PATH,
    RunContext,
    new_run_dir,
    signing_key_path,
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
    """Run from a product artifact, including ingest and SBOM synthesis."""
    yield from _run(
        artifact,
        input_type="artifact",
        out_base=out_base,
        clock_speed=clock_speed,
        offline=offline,
    )


def run_sbom(
    sbom_path: Path,
    out_base: Path | None = None,
    clock_speed: float = 1.0,
    offline: bool = False,
) -> ev.Stream:
    """Run from a supplied JSON SBOM, skipping artifact ingest and Syft."""
    yield from _run(
        sbom_path,
        input_type="sbom",
        out_base=out_base,
        clock_speed=clock_speed,
        offline=offline,
    )


def _run(
    artifact: Path,
    input_type: str,
    out_base: Path | None,
    clock_speed: float,
    offline: bool,
) -> ev.Stream:
    artifact = Path(artifact).resolve()
    if not artifact.exists():
        label = "SBOM" if input_type == "sbom" else "artifact"
        raise FileNotFoundError(f"{label} not found: {artifact}")

    run_dir, run_id = new_run_dir(out_base)
    ledger = Ledger(run_dir)
    ctx = RunContext(
        artifact=artifact,
        run_dir=run_dir,
        run_id=run_id,
        ledger=ledger,
        clock_speed=clock_speed,
        input_type=input_type,
    )
    ctx.tool_versions["pandax"] = "0.1.0"

    yield ev.log(
        "RUN",
        f"run {run_id} -> {run_dir}",
        ev.INFO,
        run_id=run_id,
        run_dir=str(run_dir),
        artifact=str(artifact),
        input_type=input_type,
    )

    feeds = Feeds(CACHE_DIR, offline=offline)
    try:
        if input_type == "artifact":
            yield from ingest.run(ctx)
            ctx.product = load_product_metadata(artifact, ctx.extracted_dir)
            yield from sbom.run(ctx)
        else:
            reason = "SBOM supplied; product artifact ingestion skipped"
            yield ev.skipped("S1 INGEST", reason, reason=reason)
            ctx.ledger.append(
                stage="S1_INGEST",
                tool="pandax.skip",
                tool_version="0.1.0",
                inputs=[],
                outputs=[],
                params={"reason": reason, "input_type": "sbom"},
            )
            yield from sbom.import_run(ctx)

        product = ctx.product.get("product", {})
        if product:
            yield ev.log(
                "RUN",
                (
                    f"product.yaml: {product.get('name')} v{product.get('version')} "
                    f"(tier: {product.get('risk_tier', 'unknown')})"
                    if input_type == "artifact"
                    else f"SBOM product metadata: {product.get('name')} "
                    f"v{product.get('version', 'unknown')}"
                ),
                ev.GOOD,
            )
        else:
            yield ev.log(
                "RUN",
                (
                    "no product.yaml found - Annex fields will be marked as required input"
                    if input_type == "artifact"
                    else "no unambiguous product identity in SBOM - Annex fields will be marked as required input"
                ),
                ev.WARN,
            )

        yield from match.run(ctx, feeds)
        yield from triage.run(ctx, feeds)
        source_path = ctx.path("release-source.json")
        if source_path.exists():
            from .scenarios import check_release
            result = check_release(ctx, json.loads(source_path.read_text(encoding="utf-8")))
            checks_path = ctx.path("release-checks.json")
            checks_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
            ctx.ledger.append(stage="RELEASE_CHECKS", tool="pandax.scenarios", tool_version="1",
                inputs=[ctx.ledger.ref(source_path), ctx.ledger.ref(ctx.path("native-assessments.json")),
                        ctx.ledger.ref(ctx.sbom_path),
                        ctx.ledger.ref(ctx.path("findings.json"))],
                outputs=[ctx.ledger.ref(checks_path)], params={"oracle_separate_from_matching": True})
            yield ev.log("RUN", "Release checks: " + ("passed" if result['passed'] else "FAILED"),
                         ev.GOOD if result['passed'] else ev.ALERT_LVL)
        yield from clock.run(ctx)
        yield from dossier.run(ctx)
    finally:
        feeds.close()

    # --- seal the bundle -----------------------------------------------------
    yield ev.start(STAGE_SEAL, "hash-chaining and signing the evidence bundle")
    configured_key_path = signing_key_path(KEY_PATH)
    key = load_or_create_key(configured_key_path)
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
    yield ev.log(STAGE_SEAL, f"signing key: {configured_key_path}")
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
        input_type=ctx.input_type,
        sbom_format=ctx.sbom_source_format,
        sbom_version=ctx.sbom_source_version,
        matchable_components=ctx.matchable_components,
        skipped_components=ctx.skipped_components,
        coverage_summary={
            status: sum(
                1
                for check in ctx.vulnerability_coverage
                if check.get("status") == status
            )
            for status in ("completed", "failed", "unknown", "unsupported", "unscanned")
        },
    )


def cleanup_extracted(run_dir: Path) -> None:
    """Optional: drop the unpacked copy, keeping digests and outputs."""
    target = Path(run_dir) / "extracted"
    if target.exists():
        shutil.rmtree(target)
