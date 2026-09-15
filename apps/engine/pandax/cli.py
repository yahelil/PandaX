"""Actis by PandaX command line."""

from __future__ import annotations

import datetime as dt
import json
import os
import random
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__, events as ev
from .context import CACHE_DIR, OUT_DIR, signing_key_path
from .evidence import (
    TrustedKeyConfigurationError,
    load_or_create_key,
    verify_bundle,
    write_public_key,
)
from .render_cli import CliRenderer, banner, render_checks

def _force_utf8() -> None:
    """Windows consoles default to cp1252, which cannot encode the box glyphs.

    Reconfiguring here means the CLI renders identically whether it is attached
    to a terminal, piped into a file, or captured by CI.
    """
    import sys

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


_force_utf8()

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Actis by PandaX: artifact or SBOM to verifiable CRA evidence.",
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"Actis by PandaX {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the Actis version and exit.",
    ),
) -> None:
    """Run Actis locally or in CI."""
from .case_cli import app as case_app
app.add_typer(case_app, name="case")
from .monitor_cli import app as monitor_app
app.add_typer(monitor_app, name="monitor")
from .telemetry_cli import app as telemetry_app
app.add_typer(telemetry_app, name="telemetry")
from .advisory_cli import app as advisory_app
app.add_typer(advisory_app, name="advisory")
from .exposure_cli import app as exposure_app
app.add_typer(exposure_app, name="exposure")
key_app = typer.Typer(add_completion=False, help="Manage the installation signing identity.")
app.add_typer(key_app, name="key")

# legacy_windows=False keeps Rich off the win32 console API, which cannot
# render UTF-8 and is never needed on a modern terminal.
console = Console(legacy_windows=False)


@key_app.command("export-public")
def export_public_key(
    output: Path = typer.Argument(..., help="Destination for the public PEM key"),
    signing_key: Optional[Path] = typer.Option(
        None, "--signing-key", help="Private signing key (default: PANDAX_SIGNING_KEY)"
    ),
    force: bool = typer.Option(False, "--force", help="Replace an existing public-key file"),
) -> None:
    """Export the public verification key without exposing the private key."""
    source = signing_key or signing_key_path()
    try:
        key = load_or_create_key(source)
        fingerprint = write_public_key(key, output, force=force)
    except FileExistsError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except (OSError, TypeError, ValueError) as exc:
        raise typer.BadParameter(f"signing key cannot be used: {exc}") from exc
    console.print(f"[green]public key exported:[/] {output}")
    console.print(f"[dim]SHA-256 fingerprint:[/] [bold cyan]{fingerprint}[/]")
    console.print(
        "[yellow]Distribute this key separately from evidence bundles and confirm "
        "the fingerprint through a trusted administrator channel.[/]"
    )


def _latest_run() -> Path:
    runs = sorted(
        (p for p in OUT_DIR.glob("run-*") if p.is_dir()),
        key=lambda p: p.stat().st_mtime,
    )
    if not runs:
        raise typer.BadParameter(
            "no runs found in workspace/runs/. Run `actis scan <artifact>` first."
        )
    return runs[-1]


def _resolve_run(run_dir: Optional[Path]) -> Path:
    if run_dir is None:
        resolved = _latest_run()
        console.print(f"[dim]using most recent run: {resolved}[/]")
        return resolved
    if not run_dir.exists():
        raise typer.BadParameter(f"run directory not found: {run_dir}")
    return run_dir


# --------------------------------------------------------------------- scan


def _render_pipeline(
    source: Path,
    stream: ev.Stream,
    quiet: bool,
    input_label: str = "artifact",
    subtitle: str = "",
    json_output: Path | None = None,
    sarif_output: Path | None = None,
) -> None:
    banner(console, str(source), subtitle=subtitle, input_label=input_label)
    renderer = CliRenderer(console, verbose=not quiet)

    ctx_holder: dict = {}
    try:
        for event in stream:
            if event.kind == ev.LOG and "run_dir" in event.data:
                ctx_holder["run_dir"] = event.data["run_dir"]
            renderer.handle(event)
    except Exception as exc:
        console.print()
        console.print(
            Panel(
                Text(f"{type(exc).__name__}: {exc}", style="bold red"),
                title="PIPELINE FAILED",
                border_style="red",
                padding=(1, 2),
            )
        )
        raise typer.Exit(code=1)

    run_dir = renderer.summary.get("run_dir") or ctx_holder.get("run_dir", "")
    findings = []
    findings_path = Path(run_dir) / "findings.json" if run_dir else None
    if findings_path and findings_path.exists():
        from .context import Finding

        findings = [
            Finding(**row) for row in json.loads(findings_path.read_text(encoding="utf-8"))
        ]
    if run_dir and (json_output is not None or sarif_output is not None):
        from .ci_report import write_reports

        try:
            write_reports(
                Path(run_dir),
                renderer.summary,
                json_output=json_output,
                sarif_output=sarif_output,
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            console.print(f"[bold red]CI report failed:[/] {exc}")
            raise typer.Exit(code=1) from exc
    renderer.final_report(findings, str(run_dir))

    if renderer.summary.get("kev"):
        raise typer.Exit(code=2)


@app.command()
def scan(
    artifact: Path = typer.Argument(..., help="Product artifact: .zip, .tar.gz, or directory"),
    out: Optional[Path] = typer.Option(None, "--out", help="Output base directory"),
    offline: bool = typer.Option(False, "--offline", help="Use cached feeds only"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress per-file detail"),
    telemetry: Optional[Path] = typer.Option(
        None,
        "--telemetry",
        help="Approved, privacy-minimised runtime evidence JSON",
    ),
    exposure_context: Optional[Path] = typer.Option(
        None,
        "--exposure-context",
        help="Reviewed build, feature and network-exposure evidence JSON",
    ),
    json_output: Optional[Path] = typer.Option(
        None, "--json-output", help="Write CI summary JSON outside the sealed bundle"
    ),
    sarif_output: Optional[Path] = typer.Option(
        None, "--sarif-output", help="Write SARIF 2.1.0 outside the sealed bundle"
    ),
) -> None:
    """Run the full pipeline: ingest, SBOM, match, triage, Article 14, dossier."""
    from . import pipeline

    optional = {}
    if telemetry is not None:
        optional["telemetry_path"] = telemetry
    if exposure_context is not None:
        optional["exposure_context_path"] = exposure_context
    stream = pipeline.run(artifact, out_base=out, offline=offline, **optional)
    _render_pipeline(
        artifact,
        stream,
        quiet,
        json_output=json_output,
        sarif_output=sarif_output,
    )


@app.command("scan-sbom")
def scan_sbom(
    sbom_file: Path = typer.Argument(..., help="CycloneDX 1.2/1.6 or SPDX 2.2/2.3 JSON SBOM"),
    out: Optional[Path] = typer.Option(None, "--out", help="Output base directory"),
    offline: bool = typer.Option(False, "--offline", help="Use cached feeds only"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress per-file detail"),
    telemetry: Optional[Path] = typer.Option(
        None,
        "--telemetry",
        help="Approved, privacy-minimised runtime evidence JSON",
    ),
    exposure_context: Optional[Path] = typer.Option(
        None,
        "--exposure-context",
        help="Reviewed build, feature and network-exposure evidence JSON",
    ),
    json_output: Optional[Path] = typer.Option(
        None, "--json-output", help="Write CI summary JSON outside the sealed bundle"
    ),
    sarif_output: Optional[Path] = typer.Option(
        None, "--sarif-output", help="Write SARIF 2.1.0 outside the sealed bundle"
    ),
) -> None:
    """Run from an existing JSON SBOM, skipping artifact ingest and Syft."""
    from . import pipeline

    optional = {}
    if telemetry is not None:
        optional["telemetry_path"] = telemetry
    if exposure_context is not None:
        optional["exposure_context_path"] = exposure_context
    stream = pipeline.run_sbom(sbom_file, out_base=out, offline=offline, **optional)
    _render_pipeline(
        sbom_file,
        stream,
        quiet,
        input_label="SBOM",
        subtitle="format is detected automatically; input is preserved in the sealed bundle",
        json_output=json_output,
        sarif_output=sarif_output,
    )


# ------------------------------------------------------------------ verdict


def _load_run(target: Path) -> tuple[dict, list, list, dict]:
    def load(name: str, default):
        path = target / name
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default

    dossier = load("dossier.json", {})
    return (
        dossier.get("product", {}),
        load("findings.json", []),
        load("incidents.json", []),
        dossier,
    )


@app.command()
def verdict(
    run_dir: Optional[Path] = typer.Argument(None, help="Run directory (default: latest)"),
) -> None:
    """Answer the only question that matters: can this product go on the market?"""
    from .render_verdict import render
    from .verdict import build_verdict

    target = _resolve_run(run_dir)
    product, findings, incidents, dossier = _load_run(target)
    if not dossier:
        raise typer.BadParameter(f"{target} has no dossier.json - not a completed run")

    result = build_verdict(findings, incidents, dossier)
    render(console, product, result)
    console.print(
        Text("  evidence: ", style="dim")
        + Text(str(target), style="cyan")
        + Text("   verify with ", style="dim")
        + Text(f"actis verify {target.name}", style="bold cyan")
    )
    console.print()
    raise typer.Exit(code=0 if result.can_ship else 2)


# ------------------------------------------------------------------- verify


@app.command()
def verify(
    run_dir: Optional[Path] = typer.Argument(None, help="Run directory (default: latest)"),
    trusted_key: Optional[Path] = typer.Option(
        None,
        "--trusted-key",
        help="Independently supplied Ed25519 public key (default: PANDAX_TRUSTED_KEY)",
    ),
    inspect_only: bool = typer.Option(
        False,
        "--inspect-only",
        help="Inspect internal integrity without claiming that the signer is trusted",
    ),
    online: bool = typer.Option(
        False, "--online", help="Also re-query OSV.dev to confirm findings reproduce"
    ),
) -> None:
    """Verify bundle integrity and signer trust as separate claims."""
    if trusted_key is not None and inspect_only:
        raise typer.BadParameter("--trusted-key and --inspect-only cannot be used together")
    target = _resolve_run(run_dir)
    console.print()
    console.print(
        Panel(
            Text(
                "Recomputing every hash and chain link from the files on disk. "
                "Signer trust is checked only against a public key supplied "
                "separately from this evidence bundle.",
                style="dim",
            ),
            title=f"Verifying {target.name}",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    configured = None
    if not inspect_only:
        configured = trusted_key or (
            Path(os.environ["PANDAX_TRUSTED_KEY"])
            if os.environ.get("PANDAX_TRUSTED_KEY")
            else None
        )
    try:
        result = verify_bundle(target, configured)
    except TrustedKeyConfigurationError as exc:
        console.print(f"[bold red]Trusted-key configuration error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    if online:
        result.checks.append(_reproduce_findings(target))

    ok = render_checks(
        console,
        result,
        f"Verification — {target}",
        inspect_only=inspect_only,
    )
    raise typer.Exit(code=0 if ok else 1)


def _reproduce_findings(run_dir: Path):
    """Re-query OSV for the recorded components and compare the CVE sets.

    Comparison is on CVE identity, not OSV advisory id. Several advisories can
    describe the same CVE for the same package, and a scan keeps one row per
    (CVE, component) - so comparing raw advisory ids would report deduplicated
    entries as if they were newly published, which is simply untrue.

    A recorded CVE that the live feed no longer returns is a real discrepancy.
    A CVE that appeared since the scan is expected drift, reported but not failed:
    the bundle attests to what was known when it was sealed.
    """
    from .evidence import Check
    from .feeds import Feeds, FeedError

    sbom_path = run_dir / "sbom.cdx.json"
    findings_path = run_dir / "findings.json"
    if not sbom_path.exists() or not findings_path.exists():
        return Check("OSV reproducibility", False, "sbom.cdx.json or findings.json missing")

    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    purls = [c["purl"] for c in sbom.get("components", []) if c.get("purl")]
    recorded = {row["cve"] for row in json.loads(findings_path.read_text(encoding="utf-8"))
                if row.get("source", "OSV") == "OSV"}

    feeds = Feeds(CACHE_DIR)
    try:
        live: set[str] = set()
        for advisory_ids in feeds.query_purls(purls).values():
            for advisory_id in advisory_ids:
                detail = feeds.vuln_detail(advisory_id)
                aliases = [a for a in detail.get("aliases", []) if a.startswith("CVE-")]
                live.update(aliases or [advisory_id])
    except FeedError as exc:
        return Check("OSV reproducibility", False, str(exc))
    finally:
        feeds.close()

    missing = recorded - live
    appeared = live - recorded
    if missing:
        return Check(
            "OSV reproducibility",
            False,
            f"{len(missing)} recorded CVEs are no longer returned by OSV: "
            + ", ".join(sorted(missing)[:5]),
        )
    if appeared:
        return Check(
            "OSV reproducibility",
            True,
            f"all {len(recorded)} recorded CVEs still reproduce; "
            f"{len(appeared)} newly published since the scan",
        )
    return Check(
        "OSV reproducibility",
        True,
        f"all {len(recorded)} CVEs reproduce exactly against the live feed",
    )


# ------------------------------------------------------------------- tamper


@app.command()
def tamper(
    run_dir: Optional[Path] = typer.Argument(None, help="Run directory (default: latest)"),
    target: str = typer.Option(
        "sbom.cdx.json", "--target", help="File inside the bundle to corrupt"
    ),
) -> None:
    """Flip one byte in a sealed bundle, to prove the verifier actually catches it."""
    bundle = _resolve_run(run_dir)
    victim = bundle / target
    if not victim.exists():
        raise typer.BadParameter(f"{target} not found in {bundle}")

    blob = bytearray(victim.read_bytes())
    # Pick a byte inside a digit run so the file stays valid JSON and the only
    # thing that changed is the content - not the ability to parse it.
    candidates = [i for i, b in enumerate(blob) if chr(b).isdigit()]
    index = random.choice(candidates) if candidates else len(blob) // 2
    before = chr(blob[index])
    blob[index] = ord("9") if before != "9" else ord("8")
    victim.write_bytes(bytes(blob))

    console.print()
    console.print(
        Panel(
            Text.assemble(
                ("Corrupted ", "dim"),
                (str(target), "bold yellow"),
                (f" at byte offset {index}: ", "dim"),
                (f"'{before}'", "bold"),
                (" -> ", "dim"),
                (f"'{chr(blob[index])}'", "bold red"),
                ("\n\nThe file is still valid JSON and still looks entirely "
                 "plausible to a human reader. Run ", "dim"),
                (f"actis verify {bundle}", "bold cyan"),
                (" to see the seal catch it.", "dim"),
            ),
            title="ONE BYTE CHANGED",
            border_style="yellow",
            padding=(1, 2),
        )
    )
    console.print()


# -------------------------------------------------------------------- clock


@app.command()
def clock(
    run_dir: Optional[Path] = typer.Argument(None, help="Run directory (default: latest)"),
    speed: float = typer.Option(
        1.0,
        "--speed",
        help="Compress elapsed time for demos (3600 = one second per hour)",
    ),
) -> None:
    """Show live Article 14 countdowns for every open incident."""
    from .stages.clock import PENDING_FINAL_REPORT, parse_timestamp, remaining_seconds

    target = _resolve_run(run_dir)
    incidents_path = target / "incidents.json"
    if not incidents_path.exists():
        console.print()
        console.print(
            Panel(
                Text(
                    "No Article 14 incidents were opened for this run: no "
                    "actively exploited vulnerabilities were found.",
                    style="green",
                ),
                title="No reporting obligation",
                border_style="green",
                padding=(1, 2),
            )
        )
        return

    incidents = json.loads(incidents_path.read_text(encoding="utf-8"))
    now = dt.datetime.now(dt.timezone.utc)

    def _remaining(due_iso: str | None, display_now: dt.datetime) -> Text:
        remaining = remaining_seconds(due_iso, display_now)
        if remaining is None:
            return Text(PENDING_FINAL_REPORT, style="yellow")
        seconds = int(remaining)
        if seconds <= 0:
            return Text(f"OVERDUE {abs(seconds) // 3600}h", style="bold white on red")
        hours, rest = divmod(seconds, 3600)
        style = "bold red" if hours < 24 else "yellow"
        return Text(f"{hours}h {rest // 60:02d}m", style=style)

    table = Table(
        title=f"CRA Article 14 reporting clocks - {len(incidents)} open incident(s)",
        title_style="bold red",
        border_style="red",
        header_style="bold",
        pad_edge=False,
        caption="(a) 24h early warning  (b) 72h vulnerability notification  "
                "(c) 14d final report - Art.14(2)",
        caption_style="dim",
    )
    table.add_column("CVE", style="bold red", no_wrap=True)
    table.add_column("Component", max_width=16, overflow="ellipsis", no_wrap=True)
    table.add_column("24h (a)", justify="right", no_wrap=True)
    table.add_column("72h (b)", justify="right", no_wrap=True)
    table.add_column("14d (c)", justify="right")

    for incident in incidents:
        aware = parse_timestamp(incident["aware_at"])
        # Simulation affects display only; stored timestamps remain untouched.
        display_now = now if speed == 1.0 else aware + (now - aware) * speed
        due = incident["deadlines"]
        table.add_row(
            incident["cve"],
            incident["component"],
            _remaining(due.get("early_warning"), display_now),
            _remaining(due.get("notification"), display_now),
            _remaining(due.get("final_report"), display_now),
        )

    console.print()
    if speed != 1.0 and incidents:
        aware0 = parse_timestamp(incidents[0]["aware_at"])
        scaled_hours = (now - aware0).total_seconds() * speed / 3600
        console.print(
            f"[yellow]demo clock x{speed:,.0f}: "
            f"{(now - aware0).total_seconds():.0f}s real = "
            f"{scaled_hours:.1f}h elapsed. "
            f"Stored deadlines are the real statutory ones.[/]"
        )
    console.print(table)
    console.print()
    console.print(
        Text("  filing drafts: ", style="dim")
        + Text(str(target / "filings"), style="cyan")
    )
    console.print(
        Text(
            "  Submission route: ENISA single reporting platform (Art.16), which "
            "is not operational until 11 Sept 2026.",
            style="dim",
        )
    )
    console.print()


# -------------------------------------------------------------------- serve


def _dashboard_repository_root() -> Path:
    candidates = (Path.cwd(), *Path.cwd().parents, *Path(__file__).resolve().parents)
    for candidate in candidates:
        if (candidate / "apps" / "dashboard" / "package.json").is_file():
            return candidate
    raise RuntimeError(
        "Actis dashboard sources were not found. Run this command from the Actis repository checkout."
    )


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address"),
    port: int = typer.Option(4175, min=1, max=65535, help="Port"),
) -> None:
    """Run the Actis React dashboard with Vite hot reload."""
    npm = shutil.which("npm")
    if npm is None:
        typer.echo("npm was not found. Install Node.js and try again.", err=True)
        raise typer.Exit(1)
    try:
        root = _dashboard_repository_root()
    except RuntimeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"Actis dashboard: http://{host}:{port}")
    result = subprocess.run(
        [npm, "run", "dev", "--workspace", "@pandax/dashboard", "--", "--host", host, "--port", str(port)],
        cwd=root,
        check=False,
    )
    if result.returncode:
        raise typer.Exit(result.returncode)


@app.command()
def compare(scenario: str = typer.Argument(..., help="Scenario id, or 'list'"),
            out: Optional[Path] = typer.Option(None, "--out")) -> None:
    """Download both releases, scan them and seal a comparison (including failures)."""
    from .scenarios import SCENARIOS, run_scenario
    if scenario == 'list':
        for item in SCENARIOS.values():
            console.print(f"{item['id']}: {item['before']} → {item['after']}")
        return
    if scenario not in SCENARIOS:
        raise typer.BadParameter('Unknown scenario. Run actis compare list')
    renderer = CliRenderer(console)
    summary = {}
    for event in run_scenario(scenario, out_base=out):
        renderer.handle(event)
        if event.kind == ev.RUN_DONE:
            summary = event.data
    report = summary.get('comparison', {})
    for row in report.get('rows', []):
        console.print(f"{'PASS' if row['passed'] else 'FAIL'} {row['cve']}: "
                      f"{row['before']['observed']} → {row['after']['observed']} — {row['result']}")
    console.print(f"Evidence: {summary.get('run_dir', '')}")
    raise typer.Exit(code=0 if report.get('passed') else 1)


if __name__ == "__main__":
    app()
