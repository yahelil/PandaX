"""Commands for registering and running continuous product monitoring."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

import typer

from .context import OUT_DIR
from .monitoring import MonitoringError, MonitoringStore


app = typer.Typer(help="Schedule repeat scans and report only meaningful changes.")


def _store() -> MonitoringStore:
    data_dir = Path(os.environ.get("PANDAX_DATA_DIR", OUT_DIR / ".pandax"))
    return MonitoringStore(data_dir / "monitoring.sqlite3")


def _output(operation) -> None:
    try:
        typer.echo(json.dumps(operation(), ensure_ascii=False, indent=2))
    except (MonitoringError, OSError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc


@app.command("add")
def add(
    name: str = typer.Argument(..., help="Product or release name"),
    source: Path = typer.Argument(..., exists=True, help="Artifact directory/archive or SBOM"),
    source_type: str = typer.Option("artifact", "--type", help="artifact or sbom"),
    every_minutes: int = typer.Option(360, "--every-minutes", min=1),
    telemetry: Optional[Path] = typer.Option(
        None,
        "--telemetry",
        help="Approved runtime evidence to attach to every scheduled scan",
    ),
) -> None:
    """Register a product source for repeat checks."""
    _output(
        lambda: _store().add_policy(
            name, source, source_type, every_minutes, telemetry
        )
    )


@app.command("list")
def list_policies() -> None:
    _output(lambda: _store().list_policies())


@app.command("run")
def run(policy_id: Optional[str] = typer.Argument(None)) -> None:
    """Run one policy now, or every policy that is currently due."""
    _output(
        lambda: _store().run_policy(policy_id)
        if policy_id
        else _store().run_due()
    )


@app.command("alerts")
def alerts(policy_id: Optional[str] = typer.Option(None, "--policy")) -> None:
    _output(lambda: _store().list_alerts(policy_id))


@app.command("watch")
def watch(poll_seconds: int = typer.Option(60, "--poll-seconds", min=5)) -> None:
    """Keep running and launch checks when their saved schedule becomes due."""
    store = _store()
    typer.echo("PandaX monitoring started. Press Ctrl+C to stop.")
    try:
        while True:
            results = store.run_due()
            for result in results:
                typer.echo(json.dumps(result, ensure_ascii=False))
            time.sleep(poll_seconds)
    except KeyboardInterrupt:
        typer.echo("PandaX monitoring stopped.")
