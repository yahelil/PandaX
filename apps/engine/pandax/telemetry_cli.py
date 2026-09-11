"""Commands for checking privacy-minimised runtime evidence."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from .telemetry import TelemetryError, summary


app = typer.Typer(
    add_completion=False,
    help="Validate approved runtime evidence before attaching it to a scan.",
)


@app.command("validate")
def validate(path: Path = typer.Argument(..., help="Runtime telemetry JSON file")) -> None:
    """Check the format and show a safe summary without printing device records."""
    try:
        typer.echo(json.dumps(summary(path), ensure_ascii=False, indent=2))
    except (TelemetryError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
