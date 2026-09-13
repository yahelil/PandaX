"""Commands for checking reviewed product exposure context."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from .exposure import ExposureError, summary


app = typer.Typer(
    add_completion=False,
    help="Validate reviewed build, configuration and network-exposure facts.",
)


@app.command("validate")
def validate(path: Path = typer.Argument(..., help="Exposure context JSON")) -> None:
    """Check the format without printing component-level evidence."""
    try:
        typer.echo(json.dumps(summary(path), ensure_ascii=False, indent=2))
    except (ExposureError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
