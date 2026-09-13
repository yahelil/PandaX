"""Administration commands for reviewed vendor intelligence."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from .vendor_intelligence import (
    VendorIntelligenceError,
    install as install_catalog,
    load,
    load_active,
    summary,
)


app = typer.Typer(
    add_completion=False,
    help="Manage reviewed vendor advisories and backported-fix decisions.",
)


def _print(operation) -> None:
    try:
        typer.echo(json.dumps(operation(), ensure_ascii=False, indent=2))
    except (VendorIntelligenceError, FileExistsError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc


@app.command("validate")
def validate(path: Path = typer.Argument(..., help="Vendor intelligence JSON")) -> None:
    """Check a catalogue without installing it."""
    _print(lambda: summary(load(path), path))


@app.command("install")
def install(
    path: Path = typer.Argument(..., help="Reviewed vendor intelligence JSON"),
    force: bool = typer.Option(False, "--force", help="Replace the active catalogue"),
) -> None:
    """Install a reviewed catalogue for all scans on this deployment."""
    _print(lambda: install_catalog(path, force=force))


@app.command("status")
def status() -> None:
    """Show the active catalogue without printing its advisory statements."""
    def operation():
        document, path = load_active()
        if document is None:
            return {"installed": False, "path": str(path.resolve())}
        return {"installed": True, **summary(document, path)}

    _print(operation)
