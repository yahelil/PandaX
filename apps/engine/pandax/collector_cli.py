"""Windows customer Collector CLI. Collection/export is offline by default."""

from __future__ import annotations

import getpass
import json
import os
from pathlib import Path

import typer

from .collector import CollectorError, collect as collect_package, inspect_package, upload as upload_package

app = typer.Typer(name="actis-collector", help="Collect, sign and optionally upload minimized PandaX evidence")


def _show(preview: dict) -> None:
    typer.echo(json.dumps({
        "package": preview["package"], "sha256": preview["sha256"],
        "files_for_upload": preview["files"], "binding": preview["manifest"],
        "summary": preview["summary"], "coverage": preview["coverage"],
    }, indent=2))


def _approved(approve_upload: bool) -> bool:
    return approve_upload or typer.confirm("Upload exactly this signed package for hosted analysis?", default=False)


def _token(token_env: str) -> str:
    token = os.environ.get(token_env)
    return token if token else getpass.getpass("Short-lived bearer token after MFA login: ")


def _fail(exc: Exception) -> None:
    typer.echo(str(exc), err=True)
    raise typer.Exit(code=1)


@app.command("collect")
def collect_command(
    source: Path = typer.Argument(..., help="Directory, ZIP/TAR archive, CycloneDX or SPDX JSON"),
    output: Path = typer.Option(..., "--output", "-o", help="Offline signed ZIP destination"),
    organization_id: str = typer.Option(..., "--organization-id"),
    product_id: str = typer.Option(..., "--product-id"),
    release_id: str = typer.Option(..., "--release-id"),
    signing_key: Path = typer.Option(..., "--signing-key", help="Customer Ed25519 PEM; no development-key fallback"),
    syft: Path | None = typer.Option(None, "--syft"),
    workspace: Path | None = typer.Option(None, "--workspace"),
) -> None:
    try:
        _show(collect_package(source, output, organization_id=organization_id, product_id=product_id,
                              release_id=release_id, signing_key=signing_key, syft=syft, workspace=workspace))
    except (CollectorError, OSError, ValueError) as exc:
        _fail(exc)


@app.command("upload")
def upload_command(
    package: Path = typer.Argument(..., help="Previously collected signed ZIP"),
    base_url: str = typer.Option(..., "--base-url", envvar="PANDAX_API_URL"),
    token_env: str = typer.Option("PANDAX_ACCESS_TOKEN", "--token-env"),
    idempotency_key: str | None = typer.Option(None, "--idempotency-key"),
    approve_upload: bool = typer.Option(False, "--approve-upload", help="Explicit non-interactive upload approval"),
) -> None:
    try:
        preview = inspect_package(package)
        _show(preview)
        if not _approved(approve_upload):
            typer.echo("Upload cancelled; signed package remains local.")
            return
        result = upload_package(package, base_url=base_url, token=_token(token_env), idempotency_key=idempotency_key)
        typer.echo(json.dumps({"analysis_job_id": result.get("id"), "status": result.get("status")}, indent=2))
    except (CollectorError, OSError, ValueError) as exc:
        _fail(exc)


@app.command("run")
def run_command(
    source: Path = typer.Argument(...),
    output: Path = typer.Option(..., "--output", "-o"),
    organization_id: str = typer.Option(..., "--organization-id"),
    product_id: str = typer.Option(..., "--product-id"),
    release_id: str = typer.Option(..., "--release-id"),
    signing_key: Path = typer.Option(..., "--signing-key"),
    base_url: str = typer.Option(..., "--base-url", envvar="PANDAX_API_URL"),
    token_env: str = typer.Option("PANDAX_ACCESS_TOKEN", "--token-env"),
    idempotency_key: str | None = typer.Option(None, "--idempotency-key"),
    approve_upload: bool = typer.Option(False, "--approve-upload"),
    syft: Path | None = typer.Option(None, "--syft"),
    workspace: Path | None = typer.Option(None, "--workspace"),
) -> None:
    try:
        preview = collect_package(source, output, organization_id=organization_id, product_id=product_id,
                                  release_id=release_id, signing_key=signing_key, syft=syft, workspace=workspace)
        _show(preview)
        if not _approved(approve_upload):
            typer.echo("Upload cancelled; signed package remains local.")
            return
        result = upload_package(output, base_url=base_url, token=_token(token_env), idempotency_key=idempotency_key)
        typer.echo(json.dumps({"analysis_job_id": result.get("id"), "status": result.get("status")}, indent=2))
    except (CollectorError, OSError, ValueError) as exc:
        _fail(exc)
