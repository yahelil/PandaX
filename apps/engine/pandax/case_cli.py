"""JSON command files preserve request IDs across retries."""
import json
from pathlib import Path
from typing import Optional

import typer

from .case_service import CaseService
from .cases import CaseError

app = typer.Typer(help='Durable local regulatory cases; manual submission only.')


def output(operation):
    try:
        typer.echo(json.dumps(operation(), ensure_ascii=False, indent=2))
    except (CaseError, OSError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc


@app.command('list')
def list_cases():
    output(lambda: CaseService().list())


@app.command()
def show(case_id: str):
    output(lambda: CaseService().get(case_id))


@app.command()
def apply(action: str, input: Path = typer.Option(..., exists=True, dir_okay=False), case_id: Optional[str] = None):
    """Apply create/import-draft/observe-release/confirm-measure from JSON."""
    output(lambda: CaseService().execute(action, json.loads(input.read_text(encoding='utf-8')), case_id))
