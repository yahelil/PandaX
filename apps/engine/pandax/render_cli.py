"""Rich terminal presentation of the pipeline event stream.

Contains no pipeline logic: it renders whatever events arrive, exactly as the
SSE dashboard does. Anything shown here is shown there.
"""

from __future__ import annotations

import time
from typing import Any, Iterable

from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from . import events as ev

LEVEL_STYLE = {
    ev.INFO: "dim",
    ev.GOOD: "green",
    ev.WARN: "yellow",
    ev.ALERT_LVL: "bold red",
}
LEVEL_MARK = {
    ev.INFO: "·",  # middot
    ev.GOOD: "✓",  # check
    ev.WARN: "!",
    ev.ALERT_LVL: "▶",  # triangle
}

BANNER = "PandaX — CRA Compliance Engine"


def banner(console: Console, artifact: str, subtitle: str = "") -> None:
    body = Text()
    body.append("Regulation (EU) 2024/2847 ", style="bold")
    body.append("— artifact → SBOM → CVE → KEV → "
                "Art.14 → Annex VII, sealed and verifiable", style="dim")
    body.append("\n\nartifact  ", style="dim")
    body.append(artifact, style="bold cyan")
    if subtitle:
        body.append("\n" + subtitle, style="dim")
    console.print(Panel(body, title=BANNER, border_style="cyan", padding=(1, 2)))


class CliRenderer:
    """Streams events to the terminal, one stage block at a time."""

    def __init__(self, console: Console | None = None, verbose: bool = True):
        self.console = console or Console()
        self.verbose = verbose
        self.stage_started: dict[str, float] = {}
        self.summary: dict[str, Any] = {}
        self.alerts: list[str] = []

    def handle(self, event: ev.Event) -> None:
        console = self.console

        if event.kind == ev.STAGE_START:
            self.stage_started[event.stage] = time.perf_counter()
            console.print()
            header = Text()
            header.append(f"  {event.stage}  ", style="bold white on blue")
            header.append(f" {event.message}", style="bold")
            console.print(header)

        elif event.kind == ev.LOG:
            if not self.verbose and event.level == ev.INFO:
                return
            mark = LEVEL_MARK.get(event.level, "·")
            style = LEVEL_STYLE.get(event.level, "dim")
            console.print(f"      [{style}]{mark}[/] [{style}]{event.message}[/]")

        elif event.kind == ev.METRIC:
            label = str(event.data.get("label", ""))
            value = str(event.data.get("value", ""))
            console.print(
                f"        [dim]{label:<26}[/] [bold bright_white]{value}[/]"
            )

        elif event.kind == ev.ARTIFACT:
            digest = str(event.data.get("sha256", ""))[:16]
            note = event.data.get("note", "")
            suffix = f" [dim]({note})[/]" if note else ""
            console.print(
                f"      [green]→[/] [bold]{event.data.get('path')}[/]"
                f"  [dim]sha256 {digest}...[/]{suffix}"
            )

        elif event.kind == ev.ALERT:
            self.alerts.append(event.message)
            console.print(f"      [bold red]▶ {event.message}[/]")

        elif event.kind == ev.STAGE_DONE:
            elapsed = time.perf_counter() - self.stage_started.get(
                event.stage, time.perf_counter()
            )
            colour = "red" if event.level == ev.ALERT_LVL else "green"
            console.print(
                f"    [{colour}]✔[/] [bold]{event.stage}[/] "
                f"[{colour}]{event.message}[/] [dim]({elapsed:.2f}s)[/]"
            )

        elif event.kind == ev.RUN_DONE:
            self.summary = dict(event.data)
            self.summary["message"] = event.message
            self.summary["level"] = event.level

    def consume(self, stream: Iterable[ev.Event]) -> dict[str, Any]:
        for event in stream:
            self.handle(event)
        return self.summary

    def final_report(self, findings: list, run_dir: str) -> None:
        console = self.console
        console.print()
        console.print(Rule(style="dim"))

        stats = Table.grid(padding=(0, 3))
        stats.add_column(justify="right", style="bold bright_white")
        stats.add_column(style="dim")
        stats.add_row(str(self.summary.get("components", 0)), "components inventoried")
        stats.add_row(str(self.summary.get("findings", 0)), "known vulnerabilities")
        kev = int(self.summary.get("kev", 0))
        stats.add_row(
            Text(str(kev), style="bold red" if kev else "bold green"),
            "actively exploited (CISA KEV)",
        )
        stats.add_row(
            str(self.summary.get("incidents", 0)), "Article 14 clocks armed"
        )

        console.print()
        console.print(stats)

        kev_findings = [f for f in findings if f.kev]
        if kev_findings:
            console.print()
            table = Table(
                title="Actively exploited — CRA Article 14(1) engaged",
                title_style="bold red",
                border_style="red",
                header_style="bold",
                expand=False,
            )
            table.add_column("CVE", style="bold red")
            table.add_column("Component")
            table.add_column("Severity")
            table.add_column("EPSS", justify="right")
            table.add_column("KEV since")
            table.add_column("Fixed in")
            for f in sorted(kev_findings, key=lambda f: -f.epss):
                table.add_row(
                    f.cve,
                    f"{f.component} {f.version}",
                    f.severity,
                    f"{f.epss:.5f}",
                    f.kev_date_added,
                    f.fixed_version or "[yellow]none[/]",
                )
            console.print(table)

        console.print()
        outputs = Table.grid(padding=(0, 2))
        outputs.add_column(style="cyan")
        outputs.add_column(style="dim")
        for name, desc in (
            ("sbom.cdx.json", "CycloneDX 1.6 SBOM (Annex I Part II(1))"),
            ("findings.cdx-vex.json", "CycloneDX VEX — exploitation status"),
            ("filings/", "ENISA Article 14 filing drafts (24h / 72h / 14d)"),
            ("AnnexVII_Technical_Documentation.pdf", "Annex VII dossier, PDF/A-2b"),
            ("EU_Declaration_of_Conformity.pdf", "Annex V declaration, PDF/A-2b"),
            ("ledger.jsonl", "hash-chained evidence of every stage"),
            ("manifest.json + manifest.sig", "Ed25519-sealed bundle"),
        ):
            outputs.add_row(name, desc)
        console.print(
            Panel(
                Group(Text(run_dir, style="bold"), Text(""), outputs),
                title="Evidence bundle",
                border_style="green",
                padding=(1, 2),
            )
        )

        console.print()
        console.print(
            Text("  next: ", style="dim")
            + Text(f"pandax verify {run_dir}", style="bold cyan")
            + Text("   then   ", style="dim")
            + Text(f"pandax tamper {run_dir}", style="bold yellow")
            + Text(" to watch it fail", style="dim")
        )
        console.print()


def render_checks(console: Console, checks, title: str) -> bool:
    """Render verification results. Returns True if everything passed."""
    all_ok = all(c.ok for c in checks)
    table = Table(
        title=title,
        title_style="bold",
        border_style="green" if all_ok else "red",
        header_style="bold",
        expand=False,
    )
    table.add_column("", width=3)
    table.add_column("Check")
    table.add_column("Detail", style="dim", overflow="fold", max_width=70)
    for check in checks:
        table.add_row(
            "[green]✔[/]" if check.ok else "[bold red]✘[/]",
            Text(check.name, style="" if check.ok else "bold red"),
            check.detail,
        )
    console.print()
    console.print(table)
    console.print()
    if all_ok:
        console.print(
            Panel(
                Text(
                    "All checks passed. Every digest was recomputed, every chain "
                    "link re-derived, and the Ed25519 signature verified against "
                    "the bundled public key.\n\nThis proves the bundle has not "
                    "been altered since it was sealed. It does not prove the "
                    "legal identity of the signer — that requires an eIDAS "
                    "qualified electronic seal.",
                    style="green",
                ),
                title="VERIFIED",
                border_style="green",
                padding=(1, 2),
            )
        )
    else:
        failed = [c for c in checks if not c.ok]
        body = Text(
            "The evidence bundle does not match its seal. Failed checks:\n\n",
            style="bold red",
        )
        for check in failed:
            body.append(f"  ✘ {check.name}\n", style="bold red")
            body.append(f"    {check.detail}\n", style="red")
        body.append(
            "\nA regulator reading this bundle would reject it: the documents "
            "on disk are not the documents that were signed.",
            style="dim",
        )
        console.print(
            Panel(body, title="TAMPERING DETECTED", border_style="red", padding=(1, 2))
        )
    console.print()
    return all_ok
