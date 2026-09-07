"""The one screen a manufacturer reads: can this product go on the market?"""

from __future__ import annotations

import datetime as dt

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .verdict import Verdict


def _countdown(due_iso: str, now: dt.datetime) -> Text:
    due = dt.datetime.fromisoformat(due_iso.replace("Z", "+00:00"))
    seconds = int((due - now).total_seconds())
    if seconds <= 0:
        return Text(f"OVERDUE by {abs(seconds) // 3600}h", style="bold white on red")
    hours, rest = divmod(seconds, 3600)
    style = "bold red" if hours < 24 else "yellow"
    return Text(f"{hours}h {rest // 60:02d}m left", style=style)


def render(console: Console, product: dict, verdict: Verdict) -> None:
    name = product.get("name", "product")
    version = product.get("version", "")

    # --- the headline -------------------------------------------------------
    if verdict.can_ship:
        headline = Text("YES", style="bold white on green")
        message = Text(
            "\n\nNo blocking issues found. The technical file is complete and the "
            "product carries no known exploitable vulnerabilities.",
            style="green",
        )
    else:
        count = len(verdict.blockers)
        headline = Text(f"NO — {count} blocker{'s' if count != 1 else ''}", style="bold white on red")
        message = Text(
            "\n\nThis product cannot lawfully be placed on the EU market until the "
            "items below are resolved.",
            style="red",
        )

    console.print()
    console.print(
        Panel(
            Group(headline, message),
            title=f"Can {name} {version} be placed on the EU market?",
            border_style="green" if verdict.can_ship else "red",
            padding=(1, 2),
        )
    )

    # --- blockers -----------------------------------------------------------
    for group, label, colour in (
        (verdict.blockers, "BLOCKERS", "red"),
        (verdict.warnings, "WARNINGS", "yellow"),
    ):
        if not group:
            continue
        console.print()
        console.print(Text(f"  {label}", style=f"bold {colour}"))
        for item in group:
            console.print(
                Text("    ✘ " if colour == "red" else "    ! ", style=f"bold {colour}")
                + Text(item.title, style="bold")
                + Text(f"   [{item.article}]", style="dim")
            )
            console.print(Text(f"        {item.detail}", style="dim"))
            console.print(Text(f"        → {item.action}", style=colour))

    # --- statutory clocks ---------------------------------------------------
    if verdict.deadlines:
        now = dt.datetime.now(dt.timezone.utc)
        console.print()
        console.print(Text("  DEADLINES RUNNING NOW", style="bold red"))
        table = Table(
            box=None, pad_edge=False, show_header=True, header_style="dim", padding=(0, 2)
        )
        table.add_column("  Filing", no_wrap=True)
        table.add_column("Article", style="dim", no_wrap=True)
        table.add_column("Covers", style="dim", no_wrap=True)
        table.add_column("Due (UTC)", style="dim", no_wrap=True)
        table.add_column("", justify="right", no_wrap=True)

        # Incidents detected in one scan share a deadline, so one row per filing
        # type reads better than one per CVE.
        grouped: dict[tuple[str, str, str], list[str]] = {}
        for row in verdict.deadlines:
            grouped.setdefault(
                (row["filing"], row["article"], row["due"]), []
            ).append(row["cve"])

        for (filing, article, due_iso), cves in sorted(
            grouped.items(), key=lambda kv: kv[0][2]
        ):
            due = dt.datetime.fromisoformat(due_iso.replace("Z", "+00:00"))
            covers = cves[0] if len(cves) == 1 else f"{len(cves)} incidents"
            table.add_row(
                "  " + filing,
                article,
                covers,
                due.strftime("%d %b %H:%M"),
                _countdown(due_iso, now),
            )
        console.print(table)

    # --- the fix list -------------------------------------------------------
    actionable = [u for u in verdict.upgrades if u.actionable]
    if actionable:
        total_cves = sum(len(u.cves) for u in verdict.upgrades)
        console.print()
        console.print(
            Text("  TO FIX EVERYTHING: ", style="bold")
            + Text(f"{len(actionable)} package upgrades", style="bold cyan")
            + Text(f"  (clears {total_cves} findings)", style="dim")
        )
        table = Table(
            box=None, pad_edge=False, show_header=True, header_style="dim", padding=(0, 2)
        )
        table.add_column("  Package", no_wrap=True)
        table.add_column("Upgrade", no_wrap=True)
        table.add_column("Clears", justify="right", no_wrap=True)
        table.add_column("", no_wrap=True)
        for upgrade in actionable:
            table.add_row(
                "  " + upgrade.component,
                Text(upgrade.version, style="dim")
                + Text("  →  ", style="dim")
                + Text(upgrade.target, style="bold cyan"),
                str(len(upgrade.cves)),
                Text(f"{len(upgrade.kev)} exploited", style="bold red")
                if upgrade.kev
                else "",
            )
        console.print(table)

    stuck = [u for u in verdict.upgrades if not u.actionable]
    if stuck:
        console.print()
        console.print(
            Text("  NO UPGRADE AVAILABLE — needs a documented mitigation", style="bold yellow")
        )
        for upgrade in stuck:
            console.print(
                Text(f"    {upgrade.component} {upgrade.version}", style="bold")
                + Text(f"   {len(upgrade.cves)} findings", style="dim")
            )
    console.print()
