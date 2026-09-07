"""The single contract shared by every stage and both renderers.

Stages are pure generators of Events. Neither the Rich CLI nor the SSE
dashboard contains pipeline logic - they are two renderings of one stream.
That is what makes a first-class CLI *and* a first-class dashboard affordable.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Iterator

# Event kinds
STAGE_START = "stage_start"
LOG = "log"
METRIC = "metric"
ARTIFACT = "artifact"
ALERT = "alert"
TABLE = "table"
STAGE_DONE = "stage_done"
STAGE_SKIPPED = "stage_skipped"
RUN_DONE = "run_done"

# The pipeline's stages, in order. Both renderers use this to show progress
# as "[n/7]", so the sequence lives here rather than in either renderer.
PIPELINE_STAGES = [
    "S1 INGEST",
    "S2 SBOM",
    "S3 MATCH",
    "S4 TRIAGE",
    "S5 CLOCK",
    "S6 DOSSIER",
    "SEAL",
]


def stage_number(stage: str) -> str:
    """'S2 SBOM' -> '[2/7]'. Unknown stages get blank padding, not a wrong index."""
    try:
        return f"[{PIPELINE_STAGES.index(stage) + 1}/{len(PIPELINE_STAGES)}]"
    except ValueError:
        return " " * 5

# Levels drive colour in both renderers.
INFO, GOOD, WARN, ALERT_LVL = "info", "good", "warn", "alert"


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


@dataclass
class Event:
    kind: str
    stage: str = ""
    message: str = ""
    level: str = INFO
    data: dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=now_iso)

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# --- constructors, so stages read as prose ----------------------------------

def start(stage: str, message: str) -> Event:
    return Event(STAGE_START, stage, message)


def log(stage: str, message: str, level: str = INFO, **data: Any) -> Event:
    return Event(LOG, stage, message, level, data)


def metric(stage: str, label: str, value: Any, level: str = INFO) -> Event:
    return Event(METRIC, stage, label, level, {"label": label, "value": value})


def artifact(stage: str, path: str, sha256: str, note: str = "") -> Event:
    return Event(
        ARTIFACT, stage, path, GOOD, {"path": path, "sha256": sha256, "note": note}
    )


def alert(stage: str, message: str, **data: Any) -> Event:
    return Event(ALERT, stage, message, ALERT_LVL, data)


def table(
    stage: str,
    title: str,
    columns: list[str],
    rows: list[list[str]],
    level: str = INFO,
) -> Event:
    """A small tabular result. The CLI draws it as a box; the browser as a table."""
    return Event(
        TABLE, stage, title, level, {"title": title, "columns": columns, "rows": rows}
    )


def done(stage: str, message: str, level: str = GOOD, **data: Any) -> Event:
    return Event(STAGE_DONE, stage, message, level, data)


def skipped(stage: str, message: str, **data: Any) -> Event:
    return Event(STAGE_SKIPPED, stage, message, WARN, data)


def run_done(message: str, level: str = GOOD, **data: Any) -> Event:
    return Event(RUN_DONE, "", message, level, data)


Stream = Iterator[Event]
