"""Shared state threaded through the six stages."""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .evidence import Ledger

# Repo root, derived from this file: apps/engine/pandax/context.py -> ../../..
ROOT = Path(__file__).resolve().parents[3]
TOOLS_DIR = ROOT / ".tools"
OUT_DIR = ROOT / "out"
CACHE_DIR = ROOT / ".cache"
KEY_PATH = Path.home() / ".pandax" / "dev_signing_key.pem"


@dataclass
class Finding:
    """One vulnerability affecting one component of the product."""

    cve: str
    osv_id: str
    purl: str
    component: str
    version: str
    summary: str
    cvss_vector: str = ""
    severity: str = "UNKNOWN"
    fixed_version: str = ""
    kev: bool = False
    kev_date_added: str = ""
    kev_action: str = ""
    epss: float = 0.0
    # CycloneDX bom-ref of the affected component, so VEX rows point at the
    # exact SBOM entry rather than being re-matched by name.
    bom_ref: str = ""
    source: str = "OSV"
    source_url: str = ""
    applicability: str = ""

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class RunContext:
    artifact: Path
    run_dir: Path
    run_id: str
    ledger: Ledger
    product: dict[str, Any] = field(default_factory=dict)

    extracted_dir: Path | None = None
    sbom_path: Path | None = None
    sbom: dict[str, Any] = field(default_factory=dict)
    components: list[dict[str, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    incidents: list[dict[str, Any]] = field(default_factory=list)
    tool_versions: dict[str, str] = field(default_factory=dict)
    started: str = ""
    native_inventory: dict[str, Any] = field(default_factory=dict)

    # Demo control: compress statutory countdowns so 24h/72h/14d are watchable.
    clock_speed: float = 1.0

    @property
    def kev_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.kev]

    def path(self, name: str) -> Path:
        return self.run_dir / name


def new_run_dir(base: Path | None = None) -> tuple[Path, str]:
    base = base or OUT_DIR
    run_id = "run-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f") + "-" + uuid.uuid4().hex[:6]
    run_dir = base / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir, run_id


def syft_binary() -> Path:
    """Locate the pinned syft installed by tools/bootstrap.py."""
    for name in ("syft.exe", "syft"):
        candidate = TOOLS_DIR / name
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "syft not found in .tools/. Run:  uv run python tools/bootstrap.py"
    )
