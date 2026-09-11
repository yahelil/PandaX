"""Shared state threaded through the six stages."""

from __future__ import annotations

import datetime as dt
import os
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


def signing_key_path(fallback: Path | None = None) -> Path:
    """Resolve the installation signing key without caching environment state."""
    configured = os.environ.get("PANDAX_SIGNING_KEY")
    return Path(configured) if configured else Path(fallback or KEY_PATH)


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
    # Coverage, affectedness, exploitation signals and product reachability are
    # separate facts. Defaults keep historical/in-memory findings conservative.
    coverage_status: str = "unknown"
    affectedness: str = "unknown"
    affectedness_evidence: str = ""
    reachability: str = "unknown"
    reachability_evidence: str = ""
    # Approved runtime observations support a human review. They deliberately
    # do not change reachability or legal reportability by themselves.
    runtime_evidence_status: str = "not_supplied"
    runtime_evidence: list[dict[str, Any]] = field(default_factory=list)
    query_source: str = ""
    query_value: str = ""
    source_retrieved_at: str = ""
    kev_check_status: str = "unknown"
    kev_source_url: str = ""
    kev_checked_at: str = ""
    epss_check_status: str = "unknown"
    epss_source_url: str = ""
    epss_checked_at: str = ""

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
    vulnerability_coverage: list[dict[str, Any]] = field(default_factory=list)
    runtime_telemetry_path: Path | None = None
    telemetry_assessments_path: Path | None = None

    # A run can begin from a product artifact or from a pre-built SBOM.  These
    # fields make that provenance available to the dossier and both renderers.
    input_type: str = "artifact"
    sbom_source_format: str = "CycloneDX"
    sbom_source_version: str = "1.6"
    matchable_components: int = 0
    skipped_components: int = 0

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
