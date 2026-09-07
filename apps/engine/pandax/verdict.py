"""Turn findings into the two answers a manufacturer actually needs.

A list of 102 CVEs is not a decision. The questions behind a CRA scan are:

    Can I place this product on the EU market?      -> blockers, with the article
    What do I have to do, and by when?              -> Article 14 clocks
    What do I have to fix?                          -> upgrades, not CVEs

The third one matters more than it looks. Across every artifact evaluated so
far, 97-100% of findings had an upstream fix available, and grouping by
component collapses ~100 CVE rows into ~10 upgrades. That is the honest way to
cut triage noise: not by arguing vulnerable code is unreachable, but by naming
the handful of upgrades that clear the backlog.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# --- versions ---------------------------------------------------------------


def version_key(version: str) -> tuple:
    """Sortable key for a version string. Numeric parts compare numerically.

    Deliberately forgiving: ecosystems disagree about version grammar, and a
    crash here would lose a real finding. Unparseable parts sort as text.
    """
    parts: list[tuple[int, int, str]] = []
    for chunk in re.split(r"[._\-+]", str(version)):
        if chunk.isdigit():
            parts.append((0, int(chunk), ""))
        elif chunk:
            parts.append((1, 0, chunk))
    return tuple(parts)


def looks_like_version(value: str) -> bool:
    """Reject things that are not a version a human could install.

    OSV sometimes records commit hashes as the fixed point of a GIT range.
    "Upgrade to 2444cddab2f8..." is not actionable advice, so such values never
    become an upgrade target.
    """
    if not value or not value[0].isdigit():
        return False
    return not re.fullmatch(r"[0-9a-f]{7,40}", value)


def highest(versions: Iterable[str]) -> str:
    """The greatest version in the set - the upgrade that clears the most."""
    candidates = [v for v in versions if looks_like_version(v)]
    if not candidates:
        return ""
    return max(candidates, key=version_key)


# --- remediation ------------------------------------------------------------


@dataclass
class Upgrade:
    """One package upgrade, and everything it resolves."""

    component: str
    version: str
    purl: str
    target: str
    cves: list[str] = field(default_factory=list)
    kev: list[str] = field(default_factory=list)
    unfixable: list[str] = field(default_factory=list)

    @property
    def actionable(self) -> bool:
        return bool(self.target)

    def as_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "version": self.version,
            "purl": self.purl,
            "target": self.target,
            "cves": sorted(self.cves),
            "kev": sorted(self.kev),
            "unfixable": sorted(self.unfixable),
            "clears": len(self.cves),
        }


def remediation_plan(findings: list[dict[str, Any]]) -> list[Upgrade]:
    """Collapse findings into the smallest set of upgrades that clears them.

    Ordered by exploited-first, then by how much each upgrade resolves, so the
    top of the list is always the highest-value action.
    """
    grouped: dict[tuple[str, str], Upgrade] = {}
    for finding in findings:
        key = (finding["component"], finding["version"])
        upgrade = grouped.get(key)
        if upgrade is None:
            upgrade = Upgrade(
                component=finding["component"],
                version=finding["version"],
                purl=finding.get("purl", ""),
                target="",
            )
            grouped[key] = upgrade
        upgrade.cves.append(finding["cve"])
        if finding.get("kev"):
            upgrade.kev.append(finding["cve"])
        if finding.get("fixed_version"):
            upgrade.target = highest([upgrade.target, finding["fixed_version"]])
        else:
            upgrade.unfixable.append(finding["cve"])

    return sorted(
        grouped.values(),
        key=lambda u: (-len(u.kev), -len(u.cves), u.component),
    )


# --- verdict ----------------------------------------------------------------


@dataclass
class Blocker:
    """Something that legally prevents placing the product on the market."""

    title: str
    article: str
    detail: str
    action: str


@dataclass
class Verdict:
    can_ship: bool
    blockers: list[Blocker]
    warnings: list[Blocker]
    upgrades: list[Upgrade]
    deadlines: list[dict[str, Any]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "can_ship": self.can_ship,
            "blockers": [b.__dict__ for b in self.blockers],
            "warnings": [b.__dict__ for b in self.warnings],
            "upgrades": [u.as_dict() for u in self.upgrades],
            "deadlines": self.deadlines,
        }


def build_verdict(
    findings: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
    dossier: dict[str, Any],
) -> Verdict:
    """Decide whether this product can lawfully be placed on the market."""
    upgrades = remediation_plan(findings)
    kev = [f for f in findings if f.get("kev")]
    summary = dossier.get("summary", {})
    required = int(summary.get("required_input", 0))
    unfixable = [f for f in findings if not f.get("fixed_version")]

    blockers: list[Blocker] = []
    warnings: list[Blocker] = []

    if kev:
        names = ", ".join(sorted({f["component"] for f in kev}))
        blockers.append(
            Blocker(
                title=f"{len(kev)} actively exploited vulnerabilities are present",
                article="Annex I Part I(2)(a)",
                detail=(
                    "Products must be made available on the market without known "
                    f"exploitable vulnerabilities. Affected: {names}."
                ),
                action="Apply the upgrades listed below, then re-scan.",
            )
        )

    if required:
        missing = []
        for section in dossier.get("annex_vii", []):
            for entry in section.get("entries", []):
                if entry.get("status") == "required_input":
                    missing.append(entry["ref"])
        for entry in dossier.get("annex_v", []):
            if entry.get("status") == "required_input":
                missing.append(f"Annex V item {entry['ref']}")
        blockers.append(
            Blocker(
                title=f"{required} technical-file entries have no evidence",
                article="Article 31(1), Annex VII",
                detail=(
                    "The technical documentation must contain at least the Annex VII "
                    f"elements. Outstanding: {', '.join(missing[:8])}"
                    + (" ..." if len(missing) > 8 else "")
                ),
                action="Supply these in product.yaml or attach the documents.",
            )
        )

    if unfixable:
        warnings.append(
            Blocker(
                title=f"{len(unfixable)} vulnerabilities have no upstream fix",
                article="Annex I Part II(2)",
                detail=(
                    "Vulnerabilities must be addressed without delay. Where no fix "
                    "exists, a documented mitigation is required."
                ),
                action="Record a mitigation, or replace the component.",
            )
        )

    return Verdict(
        can_ship=not blockers,
        blockers=blockers,
        warnings=warnings,
        upgrades=upgrades,
        deadlines=_deadlines(incidents),
    )


def _deadlines(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten incident clocks into a single due-date-ordered list."""
    labels = {
        "early_warning": ("24h early warning", "Art.14(2)(a)"),
        "notification": ("72h notification", "Art.14(2)(b)"),
        "final_report": ("14d final report", "Art.14(2)(c)"),
    }
    rows = []
    for incident in incidents:
        for key, (label, article) in labels.items():
            rows.append(
                {
                    "cve": incident["cve"],
                    "component": incident.get("component", ""),
                    "filing": label,
                    "article": article,
                    "due": incident["deadlines"][key],
                }
            )
    return sorted(rows, key=lambda r: r["due"])
