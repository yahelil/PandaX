"""Reviewed vendor advisory and exact-package backport intelligence.

Generic vulnerability feeds often describe upstream versions. Distribution
vendors may repair those versions with a backported patch while retaining the
same upstream number. PandaX therefore accepts only reviewed decisions tied to
an exact Package URL; it never guesses from a package name or loose range.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .context import Finding, OUT_DIR
from .evidence import sha256_file


SCHEMA = "pandax/vendor-intelligence/v1"
MAX_BYTES = 5 * 1024 * 1024
MAX_ENTRIES = 20_000
DECISIONS = {"affected", "fixed_by_backport", "not_affected", "unknown"}
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class VendorIntelligenceError(ValueError):
    """A curated catalogue is missing required evidence or is malformed."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VendorIntelligenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VendorIntelligenceError(f"{label} must be an object")
    return value


def _only(value: dict[str, Any], allowed: set[str], label: str) -> None:
    extras = sorted(set(value) - allowed)
    if extras:
        raise VendorIntelligenceError(
            f"{label} contains unsupported fields: {', '.join(extras)}"
        )


def _text(value: Any, label: str, limit: int = 500) -> str:
    if not isinstance(value, str) or not value.strip():
        raise VendorIntelligenceError(f"{label} is required")
    result = value.strip()
    if len(result) > limit:
        raise VendorIntelligenceError(f"{label} is longer than {limit} characters")
    return result


def _timestamp(value: Any, label: str) -> str:
    text = _text(value, label, 40)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VendorIntelligenceError(f"{label} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise VendorIntelligenceError(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _https(value: Any, label: str) -> str:
    url = _text(value, label, 1000)
    if not url.startswith("https://"):
        raise VendorIntelligenceError(f"{label} must use https://")
    return url


def _purl_version(purl: str) -> str:
    body = purl.split("#", 1)[0].split("?", 1)[0]
    if not body.startswith("pkg:") or "@" not in body:
        raise VendorIntelligenceError("entry.purl must be an exact, versioned Package URL")
    return unquote(body.rsplit("@", 1)[1])


def _normalise_conflict(raw: Any, label: str) -> dict[str, str]:
    value = _object(raw, label)
    _only(
        value,
        {"source_name", "url", "asserted_state", "retrieved_at", "resolution"},
        label,
    )
    return {
        "source_name": _text(value.get("source_name"), f"{label}.source_name", 200),
        "url": _https(value.get("url"), f"{label}.url"),
        "asserted_state": _text(
            value.get("asserted_state"), f"{label}.asserted_state", 80
        ),
        "retrieved_at": _timestamp(
            value.get("retrieved_at"), f"{label}.retrieved_at"
        ),
        "resolution": _text(value.get("resolution"), f"{label}.resolution", 2000),
    }


def load(path: Path) -> dict[str, Any]:
    """Strictly validate and normalise a curator-approved catalogue."""
    source = Path(path)
    if not source.exists() or not source.is_file():
        raise VendorIntelligenceError(f"vendor catalogue not found: {source}")
    if source.stat().st_size > MAX_BYTES:
        raise VendorIntelligenceError("vendor catalogue exceeds the 5 MiB limit")
    try:
        root = json.loads(
            source.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except UnicodeDecodeError as exc:
        raise VendorIntelligenceError("vendor catalogue must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise VendorIntelligenceError(
            f"vendor catalogue is not valid JSON: {exc.msg}"
        ) from exc

    document = _object(root, "catalogue")
    _only(
        document,
        {"schema", "catalog_version", "curated_at", "curator", "scope", "entries"},
        "catalogue",
    )
    if document.get("schema") != SCHEMA:
        raise VendorIntelligenceError(f"catalogue schema must be {SCHEMA}")
    curator = _object(document.get("curator"), "curator")
    _only(curator, {"name", "authority_attestation"}, "curator")
    if curator.get("authority_attestation") is not True:
        raise VendorIntelligenceError(
            "curator.authority_attestation must be true for an authorized security curator"
        )

    entries = document.get("entries")
    if not isinstance(entries, list):
        raise VendorIntelligenceError("entries must be a list")
    if len(entries) > MAX_ENTRIES:
        raise VendorIntelligenceError(f"catalogue has more than {MAX_ENTRIES} entries")

    normal_entries: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    for index, raw in enumerate(entries):
        label = f"entries[{index}]"
        entry = _object(raw, label)
        _only(
            entry,
            {
                "advisory_id", "cve", "purl", "component", "version", "decision",
                "fixed_version", "source", "review", "backport", "conflicts",
            },
            label,
        )
        cve = _text(entry.get("cve"), f"{label}.cve", 40).upper()
        if not _CVE.fullmatch(cve):
            raise VendorIntelligenceError(f"{label}.cve must be a CVE identifier")
        purl = _text(entry.get("purl"), f"{label}.purl", 1000)
        version = _text(entry.get("version"), f"{label}.version", 200)
        if _purl_version(purl) != version:
            raise VendorIntelligenceError(
                f"{label}.version must exactly match the version in its Package URL"
            )
        identity = (cve, purl)
        if identity in identities:
            raise VendorIntelligenceError(f"duplicate decision for {cve} and {purl}")
        identities.add(identity)

        decision = _text(entry.get("decision"), f"{label}.decision", 40)
        if decision not in DECISIONS:
            raise VendorIntelligenceError(
                f"{label}.decision must be one of: {', '.join(sorted(DECISIONS))}"
            )
        source_data = _object(entry.get("source"), f"{label}.source")
        _only(
            source_data,
            {"publisher", "url", "published_at", "retrieved_at", "statement"},
            f"{label}.source",
        )
        source = {
            "publisher": _text(
                source_data.get("publisher"), f"{label}.source.publisher", 200
            ),
            "url": _https(source_data.get("url"), f"{label}.source.url"),
            "published_at": _timestamp(
                source_data.get("published_at"), f"{label}.source.published_at"
            ),
            "retrieved_at": _timestamp(
                source_data.get("retrieved_at"), f"{label}.source.retrieved_at"
            ),
            "statement": _text(
                source_data.get("statement"), f"{label}.source.statement", 4000
            ),
        }
        if source["published_at"] > source["retrieved_at"]:
            raise VendorIntelligenceError(
                f"{label}.source.retrieved_at cannot predate publication"
            )
        review_data = _object(entry.get("review"), f"{label}.review")
        _only(review_data, {"reviewed_by", "reviewed_at"}, f"{label}.review")
        review = {
            "reviewed_by": _text(
                review_data.get("reviewed_by"), f"{label}.review.reviewed_by", 200
            ),
            "reviewed_at": _timestamp(
                review_data.get("reviewed_at"), f"{label}.review.reviewed_at"
            ),
        }
        if review["reviewed_at"] < source["retrieved_at"]:
            raise VendorIntelligenceError(
                f"{label}.review.reviewed_at cannot predate source retrieval"
            )

        raw_fixed_version = entry.get("fixed_version", "")
        if not isinstance(raw_fixed_version, str):
            raise VendorIntelligenceError(f"{label}.fixed_version must be text")
        fixed_version = raw_fixed_version.strip()
        backport: dict[str, str] | None = None
        if decision == "fixed_by_backport":
            if not fixed_version:
                raise VendorIntelligenceError(
                    f"{label}.fixed_version is required for a backported fix"
                )
            raw_backport = _object(entry.get("backport"), f"{label}.backport")
            _only(
                raw_backport,
                {"upstream_version", "vendor_revision", "patch_reference"},
                f"{label}.backport",
            )
            backport = {
                "upstream_version": _text(
                    raw_backport.get("upstream_version"),
                    f"{label}.backport.upstream_version",
                    200,
                ),
                "vendor_revision": _text(
                    raw_backport.get("vendor_revision"),
                    f"{label}.backport.vendor_revision",
                    200,
                ),
                "patch_reference": _https(
                    raw_backport.get("patch_reference"),
                    f"{label}.backport.patch_reference",
                ),
            }
            if fixed_version != version:
                raise VendorIntelligenceError(
                    f"{label}.fixed_version must equal the exact package version "
                    "for a fixed_by_backport decision"
                )
            if backport["upstream_version"] not in version:
                raise VendorIntelligenceError(
                    f"{label}.backport.upstream_version is not present in the package version"
                )
            if backport["vendor_revision"] not in version:
                raise VendorIntelligenceError(
                    f"{label}.backport.vendor_revision is not present in the package version"
                )
        elif entry.get("backport") is not None:
            raise VendorIntelligenceError(
                f"{label}.backport is allowed only for fixed_by_backport"
            )

        conflicts = entry.get("conflicts", [])
        if not isinstance(conflicts, list):
            raise VendorIntelligenceError(f"{label}.conflicts must be a list")
        normal: dict[str, Any] = {
            "advisory_id": _text(
                entry.get("advisory_id"), f"{label}.advisory_id", 200
            ),
            "cve": cve,
            "purl": purl,
            "component": _text(entry.get("component"), f"{label}.component", 300),
            "version": version,
            "decision": decision,
            "fixed_version": fixed_version,
            "source": source,
            "review": review,
            "conflicts": [
                _normalise_conflict(item, f"{label}.conflicts[{conflict_index}]")
                for conflict_index, item in enumerate(conflicts)
            ],
        }
        if backport is not None:
            normal["backport"] = backport
        normal_entries.append(normal)

    curated_at = _timestamp(document.get("curated_at"), "catalogue.curated_at")
    latest_review = max(
        (entry["review"]["reviewed_at"] for entry in normal_entries),
        default=curated_at,
    )
    if curated_at < latest_review:
        raise VendorIntelligenceError(
            "catalogue.curated_at cannot predate an entry review"
        )
    return {
        "schema": SCHEMA,
        "catalog_version": _text(
            document.get("catalog_version"), "catalogue.catalog_version", 100
        ),
        "curated_at": curated_at,
        "curator": {
            "name": _text(curator.get("name"), "curator.name", 200),
            "authority_attestation": True,
        },
        "scope": _text(document.get("scope"), "catalogue.scope", 2000),
        "entries": normal_entries,
    }


def configured_path() -> Path:
    configured = os.environ.get("PANDAX_VENDOR_CATALOG")
    if configured:
        return Path(configured)
    data_dir = Path(os.environ.get("PANDAX_DATA_DIR", OUT_DIR / ".pandax"))
    return data_dir / "vendor-intelligence.json"


def load_active() -> tuple[dict[str, Any] | None, Path]:
    path = configured_path()
    if os.environ.get("PANDAX_VENDOR_CATALOG") and not path.exists():
        raise VendorIntelligenceError(
            f"configured vendor catalogue not found: {path}"
        )
    return (load(path), path) if path.exists() else (None, path)


def summary(document: dict[str, Any], path: Path | None = None) -> dict[str, Any]:
    decisions: dict[str, int] = {}
    for entry in document["entries"]:
        decisions[entry["decision"]] = decisions.get(entry["decision"], 0) + 1
    result: dict[str, Any] = {
        "valid": True,
        "schema": document["schema"],
        "catalog_version": document["catalog_version"],
        "curated_at": document["curated_at"],
        "curator": document["curator"]["name"],
        "entries": len(document["entries"]),
        "decisions": decisions,
    }
    if path is not None:
        result["path"] = str(Path(path).resolve())
        result["sha256"] = sha256_file(path)
    return result


def install(source: Path, force: bool = False) -> dict[str, Any]:
    """Install a validated catalogue for every scan on this PandaX deployment."""
    document = load(source)
    target = configured_path()
    if target.exists() and not force:
        raise FileExistsError(f"vendor catalogue already exists: {target}; use --force")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(json.dumps(document, indent=2), encoding="utf-8")
    temporary.replace(target)
    return summary(document, target)


def assess(
    components: list[dict[str, Any]],
    findings: list[Finding],
    catalog: dict[str, Any],
) -> tuple[list[Finding], list[dict[str, Any]], list[dict[str, Any]]]:
    """Apply exact-PURL decisions and retain every displaced generic claim."""
    components_by_purl = {
        str(component.get("purl", "")): component
        for component in components
        if component.get("purl")
    }
    current = {(finding.cve.upper(), finding.purl): finding for finding in findings}
    assessments: list[dict[str, Any]] = []
    superseded: list[dict[str, Any]] = []

    for entry in catalog["entries"]:
        component = components_by_purl.get(entry["purl"])
        if component is None:
            continue
        key = (entry["cve"], entry["purl"])
        previous = current.get(key)
        conflicts = list(entry["conflicts"])
        if previous is not None and previous.source_url != entry["source"]["url"]:
            conflicts.append(
                {
                    "source_name": previous.source,
                    "url": previous.source_url,
                    "asserted_state": previous.affectedness,
                    "retrieved_at": previous.source_retrieved_at,
                    "resolution": "Retained as the prior generic-feed result; the reviewed exact-package vendor decision takes precedence.",
                }
            )

        selected_state = (
            "fixed"
            if entry["decision"] == "fixed_by_backport"
            else entry["decision"]
        )
        assessment = {
            **entry,
            "selected_state": selected_state,
            "component_ref": component.get(
                "bom_ref", component.get("bom-ref", entry["purl"])
            ),
            "conflicts": conflicts,
            "precedence": (
                "Reviewed vendor decision for the exact package URL and full vendor revision."
            ),
        }
        assessments.append(assessment)

        if entry["decision"] in {"fixed_by_backport", "not_affected"}:
            if previous is not None:
                superseded.append(
                    {
                        "finding": previous.as_dict(),
                        "selected_decision": entry["decision"],
                        "vendor_advisory": entry["source"],
                        "reason": assessment["precedence"],
                    }
                )
                del current[key]
            continue
        if entry["decision"] == "unknown":
            continue

        if previous is None:
            previous = Finding(
                cve=entry["cve"],
                osv_id="",
                purl=entry["purl"],
                component=entry["component"],
                version=entry["version"],
                summary=entry["source"]["statement"],
                bom_ref=assessment["component_ref"],
            )
            current[key] = previous
        previous.source = entry["source"]["publisher"]
        previous.source_url = entry["source"]["url"]
        previous.source_retrieved_at = entry["source"]["retrieved_at"]
        previous.affectedness = "affected"
        previous.affectedness_evidence = entry["source"]["statement"]
        previous.coverage_status = "completed"
        previous.fixed_version = entry["fixed_version"] or previous.fixed_version
        previous.query_source = f"Vendor intelligence {catalog['catalog_version']}"
        previous.query_value = entry["purl"]
        previous.reachability = "not_assessed"

    return (
        sorted(current.values(), key=lambda finding: (finding.component, finding.cve)),
        assessments,
        superseded,
    )
