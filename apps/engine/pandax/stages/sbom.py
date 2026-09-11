"""S2 SBOM - synthesise a CycloneDX 1.6 bill of materials with Syft.

CRA Annex I Part II(1) requires a "software bill of materials in a commonly
used and machine-readable format covering at the very least the top-level
dependencies". CycloneDX 1.6 satisfies that.

The blueprint's "Zero CVE invariant" - SBOMs record what is *in* the product,
vulnerability state lives in a separate, continuously-updated VEX feed - is
enforced here as an assertion rather than asserted in prose. If Syft ever
started emitting vulnerability data into the SBOM, this stage fails loudly.
"""

from __future__ import annotations

import json
import hashlib
import shutil
import subprocess
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any

from .. import events as ev
from ..context import RunContext, syft_binary
from ..evidence import sha256_file

STAGE = "S2 SBOM"
CDX_VERSION = "1.6"


class SbomError(Exception):
    """Raised when SBOM synthesis fails or violates an invariant."""


SUPPORTED_CYCLONEDX = {"1.2", "1.6"}
SUPPORTED_SPDX = {"SPDX-2.2", "SPDX-2.3"}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SbomError(f"invalid JSON SBOM: {exc}") from exc
    if not isinstance(value, dict):
        raise SbomError("invalid JSON SBOM: top-level value must be an object")
    return value


def is_matchable_purl(value: Any) -> bool:
    """Whether a purl identifies a concrete, versioned package for OSV."""
    if not isinstance(value, str) or not value.startswith("pkg:"):
        return False
    package = value.split("#", 1)[0].split("?", 1)[0]
    head, separator, version = package.rpartition("@")
    return bool(separator and version and "/" in head[4:] and " " not in value)


def _generated_ref(source_format: str, identity: str, index: int) -> str:
    seed = f"{source_format}:{identity}:{index}".encode("utf-8")
    return "urn:pandax:component:" + hashlib.sha256(seed).hexdigest()[:32]


def _unique_ref(
    candidate: Any, source_format: str, identity: str, index: int, used: set[str]
) -> str:
    value = str(candidate or "").strip()
    if not value or value in used:
        value = _generated_ref(source_format, identity, index)
        while value in used:
            value += "-duplicate"
    used.add(value)
    return value


def _component_rows(sbom: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    for comp in sbom.get("components", []):
        purl = str(comp.get("purl", "") or "")
        rows.append(
            {
                "purl": purl,
                "name": str(comp.get("name", "") or ""),
                "version": str(comp.get("version", "") or ""),
                "type": str(comp.get("type", "library") or "library"),
                "bom_ref": str(comp.get("bom-ref", "") or purl),
            }
        )
    return rows


def _normalise_cyclonedx(
    document: dict[str, Any], version: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    if version not in SUPPORTED_CYCLONEDX:
        raise SbomError(
            f"unsupported CycloneDX version {version or 'unknown'}; supported: 1.2, 1.6"
        )
    if "vulnerabilities" in document:
        raise SbomError(
            "Zero-CVE invariant violated: the SBOM carries vulnerability data. "
            "Component inventory and vulnerability state must stay decoupled."
        )
    components = document.get("components")
    if not isinstance(components, list) or not components:
        raise SbomError("CycloneDX SBOM must contain a non-empty components array")

    normalised = deepcopy(document) if version == CDX_VERSION else _upgrade_cyclonedx_12(document)
    used: set[str] = set()
    for index, component in enumerate(normalised["components"]):
        if not isinstance(component, dict) or not str(component.get("name", "")).strip():
            raise SbomError(f"CycloneDX component {index + 1} must have a name")
        component.setdefault("type", "library")
        identity = str(component.get("purl") or component.get("name"))
        component["bom-ref"] = _unique_ref(
            component.get("bom-ref"), "CycloneDX", identity, index, used
        )
    normalised.setdefault("version", 1)

    meta_component = (normalised.get("metadata") or {}).get("component") or {}
    product = {}
    if isinstance(meta_component, dict):
        if meta_component.get("name"):
            product["name"] = str(meta_component["name"])
        if meta_component.get("version"):
            product["version"] = str(meta_component["version"])
    return normalised, {"product": product} if product else {}


def _upgrade_cyclonedx_12(document: dict[str, Any]) -> dict[str, Any]:
    """Project a CycloneDX 1.2 inventory into the 1.6 fields PandaX consumes.

    The original document remains in input/.  This projection deliberately
    keeps identity, package coordinates and resolvable dependency edges while
    avoiding legacy fields whose shapes changed in later CycloneDX releases.
    """
    legacy_metadata = document.get("metadata") or {}
    metadata: dict[str, Any] = {
        "properties": [
            {"name": "pandax:source-format", "value": "CycloneDX 1.2"},
        ]
    }
    if legacy_metadata.get("timestamp"):
        metadata["timestamp"] = legacy_metadata["timestamp"]

    root = legacy_metadata.get("component")
    if isinstance(root, dict) and root.get("name"):
        metadata["component"] = _legacy_component(root)

    tools = []
    for tool in legacy_metadata.get("tools") or []:
        if not isinstance(tool, dict) or not tool.get("name"):
            continue
        converted = {
            "type": "application",
            "name": str(tool["name"]),
        }
        if tool.get("vendor"):
            converted["group"] = str(tool["vendor"])
        if tool.get("version"):
            converted["version"] = str(tool["version"])
        tools.append(converted)
    if tools:
        metadata["tools"] = {"components": tools}

    upgraded: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_VERSION,
        "version": int(document.get("version", 1) or 1),
        "metadata": metadata,
        "components": [_legacy_component(component) for component in document["components"]],
    }
    serial = document.get("serialNumber")
    if isinstance(serial, str) and serial.startswith("urn:uuid:"):
        upgraded["serialNumber"] = serial

    allowed_refs = {
        str(component.get("bom-ref", ""))
        for component in upgraded["components"]
        if component.get("bom-ref")
    }
    if metadata.get("component", {}).get("bom-ref"):
        allowed_refs.add(str(metadata["component"]["bom-ref"]))
    dependencies = []
    for dependency in document.get("dependencies") or []:
        if not isinstance(dependency, dict) or dependency.get("ref") not in allowed_refs:
            continue
        dependencies.append(
            {
                "ref": dependency["ref"],
                "dependsOn": [
                    ref for ref in dependency.get("dependsOn") or [] if ref in allowed_refs
                ],
            }
        )
    if dependencies:
        upgraded["dependencies"] = dependencies
    return upgraded


def _legacy_component(component: dict[str, Any]) -> dict[str, Any]:
    converted: dict[str, Any] = {
        "type": str(component.get("type", "library") or "library"),
        "name": str(component.get("name", "") or ""),
    }
    for field in ("group", "version", "purl"):
        if component.get(field):
            converted[field] = str(component[field])
    bom_ref = component.get("bom-ref") or component.get("purl")
    if bom_ref:
        converted["bom-ref"] = str(bom_ref)
    return converted


_SPDX_TYPE = {
    "APPLICATION": "application",
    "CONTAINER": "container",
    "DEVICE": "device",
    "FIRMWARE": "firmware",
    "FRAMEWORK": "framework",
    "LIBRARY": "library",
    "OPERATING-SYSTEM": "operating-system",
    "SOURCE": "file",
}


def _spdx_purl(package: dict[str, Any]) -> str:
    for reference in package.get("externalRefs") or []:
        if not isinstance(reference, dict):
            continue
        if str(reference.get("referenceType", "")).lower() != "purl":
            continue
        locator = str(reference.get("referenceLocator", "") or "")
        if locator.startswith("pkg:"):
            return locator
    return ""


def _normalise_spdx(
    document: dict[str, Any], version: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    if version not in SUPPORTED_SPDX:
        raise SbomError(
            f"unsupported SPDX version {version or 'unknown'}; supported: SPDX-2.2, SPDX-2.3"
        )
    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        raise SbomError("SPDX SBOM must contain a non-empty packages array")

    components: list[dict[str, Any]] = []
    packages_by_id: dict[str, dict[str, Any]] = {}
    used: set[str] = set()
    for index, package in enumerate(packages):
        if not isinstance(package, dict) or not str(package.get("name", "")).strip():
            raise SbomError(f"SPDX package {index + 1} must have a name")
        spdx_id = str(package.get("SPDXID", "") or "")
        if spdx_id:
            packages_by_id[spdx_id] = package
        purl = _spdx_purl(package)
        component: dict[str, Any] = {
            "type": _SPDX_TYPE.get(
                str(package.get("primaryPackagePurpose", "")).upper(), "library"
            ),
            "name": str(package["name"]),
            "version": str(package.get("versionInfo", "") or ""),
            "bom-ref": _unique_ref(
                spdx_id, "SPDX", spdx_id or str(package["name"]), index, used
            ),
        }
        if purl:
            component["purl"] = purl
        components.append(component)

    described = document.get("documentDescribes") or []
    root = packages_by_id.get(described[0]) if len(described) == 1 else None
    product: dict[str, str] = {}
    if root:
        product["name"] = str(root.get("name", "") or "")
        if root.get("versionInfo"):
            product["version"] = str(root["versionInfo"])
    elif document.get("name"):
        product["name"] = str(document["name"])

    namespace = str(document.get("documentNamespace", "") or "")
    if not namespace:
        namespace = json.dumps(document, sort_keys=True, separators=(",", ":"))
    serial = uuid.uuid5(uuid.NAMESPACE_URL, namespace)
    metadata: dict[str, Any] = {
        "properties": [
            {"name": "pandax:source-format", "value": version},
        ]
    }
    created = (document.get("creationInfo") or {}).get("created")
    if created:
        metadata["timestamp"] = created
    if product.get("name"):
        metadata["component"] = {
            "type": "application",
            "name": product["name"],
            "version": product.get("version", ""),
        }

    normalised = {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_VERSION,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }
    return normalised, {"product": product} if product else {}


def normalise_document(
    document: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    if document.get("bomFormat") == "CycloneDX":
        version = str(document.get("specVersion", "") or "")
        normalised, product = _normalise_cyclonedx(document, version)
        return normalised, product, "CycloneDX", version
    if "spdxVersion" in document:
        version = str(document.get("spdxVersion", "") or "")
        normalised, product = _normalise_spdx(document, version)
        return normalised, product, "SPDX", version
    raise SbomError(
        "unsupported JSON SBOM format; expected CycloneDX bomFormat or SPDX spdxVersion"
    )


def inspect_sbom(path: Path) -> dict[str, Any]:
    """Validate an uploaded SBOM without creating a run."""
    normalised, product, source_format, source_version = normalise_document(
        _read_json(Path(path))
    )
    rows = _component_rows(normalised)
    matchable = sum(1 for row in rows if is_matchable_purl(row["purl"]))
    if not matchable:
        raise SbomError(
            "SBOM has no components with a usable, versioned Package URL (purl)"
        )
    return {
        "format": source_format,
        "version": source_version,
        "components": len(rows),
        "matchable_components": matchable,
        "skipped_components": len(rows) - matchable,
        "product": product.get("product", {}),
    }


def syft_version(binary: Path) -> str:
    out = subprocess.run(
        [str(binary), "--version"], capture_output=True, text=True, timeout=60
    )
    return out.stdout.strip().replace("syft ", "") or "unknown"


def run(ctx: RunContext) -> ev.Stream:
    yield ev.start(STAGE, f"synthesising CycloneDX {CDX_VERSION} SBOM")

    binary = syft_binary()
    version = syft_version(binary)
    ctx.tool_versions["syft"] = version
    yield ev.log(STAGE, f"syft {version} (pinned, digest-verified at bootstrap)")

    if ctx.extracted_dir is None:
        raise SbomError("ingest stage did not run")

    out_path = ctx.path("sbom.cdx.json")
    name = str(ctx.product.get("product", {}).get("name", "product")).replace(" ", "-")
    product_version = str(ctx.product.get("product", {}).get("version", "0.0.0"))

    cmd = [
        str(binary),
        "scan",
        f"dir:{ctx.extracted_dir}",
        "-o",
        f"cyclonedx-json@{CDX_VERSION}={out_path}",
        "--source-name",
        name,
        "--source-version",
        product_version,
        "-q",
    ]
    yield ev.log(STAGE, "syft scan dir:<extracted> -o cyclonedx-json@1.6")

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    if proc.returncode != 0 or not out_path.exists():
        raise SbomError(f"syft failed (exit {proc.returncode}): {proc.stderr.strip()}")

    sbom = json.loads(out_path.read_text(encoding="utf-8"))
    raw_path = ctx.path("sbom.syft.json")
    shutil.copyfile(out_path, raw_path)
    from ..package_identity import enrich
    resolved = enrich(sbom, ctx.extracted_dir)
    yield ev.log(STAGE, f"publisher binary identities verified by SHA-256: {resolved}")
    from ..native import inventory, enrich_sbom
    release_source = ctx.path("release-source.json")
    source_identity = (
        json.loads(release_source.read_text(encoding="utf-8"))
        if release_source.exists()
        else None
    )
    ctx.native_inventory = inventory(ctx.extracted_dir, source_identity)
    enrich_sbom(sbom, ctx.native_inventory)
    out_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    native_path = ctx.path("native-inventory.json")
    native_path.write_text(json.dumps(ctx.native_inventory, indent=2), encoding="utf-8")
    yield ev.log(STAGE, f"native metadata adapter: {len(ctx.native_inventory['components'])} components")

    # --- invariants, checked not claimed ---
    spec = sbom.get("specVersion")
    if spec != CDX_VERSION:
        raise SbomError(f"expected CycloneDX {CDX_VERSION}, got {spec}")
    yield ev.log(STAGE, f"specVersion == {spec}", ev.GOOD)

    if "vulnerabilities" in sbom:
        raise SbomError(
            "Zero-CVE invariant violated: the SBOM carries vulnerability data. "
            "Component inventory and vulnerability state must stay decoupled."
        )
    yield ev.log(
        STAGE, "zero-CVE invariant holds - no vulnerability data in the SBOM", ev.GOOD
    )

    components = _component_rows(sbom)
    ctx.sbom = sbom
    ctx.sbom_path = out_path
    ctx.components = components
    ctx.matchable_components = sum(
        1 for component in components if is_matchable_purl(component["purl"])
    )
    ctx.skipped_components = len(components) - ctx.matchable_components

    ecosystems: dict[str, int] = {}
    for comp in components:
        eco = (
            comp["purl"].split("/")[0].replace("pkg:", "")
            if comp["purl"]
            else "unidentified"
        )
        ecosystems[eco] = ecosystems.get(eco, 0) + 1

    yield ev.metric(STAGE, "components", len(components))
    yield ev.metric(
        STAGE,
        "ecosystems",
        ", ".join(f"{k}={v}" for k, v in sorted(ecosystems.items())),
    )
    for comp in components[:12]:
        yield ev.log(STAGE, f"  {comp['purl']}")
    if len(components) > 12:
        yield ev.log(STAGE, f"  ... and {len(components) - 12} more")

    yield ev.artifact(
        STAGE, ctx.ledger.rel(out_path), sha256_file(out_path), "CycloneDX 1.6"
    )

    ctx.ledger.append(
        stage="S2_SBOM",
        tool="syft",
        tool_version=version,
        inputs=[ctx.ledger.ref(ctx.path("ingest_tree.json"))],
        outputs=[ctx.ledger.ref(out_path), ctx.ledger.ref(raw_path), ctx.ledger.ref(native_path)],
        params={"format": f"cyclonedx-json@{CDX_VERSION}", "source_name": name,
                "publisher_identity": "pandax.package_identity/1",
                "native_adapter": "pandax.native/1"},
    )
    yield ev.done(STAGE, f"{len(components)} components inventoried")


def import_run(ctx: RunContext) -> ev.Stream:
    """Validate a supplied JSON SBOM and install a CycloneDX 1.6 run input."""
    yield ev.start(STAGE, "validating and normalising supplied JSON SBOM")

    inputs_dir = ctx.path("input")
    inputs_dir.mkdir(parents=True, exist_ok=True)
    original = inputs_dir / ctx.artifact.name
    shutil.copy2(ctx.artifact, original)

    normalised, product, source_format, source_version = normalise_document(
        _read_json(original)
    )
    components = _component_rows(normalised)
    matchable = sum(1 for row in components if is_matchable_purl(row["purl"]))
    skipped = len(components) - matchable
    if not matchable:
        raise SbomError(
            "SBOM has no components with a usable, versioned Package URL (purl)"
        )

    out_path = ctx.path("sbom.cdx.json")
    out_path.write_text(
        json.dumps(normalised, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    ctx.product = product
    ctx.sbom = normalised
    ctx.sbom_path = out_path
    ctx.components = components
    ctx.sbom_source_format = source_format
    ctx.sbom_source_version = source_version
    ctx.matchable_components = matchable
    ctx.skipped_components = skipped

    ctx.tool_versions["sbom_import"] = "pandax/0.1.0"
    yield ev.log(STAGE, f"detected {source_format} {source_version}", ev.GOOD)
    yield ev.metric(STAGE, "components", len(components))
    yield ev.metric(STAGE, "matchable purls", matchable)
    yield ev.metric(STAGE, "skipped without usable purl", skipped)
    if skipped:
        yield ev.log(
            STAGE,
            f"{skipped} component(s) retained but excluded from OSV matching",
            ev.WARN,
        )
    yield ev.artifact(
        STAGE, ctx.ledger.rel(out_path), sha256_file(out_path), "CycloneDX 1.6"
    )

    ctx.ledger.append(
        stage="S2_SBOM",
        tool="pandax.sbom-import",
        tool_version="0.1.0",
        inputs=[ctx.ledger.ref(original)],
        outputs=[ctx.ledger.ref(out_path)],
        params={
            "source_format": source_format,
            "source_version": source_version,
            "normalised_format": "CycloneDX 1.6",
            "components": len(components),
            "matchable_components": matchable,
            "skipped_components": skipped,
        },
    )
    yield ev.done(STAGE, f"{len(components)} components imported; {matchable} matchable")
