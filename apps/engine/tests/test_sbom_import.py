from __future__ import annotations

import json
from pathlib import Path

import pytest

from pandax import events as ev
from pandax.context import RunContext
from pandax.evidence import Ledger, verify_run
from pandax.stages import dossier, match, sbom


def cyclonedx(*components: dict, vulnerabilities: bool = False) -> dict:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "Example", "version": "2.0"}
        },
        "components": list(components),
    }
    if vulnerabilities:
        document["vulnerabilities"] = []
    return document


def spdx(version: str = "SPDX-2.3") -> dict:
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": version,
        "name": "Example document",
        "documentNamespace": "https://example.invalid/spdx/example",
        "documentDescribes": ["SPDXRef-App"],
        "creationInfo": {"created": "2026-01-01T00:00:00Z"},
        "packages": [
            {
                "SPDXID": "SPDXRef-App",
                "name": "Example App",
                "versionInfo": "3.1",
                "primaryPackagePurpose": "APPLICATION",
                "externalRefs": [],
            },
            {
                "SPDXID": "SPDXRef-Library",
                "name": "requests",
                "versionInfo": "2.31.0",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:pypi/requests@2.31.0",
                    }
                ],
            },
        ],
    }


def write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_inspect_cyclonedx_detects_format_identity_and_skipped_components(tmp_path: Path):
    path = write_json(
        tmp_path / "bom.json",
        cyclonedx(
            {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
            {"type": "library", "name": "internal", "version": "1.0"},
        ),
    )

    info = sbom.inspect_sbom(path)

    assert info == {
        "format": "CycloneDX",
        "version": "1.6",
        "components": 2,
        "matchable_components": 1,
        "skipped_components": 1,
        "product": {"name": "Example", "version": "2.0"},
    }


def test_cyclonedx_12_is_upgraded_to_16_without_losing_inventory():
    legacy = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.2",
        "serialNumber": "urn:uuid:b4f2954f-a96d-4578-9509-1ae2d6476209",
        "version": 1,
        "metadata": {
            "timestamp": "2020-08-02T21:27:04Z",
            "tools": [
                {"vendor": "CycloneDX", "name": "CycloneDX Maven plugin", "version": "2.0.2"}
            ],
            "component": {
                "type": "application",
                "name": "Legacy App",
                "version": "1.3.15",
                "purl": "pkg:maven/example/legacy-app@1.3.15",
            },
        },
        "components": [
            {
                "type": "library",
                "group": "com.example",
                "name": "legacy-library",
                "version": "2.0.0",
                "purl": "pkg:maven/com.example/legacy-library@2.0.0?type=jar",
            }
        ],
        "dependencies": [
            {
                "ref": "pkg:maven/example/legacy-app@1.3.15",
                "dependsOn": ["pkg:maven/com.example/legacy-library@2.0.0?type=jar"],
            }
        ],
    }

    normalised, product, source_format, source_version = sbom.normalise_document(legacy)

    assert source_format == "CycloneDX" and source_version == "1.2"
    assert normalised["specVersion"] == "1.6"
    assert normalised["serialNumber"] == legacy["serialNumber"]
    assert normalised["components"][0]["purl"] == legacy["components"][0]["purl"]
    assert normalised["metadata"]["tools"]["components"][0]["name"] == "CycloneDX Maven plugin"
    assert normalised["dependencies"] == legacy["dependencies"]
    assert product["product"] == {"name": "Legacy App", "version": "1.3.15"}


@pytest.mark.parametrize("version", ["SPDX-2.2", "SPDX-2.3"])
def test_spdx_is_normalised_and_uses_document_describes(version: str):
    normalised, product, source_format, source_version = sbom.normalise_document(spdx(version))

    assert source_format == "SPDX" and source_version == version
    assert normalised["bomFormat"] == "CycloneDX"
    assert normalised["specVersion"] == "1.6"
    assert product["product"] == {"name": "Example App", "version": "3.1"}
    assert len(normalised["components"]) == 2
    assert normalised["components"][1]["purl"] == "pkg:pypi/requests@2.31.0"


def test_generated_bom_refs_are_stable_and_unique():
    source = cyclonedx(
        {"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1"},
        {"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1"},
    )
    first, *_ = sbom.normalise_document(source)
    second, *_ = sbom.normalise_document(source)

    refs = [component["bom-ref"] for component in first["components"]]
    assert refs == [component["bom-ref"] for component in second["components"]]
    assert len(set(refs)) == 2


@pytest.mark.parametrize(
    "document, message",
    [
        ({"hello": "world"}, "unsupported JSON SBOM format"),
        ({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{}]}, "unsupported CycloneDX"),
        ({"spdxVersion": "SPDX-3.0", "packages": [{}]}, "unsupported SPDX"),
        (cyclonedx(vulnerabilities=True), "Zero-CVE invariant"),
        ({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}, "non-empty components"),
    ],
)
def test_invalid_documents_are_rejected(document: dict, message: str):
    with pytest.raises(sbom.SbomError, match=message):
        sbom.normalise_document(document)


def test_document_with_no_matchable_purl_is_rejected(tmp_path: Path):
    path = write_json(
        tmp_path / "bom.json",
        cyclonedx({"type": "library", "name": "internal", "version": "1"}),
    )
    with pytest.raises(sbom.SbomError, match="no components with a usable"):
        sbom.inspect_sbom(path)


def test_match_sends_only_usable_purls_and_preserves_inventory(ctx: RunContext):
    ctx.components.append(
        {"purl": "", "name": "internal", "version": "1", "type": "library", "bom_ref": "internal"}
    )
    ctx.skipped_components = 1
    seen = []

    class Feeds:
        def query_purls(self, purls):
            seen.extend(purls)
            return {purl: [] for purl in purls}

    list(match.run(ctx, Feeds()))

    assert seen == [component["purl"] for component in ctx.components if component["purl"]]
    assert len(ctx.components) == 3


def test_run_from_sbom_skips_syft_and_seals_original(monkeypatch, tmp_path: Path):
    from pandax import pipeline

    source = write_json(
        tmp_path / "uploaded.json",
        cyclonedx(
            {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}
        ),
    )

    class Feeds:
        def __init__(self, *_args, **_kwargs): pass
        def query_purls(self, purls): return {purl: [] for purl in purls}
        def kev(self): return {}
        def kev_released(self): return "2026-01-01"
        def epss(self, _cves): return {}
        def close(self): pass

    def compile_pdf(_typ: Path, output: Path, _root: Path) -> str:
        output.write_bytes(b"%PDF-1.7\n" + b"x" * 11_000)
        return ""

    monkeypatch.setattr(pipeline, "Feeds", Feeds)
    monkeypatch.setattr(pipeline, "KEY_PATH", tmp_path / "signing-key.pem")
    monkeypatch.setattr(dossier, "_compile", compile_pdf)
    monkeypatch.setattr(dossier.pdfa, "validate_pdf", lambda *_args: {
        "compliant": True, "validator_version": dossier.pdfa.VERSION,
    })

    events = list(pipeline.run_sbom(source, out_base=tmp_path / "out", product_metadata={
        "product": {"name": "Industrial Sensor", "version": "2.1", "unique_id": "sensor-21", "risk_tier": "default"},
        "manufacturer": {"legal_name": "Acme Devices"},
    }))
    summary = next(event.data for event in events if event.kind == ev.RUN_DONE)
    run_dir = Path(summary["run_dir"])

    assert any(event.kind == ev.STAGE_SKIPPED and event.stage == "S1 INGEST" for event in events)
    assert (run_dir / "input" / "uploaded.json").exists()
    assert (run_dir / "sbom.cdx.json").exists()
    dossier_data = json.loads((run_dir / "dossier.json").read_text(encoding="utf-8"))
    assert dossier_data["product"]["name"] == "Industrial Sensor"
    assert dossier_data["product"]["version"] == "2.1"
    assert dossier_data["product"]["unique_id"] == "sensor-21"
    assert dossier_data["manufacturer"]["legal_name"] == "Acme Devices"
    assert "syft" not in json.loads((run_dir / "manifest.json").read_text())["tool_versions"]
    assert summary["coverage_summary"] == {
        "completed": 1,
        "unsupported": 0,
        "unscanned": 0,
        "failed": 0,
        "unknown": 0,
    }
    assert all(check.ok for check in verify_run(run_dir))
