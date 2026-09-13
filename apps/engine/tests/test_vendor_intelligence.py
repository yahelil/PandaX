from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from pandax import cli, vendor_intelligence
from pandax.context import Finding
from pandax.stages import match


PURL = "pkg:deb/debian/example@1.2.3-0%2Bdeb11u5?arch=amd64&distro=debian-11"


def _catalog(decision: str = "fixed_by_backport") -> dict:
    entry = {
        "advisory_id": "DSA-2026-001",
        "cve": "CVE-2026-10001",
        "purl": PURL,
        "component": "example",
        "version": "1.2.3-0+deb11u5",
        "decision": decision,
        "fixed_version": "1.2.3-0+deb11u5" if decision == "fixed_by_backport" else "1.2.4",
        "source": {
            "publisher": "Distribution security team",
            "url": "https://vendor.example/advisory/DSA-2026-001",
            "published_at": "2026-09-10T08:00:00Z",
            "retrieved_at": "2026-09-12T08:00:00Z",
            "statement": "The exact distribution package contains the security fix.",
        },
        "review": {
            "reviewed_by": "PandaX security curator",
            "reviewed_at": "2026-09-13T08:00:00Z",
        },
        "conflicts": [],
    }
    if decision == "fixed_by_backport":
        entry["backport"] = {
            "upstream_version": "1.2.3",
            "vendor_revision": "0+deb11u5",
            "patch_reference": "https://vendor.example/packages/example/changelog",
        }
    return {
        "schema": vendor_intelligence.SCHEMA,
        "catalog_version": "2026-09-13.1",
        "curated_at": "2026-09-13T08:00:00Z",
        "curator": {
            "name": "PandaX security curation team",
            "authority_attestation": True,
        },
        "scope": "Reviewed test decisions for exact distribution packages.",
        "entries": [entry],
    }


def _write(path: Path, document: dict | None = None) -> Path:
    path.write_text(json.dumps(document or _catalog()), encoding="utf-8")
    return path


def _component() -> dict:
    return {
        "name": "example",
        "version": "1.2.3-0+deb11u5",
        "purl": PURL,
        "bom_ref": "component-example",
        "bom-ref": "component-example",
    }


def _finding() -> Finding:
    return Finding(
        cve="CVE-2026-10001",
        osv_id="OSV-2026-1",
        purl=PURL,
        component="example",
        version="1.2.3-0+deb11u5",
        summary="Generic range says affected",
        source="OSV",
        source_url="https://osv.dev/vulnerability/OSV-2026-1",
        source_retrieved_at="2026-09-12T07:00:00Z",
        affectedness="affected",
    )


def test_backport_supersedes_but_preserves_generic_finding(tmp_path):
    catalog = vendor_intelligence.load(_write(tmp_path / "catalog.json"))

    findings, assessments, superseded = vendor_intelligence.assess(
        [_component()], [_finding()], catalog
    )

    assert findings == []
    assert assessments[0]["selected_state"] == "fixed"
    assert assessments[0]["backport"]["vendor_revision"] == "0+deb11u5"
    assert assessments[0]["conflicts"][-1]["source_name"] == "OSV"
    assert superseded[0]["finding"]["osv_id"] == "OSV-2026-1"


def test_affected_vendor_decision_enriches_finding_without_claiming_reachability(tmp_path):
    catalog = vendor_intelligence.load(
        _write(tmp_path / "catalog.json", _catalog("affected"))
    )

    findings, assessments, superseded = vendor_intelligence.assess(
        [_component()], [_finding()], catalog
    )

    assert len(findings) == 1
    assert findings[0].source == "Distribution security team"
    assert findings[0].source_url.startswith("https://vendor.example/")
    assert findings[0].affectedness == "affected"
    assert findings[0].reachability == "not_assessed"
    assert assessments[0]["conflicts"][-1]["asserted_state"] == "affected"
    assert superseded == []


def test_catalogue_does_not_match_a_similar_package_name(tmp_path):
    catalog = vendor_intelligence.load(_write(tmp_path / "catalog.json"))
    similar = _component()
    similar["purl"] = PURL.replace("deb11u5", "deb11u4")

    findings, assessments, superseded = vendor_intelligence.assess(
        [similar], [_finding()], catalog
    )

    assert len(findings) == 1
    assert assessments == []
    assert superseded == []


def test_backport_requires_patch_evidence(tmp_path):
    document = _catalog()
    del document["entries"][0]["backport"]

    with pytest.raises(vendor_intelligence.VendorIntelligenceError, match="backport"):
        vendor_intelligence.load(_write(tmp_path / "catalog.json", document))


def test_package_version_must_match_exact_purl(tmp_path):
    document = _catalog()
    document["entries"][0]["version"] = "1.2.3"

    with pytest.raises(vendor_intelligence.VendorIntelligenceError, match="exactly match"):
        vendor_intelligence.load(_write(tmp_path / "catalog.json", document))


def test_insecure_source_url_is_rejected(tmp_path):
    document = _catalog()
    document["entries"][0]["source"]["url"] = "http://vendor.example/advisory"

    with pytest.raises(vendor_intelligence.VendorIntelligenceError, match="https"):
        vendor_intelligence.load(_write(tmp_path / "catalog.json", document))


def test_configured_missing_catalogue_is_a_visible_error(tmp_path, monkeypatch):
    missing = tmp_path / "missing.json"
    monkeypatch.setenv("PANDAX_VENDOR_CATALOG", str(missing))

    with pytest.raises(
        vendor_intelligence.VendorIntelligenceError, match="configured.*not found"
    ):
        vendor_intelligence.load_active()


def test_cli_installs_catalogue_once_and_reports_status(tmp_path, monkeypatch):
    source = _write(tmp_path / "catalog.json")
    monkeypatch.setenv("PANDAX_DATA_DIR", str(tmp_path / "data"))
    runner = CliRunner()

    installed = runner.invoke(cli.app, ["advisory", "install", str(source)])
    repeated = runner.invoke(cli.app, ["advisory", "install", str(source)])
    status = runner.invoke(cli.app, ["advisory", "status"])

    assert installed.exit_code == 0
    assert repeated.exit_code == 1
    assert "use --force" in repeated.output
    assert status.exit_code == 0
    assert '"installed": true' in status.output
    assert '"catalog_version": "2026-09-13.1"' in status.output


def test_match_stage_applies_active_catalogue_and_seals_conflict_evidence(
    ctx, tmp_path, monkeypatch
):
    source = _write(tmp_path / "catalog.json", _catalog("affected"))
    monkeypatch.setenv("PANDAX_VENDOR_CATALOG", str(source))
    ctx.components = [_component()]
    ctx.native_inventory = {"components": []}

    class EmptyFeeds:
        def query_purls(self, purls):
            return {purl: [] for purl in purls}

    list(match.run(ctx, EmptyFeeds()))

    assert [(item.cve, item.source) for item in ctx.findings] == [
        ("CVE-2026-10001", "Distribution security team")
    ]
    assessments = json.loads(ctx.path("vendor-assessments.json").read_text())
    assert assessments["matched_entries"] == 1
    assert ctx.path("vendor-superseded-findings.json").exists()
    output_names = {row["path"] for row in ctx.ledger.records[-1]["outputs"]}
    assert {
        "vendor-intelligence.json",
        "vendor-assessments.json",
        "vendor-superseded-findings.json",
    }.issubset(output_names)


def test_match_stage_vendor_backport_supersedes_osv_but_keeps_original(
    ctx, tmp_path, monkeypatch
):
    source = _write(tmp_path / "catalog.json")
    monkeypatch.setenv("PANDAX_VENDOR_CATALOG", str(source))
    ctx.components = [_component()]
    ctx.native_inventory = {"components": []}

    class ConflictingFeeds:
        def query_purls(self, purls):
            return {purl: ["OSV-2026-1"] for purl in purls}

        def vuln_detail(self, _identifier):
            return {
                "id": "OSV-2026-1",
                "aliases": ["CVE-2026-10001"],
                "summary": "Generic upstream range says affected",
                "affected": [
                    {
                        "package": {"purl": PURL},
                        "ranges": [{"type": "ECOSYSTEM", "events": []}],
                    }
                ],
            }

    list(match.run(ctx, ConflictingFeeds()))

    assert ctx.findings == []
    superseded = json.loads(ctx.path("vendor-superseded-findings.json").read_text())
    assert superseded["count"] == 1
    assert superseded["findings"][0]["finding"]["source"] == "OSV"


def test_api_reports_active_catalogue_without_advisory_text(tmp_path, monkeypatch):
    from pandax import server

    source = _write(tmp_path / "catalog.json")
    monkeypatch.setenv("PANDAX_VENDOR_CATALOG", str(source))

    response = TestClient(server.api).get("/api/vendor-intelligence")

    assert response.status_code == 200
    assert response.json()["installed"] is True
    assert response.json()["entries"] == 1
    assert "security fix" not in response.text
