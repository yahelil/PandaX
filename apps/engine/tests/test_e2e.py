"""End-to-end: the real artifact, the real Syft, the real feeds.

Marked `slow` because it needs the network and the bootstrapped Syft binary:
    uv run pytest -m "not slow"     # unit tests only
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pandax import events as ev
from pandax.context import ROOT
from pandax.evidence import verify_run

ARTIFACT = ROOT / "fixtures" / "smarthub-sh100-v2.3.1.zip"
SYFT = [ROOT / "workspace" / "tools" / "syft.exe", ROOT / "workspace" / "tools" / "syft"]

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not ARTIFACT.exists(), reason="run tools/bootstrap.py first"),
    pytest.mark.skipif(
        not any(p.exists() for p in SYFT), reason="syft not installed; run bootstrap"
    ),
]

# These three CVEs are in the CISA KEV catalogue and are what the fixture is
# built to surface - one per ecosystem.
EXPECTED_KEV = {"CVE-2021-44228", "CVE-2023-4863", "CVE-2020-11023"}


@pytest.fixture(scope="module")
def completed(tmp_path_factory) -> tuple[Path, dict]:
    from pandax import pipeline

    out = tmp_path_factory.mktemp("e2e")
    summary: dict = {}
    for event in pipeline.run(ARTIFACT, out_base=out):
        if event.kind == ev.RUN_DONE:
            summary = dict(event.data)
    assert summary, "pipeline produced no run_done event"
    return Path(summary["run_dir"]), summary


def test_sbom_is_cyclonedx_16_with_no_vulnerability_data(completed):
    run_dir, _ = completed
    sbom = json.loads((run_dir / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert sbom["specVersion"] == "1.6"
    assert "vulnerabilities" not in sbom  # the zero-CVE invariant


def test_all_three_ecosystems_are_catalogued(completed):
    run_dir, _ = completed
    sbom = json.loads((run_dir / "sbom.cdx.json").read_text(encoding="utf-8"))
    purls = {c["purl"] for c in sbom["components"] if c.get("purl")}
    ecosystems = {p.split("/")[0] for p in purls}
    assert {"pkg:npm", "pkg:pypi", "pkg:maven"} <= ecosystems


def test_the_known_exploited_vulnerabilities_are_found(completed):
    run_dir, summary = completed
    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    kev = {f["cve"] for f in findings if f["kev"]}
    assert EXPECTED_KEV <= kev, f"missing: {EXPECTED_KEV - kev}"
    assert summary["kev"] == len(kev)


def test_log4shell_is_attributed_to_the_bundled_jar(completed):
    """The jar is a real binary - proving Syft reads inside it, not just manifests."""
    run_dir, _ = completed
    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    log4shell = next(f for f in findings if f["cve"] == "CVE-2021-44228")
    assert log4shell["component"] == "log4j-core"
    assert log4shell["version"] == "2.14.1"
    assert log4shell["purl"].startswith("pkg:maven/")
    assert log4shell["fixed_version"] == "2.15.0"


def test_vex_keeps_kev_separate_and_nothing_not_affected(completed):
    run_dir, _ = completed
    vex = json.loads((run_dir / "findings.cdx-vex.json").read_text(encoding="utf-8"))
    assert vex["specVersion"] == "1.6"
    states = {v["analysis"]["state"] for v in vex["vulnerabilities"]}
    assert "in_triage" in states
    assert "exploitable" not in states
    assert "not_affected" not in states
    kev = next(v for v in vex["vulnerabilities"] if v["id"] in EXPECTED_KEV)
    properties = {item["name"]: item["value"] for item in kev["properties"]}
    assert properties["pandax:kev-signal"] == "true"
    assert properties["pandax:reachability"] == "not_assessed"


def test_article_14_filings_exist_for_every_kev_hit(completed):
    run_dir, _ = completed
    incidents = json.loads((run_dir / "incidents.json").read_text(encoding="utf-8"))
    assert {i["cve"] for i in incidents} >= EXPECTED_KEV
    for incident in incidents:
        target = run_dir / "filings" / incident["cve"]
        for name in ("early_warning", "notification", "final_report"):
            assert (target / f"{name}.json").exists()


def test_both_annex_documents_are_produced_as_pdf(completed):
    run_dir, _ = completed
    for name in (
        "AnnexVII_Technical_Documentation.pdf",
        "EU_Declaration_of_Conformity.pdf",
    ):
        pdf = run_dir / name
        assert pdf.exists() and pdf.stat().st_size > 10_000
        assert pdf.read_bytes().startswith(b"%PDF")


def test_dossier_flags_undecidable_fields_rather_than_inventing_them(completed):
    run_dir, _ = completed
    data = json.loads((run_dir / "dossier.json").read_text(encoding="utf-8"))
    assert data["summary"]["required_input"] > 0
    assert data["summary"]["derived"] > 0


def test_the_sealed_bundle_verifies(completed):
    run_dir, _ = completed
    checks = verify_run(run_dir)
    failed = [c.name for c in checks if not c.ok]
    assert not failed, f"failed checks: {failed}"


def test_one_flipped_byte_breaks_verification(completed):
    """The end-to-end version of the tamper demo."""
    run_dir, _ = completed
    victim = run_dir / "sbom.cdx.json"
    original = victim.read_bytes()
    try:
        blob = bytearray(original)
        index = next(i for i, b in enumerate(blob) if chr(b).isdigit())
        blob[index] = ord("9") if chr(blob[index]) != "9" else ord("8")
        victim.write_bytes(bytes(blob))

        failed = {c.name: c.detail for c in verify_run(run_dir) if not c.ok}
        assert any(n.startswith("file digests") for n in failed)
        assert "sbom.cdx.json" in failed["stage outputs re-hashed"]
        assert "S2_SBOM" in failed["stage outputs re-hashed"]
    finally:
        victim.write_bytes(original)
    assert all(c.ok for c in verify_run(run_dir))  # restoring the byte re-verifies
