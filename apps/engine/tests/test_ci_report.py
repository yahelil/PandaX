from __future__ import annotations

import json
from pathlib import Path

import pytest

from pandax.ci_report import build_sarif, build_summary, write_reports


def _run(tmp_path: Path) -> Path:
    run = tmp_path / "run-example"
    run.mkdir()
    (run / "findings.json").write_text(
        json.dumps(
            [
                {
                    "cve": "CVE-2026-1234",
                    "osv_id": "OSV-2026-1",
                    "component": "example",
                    "version": "1.0.0",
                    "purl": "pkg:pypi/example@1.0.0",
                    "summary": "Example vulnerability",
                    "severity": "HIGH",
                    "kev": True,
                    "source": "OSV",
                    "source_url": "https://osv.dev/vulnerability/OSV-2026-1",
                    "source_retrieved_at": "2026-09-15T08:00:00Z",
                    "affectedness": "affected",
                    "reachability": "unknown",
                }
            ]
        ),
        encoding="utf-8",
    )
    return run


def test_builds_conservative_json_summary(tmp_path: Path):
    run = _run(tmp_path)
    report = build_summary(
        run,
        {
            "run_id": "run-example",
            "components": 4,
            "matchable_components": 3,
            "skipped_components": 1,
            "incidents": 1,
            "coverage_summary": {"completed": 3, "unscanned": 1},
        },
    )

    assert report["result"] == {
        "status": "urgent_review",
        "components": 4,
        "matchable_components": 3,
        "skipped_components": 1,
        "findings": 1,
        "kev_signals": 1,
        "article_14_clocks": 1,
        "coverage": {"completed": 3, "unscanned": 1},
    }
    assert "not automatic CRA Article 14 reportability" in report["limitations"][1]


def test_builds_sarif_with_stable_package_identity(tmp_path: Path):
    report = build_sarif(_run(tmp_path))
    driver = report["runs"][0]["tool"]["driver"]
    result = report["runs"][0]["results"][0]

    assert report["version"] == "2.1.0"
    assert driver["rules"][0]["id"] == "CVE-2026-1234"
    assert result["level"] == "error"
    assert result["logicalLocations"][0]["fullyQualifiedName"] == "pkg:pypi/example@1.0.0"
    assert len(result["partialFingerprints"]["pandaxFinding/v1"]) == 64


def test_writes_reports_without_mutating_sealed_bundle(tmp_path: Path):
    run = _run(tmp_path)
    summary = tmp_path / "reports" / "summary.json"
    sarif = tmp_path / "reports" / "pandax.sarif"
    write_reports(run, {}, json_output=summary, sarif_output=sarif)

    assert json.loads(summary.read_text(encoding="utf-8"))["result"]["findings"] == 1
    assert json.loads(sarif.read_text(encoding="utf-8"))["version"] == "2.1.0"

    with pytest.raises(ValueError, match="outside the sealed evidence bundle"):
        write_reports(run, {}, json_output=run / "summary.json")
