from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from pandax import cli, exposure, pipeline
from pandax.monitoring import MonitoringStore, pipeline_runner
from pandax.stages import triage


PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


def _document(**component_changes) -> dict:
    component = {
        "purl": PURL,
        "observed_at": "2026-09-13T09:30:00Z",
        "compiled_state": "included",
        "feature_state": "disabled",
        "network_exposure": "not_exposed",
        "evidence_ref": "release-review/SH100-2.3.1/logging",
        "build_flags": [
            {
                "name": "REMOTE_LOOKUPS",
                "state": "disabled",
                "effect": "supports_not_reachable",
                "evidence_ref": "build-record/SH100-2.3.1/flags",
            }
        ],
    }
    component.update(component_changes)
    return {
        "schema": exposure.SCHEMA,
        "product": {
            "name": "SmartHub SH-100",
            "version": "2.3.1",
            "unique_id": "PDX-SH100-EU",
        },
        "approval": {
            "reviewer": "Company security reviewer",
            "reviewed_at": "2026-09-13T10:00:00Z",
            "authority_attestation": True,
        },
        "components": [component],
    }


def _write(path: Path, document: dict | None = None) -> Path:
    path.write_text(json.dumps(document or _document()), encoding="utf-8")
    return path


def _prepare(ctx) -> None:
    root_ref = "product-root"
    ctx.sbom = {
        "metadata": {
            "component": {
                "bom-ref": root_ref,
                "name": "SmartHub SH-100",
            }
        },
        "components": [
            {"bom-ref": finding.bom_ref, "name": finding.component}
            for finding in ctx.findings
        ],
        "dependencies": [
            {"ref": root_ref, "dependsOn": [ctx.findings[0].bom_ref]},
        ],
    }
    ctx.path("findings.matched.json").write_text("[]", encoding="utf-8")


def test_reviewed_disabled_feature_supports_non_reachability_without_deciding_it(
    ctx, tmp_path
):
    _prepare(ctx)
    source = _write(tmp_path / "exposure.json")

    list(exposure.run(ctx, source))

    finding = ctx.findings[0]
    assert finding.exposure_assessment == "evidence_supports_not_reachable"
    assert finding.reachability == "unknown"
    result = json.loads(ctx.path("exposure-assessments.json").read_text())
    assessment = result["assessments"][0]
    assert assessment["dependency_path"] == ["SmartHub SH-100", "log4j-core"]
    assert any("build flag REMOTE_LOOKUPS" in row for row in assessment["negative_evidence"])
    assert assessment["decision"] == "not_made_automatically"
    assert assessment["recommendation"] == {
        "reachability": "not_reachable",
        "confidence": "high",
        "reason_codes": [
            "build_flag_supports_not_reachable",
            "network_not_exposed",
            "vulnerable_feature_disabled",
        ],
        "limitations": [
            "The SBOM dependency path proves declared inclusion only, not execution."
        ],
        "review_required": True,
        "recommended_vex": {
            "state": "not_affected",
            "justification": "code_not_reachable",
        },
    }
    vex = triage.build_vex(ctx)["vulnerabilities"][0]
    assert vex["analysis"]["state"] == "in_triage"
    assert "supporting evidence" in vex["analysis"]["detail"]


def test_runtime_execution_and_disabled_feature_are_reported_as_a_conflict(ctx, tmp_path):
    _prepare(ctx)
    ctx.findings[0].runtime_evidence = [
        {
            "purl": PURL,
            "signal": "component_executed",
            "observed_at": "2026-09-13T09:00:00Z",
        }
    ]

    list(exposure.run(ctx, _write(tmp_path / "exposure.json")))

    assert ctx.findings[0].exposure_assessment == "conflicting_evidence"
    result = json.loads(ctx.path("exposure-assessments.json").read_text())
    assessment = result["assessments"][0]
    assert assessment["positive_evidence"]
    assert assessment["negative_evidence"]
    assert assessment["recommendation"]["reachability"] == "review"
    assert assessment["recommendation"]["confidence"] == "low"
    assert assessment["recommendation"]["recommended_vex"] == {
        "state": "in_triage"
    }


def test_runtime_network_signal_conflicts_with_reviewed_non_exposure(ctx, tmp_path):
    _prepare(ctx)
    ctx.findings[0].runtime_evidence = [
        {
            "purl": PURL,
            "signal": "network_exposed",
            "observed_at": "2026-09-13T09:00:00Z",
        }
    ]
    document = _document(feature_state="unknown", build_flags=[])

    list(exposure.run(ctx, _write(tmp_path / "exposure.json", document)))

    assert ctx.findings[0].exposure_assessment == "conflicting_evidence"


def test_network_not_exposed_alone_does_not_recommend_not_reachable(ctx, tmp_path):
    _prepare(ctx)
    document = _document(
        compiled_state="unknown",
        feature_state="unknown",
        network_exposure="not_exposed",
        build_flags=[],
    )

    list(exposure.run(ctx, _write(tmp_path / "exposure.json", document)))

    result = json.loads(ctx.path("exposure-assessments.json").read_text())
    assessment = result["assessments"][0]
    assert assessment["status"] == "insufficient_evidence"
    assert assessment["recommendation"]["reachability"] == "review"
    assert assessment["recommendation"]["reason_codes"] == ["network_not_exposed"]


def test_excluded_component_recommends_reviewed_not_affected_without_applying_it(
    ctx, tmp_path
):
    _prepare(ctx)
    document = _document(
        compiled_state="excluded",
        feature_state="unknown",
        network_exposure="unknown",
        build_flags=[],
    )

    list(exposure.run(ctx, _write(tmp_path / "exposure.json", document)))

    finding = ctx.findings[0]
    assessment = json.loads(
        ctx.path("exposure-assessments.json").read_text()
    )["assessments"][0]
    assert assessment["recommendation"]["reachability"] == "not_reachable"
    assert assessment["recommendation"]["recommended_vex"] == {
        "state": "not_affected",
        "justification": "code_not_present",
    }
    assert assessment["review_required"] is True
    assert finding.reachability == "unknown"
    assert finding.exposure_evidence["recommendation"] == assessment["recommendation"]
    assert triage.build_vex(ctx)["vulnerabilities"][0]["analysis"]["state"] == "in_triage"


def test_runtime_network_signal_can_be_analyzed_without_a_context_file(ctx):
    _prepare(ctx)
    ctx.findings[0].runtime_evidence = [
        {
            "purl": PURL,
            "signal": "network_exposed",
            "observed_at": "2026-09-13T09:00:00Z",
        }
    ]

    list(exposure.run(ctx))

    assert ctx.findings[0].exposure_assessment == "evidence_supports_reachable"
    assert not ctx.path("exposure-context.json").exists()
    assert ctx.path("exposure-assessments.json").exists()
    assessment = json.loads(
        ctx.path("exposure-assessments.json").read_text()
    )["assessments"][0]
    assert assessment["recommendation"]["reachability"] == "reachable"
    assert assessment["recommendation"]["confidence"] == "high"


def test_context_must_match_exact_product_release(ctx, tmp_path):
    _prepare(ctx)
    document = _document()
    document["product"]["version"] = "9.9.9"

    with pytest.raises(exposure.ExposureError, match="not SmartHub SH-100 2.3.1"):
        list(exposure.run(ctx, _write(tmp_path / "exposure.json", document)))


def test_raw_configuration_and_free_form_evidence_are_rejected(tmp_path):
    document = _document(raw_configuration="PASSWORD=secret")
    with pytest.raises(exposure.ExposureError, match="Raw configuration"):
        exposure.load(_write(tmp_path / "raw.json", document))

    document = _document(evidence_ref="this is raw free form evidence")
    with pytest.raises(exposure.ExposureError, match="short evidence identifier"):
        exposure.load(_write(tmp_path / "free-form.json", document))


def test_unmatched_context_is_visible_instead_of_silently_applied(ctx, tmp_path):
    _prepare(ctx)
    document = _document(purl="pkg:npm/not-in-this-product@1.0.0")

    list(exposure.run(ctx, _write(tmp_path / "exposure.json", document)))

    result = json.loads(ctx.path("exposure-assessments.json").read_text())
    assert result["context_scope"]["not_present_in_sbom"] == [
        "pkg:npm/not-in-this-product@1.0.0"
    ]
    assert all(
        item["status"] == "insufficient_evidence" for item in result["assessments"]
    )


def test_company_review_must_follow_the_evidence(tmp_path):
    document = _document()
    document["approval"]["reviewed_at"] = "2026-09-13T09:00:00Z"

    with pytest.raises(exposure.ExposureError, match="earlier than evidence"):
        exposure.load(_write(tmp_path / "exposure.json", document))


def test_cli_validation_prints_summary_not_component_evidence(tmp_path):
    source = _write(tmp_path / "exposure.json")
    result = CliRunner().invoke(cli.app, ["exposure", "validate", str(source)])

    assert result.exit_code == 0
    assert '"valid": true' in result.stdout
    assert "REMOTE_LOOKUPS" not in result.stdout
    assert "release-review" not in result.stdout


def test_scan_sbom_forwards_exposure_context(monkeypatch, tmp_path):
    sbom = tmp_path / "bom.json"
    sbom.write_text("{}", encoding="utf-8")
    context = _write(tmp_path / "exposure.json")
    captured = {}

    def run_sbom(path, out_base=None, offline=False, exposure_context_path=None):
        captured.update(path=path, exposure=exposure_context_path)
        return iter(())

    monkeypatch.setattr(pipeline, "run_sbom", run_sbom)
    monkeypatch.setattr(cli, "_render_pipeline", lambda *args, **kwargs: None)
    result = CliRunner().invoke(
        cli.app,
        ["scan-sbom", str(sbom), "--exposure-context", str(context)],
    )

    assert result.exit_code == 0
    assert captured["exposure"] == context


def test_monitoring_saves_and_forwards_exposure_context(monkeypatch, tmp_path):
    from pandax import events as ev

    source = tmp_path / "product.zip"
    source.write_bytes(b"product")
    context = _write(tmp_path / "exposure.json")
    store = MonitoringStore(tmp_path / "monitoring.sqlite3")
    policy = store.add_policy("Product", source, exposure_context=context)
    captured = {}
    run_dir = tmp_path / "run-test"
    run_dir.mkdir()

    def run(path, out_base=None, exposure_context_path=None):
        captured.update(path=path, exposure=exposure_context_path)
        return iter([ev.log("RUN", "started", run_dir=str(run_dir))])

    monkeypatch.setattr(pipeline, "run", run)

    assert pipeline_runner(policy, tmp_path / "out") == run_dir
    assert captured["exposure"] == context.resolve()
    assert policy["exposure_context_path"] == str(context.resolve())


def test_exposure_validation_api_returns_only_summary(tmp_path):
    from pandax import server

    source = _write(tmp_path / "exposure.json")
    response = TestClient(server.api).post(
        "/api/exposure/validate", json={"path": str(source)}
    )

    assert response.status_code == 200
    assert response.json()["components"] == 1
    assert "REMOTE_LOOKUPS" not in response.text


def test_sbom_api_accepts_exposure_context_upload(tmp_path, monkeypatch):
    from pandax import server

    server.CURRENT = None
    captured = {}

    def start(
        self,
        artifact,
        input_type="artifact",
        cleanup_dir=None,
        telemetry_path=None,
        exposure_context_path=None,
    ):
        captured.update(
            input_type=input_type,
            exposure=exposure_context_path,
        )
        self.finished = True
        if cleanup_dir:
            shutil.rmtree(cleanup_dir, ignore_errors=True)

    monkeypatch.setattr(server.Job, "start", start)
    sbom = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "log4j-core",
                    "version": "2.14.1",
                    "purl": PURL,
                }
            ],
        }
    ).encode()
    context = json.dumps(_document()).encode()

    response = TestClient(server.api).post(
        "/api/scan/sbom",
        files={
            "file": ("bom.json", sbom, "application/json"),
            "exposure_context": ("exposure.json", context, "application/json"),
        },
    )

    assert response.status_code == 200
    assert response.json()["exposure_context_attached"] is True
    assert captured["input_type"] == "sbom"
    assert captured["exposure"].name == "exposure-context.json"
    server.CURRENT = None
