from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from pandax import cli, pipeline, telemetry
from pandax.monitoring import MonitoringStore, pipeline_runner
from pandax.stages import triage


DEVICE_HASH = "a" * 64


def _document(**changes) -> dict:
    result = {
        "schema": telemetry.SCHEMA,
        "product": {
            "name": "SmartHub SH-100",
            "version": "2.3.1",
            "unique_id": "PDX-SH100-EU",
        },
        "approval": {
            "operator": "Company security reviewer",
            "approved_at": "2026-09-11T08:00:00+00:00",
            "authority_attestation": True,
        },
        "observations": [
            {
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "signal": "component_executed",
                "observed_at": "2026-09-11T07:30:00Z",
                "device_ref_hash": DEVICE_HASH,
                "evidence_ref": "collector-batch/2026-09-11-01",
            }
        ],
    }
    result.update(changes)
    return result


def _write(path: Path, document: dict | None = None) -> Path:
    path.write_text(json.dumps(document or _document()), encoding="utf-8")
    return path


def test_runtime_evidence_is_attached_but_never_makes_a_legal_decision(ctx, tmp_path):
    source = _write(tmp_path / "telemetry.json")
    ctx.path("findings.matched.json").write_text("[]", encoding="utf-8")

    events = list(telemetry.apply(ctx, source))

    finding = ctx.findings[0]
    assert finding.runtime_evidence_status == "available_for_review"
    assert finding.runtime_evidence[0]["signal"] == "component_executed"
    assert finding.reachability == "unknown"
    assert finding.reachability_evidence == ""
    assessment = json.loads(ctx.path("telemetry-assessments.json").read_text())
    assert assessment["findings"][0]["review_required"] is True
    assert assessment["findings"][0]["decision"] == "not_made_automatically"
    source_receipt = json.loads(ctx.path("telemetry-source.json").read_text())
    assert source_receipt["sha256"] == telemetry.sha256_file(source)
    assert source_receipt["original_source_retained"] is False
    entry = triage.build_vex(ctx)["vulnerabilities"][0]
    assert entry["analysis"]["state"] == "in_triage"
    assert "has not converted" in entry["analysis"]["detail"]
    assert events[-1].message.startswith("approved telemetry attached")


def test_unmatched_observation_is_preserved_for_review(ctx, tmp_path):
    document = _document()
    document["observations"][0]["purl"] = "pkg:npm/not-in-findings@1.0.0"
    source = _write(tmp_path / "telemetry.json", document)
    ctx.path("findings.matched.json").write_text("[]", encoding="utf-8")

    list(telemetry.apply(ctx, source))

    assessment = json.loads(ctx.path("telemetry-assessments.json").read_text())
    assert assessment["unmatched_observations"][0]["purl"].endswith("@1.0.0")
    assert all(f.runtime_evidence_status == "not_supplied" for f in ctx.findings)


def test_telemetry_must_match_the_exact_product_release(ctx, tmp_path):
    document = _document()
    document["product"]["version"] = "9.9.9"
    source = _write(tmp_path / "telemetry.json", document)
    ctx.path("findings.matched.json").write_text("[]", encoding="utf-8")

    with pytest.raises(telemetry.TelemetryError, match="not SmartHub SH-100 2.3.1"):
        list(telemetry.apply(ctx, source))


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda row: row.update({"raw_log": "secret"}), "unsupported fields"),
        (lambda row: row.update({"device_ref_hash": "customer-host-1"}), "SHA-256"),
    ],
)
def test_raw_or_identifying_device_data_is_rejected(tmp_path, change, message):
    document = _document()
    change(document["observations"][0])

    with pytest.raises(telemetry.TelemetryError, match=message):
        telemetry.load(_write(tmp_path / "telemetry.json", document))


def test_approval_is_required(tmp_path):
    document = _document()
    document["approval"]["authority_attestation"] = False

    with pytest.raises(telemetry.TelemetryError, match="authorized company reviewer"):
        telemetry.load(_write(tmp_path / "telemetry.json", document))


def test_approval_must_follow_the_observation(tmp_path):
    document = _document()
    document["approval"]["approved_at"] = "2026-09-11T07:00:00Z"

    with pytest.raises(telemetry.TelemetryError, match="earlier than an observation"):
        telemetry.load(_write(tmp_path / "telemetry.json", document))


def test_cli_validates_without_printing_device_rows(tmp_path):
    source = _write(tmp_path / "telemetry.json")

    result = CliRunner().invoke(cli.app, ["telemetry", "validate", str(source)])

    assert result.exit_code == 0
    assert '"valid": true' in result.stdout
    assert DEVICE_HASH not in result.stdout


def test_scan_sbom_forwards_telemetry(monkeypatch, tmp_path):
    source = _write(tmp_path / "bom.json", {"bomFormat": "CycloneDX"})
    runtime = _write(tmp_path / "telemetry.json")
    captured = {}

    def run_sbom(path, out_base=None, offline=False, telemetry_path=None):
        captured.update(path=path, telemetry=telemetry_path)
        return iter(())

    monkeypatch.setattr(pipeline, "run_sbom", run_sbom)
    monkeypatch.setattr(cli, "_render_pipeline", lambda *args, **kwargs: None)

    result = CliRunner().invoke(
        cli.app, ["scan-sbom", str(source), "--telemetry", str(runtime)]
    )

    assert result.exit_code == 0
    assert captured["telemetry"] == runtime


def test_monitoring_policy_saves_and_forwards_telemetry(monkeypatch, tmp_path):
    from pandax import events as ev

    source = tmp_path / "product.zip"
    source.write_bytes(b"product")
    runtime = _write(tmp_path / "telemetry.json")
    store = MonitoringStore(tmp_path / "monitoring.sqlite3")
    policy = store.add_policy("Product", source, telemetry=runtime)
    captured = {}
    run_dir = tmp_path / "run-test"
    run_dir.mkdir()

    def run(path, out_base=None, telemetry_path=None):
        captured.update(path=path, telemetry=telemetry_path)
        return iter([ev.log("RUN", "started", run_dir=str(run_dir))])

    monkeypatch.setattr(pipeline, "run", run)

    assert pipeline_runner(policy, tmp_path / "out") == run_dir
    assert captured["telemetry"] == runtime.resolve()
    assert store.get_policy(policy["id"])["telemetry_path"] == str(runtime.resolve())


def test_telemetry_validation_api_returns_only_a_summary(tmp_path):
    from pandax import server

    source = _write(tmp_path / "telemetry.json")
    response = TestClient(server.api).post(
        "/api/telemetry/validate", json={"path": str(source)}
    )

    assert response.status_code == 200
    assert response.json()["observations"] == 1
    assert DEVICE_HASH not in response.text
