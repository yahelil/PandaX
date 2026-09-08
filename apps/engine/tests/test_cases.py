from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from pandax.cases import CaseError, CaseStore


@pytest.fixture
def store(tmp_path):
    return CaseStore(tmp_path / "pandax.sqlite3")


@pytest.fixture
def finding():
    return {
        "cve": "CVE-2021-44228",
        "component": "log4j-core",
        "version": "2.14.1",
        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        "severity": "CRITICAL",
        "summary": "Remote code execution",
        "fixed_version": "2.15.0",
        "kev": True,
    }


def test_case_creation_is_idempotent_and_durable(store, finding):
    first = store.create("run-source", finding)
    second = store.create("run-source", finding)

    assert first["id"] == second["id"]
    assert store.list()[0]["status"] == "detected"
    assert store.list()[0]["events"][0]["event_type"] == "finding_recorded"


def test_release_observation_never_claims_automatic_remediation(store, finding):
    case = store.create("run-source", finding)
    updated = store.observe_release(
        case["id"],
        "run-later",
        findings=[],
        components=[{"name": "log4j-core", "version": "2.17.1"}],
    )

    assert updated["status"] == "candidate_resolution"
    assert updated["candidate"]["result"] == "candidate_component_changed"
    assert updated["candidate"]["coverage_statement"] == "No finding in checked sources"
    assert "Manufacturer confirmation is required" in updated["candidate"]["explanation"]
    assert updated["measure_available_at"] is None
    assert updated["final_deadline"] is None


def test_persistent_finding_stays_detected(store, finding):
    case = store.create("run-source", finding)
    updated = store.observe_release(case["id"], "run-later", [finding], [])
    assert updated["status"] == "detected"
    assert updated["candidate"]["result"] == "still_detected"


def test_missing_component_is_an_uncertain_candidate(store, finding):
    case = store.create("run-source", finding)
    updated = store.observe_release(case["id"], "run-later", [], [])
    assert updated["candidate"]["result"] == "candidate_component_not_observed"
    assert "incomplete identification" in updated["candidate"]["explanation"]


def test_confirmation_calculates_deadline_and_creates_review_draft(store, finding):
    case = store.create("run-source", finding)
    store.observe_release(case["id"], "run-later", [], [{"name": "log4j-core", "version": "2.17.1"}])

    confirmed = store.confirm_measure(
        case["id"],
        "2026-09-15T12:00:00+03:00",
        "Yaheli Levit",
        "I am authorised by the manufacturer to confirm this measure.",
        "Firmware 2.4.0 with log4j-core 2.17.1 was made available to users.",
    )

    assert confirmed["status"] == "measure_confirmed"
    assert confirmed["measure_available_at"] == "2026-09-15T09:00:00Z"
    assert confirmed["final_deadline"] == "2026-09-29T09:00:00Z"
    assert confirmed["report"]["revision"] == 1
    report = confirmed["report"]["payload"]
    assert report["submission_status"] == "REVIEW REQUIRED - not submitted"
    assert report["final_report_deadline"] == confirmed["final_deadline"]
    assert "did not patch or deploy" in report["automation_limit"]
    assert len(confirmed["report"]["report_hash"]) == 64


@pytest.mark.parametrize(
    "operator,attestation,details,message",
    [
        ("", "authorised", "released", "named operator"),
        ("Yaheli", "", "released", "authority attestation"),
        ("Yaheli", "authorised", "", "measure details"),
    ],
)
def test_confirmation_requires_manufacturer_evidence(
    store, finding, operator, attestation, details, message
):
    case = store.create("run-source", finding)
    with pytest.raises(CaseError, match=message):
        store.confirm_measure(
            case["id"], "2026-09-15T12:00:00Z", operator, attestation, details
        )


def test_report_payload_is_valid_json_after_restart(store, finding):
    case = store.create("run-source", finding)
    store.confirm_measure(
        case["id"], "2026-09-15T12:00:00Z", "Operator", "Authorised", "OTA update"
    )
    reopened = CaseStore(store.path).get(case["id"])
    json.dumps(reopened)
    assert reopened["report"]["payload"]["case_id"] == case["id"]


def test_case_api_runs_the_detection_to_report_workflow(tmp_path, monkeypatch, finding):
    from pandax import server

    source = tmp_path / "run-source"
    source.mkdir()
    (source / "findings.json").write_text(json.dumps([finding]), encoding="utf-8")
    (source / "dossier.json").write_text(
        json.dumps({
            "product": {"name": "SmartHub SH-100", "version": "2.3.1"},
            "generated": "2026-09-01T12:00:00Z",
        }),
        encoding="utf-8",
    )
    target = tmp_path / "run-target"
    target.mkdir()
    (target / "findings.json").write_text("[]", encoding="utf-8")
    (target / "dossier.json").write_text(
        json.dumps({
            "product": {"name": "SmartHub SH-100", "version": "2.4.0"},
            "generated": "2026-09-02T12:00:00Z",
        }),
        encoding="utf-8",
    )
    (target / "sbom.cdx.json").write_text(
        json.dumps({"components": [{"name": "log4j-core", "version": "2.17.1"}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(server, "OUT_DIR", tmp_path)
    monkeypatch.setenv("PANDAX_DATA_DIR", str(tmp_path / "data"))
    client = TestClient(server.api)

    created = client.post(
        "/api/cases", json={"request_id": "create", "source_run_id": "run-source", "cve": finding["cve"]}
    )
    assert created.status_code == 200
    case_id = created.json()["id"]

    observed = client.post(
        f"/api/cases/{case_id}/observe-release", json={"request_id": "observe", "expected_version": 1, "target_run_id": "run-target"}
    )
    assert observed.status_code == 200
    assert observed.json()["status"] == "candidate_resolution"

    confirmed = client.post(
        f"/api/cases/{case_id}/confirm-measure",
        json={
            "request_id": "confirm", "expected_version": 2,
            "measure_available_at": "2026-09-15T12:00:00Z",
            "operator": "Yaheli",
            "authority_attestation": "Authorised manufacturer representative",
            "measure_details": "Firmware 2.4.0 was published to users",
        },
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["final_deadline"] == "2026-09-29T12:00:00Z"
    report = client.get(f"/api/cases/{case_id}/report")
    assert report.status_code == 200
    assert report.json()["payload"]["submission_status"] == "REVIEW REQUIRED - not submitted"


def test_case_api_rejects_release_for_another_product(tmp_path, monkeypatch, finding):
    from pandax import server

    for run_id, product in (("run-source", "SmartHub"), ("run-target", "OpenWrt")):
        run = tmp_path / run_id
        run.mkdir()
        (run / "findings.json").write_text(
            json.dumps([finding] if run_id == "run-source" else []), encoding="utf-8"
        )
        (run / "dossier.json").write_text(
            json.dumps({
                "product": {"name": product, "version": "1"},
                "generated": "2026-09-01T12:00:00Z" if run_id == "run-source" else "2026-09-02T12:00:00Z",
            }), encoding="utf-8"
        )
        (run / "sbom.cdx.json").write_text('{"components": []}', encoding="utf-8")
    monkeypatch.setattr(server, "OUT_DIR", tmp_path)
    monkeypatch.setenv("PANDAX_DATA_DIR", str(tmp_path / "data"))
    client = TestClient(server.api)
    case_id = client.post(
        "/api/cases", json={"request_id": "create", "source_run_id": "run-source", "cve": finding["cve"]}
    ).json()["id"]

    response = client.post(
        f"/api/cases/{case_id}/observe-release", json={"request_id": "observe", "expected_version": 1, "target_run_id": "run-target"}
    )

    assert response.status_code == 422
    assert "product mismatch" in response.json()["detail"]


def test_case_api_rejects_unknown_run(tmp_path, monkeypatch):
    from pandax import server

    monkeypatch.setattr(server, "OUT_DIR", tmp_path)
    monkeypatch.setenv("PANDAX_DATA_DIR", str(tmp_path / "data"))
    response = TestClient(server.api).post(
        "/api/cases", json={"request_id": "bad", "source_run_id": "../outside", "cve": "CVE-1"}
    )
    assert response.status_code == 422
