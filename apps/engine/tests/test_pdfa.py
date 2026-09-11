"""Validation failures must never turn into a signed, completed dossier."""

import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from pandax import pdfa, pipeline
from pandax.evidence import canonical, sha256_bytes, sha256_file, verify_run
from pandax.stages import dossier


def report(pdf):
    root = ET.Element("report")
    build = ET.SubElement(root, "buildInformation")
    for part in ("core", "validation-model", "apps"):
        ET.SubElement(build, "releaseDetails", id=part, version=pdfa.VERSION)
    job = ET.SubElement(ET.SubElement(root, "jobs"), "job")
    ET.SubElement(ET.SubElement(job, "item"), "name").text = str(pdf.resolve())
    validation = ET.SubElement(job, "validationReport", profileName=pdfa.PROFILE,
                               jobEndStatus="normal", isCompliant="true")
    ET.SubElement(validation, "details", failedRules="0", failedChecks="0",
                  passedRules="144", passedChecks="540")
    batch = ET.SubElement(root, "batchSummary", totalJobs="1", failedToParse="0",
                          encrypted="0", outOfMemory="0", veraExceptions="0")
    ET.SubElement(batch, "validationReports", compliant="1", nonCompliant="0", failedJobs="0")
    return root


def fake_runner(monkeypatch, raw, code=0):
    monkeypatch.setattr(pdfa, "validator_command", lambda *_: ["java", "-jar", "validator.jar"])

    def run(command, *, stdout, stderr, timeout, check):
        assert command[-7:-1] == ["--format", "xml", "--flavour", "2b", "--maxfailuresdisplayed", "10"]
        assert timeout == 60 and not check
        stdout.write(raw)
        stderr.write(b"validator diagnostic")
        return subprocess.CompletedProcess(command, code)

    monkeypatch.setattr(pdfa.subprocess, "run", run)


@pytest.fixture
def pdf(tmp_path):
    path = tmp_path / "a document & data.pdf"
    path.write_bytes(b"%PDF-1.7\nfixture")
    return path


def test_success_retains_hash_version_command_and_raw_reports(monkeypatch, pdf, tmp_path):
    raw = ET.tostring(report(pdf))
    fake_runner(monkeypatch, raw)
    folder = tmp_path / "reports"
    result = pdfa.validate_pdf(pdf, folder)
    assert result["compliant"] and result["validator_version"] == pdfa.VERSION
    assert result["sha256"] == sha256_file(pdf)
    assert result["validator_sha256"] == pdfa.JAR_SHA256
    assert (folder / result["report"]).read_bytes() == raw
    assert (folder / result["stderr"]).read_text() == "validator diagnostic"
    assert json.loads(next(folder.glob("*.json")).read_text()) == result


@pytest.mark.parametrize("element,attribute,value", [
    ("jobs/job/validationReport", "isCompliant", "false"),
    ("jobs/job/validationReport", "profileName", "PDF/A-1b validation profile"),
    ("jobs/job/validationReport", "jobEndStatus", "failed"),
    ("jobs/job/validationReport/details", "failedChecks", "1"),
    ("jobs/job/validationReport/details", "failedRules", "1"),
    ("batchSummary", "totalJobs", "2"),
    ("batchSummary", "failedToParse", "1"),
    ("batchSummary", "encrypted", "1"),
    ("batchSummary", "outOfMemory", "1"),
    ("batchSummary", "veraExceptions", "1"),
    ("batchSummary/validationReports", "failedJobs", "1"),
    ("batchSummary/validationReports", "nonCompliant", "1"),
    ("batchSummary/validationReports", "compliant", "0"),
    ("buildInformation/releaseDetails", "version", "1.28.2"),
])
def test_fail_closed_on_report_failures(monkeypatch, pdf, tmp_path, element, attribute, value):
    root = report(pdf)
    root.find(element).set(attribute, value)
    fake_runner(monkeypatch, ET.tostring(root))
    result = pdfa.validate_pdf(pdf, tmp_path / "reports")
    assert not result["compliant"] and result["error"]


@pytest.mark.parametrize("mutation", ["missing", "multiple", "wrong_pdf", "malformed", "empty", "doctype", "oversized"])
def test_rejects_untrustworthy_reports(monkeypatch, pdf, tmp_path, mutation):
    root = report(pdf)
    if mutation == "missing":
        root.find("jobs/job").remove(root.find("jobs/job/validationReport"))
    elif mutation == "multiple":
        root.find("jobs").append(root.find("jobs/job"))
    elif mutation == "wrong_pdf":
        root.find("jobs/job/item/name").text = str(tmp_path / "other.pdf")
    raw = ET.tostring(root)
    raw = {"malformed": b"<report>", "empty": b"", "doctype": b"<!DOCTYPE report>" + raw,
           "oversized": b" " * (16 * 1024 * 1024 + 1)}.get(mutation, raw)
    fake_runner(monkeypatch, raw)
    result = pdfa.validate_pdf(pdf, tmp_path / "reports")
    assert not result["compliant"] and result["error"]


def test_nonzero_exit_cannot_override_a_passing_report(monkeypatch, pdf, tmp_path):
    fake_runner(monkeypatch, ET.tostring(report(pdf)), code=2)
    result = pdfa.validate_pdf(pdf, tmp_path / "reports")
    assert not result["compliant"] and result["returncode"] == 2


def test_missing_validator_retains_diagnostics(monkeypatch, pdf, tmp_path):
    monkeypatch.setenv("PANDAX_VERAPDF", str(tmp_path / "missing.bat"))
    result = pdfa.validate_pdf(pdf, tmp_path / "reports")
    assert not result["compliant"] and "not found" in result["error"]
    assert result["command"] is None and result["validator_sha256"] is None
    assert len(list((tmp_path / "reports").iterdir())) == 3


def test_missing_pdf_retains_diagnostics(tmp_path):
    result = pdfa.validate_pdf(tmp_path / "missing.pdf", tmp_path / "reports")
    assert not result["compliant"] and result["error"] and result["sha256"] is None
    assert len(list((tmp_path / "reports").iterdir())) == 3


def test_pdf_changed_during_validation_is_rejected(monkeypatch, pdf, tmp_path):
    fake_runner(monkeypatch, ET.tostring(report(pdf)))
    original = pdfa.subprocess.run

    def mutate(*args, **kwargs):
        completed = original(*args, **kwargs)
        pdf.write_bytes(b"changed PDF")
        return completed

    monkeypatch.setattr(pdfa.subprocess, "run", mutate)
    result = pdfa.validate_pdf(pdf, tmp_path / "reports")
    assert not result["compliant"] and "changed" in result["error"]


def test_timeout_kills_process_and_preserves_partial_output(monkeypatch, pdf, tmp_path):
    monkeypatch.setattr(pdfa, "validator_command", lambda *_: [sys.executable, "-u", "-c",
        "import time; print('partial report', flush=True); time.sleep(30)"])
    result = pdfa.validate_pdf(pdf, tmp_path / "reports", timeout=1)
    assert not result["compliant"] and "timed out" in result["error"]
    assert (tmp_path / "reports" / result["report"]).read_text().strip() == "partial report"


def test_resolver_supports_launcher_paths_with_spaces_without_shell(monkeypatch, tmp_path):
    launcher = tmp_path / "tools & spaces" / "verapdf.bat"
    jar = launcher.parent / "bin" / f"cli-{pdfa.VERSION}.jar"
    jar.parent.mkdir(parents=True)
    jar.write_bytes(b"jar")
    monkeypatch.setattr(pdfa, "JAR_SHA256", sha256_bytes(b"jar"))
    monkeypatch.setattr(pdfa.shutil, "which", lambda name: "java.exe" if name == "java" else None)
    assert pdfa.validator_command(launcher) == ["java.exe", "-Dfile.encoding=UTF-8", "-jar", str(jar)]
    assert pdfa.validator_command(jar)[-1] == str(jar)
    monkeypatch.setenv("PANDAX_VERAPDF", str(launcher))
    assert pdfa.validator_command()[-1] == str(jar)


def test_missing_java_is_actionable(monkeypatch, tmp_path):
    jar = tmp_path / "cli.jar"
    jar.write_bytes(b"jar")
    monkeypatch.setattr(pdfa, "JAR_SHA256", sha256_bytes(b"jar"))
    monkeypatch.setattr(pdfa.shutil, "which", lambda _: None)
    with pytest.raises(FileNotFoundError, match="Java is required"):
        pdfa.validator_command(jar)


def test_changed_validator_binary_is_rejected(tmp_path):
    jar = tmp_path / f"cli-{pdfa.VERSION}.jar"
    jar.write_bytes(b"changed validator")
    with pytest.raises(ValueError, match="digest mismatch"):
        pdfa.validator_command(jar)


@pytest.mark.parametrize("selection", ["env_jar", "env_launcher", "path_unix", "path_windows", "local"])
def test_validator_discovery_matrix(monkeypatch, tmp_path, selection):
    folder = tmp_path / "verapdf"
    jar = folder / "bin" / f"cli-{pdfa.VERSION}.jar"
    jar.parent.mkdir(parents=True)
    jar.write_bytes(b"jar")
    monkeypatch.setattr(pdfa, "JAR_SHA256", sha256_bytes(b"jar"))
    monkeypatch.setattr(pdfa, "TOOLS_DIR", tmp_path)
    monkeypatch.delenv("PANDAX_VERAPDF", raising=False)
    found = {"java": "java.exe"}
    if selection == "env_jar":
        monkeypatch.setenv("PANDAX_VERAPDF", str(jar))
    elif selection == "env_launcher":
        monkeypatch.setenv("PANDAX_VERAPDF", str(folder / "verapdf.bat"))
    elif selection == "path_unix":
        found["verapdf"] = str(folder / "verapdf")
    elif selection == "path_windows":
        found["verapdf.bat"] = str(folder / "verapdf.bat")
    monkeypatch.setattr(pdfa.shutil, "which", found.get)
    assert pdfa.validator_command()[-1] == str(jar)


def test_setup_pin_matches_runner_and_never_overwrites(monkeypatch, tmp_path):
    from pandax.context import ROOT

    monkeypatch.syspath_prepend(str(ROOT / "tools"))
    import setup_verapdf

    assert setup_verapdf.VERSION == pdfa.VERSION
    monkeypatch.setattr(setup_verapdf, "TOOLS", tmp_path)
    monkeypatch.setattr(setup_verapdf.shutil, "which", lambda _: "java")
    monkeypatch.setattr(setup_verapdf, "fetch", lambda *_: pytest.fail("unexpected download"))
    (tmp_path / "verapdf").mkdir()
    with pytest.raises(SystemExit, match="already exists"):
        setup_verapdf.main()


@pytest.mark.parametrize("failure", ["compile", "validation"])
def test_dossier_checks_whole_batch_and_fails_before_done(monkeypatch, ctx, failure):
    compiled, validated = [], []

    def compile_pdf(source, output, root):
        compiled.append(output)
        if failure == "compile" and len(compiled) == 2:
            return "deliberate compilation error\nfull diagnostic"
        output.write_bytes(b"%PDF")
        return ""

    def validate(pdf, reports):
        validated.append(pdf)
        return {"compliant": not (failure == "validation" and len(validated) == 2),
                "validator_version": pdfa.VERSION, "error": "deliberate validation failure"}

    monkeypatch.setattr(dossier, "_compile", compile_pdf)
    monkeypatch.setattr(pdfa, "validate_pdf", validate)
    with pytest.raises(RuntimeError, match="Dossier not sealed"):
        list(dossier.run(ctx))
    assert len(compiled) == 3
    assert len(validated) == (2 if failure == "compile" else 3)
    assert ctx.ledger.records[-1]["params_sha256"] == sha256_bytes(canonical({
        "pdf_standard": "a-2b", "annexes": ["VII", "V", "VI"],
        "validator": "verapdf", "validator_version": pdfa.VERSION, "validation_passed": False,
    }))
    if failure == "compile":
        assert "full diagnostic" in next(ctx.path("pdf-validation").glob("*.compile.txt")).read_text()
    assert not ctx.path("manifest.sig").exists()


class OfflineFeeds:
    def __init__(self, *_args, **_kwargs): pass
    def query_purls(self, purls): return {purl: [] for purl in purls}
    def kev(self): return {}
    def kev_released(self): return "2026-09-10"
    def epss(self, _cves): return {}
    def close(self): pass


def sbom_source(tmp_path, format):
    if format == "cdx":
        data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "components": [{"type": "library", "name": "requests", "version": "2.31.0",
                                "purl": "pkg:pypi/requests@2.31.0"}]}
    else:
        data = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
                "name": "PDF validation simulation", "dataLicense": "CC0-1.0",
                "documentNamespace": "https://example.invalid/pdfa-simulation",
                "packages": [{"SPDXID": "SPDXRef-requests", "name": "requests", "versionInfo": "2.31.0",
                              "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                                "referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.31.0"}]}]}
    source = tmp_path / "supplied sbom.json"
    source.write_text(json.dumps(data), encoding="utf-8")
    return source


def test_pipeline_never_seals_when_validator_is_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "Feeds", OfflineFeeds)
    monkeypatch.setenv("PANDAX_VERAPDF", str(tmp_path / "missing.bat"))
    with pytest.raises(RuntimeError, match="Dossier not sealed"):
        list(pipeline.run_sbom(sbom_source(tmp_path, "cdx"), out_base=tmp_path / "out"))
    assert not list((tmp_path / "out").rglob("manifest.sig"))
    assert not list((tmp_path / "out").rglob("manifest.json"))
    results = list((tmp_path / "out").rglob("*.validation.json"))
    assert len(results) == 3
    assert all(not json.loads(p.read_text())["compliant"] for p in results)


real = pytest.mark.skipif(os.environ.get("PANDAX_PDFA_INTEGRATION") != "1",
                          reason="set PANDAX_PDFA_INTEGRATION=1 with pinned veraPDF installed")


@real
@pytest.mark.parametrize("kind", ["pdfa", "ordinary_pdf", "malformed"])
def test_real_validator_accepts_only_pdfa(tmp_path, kind):
    import typst

    pdf = tmp_path / "real document & spaces.pdf"
    pdf.write_bytes(b"%PDF-1.7\ngarbage" if kind == "malformed" else
                    typst.compile(b'= Validation sample\nHello!', pdf_standards=["a-2b"] if kind == "pdfa" else []))
    result = pdfa.validate_pdf(pdf, tmp_path / "reports")
    assert result["compliant"] is (kind == "pdfa")
    assert (tmp_path / "reports" / result["report"]).stat().st_size > 0


@real
@pytest.mark.parametrize("format", ["cdx", "spdx"])
def test_real_sbom_to_validated_signed_bundle(monkeypatch, tmp_path, format):
    monkeypatch.setattr(pipeline, "Feeds", OfflineFeeds)
    monkeypatch.setenv("PANDAX_SIGNING_KEY", str(tmp_path / "test-key.pem"))
    events = list(pipeline.run_sbom(sbom_source(tmp_path, format), out_base=tmp_path / "out"))
    completed = next(event for event in events if event.kind == "run_done")
    run_dir = Path(completed.data["run_dir"])
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["tool_versions"]["verapdf"] == pdfa.VERSION
    results = list((run_dir / "pdf-validation").glob("*.validation.json"))
    assert len(results) == 3
    files = {entry["path"] for entry in manifest["files"]}
    for path in results:
        result = json.loads(path.read_text())
        assert result["compliant"] and result["sha256"] == sha256_file(run_dir / result["pdf"])
        assert result["validator_sha256"] == pdfa.JAR_SHA256
        for name in (path.name, result["report"], result["stderr"]):
            assert "pdf-validation/" + name in files
    assert all(check.ok for check in verify_run(run_dir))
    results[0].write_text("tampered")
    assert not all(check.ok for check in verify_run(run_dir))


@real
@pytest.mark.parametrize("failure", ["compile", "invalid_pdf"])
def test_real_mixed_batch_retains_all_diagnostics_without_sealing(monkeypatch, tmp_path, failure):
    import typst

    original = dossier._compile
    attempts = []

    def compile_one_bad_pdf(source, output, root):
        attempts.append(output)
        if len(attempts) == 2:
            if failure == "compile":
                return "deliberate compile failure"
            output.write_bytes(typst.compile(b'Ordinary non-archival PDF'))
            return ""
        return original(source, output, root)

    monkeypatch.setattr(pipeline, "Feeds", OfflineFeeds)
    monkeypatch.setattr(dossier, "_compile", compile_one_bad_pdf)
    with pytest.raises(RuntimeError, match="Dossier not sealed"):
        list(pipeline.run_sbom(sbom_source(tmp_path, "cdx"), out_base=tmp_path / "out"))
    assert len(attempts) == 3
    results = [json.loads(p.read_text()) for p in (tmp_path / "out").rglob("*.validation.json")]
    assert sum(r["compliant"] for r in results) == 2
    assert len(results) == (2 if failure == "compile" else 3)
    assert not list((tmp_path / "out").rglob("manifest.json"))
    assert not list((tmp_path / "out").rglob("manifest.sig"))
