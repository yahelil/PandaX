"""Card 13: recursive export checks and deterministic PDF rendering stress cases.

Set PANDAX_PDFA_INTEGRATION=1 with veraPDF, pypdfium2 and Pillow installed
to retain compiled PDFs, page renders and layout evidence in pytest's basetemp.
"""

import dataclasses
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from pandax.context import ROOT
from pandax.evidence import sha256_file
from pandax.stages import dossier


@pytest.fixture
def directory_checker(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "tools"))
    import validate_pdfs
    return validate_pdfs


def test_recursive_command_preserves_inputs_and_duplicate_names(directory_checker, monkeypatch, tmp_path):
    source = tmp_path / "signed export"
    for name in ("one/same.pdf", "two/same.PDF", "one/not-a-pdf.txt"):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"unchanged")
    before = {p.relative_to(source): sha256_file(p) for p in source.rglob("*") if p.is_file()}
    destinations = []

    def validate(pdf, destination, *, executable):
        assert executable == "path with spaces/verapdf.bat"
        destinations.append(destination)
        destination.mkdir(parents=True)
        (destination / "raw.xml").write_text("evidence")
        return {"compliant": pdf.suffix == ".pdf", "error": None}

    monkeypatch.setattr(directory_checker, "validate_pdf", validate)
    reports = tmp_path / "reports"
    code = directory_checker.main([str(source), "--reports", str(reports),
                                   "--verapdf", "path with spaces/verapdf.bat"])
    summary = json.loads((reports / "summary.json").read_text())
    assert code == 1 and summary["total"] == 2 and summary["passed"] == 1
    assert len(set(destinations)) == 2
    for entry in summary["results"]:
        assert entry["sha256"] == sha256_file(source / entry["input_path"])
        assert (reports / entry["report_directory"]).is_dir()
    assert summary["expected_validator_version"] == directory_checker.VERSION
    assert {p.relative_to(source): sha256_file(p) for p in source.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize("case", ["missing", "empty", "nested", "ancestor", "existing"])
def test_directory_errors_are_readable(directory_checker, tmp_path, capsys, case):
    source, reports = tmp_path / "input", tmp_path / "reports"
    if case != "missing":
        source.mkdir()
    if case == "nested":
        reports = source / "reports"
    elif case == "ancestor":
        reports = tmp_path
    elif case == "existing":
        reports.mkdir()
        (reports / "keep.txt").write_text("keep")
    assert directory_checker.main([str(source), "--reports", str(reports)]) == 1
    assert "FAIL" in capsys.readouterr().out
    if case == "empty":
        assert json.loads((reports / "summary.json").read_text())["compliant"] is False
    if case == "existing":
        assert (reports / "keep.txt").read_text() == "keep"


def test_unreadable_subtree_is_not_silently_skipped(directory_checker, monkeypatch, tmp_path):
    source = tmp_path / "input"
    source.mkdir()

    def walk(*args, **kwargs):
        kwargs["onerror"](PermissionError("denied subtree"))

    monkeypatch.setattr(directory_checker.os, "walk", walk)
    assert directory_checker.main([str(source), "--reports", str(tmp_path / "reports")]) == 1


@pytest.mark.parametrize("linked_directory", [False, True])
def test_linked_entries_fail_without_following(directory_checker, monkeypatch, tmp_path, linked_directory):
    source = tmp_path / "input"
    source.mkdir()
    linked = source / "external"
    linked.mkdir() if linked_directory else linked.write_bytes(b"link fixture")
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda p: p == linked or original(p))
    assert directory_checker.main([str(source), "--reports", str(tmp_path / "reports")]) == 1
    assert not (tmp_path / "reports").exists()


def test_validator_error_does_not_skip_later_pdfs(directory_checker, monkeypatch, tmp_path):
    source = tmp_path / "input"
    source.mkdir()
    for name in ("a.pdf", "b.pdf"):
        (source / name).write_bytes(b"PDF")
    calls = []

    def validate(pdf, *_args, **_kwargs):
        calls.append(pdf.name)
        if pdf.name == "a.pdf":
            raise PermissionError("report cannot be written")
        return {"compliant": True, "error": None}

    monkeypatch.setattr(directory_checker, "validate_pdf", validate)
    result = directory_checker.validate_directory(source, tmp_path / "reports")
    assert calls == ["a.pdf", "b.pdf"] and result["passed"] == 1 and not result["compliant"]
    failed, passed = result["results"]
    assert failed.keys() == passed.keys()
    assert failed["sha256"] == sha256_file(source / "a.pdf")
    assert failed["report_directory"] is None and failed["report"] is None
    assert failed["validator_version"] is None


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_real_windows_junction_is_rejected(directory_checker, tmp_path):
    source, external = tmp_path / "input", tmp_path / "external"
    source.mkdir()
    external.mkdir()
    (external / "outside.pdf").write_bytes(b"outside")
    # Native argument array; no interpolated shell command or admin-only symlink.
    linked = source / "junction"
    env = dict(os.environ, PANDAX_TEST_LINK=str(linked), PANDAX_TEST_TARGET=str(external))
    command = ["powershell", "-NoProfile", "-Command",
               "New-Item -ItemType Junction -Path $env:PANDAX_TEST_LINK -Target $env:PANDAX_TEST_TARGET"]
    subprocess.run(command, env=env, check=True, capture_output=True)
    assert directory_checker.main([str(source), "--reports", str(tmp_path / "reports")]) == 1
    assert not (tmp_path / "reports").exists()
    assert (external / "outside.pdf").read_bytes() == b"outside"


real = pytest.mark.skipif(os.environ.get("PANDAX_PDFA_INTEGRATION") != "1",
                          reason="enable PDF/A integration and install render test dependencies")


def configure_corpus(ctx, scenario):
    """Use production dossier assembly; all enlarged data is explicitly synthetic."""
    ctx.run_id = "synthetic-pdf-corpus"
    ctx.findings = [] if scenario != "blocked" else ctx.findings
    if scenario == "missing":
        ctx.product = {}
    elif scenario == "long_text":
        ctx.product["product"]["name"] = "Synthetic industrial controller " * 8
        ctx.product["product"]["intended_purpose"] = "Synthetic purpose with extended manufacturer information. " * 70
        ctx.product["manufacturer"]["legal_name"] = "Synthetic manufacturer with an extended legal name " * 6
        ctx.product["manufacturer"]["address"] = "Synthetic address, industrial district, building 42, " * 15
        handling = ctx.product["vulnerability_handling"]
        handling["declaration_url"] = "https://example.invalid/" + "longpath" * 24 + "/declaration"
        handling["cvd_policy_url"] = handling["declaration_url"]
    elif scenario == "long_tables":
        from pandax.context import Finding
        base = Finding(cve="", osv_id="synthetic", purl="pkg:generic/synthetic@1.0",
                       component="synthetic component with a long descriptive name " * 2,
                       version="1.0", summary="Synthetic test finding", severity="HIGH",
                       fixed_version="2.0", kev_date_added="2026-01-01")
        ctx.findings = [dataclasses.replace(base, cve=f"CVE-2099-{1000+i}", kev=i < 24)
                        for i in range(99)]  # 24 KEV + 75 others: keep 60, disclose 15 omitted.
    return ctx


def badge_overlaps(text):
    """Check rendered glyphs, not template source, for obscured provenance badges."""
    boxes = [text.get_charbox(i) for i in range(text.count_chars())]
    overlaps = []
    for label in ("MACHINE-DERIVED", "MANUFACTURER-ATTESTED", "INPUT REQUIRED"):
        search = text.search(label, match_case=True)
        while found := search.get_next():
            start, count = found
            own = boxes[start:start+count]
            left, bottom = min(b[0] for b in own), min(b[1] for b in own)
            right, top = max(b[2] for b in own), max(b[3] for b in own)
            # Badge glyphs are under 7 pt high, with 5 pt horizontal template padding.
            # Ordinary larger input notices have no badge padding.
            if top - bottom < 7:
                left -= 5
                right += 5
            for i, (l, b, r, t) in enumerate(boxes):
                if start <= i < start+count or r <= l or t <= b:
                    continue
                if min(right, r) - max(left, l) > 0.5 and min(top, t) - max(bottom, b) > 0.5:
                    overlaps.append(label)
                    break
        search.close()
    return overlaps


@real
@pytest.mark.parametrize("scenario", ["normal", "blocked", "missing", "long_text", "long_tables"])
def test_render_corpus(ctx, tmp_path, scenario):
    import pypdfium2 as pdfium

    configure_corpus(ctx, scenario)
    list(dossier.run(ctx))
    data = json.loads(ctx.path("dossier.json").read_text(encoding="utf-8"))
    if scenario == "long_tables":
        assert len(data["other_rows"]) == 60 and data["other_rows_truncated"] == 15
    pdfs = sorted(ctx.run_dir.glob("*.pdf"))
    assert len(pdfs) == 3
    render_dir = tmp_path / "renders"
    render_dir.mkdir()
    failures, evidence = [], []
    for pdf in pdfs:
        report = json.loads((ctx.path("pdf-validation") / f"{pdf.stem}.validation.json").read_text())
        assert report["compliant"]
        texts = []
        with pdfium.PdfDocument(pdf) as document:
            for index in range(len(document)):
                page = document[index]
                width, height = page.get_size()
                text = page.get_textpage()
                content = text.get_text_range()
                texts.append(content)
                outside = []
                for i in range(text.count_chars()):
                    left, bottom, right, top = text.get_charbox(i)
                    if left < -1 or bottom < -1 or right > width + 1 or top > height + 1:
                        outside.append(i)
                if outside:
                    failures.append(f"{pdf.name} page {index+1}: {len(outside)} characters outside page")
                if pdf.name.startswith("AnnexVII") and badge_overlaps(text):
                    failures.append(f"{pdf.name} page {index+1}: overlapping badge text")
                if pdf.name != "Simplified_EU_Declaration_of_Conformity.pdf":
                    assert f"{index+1} / {len(document)}" in content
                bitmap = page.render(scale=1.5)
                image = bitmap.to_pil()
                image.save(render_dir / f"{pdf.stem}-{index+1:03}.png")
                image.close()
                bitmap.close()
                text.close()
                page.close()
            evidence.append({"pdf": pdf.name, "sha256": sha256_file(pdf), "pages": len(document)})
        combined = " ".join(texts)
        if scenario == "blocked" and pdf.name == "EU_Declaration_of_Conformity.pdf":
            assert "NOT VALID FOR SIGNATURE" in combined
        if scenario == "missing":
            assert "INPUT" in combined
        if scenario == "long_tables" and pdf.name.startswith("AnnexVII"):
            assert "15 further findings omitted" in combined
    (render_dir / "layout.json").write_text(json.dumps({"documents": evidence, "failures": failures}, indent=2))
    assert not failures, failures  # Geometry is a regression check, not a substitute for visual review.


@real
def test_real_directory_cli(directory_checker, tmp_path):
    import typst

    source = tmp_path / "exports"
    for name in ("one/report.pdf", "two/report.PDF"):
        pdf = source / name
        pdf.parent.mkdir(parents=True)
        pdf.write_bytes(typst.compile(b'Valid archival PDF', pdf_standards=["a-2b"]))
    before = {p: sha256_file(p) for p in source.rglob("*") if p.is_file()}
    command = [sys.executable, str(ROOT / "tools/validate_pdfs.py"), str(source), "--reports"]
    passed = subprocess.run(command + [str(tmp_path / "passed")], capture_output=True, text=True, timeout=90)
    assert passed.returncode == 0, passed.stdout + passed.stderr
    (source / "bad.pdf").write_bytes(b"invalid PDF")
    before[source / "bad.pdf"] = sha256_file(source / "bad.pdf")
    failed = subprocess.run(command + [str(tmp_path / "failed")], capture_output=True, text=True, timeout=90)
    assert failed.returncode == 1, failed.stdout + failed.stderr
    summary = json.loads((tmp_path / "failed/summary.json").read_text())
    assert summary["total"] == 3 and summary["passed"] == 2
    assert {p: sha256_file(p) for p in source.rglob("*") if p.is_file()} == before
