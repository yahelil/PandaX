"""Pinned veraPDF validation. Invoked only when generating dossier PDFs."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from .context import TOOLS_DIR
from .evidence import sha256_file

VERSION = "1.30.2"
# CLI jar inside the digest-verified official installer in tools/setup_verapdf.py.
JAR_SHA256 = "889075253fb9df4db5482efb8f8208fb3b4f2e00f5f7e1b1e31edf6fb4b69bb6"
PROFILE = "PDF/A-2b validation profile"


def validator_command(executable: str | Path | None = None) -> list[str]:
    """Accept the standard launcher or CLI jar; run Java directly, without a shell.

    This also makes timeouts kill the validator itself, not a batch-file parent.
    """
    configured = executable or os.environ.get("PANDAX_VERAPDF")
    if configured:
        launcher = Path(shutil.which(str(configured)) or configured).resolve()
    else:
        found = shutil.which("verapdf") or shutil.which("verapdf.bat")
        # Only the parent matters: the launcher is not executed, even on POSIX.
        launcher = Path(found) if found else TOOLS_DIR / "verapdf" / "verapdf.bat"
    jar = launcher if launcher.suffix.lower() == ".jar" else launcher.resolve().parent / "bin" / f"cli-{VERSION}.jar"
    if not jar.is_file():
        raise FileNotFoundError(
            f"veraPDF {VERSION} CLI jar not found beside {launcher}. "
            "Run python tools/setup_verapdf.py or set PANDAX_VERAPDF to its launcher/CLI jar."
        )
    if sha256_file(jar) != JAR_SHA256:
        raise ValueError(f"veraPDF CLI jar digest mismatch: {jar}; reinstall the pinned distribution")
    java = shutil.which("java")
    if not java:
        raise FileNotFoundError("Java is required for veraPDF; install Java and add it to PATH")
    return [java, "-Dfile.encoding=UTF-8", "-jar", str(jar)]


def _read_report(raw: bytes, pdf: Path) -> str:
    if len(raw) > 16 * 1024 * 1024 or b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise ValueError("unsafe or oversized veraPDF report")
    root = ET.fromstring(raw)
    if root.tag != "report":
        raise ValueError("expected a veraPDF report")
    versions = {e.get("id"): e.get("version") for e in root.findall("buildInformation/releaseDetails")}
    if any(versions.get(part) != VERSION for part in ("core", "validation-model", "apps")):
        raise ValueError(f"expected veraPDF {VERSION}, report contains {versions}")
    jobs = root.findall("jobs/job")
    if len(jobs) != 1:
        raise ValueError("expected exactly one validation job")
    job = jobs[0]
    if Path(job.findtext("item/name", "")).resolve() != pdf.resolve():
        raise ValueError("veraPDF report refers to a different PDF")
    reports = job.findall("validationReport")
    if len(reports) != 1:
        raise ValueError("missing or ambiguous validation result")
    report = reports[0]
    if report.get("profileName") != PROFILE or report.get("jobEndStatus") != "normal":
        raise ValueError("wrong validation profile or incomplete validation")
    details = report.find("details")
    batch = root.find("batchSummary")
    totals = root.find("batchSummary/validationReports")
    if (report.get("isCompliant") != "true" or details is None
            or any(details.get(k) != "0" for k in ("failedRules", "failedChecks"))
            or batch is None or batch.get("totalJobs") != "1"
            or any(batch.get(k) != "0" for k in ("failedToParse", "encrypted", "outOfMemory", "veraExceptions"))
            or totals is None or totals.get("compliant") != "1"
            or totals.get("nonCompliant") != "0" or totals.get("failedJobs") != "0"):
        raise ValueError("PDF/A-2b validation failed; see the raw veraPDF report")
    return VERSION


def validate_pdf(pdf: Path, report_dir: Path, *, executable: str | Path | None = None,
                 timeout: float = 60) -> dict:
    """Persist diagnostics on success AND failure; never infer compliance from exit 0."""
    pdf = pdf.resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    raw_path = report_dir / f"{pdf.stem}.xml"
    stderr_path = report_dir / f"{pdf.stem}.stderr.txt"
    result = {"pdf": pdf.name, "sha256": None, "profile": "2b",
              "expected_version": VERSION, "validator_version": None,
              "validator_sha256": None, "command": None,
              "compliant": False, "error": None, "returncode": None,
              "report": raw_path.name, "stderr": stderr_path.name}
    with raw_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        try:
            result["sha256"] = sha256_file(pdf)
            command = validator_command(executable)
            result["validator_sha256"] = JAR_SHA256  # verified by validator_command
            result["command"] = command + ["--format", "xml", "--flavour", "2b",
                                            "--maxfailuresdisplayed", "10", str(pdf)]
            completed = subprocess.run(result["command"], stdout=stdout, stderr=stderr,
                                       timeout=timeout, check=False)
            result["returncode"] = completed.returncode
            stdout.flush()
            if completed.returncode != 0:
                raise ValueError(f"veraPDF exited with code {completed.returncode}")
            with raw_path.open("rb") as report:
                result["validator_version"] = _read_report(report.read(16 * 1024 * 1024 + 1), pdf)
            if sha256_file(pdf) != result["sha256"]:
                raise ValueError("PDF changed during validation")
            result["compliant"] = True
        except (OSError, ValueError, ET.ParseError, subprocess.TimeoutExpired) as exc:
            result["error"] = str(exc)
    (report_dir / f"{pdf.stem}.validation.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8")
    return result
