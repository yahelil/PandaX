"""Read-only recursive PDF/A-2b check; write evidence to a new, separate folder."""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
from datetime import datetime, timezone

from pandax.pdfa import JAR_SHA256, VERSION, validate_pdf
from pandax.evidence import sha256_file


def validate_directory(source: Path, reports: Path, *, executable: str | Path | None = None) -> dict:
    source, reports = source.resolve(), reports.resolve()
    if not source.is_dir():
        raise ValueError(f"Input must be a directory: {source}")
    if reports.is_relative_to(source) or source.is_relative_to(reports):
        raise ValueError("Input and report directories must be separate, not nested")
    if reports.exists():
        raise ValueError("Report directory already exists; choose a new directory for this run")

    def walk_error(error):
        raise error

    pdfs = []
    for folder, directories, files in os.walk(source, onerror=walk_error, followlinks=False):
        for name in directories + files:
            path = Path(folder) / name
            # Includes Windows junctions on Python 3.10/3.11 (before Path.is_junction).
            if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                raise ValueError(f"Linked entries are not supported: {path}")
        pdfs.extend(Path(folder) / name for name in files if Path(name).suffix.lower() == ".pdf")

    reports.mkdir(parents=True)
    results = []
    for index, pdf in enumerate(sorted(pdfs), start=1):
        relative = pdf.relative_to(source)
        # Short numbered directories avoid duplicate-name collisions and deep paths.
        destination = reports / "files" / f"{index:06d}"
        result = {"pdf": pdf.name, "sha256": None, "profile": "2b",
                  "expected_version": VERSION, "validator_version": None,
                  "validator_sha256": None, "command": None, "compliant": False,
                  "error": None, "returncode": None, "report": None, "stderr": None}
        try:
            result["sha256"] = sha256_file(pdf)
            result.update(validate_pdf(pdf, destination, executable=executable))
        except (OSError, ValueError) as exc:
            result["error"] = str(exc)
        result["input_path"] = relative.as_posix()
        result["report_directory"] = destination.relative_to(reports).as_posix() if destination.is_dir() else None
        results.append(result)
        print(f"{'PASS' if result['compliant'] else 'FAIL'} {relative.as_posix()!r}")
        if result.get("error"):
            print(f"  {result['error']}")
    summary = {"input_directory": str(source), "profile": "2b", "total": len(results),
               "expected_validator_version": VERSION, "expected_validator_sha256": JAR_SHA256,
               "checked_at": datetime.now(timezone.utc).isoformat(),
               "passed": sum(r["compliant"] for r in results),
               "compliant": bool(results) and all(r["compliant"] for r in results),
               "results": results}
    (reports / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--reports", type=Path, required=True, help="new directory outside the input tree")
    parser.add_argument("--verapdf", help="standard veraPDF launcher or pinned CLI jar")
    args = parser.parse_args(argv)
    try:
        summary = validate_directory(args.directory, args.reports, executable=args.verapdf)
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}")
        return 1
    if not summary["total"]:
        print("FAIL: no PDFs found")
    print(f"{summary['passed']}/{summary['total']} PDFs passed; evidence: {args.reports}")
    return 0 if summary["compliant"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
