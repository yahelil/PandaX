# Dossier PDF validation (card 10)

Generation now requires every dossier PDF to pass veraPDF's explicit PDF/A-2b
profile before the pipeline seals its bundle. A successful Typst compilation or
validator exit code alone is insufficient. Compilation errors, missing Java or
veraPDF, a 60-second timeout per PDF, malformed reports, unexpected versions,
wrong profiles and noncompliance all stop sealing. Other stages can start without
veraPDF; no download happens during a scan.

## Local setup

Install Java and make `java` available on PATH, then run from the repository root:

```powershell
python tools/setup_verapdf.py
```

The setup uses the official [veraPDF 1.30.2 installer](https://software.verapdf.org/releases/1.30/)
and checks its SHA-256 before executing it:
`6cc6341cb1af644044054b81f00a6590a7918abb18f762243de115258bcad838`.
Before every validation, the engine also checks the installed CLI jar against
SHA-256 `889075253fb9df4db5482efb8f8208fb3b4f2e00f5f7e1b1e31edf6fb4b69bb6`;
the verified digest is recorded in the validation JSON.
Installation follows veraPDF's [automated installation procedure](https://docs.verapdf.org/install/)
and writes to `.tools/verapdf`. An existing directory is never overwritten;
move it aside explicitly if a reinstall is needed.

The runner accepts `PANDAX_VERAPDF` pointing to a standard `verapdf`/
`verapdf.bat` launcher or the installed `bin/cli-1.30.2.jar`. Otherwise it looks
on PATH, then in `.tools/verapdf`. An explicit selection or PATH installation
with the wrong version fails; it does not silently fall back. Example:

```powershell
$env:PANDAX_VERAPDF = "$PWD/.tools/verapdf/verapdf.bat"
```

For the separately owned preflight command, use its `--verapdf` option with the
launcher, or add `.tools/verapdf` to PATH. No preflight files are changed here.
The engine executes the launcher's adjacent pinned CLI jar directly through Java,
using argument arrays and no shell. Paths containing spaces or shell characters
stay literal, and a timeout terminates Java itself. Custom wrapper scripts are
not executed. Java and veraPDF must be installed in the environment running the
engine, including a container if generation runs there.

## Evidence and failures

Each run retains `pdf-validation/<PDF stem>.xml`, `.stderr.txt`, and
`.validation.json`. The JSON records the input hash, requested profile, expected
version, verified version on success, command, exit code and error. Compilation
failures retain `.compile.txt` instead. All three dossier PDFs are attempted so
the failed run contains diagnostics for the complete batch.

Successful runs include the reports in the existing ledger and signed manifest,
and record `verapdf: 1.30.2` in tool versions. Failed runs retain their diagnostics
and ledger but produce no completed signed bundle. This checks the PDF format;
it does not certify legal compliance or approve manufacturer assertions.

## Checks

```powershell
python -m pytest apps/engine/tests/test_pdfa.py -q
$env:PANDAX_PDFA_INTEGRATION = '1'
python -m pytest apps/engine/tests/test_pdfa.py -q
```

The opt-in checks run real veraPDF against compliant, ordinary and malformed
PDFs, then generate and verify signed bundles from CycloneDX and SPDX SBOMs with
offline feed fixtures. The existing end-to-end suite also exercises real artifact
ingestion and real feeds. The later card 13 owns exhaustive corpus/layout stress
tests, visual review and the directory-wide validation command.

Verified locally on 2026-09-10 with Windows, Java 25.0.1, Typst 0.15.0 and
veraPDF 1.30.2: the full suite passed **352 tests, zero skipped**, with both
`PANDAX_PDFA_INTEGRATION=1` and `PANDAX_FIRMWARE_INTEGRATION=1`. This included
real Docker extraction, the artifact/real-feed end-to-end run, both SBOM formats,
and mixed batches where one compilation or validation failure prevents sealing.
The setup script was also run against a fresh local installation directory;
the archive digest and installed version both matched. Linux/macOS setup has
not been exercised in this check.

Claude Opus independently reviewed the implementation and reported no blockers.
Its binary-provenance suggestion led to the runtime jar digest check above;
executable-discovery tests, stable failure fields and an exact setup version
check were also added. Its ledger warning was inapplicable: compiled PDFs are
already added to outputs before validation. Its suggested PDF-mutation,
report-size/DTD and mismatched-file checks were already covered. Raw upstream
reports retain local paths by design, so command paths are retained as provenance
too. The configured Fable model required credits and Sonnet timed out; the Opus
review completed successfully.
