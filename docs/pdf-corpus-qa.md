# PDF corpus and export checks â€” card 13

Run from the repository root with PandaX installed in the active Python
environment. [Set up the pinned validator first](pdfa-validation.md).

```powershell
python tools/validate_pdfs.py "out/final-exports" --reports ".cache/final-export-pdf-check"
```

The command recursively checks every `.pdf` (case-insensitive) using the existing
PDF/A-2b validator. Exit 0 means at least one PDF was found and all PDFs passed;
exit 1 means failure, including empty/missing input, inaccessible directories,
missing tools or invalid PDFs. `--verapdf PATH` optionally selects the standard
launcher or pinned CLI jar. Extract ZIP exports to a folder before checking.

Use a **new report directory outside the input tree** on each run. The command
does not edit input PDFs or add files to a signed bundle. It refuses overlapping
input/report directories, existing report destinations and symbolic links/reparse points
(including Windows junctions), instead of following links or silently omitting
parts of an export. Keep exported folders unchanged during the check.

`summary.json` records the overall result and each PDF's relative path, hash,
status and diagnostic/report location. If evidence cannot be written, report
locations are null; an unreadable input also has a null hash. Expected validator
version/digest and UTC check time are recorded; actual validator provenance is
reported per PDF only when verified. Detailed evidence lives under
`files/<sequence number>/`, so different exports with the same PDF name
cannot overwrite each other's reports. A passing format check is separate from
signature verification and visual/legal review. Case exports currently contain
HTML/JSON; a directory without PDFs fails visibly rather than implying coverage.

## Reproduce the render corpus

The render dependencies are test-only; the validator command needs no new Python
dependency beyond the engine. Versions used for this check:

```powershell
python -m pip install pypdfium2==5.13.0 Pillow==12.3.0
$env:PANDAX_PDFA_INTEGRATION = '1'
python -m pytest apps/engine/tests/test_pdf_corpus.py -q --basetemp .cache/pdf-corpus-qa
```

Use a disposable `--basetemp`: pytest clears it before running. Fixture definitions
are in `apps/engine/tests/test_pdf_corpus.py`, using production dossier assembly:

| Scenario | Coverage |
| --- | --- |
| Normal | Standard manufacturer data, no findings |
| Blocked | Known-exploited finding and the full declaration's blocking notice |
| Missing | Absent manufacturer metadata, URL and SBOM hash; input-required notices |
| Long text | Long product/manufacturer names, address, purpose and a long URL token |
| Long tables | 24 synthetic KEV rows and 75 other findings; 60 displayed and 15 disclosed as omitted |

Every scenario generates all three document types: Annex VII technical
documentation, Annex V full declaration and Annex VI simplified declaration.
The test retains PDFs and raw veraPDF evidence under each `run-test` directory,
plus PNGs for **every page** and `layout.json` under its sibling `renders` folder.
It checks page boundaries, provenance-badge overlap, page numbers and key notices.
Geometry checks supplement human/model visual inspection; they do not certify
readability on their own.

Inspect every PNG for clipping, overlap, readable notices, repeated table headers
and correct pagination. Keep the PDFs/raw evidence and record the renderer/tool
versions and actual results with the handoff to Eden. Only layout fixes belong
here; semantic findings belong to Yaheli.

## Findings and boundaries

- Fixed a compilation failure when the full declaration tried to slice 32
  characters from an empty SBOM digest.
- Added space between Annex VII entry titles and their provenance badges, and
  between long footer text and page numbers. The overlap test detects the
  pre-fix badge defect in the long-text fixture.
- Kept full-declaration item headings with their following text across page
  breaks. Existing `"1 / 1"` numbering was already a dynamic Typst pattern,
  confirmed in rendered multi-page PDFs; it was not replaced.
- Preserved the 60-row cap, omission notice, reporting field definitions and
  signing behavior.

Semantic handoff for Yaheli: in the existing blocked scenario, the full declaration
shows its blocking notice while the simplified declaration still prints its
unconditional conformity sentence. This predates card 13 and is not changed by
these layout fixes. Passing PDF/A and visual checks does not resolve that content
question or authorize issuing either declaration.


## Verification record — 2026-09-13

- Latest main incorporated: `4e55b2d` (PR 20). Work remains on `simon-pdfa`.
- Corpus/command tests after review fixes: **17 passed**, including a real
  Windows junction rejection and valid/invalid PDF CLI subprocesses.
- **15/15 PDFs** passed veraPDF 1.30.2 in both dossier generation and a separate
  recursive directory run. Inspected **all 38 rendered pages** across five
  scenarios; no clipping or badge/footer overlaps remained. Table headers,
  omission notice and current/total pagination were readable.
- Tools: Python 3.12, Typst 0.15.0, veraPDF 1.30.2, pypdfium2 5.13.0,
  Pillow 12.3.0. The badge regression was also checked against the pre-fix
  long-text render and detects its overlap.
- Broader suite before review refinements: **391 passed, nine setup errors**.
  All nine were firmware integration tests requiring Docker. Docker Desktop
  failed during startup because its secrets-engine socket was inaccessible;
  those tests remain unverified in this run. No factory reset was attempted.
- Local evidence: `.cache/card13-reviewed`, `.cache/card13-full.xml`,
  `.cache/card13-visual-final`, `.cache/card13-corpus-validation` and
  `.cache/card13-claude`. Generated PDFs and review output are kept outside Git.

- Claude Opus independently reviewed the changes twice. Addressed failure-record
  consistency, short report paths, provenance, real junction coverage and input
  immutability assertions; the follow-up reported **no blockers**. Existing
  pipeline tests already cover refusing to seal on validation failure. The link
  policy also rejects OneDrive reparse placeholders; use a regular local export
  directory for validation.
