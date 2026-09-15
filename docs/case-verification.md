# Case workflow verification — 2026-09-08

Branch: `yaheli-case-workflow`. Cards 05 → 11 → 14 → 15 → 16 → 17.

| Card | Commit | Focused result |
| --- | --- | --- |
| 05 | 775de05 | 34 passed: storage, migrations, rollback, retries, concurrent updates, API/CLI |
| 11 | f2f33cd | 21 passed: factual dates, corrections, immutable history, approval invalidation |
| 14 | 8c55645 | 22 passed: reviewed vulnerability stages and persistent clocks |
| 15 | 6153d2b | 26 passed: incident intake, coexistence, calendar months and restart |
| 16 | 230002d | 35 passed: glossary fields, conditional inputs, readiness and exports |
| 17 | This commit | See final regression command below and Trello completion evidence |

Final regression command (from repository root):

```powershell
.venv/Scripts/python.exe -m pytest -m "not slow" -q -p no:cacheprovider --basetemp workspace/tmp/case-delivery-check
```

Slow tests requiring external bootstrap/network are excluded explicitly. Existing
FastAPI/Starlette dependency deprecation warnings are unchanged.
Final result: **164 passed, 10 deselected, 2 warnings** in 18.68 seconds.

Browser smoke test used an isolated database under `workspace/tmp/case-ui-smoke/data`
and a local server at 127.0.0.1:8769. All test activity was simulated:

- Opened the Cases page and verified incident-specific display and rehearsal labels.
- Edited a report through glossary-generated fields; previous approval became invalid.
- Approved the exact new revision and recorded a simulated submission.
- Restarted the server; events, submitted status and revisions persisted.
- Created a sealed snapshot through the UI; its download link appeared.
- A second stale tab failed with a version conflict, retained input, and recovered
  after refreshing. No duplicate snapshot was created by the rejected action.
- Inspected rendered layout, conditional form fields and browser console (no errors).

Automated lifecycle tests exercise both case types through both public adapters,
including reviewed report preparation, submission, receipt, amendment, fresh
approval, snapshot creation and restart. ZIP tests verify the existing evidence
ledger/signature, receipt digests and unchanged original scan bytes. These are
local integrity checks, not a claim of externally trusted signer verification.
