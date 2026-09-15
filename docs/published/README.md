# Published PandaX artifacts

These are committed snapshots of validation results, PDFs, review packages,
videos, and presentations. They are kept for review and historical context.
Running the engine or the review helpers writes new files under the ignored
`workspace/` folder; publishing a new snapshot requires copying the chosen
files here and reviewing the resulting Git changes.

Historical reports and JSON records describe the paths used when their runs
were made. Existing local run bundles were moved to `workspace/runs/`; the
review helpers resolve the older `out/` path recorded by those reports.
