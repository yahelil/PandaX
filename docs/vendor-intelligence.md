# Vendor advisories and backported fixes

Generic vulnerability feeds usually compare an upstream software version with
an affected version range. Linux and device vendors often repair that software
by adding a patch to their own package while keeping the upstream version
number. Without the full vendor revision, a repaired package can therefore look
vulnerable.

PandaX handles this with an installation-wide, reviewed catalogue. The
deployment's authorized security curator prepares the catalogue from official
vendor notices, validates it, and installs it:

```powershell
actis advisory validate .\vendor-intelligence.json
actis advisory install .\vendor-intelligence.json
actis advisory status
```

Start with [the example catalogue](vendor-intelligence-example.json), but do not
use its fictional decision as real evidence.

## Safety rules

- Every decision names one CVE and one exact, versioned Package URL.
- A backport records the upstream version, complete vendor revision, vendor
  notice, patch or changelog reference, retrieval time, and human review.
- Source and review dates are mandatory. Vendor and patch addresses must use
  HTTPS.
- Package-name matching and guessed version ranges are not allowed.
- One catalogue cannot contain two decisions for the same CVE and package URL.
- A fixed or not-affected vendor decision can supersede a generic-feed finding,
  but PandaX preserves that prior finding and explains the source precedence.
- An affectedness decision never proves runtime reachability or reportability.

## Evidence in each scan

When a catalogue is installed, every signed run includes its normalized
snapshot, exact-package assessments, and any generic findings it superseded:

- `vendor-intelligence.json`
- `vendor-assessments.json`
- `vendor-superseded-findings.json`

The vulnerability coverage view also shows the selected vendor decision,
reviewer, backport details, and conflicting source statements. If no catalogue
is installed, the existing OSV and bounded native-advisory behavior is unchanged.

Installing or replacing the catalogue is an administrator operation. Ordinary
scan and report reviewers do not choose a catalogue for an individual scan.
