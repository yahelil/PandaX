# PandaX Compliance Evidence

PandaX turns product-security observations and manufacturer attestations into reviewable Cyber Resilience Act evidence without modifying products or submitting reports.

## Language

**Finding**:
A vulnerability reported by a named checked source for an identified product component.
_Avoid_: Proven exploitability, confirmed product impact

**Candidate resolution**:
A machine-observed change suggesting that a finding may have been addressed, while retaining coverage limits and requiring manufacturer review.
_Avoid_: Patched, fixed, resolved

**Measure confirmation**:
A named manufacturer operator's attestation that a corrective or mitigating measure is available for the affected product.
_Avoid_: Automatic remediation, inferred availability

**Measure availability time**:
The confirmed time at which users could obtain or apply the corrective or mitigating measure for the affected product.
_Avoid_: Upstream release date, scan time, detection time

**Final-report deadline**:
The measure availability time plus 14 calendar days for an actively exploited vulnerability report.
_Avoid_: Vulnerability date plus 14 days

**Checked-source absence**:
No matching finding was returned for the release by the sources and coverage recorded for that scan.
_Avoid_: Clean, vulnerability-free

**Remediation case**:
The durable history joining an original finding, later release observations, manufacturer decisions, deadlines, and report revisions.
_Avoid_: Mutable scan bundle
