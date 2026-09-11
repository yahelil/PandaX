# Native curl and OpenSSL advisory coverage

PandaX can make a reliable vulnerability decision only when it knows both what
software was found and where that software came from. For the curl and OpenSSL
release scenarios, PandaX first checks the downloaded file against the approved
SHA-256 fingerprint for that official release. It then applies a reviewed vendor
advisory to that exact project and version.

This prevents a folder that merely calls itself `curl-8.3.0`, a repackaged copy,
or an unrelated distribution package from receiving an upstream curl verdict.

## Included decisions

The current catalogue covers these selected release boundaries:

| Project | Advisory | Affected releases in the catalogue | Fixed releases in the catalogue |
|---|---|---|---|
| curl | CVE-2023-38545 | 8.3.0 | 8.4.0, 8.5.0 |
| curl | CVE-2023-38546 | 8.3.0 | 8.4.0, 8.5.0 |
| curl | CVE-2023-46218 | 8.3.0, 8.4.0 | 8.5.0 |
| OpenSSL | CVE-2014-0160 | 1.0.1f | 1.0.1g, 1.0.1h |
| OpenSSL | CVE-2014-0224 | 1.0.1f, 1.0.1g | 1.0.1h |
| OpenSSL | CVE-2014-0195 | 1.0.1f, 1.0.1g | 1.0.1h |

These rows are a reviewed set for PandaX's release scenarios. They are not a
promise that every curl or OpenSSL vulnerability is covered. A release outside
the listed boundaries remains **unknown** until its advisory evidence is added
and reviewed.

## Which source wins

PandaX follows this order:

1. For a Linux distribution package, the applicable distribution advisory and
   its complete package revision take priority because the distribution may
   have backported a fix without changing the upstream version number.
2. For a fingerprint-verified official upstream release, the official curl or
   OpenSSL advisory takes priority.
3. Converted or inferred database ranges may provide useful context, but they
   cannot silently override the applicable vendor source.

If sources disagree, PandaX stores both statements, their addresses, retrieval
times, and the reason for the selected decision in the evidence bundle. For
example, the recorded OSV range conflict for curl 8.4.0 and CVE-2023-38546 is
retained even though the official curl advisory identifies 8.4.0 as fixed.

## Evidence produced

Each run includes:

- `native-advisory-sources.json`, the exact version of the reviewed catalogue;
- `native-assessments.json`, the decision for every covered advisory and the
  evidence supporting it; and
- `coverage.json`, a plain summary of what was checked and whether the result
  was affected, fixed, or still unknown.

These files are added to the run's evidence ledger and signed manifest. They
record the raw advisory statement, source address, retrieval time, release
fingerprint identity, version boundaries, and any conflicting source.

## What the decision does not mean

An **affected** version does not prove that the vulnerable feature can be used
in the customer's product. Build options and runtime configuration still need
separate review. PandaX therefore records product reachability as **not
assessed** and does not turn an affectedness result into a claim of confirmed
exploitation.

OpenWrt packages remain on their distribution-specific rules. PandaX uses their
full package revision where a reviewed OpenWrt advisory exists and does not
apply the curl/OpenSSL upstream release table to those packages.
