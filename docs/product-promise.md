# Actis by PandaX product promise

Actis turns product artifacts and SBOMs that a customer is authorized to use
into traceable vulnerability findings, reviewable Cyber Resilience Act (CRA)
workflows, and independently verifiable evidence packages.

Actis helps a manufacturer understand what was found, where it came from, what
still needs human input, and whether the resulting evidence has changed. The
scanner collects and derives evidence, the hosted application supports review
and workflow, and the standalone verifier checks a copied package offline.

## Boundaries and non-goals

- Actis does not certify CRA compliance, provide legal advice, submit filings,
  or replace the manufacturer's accountable decision-makers.
- A finding is not proof that a product is exploitable. Absence of a finding is
  not proof that a product is secure.
- Automation may preserve evidence and identify exact affected matches. It does
  not automatically make a risk-reducing VEX conclusion such as
  `not_affected`; those conclusions require named review and supporting evidence.
- The evidence seal proves integrity. An Ed25519 signature verified with a
  separately obtained public key ties a package to that approved signing key,
  not to a legal person and not to an eIDAS-qualified seal.
- The private beta is pre-production. It does not promise a production SLA,
  strict EU-only residency, managed key custody, or fully automatic compliance.

## Component responsibilities

| Component | Does | Does not do |
|---|---|---|
| Actis Collector/scanner | Runs customer-side collection and heavy artifact, SBOM, firmware, container, and reachability analysis; emits minimized evidence. | Execute untrusted product content, send private signing keys to PandaX, or decide legal compliance. |
| Hosted Actis | Stores minimized evidence and public trust material; supports tenant-scoped review, audit, and CRA workflow. | Act as the independent trust anchor, store customer private signing keys, or turn a scanner result into an automatic compliance claim. |
| Standalone verifier | Reads a folder or ZIP offline; verifies v1 structure, digests, ledger chain, bundled signature, and an externally supplied Ed25519 public key. | Scan products, contact Actis, infer signer identity, assess vulnerability severity, or decide CRA compliance. |

The stable evidence-package contract shared by these components is defined in
[Evidence bundle format v1](evidence-format-v1.md).
