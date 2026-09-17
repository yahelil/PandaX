#let report = json("report.json")
#let subject = report.subject
#let summary = report.summary
#let missing(value) = if value == none or value == "" { "Not recorded" } else { str(value) }

#set document(title: "Product release security report", author: "Actis by PandaX")
#set page(paper: "a4", margin: (x: 1.9cm, top: 2cm, bottom: 1.8cm), numbering: "1 / 1")
#set text(size: 9.5pt, lang: "en")
#set par(leading: 0.65em)
#show heading.where(level: 1): it => block(above: 16pt, below: 8pt)[
  #set text(size: 14pt, weight: "bold", fill: rgb("#10254c"))
  #it.body
]
#show heading.where(level: 2): it => block(above: 11pt, below: 5pt)[
  #set text(size: 11pt, weight: "bold", fill: rgb("#10254c"))
  #it.body
]

#text(size: 20pt, weight: "bold", fill: rgb("#10254c"))[Product release security report]

#v(5pt)
#text(fill: rgb("#52627d"))[Product: #missing(subject.product_name)  |  Release: #missing(subject.release_version)]

Generated #report.generated_at. Product ID #subject.product_id. Release ID #subject.release_id.

Product identifier: #missing(subject.product_identifier). Manufacturer: #missing(subject.manufacturer).
CRA classification recorded: #missing(subject.cra_class).

#rect(fill: rgb("#edf3ff"), inset: 11pt, radius: 4pt)[
  *Assessment record.* This report records observed software findings, human decisions,
  remediation, and monitoring coverage for this release. It is not a declaration of
  conformity, regulatory filing, or certification.
]

= Summary

#table(
  columns: (1fr, 1fr),
  inset: 7pt,
  [Total findings], [#summary.total],
  [Awaiting review], [#summary.awaiting_decision],
  [Known exploited], [#summary.known_exploited],
  [Monitoring configured], [#report.coverage.monitored],
)

= Evidence and coverage

#if report.coverage.monitored [
  Monitoring health: #missing(report.coverage.health).
  Sources: #report.coverage.sources.join(", ").
  Last check: #missing(report.coverage.last_check_at).
  Limitations: #if report.coverage.limitations.len() == 0 { "None recorded" } else { report.coverage.limitations.join("; ") }.
] else [
  #report.coverage.reason
]

= Findings and decisions

#if report.findings.len() == 0 [No findings are recorded for this release.] else [
  #for finding in report.findings [
    == #finding.reference_id: #finding.title

    #finding.description

    *Component:* #missing(finding.component) #missing(finding.component_version) \
    *Package URL:* #missing(finding.purl) \
    *Severity:* #finding.severity  |  *CVSS:* #missing(finding.cvss)  |  *Known exploited:* #finding.known_exploited \
    *EPSS:* #missing(finding.epss)  |  *Reachability:* #finding.reachability  |  *Source:* #missing(finding.source) \
    *Status:* #finding.status  |  *Decision:* #missing(finding.decision)

    *Decision rationale:* #missing(finding.decision_rationale)

    *Remediation:* #finding.remediation_status. #missing(finding.remediation_plan) \
    *Target date:* #missing(finding.remediation_due_date)  |  *Verification evidence items:* #finding.verification_evidence_count

    *First observed:* #missing(finding.first_seen_at)  |  *Last observed:* #missing(finding.last_seen_at)
  ]
]

= Limitations and next steps

#if summary.awaiting_decision > 0 [
  #summary.awaiting_decision finding(s) still require a human decision.
]
An SBOM identifies software components. It does not by itself provide product design,
manufacturer attestations, runtime reachability, or proof that corrective measures
were verified. Review the technical documentation and declaration separately.
