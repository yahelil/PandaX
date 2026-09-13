// Annex VII technical documentation, Regulation (EU) 2024/2847.
// Data comes from dossier.json, written beside this file by S6 DOSSIER.

#let data = json("dossier.json")

#set document(title: "CRA Annex VII Technical Documentation", author: "PandaX")
#set page(
  paper: "a4",
  margin: (x: 1.9cm, top: 2cm, bottom: 1.8cm),
  numbering: "1 / 1",
  footer: context [
    #set text(size: 7pt, fill: rgb("#64748b"))
    #line(length: 100%, stroke: 0.4pt + rgb("#e2e8f0"))
    #v(2pt)
    #grid(
      columns: (1fr, auto),
      column-gutter: 10pt,
      align(left)[Annex VII technical documentation · #data.product.name #data.product.version · run #data.run_id],
      align(right)[#counter(page).display("1 / 1", both: true)],
    )
  ],
)
#set text(size: 9.2pt, lang: "en")
#set par(justify: true, leading: 0.62em)

#let ink = rgb("#0f172a")
#let muted = rgb("#64748b")
#let line_c = rgb("#e2e8f0")

#show heading.where(level: 1): it => block(above: 16pt, below: 8pt)[
  #set text(size: 13pt, weight: "bold", fill: ink)
  #it.body
]
#show heading.where(level: 2): it => block(above: 12pt, below: 6pt)[
  #set text(size: 10pt, weight: "bold", fill: ink)
  #it.body
]

#let badge(status) = {
  let spec = if status == "derived" {
    (rgb("#dcfce7"), rgb("#14532d"), "MACHINE-DERIVED")
  } else if status == "attested" {
    (rgb("#dbeafe"), rgb("#1e3a8a"), "MANUFACTURER-ATTESTED")
  } else {
    (rgb("#fee2e2"), rgb("#7f1d1d"), "INPUT REQUIRED")
  }
  box(
    fill: spec.at(0),
    inset: (x: 5pt, y: 2.5pt),
    radius: 2pt,
    text(size: 6.5pt, weight: "bold", fill: spec.at(1), spec.at(2)),
  )
}

#let entry(e) = block(
  above: 9pt,
  below: 2pt,
  width: 100%,
  fill: if e.status == "required_input" { rgb("#fef2f2") } else { white },
  stroke: (left: 2pt + if e.status == "required_input" { rgb("#dc2626") } else { line_c }),
  inset: (left: 8pt, rest: 6pt),
)[
  #grid(
    columns: (1fr, auto),
    column-gutter: 8pt,
    align(left)[
      #text(weight: "bold", size: 9pt)[#e.ref  #h(3pt) #e.title]
    ],
    align(right)[#badge(e.status)],
  )
  #v(3pt)
  #if e.status == "required_input" [
    #text(fill: rgb("#b91c1c"), weight: "bold", size: 9pt)[#e.value]
  ] else [
    #text(fill: ink)[#e.value]
  ]
  #if e.note != "" [
    #v(2pt)
    #text(size: 7.6pt, fill: muted, style: "italic")[Note: #e.note]
  ]
]

// ---------------------------------------------------------------- title page

#block(width: 100%, inset: 0pt)[
  #text(size: 7.5pt, weight: "bold", fill: muted, tracking: 1.2pt)[
    REGULATION (EU) 2024/2847 — CYBER RESILIENCE ACT
  ]
  #v(6pt)
  #text(size: 21pt, weight: "bold", fill: ink)[Annex VII]
  #v(1pt)
  #text(size: 14pt, fill: ink)[Content of the technical documentation]
  #v(10pt)
  #line(length: 100%, stroke: 1.2pt + ink)
]

#v(10pt)

#grid(
  columns: (1fr, 1fr),
  column-gutter: 14pt,
  [
    #text(size: 7.5pt, weight: "bold", fill: muted)[PRODUCT]
    #v(3pt)
    #text(size: 12pt, weight: "bold")[#data.product.name]
    #v(2pt)
    #text(size: 8.6pt, fill: muted)[
      #data.product.type \
      Version #data.product.version · ID #data.product.unique_id \
      Risk tier: #upper(data.product.risk_tier) · #data.product.conformity_route
    ]
  ],
  [
    #text(size: 7.5pt, weight: "bold", fill: muted)[MANUFACTURER]
    #v(3pt)
    #text(size: 12pt, weight: "bold")[#data.manufacturer.legal_name]
    #v(2pt)
    #text(size: 8.6pt, fill: muted)[
      #data.manufacturer.address \
      Generated #data.generated \
      Evidence run #data.run_id
    ]
  ],
)

#v(12pt)

// ------------------------------------------------------------ provenance key

#block(
  width: 100%,
  fill: rgb("#f8fafc"),
  stroke: 0.6pt + line_c,
  radius: 3pt,
  inset: 9pt,
)[
  #text(size: 8.4pt, weight: "bold")[How to read this document]
  #v(4pt)
  #set text(size: 8.2pt)
  Every entry below is labelled with its provenance. Nothing in this dossier is
  inferred or invented: fields that can be neither computed from the product
  artifact nor read from the manufacturer's declared metadata are marked
  #badge("required_input") and must be completed before the technical
  documentation is compliant.
  #v(5pt)
  #grid(
    columns: (auto, 1fr),
    row-gutter: 3pt,
    column-gutter: 7pt,
    badge("derived"), [Computed by the pipeline from the product artifact itself (#data.summary.derived fields).],
    badge("attested"), [Declared by the manufacturer in product metadata (#data.summary.attested fields).],
    badge("required_input"), [Neither available — manufacturer must supply (#data.summary.required_input fields).],
  )
]

#v(10pt)

// -------------------------------------------------------------- key evidence

#block(
  width: 100%,
  fill: if data.summary.actively_exploited > 0 { rgb("#fef2f2") } else { rgb("#f0fdf4") },
  stroke: 0.6pt + if data.summary.actively_exploited > 0 { rgb("#fecaca") } else { rgb("#bbf7d0") },
  radius: 3pt,
  inset: 9pt,
)[
  #text(size: 8.4pt, weight: "bold")[Composition and vulnerability summary]
  #v(5pt)
  #grid(
    columns: (1fr, 1fr, 1fr, 1fr),
    column-gutter: 8pt,
    [
      #text(size: 17pt, weight: "bold")[#data.summary.components] \
      #text(size: 7.4pt, fill: muted)[COMPONENTS \ #data.summary.ecosystems]
    ],
    [
      #text(size: 17pt, weight: "bold")[#data.summary.vulnerabilities] \
      #text(size: 7.4pt, fill: muted)[KNOWN VULNERABILITIES \ #data.summary.by_severity]
    ],
    [
      #text(
        size: 17pt,
        weight: "bold",
        fill: if data.summary.actively_exploited > 0 { rgb("#b91c1c") } else { rgb("#15803d") },
      )[#data.summary.actively_exploited] \
      #text(size: 7.4pt, fill: muted)[ACTIVELY EXPLOITED \ CISA KEV — Art.14 trigger]
    ],
    [
      #text(size: 17pt, weight: "bold", fill: rgb("#b45309"))[#data.summary.required_input] \
      #text(size: 7.4pt, fill: muted)[FIELDS AWAITING \ MANUFACTURER INPUT]
    ],
  )
]

#v(6pt)
#text(size: 7.4pt, fill: muted)[
  SBOM digest (SHA-256): #raw(data.summary.sbom_sha256) \
  VEX digest (SHA-256): #raw(data.summary.vex_sha256)
]

// ------------------------------------------------- actively exploited detail

#if data.kev_rows.len() > 0 [
  #pagebreak()
  = Actively exploited vulnerabilities

  #block(
    width: 100%,
    fill: rgb("#fef2f2"),
    stroke: 0.6pt + rgb("#fecaca"),
    radius: 3pt,
    inset: 9pt,
  )[
    #text(size: 8.6pt, weight: "bold", fill: rgb("#7f1d1d"))[
      Article 14(1) reporting obligation is engaged.
    ]
    #v(3pt)
    #text(size: 8.2pt)[
      The vulnerabilities below appear in the CISA Known Exploited
      Vulnerabilities catalogue. Under Article 14(2) the manufacturer must submit
      an early warning within 24 hours of becoming aware, a vulnerability
      notification within 72 hours, and a final report no later than 14 days
      after a corrective measure is available. Annex I Part I(2)(a) additionally
      requires products to be placed on the market without known exploitable
      vulnerabilities.
    ]
  ]

  #v(8pt)
  #table(
    columns: (auto, 1fr, auto, auto, auto, auto),
    inset: (x: 6pt, y: 5pt),
    stroke: 0.4pt + line_c,
    fill: (_, y) => if y == 0 { rgb("#f1f5f9") } else { white },
    table.header(
      [#text(size: 7.4pt, weight: "bold")[CVE]],
      [#text(size: 7.4pt, weight: "bold")[COMPONENT]],
      [#text(size: 7.4pt, weight: "bold")[SEVERITY]],
      [#text(size: 7.4pt, weight: "bold")[EPSS]],
      [#text(size: 7.4pt, weight: "bold")[KEV SINCE]],
      [#text(size: 7.4pt, weight: "bold")[FIXED IN]],
    ),
    ..data.kev_rows
      .map(r => (
        [#text(size: 8pt, weight: "bold", fill: rgb("#b91c1c"))[#r.cve]],
        [#text(size: 8pt)[#r.component]],
        [#text(size: 8pt)[#r.severity]],
        [#text(size: 8pt)[#r.epss]],
        [#text(size: 8pt)[#r.kev_since]],
        [#text(size: 8pt)[#r.fix]],
      ))
      .flatten(),
  )
]

// ------------------------------------------------------------ the eight items

#pagebreak()
= Technical documentation

#text(size: 8.3pt, fill: muted)[
  Annex VII requires the technical documentation to contain at least the
  following information, as applicable to the relevant product with digital
  elements. Item numbering below follows the Regulation exactly.
]

#for section in data.annex_vii [
  == Item #section.item — #section.title
  #for e in section.entries [ #entry(e) ]
]

// ------------------------------------------------------------ other findings

#if data.other_rows.len() > 0 [
  #pagebreak()
  = Annex to item 6 — full vulnerability register

  #text(size: 8.3pt, fill: muted)[
    Known vulnerabilities not listed in the CISA KEV catalogue. These are
    recorded as #raw("in_triage") in the accompanying CycloneDX VEX document. No
    #raw("not_affected") determination is asserted: this pipeline performs no
    reachability analysis, and an unfounded suppression would misrepresent
    conformity.
  ]

  #v(7pt)
  #table(
    columns: (auto, 1fr, auto, auto, auto),
    inset: (x: 6pt, y: 4pt),
    stroke: 0.4pt + line_c,
    fill: (_, y) => if y == 0 { rgb("#f1f5f9") } else { white },
    table.header(
      [#text(size: 7.4pt, weight: "bold")[CVE]],
      [#text(size: 7.4pt, weight: "bold")[COMPONENT]],
      [#text(size: 7.4pt, weight: "bold")[SEVERITY]],
      [#text(size: 7.4pt, weight: "bold")[EPSS]],
      [#text(size: 7.4pt, weight: "bold")[FIXED IN]],
    ),
    ..data.other_rows
      .map(r => (
        [#text(size: 7.6pt)[#r.cve]],
        [#text(size: 7.6pt)[#r.component]],
        [#text(size: 7.6pt)[#r.severity]],
        [#text(size: 7.6pt)[#r.epss]],
        [#text(size: 7.6pt)[#r.fix]],
      ))
      .flatten(),
  )

  #if data.other_rows_truncated > 0 [
    #v(4pt)
    #text(size: 7.6pt, fill: muted)[
      #data.other_rows_truncated further findings omitted for brevity; the
      complete set is in findings.cdx-vex.json.
    ]
  ]
]

#v(12pt)
#line(length: 100%, stroke: 0.4pt + line_c)
#v(4pt)
#text(size: 7.4pt, fill: muted)[
  Generated by PandaX from evidence run #data.run_id. Every input and output of
  that run is recorded in a hash-chained ledger and sealed with an Ed25519
  signature over manifest.json, which can be verified independently with
  #raw("pandax verify"). The signature proves the integrity of this bundle, not
  the legal identity of the signer; an eIDAS qualified electronic seal is
  required for that.
]
