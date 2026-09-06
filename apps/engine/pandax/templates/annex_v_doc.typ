// EU Declaration of Conformity, Annex V of Regulation (EU) 2024/2847.

#let data = json("dossier.json")

#set document(title: "EU Declaration of Conformity", author: "PandaX")
#set page(
  paper: "a4",
  margin: (x: 2.2cm, top: 2.2cm, bottom: 2cm),
  numbering: "1 / 1",
)
#set text(size: 9.6pt, lang: "en")
#set par(justify: true, leading: 0.65em)

#let ink = rgb("#0f172a")
#let muted = rgb("#64748b")
#let line_c = rgb("#e2e8f0")
#let blocked = data.summary.actively_exploited > 0

#block(width: 100%)[
  #text(size: 7.5pt, weight: "bold", fill: muted, tracking: 1.2pt)[
    REGULATION (EU) 2024/2847 — ANNEX V
  ]
  #v(6pt)
  #text(size: 20pt, weight: "bold", fill: ink)[EU Declaration of Conformity]
  #v(9pt)
  #line(length: 100%, stroke: 1.2pt + ink)
]

#v(12pt)

#if blocked [
  #block(
    width: 100%,
    fill: rgb("#fef2f2"),
    stroke: 1.2pt + rgb("#dc2626"),
    radius: 3pt,
    inset: 11pt,
  )[
    #text(size: 11pt, weight: "bold", fill: rgb("#7f1d1d"))[
      DRAFT — NOT VALID FOR SIGNATURE
    ]
    #v(4pt)
    #text(size: 8.8pt)[
      This declaration cannot be issued. #data.summary.actively_exploited
      actively exploited #if data.summary.actively_exploited == 1 [vulnerability
      is] else [vulnerabilities are] present in the product. Annex I Part I(2)(a)
      requires that products with digital elements are made available on the
      market #emph[without known exploitable vulnerabilities]. Remediate the
      findings listed in the accompanying Annex VII technical documentation, then
      re-run the assessment.
    ]
  ]
  #v(12pt)
]

#let row(e) = block(above: 8pt, below: 0pt, width: 100%)[
  #grid(
    columns: (0.9cm, 1fr),
    column-gutter: 4pt,
    align(left)[#text(weight: "bold", size: 9.2pt, fill: muted)[#e.ref.]],
    [
      #text(weight: "bold", size: 9.2pt)[#e.title]
      #v(2pt)
      #if e.status == "required_input" [
        #text(fill: rgb("#b91c1c"), weight: "bold")[#e.value]
      ] else [
        #text(fill: ink)[#e.value]
      ]
      #if e.note != "" [
        #v(2pt)
        #text(size: 7.6pt, fill: muted, style: "italic")[#e.note]
      ]
    ],
  )
  #v(4pt)
  #line(length: 100%, stroke: 0.4pt + line_c)
]

#for e in data.annex_v [ #row(e) ]

#v(16pt)

#grid(
  columns: (1fr, 1fr),
  column-gutter: 20pt,
  [
    #text(size: 8pt, fill: muted)[Signed for and on behalf of]
    #v(3pt)
    #text(size: 10pt, weight: "bold")[#data.manufacturer.legal_name]
    #v(14pt)
    #line(length: 90%, stroke: 0.6pt + ink)
    #v(2pt)
    #text(size: 8pt, fill: muted)[
      #data.manufacturer.signatory_name — #data.manufacturer.signatory_function
    ]
  ],
  [
    #text(size: 8pt, fill: muted)[Place and date of issue]
    #v(3pt)
    #text(size: 10pt, weight: "bold")[#data.manufacturer.place_of_issue]
    #v(14pt)
    #line(length: 90%, stroke: 0.6pt + ink)
    #v(2pt)
    #text(size: 8pt, fill: muted)[#data.generated]
  ],
)

#v(20pt)
#line(length: 100%, stroke: 0.4pt + line_c)
#v(4pt)
#text(size: 7.4pt, fill: muted)[
  Supporting technical documentation: Annex VII dossier from evidence run
  #data.run_id. SBOM digest #raw(data.summary.sbom_sha256). Both documents are
  covered by a hash-chained evidence ledger sealed with an Ed25519 signature;
  verify with #raw("pandax verify"). Retention: Article 31 requires the technical
  documentation and this declaration to be kept for 10 years after the product is
  placed on the market, or for the support period, whichever is longer.
]
