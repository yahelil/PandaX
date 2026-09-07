// EU Declaration of Conformity.
//
// Article 28(2): "The EU declaration of conformity shall have the model
// structure set out in Annex V". This template therefore follows Annex V
// item for item, in order, including its closing block. Nothing is added
// between the numbered items and nothing is reordered.

#let data = json("dossier.json")

#set document(title: "EU Declaration of Conformity", author: "PandaX")
#set page(
  paper: "a4",
  margin: (x: 2.2cm, top: 2cm, bottom: 1.8cm),
  numbering: "1 / 1",
)
#set text(size: 10pt, lang: "en")
#set par(justify: false, leading: 0.65em)

#let ink = rgb("#0f172a")
#let muted = rgb("#5b6b84")
#let line_c = rgb("#d9e0ea")
#let blocked = data.summary.actively_exploited > 0

// The CE marking is NOT drawn here. Its graphic form is prescribed by Annex II
// to Regulation (EC) No 765/2008; an approximation drawn in this template could
// itself be a non-conforming mark. The manufacturer supplies the official
// artwork, or the space is reserved and flagged.
#let ce-placement(artwork, size: 16mm) = {
  if artwork != "" {
    box(height: size, image(artwork, height: size))
  } else {
    box(
      width: size * 1.6, height: size,
      stroke: (thickness: 0.8pt, paint: rgb("#b91c1c"), dash: "dashed"),
      radius: 2pt,
      align(center + horizon, text(
        size: 6.5pt, fill: rgb("#b91c1c"), weight: "bold",
      )[AFFIX\ CE MARKING]),
    )
  }
}

// ------------------------------------------------------------------ heading

#align(center)[
  #text(size: 8pt, weight: "bold", fill: muted, tracking: 1.4pt)[
    ANNEX V — REGULATION (EU) 2024/2847
  ]
  #v(5pt)
  #text(size: 19pt, weight: "bold", fill: ink)[EU DECLARATION OF CONFORMITY]
]

#v(4pt)
#line(length: 100%, stroke: 1pt + ink)
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
    #text(size: 9pt)[
      This declaration cannot be issued. #data.summary.actively_exploited
      actively exploited #if data.summary.actively_exploited == 1 [vulnerability
      is] else [vulnerabilities are] present in the product. Annex I Part I(2)(a)
      requires that products with digital elements are made available on the
      market #emph[without known exploitable vulnerabilities]. Remediate the
      findings listed in the accompanying technical documentation, then re-run
      the assessment.
    ]
  ]
  #v(12pt)
]

// ------------------------------------------------- Annex V, items 1 to 8

#let item(n, title, body, flagged: false) = block(above: 9pt, below: 0pt, width: 100%)[
  #grid(
    columns: (1cm, 1fr),
    column-gutter: 2pt,
    align(left)[#text(weight: "bold", size: 10pt)[#n.]],
    [
      #text(weight: "bold", size: 10pt)[#title]
      #v(2.5pt)
      #if flagged [
        #text(fill: rgb("#b91c1c"), weight: "bold")[#body]
      ] else [
        #body
      ]
    ],
  )
  #v(5pt)
  #line(length: 100%, stroke: 0.4pt + line_c)
]

#for e in data.annex_v {
  item(e.ref, e.title, e.value, flagged: e.status == "required_input")
}

// Annex V places the signature block immediately under item 8, with these
// three prescribed captions. It is reproduced verbatim.
#v(10pt)
#block(breakable: false, inset: (left: 1cm))[
  #text(size: 9.5pt, weight: "bold")[Signed for and on behalf of:]
  #v(3pt)
  #text(size: 10pt)[#data.manufacturer.legal_name]
  #v(16pt)
  #grid(
    columns: (1fr, 1fr),
    column-gutter: 24pt,
    [
      #line(length: 92%, stroke: 0.6pt + ink)
      #v(2pt)
      #text(size: 8pt, fill: muted)[(place and date of issue):]
      #v(2pt)
      #text(size: 9pt)[#data.manufacturer.place_of_issue, #data.generated.slice(0, 10)]
    ],
    [
      #line(length: 92%, stroke: 0.6pt + ink)
      #v(2pt)
      #text(size: 8pt, fill: muted)[(name, function) (signature):]
      #v(2pt)
      #text(size: 9pt)[
        #data.manufacturer.signatory_name — #data.manufacturer.signatory_function
      ]
    ],
  )
]

// --------------------------------------------- legal act being declared to

#v(10pt)
#block(
  breakable: false,
  width: 100%,
  fill: rgb("#f8fafc"),
  stroke: 0.6pt + line_c,
  radius: 3pt,
  inset: 10pt,
)[
  #text(size: 8.5pt, weight: "bold")[Union harmonisation legislation applied]
  #v(4pt)
  #text(size: 8.5pt)[
    #data.regulation_reference.title \
    #data.regulation_reference.oj — ELI: #link(data.regulation_reference.eli)[#data.regulation_reference.eli]
  ]
]

// ------------------------------------------------------- CE marking + sign

#v(14pt)
#grid(
  columns: (auto, 1fr),
  column-gutter: 18pt,
  align(left + top)[
    #ce-placement(data.ce_marking.artwork)
    #v(3pt)
    #text(size: 7pt, fill: muted)[CE marking\ (Art. 29–30)]
  ],
  [
    #text(size: 8.2pt, fill: muted)[
      #data.ce_marking.placement \
      #data.ce_marking.form
      #if data.ce_marking.notified_body_number != "" [
        \ Notified body identification number: #data.ce_marking.notified_body_number
      ]
    ]
  ],
)

#v(16pt)
#line(length: 100%, stroke: 0.4pt + line_c)
#v(4pt)
#text(size: 7.4pt, fill: muted)[
  #data.retention.statement
  Supporting technical documentation: Annex VII dossier from evidence run
  #data.run_id, SBOM digest #raw(data.summary.sbom_sha256.slice(0, 32)).
  Article 28(2): this declaration must be made available in the languages
  required by each Member State in which the product is placed on the market.
]
