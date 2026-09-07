// Simplified EU declaration of conformity.
//
// Article 13(20): manufacturers shall provide EITHER a copy of the full EU
// declaration of conformity OR a simplified one, which must contain the exact
// internet address at which the full declaration can be accessed.
//
// Article 28(2): the simplified declaration "shall have the model structure set
// out in Annex VI". Annex VI prescribes the wording verbatim, so the sentence
// below is reproduced exactly, with only the bracketed placeholders filled in.

#let data = json("dossier.json")

#set document(title: "Simplified EU Declaration of Conformity", author: "PandaX")
#set page(paper: "a4", margin: (x: 2.4cm, y: 2.4cm))
#set text(size: 11pt, lang: "en")
#set par(justify: false, leading: 0.7em)

#let ink = rgb("#0f172a")
#let muted = rgb("#5b6b84")
#let missing = data.doc_url == ""

#align(center)[
  #text(size: 8pt, weight: "bold", fill: muted, tracking: 1.4pt)[
    ANNEX VI — REGULATION (EU) 2024/2847
  ]
  #v(5pt)
  #text(size: 17pt, weight: "bold", fill: ink)[
    SIMPLIFIED EU DECLARATION OF CONFORMITY
  ]
]

#v(4pt)
#line(length: 100%, stroke: 1pt + ink)
#v(22pt)

// --- the prescribed sentence, verbatim from Annex VI ------------------------

#block(inset: (left: 4pt), [
  Hereby, #text(weight: "bold")[#data.manufacturer.legal_name] declares that the
  product with digital elements type
  #text(weight: "bold")[#data.product.name #data.product.version]
  is in compliance with Regulation (EU) 2024/2847#super[(1)].

  #v(10pt)

  The full text of the EU declaration of conformity is available at the
  following internet address:
  #v(4pt)
  #if missing [
    #text(fill: rgb("#b91c1c"), weight: "bold")[
      MANUFACTURER INPUT REQUIRED — Article 13(20) requires the exact internet
      address at which the full EU declaration of conformity can be accessed.
      Set `vulnerability_handling.declaration_url` in the product metadata.
    ]
  ] else [
    #text(weight: "bold")[#link(data.doc_url)[#data.doc_url]]
  ]
])

#v(30pt)
#line(length: 40%, stroke: 0.4pt + muted)
#v(4pt)
#text(size: 8pt, fill: muted)[
  #super[(1)] #data.regulation_reference.oj, ELI:
  #link(data.regulation_reference.eli)[#data.regulation_reference.eli]
]

#v(24pt)
#text(size: 8pt, fill: muted)[
  Provided with the product with digital elements in accordance with Article
  13(20). Article 28(2): to be made available in the languages required by each
  Member State in which the product is placed on the market.
]
