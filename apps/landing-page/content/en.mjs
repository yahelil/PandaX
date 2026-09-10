/**
 * All site copy, in one place.
 *
 * Edit here, then run `node build.mjs` to regenerate the HTML. Nothing in the
 * generated pages should be edited by hand — it will be overwritten.
 *
 * Structured for translation: a German file would be content/de.js with the
 * same shape. No German copy is written yet.
 */

export const meta = {
  lang: "en",
  domain: "pandax.online",
  brand: "PandaX",
  // The dashboard currently calls itself "CRA Compliance Vault". The public
  // site uses the brand name only, consistently. Flagged for a decision.
  tagline: "CRA compliance evidence for connected products",
};

export const nav = {
  links: [
    { label: "The gap", href: "#gap" },
    { label: "How it works", href: "#how" },
    { label: "The export", href: "#export" },
    { label: "For labs", href: "#labs" },
    { label: "Questions", href: "#faq" },
  ],
  action: { label: "Book a walkthrough", href: "#contact" },
};

export const hero = {
  headline: "Every release, audit-ready.",
  subhead:
    "PandaX turns firmware analysis into the technical file the Cyber Resilience Act asks for — component inventory, risk decisions, and the reasoning behind them, sealed to the release that shipped.",
  primary: { label: "See a sample evidence package", href: "#contact" },
  secondary: { label: "Book a 30-minute walkthrough", href: "#contact" },
  /**
   * The hero record. This is an EXAMPLE, labelled as one on the page.
   * TODO(asset): replace with a real anonymised run once one exists. The
   * public reference target is an official OpenWrt device image.
   */
  record: {
    label: "Example record",
    product: "Gateway controller",
    release: "4.2.1",
    runId: "run-20260910-084417-c31f0a",
    sealed: "2026-09-10T08:44:17Z",
    image: "openwrt-23.05.5-ath79-generic-squashfs-sysupgrade.bin",
    sha256: "3f7c1d9a5b0e482c6a1f9d3b7e0c2a48d5f61b93ac7e284f0d6b1c53a97e40f2",
    stats: [
      { value: "412", label: "components" },
      { value: "7", label: "findings" },
      { value: "1", label: "actively exploited" },
      { value: "6 of 6", label: "checks passed" },
    ],
    checks: [
      "Inventory tied to image digest",
      "Findings reproduced against source feeds",
      "Risk decisions recorded with rationale",
      "Reporting timeline complete",
      "Documents validated",
      "Bundle sealed and countersigned",
    ],
    finding: {
      cve: "CVE-2023-46218",
      component: "curl 8.3.0",
      note: "Cookie leak across domains.",
      fix: "Upgrade to curl 8.5.0",
      decision: "Accepted for 4.2.1 — not reachable in this build. Cleared in 4.3.0.",
    },
  },
};

export const deadlines = {
  heading: "The dates are already running.",
  rows: [
    {
      date: "11 June 2026",
      iso: "2026-06-11",
      title: "Conformity assessment bodies can be designated",
      state: "past",
    },
    {
      date: "11 September 2026",
      iso: "2026-09-11",
      title: "Article 14 reporting obligations apply",
      state: "active",
      stateLabel: "In effect",
    },
    {
      date: "11 December 2027",
      iso: "2027-12-11",
      title:
        "Full obligations: Annex I requirements, Annex VII technical documentation, CE marking",
      state: "future",
    },
  ],
  note: "Penalties reach €15M or 2.5% of global annual turnover.",
};

export const gap = {
  heading: "A scanner answers a different question.",
  columns: [
    {
      title: "What a scanner gives you",
      items: [
        "A CVE list per build",
        "Severity scores",
        "A report regenerated from scratch each time",
        "No record of why a risk was accepted",
        "No link to the release that shipped",
      ],
    },
    {
      title: "What a reviewer asks for",
      items: [
        "Annex VII technical documentation",
        "The risk assessment and how it was resolved",
        "Evidence the vulnerability handling process actually ran",
        "An inventory tied to the shipped image",
        "A timeline that still holds up two years later",
      ],
    },
  ],
  closing:
    "Between the two sits weeks of manual reconstruction, repeated for every release.",
};

export const clock = {
  heading: "Article 14 runs on a clock.",
  rows: [
    { at: "24 hours", title: "Early warning" },
    { at: "72 hours", title: "Notification" },
    { at: "14 days", title: "Final report" },
  ],
  recipients:
    "Recipients are the national CSIRT and ENISA, through the single reporting platform of Article 16.",
  closing: "The evidence has to exist before the legal review starts.",
};

export const how = {
  heading: "Four stages.",
  stages: [
    {
      title: "Extraction",
      body: "A build or firmware package goes in. PandaX unpacks it and records the digest of the file it read.",
    },
    {
      title: "Detection",
      body: "The inventory is matched against public advisory sources. Sources that failed are shown as failed, not as clean.",
    },
    {
      title: "Evidence",
      body: "Each risk decision is recorded as it is made, with its rationale, its author and its date.",
    },
    {
      title: "Sealed release file",
      body: "The result is sealed to the release and timestamped, so a reviewer can check that nothing changed afterwards.",
    },
  ],
  notes: [
    "No source code required.",
    "The build never leaves the customer's control.",
  ],
};

export const exportPack = {
  heading: "What is in the export.",
  items: [
    { title: "Component inventory", body: "An SBOM tied to the image that shipped." },
    { title: "Findings", body: "Each one with the upgrade that clears it." },
    { title: "Risk decisions", body: "With the rationale, the author and the date." },
    { title: "Release check", body: "Sealed and timestamped." },
    { title: "Reporting timeline pack", body: "The Article 14 record, stage by stage." },
    { title: "Case file per incident", body: "One file per case, kept whole." },
  ],
  closing: "One export, open format. The customer owns it.",
};

export const proof = {
  heading: "The working product.",
  body: "A proof of concept runs today: it ingests a package, produces an inventory and findings, records decisions, and seals the result.",
  // TODO(asset): no firmware dashboard screenshot exists yet. Do not publish
  // the Java/Maven run next to firmware copy — the mismatch is obvious to a
  // product security engineer. Placeholder stays until the right asset exists.
  placeholder: {
    title: "Screenshot pending",
    body: "A dashboard image of a firmware run goes here, labelled with the image it analysed.",
  },
};

export const audience = {
  heading: "Who this is for.",
  body: "Manufacturers of connected products with 50 to 1,000 employees.",
  points: [
    "There is no compliance department. The regulation lands on an engineering or quality lead who already has a job.",
    "A consultant-built file per release does not scale to a release cadence.",
    "The €15M ceiling is the same as it is for a corporation with a legal team.",
  ],
};

export const labs = {
  heading: "For labs and advisory firms.",
  body: "PandaX does not compete with the assessor. It prepares the file the assessor reads.",
  points: [
    {
      title: "Scanner-neutral",
      body: "PandaX ingests any scanner's output and does not replace anyone's tooling.",
    },
    {
      title: "No opinions issued",
      body: "PandaX never issues conformity opinions, certificates or verdicts. The judgement stays with the assessor.",
    },
    {
      title: "Portable export",
      body: "The manufacturer owns the package and can take it to any reviewer.",
    },
    {
      title: "Pricing independent of outcome",
      body: "Pricing is never tied to the outcome of an assessment.",
    },
  ],
  action: { label: "Read the partner page", href: "/partners/" },
};

export const faq = {
  heading: "Questions worth asking.",
  items: [
    {
      q: "How is this different from a firmware scanner?",
      a: "A scanner produces findings. PandaX produces the file a reviewer asks for: the inventory tied to the shipped image, the decision made about each finding, who made it and when, and the reasoning. A scan is an input to that file, not a substitute for it.",
    },
    {
      q: "Do you need our source code?",
      a: "No. PandaX works from a build or firmware package. Source code is never required and the build never leaves your control.",
    },
    {
      q: "Where does our data sit, and who can read it?",
      a: "The proof of concept runs locally, on your machine. The hosted workspace is being built and will be EU-hosted; the access model is not settled yet, and we would rather say so than describe something that does not exist.",
    },
    {
      q: "What happens to our evidence if we stop being a customer?",
      a: "The export is an open format and it is yours. It is designed to be read without PandaX installed, which is also what makes it useful to a reviewer.",
    },
    {
      q: "Does this make us CRA-compliant?",
      a: "No. PandaX produces the documentation and records the process. Conformity is assessed by a body, not by a tool. Any vendor that tells you otherwise is selling you a problem.",
    },
    {
      q: "What exists today, and what is still being built?",
      a: "Today: ingest, component inventory, findings from public sources, recorded decisions, the Article 14 timeline, document generation and a sealed, independently verifiable export. Being built: the hosted multi-user workspace, scheduled advisory monitoring and broader firmware format coverage.",
    },
  ],
};

export const closing = {
  heading: "See what the file looks like.",
  body: "The fastest way to judge this is to read one. Ask for the sample evidence package, or take thirty minutes and we will walk through a real run.",
  primary: { label: "See a sample evidence package", href: "#contact" },
  secondary: { label: "Book a 30-minute walkthrough", href: "#contact" },
};

export const contact = {
  heading: "Get in touch.",
  body: "Tell us what you build and which release is next. We will reply with the sample package or a time.",
  fields: {
    name: "Name",
    email: "Work email",
    company: "Company",
    message: "What do you build?",
    submit: "Send",
  },
  // No third-party embed. Set FORM_ENDPOINT in build.mjs to post somewhere;
  // with no endpoint configured the form falls back to mailto.
  fallbackAddress: "hello@pandax.online", // TODO(legal): confirm the real address
};

export const footer = {
  lines: ["PandaX", "CRA compliance evidence for connected products"],
  links: [
    { label: "Partners", href: "/partners/" },
    { label: "Impressum", href: "/impressum/" },
    { label: "Datenschutzerklärung", href: "/datenschutz/" },
    { label: "Privacy", href: "/privacy/" },
  ],
  legal:
    "PandaX produces compliance documentation. It does not issue conformity opinions, certificates or verdicts.",
};

export const partners = {
  title: "Partners",
  description:
    "How PandaX works with testing, inspection and certification firms and advisory practices.",
  heading: "PandaX prepares the file. You assess it.",
  intro:
    "Manufacturers arrive at an assessment with evidence scattered across scanners, spreadsheets and email. PandaX collects it into one reviewable package. That shortens your intake, and it does not touch your judgement.",
  guardrails: {
    heading: "Four guardrails.",
    items: [
      {
        title: "Scanner-neutral",
        body: "PandaX ingests output from any scanner and does not replace tooling you or your client already use. If a client brings their own analysis, it becomes an input, not a competitor.",
      },
      {
        title: "No conformity opinions",
        body: "PandaX never issues certificates, verdicts or conformity opinions, and the product is built so it cannot imply one. Findings are recorded as observations with their sources; the assessment is yours.",
      },
      {
        title: "Portable export",
        body: "The evidence package is an open format the manufacturer owns, readable without PandaX installed. Nothing locks a client to us or routes them to a particular reviewer.",
      },
      {
        title: "Pricing independent of outcome",
        body: "Pricing is per workspace and never tied to the outcome of an assessment. There is no arrangement under which PandaX earns more from a favourable result.",
      },
    ],
  },
  models: {
    heading: "Three ways to work together.",
    items: [
      {
        title: "Referral",
        body: "You send a manufacturer who needs their evidence in order before an assessment. They arrive with a reviewable package.",
      },
      {
        title: "Co-sell",
        body: "PandaX sits inside your own CRA readiness offering as the evidence workspace, under your engagement.",
      },
      {
        title: "White-label workspace",
        body: "A branded evidence workspace for your clients, with your firm as the front door.",
      },
    ],
  },
  form: {
    heading: "Partner enquiry.",
    body: "Tell us about your practice and the clients you are seeing CRA questions from.",
  },
};

export const legalPages = {
  impressum: {
    title: "Impressum",
    description: "Angaben gemäß § 5 TMG.",
    heading: "Impressum",
    note: "Angaben gemäß § 5 TMG. This page is required for a German-facing site and is not yet complete.",
    sections: [
      {
        title: "Diensteanbieter",
        rows: [
          ["Legal entity", "TODO — registered company name and legal form"],
          ["Address", "TODO — street, postal code, city, country"],
        ],
      },
      {
        title: "Vertreten durch",
        rows: [["Managing director", "TODO — name of the managing director"]],
      },
      {
        title: "Kontakt",
        rows: [
          ["Email", "TODO — contact email address"],
          ["Telephone", "TODO — contact telephone number"],
        ],
      },
      {
        title: "Registereintrag",
        rows: [
          ["Register", "TODO — register court and registration number"],
          ["VAT ID", "TODO — Umsatzsteuer-Identifikationsnummer per § 27a UStG"],
        ],
      },
      {
        title: "Verantwortlich für den Inhalt",
        rows: [["Responsible", "TODO — name and address per § 18 Abs. 2 MStV"]],
      },
    ],
  },
  datenschutz: {
    title: "Datenschutzerklärung",
    description: "Informationen zur Verarbeitung personenbezogener Daten.",
    heading: "Datenschutzerklärung",
    note: "This site sets no cookies and runs no analytics. The structure below is complete; the entries marked TODO need the legal entity's details before publication.",
  },
  privacy: {
    title: "Privacy",
    description: "How this website handles personal data.",
    heading: "Privacy",
    note: "English translation of the Datenschutzerklärung. The German version is authoritative.",
  },
};

/** Shared by /datenschutz and /privacy. */
export const privacyBody = {
  sections: [
    {
      title: "Controller",
      body: "TODO — the legal entity responsible for processing, with its address and contact details. See the Impressum.",
    },
    {
      title: "What this website collects",
      body: "This website sets no cookies, runs no analytics and embeds no third-party services. No consent banner is required, because nothing is stored on your device beyond what is technically necessary to serve the page.",
    },
    {
      title: "Server logs",
      body: "The hosting provider records standard request data — IP address, time, requested file, referrer and user agent — for the purpose of delivering and securing the site. Legal basis: Art. 6(1)(f) GDPR. TODO — confirm the retention period with the provider.",
    },
    {
      title: "Contact form and email",
      body: "If you write to us, the details you send are processed for the purpose of answering you and are kept for as long as the enquiry requires. Legal basis: Art. 6(1)(b) and (f) GDPR. The form posts to our own endpoint; there is no third-party form service.",
    },
    {
      title: "Fonts and assets",
      body: "Fonts and images are served from this domain. No request is made to Google Fonts or any other external host.",
    },
    {
      title: "Hosting",
      body: "TODO — name the hosting provider, the processing location and the data processing agreement in place.",
    },
    {
      title: "Your rights",
      body: "You have the right of access, rectification, erasure, restriction, data portability and objection, and the right to complain to a supervisory authority. TODO — name the competent supervisory authority.",
    },
  ],
};
