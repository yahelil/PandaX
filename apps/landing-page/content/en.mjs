/**
 * All site copy, in one place.
 *
 * Edit here, then run `node build.mjs` to regenerate the HTML. Never edit the
 * generated pages by hand — they are overwritten.
 *
 * Structured for translation: a German file would be content/de.mjs with the
 * same shape. No German copy is written yet.
 *
 * House rules: sentence case everywhere. Say record, evidence, audit trail —
 * never "CRA-compliant", "certified" or "guaranteed". The product analyses an
 * SBOM, so the word "firmware" does not appear on this site.
 */

export const meta = {
  lang: "en",
  domain: "pandax.online",
  brand: "PandaX",
  // The dashboard UI says "CRA Compliance Vault". The public site uses the
  // brand name only. Flagged for a decision rather than settled quietly.
  tagline: "Product security evidence for the EU Cyber Resilience Act",
};

export const nav = {
  links: [
    { label: "The obligation", href: "#obligation" },
    { label: "What PandaX does", href: "#does" },
    { label: "Source code", href: "#source" },
    { label: "For labs", href: "#labs" },
    { label: "Questions", href: "#faq" },
  ],
  action: { label: "Book a walkthrough", href: "#contact" },
};

/* 1 ------------------------------------------------------------- hero --- */

export const hero = {
  headline: "Every release. Evidence ready.",
  subhead: "Product security evidence for the EU Cyber Resilience Act.",
  body: "Upload a product release. PandaX turns it into a clear record for review.",
  primary: { label: "See a sample record", href: "#contact" },
  secondary: { label: "Book a 30-minute walkthrough", href: "#contact" },
  /** Shown on the laptop screen. An example, labelled as one on the page. */
  record: {
    label: "Example record",
    product: "Gateway controller",
    release: "4.2.1",
    runId: "run-20260910-084417-c31f0a",
    sealed: "2026-09-10T08:44:17Z",
    stats: [
      { value: "412", label: "components" },
      { value: "7", label: "findings" },
      { value: "1", label: "needs a decision" },
      { value: "6 of 6", label: "checks passed" },
    ],
    checks: ["Inventory", "Findings", "Decisions", "Timeline", "Documents", "Sealed"],
    finding: {
      cve: "CVE-2023-46218",
      component: "curl 8.3.0",
      fix: "Upgrade to curl 8.5.0",
    },
  },
};

/* 2 -------------------------------------------------------- obligation --- */

export const obligation = {
  heading: "The CRA makes product security a legal obligation",
  lede: "New EU rules apply to software and connected products.",
  points: [
    "Companies must secure products and manage vulnerabilities throughout the product lifecycle.",
    "Incident reporting starts 11 September 2026. Full application follows on 11 December 2027.",
    "Penalties can reach €15 million or 2.5% of worldwide annual revenue.",
  ],
  closing: "Every release doesn't just need a security checklist. It needs evidence.",
  source:
    "European Commission Digital Strategy; Regulation (EU) 2024/2847, Articles 71 and 73.",
  live: { date: "11 September 2026", iso: "2026-09-11", label: "In effect" },
};

/* 3 ------------------------------------------------------------ vector --- */

export const vectors = {
  heading: "Vulnerability exploitation is now the fastest-growing way in",
  lede: "Verizon 2025 DBIR, initial access vectors.",
  /** One measure, four categories, one of them the point. Bronze marks it. */
  bars: [
    { label: "Other vectors and unknowns", value: 42 },
    { label: "Stolen credentials", value: 22 },
    { label: "Vulnerability exploitation", value: 20, mark: true },
    { label: "Phishing", value: 16 },
  ],
  facts: [
    "20% of breaches began with vulnerability exploitation.",
    "Up 34% year over year.",
    "Edge and VPN devices went from 3% to 22% of exploitation incidents.",
  ],
  source:
    "Verizon 2025 DBIR. The DBIR reports phishing at about 15%; the figure here is rounded to 16%.",
};

/* 4 ----------------------------------------------------------- problem --- */

export const problem = {
  heading: "When proof is requested, teams reconstruct compliance by hand",
  lede: "Product security and compliance tools leave evidence fragmented.",
  lines: [
    { lead: "Product security tools find risks,", rest: "but do not assemble CRA proof." },
    { lead: "General compliance tools track policy,", rest: "but not each product release." },
    { lead: "Jira, CI/CD, SBOM tools, documents and legal workflows hold the evidence,", rest: "and stay disconnected." },
  ],
};

/* 5 ------------------------------------------------------------ manual --- */

export const manual = {
  heading: "The manual process",
  lede: "Each release creates the same work again.",
  steps: [
    { title: "Inventory the release", body: "Catalogue every component and library in the release." },
    { title: "Assess the exposure", body: "Trace each vulnerability to the code the product uses." },
    { title: "Submit the evidence", body: "Compile the required forms and file them with regulators." },
  ],
  clock: "24h early warning · 72h follow-up notice — the clock starts when the manufacturer becomes aware.",
  closing: "Manual work grows with every release.",
};

/* 6 --------------------------------------------------------------- does --- */

export const does = {
  heading: "PandaX makes every release evidence ready",
  lede: "Connect the evidence. Generate the documents. Submit with approval.",
  points: [
    "Connects Jira, CI/CD, SBOM, documents and legal workflows to each product release.",
    "Generates the required legal documents in the correct regulatory format, and flags what is missing.",
    "Submits after your company's approval, and retains a time-stamped audit trail of every submission.",
  ],
  closing: "Nothing is submitted without the company's explicit authorization.",
};

/* 7 ------------------------------------------------------------- source --- */

export const source = {
  heading: "Your source code never leaves your environment",
  lede: "PandaX works from the SBOM, not the code.",
  points: [
    "PandaX never receives or views your source code. It stays inside your environment.",
    "The company provides only the SBOM — the component and dependency inventory needed for analysis.",
    "If an SBOM is not available, PandaX provides the tools to generate it without sharing source code.",
  ],
  closing: "CRA evidence without giving PandaX access to your source code.",
};

/* 8 ------------------------------------------------------------- useful --- */

export const useful = {
  heading: "What makes PandaX useful",
  items: [
    { title: "Starts with the product", body: "Takes a ready SBOM, or gives the option to generate one." },
    { title: "Follows every update", body: "Keeps the report history available for later." },
    { title: "Shows what is missing", body: "People add only what software cannot know." },
    { title: "Creates a clear record", body: "The reports stay easy to review." },
  ],
};

/* 9 --------------------------------------------------------------- who --- */

export const who = {
  heading: "Built for smaller manufacturers",
  lede: "The CRA reaches every product with digital elements. Most smaller manufacturers have no compliance department to read it for them.",
  rows: [
    { title: "Who they are", body: "Small product and device makers placing hardware with software inside on the EU market." },
    { title: "What they lack", body: "No in-house legal, security or compliance team to turn CRA articles into actual work." },
    { title: "What PandaX does", body: "Turns each release into the record the CRA asks for, without hiring that team." },
  ],
  closing: "Every release. Evidence ready. Compliance work that used to need a legal team, handled by the product team.",
};

/* 10 -------------------------------------------------------------- labs --- */

export const labs = {
  heading: "For labs and advisory firms",
  points: [
    { title: "Scanner-neutral", body: "We ingest any scanner's output. We replace nothing." },
    { title: "No conformity opinions", body: "No certificates, no verdicts. The judgement stays with the assessor." },
    { title: "Portable export", body: "The manufacturer owns the record and can take it anywhere." },
    { title: "Outcome-independent pricing", body: "Our price never depends on an assessment result." },
  ],
  action: { label: "Read the partner page", href: "/partners/" },
};

/* 11 --------------------------------------------------------------- faq --- */

export const faq = {
  heading: "Questions worth asking",
  items: [
    {
      q: "Do you need our source code?",
      a: "No. PandaX works from the SBOM. Your source code never leaves your environment and PandaX never receives or views it.",
    },
    {
      q: "What if we don't have an SBOM?",
      a: "PandaX provides the tools to generate one, without sharing source code.",
    },
    {
      q: "Does this make us CRA-compliant?",
      a: "No. PandaX produces the documentation and records the process. Conformity is assessed by a body, not by a tool.",
    },
    {
      q: "Who decides what gets submitted to a regulator?",
      a: "The company. Nothing is submitted without explicit authorization, and every submission keeps a time-stamped audit trail.",
    },
    {
      q: "How is this different from a vulnerability scanner?",
      a: "A scanner finds risks. It does not assemble the proof. PandaX connects the release, the findings, the decisions and the documents into one record a reviewer can read.",
    },
    {
      q: "What happens to our records if we stop being a customer?",
      a: "The export is an open format and it is yours. It is built to be read without PandaX, which is also what makes it useful to a reviewer.",
    },
    {
      q: "What exists today, and what is still being built?",
      a: "Today: a working proof of concept that takes a release, builds the inventory and findings, records decisions, generates the documents and seals the result. Being built: the hosted workspace, connectors and scheduled monitoring.",
    },
  ],
};

/* 12 ------------------------------------------------------------- close --- */

export const closing = {
  heading: "See what the record looks like",
  body: "The fastest way to judge this is to read one.",
  primary: { label: "See a sample record", href: "#contact" },
  secondary: { label: "Book a 30-minute walkthrough", href: "#contact" },
};

export const contact = {
  heading: "Get in touch",
  body: "Tell us what you build and which release is next.",
  fields: {
    name: "Name",
    email: "Work email",
    company: "Company",
    message: "What do you build?",
    submit: "Send",
  },
  fallbackAddress: "hello@pandax.online", // TODO(legal): confirm the real address
};

export const proof = {
  heading: "The working product",
  lede: "A proof of concept runs today.",
  // TODO(asset): the PoC dashboard screenshot is not in this repo. The known
  // run analysed a Java package (maven=39) and must be labelled as that, never
  // presented as a device release. Placeholder until the image arrives.
  placeholder: {
    title: "Screenshot pending",
    body: "A dashboard image goes here, labelled with what the run actually analysed.",
  },
};

export const footer = {
  lines: ["PandaX", "Product security evidence for the EU Cyber Resilience Act"],
  links: [
    { label: "Partners", href: "/partners/" },
    { label: "Impressum", href: "/impressum/" },
    { label: "Datenschutzerklärung", href: "/datenschutz/" },
    { label: "Privacy", href: "/privacy/" },
  ],
  legal:
    "PandaX produces compliance documentation. It does not issue conformity opinions, certificates or verdicts.",
};

/* ---------------------------------------------------------- /partners --- */

export const partners = {
  title: "Partners",
  description:
    "How PandaX works with testing, inspection and certification firms and advisory practices.",
  heading: "PandaX prepares the record. You assess it.",
  intro:
    "Manufacturers arrive at an assessment with evidence scattered across tools, spreadsheets and email. PandaX collects it into one reviewable record. That shortens your intake, and it does not touch your judgement.",
  guardrails: {
    heading: "Four guardrails",
    items: [
      {
        title: "Scanner-neutral",
        body: "We ingest output from any scanner and replace nothing you or your client already use. A client's own analysis becomes an input, not a competitor.",
      },
      {
        title: "No conformity opinions",
        body: "No certificates, no verdicts, no conformity opinions — and the product is built so it cannot imply one. Findings are recorded as observations with their sources. The judgement stays with the assessor.",
      },
      {
        title: "Portable export",
        body: "The record is an open format the manufacturer owns, readable without PandaX. Nothing locks a client to us or routes them to a particular reviewer.",
      },
      {
        title: "Outcome-independent pricing",
        body: "Pricing is per workspace and never tied to the result of an assessment. There is no arrangement under which PandaX earns more from a favourable outcome.",
      },
    ],
  },
  models: {
    heading: "Three ways to work together",
    items: [
      { title: "Referral", body: "You send a manufacturer who needs their evidence in order before an assessment. They arrive with a reviewable record." },
      { title: "Co-sell", body: "PandaX sits inside your own CRA readiness offering as the evidence workspace, under your engagement." },
      { title: "White-label workspace", body: "A branded evidence workspace for your clients, with your firm as the front door." },
    ],
  },
  form: {
    heading: "Partner enquiry",
    body: "Tell us about your practice and the clients raising CRA questions.",
  },
};

/* ------------------------------------------------------------- legal --- */

export const legalPages = {
  impressum: {
    title: "Impressum",
    description: "Angaben gemäß § 5 TMG.",
    heading: "Impressum",
    note: "Angaben gemäß § 5 TMG. This page is required for a German-facing site and is not yet complete.",
    sections: [
      { title: "Diensteanbieter", rows: [["Legal entity", "TODO — registered company name and legal form"], ["Address", "TODO — street, postal code, city, country"]] },
      { title: "Vertreten durch", rows: [["Managing director", "TODO — name of the managing director"]] },
      { title: "Kontakt", rows: [["Email", "TODO — contact email address"], ["Telephone", "TODO — contact telephone number"]] },
      { title: "Registereintrag", rows: [["Register", "TODO — register court and registration number"], ["VAT ID", "TODO — Umsatzsteuer-Identifikationsnummer per § 27a UStG"]] },
      { title: "Verantwortlich für den Inhalt", rows: [["Responsible", "TODO — name and address per § 18 Abs. 2 MStV"]] },
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

export const privacyBody = {
  sections: [
    { title: "Controller", body: "TODO — the legal entity responsible for processing, with its address and contact details. See the Impressum." },
    { title: "What this website collects", body: "This website sets no cookies, runs no analytics and embeds no third-party services. No consent banner is required, because nothing is stored on your device beyond what is technically necessary to serve the page." },
    { title: "Server logs", body: "The hosting provider records standard request data — IP address, time, requested file, referrer and user agent — to deliver and secure the site. Legal basis: Art. 6(1)(f) GDPR. TODO — confirm the retention period with the provider." },
    { title: "Contact form and email", body: "If you write to us, the details you send are processed to answer you and kept for as long as the enquiry requires. Legal basis: Art. 6(1)(b) and (f) GDPR. The form posts to our own endpoint; there is no third-party form service." },
    { title: "Fonts and assets", body: "Fonts and images are served from this domain. No request is made to Google Fonts or any other external host." },
    { title: "Hosting", body: "This site is hosted by Cloudflare, Inc. and served from its global edge network, which means the server nearest the visitor answers the request. TODO — confirm the data processing agreement and the standard contractual clauses on the account." },
    { title: "Your rights", body: "You have the right of access, rectification, erasure, restriction, data portability and objection, and the right to complain to a supervisory authority. TODO — name the competent supervisory authority." },
  ],
};
