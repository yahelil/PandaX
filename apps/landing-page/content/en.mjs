/**
 * All site copy, in one place. Sourced from the PandaX deck.
 *
 * Edit here, then run `node build.mjs`. Never edit the generated pages by hand.
 * Structured for translation: a German file would be content/de.mjs, same shape.
 *
 * House rules: sentence case. Say record, evidence, audit trail — never
 * "CRA-compliant", "certified" or "guaranteed". The product reads an SBOM, so
 * the word "firmware" does not appear.
 */

export const meta = {
  lang: "en",
  domain: "pandax.online",
  brand: "PandaX",
  product: "Actis",
  tagline: "Product security evidence for the EU Cyber Resilience Act",
};

export const nav = {
  productsLabel: "Our products",
  /** Add a product here and it appears in the header menu. */
  products: [
    {
      name: "Actis",
      href: "actis/",
      mark: "assets/actis-mark.png",
      blurb: "Turns a release into a reviewable record",
    },
  ],
  links: [],
  action: { label: "Book a walkthrough", href: "#contact" },
};

/* 0 ------------------------------------------------------------- boot --- */

export const boot = {
  meta: "PandaX",
  metaRight: "EU Cyber Resilience Act",
  screenNav: ["Releases", "Findings", "Documents", "Submissions"],
  screenYear: "2026",
  name: "PandaX",
  tag: "Evidence for the Cyber Resilience Act",
  hint: "Scroll",
};

/* 1 ------------------------------------------------------------- hero --- */

export const hero = {
  headline: "Automate CRA compliance",
  /** The word that takes the highlight, matched in the headline. */
  highlight: "Automate",
  subhead: "Product security evidence for the EU Cyber Resilience Act.",
  body: "Every release needs legal evidence. PandaX builds it.",
  primary: { label: "Book a 30-minute walkthrough", href: "#contact" },
  secondary: { label: "See Actis", href: "/actis/" },
  /** The machine cycles through these. Each is a complete, consistent example. */
  records: [
    {
      label: "Example record",
      product: "Gateway controller",
      release: "4.2.1",
      runId: "run-20260910-084417-c31f0a",
      stats: [
        { value: "412", label: "components" },
        { value: "7", label: "findings" },
        { value: "1", label: "needs a decision" },
        { value: "6 of 6", label: "checks passed" },
      ],
      checks: ["Inventory", "Findings", "Decisions", "Timeline", "Documents", "Sealed"],
      finding: { cve: "CVE-2023-46218", component: "curl 8.3.0", fix: "Upgrade to curl 8.5.0" },
    },
    {
      label: "Example record",
      product: "Sensor hub",
      release: "2.8.0",
      runId: "run-20260911-113902-7ae4d1",
      stats: [
        { value: "286", label: "components" },
        { value: "3", label: "findings" },
        { value: "0", label: "needs a decision" },
        { value: "6 of 6", label: "checks passed" },
      ],
      checks: ["Inventory", "Findings", "Decisions", "Timeline", "Documents", "Sealed"],
      finding: { cve: "CVE-2024-2511", component: "openssl 3.0.12", fix: "Upgrade to openssl 3.0.14" },
    },
    {
      label: "Example record",
      product: "Edge router",
      release: "1.14.3",
      runId: "run-20260912-201545-b09f38",
      stats: [
        { value: "531", label: "components" },
        { value: "12", label: "findings" },
        { value: "2", label: "needs a decision" },
        { value: "6 of 6", label: "checks passed" },
      ],
      checks: ["Inventory", "Findings", "Decisions", "Timeline", "Documents", "Sealed"],
      finding: { cve: "CVE-2023-44487", component: "nghttp2 1.52.0", fix: "Upgrade to nghttp2 1.57.0" },
    },
  ],
};

/* --- the engine, shown only on the product page ------------------------ */

export const pipeline = {
  heading: "Actis, running",
  lines: [
    { cmd: "ingest",  arg: "release-4.2.1",        out: "412 components" },
    { cmd: "match",   arg: "osv · kev · epss",     out: "7 findings" },
    { cmd: "assess",  arg: "reachability",         out: "1 needs a decision" },
    { cmd: "record",  arg: "decision + rationale", out: "logged" },
    { cmd: "docs",    arg: "annex vii · annex v",  out: "generated" },
    { cmd: "seal",    arg: "ed25519",              out: "sealed" },
  ],
  note: "One command. The record is the output, not a by-product.",
};

/* 2 -------------------------------------------------------- obligation --- */

export const obligation = {
  heading: "The Cyber Resilience Act hardens vulnerability compliance",
  lede: "Every release needs legal evidence.",
  marks: [
    { date: "11 Sep 2026", iso: "2026-09-11", label: "Vulnerability-handling requirements apply", live: true },
    { date: "11 Dec 2027", iso: "2027-12-11", label: "Full CRA application" },
  ],
  liveLabel: "In effect",
  points: [
    "Companies must maintain technical files — cybersecurity risk assessments, software architecture designs and test reports — available to authorities for at least 10 years.",
    "Penalties can reach €15 million or 2.5% of worldwide annual turnover, whichever is higher.",
  ],
  source:
    "European Commission Digital Strategy; Regulation (EU) 2024/2847, Articles 71 and 73.",
};

/* 3 ------------------------------------------------------- accelerating --- */

export const growth = {
  heading: "Vulnerability discovery is accelerating",
  lede: "CVE reports more than doubled between 2020 and 2025.",
  /** Actual CVE Program totals, then an exponential fit — labelled as one. */
  series: [
    { year: "2020", value: 18375 },
    { year: "2021", value: 20161 },
    { year: "2022", value: 25059 },
    { year: "2023", value: 28961 },
    { year: "2024", value: 40077 },
    { year: "2025", value: 48244 },
    { year: "2026", value: 57300, projected: true },
    { year: "2027", value: 70000, projected: true },
    { year: "2028", value: 85600, projected: true },
    { year: "2029", value: 104700, projected: true },
    { year: "2030", value: 128000, projected: true },
  ],
  actualLabel: "Published",
  projectedLabel: "Projected",
  facts: [
    { value: "42,595", label: "New vulnerabilities disclosed in the ENISA reporting period, up 27%." },
    { value: "33%", label: "Rated high or critical — 7% critical, 26% high." },
  ],
  ai: {
    title: "The curve is not flattening",
    body: "As AI tools speed up discovery, the number of findings that need evaluation and tracking grows with it.",
  },
  source:
    "ENISA Threat Landscape 2025; CVE Program Metrics 2020–2025. Figures from 2026 on are an exponential fit to those totals, not a forecast. The 42,595 count is ENISA's reporting period and does not line up with a calendar year.",
};

/* 4 ---------------------------------------------------------- workflow --- */

export const workflow = {
  heading: "Vulnerability reporting workflow",
  lede: "The 24-hour and 72-hour deadlines both run from the company's awareness.",
  stages: [
    { at: "24 hours", title: "Early warning", body: "Alerting for an actively exploited vulnerability or severe incident." },
    { at: "72 hours", title: "Notification", body: "Affected product information, measures taken and user protection steps." },
    { at: "14 days", title: "Actively exploited vulnerability", body: "Final report, once a corrective or mitigating measure becomes available." },
    { at: "1 month", title: "Severe incident", body: "Final report, after the 72-hour notification." },
  ],
  closing: "Reports are submitted through the CRA Single Reporting Platform.",
};

/* 5 ------------------------------------------------------------ market --- */

export const market = {
  heading: "What the current market lacks",
  lede: "Current solutions detect vulnerabilities. None of them automate CRA compliance.",
  columns: [
    {
      title: "What the market delivers",
      items: ["Vulnerability detection", "Severity scores", "SBOMs and scan reports", "Point-in-time security findings"],
    },
    {
      title: "What the market misses",
      items: [
        "Evidence tied to the shipped product version",
        "Annex VII technical documentation compatibility",
        "Risk assessment, and how the risks were addressed",
        "An SBOM tied to the shipped image",
      ],
      mark: true,
    },
  ],
};

/* 6 ------------------------------------------------------------ manual --- */

export const manual = {
  heading: "The manual work",
  lede: "Each vulnerability creates the same work again.",
  steps: [
    { title: "Break down the release", body: "Catalogue every component and library in the release." },
    { title: "Assess the exposure", body: "Trace each vulnerability to the affected product and version." },
    { title: "Prove the vulnerability was patched", body: "Prepare the remediation evidence and show the fix shipped." },
    { title: "Submit the evidence", body: "Enter the required information by hand through the CRA reporting process." },
  ],
  clock: "24h early warning. 72h notification. The countdown begins with manufacturer awareness.",
};

/* 7 -------------------------------------------------------- automation --- */

export const does = {
  eyebrow: "Our product",
  name: "Actis",
  heading: "PandaX automates everything",
  lede: "Connect the evidence. Draft the documents. File with approval.",
  points: [
    "Connects existing evidence from configured Jira, CI/CD, SBOM and document sources to the relevant product version.",
    "Identifies missing evidence, flags missing inputs and drafts all required legal documents.",
    "After your company's approval, files the reports and retains a time-stamped audit trail of every submission.",
  ],
  closing: "Nothing is submitted without the company's explicit authorization.",
  action: { label: "See what Actis produces", href: "/actis/" },
};

/* 7b ----------------------------------------------------- questions --- */

export const questions = {
  heading: "The proof,",
  highlight: "assembled once.",
  items: [
    {
      glyph: "evidence",
      title: "Evidence, not just findings",
      body: "A scanner hands you a list. Actis ties every component, finding and decision to the release that shipped, so there is something to show when proof is asked for.",
    },
    {
      glyph: "document",
      title: "The documents, generated",
      body: "Annex VII technical documentation and the Annex V declaration, drafted in the format the regulation asks for, with the missing inputs flagged rather than guessed.",
    },
    {
      glyph: "again",
      title: "No more rebuilding by hand",
      body: "The work that repeats on every release \u2014 inventory, exposure, remediation proof, submission \u2014 runs once and keeps its own history.",
    },
  ],
};

/* 8 ------------------------------------------------------------ source --- */

export const source = {
  heading: "Your source code never leaves your environment",
  lede: "PandaX works from the SBOM, not the code.",
  points: [
    "The company provides only the SBOM.",
    "PandaX never receives or views your source code. It stays inside your environment.",
    "If an SBOM is not available, PandaX provides the tools to generate one locally and export it.",
  ],
};

/* 9 -------------------------------------------------------- capability --- */

export const capability = {
  heading: "What PandaX does",
  items: [
    { title: "Release evidence mapping", body: "Links each product release to SBOMs, tests, risks, tickets and approvals." },
    { title: "Gap review", body: "Audits evidence against Annex VII and SRP requirements to pinpoint compliance gaps." },
    { title: "Follows every update", body: "Syncs submission content across product revisions and regulatory changes." },
    { title: "Evidence history", body: "Maintains dated, protected evidence for the retention period the CRA requires." },
    { title: "Create legal documents", body: "Generates documents that follow the applicable legal standards." },
    { title: "Submit the reports", body: "Guides approved technical reports through submission to ENISA." },
  ],
  closing: {
    title: "Designed for small manufacturers",
    body: "Meet the CRA without adding a dedicated legal or compliance team.",
  },
};

export const action = {
  lead: "Ready to see",
  highlight: "Actis",
  tail: "in action?",
  body: "One run against one firmware image, and the record it seals. Components, findings, the fix that shipped, and the proof it was signed off — this is what comes out the other side.",
  cta: { label: "See Actis", href: "/actis/" },
};

export const contact = {
  heading: "Get in touch",
  body: "Tell us what you build and which release is next.",
  fields: { name: "Name", email: "Work email", company: "Company", message: "What do you build?", submit: "Send" },
  fallbackAddress: "contact@pandax.online",
  sending: "Sending\u2026",
  sent: "Thank you. Your message is with us, and we will come back to you shortly.",
};

export const footer = {
  lines: ["PandaX", "Product security evidence for the EU Cyber Resilience Act"],
  links: [
    { label: "Actis", href: "/actis/" },
    { label: "Privacy", href: "/privacy/" },
  ],
  legal:
    "PandaX produces compliance documentation. It does not issue conformity opinions, certificates or verdicts.",
};

/* ------------------------------------------------------------- /actis --- */

export const actis = {
  title: "Actis",
  description:
    "Actis is the PandaX product: it turns a product release into the record the Cyber Resilience Act asks for.",
  heading: "Actis",
  lede: "The product. A release goes in, a reviewable record comes out.",
  body: "Actis is built by PandaX. It reads an SBOM, matches it against public advisory sources, records what you decide about each finding, generates the documents, and seals the result to the release that shipped.",
  runs: { heading: "What it does", note: "One command. The record is the output, not a by-product." },
  record: {
    heading: "What a record looks like",
    lede: "Every run produces one of these. This is an example, not a customer's.",
  },
  pack: {
    heading: "What you get",
    items: [
      { title: "Component inventory", body: "An SBOM tied to the release that shipped." },
      { title: "Findings", body: "Each with the upgrade that clears it." },
      { title: "Decisions", body: "What you decided, who decided it, and why." },
      { title: "Documents", body: "Annex VII technical documentation and the Annex V declaration." },
      { title: "Reporting timeline", body: "The Article 14 record, stage by stage." },
      { title: "Sealed bundle", body: "Timestamped, and verifiable without Actis installed." },
    ],
    closing: "Open format. You own it, and you can take it to any reviewer.",
  },
  state: {
    heading: "What exists today",
    now: [
      "Ingest a release and build the component inventory.",
      "Match against public advisory sources, with failed sources shown as failed.",
      "Record decisions with their rationale, author and date.",
      "Generate the documents and seal the result.",
      "Verify a sealed bundle from a clean machine, with a key supplied separately.",
    ],
    building: [
      "The hosted workspace, for more than one person.",
      "Connectors into Jira, CI/CD and document systems.",
      "Scheduled advisory monitoring that opens cases on its own.",
    ],
    nowLabel: "Working today",
    buildingLabel: "Being built",
  },
  action: { label: "Book a 30-minute walkthrough", href: "/#contact" },
};

/* ------------------------------------------------------------- legal --- */

export const legalPages = {
  privacy: {
    title: "Privacy",
    description: "How this website handles personal data.",
    heading: "Privacy",
    updated: "Last updated 13 September 2026.",
  },
};

export const privacyBody = {
  intro:
    "This notice explains what happens to personal data when you use this website. It is short because the site does very little with it.",
  sections: [
    {
      title: "Who is responsible",
      body: "PandaX operates this website and decides how the data described here is handled. Questions about this notice, or any request below, can go to contact@pandax.online.",
    },
    {
      title: "What the site collects",
      body: "Nothing on its own. This website sets no cookies, runs no analytics and embeds no third-party services, so no consent banner is needed. Nothing is stored on your device beyond what is technically necessary to serve the page.",
    },
    {
      title: "Server logs",
      body: "The hosting provider records standard request data — IP address, time, requested file, referrer and user agent — in order to deliver and secure the site. These logs are kept only as long as that purpose requires. Legal basis: Art. 6(1)(f) GDPR.",
    },
    {
      title: "If you write to us",
      body: "The details you send through the contact form or by email are used to answer you, and kept for as long as the enquiry requires. Legal basis: Art. 6(1)(b) and (f) GDPR. The form posts to our own address; there is no third-party form service.",
    },
    {
      title: "Fonts and images",
      body: "Everything is served from this domain. No request is made to Google Fonts or to any other external host, so no data reaches a third party by loading the page.",
    },
    {
      title: "Hosting",
      body: "The site is hosted by Cloudflare, Inc. and served from its global edge network, which means the server nearest you answers the request. Cloudflare handles this data as our hosting provider.",
    },
    {
      title: "Your rights",
      body: "You have the right of access, rectification, erasure, restriction, data portability and objection. You can exercise any of these by writing to contact@pandax.online. You also have the right to complain to your local data protection supervisory authority.",
    },
  ],
  // TODO(legal): once the operating entity is registered, add its legal name,
  // registered address and — if the site keeps targeting Germany — an Impressum
  // per § 5 DDG. Nothing on the page states anything untrue without them.
};
