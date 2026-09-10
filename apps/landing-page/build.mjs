/**
 * Renders the static pages from content/en.mjs.
 *
 * The site ships as plain files to Cloudflare static assets — there is no
 * framework and no bundler. This script exists only so that all copy lives in
 * one editable file, per the brief. Generated HTML is committed alongside it.
 *
 *   node build.mjs
 *
 * Never edit the generated .html files by hand; they are overwritten.
 */

import { writeFileSync, mkdirSync } from "node:fs";
import * as C from "./content/en.mjs";

/** Set to post the forms somewhere. Empty string falls back to mailto. */
const FORM_ENDPOINT = process.env.PANDAX_FORM_ENDPOINT ?? "";

const esc = (s) =>
  String(s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

/** Mono is reserved for machine-generated identifiers. */
const id = (s) => `<span class="id">${esc(s)}</span>`;

const rel = (depth) => (depth ? "../".repeat(depth) : "");

function shell({ ogTitle, description, depth = 0, slug = "", body, script = "" }) {
  // The browser tab shows the brand alone, by request. The descriptive
  // title stays in og:title and the meta description.
  const title = C.meta.brand;
  const canonical = `https://${C.meta.domain}/${slug}`;
  const r = rel(depth);
  return `<!doctype html>
<html lang="${C.meta.lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<link rel="canonical" href="${canonical}">
<meta property="og:type" content="website">
<meta property="og:title" content="${esc(ogTitle)}">
<meta property="og:description" content="${esc(description)}">
<meta property="og:image" content="https://${C.meta.domain}/assets/favicon-512.png">
<meta name="theme-color" content="#F2F2F0">

<link rel="icon" href="${r}assets/favicon-32.png" sizes="32x32" type="image/png">
<link rel="icon" href="${r}assets/favicon-dark-32.png" sizes="32x32" type="image/png" media="(prefers-color-scheme: dark)">
<link rel="apple-touch-icon" href="${r}assets/favicon-180.png">

<link rel="preload" as="font" type="font/woff2" href="${r}assets/fonts/archivo-var.woff2" crossorigin>
<link rel="preload" as="font" type="font/woff2" href="${r}assets/fonts/inter-var.woff2" crossorigin>
<link rel="stylesheet" href="${r}pandax.css">

<script type="application/ld+json">
${JSON.stringify({
  "@context": "https://schema.org",
  "@type": "Organization",
  name: C.meta.brand,
  url: `https://${C.meta.domain}/`,
  description: C.meta.tagline,
  logo: `https://${C.meta.domain}/assets/favicon-512.png`,
}, null, 2)}
</script>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
${header(depth)}
<main id="main">
${body}
</main>
${footer(depth)}
${script ? `<script src="${r}pandax.js" defer></script>` : ""}
</body>
</html>
`;
}

function header(depth) {
  const r = rel(depth);
  const home = depth ? `${r}index.html` : "#top";
  const links = depth
    ? ""
    : C.nav.links.map((l) => `<a href="${l.href}">${esc(l.label)}</a>`).join("\n        ");
  return `<header class="head">
  <div class="wrap head-in">
    <a class="mark" href="${home}">
      <img src="${r}assets/favicon-512.png" alt="" width="26" height="26">
      <span>${esc(C.meta.brand)}</span>
    </a>
    <nav class="head-nav" aria-label="Sections">
        ${links}
    </nav>
    <a class="btn btn-sm" href="${depth ? `${r}index.html#contact` : C.nav.action.href}">${esc(C.nav.action.label)}</a>
  </div>
</header>`;
}

function footer(depth) {
  const r = rel(depth);
  const links = C.footer.links
    .map((l) => `<a href="${l.href === "/partners/" && depth ? `${r}partners/` : l.href}">${esc(l.label)}</a>`)
    .join("\n      ");
  return `<footer class="foot">
  <div class="wrap foot-in">
    <div class="foot-brand">
      <img src="${r}assets/favicon-512.png" alt="" width="22" height="22">
      <span>${esc(C.footer.lines[0])}</span>
      <span class="foot-tag">${esc(C.footer.lines[1])}</span>
    </div>
    <nav class="foot-links" aria-label="Site">
      ${links}
    </nav>
    <p class="foot-legal">${esc(C.footer.legal)}</p>
  </div>
</footer>`;
}

/* ---------------------------------------------------------------- hero ---- */

function heroRecord(rec) {
  const stats = rec.stats
    .map(
      (s, i) => `<div class="rec-stat" data-i="${i}">
          <span class="rec-stat-v" data-count="${esc(s.value)}">${esc(s.value)}</span>
          <span class="rec-stat-l">${esc(s.label)}</span>
        </div>`)
    .join("\n        ");

  const checks = rec.checks
    .map(
      (c, i) => `<li data-i="${i}"><span class="tick" aria-hidden="true"></span>${esc(c)}</li>`)
    .join("\n            ");

  return `<div class="rec" id="rec" aria-label="Example evidence record">
        <div class="rec-top">
          <span class="rec-flag">${esc(rec.label)}</span>
          <span class="rec-seal" id="recSeal"><span class="seal-dot" aria-hidden="true"></span>Sealed</span>
        </div>

        <div class="rec-head">
          <div class="rec-title">${esc(rec.product)} <span class="rec-rel">${esc(rec.release)}</span></div>
          <dl class="rec-ids">
            <div><dt>Run</dt><dd>${id(rec.runId)}</dd></div>
            <div><dt>Sealed</dt><dd><time datetime="${esc(rec.sealed)}">${id(rec.sealed)}</time></dd></div>
            <div class="rec-wide"><dt>Image</dt><dd>${id(rec.image)}</dd></div>
            <div class="rec-wide"><dt>SHA-256</dt><dd>${id(rec.sha256)}</dd></div>
          </dl>
        </div>

        <div class="rec-stats">
        ${stats}
        </div>

        <div class="rec-split">
          <div class="rec-checks">
            <h3>Release checks</h3>
            <ul class="checks">
            ${checks}
            </ul>
          </div>
          <div class="rec-finding">
            <h3>Open finding</h3>
            <p class="fx-id">${id(rec.finding.cve)} <span class="fx-comp">${id(rec.finding.component)}</span></p>
            <p class="fx-note">${esc(rec.finding.note)}</p>
            <p class="fx-fix"><span class="fx-arrow" aria-hidden="true"></span>${esc(rec.finding.fix)}</p>
            <p class="fx-dec">${esc(rec.finding.decision)}</p>
          </div>
        </div>
      </div>`;
}

function heroSection() {
  const h = C.hero;
  return `<section class="hero" id="top">
  <div class="wrap hero-in">
    <div class="hero-copy">
      <h1>${esc(h.headline)}</h1>
      <p class="lede">${esc(h.subhead)}</p>
      <div class="acts">
        <a class="btn" href="${h.primary.href}">${esc(h.primary.label)}</a>
        <a class="btn btn-q" href="${h.secondary.href}">${esc(h.secondary.label)}</a>
      </div>
    </div>

    <div class="hero-stage">
      <div class="lap" id="lap">
        <div class="lap-lid">
          <div class="lap-back" aria-hidden="true"><span class="lap-mark"></span></div>
          <div class="lap-bezel">
            <span class="lap-cam" aria-hidden="true"></span>
            <div class="lap-screen">
              ${heroRecord(h.record)}
            </div>
            <div class="lap-glare" aria-hidden="true"></div>
          </div>
        </div>
        <div class="lap-base" aria-hidden="true"><span class="lap-notch"></span></div>
        <div class="lap-shadow" aria-hidden="true"></div>
      </div>
    </div>
  </div>
</section>`;
}

/* ------------------------------------------------------------ sections ---- */

function deadlinesSection() {
  const d = C.deadlines;
  // Derived, not asserted: whichever day this is built, the label is true.
  const today = new Date().toISOString().slice(0, 10);
  const rows = d.rows
    .map(
      (r) => `<tr class="dl-${r.state === "active" && r.iso > today ? "active dl-soon" : r.state}">
        <th scope="row"><time datetime="${esc(r.iso)}">${esc(r.date)}</time></th>
        <td>${esc(r.title)}</td>
        <td class="dl-state">${
          r.state === "active"
            ? `<span class="live"><span class="live-dot" aria-hidden="true"></span>${esc(r.iso <= today ? r.stateLabel : "Applies soon")}</span><span class="since" data-since="${esc(r.iso)}"></span>`
            : r.state === "past"
            ? "Passed"
            : "Upcoming"
        }</td>
      </tr>`)
    .join("\n      ");

  return `<section class="sec" id="dates">
  <div class="wrap">
    <h2>${esc(d.heading)}</h2>
    <table class="tbl dl">
      <caption class="vh">Cyber Resilience Act application dates</caption>
      <tbody>
      ${rows}
      </tbody>
    </table>
    <p class="note">${esc(d.note)}</p>
  </div>
</section>`;
}

function gapSection() {
  const g = C.gap;
  const col = (c) => `<div class="gap-col">
        <h3>${esc(c.title)}</h3>
        <ul class="rule-list">${c.items.map((i) => `<li>${esc(i)}</li>`).join("")}</ul>
      </div>`;
  return `<section class="sec" id="gap">
  <div class="wrap">
    <h2>${esc(g.heading)}</h2>
    <div class="gap">
      ${g.columns.map(col).join("\n      ")}
    </div>
    <p class="closer">${esc(g.closing)}</p>
  </div>
</section>`;
}

function clockSection() {
  const c = C.clock;
  const rows = c.rows
    .map(
      (r, i) => `<div class="ck" data-stage="${i}">
        <div class="ck-at">${esc(r.at)}</div>
        <div class="ck-title">${esc(r.title)}</div>
        <div class="ck-run" data-countdown="${i}" aria-hidden="true"></div>
      </div>`)
    .join("\n      ");
  return `<section class="sec sec-dark" id="clock">
  <div class="wrap">
    <h2>${esc(c.heading)}</h2>
    <div class="cks" id="cks">
      ${rows}
    </div>
    <p class="note note-dark">${esc(c.recipients)}</p>
    <p class="closer closer-dark">${esc(c.closing)}</p>
  </div>
</section>`;
}

function howSection() {
  const h = C.how;
  const stages = h.stages
    .map(
      (s, i) => `<li class="stage" data-i="${i}">
        <span class="stage-n">${i + 1}</span>
        <h3>${esc(s.title)}</h3>
        <p>${esc(s.body)}</p>
      </li>`)
    .join("\n      ");
  return `<section class="sec" id="how">
  <div class="wrap">
    <h2>${esc(h.heading)}</h2>
    <ol class="stages" id="stages">
      <span class="stage-line" aria-hidden="true"><i id="stageFill"></i></span>
      ${stages}
    </ol>
    <p class="note">${h.notes.map(esc).join(" ")}</p>
  </div>
</section>`;
}

function exportSection() {
  const e = C.exportPack;
  const rows = e.items
    .map(
      (i) => `<tr><th scope="row">${esc(i.title)}</th><td>${esc(i.body)}</td></tr>`)
    .join("\n      ");
  return `<section class="sec" id="export">
  <div class="wrap">
    <h2>${esc(e.heading)}</h2>
    <table class="tbl">
      <caption class="vh">Contents of a PandaX evidence export</caption>
      <tbody>
      ${rows}
      </tbody>
    </table>
    <p class="closer">${esc(e.closing)}</p>
  </div>
</section>`;
}

function proofSection() {
  const p = C.proof;
  return `<section class="sec" id="proof">
  <div class="wrap">
    <h2>${esc(p.heading)}</h2>
    <p class="lede lede-sm">${esc(p.body)}</p>
    <div class="shot-todo">
      <span class="shot-todo-t">${esc(p.placeholder.title)}</span>
      <span class="shot-todo-b">${esc(p.placeholder.body)}</span>
    </div>
  </div>
</section>`;
}

function audienceSection() {
  const a = C.audience;
  return `<section class="sec" id="who">
  <div class="wrap">
    <h2>${esc(a.heading)}</h2>
    <p class="lede lede-sm">${esc(a.body)}</p>
    <ul class="rule-list rule-list-wide">${a.points.map((p) => `<li>${esc(p)}</li>`).join("")}</ul>
  </div>
</section>`;
}

function labsSection() {
  const l = C.labs;
  const rows = l.points
    .map((p) => `<tr><th scope="row">${esc(p.title)}</th><td>${esc(p.body)}</td></tr>`)
    .join("\n      ");
  return `<section class="sec" id="labs">
  <div class="wrap">
    <h2>${esc(l.heading)}</h2>
    <p class="lede lede-sm">${esc(l.body)}</p>
    <table class="tbl">
      <caption class="vh">Guardrails for testing, inspection and certification firms</caption>
      <tbody>
      ${rows}
      </tbody>
    </table>
    <p><a class="lnk" href="${l.action.href}">${esc(l.action.label)}</a></p>
  </div>
</section>`;
}

function faqSection() {
  const f = C.faq;
  const items = f.items
    .map(
      (i) => `<details class="qa">
        <summary><span>${esc(i.q)}</span></summary>
        <div class="qa-a"><p>${esc(i.a)}</p></div>
      </details>`)
    .join("\n      ");
  return `<section class="sec" id="faq">
  <div class="wrap">
    <h2>${esc(f.heading)}</h2>
    <div class="qas">
      ${items}
    </div>
  </div>
</section>`;
}

function formBlock(heading, body, kind) {
  const c = C.contact;
  const action = FORM_ENDPOINT || `mailto:${c.fallbackAddress}`;
  return `<div class="form-wrap">
      <h2>${esc(heading)}</h2>
      <p class="lede lede-sm">${esc(body)}</p>
      <form class="form" method="post" action="${esc(action)}"${FORM_ENDPOINT ? "" : ' enctype="text/plain"'}>
        <input type="hidden" name="kind" value="${esc(kind)}">
        <p class="hp"><label>Leave this empty<input type="text" name="company_url" tabindex="-1" autocomplete="off"></label></p>
        <div class="row">
          <label>${esc(c.fields.name)}<input type="text" name="name" required autocomplete="name"></label>
          <label>${esc(c.fields.email)}<input type="email" name="email" required autocomplete="email"></label>
        </div>
        <label>${esc(c.fields.company)}<input type="text" name="company" autocomplete="organization"></label>
        <label>${esc(c.fields.message)}<textarea name="message" rows="4"></textarea></label>
        <button class="btn" type="submit">${esc(c.fields.submit)}</button>
      </form>
    </div>`;
}

function closingSection() {
  const cl = C.closing;
  const c = C.contact;
  return `<section class="sec sec-close" id="contact">
  <div class="wrap close-in">
    <div>
      <h2>${esc(cl.heading)}</h2>
      <p class="lede lede-sm">${esc(cl.body)}</p>
    </div>
    ${formBlock(c.heading, c.body, "sample")}
  </div>
</section>`;
}

/* --------------------------------------------------------------- pages ---- */

const home = shell({
  ogTitle: `${C.meta.brand} — CRA compliance evidence for connected products`,
  description: C.hero.subhead,
  body: [
    heroSection(),
    deadlinesSection(),
    gapSection(),
    clockSection(),
    howSection(),
    exportSection(),
    proofSection(),
    audienceSection(),
    labsSection(),
    faqSection(),
    closingSection(),
  ].join("\n\n"),
  script: true,
});

const p = C.partners;
const partnersPage = shell({
  slug: "partners/",
  ogTitle: `${C.meta.brand} — Partners`,
  description: p.description,
  depth: 1,
  body: `<section class="sec sec-lead">
  <div class="wrap">
    <h1>${esc(p.heading)}</h1>
    <p class="lede">${esc(p.intro)}</p>
  </div>
</section>

<section class="sec">
  <div class="wrap">
    <h2>${esc(p.guardrails.heading)}</h2>
    <table class="tbl">
      <caption class="vh">Guardrails</caption>
      <tbody>
      ${p.guardrails.items.map((i) => `<tr><th scope="row">${esc(i.title)}</th><td>${esc(i.body)}</td></tr>`).join("\n      ")}
      </tbody>
    </table>
  </div>
</section>

<section class="sec">
  <div class="wrap">
    <h2>${esc(p.models.heading)}</h2>
    <table class="tbl">
      <caption class="vh">Ways to work together</caption>
      <tbody>
      ${p.models.items.map((i) => `<tr><th scope="row">${esc(i.title)}</th><td>${esc(i.body)}</td></tr>`).join("\n      ")}
      </tbody>
    </table>
  </div>
</section>

<section class="sec sec-close">
  <div class="wrap close-in close-one">
    ${formBlock(p.form.heading, p.form.body, "partner")}
  </div>
</section>`,
});

function legalPage(key, extra) {
  const L = C.legalPages[key];
  return shell({
    slug: `${key}/`,
    ogTitle: `${C.meta.brand} — ${L.title}`,
    description: L.description,
    depth: 1,
    body: `<section class="sec sec-lead">
  <div class="wrap narrow">
    <h1>${esc(L.heading)}</h1>
    <p class="note">${esc(L.note)}</p>
    ${extra}
  </div>
</section>`,
  });
}

const impressumBody = C.legalPages.impressum.sections
  .map(
    (s) => `<h2>${esc(s.title)}</h2>
    <table class="tbl tbl-legal"><tbody>
    ${s.rows.map(([k, v]) => `<tr><th scope="row">${esc(k)}</th><td>${v.startsWith("TODO") ? `<span class="todo">${esc(v)}</span>` : esc(v)}</td></tr>`).join("\n    ")}
    </tbody></table>`)
  .join("\n\n    ");

const privacySections = C.privacyBody.sections
  .map(
    (s) => `<h2>${esc(s.title)}</h2>
    <p>${s.body.split(/(TODO[^.]*\.)/).map((part) => (part.startsWith("TODO") ? `<span class="todo">${esc(part)}</span>` : esc(part))).join("")}</p>`)
  .join("\n\n    ");

/* --------------------------------------------------------------- write ---- */

const pages = [
  ["index.html", home],
  ["partners/index.html", partnersPage],
  ["impressum/index.html", legalPage("impressum", impressumBody)],
  ["datenschutz/index.html", legalPage("datenschutz", privacySections)],
  ["privacy/index.html", legalPage("privacy", privacySections)],
];

for (const [path, html] of pages) {
  const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : null;
  if (dir) mkdirSync(new URL(dir, import.meta.url), { recursive: true });
  writeFileSync(new URL(path, import.meta.url), html);
  console.log(`${path.padEnd(26)} ${(html.length / 1024).toFixed(1)} KB`);
}
console.log(FORM_ENDPOINT ? `forms post to ${FORM_ENDPOINT}` : "forms fall back to mailto");
