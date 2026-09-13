/**
 * Renders the static pages from content/en.mjs.
 *
 * The site ships as plain files to Cloudflare static assets — no framework, no
 * bundler. This script exists only so all copy lives in one editable file.
 * Generated HTML is committed alongside it.
 *
 *   node build.mjs
 */

import { writeFileSync, mkdirSync } from "node:fs";
import * as C from "./content/en.mjs";

/** Set to post the forms somewhere. Empty falls back to mailto. */
const FORM_ENDPOINT = process.env.PANDAX_FORM_ENDPOINT ?? "";

const esc = (s) =>
  String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

/** Mono is reserved for machine-generated identifiers. */
const id = (s) => `<span class="id">${esc(s)}</span>`;
const rel = (d) => (d ? "../".repeat(d) : "");
const n2 = (i) => String(i + 1).padStart(2, "0");

function shell({ ogTitle, description, depth = 0, slug = "", body, script = false, doc = false }) {
  const bodyClass = doc ? ' class="doc"' : "";
  const r = rel(depth);
  return `<!doctype html>
<html lang="${C.meta.lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(C.meta.brand)}</title>
<meta name="description" content="${esc(description)}">
<link rel="canonical" href="https://${C.meta.domain}/${slug}">
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
<body${bodyClass}>
<a class="skip" href="#main">Skip to content</a>
${header(depth)}
<main id="main">
${body}
</main>
${footer(depth)}
${script ? `<script>window.PANDAX_RECORDS = ${JSON.stringify(C.hero.records)};</script>\n<script src="${r}pandax.js" defer></script>` : ""}
</body>
</html>
`;
}

function productsMenu(depth) {
  const r = rel(depth);
  const items = C.nav.products
    .map((p) => `<a class="menu-item" href="${r}${p.href}">
          <img src="${r}${p.mark}" alt="" width="36" height="36">
          <span><strong>${esc(p.name)}</strong><small>${esc(p.blurb)}</small></span>
        </a>`).join("\n        ");
  return `<div class="menu" id="menu">
      <button class="menu-btn" id="menuBtn" aria-expanded="false" aria-controls="menuPanel">
        ${esc(C.nav.productsLabel)}<span class="menu-chev" aria-hidden="true"></span>
      </button>
      <div class="menu-panel" id="menuPanel">
        ${items}
      </div>
    </div>`;
}

function header(depth) {
  const r = rel(depth);
  const links = depth ? "" : C.nav.links.map((l) => `<a href="${l.href}">${esc(l.label)}</a>`).join("\n        ");
  return `<header class="head">
  <div class="wrap head-in">
    <a class="mark" href="${depth ? `${r}index.html` : "#top"}">
      <img src="${r}assets/favicon-512.png" alt="" width="26" height="26">
      <span>${esc(C.meta.brand)}</span>
    </a>
    <nav class="head-nav" aria-label="Sections">
        ${links}
    </nav>
    ${productsMenu(depth)}
    <a class="btn btn-sm" href="${depth ? `${r}index.html#contact` : C.nav.action.href}">${esc(C.nav.action.label)}</a>
  </div>
</header>`;
}

function footer(depth) {
  const r = rel(depth);
  const links = C.footer.links
    .map((l) => `<a href="${depth && l.href.startsWith("/") ? r + l.href.slice(1) : l.href}">${esc(l.label)}</a>`)
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


/* 1 ------------------------------------------------------------- hero --- */

function screen(rec) {
  const stats = rec.stats
    .map((s, i) => `<div class="sc-stat"${i === 2 ? ' data-mark="1"' : ""}>
              <span class="sc-v" data-count="${esc(s.value)}">${esc(s.value)}</span>
              <span class="sc-l">${esc(s.label)}</span>
            </div>`).join("\n            ");
  const checks = rec.checks
    .map((c, i) => `<li data-i="${i}"><span class="tick" aria-hidden="true"></span>${esc(c)}</li>`).join("");
  return `<div class="sc" id="sc">
          <div class="sc-bar" aria-hidden="true">
            <span class="sc-dots"><i></i><i></i><i></i></span>
            <span class="sc-app">${esc(C.meta.product)}</span>
          </div>
          <div class="sc-body">
            <div class="sc-head">
              <span class="sc-flag">${esc(rec.label)}</span>
              <span class="sc-seal" id="scSeal"><span class="seal-dot" aria-hidden="true"></span>Sealed</span>
            </div>
            <div class="sc-title"><span data-f="product">${esc(rec.product)}</span> <span data-f="release">${esc(rec.release)}</span></div>
            <div class="sc-run"><span class="id" data-f="runId">${esc(rec.runId)}</span></div>
            <div class="sc-stats">
            ${stats}
            </div>
            <ul class="sc-checks">${checks}</ul>
            <div class="sc-fix">
              <span class="fx-arrow" aria-hidden="true"></span>
              <span class="id" data-f="cve">${esc(rec.finding.cve)}</span> in <span class="id" data-f="component">${esc(rec.finding.component)}</span> — <span data-f="fix">${esc(rec.finding.fix)}</span>
            </div>
          </div>
        </div>`;
}

const KEYS = [
  ["lk-fn", "esc F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 ⏻"],
  ["lk-num", "~ 1 2 3 4 5 6 7 8 9 0 - = |delete"],
  ["lk-q", "|tab Q W E R T Y U I O P [ ] \\"],
  ["lk-a", "|caps A S D F G H J K L ; ' |return"],
  ["lk-z", "!shift Z X C V B N M , . / !shift"],
  ["lk-sp", "fn ⌃ ⌥ ⌘ = ⌘ ⌥ ◀ ▲▼ ▶"],
];


function keyboard() {
  const rows = KEYS.map(([cls, keys]) => {
    const cells = keys.split(" ").map((k) => {
      if (k === "=") return `<span class="lk-bar"></span>`;
      if (k.startsWith("|")) return `<span class="lk-w">${esc(k.slice(1))}</span>`;
      if (k.startsWith("!")) return `<span class="lk-w2">${esc(k.slice(1))}</span>`;
      return `<span>${esc(k)}</span>`;
    }).join("");
    return `<div class="lk-row ${cls}">${cells}</div>`;
  }).join("\n          ");
  return `<div class="laptop-keys" aria-hidden="true">
          ${rows}
        </div>`;
}

/** The engine, typed out. Used on the product page. */
function terminal() {
  const pl = C.pipeline;
  const lines = pl.lines
    .map((l, i) => `<li data-i="${i}">
          <span class="t-p" aria-hidden="true">&rsaquo;</span>
          <span class="t-c">${esc(l.cmd)}</span>
          <span class="t-a">${esc(l.arg)}</span>
          <span class="t-o">${esc(l.out)}</span>
        </li>`).join("\n        ");
  return `<div class="term" id="term">
      <div class="term-bar" aria-hidden="true"><i></i><i></i><i></i><span>actis</span></div>
      <ol class="term-lines">
        ${lines}
        <li class="t-caret" aria-hidden="true"><span class="t-p">&rsaquo;</span><span class="caret"></span></li>
      </ol>
    </div>`;
}

/** The evidence path, drawn as one line: a release goes in, a record comes out.
 *  Continuous motion, no JS — everything travels and breathes in CSS. */
function scene() {
  return `<svg class="scene" viewBox="0 0 600 460" role="img"
     aria-label="A release enters, is matched against sources, weighed at a decision, and leaves as a sealed record.">
  <defs>
    <!-- Radial, and fully transparent before the edge, so nothing is clipped. -->
    <radialGradient id="wash-a">
      <stop offset="0%"   stop-color="#B0801F" stop-opacity="0.34"/>
      <stop offset="55%"  stop-color="#D9AE55" stop-opacity="0.16"/>
      <stop offset="100%" stop-color="#D9AE55" stop-opacity="0"/>
    </radialGradient>
    <radialGradient id="wash-b">
      <stop offset="0%"   stop-color="#4A4FA8" stop-opacity="0.24"/>
      <stop offset="55%"  stop-color="#B4577E" stop-opacity="0.12"/>
      <stop offset="100%" stop-color="#B4577E" stop-opacity="0"/>
    </radialGradient>
    <path id="route"
      d="M108 176 C 176 176, 178 108, 246 108 C 314 108, 318 244, 386 244
         C 442 244, 452 336, 502 336"/>
  </defs>

  <circle class="wash"   cx="212" cy="178" r="162" fill="url(#wash-a)"/>
  <circle class="wash wash-2" cx="406" cy="296" r="156" fill="url(#wash-b)"/>

  <g class="ink" fill="none" stroke-linecap="round" stroke-linejoin="round">

    <use href="#route" class="route"/>

    <!-- the release, as a box being opened -->
    <g class="node node-in">
      <path d="M34 150 L82 124 L130 150 L82 176 Z"/>
      <path d="M34 150 L34 208 L82 234 L82 176"/>
      <path d="M130 150 L130 208 L82 234"/>
      <path class="thin" d="M58 163 L58 221"/>
      <path class="thin" d="M82 124 L82 176"/>
    </g>

    <!-- the lattice: the mark's own geometry, where components are matched -->
    <g class="node node-mid">
      <path d="M246 56 L290 81 L290 131 L246 156 L202 131 L202 81 Z"/>
      <path class="thin" d="M246 56 L246 106 M246 106 L290 131 M246 106 L202 131"/>
      <circle class="dot node-beat" cx="246" cy="106" r="6"/>
      <circle class="orbit" cx="246" cy="106" r="70"/>
    </g>

    <!-- the decision: one route taken, one not, and the choice recorded -->
    <g class="node node-dec">
      <circle cx="386" cy="244" r="26"/>
      <path class="thin branch-off" d="M386 244 L440 206"/>
      <path class="branch-on" d="M386 244 L440 282"/>
      <circle class="dot" cx="386" cy="244" r="5.5"/>
      <circle class="dot mark-off" cx="440" cy="206" r="4"/>
    </g>

    <!-- the record: sheets, and the seal that closes them -->
    <g class="node node-out">
      <path d="M470 286 H556 a6 6 0 0 1 6 6 V404 a6 6 0 0 1 -6 6 H470 a6 6 0 0 1 -6 -6 V292 a6 6 0 0 1 6 -6 Z"/>
      <path class="thin" d="M486 314 H540 M486 334 H540 M486 354 H518"/>
      <g class="seal">
        <circle cx="546" cy="392" r="22"/>
        <path class="seal-tick" d="M535 393 l7 8 l15 -18"/>
      </g>
    </g>

    <!-- what travels the route -->
    <circle class="pulse" r="6">
      <animateMotion dur="7.5s" repeatCount="indefinite">
        <mpath href="#route"/>
      </animateMotion>
    </circle>
    <circle class="pulse pulse-2" r="4" opacity="0">
      <animate attributeName="opacity" to="1" begin="2.5s" dur="0.01s" fill="freeze"/>
      <animateMotion dur="7.5s" begin="2.5s" repeatCount="indefinite">
        <mpath href="#route"/>
      </animateMotion>
    </circle>
  </g>
</svg>`;
}

function heroSection() {
  const h = C.hero;
  return `<section class="hero" id="top">
  <div class="wrap hero-in">
    <div class="hero-copy">
      <h1>${esc(h.headline).replace(esc(h.highlight), `<span class="hl">${esc(h.highlight)}</span>`)}</h1>
      <p class="lede">${esc(h.subhead)}</p>
      <p class="lede lede-sm">${esc(h.body)}</p>
      <div class="acts">
        <a class="btn" href="${h.primary.href}">${esc(h.primary.label)}</a>
        <a class="btn btn-q" href="${h.secondary.href}">${esc(h.secondary.label)}</a>
      </div>
    </div>
    <div class="hero-stage">
      ${scene()}
    </div>
  </div>
</section>`;
}

/* 2 -------------------------------------------------------- obligation --- */

function obligationSection() {
  const o = C.obligation;
  const today = new Date().toISOString().slice(0, 10);
  const marks = o.marks
    .map((m) => {
      const past = m.iso <= today;
      const cls = m.live ? "tl-mark is-live" : past ? "tl-mark is-past" : "tl-mark";
      return `<li class="${cls}">
          <span class="tl-dot" aria-hidden="true"></span>
          <time datetime="${esc(m.iso)}">${esc(m.date)}</time>
          <span class="tl-label">${esc(m.label)}</span>
          ${m.live ? `<span class="tl-live">${esc(o.liveLabel)}</span><span class="since" data-since="${esc(m.iso)}"></span>` : ""}
        </li>`;
    }).join("\n        ");
  const points = o.points.map((x) => `<li>${esc(x)}</li>`).join("");
  return `<section class="sec" id="obligation">
  <div class="wrap">
    <h2>${esc(o.heading)}</h2>
    <p class="lede">${esc(o.lede)}</p>

    <ol class="tl" id="tl">
      <span class="tl-rail" aria-hidden="true"><i id="tlFill"></i></span>
        ${marks}
    </ol>

    <ul class="rule-list">${points}</ul>
    <p class="src">${esc(o.source)}</p>
  </div>
</section>`;
}

/* 3 ------------------------------------------------------- accelerating --- */

function growthSection() {
  const g = C.growth;
  const max = Math.max(...g.series.map((s) => s.value));
  const shown = new Set(["2020", "2025", "2030"]);   // label the turns, not every bar
  const bars = g.series
    .map((s, i) => `<div class="col${s.projected ? " is-proj" : ""}" data-i="${i}">
          <span class="col-v">${shown.has(s.year) ? esc(Math.round(s.value / 1000)) + "K" : ""}</span>
          <span class="col-bar" style="--h:${((s.value / max) * 100).toFixed(1)}%"></span>
          <span class="col-y">${esc(s.year)}</span>
        </div>`).join("\n        ");
  const rows = g.series
    .map((s) => `<tr><th scope="row">${esc(s.year)}</th><td>${s.value.toLocaleString("en-US")}${s.projected ? " (projected)" : ""}</td></tr>`).join("");
  const facts = g.facts
    .map((f) => `<div class="figure"><span class="figure-v">${esc(f.value)}</span><span class="figure-l">${esc(f.label)}</span></div>`).join("\n        ");

  return `<section class="sec" id="growth">
  <div class="wrap">
    <h2>${esc(g.heading)}</h2>
    <p class="lede">${esc(g.lede)}</p>

    <figure class="chart" id="chart">
      <figcaption class="chart-key">
        <span class="key key-actual">${esc(g.actualLabel)}</span>
        <span class="key key-proj">${esc(g.projectedLabel)}</span>
      </figcaption>
      <div class="cols">
        ${bars}
      </div>
      <table class="vh"><caption>Annual published CVEs</caption><tbody>${rows}</tbody></table>
    </figure>

    <div class="figures">
        ${facts}
    </div>

    <div class="aside">
      <h3>${esc(g.ai.title)}</h3>
      <p>${esc(g.ai.body)}</p>
    </div>

    <p class="src">${esc(g.source)}</p>
  </div>
</section>`;
}

/* 4 ---------------------------------------------------------- workflow --- */

function workflowSection() {
  const w = C.workflow;
  const stages = w.stages
    .map((s, i) => `<li class="wf" data-i="${i}">
        <span class="wf-dot" aria-hidden="true"></span>
        <span class="wf-at">${esc(s.at)}</span>
        <h3>${esc(s.title)}</h3>
        <p>${esc(s.body)}</p>
      </li>`).join("\n      ");
  return `<section class="sec sec-dark" id="workflow">
  <div class="wrap">
    <h2>${esc(w.heading)}</h2>
    <p class="lede lede-dark">${esc(w.lede)}</p>
    <ol class="wfs" id="wfs">
      <span class="wf-rail" aria-hidden="true"><i id="wfFill"></i></span>
      ${stages}
    </ol>
    <p class="closer closer-dark">${esc(w.closing)}</p>
  </div>
</section>`;
}

/* 5 ------------------------------------------------------------ market --- */

function marketSection() {
  const m = C.market;
  const col = (c) => `<div class="mk-col${c.mark ? " is-mark" : ""}">
        <h3>${esc(c.title)}</h3>
        <ul>${c.items.map((i) => `<li>${esc(i)}</li>`).join("")}</ul>
      </div>`;
  return `<section class="sec" id="market">
  <div class="wrap">
    <h2>${esc(m.heading)}</h2>
    <p class="lede">${esc(m.lede)}</p>
    <div class="mk">
      ${m.columns.map(col).join("\n      ")}
    </div>
  </div>
</section>`;
}

/* 9 -------------------------------------------------------- capability --- */

function capabilitySection() {
  const c = C.capability;
  const items = c.items
    .map((i, n) => `<li class="cap" data-i="${n}">
        <span class="cap-n">${n2(n)}</span>
        <h3>${esc(i.title)}</h3>
        <p>${esc(i.body)}</p>
      </li>`).join("\n      ");
  return `<section class="sec" id="capability">
  <div class="wrap">
    <h2>${esc(c.heading)}</h2>
    <ol class="caps">
      ${items}
    </ol>
    <div class="band">
      <h3>${esc(c.closing.title)}</h3>
      <p>${esc(c.closing.body)}</p>
    </div>
  </div>
</section>`;
}

/* 5 ------------------------------------------------------------ manual --- */

function manualSection() {
  const m = C.manual;
  const steps = m.steps
    .map((s, i) => `<li class="step" data-i="${i}">
        <span class="step-n">${n2(i)}</span>
        <h3>${esc(s.title)}</h3>
        <p>${esc(s.body)}</p>
      </li>`).join("\n      ");
  return `<section class="sec" id="manual">
  <div class="wrap">
    <h2>${esc(m.heading)}</h2>
    <p class="lede">${esc(m.lede)}</p>
    <ol class="steps" id="steps">
      <span class="step-line" aria-hidden="true"><i id="stepFill"></i></span>
      ${steps}
    </ol>
    <p class="note">${esc(m.clock)}</p>
  </div>
</section>`;
}

/* 6 -------------------------------------------------------------- does --- */

function doesSection() {
  const d = C.does;
  const points = d.points.map((x) => `<li>${esc(x)}</li>`).join("\n        ");
  return `<section class="sec sec-dark" id="does">
  <div class="wrap">
    <h2>${esc(d.heading)}</h2>
    <p class="lede lede-dark">${esc(d.lede)}</p>

    <div class="flow" id="flow" aria-hidden="true">
      <div class="flow-in">
        <span class="fl-src" data-i="0">Jira</span>
        <span class="fl-src" data-i="1">CI/CD</span>
        <span class="fl-src" data-i="2">SBOM</span>
        <span class="fl-src" data-i="3">Documents</span>
        <span class="fl-src" data-i="4">Legal</span>
      </div>
      <div class="flow-core">${esc(d.name)}</div>
      <div class="flow-out">
        <span class="fl-doc" data-i="0">Record</span>
        <span class="fl-doc" data-i="1">Documents</span>
        <span class="fl-doc" data-i="2">Audit trail</span>
      </div>
    </div>

    <ul class="rule-list rule-list-dark">
        ${points}
    </ul>
    <p class="closer closer-dark">${esc(d.closing)}</p>
    <div class="acts"><a class="btn btn-light" href="${d.action.href}">${esc(d.action.label)}</a></div>
  </div>
</section>`;
}

/* 7b -------------------------------------------------------- easier --- */

/** A stack of cards with one drawing on the face. The accent dot is the only
 *  colour in it, the way a single highlight carries a whole row. */
function cardGlyph(kind) {
  const inner = {
    record: `<rect x="34" y="36" width="52" height="42" rx="3"/>
        <path d="M34 46 H86"/>
        <circle class="g-dot" cx="46" cy="62" r="4"/>
        <path d="M50 62 H60 M64 58 L70 54 M64 66 L70 70"/>
        <circle cx="72" cy="52" r="3.5"/>
        <circle cx="72" cy="72" r="3.5"/>`,
    document: `<path d="M40 30 H74 L82 38 V84 H40 Z"/>
        <path d="M74 30 V38 H82"/>
        <path d="M48 50 H72 M48 58 H72 M48 66 H64"/>
        <circle class="g-dot" cx="70" cy="74" r="7"/>
        <path d="M66 80 L66 90 L70 87 L74 90 L74 80"/>`,
    automate: `<circle cx="66" cy="48" r="14"/>
        <circle class="g-dot" cx="66" cy="48" r="5"/>
        <path d="M66 30 V36 M66 60 V66 M48 48 H54 M78 48 H84 M54 36 L58 40 M74 56 L78 60 M54 60 L58 56 M74 40 L78 36"/>
        <path d="M36 88 V66 a5 5 0 0 1 10 0 V78 h8 a5 5 0 0 1 5 5 v5"/>`,
  }[kind];
  return `<svg class="cardart" viewBox="0 0 120 120" aria-hidden="true">
      <g fill="none" stroke-linecap="round" stroke-linejoin="round">
        <rect class="card card-3" x="22" y="22" width="86" height="86" rx="12"/>
        <rect class="card card-2" x="16" y="16" width="86" height="86" rx="12"/>
        <rect class="card card-1" x="10" y="10" width="86" height="86" rx="12"/>
        <g class="glyph">${inner}</g>
      </g>
    </svg>`;
}

function easierSection() {
  const e = C.easier;
  const items = e.items
    .map((i, n) => `<li class="ez" data-i="${n}">
        ${cardGlyph(i.glyph)}
        <h3>${esc(i.title)}</h3>
        <p>${esc(i.body)}</p>
      </li>`).join("\n      ");
  return `<section class="sec sec-ez" id="easier">
  <div class="wrap">
    <h2 class="ez-head">${esc(e.heading)} <span class="hl hl-rose">${esc(e.highlight)}</span></h2>
    <ul class="ezs">
      ${items}
    </ul>
  </div>
</section>`;
}

/* 7 ------------------------------------------------------------ source --- */

function sourceSection() {
  const s = C.source;
  const points = s.points.map((x) => `<li>${esc(x)}</li>`).join("\n        ");
  return `<section class="sec" id="source">
  <div class="wrap">
    <h2>${esc(s.heading)}</h2>
    <p class="lede">${esc(s.lede)}</p>

    <div class="bound" id="bound" aria-hidden="true">
      <div class="bound-side">
        <span class="bound-cap">Your environment</span>
        <span class="bound-item">Source code</span>
        <span class="bound-item">Build system</span>
        <span class="bound-item">Signing keys</span>
      </div>
      <div class="bound-gate">
        <span class="bound-wire"></span>
        <span class="bound-pass">SBOM</span>
        <span class="bound-wire"></span>
      </div>
      <div class="bound-side bound-side-x">
        <span class="bound-cap">PandaX</span>
        <span class="bound-item is-on">Inventory</span>
        <span class="bound-item is-on">Findings</span>
        <span class="bound-item is-on">Record</span>
      </div>
    </div>

    <ul class="rule-list">
        ${points}
    </ul>
  </div>
</section>`;
}

/* 12 ------------------------------------------------------------- close --- */

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
  const c = C.contact;
  return `<section class="sec sec-close" id="contact">
  <div class="wrap close-in close-one">
    ${formBlock(c.heading, c.body, "sample")}
  </div>
</section>`;
}

/* --------------------------------------------------------- /actis --- */

function actisPage() {
  const a = C.actis;
  const pack = a.pack.items
    .map((i) => `<tr><th scope="row">${esc(i.title)}</th><td>${esc(i.body)}</td></tr>`).join("\n      ");
  const now = a.state.now.map((x) => `<li>${esc(x)}</li>`).join("");
  const building = a.state.building.map((x) => `<li>${esc(x)}</li>`).join("");

  return shell({
    slug: "actis/",
    ogTitle: `${esc(C.meta.product)} — ${esc(C.meta.tagline)}`,
    description: a.description,
    depth: 1,
    script: true,
    body: `<section class="sec sec-lead" id="top">
  <div class="wrap">
    <div class="hero-in">
      <div class="prod-text">
        <div class="pname-lead">
          <span class="pname-eyebrow">${esc(C.does.eyebrow)}</span>
          <h1 class="pname-word">
            <img class="pname-mark" src="../assets/actis-mark.png" alt="" width="60" height="60">
            ${esc(a.heading)}
          </h1>
        </div>
        <p class="lede">${esc(a.lede)}</p>
        <p class="lede lede-sm">${esc(a.body)}</p>
        <div class="acts"><a class="btn" href="${a.action.href}">${esc(a.action.label)}</a></div>
      </div>
      <div class="hero-stage">
        <div class="laptop laptop-cycling">
          <div class="laptop-lid">
            <div class="laptop-lid-back" aria-hidden="true">
              <img src="../assets/actis-mark-light.png" alt="" width="60" height="60">
            </div>
            <div class="laptop-bezel">
              <span class="laptop-camera" aria-hidden="true"></span>
              <div class="laptop-screen">
                ${screen(C.hero.records[0])}
              </div>
              <div class="laptop-glare" aria-hidden="true"></div>
            </div>
          </div>
          <div class="laptop-base">
            ${keyboard()}
          </div>
          <div class="laptop-shadow" aria-hidden="true"></div>
        </div>
      </div>
    </div>
  </div>
</section>

<section class="sec sec-term">
  <div class="wrap">
    <h2>${esc(a.runs.heading)}</h2>
    ${terminal()}
    <p class="note note-dark">${esc(a.runs.note)}</p>
  </div>
</section>

<section class="sec">
  <div class="wrap">
    <h2>${esc(a.record.heading)}</h2>
    <p class="lede">${esc(a.record.lede)}</p>
    <div class="rec-frame">
      ${screen(C.hero.records[0])}
    </div>
  </div>
</section>

<section class="sec">
  <div class="wrap">
    <h2>${esc(a.pack.heading)}</h2>
    <table class="tbl"><caption class="vh">What an Actis export contains</caption><tbody>
      ${pack}
    </tbody></table>
    <p class="closer">${esc(a.pack.closing)}</p>
  </div>
</section>

<section class="sec sec-rail">
  <div class="wrap">
    <h2>${esc(a.state.heading)}</h2>
    <div class="state">
      <div class="state-col">
        <h3 class="state-cap is-now">${esc(a.state.nowLabel)}</h3>
        <ul class="rule-list">${now}</ul>
      </div>
      <div class="state-col">
        <h3 class="state-cap">${esc(a.state.buildingLabel)}</h3>
        <ul class="rule-list rule-list-soft">${building}</ul>
      </div>
    </div>
  </div>
</section>`,
  });
}


/** Give the page rhythm: a counted marker per section, alternating grounds. */
function rhythm(html) {
  let n = 0;
  return html.replace(/<section class="sec([^"]*)"([\s\S]*?)<h2>/g, (m, rest, mid) => {
    n += 1;
    const num = String(n).padStart(2, "0");
    const dark = rest.includes("sec-dark");
    // Light sections alternate ground so no two in a row read the same.
    const alt = !dark && n % 2 === 0 ? " sec-alt" : "";
    // The washes alternate sides so the page is lit down its length.
    const wash = dark ? "" : ` sec-wash sec-wash-${n % 4 < 2 ? "a" : "b"}`;
    const marker = `<span class="sec-n" aria-hidden="true">${num}</span>`;
    return `<section class="sec${rest}${alt}${wash}"${mid}${marker}<h2>`;
  });
}

/* --------------------------------------------------------------- pages --- */

const home = shell({
  ogTitle: `${C.meta.brand} — ${C.meta.tagline}`,
  description: `${C.hero.subhead} ${C.hero.body}`,
  body: rhythm([
    heroSection(), obligationSection(),
    growthSection(), workflowSection(), marketSection(), manualSection(),
    doesSection(), easierSection(), sourceSection(), capabilitySection(), closingSection(),
  ].join("\n\n")),
  script: true,
});

function legalPage(key, extra) {
  const L = C.legalPages[key];
  return shell({
    slug: `${key}/`,
    ogTitle: `${C.meta.brand} — ${L.title}`,
    description: L.description,
    depth: 1,
    doc: true,
    body: `<section class="sec sec-lead">
  <div class="wrap narrow">
    <h1>${esc(L.heading)}</h1>
    <p class="doc-date">${esc(L.updated)}</p>
    ${extra}
  </div>
</section>`,
  });
}

const privacySections = `<p class="doc-intro">${esc(C.privacyBody.intro)}</p>\n\n    ` +
  C.privacyBody.sections
    .map((s) => `<section class="doc-s">
      <h2>${esc(s.title)}</h2>
      <p>${esc(s.body)}</p>
    </section>`)
    .join("\n\n    ");

const pages = [
  ["index.html", home],
  ["actis/index.html", actisPage()],
  ["privacy/index.html", legalPage("privacy", privacySections)],
];

for (const [path, html] of pages) {
  const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : null;
  if (dir) mkdirSync(new URL(dir, import.meta.url), { recursive: true });
  writeFileSync(new URL(path, import.meta.url), html);
  console.log(`${path.padEnd(26)} ${(html.length / 1024).toFixed(1)} KB`);
}
console.log(FORM_ENDPOINT ? `forms post to ${FORM_ENDPOINT}` : "forms fall back to mailto");
