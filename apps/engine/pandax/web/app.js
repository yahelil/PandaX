// Dashboard renderer. Consumes the same Event objects the CLI does, over SSE,
// then renders the sealed bundle's own files - nothing here is recomputed.

const STAGES = [
  ["S1 INGEST", "Ingest"],
  ["S2 SBOM", "SBOM"],
  ["S3 MATCH", "Match"],
  ["S4 TRIAGE", "KEV / EPSS"],
  ["S5 CLOCK", "Article 14"],
  ["S6 DOSSIER", "Dossier"],
  ["SEAL", "Seal"],
];

// Statutory milestones from Regulation (EU) 2024/2847.
const CRA_MILESTONES = [
  ["2026-09-11", "Article 14 reporting obligations apply"],
  ["2027-12-11", "Full application of the Regulation"],
];

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (ch) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[ch]));

let runId = "";
let source = null;
let DATA = null;
let RUNS = [];
let vulnFilter = "all";
let inputMode = "artifact";

// --------------------------------------------------------------- navigation

const PAGE_TITLES = {
  overview: "Dashboard",
  artifacts: "Inventory",
  vulns: "Findings",
  article14: "Deadlines",
  cases: "Cases",
  reports: "Documents",
  audit: "Evidence",
};

function showView(name, moveFocus = false) {
  if (!PAGE_TITLES[name]) name = "overview";
  document.querySelectorAll(".view").forEach((v) => {
    v.hidden = v.dataset.view !== name;
  });
  document.querySelectorAll(".nav").forEach((b) => {
    if (b.dataset.view === name) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  $("page-title").textContent = PAGE_TITLES[name];
  $("primary-nav").classList.remove("open");
  $("nav-toggle").setAttribute("aria-expanded", "false");
  window.scrollTo(0, 0);
  if (moveFocus) {
    const heading = document.querySelector(`.view[data-view="${name}"] h1`);
    if (heading) {
      heading.tabIndex = -1;
      heading.focus({ preventScroll: true });
    }
  }
}

// Views are addressable (#vulns, #audit...), so links are shareable and the
// browser back button behaves.
const routeTo = (name) => {
  if (location.hash.slice(1) === name) showView(name);
  else location.hash = name;
};
window.addEventListener("hashchange", () => {
  const view = location.hash.slice(1) || "overview";
  showView(view, true);
  if (view === "cases") loadCases();
});

document.querySelectorAll(".nav").forEach((b) =>
  b.addEventListener("click", () => {
    routeTo(b.dataset.view);
    if (b.dataset.view === "cases") loadCases();
  })
);
document.querySelectorAll("[data-goto]").forEach((b) =>
  b.addEventListener("click", () => routeTo(b.dataset.goto))
);

$("nav-toggle").addEventListener("click", () => {
  const open = $("primary-nav").classList.toggle("open");
  $("nav-toggle").setAttribute("aria-expanded", String(open));
});

// ------------------------------------------------------------------- steps

function buildSteps() {
  const host = $("steps");
  host.innerHTML = "";
  STAGES.forEach(([code, name], i) => {
    const li = el("li");
    li.id = "step-" + code.replace(/\s/g, "-");
    li.append(el("div", "n", `[${i + 1}/${STAGES.length}]`), el("div", "t", name));
    host.append(li);
  });
}

const stepOf = (stage) => $("step-" + stage.replace(/\s/g, "-"));
const stageIndex = (stage) => STAGES.findIndex(([c]) => c === stage) + 1;

// ----------------------------------------------------------------- console

function logRow(cls, ...parts) {
  const log = $("log");
  const row = el("div", "row " + cls);
  parts.forEach((p) => row.append(p));
  log.append(row);
  log.scrollTop = log.scrollHeight;
}

const MARK = { info: "·", good: "✓", warn: "!", alert: "▶" };

function boxTable(columns, rows) {
  const widths = columns.map((c, i) =>
    Math.max(String(c).length, ...rows.map((r) => String(r[i]).length))
  );
  const line = (l, m, r) => l + widths.map((w) => "─".repeat(w + 2)).join(m) + r;
  const row = (cells) =>
    "│" + cells.map((c, i) => " " + String(c).padEnd(widths[i]) + " ").join("│") + "│";
  return [
    line("┌", "┬", "┐"),
    row(columns),
    line("├", "┼", "┤"),
    ...rows.map(row),
    line("└", "┴", "┘"),
  ].join("\n");
}

function handle(e) {
  switch (e.kind) {
    case "stage_start": {
      const li = stepOf(e.stage);
      if (li) {
        li.classList.remove("done", "alert");
        li.classList.add("active");
      }
      const head = el("div", "row stage");
      head.append(
        el("span", "num", `[${stageIndex(e.stage)}/${STAGES.length}] `),
        el("span", "", e.stage + ": "),
        el("span", "info", e.message)
      );
      $("log").append(head);
      $("log").scrollTop = $("log").scrollHeight;
      break;
    }
    case "log":
      logRow(e.level, el("span", "mark", MARK[e.level] || "·"), el("span", "", e.message));
      break;
    case "metric": {
      const row = el("div", "row metric");
      row.append(
        el("span", "mark", " "),
        el("span", "info", String(e.data.label || "").padEnd(26)),
        el("b", "", String(e.data.value))
      );
      $("log").append(row);
      $("log").scrollTop = $("log").scrollHeight;
      break;
    }
    case "artifact": {
      const row = el("div", "row artifact");
      row.append(
        el("span", "mark", "→"),
        el("span", "", e.data.path + "  "),
        el("span", "sha", "sha256 " + String(e.data.sha256 || "").slice(0, 16) + "…")
      );
      $("log").append(row);
      $("log").scrollTop = $("log").scrollHeight;
      break;
    }
    case "table": {
      const pre = el("pre", "", boxTable(e.data.columns, e.data.rows));
      $("log").append(pre);
      $("log").scrollTop = $("log").scrollHeight;
      break;
    }
    case "alert": {
      const li = stepOf(e.stage);
      if (li) li.classList.add("alert");
      logRow("alert", el("span", "mark", "▶"), el("span", "", e.message));
      break;
    }
    case "stage_done": {
      const li = stepOf(e.stage);
      if (li) {
        li.classList.remove("active");
        li.classList.add(e.level === "alert" ? "alert" : "done");
      }
      logRow(
        "done" + (e.level === "alert" ? " alert" : ""),
        el("span", "mark", e.level === "alert" ? "!!" : "OK"),
        el("span", "", e.message)
      );
      break;
    }
    case "stage_skipped": {
      const li = stepOf(e.stage);
      if (li) {
        li.classList.remove("active", "done", "alert");
        li.classList.add("skipped");
      }
      logRow("warn", el("span", "mark", "–"), el("span", "", `${e.stage}: ${e.message} [SKIP]`));
      break;
    }
    case "run_done": {
      runId = e.data.run_id || runId;
      const failed = e.data.failed;
      const comparisonFailed = e.data.comparison_passed === false;
      const final = el("div", "row final " + (failed || comparisonFailed || e.data.kev ? "alert" : "good"));
      final.append(
        el("span", "", failed ? "> failed." : comparisonFailed ? "> comparison checks FAILED — see results." : e.data.kev ? "> complete — CONFORMITY BLOCKED" : "> complete.")
      );
      $("log").append(final);
      $("log").scrollTop = $("log").scrollHeight;
      if (runId && !failed) loadRun(runId);
      refreshHistory();
      break;
    }
  }
  if (e.data && e.data.run_id && !runId) runId = e.data.run_id;
}

// -------------------------------------------------------------- load a run

async function loadRun(id) {
  const res = await fetch(`/api/run/${id}/summary`);
  if (!res.ok) return;
  DATA = await res.json();
  runId = DATA.run_id;
  $("appbar-run").textContent = runId;
  renderComparison();
  renderOverview();
  renderComponents();
  renderVulns();
  renderArticle14();
  renderReports();
  renderLedger();
  populateRecentRuns();
  $("tamper2").disabled = Boolean(DATA.comparison);
  runVerify();
}

// ----------------------------------------------------------------- overview

function setMetric(name, label, value, note, tone = "blue") {
  $(`s-${name}-label`).textContent = label;
  $(`s-${name}`).textContent = value;
  $(`s-${name}-note`).textContent = note;
  const dot = name === "kev" ? $("kev-dot") : $(`s-${name}-dot`);
  dot.className = `dot ${tone}`;
  $(`s-${name}-note`).className = `note${tone === "red" ? " danger" : ""}`;
}

function nearestDeadline() {
  const now = new Date();
  const dates = DATA.incidents.flatMap((incident) =>
    Object.values(incident.deadlines || {}).filter(Boolean).map((value) => new Date(value))
  ).filter((date) => !Number.isNaN(date.valueOf())).sort((a, b) => a - b);
  if (!dates.length) return "";
  const next = dates.find((date) => date >= now) || dates[dates.length - 1];
  return `${next < now ? "Latest deadline was" : "Next deadline"} ${fmtDateTime(next)}`;
}

function setDecision(tone, kicker, title, detail, deadline, action, actionLabel) {
  $("decision-card").className = `card decision-card ${tone}`;
  $("decision-kicker").textContent = kicker;
  $("decision-title").textContent = title;
  $("decision-detail").textContent = detail;
  $("decision-deadline").textContent = deadline;
  $("decision-primary").dataset.action = action;
  $("decision-primary").textContent = actionLabel;
}

function renderOverview() {
  const s = DATA.stats;
  const p = DATA.product || {};

  $("product-line").textContent = p.name
    ? `${p.name} ${p.version || ""} · ${p.type || "product with digital elements"} · ${(p.risk_tier || "default").toUpperCase()} tier · ${p.conformity_route || ""}`
    : "Sealed evidence bundle.";

  const source = s.input_type === "sbom"
    ? `${s.sbom_source_format} ${s.sbom_source_version} · ${s.matchable_components} matchable` +
      (s.skipped_components ? ` · ${s.skipped_components} not scanned` : "")
    : (s.ecosystems || "inventoried from the software package");

  setMetric("components", "Components", s.components, source);
  setMetric("complete", "Annex VII completeness", `${s.completeness}%`,
    `${s.derived} derived + ${s.attested} attested of ${s.total_fields} fields`);
  setMetric("kev", "Active threats (KEV)", s.kev,
    s.kev ? "Article 14 reporting engaged" : "none returned by checked sources",
    s.kev ? "red" : "green");
  setMetric("dossiers", "Signed files", s.manifest_files, "in this saved result", "green");

  // A result restored from disk shows its stages already complete.
  if (!$("log").classList.contains("running")) {
    STAGES.forEach(([code]) => stepOf(code)?.classList.add("done"));
    if (s.input_type === "sbom") {
      stepOf("S1 INGEST")?.classList.remove("done");
      stepOf("S1 INGEST")?.classList.add("skipped");
    }
    $("log").innerHTML = "";
    logRow("info", el("span", "mark", "·"),
      el("span", "", `loaded saved result ${DATA.run_id} — select Start analysis to create another`));
  }
  $("chain-root").textContent = s.ledger_root || "—";
  $("console-hint").textContent = `${s.ledger_records} chained records`;

  // Vulnerability Monitor preview: the exploited ones first.
  const rows = [...DATA.findings].sort(
    (a, b) => Number(b.kev) - Number(a.kev) || b.epss - a.epss
  );
  $("monitor-table").innerHTML = vulnTable(rows.slice(0, 6), true);
  $("monitor-card").hidden = false;

  if (DATA.comparison || DATA.release_checks) {
    const report = DATA.comparison;
    const checks = DATA.release_checks;
    const passed = report ? report.passed : checks.passed;
    const items = report?.rows || checks.checks || [];
    const passing = items.filter((item) => item.passed).length;
    const affectedBefore = items.filter((item) => item.before?.observed === "affected" || item.observed === "affected").length;
    const affectedAfter = items.filter((item) => item.after?.observed === "affected").length;
    const inputs = report?.runs?.filter((item) => item.run_id && !item.error).length || 1;

    if (report) {
      $("product-line").textContent = `${report.scenario.name} — signed release comparison`;
    } else {
      const release = checks.release;
      $("product-line").textContent = `${release.name} ${release.version} — ${release.kind}`;
    }
    setMetric("components", "Checks passed", `${passing}/${items.length}`, "expected release observations", passed ? "green" : "red");
    if (report) {
      setMetric("complete", "Affected findings", `${affectedBefore} → ${affectedAfter}`, "before and after checked release", affectedAfter ? "red" : "green");
      setMetric("kev", "Evidence inputs", inputs, "verified package analysis results", "blue");
      setMetric("dossiers", "Signed files", s.manifest_files, "in this comparison result", "green");
    } else {
      setMetric("complete", "Components", s.components, source);
      setMetric("kev", "Active threats (KEV)", s.kev,
        s.kev ? "Article 14 reporting engaged" : "none returned by checked sources",
        s.kev ? "red" : "green");
      setMetric("dossiers", "Signed files", s.manifest_files, "in this package analysis", "green");
    }
    setDecision(
      passed ? "good" : "danger",
      report ? "Release comparison" : "Release check",
      passed ? "Evidence checks passed" : "Evidence checks need review",
      `${passing} of ${items.length} expected observations passed. Review evidence before relying on this result.`,
      report ? "Signed comparison evidence available" : "Signed release evidence available",
      "comparison",
      "Review evidence"
    );
    if (report) $("monitor-card").hidden = true;
  } else if (s.kev) {
    const hasFixes = DATA.verdict?.upgrades?.some((item) => item.target);
    setDecision(
      "danger",
      "Release readiness",
      `Blocked — ${s.kev} actively exploited ${s.kev === 1 ? "vulnerability" : "vulnerabilities"}`,
      "EU Declaration of Conformity remains blocked under Annex I Part I(2)(a).",
      nearestDeadline(),
      hasFixes ? "fixes" : "deadlines",
      hasFixes ? "Review required actions" : "Review deadlines"
    );
  } else {
    setDecision(
      "good",
      "Release readiness",
      "No active-exploitation blocker found",
      "Checked sources returned no actively exploited vulnerabilities. Manufacturer review and missing attestations still apply.",
      `${s.completeness}% Annex evidence complete`,
      "findings",
      "Review findings"
    );
  }
  renderFixPlan();
  renderTimeline();
}

$("decision-primary").addEventListener("click", () => {
  const action = $("decision-primary").dataset.action;
  if (action === "comparison") {
    $("comparison-panel").open = true;
    $("comparison-panel").scrollIntoView({ behavior: "smooth", block: "start" });
  } else if (action === "fixes") {
    $("fix-card").scrollIntoView({ behavior: "smooth", block: "start" });
  } else if (action === "deadlines") {
    routeTo("article14");
  } else if (action === "findings") {
    routeTo("vulns");
  } else if (action === "execution") {
    $("console-card").open = true;
    $("console-card").scrollIntoView({ behavior: "smooth", block: "start" });
  } else {
    $("new-scan").click();
  }
});

// The remediation plan is the answer to "what do I actually do?" - a handful of
// upgrades rather than a hundred CVE rows.
function renderFixPlan() {
  const upgrades = (DATA.verdict && DATA.verdict.upgrades) || [];
  const actionable = upgrades.filter((u) => u.target);
  if (!actionable.length) {
    $("fix-card").hidden = true;
    return;
  }
  const cleared = upgrades.reduce((n, u) => n + u.clears, 0);
  $("fix-hint").textContent =
    `Top ${Math.min(5, actionable.length)} of ${actionable.length} upgrades · ${cleared} findings covered`;
  $("fix-table").innerHTML = `
    <thead><tr>
      <th>Package</th><th>Installed</th><th></th><th>Upgrade to</th>
      <th style="text-align:right">Clears</th><th>Exploited</th>
    </tr></thead>
    <tbody>${actionable
      .slice(0, 5)
      .map(
        (u) => `<tr>
        <td><b>${esc(u.component)}</b></td>
        <td class="mono dim">${esc(u.version)}</td>
        <td class="dim">&rarr;</td>
        <td class="mono"><b>${esc(u.target)}</b></td>
        <td class="num">${u.clears}</td>
        <td>${u.kev.length ? kevFlag() : '<span class="dim">&mdash;</span>'}</td>
      </tr>`
      )
      .join("")}</tbody>`;
  $("fix-card").hidden = false;
}

function renderTimeline() {
  const host = $("timeline");
  host.innerHTML = "";
  const now = new Date();
  const items = [];

  for (const incident of DATA.incidents) {
    const d = incident.deadlines;
    items.push({
      when: new Date(d.early_warning),
      date: "24h early warning",
      what: `${incident.cve} — Art.14(2)(a)`,
      cls: "urgent",
    });
  }
  if (DATA.incidents.length) {
    const d = DATA.incidents[0].deadlines;
    items.push({
      when: new Date(d.notification),
      date: "72h notification",
      what: "Art.14(2)(b), all open incidents",
      cls: "soon",
    });
  }
  for (const [iso, what] of CRA_MILESTONES) {
    items.push({ when: new Date(iso + "T00:00:00Z"), date: fmtDate(iso), what, cls: "", dateOnly: true });
  }

  items.sort((a, b) => a.when - b.when);
  // Collapse the per-CVE 24h rows into one when they share a deadline.
  const seen = new Set();
  for (const item of items) {
    const key = item.date + item.when.toISOString();
    if (item.date === "24h early warning") {
      if (seen.has(key)) continue;
      seen.add(key);
      const count = DATA.incidents.length;
      item.what = `Art.14(2)(a) — ${count} incident${count === 1 ? "" : "s"}`;
    }
    const li = el("li", item.cls);
    const days = Math.round((item.when - now) / 86400000);
    li.append(el("div", "date", item.date));
    li.append(el("div", "what", item.what));
    const stamp = item.dateOnly ? "" : fmtDateTime(item.when) + " · ";
    li.append(
      el(
        "div",
        "when",
        item.when < now
          ? `overdue — was ${item.dateOnly ? fmtDate(item.when) : fmtDateTime(item.when)}`
          : days > 1
            ? `${stamp}in ${days} days`
            : `${stamp}in ${Math.max(0, Math.round((item.when - now) / 3600000))}h`
      )
    );
    if (item.when < now) li.classList.add("past");
    host.append(li);
  }
}

const fmtDate = (iso) =>
  new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
const fmtDateTime = (d) =>
  new Date(d).toLocaleString("en-GB", {
    day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit",
  });

// ---------------------------------------------------------------- artifacts

function renderComponents() {
  const rows = DATA.components
    .slice()
    .sort((a, b) => Number(b.kev) - Number(a.kev) || b.findings - a.findings);
  $("eco-hint").textContent = DATA.stats.ecosystems;
  $("components-table").innerHTML = `
    <thead><tr>
      <th>Component</th><th>Version</th><th>Ecosystem</th>
      <th>Package URL</th><th style="text-align:right">Findings</th><th>Status</th>
    </tr></thead>
    <tbody>${rows
      .map(
        (c) => `<tr>
        <td><b>${esc(c.name)}</b></td>
        <td class="mono">${esc(c.version)}</td>
        <td><span class="pill blue">${esc(c.ecosystem)}</span></td>
        <td class="mono dim">${c.purl ? esc(c.purl) : "Unavailable"}</td>
        <td class="num">${c.findings || "—"}</td>
        <td>${
          !c.matchable
            ? '<span class="pill unknown">not scanned</span>'
            : c.kev
            ? kevFlag()
            : c.affected
              ? '<span class="pill medium">affected</span>'
              : '<span class="pill good">clean</span>'
        }</td>
      </tr>`
      )
      .join("")}</tbody>`;
}

// -------------------------------------------------------------------- vulns

const kevFlag = () =>
  '<span class="kev-flag"><svg viewBox="0 0 24 24"><path d="M12 2 1 21h22L12 2zm0 6 7 12H5l7-12z"/><path d="M11 10h2v5h-2zm0 6h2v2h-2z"/></svg>KEV</span>';

const okFlag = (text) =>
  `<span class="ok-flag"><svg viewBox="0 0 24 24"><path d="M4 12.5 9.5 18 20 6.5"/></svg>${esc(text)}</span>`;

// `compact` drops the Actions column for the Overview preview, which is too
// narrow for it - the full table behind "View all" keeps the links.
function vulnTable(rows, compact = false) {
  if (!rows.length) return '<tbody><tr><td class="empty-state">No findings.</td></tr></tbody>';
  return `
    <thead><tr>
      <th>Vulnerability ID</th><th>Impacted Component</th><th>Severity</th>
      <th>KEV Status</th><th style="text-align:right">EPSS</th>
      <th>Fixed In</th>${compact ? "" : "<th>Actions</th>"}
    </tr></thead>
    <tbody>${rows
      .map(
        (f) => `<tr>
        <td class="mono"><b>${esc(f.cve)}</b></td>
        <td>${esc(f.component)} <span class="dim mono">${esc(f.version)}</span></td>
        <td><span class="pill ${f.severity.toLowerCase()}">${esc(f.severity)}</span></td>
        <td>${f.kev ? kevFlag() : '<span class="dim">—</span>'}</td>
        <td class="num">${Number(f.epss).toFixed(5)}</td>
        <td class="mono">${f.fixed_version ? esc(f.fixed_version) : '<span class="dim">none</span>'}</td>
        ${compact ? "" : `<td><a class="link" href="https://osv.dev/vulnerability/${esc(f.osv_id)}"
               target="_blank" rel="noopener">View Details</a></td>`}
      </tr>`
      )
      .join("")}</tbody>`;
}

function renderVulns() {
  let rows = [...DATA.findings];
  if (vulnFilter === "kev") rows = rows.filter((f) => f.kev);
  if (vulnFilter === "critical") rows = rows.filter((f) => ["CRITICAL", "HIGH"].includes(f.severity));
  if (vulnFilter === "fixable") rows = rows.filter((f) => f.fixed_version);
  rows.sort((a, b) => Number(b.kev) - Number(a.kev) || b.epss - a.epss);
  $("vulns-table").innerHTML = vulnTable(rows);
}

document.querySelectorAll("#vuln-filters .chip").forEach((chip) =>
  chip.addEventListener("click", () => {
    document.querySelectorAll("#vuln-filters .chip").forEach((c) => {
      c.classList.remove("active");
      c.setAttribute("aria-pressed", "false");
    });
    chip.classList.add("active");
    chip.setAttribute("aria-pressed", "true");
    vulnFilter = chip.dataset.filter;
    if (DATA) renderVulns();
  })
);

// --------------------------------------------------------------- article 14

function renderArticle14() {
  const host = $("article14-body");
  host.innerHTML = "";
  if (!DATA.incidents.length) {
    const card = el("article", "card");
    card.append(
      el("div", "empty-state",
        "No actively exploited vulnerabilities were found, so Article 14 is not triggered for this run.")
    );
    host.append(card);
    return;
  }

  const preview = $("clock-preview").value;
  for (const incident of DATA.incidents) {
    const card = el("article", "card");
    const head = el("div", "card-head");
    head.append(el("h3", "", `${incident.cve} — ${incident.component}`));
    const track = el("button", "btn", "Track remediation");
    track.addEventListener("click", () => trackRemediation(incident.cve));
    head.append(el("span", "hint", `coordinating CSIRT: ${incident.coordinating_csirt_member_state || "unknown"} · Art.14(7)`), track);
    card.append(head);

    const table = el("table", "grid");
    const previewFinal = preview === "pending"
      ? null
      : preview === "overdue"
        ? new Date(Date.now() - 3600000).toISOString()
        : incident.deadlines.final_report;
    const filings = [
      ["early_warning", "24h early warning", "Art.14(2)(a)", incident.deadlines.early_warning],
      ["notification", "72h vulnerability notification", "Art.14(2)(b)", incident.deadlines.notification],
      ["final_report", "Final report (14d after measure availability)", "Art.14(2)(c)", previewFinal],
    ];
    table.innerHTML = `
      <thead><tr><th>Filing</th><th>Article</th><th>Due (UTC)</th><th>Remaining</th><th>Draft</th></tr></thead>
      <tbody>${filings
        .map(([file, label, article, due]) => {
          if (!due) return `<tr>
            <td><b>${label}</b></td>
            <td class="mono dim">${article}</td>
            <td class="mono">Awaiting corrective measure availability</td>
            <td><span class="pill medium">INPUT REQUIRED</span></td>
            <td><a class="link" target="_blank" rel="noopener"
                   href="/api/run/${runId}/file/filings/${esc(incident.cve)}/${file}.json">Open JSON</a></td>
          </tr>`;
          const left = new Date(due) - new Date();
          const overdue = left <= 0;
          const remaining = overdue
            ? `<span class="pill critical">OVERDUE</span>`
            : `<span class="pill ${left < 86400000 ? "medium" : "low"}">${Math.floor(left / 3600000)}h ${Math.floor((left % 3600000) / 60000)}m</span>`;
          return `<tr>
            <td><b>${label}</b></td>
            <td class="mono dim">${article}</td>
            <td class="mono">${esc(due)}</td>
            <td>${remaining}</td>
            <td><a class="link" target="_blank" rel="noopener"
                   href="/api/run/${runId}/file/filings/${esc(incident.cve)}/${file}.json">Open JSON</a></td>
          </tr>`;
        })
        .join("")}</tbody>`;
    card.append(table);
    host.append(card);
  }
}

// ------------------------------------------------------------------ reports

const REPORT_META = [
  ["comparison.json", "Release comparison", "Passes, failures, exclusions and both input bundle references."],
  ["release-checks.json", "Release checks", "Expected and observed outcomes, with missing detections shown as failures."],
  ["native-inventory.json", "Native component evidence", "Package revisions, source-header evidence and declared dependencies."],
  ["native-assessments.json", "Vendor advisory determinations", "Affected, fixed, unknown and variant exclusions. Bounded coverage for the requested native CVEs."],
  ["release-source.json", "Official package provenance", "Source URL, release type and pinned SHA-256 digest."],
  ["archive-links.json", "Archive links", "Links recorded from the official archive; none are created or followed on the host."],
  ["AnnexVII_Technical_Documentation.pdf", "Annex VII technical documentation",
   "The eight items required by Annex VII, each labelled machine-derived, manufacturer-attested, or input required. PDF/A-2b."],
  ["EU_Declaration_of_Conformity.pdf", "EU Declaration of Conformity",
   "Annex V, eight items. Blocked automatically while any actively exploited vulnerability remains."],
  ["sbom.cdx.json", "Software Bill of Materials",
   "CycloneDX 1.6, satisfying Annex I Part II(1). Carries no vulnerability data by design."],
  ["findings.cdx-vex.json", "VEX exploitation status",
   "CycloneDX 1.6 VEX. KEV hits are exploitable; everything else stays in_triage."],
  ["incidents.json", "Article 14 incident register",
   "Open incidents with their 24h / 72h / 14d statutory deadlines."],
  ["manifest.json", "Signed manifest",
   "Every file digest plus the ledger head, signed with Ed25519."],
];

function renderReports() {
  const host = $("reports-body");
  host.innerHTML = "";
  for (const [file, title, desc] of REPORT_META) {
    if (!DATA.files.includes(file)) continue;
    const card = el("article", "card doc");
    card.append(el("h3", "", title));
    card.append(el("span", "file", file));
    card.append(el("p", "", desc));
    const a = el("a", "", file.endsWith(".pdf") ? "Open PDF →" : "Open JSON →");
    a.href = `/api/run/${runId}/file/${file}`;
    a.target = "_blank";
    a.rel = "noopener";
    card.append(a);
    host.append(card);
  }
}

// -------------------------------------------------------------- audit trail

function renderLedger() {
  const host = $("ledger-body");
  host.innerHTML = "";
  $("ledger-hint").textContent =
    `${DATA.ledger.length} records · root ${String(DATA.stats.ledger_root).slice(0, 16)}…`;
  for (const rec of DATA.ledger) {
    const row = el("div", "ledger-row");
    const top = el("div", "ledger-top");
    top.append(
      el("span", "seq", `#${rec.seq}`),
      el("span", "stage", rec.stage),
      el("span", "tool", `${rec.tool} ${rec.tool_version}`),
      el("span", "tool", rec.ts)
    );
    row.append(top);
    for (const out of rec.outputs || []) {
      const io = el("div", "ledger-io");
      io.append(el("span", "", "→ "), document.createTextNode(`${out.path}  ${out.sha256.slice(0, 24)}…`));
      row.append(io);
    }
    row.append(el("div", "chain-hash", `prev ${rec.prev_hash.slice(0, 24)}…  ·  hash ${rec.record_hash.slice(0, 24)}…`));
    host.append(row);
  }
}

// ------------------------------------------------------------ verify/tamper

function renderChecks(host, result) {
  host.innerHTML = "";
  for (const c of result.checks) {
    const row = el("div", "check " + (c.ok ? "ok" : "bad"));
    const body = el("div");
    body.append(el("div", "n", c.name), el("div", "d", c.detail));
    row.append(el("span", "m", c.ok ? "✔" : "✘"), body);
    host.append(row);
  }
  const verdict = el("div", "verdict " + (result.ok ? "ok" : "bad"));
  verdict.textContent = result.ok
    ? "VERIFIED — every digest recomputed, every chain link re-derived, signature valid. Proves integrity, not legal identity."
    : "TAMPERING DETECTED — the files on disk are not the files that were signed. A regulator would reject this bundle.";
  host.append(verdict);

  const pill = $("seal-pill");
  pill.hidden = false;
  pill.textContent = result.ok ? "SEALED" : "TAMPERED";
  pill.className = "seal-pill " + (result.ok ? "ok" : "bad");
}

async function runVerify() {
  if (!runId) return;
  const res = await fetch(`/api/verify/${runId}`);
  const result = await res.json();
  renderChecks($("checks2"), result);
}

async function runTamper() {
  if (!runId) return;
  if (!window.confirm("Simulate a one-byte change in this local evidence bundle? Verification will fail until the run is regenerated.")) return;
  const res = await fetch(`/api/tamper/${runId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target: "sbom.cdx.json" }),
  });
  const info = await res.json();
  logRow("warn", el("span", "mark", "!"),
    el("span", "", `tampered ${info.file} at byte ${info.offset}: '${info.before}' → '${info.after}'`));
  await runVerify();
}

$("verify2").addEventListener("click", runVerify);
$("tamper2").addEventListener("click", runTamper);

// --------------------------------------------------------------------- run

function syncRunner() {
  const sbom = inputMode === "sbom";
  $("artifact").hidden = sbom;
  $("sbom-picker").hidden = !sbom;
  $("mode-artifact").classList.toggle("active", !sbom);
  $("mode-sbom").classList.toggle("active", sbom);
  $("mode-artifact").setAttribute("aria-pressed", String(!sbom));
  $("mode-sbom").setAttribute("aria-pressed", String(sbom));
  $("run").disabled = sbom ? !$("sbom-file").files.length : !$("artifact").value;
}

function setRunnerDisabled(disabled) {
  $("mode-artifact").disabled = disabled;
  $("mode-sbom").disabled = disabled;
  $("artifact").disabled = disabled;
  $("sbom-file").disabled = disabled;
  $("run").disabled = disabled;
  if (!disabled) syncRunner();
}

$("mode-artifact").addEventListener("click", () => { inputMode = "artifact"; syncRunner(); });
$("mode-sbom").addEventListener("click", () => { inputMode = "sbom"; syncRunner(); });
$("artifact").addEventListener("change", syncRunner);
$("sbom-file").addEventListener("change", () => {
  const file = $("sbom-file").files[0];
  $("sbom-filename").textContent = file ? file.name : "Choose an SBOM JSON file";
  syncRunner();
});

$("new-scan").addEventListener("click", () => {
  $("scan-panel").open = true;
  $("scan-panel").scrollIntoView({ behavior: "smooth", block: "start" });
  $(inputMode === "sbom" ? "sbom-file" : "artifact").focus();
});

$("run").addEventListener("click", async () => {
  const artifact = $("artifact").value;
  const sbomFile = $("sbom-file").files[0];
  $("comparison-panel").hidden = true;
  if (inputMode === "artifact" && !artifact) return;
  if (inputMode === "sbom" && !sbomFile) return;
  $("scan-panel").open = false;
  $("console-card").open = true;
  setDecision(
    "warn",
    "Pipeline",
    "Analysis in progress",
    "PandaX is analyzing the selected input and creating a sealed result. Stage details stream below.",
    "",
    "execution",
    "View progress"
  );
  setRunnerDisabled(true);
  $("log").innerHTML = "";
  $("log").classList.add("running");
  $("seal-pill").hidden = true;
  runId = "";
  DATA = null;
  buildSteps();

  let res;
  try {
    if (inputMode === "sbom") {
      const form = new FormData();
      form.append("file", sbomFile);
      res = await fetch("/api/scan/sbom", { method: "POST", body: form });
    } else {
      res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ artifact }),
      });
    }
  } catch (error) {
    logRow("alert", el("span", "mark", "▶"), el("span", "", `Upload failed: ${error.message}`));
    setRunnerDisabled(false);
    $("log").classList.remove("running");
    return;
  }
  if (!res.ok) {
    let detail = await res.text();
    try { detail = JSON.parse(detail).detail || detail; } catch (_) {}
    logRow("alert", el("span", "mark", "▶"), el("span", "", detail));
    setRunnerDisabled(false);
    $("log").classList.remove("running");
    return;
  }

  attachStream();
});

function attachStream() {
  if (source) source.close();
  source = new EventSource("/api/events");
  source.onmessage = (msg) => handle(JSON.parse(msg.data));
  source.addEventListener("end", () => {
    source.close();
    source = null;
    setRunnerDisabled(false);
    $("log").classList.remove("running");
  });
}

// -------------------------------------------------------------------- boot

(async function boot() {
  buildSteps();
  showView(location.hash.slice(1) || "overview");

  const artifacts = await (await fetch("/api/artifacts")).json();
  const select = $("artifact");
  select.innerHTML = "";
  const groups = new Map();
  for (const item of artifacts) {
    const option = el("option", "",
      item.name + (item.bytes ? `  (${(item.bytes / 1024).toFixed(0)} KB)` : ""));
    option.value = item.path;
    option.dataset.note = item.note || "Runs one complete analysis of this local test package.";
    const groupName = item.group || "Local test packages — one analysis";
    if (!groups.has(groupName)) {
      const group = document.createElement("optgroup");
      group.label = groupName;
      groups.set(groupName, group);
      select.append(group);
    }
    groups.get(groupName).append(option);
  }
  const selectionNote = () => {
    $("artifact-note").textContent = select.selectedOptions[0]?.dataset.note || "";
  };
  select.addEventListener("change", selectionNote);
  selectionNote();
  if (!artifacts.length) {
    select.append(el("option", "", "No software packages available — run tools/bootstrap.py"));
    select.value = "";
  }
  syncRunner();

  // A run already in flight wins: re-attach and replay it, so reloading the
  // page mid-scan shows the live stream rather than an empty console.
  const job = await (await fetch("/api/job")).json();
  if (job.running) {
    await refreshHistory();
    setRunnerDisabled(true);
    $("log").innerHTML = "";
    $("log").classList.add("running");
    $("console-card").open = true;
    setDecision(
      "warn",
      "Pipeline",
      "Analysis in progress",
      "PandaX is analyzing the selected input and creating a sealed result. Stage details stream below.",
      "",
      "execution",
      "View progress"
    );
    attachStream();
    return;
  }

  // Otherwise load the most recent sealed run so the dashboard is never empty.
  const runs = await refreshHistory();
  if (runs.length) await loadRun(runs[0].run_id);
  if ((location.hash.slice(1) || "overview") === "cases") await loadCases();
})();


function renderComparison() {
  const report = DATA.comparison;
  const checks = DATA.release_checks;
  const host = $("comparison-panel");
  host.hidden = !report && !checks;
  if (host.hidden) return;
  const passed = report ? report.passed : checks.passed;
  $("comparison-title").textContent = (passed ? "PASS — " : "FAIL — ") +
    (report ? report.scenario.name : checks.release.name + " " + checks.release.version);
  $("comparison-scope").textContent = report ? report.scenario.note + " " + report.scope : checks.scope;
  const runs = $("comparison-runs");
  runs.replaceChildren();
  for (const [i, run] of (report?.runs || []).entries()) {
    const row = el("p", "", (i ? "After: " : "Before: ") + run.release_id + " ");
    if (run.run_id) {
      const button = el("button", "btn", "Inspect run");
      button.addEventListener("click", () => loadRun(run.run_id));
      row.append(button);
    }
    if (run.error) row.append(el("span", "", "FAILED: " + run.error));
    runs.append(row);
  }
  const rows = $("comparison-rows");
  rows.replaceChildren();
  const items = report?.rows || checks.checks.map(c => ({cve: c.cve, before: c,
    after: {observed: "—"}, passed: c.passed, result: "Expected: " + c.expected}));
  for (const item of items) {
    const row = el("tr");
    const cve = el("td", "", item.cve);
    row.append(cve);
    for (const side of [item.before, item.after]) {
      const cell = el("td", "", (side.component_version || "") + " " + side.observed);
      if (side.detail) {
        const details = el("details");
        details.append(el("summary", "", "Evidence / applicability"), el("p", "", side.detail));
        if (side.source) {
          const link = el("a", "", "Vendor advisory");
          link.href = side.source; link.target = "_blank"; link.rel = "noopener";
          details.append(link);
        }
        cell.append(details);
      }
      row.append(cell);
    }
    row.append(el("td", "", (item.passed ? "PASS: " : "FAIL: ") + item.result));
    rows.append(row);
  }
  const link = el("a", "", "Download sealed comparison / check results");
  link.href = `/api/run/${runId}/file/${report ? "comparison.json" : "release-checks.json"}`;
  link.target = "_blank"; link.rel = "noopener";
  runs.append(link);
}


function runTitle(run) {
  const status = run.comparison_passed === null ? "" : run.comparison_passed ? "PASS — " : "FAIL — ";
  const type = run.result_type === "sbom_analysis" ? "SBOM analysis"
    : run.result_type === "release_comparison" ? "Release comparison" : "Package analysis";
  const subject = (run.product || run.run_id).replace(/ comparison$/i, "");
  return `${type} — ${status}${subject} · ${run.created}`;
}

function populateRecentRuns() {
  const select = $("run-history");
  select.replaceChildren();
  const recent = RUNS.slice(0, 5);
  const selected = RUNS.find((run) => run.run_id === runId);
  if (selected && !recent.some((run) => run.run_id === runId)) recent.push(selected);
  for (const run of recent) {
    const option = el("option", "", runTitle(run));
    option.value = run.run_id;
    select.append(option);
  }
  if (runId) select.value = runId;
}

function renderRunList(query = "") {
  const host = $("run-list");
  const needle = query.trim().toLowerCase();
  const matches = RUNS.filter((run) => `${runTitle(run)} ${run.run_id}`.toLowerCase().includes(needle));
  host.replaceChildren();
  if (!matches.length) {
    host.append(el("p", "empty-state", "No saved results match this search."));
    return;
  }
  for (const run of matches) {
    const button = el("button");
    button.type = "button";
    button.append(
      el("span", "run-name", runTitle(run).replace(` · ${run.created}`, "")),
      el("span", "run-date", new Date(run.created).toLocaleString()),
      el("span", "run-id-small", run.run_id)
    );
    button.addEventListener("click", async () => {
      $("run-dialog").close();
      await loadRun(run.run_id);
    });
    host.append(button);
  }
}

async function refreshHistory() {
  RUNS = await (await fetch("/api/runs")).json();
  populateRecentRuns();
  renderRunList($("run-search").value);
  return RUNS;
}

$("open-run-history").addEventListener("click", () => {
  $("run-search").value = "";
  renderRunList();
  $("run-dialog").showModal();
  $("run-search").focus();
});
$("run-search").addEventListener("input", () => renderRunList($("run-search").value));
$("run-history").addEventListener("change", () => loadRun($("run-history").value));
$("clock-preview").addEventListener("change", renderArticle14);
