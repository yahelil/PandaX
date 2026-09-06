// Dashboard renderer. Consumes the same Event objects the CLI does, over SSE.

const STAGES = [
  ["S1 INGEST", "Ingest", "Safe unpack, digest every file"],
  ["S2 SBOM", "SBOM", "CycloneDX 1.6 via Syft"],
  ["S3 MATCH", "Match", "OSV.dev by package URL"],
  ["S4 TRIAGE", "Triage", "CISA KEV + EPSS, VEX"],
  ["S5 CLOCK", "Article 14", "24h / 72h / 14d filings"],
  ["S6 DOSSIER", "Dossier", "Annex VII + Annex V, PDF/A"],
  ["SEAL", "Seal", "Hash chain + Ed25519"],
];

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
};

let runId = "";
let source = null;

// ------------------------------------------------------------------ stages

function buildStages() {
  const host = $("pipeline");
  host.innerHTML = "";
  for (const [code, name, desc] of STAGES) {
    const card = el("div", "stage");
    card.id = "stage-" + code.replace(/\s/g, "-");
    card.append(el("div", "code", code), el("div", "name", name), el("div", "msg", desc));
    host.append(card);
  }
}

function stageCard(stage) {
  return $("stage-" + stage.replace(/\s/g, "-"));
}

// --------------------------------------------------------------------- log

function logLine(cls, ...parts) {
  const log = $("log");
  const row = el("div", "row " + cls);
  for (const part of parts) row.append(part);
  log.append(row);
  log.scrollTop = log.scrollHeight;
}

const MARK = { info: "·", good: "✓", warn: "!", alert: "▶" };

function handle(e) {
  switch (e.kind) {
    case "stage_start": {
      const card = stageCard(e.stage);
      if (card) {
        card.classList.add("active");
        card.querySelector(".msg").textContent = e.message;
      }
      $("log").append(el("div", "stage-tag", e.stage));
      break;
    }
    case "log":
      logLine(
        e.level,
        el("span", "mark", MARK[e.level] || "·"),
        el("span", "", e.message)
      );
      break;
    case "metric": {
      const row = el("div", "row metric");
      row.append(el("span", "mark", " "));
      const label = el("span", "", (e.data.label || "") + "  ");
      const value = el("b", "", String(e.data.value));
      row.append(label, value);
      $("log").append(row);
      $("log").scrollTop = $("log").scrollHeight;
      break;
    }
    case "artifact": {
      const row = el("div", "row artifact");
      row.append(el("span", "mark", "→"));
      const name = el("span", "", e.data.path + "  ");
      const sha = el("span", "sha", "sha256 " + (e.data.sha256 || "").slice(0, 16) + "…");
      row.append(name, sha);
      $("log").append(row);
      $("log").scrollTop = $("log").scrollHeight;
      break;
    }
    case "alert": {
      const card = stageCard(e.stage);
      if (card) card.classList.add("alert");
      logLine("alert", el("span", "mark", "▶"), el("span", "", e.message));
      break;
    }
    case "stage_done": {
      const card = stageCard(e.stage);
      if (card) {
        card.classList.remove("active");
        card.classList.add(e.level === "alert" ? "alert" : "done");
        card.querySelector(".msg").textContent = e.message;
      }
      logLine("done" + (e.level === "alert" ? " alert" : ""),
        el("span", "mark", "✔"), el("span", "", e.stage + "  " + e.message));
      break;
    }
    case "run_done":
      runId = e.data.run_id || runId;
      $("s-components").textContent = e.data.components ?? "—";
      $("s-vulns").textContent = e.data.findings ?? "—";
      $("s-kev").textContent = e.data.kev ?? "—";
      $("s-clocks").textContent = e.data.incidents ?? "—";
      logLine("done", el("span", "mark", "✔"), el("span", "", e.message));
      if (runId) loadSummary();
      $("run").disabled = false;
      break;
  }
  if (e.data && e.data.run_id && !runId) runId = e.data.run_id;
}

// ----------------------------------------------------------------- summary

async function loadSummary() {
  const res = await fetch(`/api/run/${runId}/summary`);
  if (!res.ok) return;
  const data = await res.json();

  const kev = data.kev || [];
  if (kev.length) {
    const table = $("kev-table");
    table.innerHTML = "";
    for (const f of kev.sort((a, b) => b.epss - a.epss)) {
      const tr = el("tr");
      tr.append(
        el("td", "cve", f.cve),
        el("td", "cmp", `${f.component} ${f.version}`),
        el("td", "epss", Number(f.epss).toFixed(5))
      );
      table.append(tr);
    }
    $("kev-panel").hidden = false;
  }

  const root = (data.dossier && data.dossier.run_id) || runId;
  $("chain-root").textContent = root;
  $("seal-panel").hidden = false;

  const docs = $("docs");
  docs.innerHTML = "";
  const interesting = [
    ["AnnexVII_Technical_Documentation.pdf", "Annex VII technical documentation (PDF/A-2b)"],
    ["EU_Declaration_of_Conformity.pdf", "Annex V EU declaration of conformity"],
    ["sbom.cdx.json", "CycloneDX 1.6 SBOM"],
    ["findings.cdx-vex.json", "CycloneDX VEX — exploitation status"],
    ["ledger.jsonl", "Hash-chained evidence ledger"],
    ["manifest.json", "Signed manifest"],
  ];
  for (const [file, label] of interesting) {
    if (!data.files.includes(file)) continue;
    const li = el("li");
    const a = el("a", "", file);
    a.href = `/api/run/${runId}/file/${file}`;
    a.target = "_blank";
    li.append(a, el("span", "tag", label));
    docs.append(li);
  }
  $("docs-panel").hidden = false;

  // Show the real chain root from the manifest.
  const man = await fetch(`/api/run/${runId}/file/manifest.json`);
  if (man.ok) {
    const manifest = JSON.parse(await man.text());
    $("chain-root").textContent = manifest.ledger_root;
  }
}

// ------------------------------------------------------------ verify/tamper

function renderChecks(result) {
  const host = $("checks");
  host.innerHTML = "";
  for (const c of result.checks) {
    const row = el("div", "check " + (c.ok ? "ok" : "bad"));
    row.append(
      el("span", "m", c.ok ? "✔" : "✘"),
      (() => {
        const wrap = el("div");
        wrap.append(el("div", "n", c.name), el("div", "d", c.detail));
        return wrap;
      })()
    );
    host.append(row);
  }
  const verdict = el("div", "verdict " + (result.ok ? "ok" : "bad"));
  verdict.textContent = result.ok
    ? "VERIFIED — every digest recomputed, every chain link re-derived, signature valid."
    : "TAMPERING DETECTED — the files on disk are not the files that were signed.";
  host.append(verdict);
}

$("verify").addEventListener("click", async () => {
  const res = await fetch(`/api/verify/${runId}`);
  renderChecks(await res.json());
});

$("tamper").addEventListener("click", async () => {
  const res = await fetch(`/api/tamper/${runId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target: "sbom.cdx.json" }),
  });
  const info = await res.json();
  logLine("warn", el("span", "mark", "!"),
    el("span", "", `tampered ${info.file} at byte ${info.offset}: '${info.before}' -> '${info.after}'`));
  const verify = await fetch(`/api/verify/${runId}`);
  renderChecks(await verify.json());
});

// --------------------------------------------------------------------- run

$("run").addEventListener("click", async () => {
  const artifact = $("artifact").value;
  if (!artifact) return;
  $("run").disabled = true;
  $("log").innerHTML = "";
  $("kev-panel").hidden = true;
  $("seal-panel").hidden = true;
  $("docs-panel").hidden = true;
  $("checks").innerHTML = "";
  runId = "";
  buildStages();

  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ artifact }),
  });
  if (!res.ok) {
    logLine("alert", el("span", "mark", "▶"), el("span", "", await res.text()));
    $("run").disabled = false;
    return;
  }

  if (source) source.close();
  source = new EventSource("/api/events");
  source.onmessage = (msg) => handle(JSON.parse(msg.data));
  source.addEventListener("end", () => {
    source.close();
    source = null;
    $("run").disabled = false;
  });
});

// -------------------------------------------------------------------- boot

(async function boot() {
  buildStages();
  const res = await fetch("/api/artifacts");
  const list = await res.json();
  const select = $("artifact");
  select.innerHTML = "";
  for (const item of list) {
    const option = el("option", "", item.name + (item.bytes ? ` (${(item.bytes / 1024).toFixed(0)} KB)` : ""));
    option.value = item.path;
    select.append(option);
  }
  if (!list.length) {
    const option = el("option", "", "no artifacts — run tools/bootstrap.py");
    option.value = "";
    select.append(option);
    $("run").disabled = true;
  }
})();
