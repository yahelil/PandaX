const CASE_VERSIONS = new Map();
// -------------------------------------------------------- remediation cases

const caseMessage = (message, failed = false) => {
  const box = $("case-message");
  box.hidden = !message;
  box.textContent = message || "";
  box.style.background = failed ? "var(--danger-bg)" : "var(--good-bg)";
  box.style.color = failed ? "var(--danger)" : "var(--good)";
};

async function caseRequest(path, options = {}) {
  if (options.method === "POST") {
    const body = JSON.parse(options.body || "{}");
    body.request_id ||= crypto.randomUUID();
    const id = path.split("/")[3];
    if (id) body.expected_version = CASE_VERSIONS.get(id);
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, {
    headers: {"Content-Type": "application/json"},
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.detail || `Request failed (${response.status})`);
  return payload;
}

async function trackRemediation(cve) {
  try {
    await caseRequest("/api/cases", {
      method: "POST",
      body: JSON.stringify({source_run_id: runId, cve}),
    });
    routeTo("cases");
    caseMessage(`${cve} is now tracked. PandaX has not changed the product.`);
    await loadCases();
  } catch (error) {
    caseMessage(error.message, true);
  }
}

function laterRunOptions(item) {
  const sourceRun = RUNS.find((run) => run.run_id === item.source_run_id);
  const matches = RUNS
    .filter((run) => run.product === item.source_product.name && run.run_id !== item.source_run_id)
    .filter((run) => !sourceRun || run.created > sourceRun.created);
  return {
    available: Boolean(matches.length),
    html: matches
    .map((run) => {
      const status = run.comparison_passed === null ? "" : run.comparison_passed ? "PASS — " : "FAIL — ";
      const label = status + (run.product || run.run_id) + " · " + run.created;
      return `<option value="${esc(run.run_id)}" ${run.run_id === item.candidate?.target_run_id ? "selected" : ""}>${esc(label)}</option>`;
    })
    .join("") || '<option value="">Analyze a newer release of this product first</option>',
  };
}

async function observeCase(caseId) {
  try {
    const target = $(`target-${caseId}`).value;
    await caseRequest(`/api/cases/${caseId}/observe-release`, {
      method: "POST",
      body: JSON.stringify({target_run_id: target}),
    });
    caseMessage("Release compared. Any resolution remains a candidate until manufacturer confirmation.");
    await loadCases();
  } catch (error) {
    caseMessage(error.message, true);
  }
}

async function confirmCase(caseId) {
  if (!$(`attest-${caseId}`).checked) {
    caseMessage("Confirm that the named operator is authorised by the manufacturer.", true);
    return;
  }
  try {
    await caseRequest(`/api/cases/${caseId}/confirm-measure`, {
      method: "POST",
      body: JSON.stringify({
        measure_available_at: $(`available-${caseId}`).value + "Z",
        operator: $(`operator-${caseId}`).value,
        authority_attestation: "I am authorised by the manufacturer to confirm this measure.",
        measure_details: $(`measure-${caseId}`).value,
      }),
    });
    caseMessage("Availability confirmed. The 14-day deadline and review draft were created.");
    await loadCases();
  } catch (error) {
    caseMessage(error.message, true);
  }
}

function renderCases(cases) {
  cases.forEach(item => CASE_VERSIONS.set(item.id, item.version));
  const host = $("cases-body");
  host.replaceChildren();
  if (!cases.length) {
    host.append(el("article", "card empty-state", "No remediation cases yet. Open Article 14 and choose Track remediation on a finding."));
    return;
  }
  for (const item of cases) {
    const card = el("article", "card case-card");
    const head = el("div", "card-head");
    head.append(el("h3", "", `${item.cve} — ${item.component} ${item.component_version}`));
    const statusClass = item.status === "measure_confirmed" ? "good" : item.status === "candidate_resolution" ? "blue" : "medium";
    head.append(el("span", `pill ${statusClass}`, item.status.replaceAll("_", " ")));
    card.append(head);
    card.append(el("p", "sub", `Source evidence: ${item.source_run_id} · PandaX detects and documents; it never patches or deploys.`));
    if (item.finding.summary) card.append(el("p", "", item.finding.summary));
    const correction = el("p", "sub");
    correction.append(el("b", "", item.finding.fixed_version
      ? `Published correction found: ${item.finding.fixed_version}`
      : "No published correction found in the checked source."));
    if (item.finding.source_url) {
      correction.append(document.createTextNode(" "));
      const sourceLink = el("a", "link", "Open source");
      sourceLink.href = item.finding.source_url;
      sourceLink.target = "_blank";
      sourceLink.rel = "noopener";
      correction.append(sourceLink);
    }
    card.append(correction);

    if (item.candidate) {
      const candidate = el("div", "candidate");
      candidate.append(el("b", "", item.candidate.coverage_statement));
      candidate.append(el("p", "", item.candidate.explanation));
      card.append(candidate);
    }

    const compare = el("div", "case-actions");
    const options = laterRunOptions(item);
    compare.innerHTML = `<label>Later analyzed release<select id="target-${esc(item.id)}">${options.html}</select></label>`;
    const compareButton = el("button", "btn", "Analyze release");
    compareButton.disabled = !options.available;
    compareButton.addEventListener("click", () => observeCase(item.id));
    compare.append(compareButton);
    card.append(compare);

    if (item.final_deadline) {
      const deadline = el("div", "deadline");
      deadline.append(el("b", "", `Final report due ${item.final_deadline}`));
      deadline.append(el("p", "", `Confirmed by ${item.operator}: ${item.measure_details}`));
      const report = el("a", "link", "Open review draft");
      report.href = `/api/cases/${item.id}/report`;
      report.target = "_blank";
      report.rel = "noopener";
      deadline.append(report);
      card.append(deadline);
    } else {
      const form = el("div", "case-grid");
      form.innerHTML = `
        <label>Named operator<input id="operator-${esc(item.id)}" autocomplete="name" placeholder="Manufacturer representative"></label>
        <label>Measure available at (UTC)<input id="available-${esc(item.id)}" type="datetime-local"></label>
        <label>Corrective or mitigating measure<textarea id="measure-${esc(item.id)}" placeholder="What users can obtain or apply, product release, and distribution channel"></textarea></label>`;
      card.append(form);
      const attest = el("label", "attestation");
      attest.innerHTML = `<input id="attest-${esc(item.id)}" type="checkbox"> I am authorised by the manufacturer to confirm this measure is available to affected users.`;
      card.append(attest);
      const confirm = el("button", "btn primary", "Confirm availability and calculate deadline");
      confirm.addEventListener("click", () => confirmCase(item.id));
      card.append(confirm);
    }

    const history = el("details");
    history.append(el("summary", "", `${item.events.length} recorded event(s)`));
    const events = el("ul");
    item.events.forEach((event) => events.append(el("li", "", `${event.recorded_at} · ${event.event_type} · ${event.actor || "system"}`)));
    history.append(events);
    card.append(history);
    card.append(reviewForm(item));
    host.append(card);
  }
}

async function loadCases() {
  try {
    renderCases(await caseRequest("/api/cases"));
  } catch (error) {
    caseMessage(error.message, true);
  }
}

$("refresh-cases").addEventListener("click", loadCases);

function reviewForm(item) {
  const details = el('details');
  details.append(el('summary', '', 'Review facts and report'));
  details.append(el('pre', '', JSON.stringify(item.state, null, 2)));
  details.append(el('p', 'sub', item.approved ? 'Latest revision approved' : 'Review required — latest revision is not approved'));
  const form = el('form', 'case-grid');
  form.innerHTML = `
    <label>Action<select name="action">
      <option value="record-awareness">Record or correct factual dates</option>
      <option value="record-decision">Decide reportability</option>
      <option value="revise">Save report revision</option>
      <option value="approve">Approve latest exact revision</option>
    </select></label>
    <label>Named operator<input name="operator" required></label>
    <label>Authority attestation<input name="authority_attestation" required></label>
    <label>Occurrence time (ISO with timezone)<input name="occurred_at" placeholder="2026-09-08T12:00:00Z"></label>
    <label>Detection time (ISO with timezone)<input name="detected_at"></label>
    <label>Awareness time (ISO with timezone)<input name="aware_at"></label>
    <label>Evidence<textarea name="evidence"></textarea></label>
    <label>Reason / correction reason<textarea name="reason"></textarea></label>
    <label>Reportability<select name="reportability"><option>under_review</option><option>reportable</option><option>not_reportable</option></select></label>
    <label>Report content (JSON)<textarea name="payload">{}</textarea></label>
    <button class="btn primary">Save reviewed action</button>`;
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(form));
    const action = values.action;
    const body = {operator: values.operator, authority_attestation: values.authority_attestation};
    if (action === 'record-awareness') {
      for (const key of ['occurred_at', 'detected_at', 'aware_at', 'evidence', 'reason']) if (values[key]) body[key] = values[key];
    } else if (action === 'record-decision') {
      Object.assign(body, {reportability: values.reportability, evidence: values.evidence, reason: values.reason});
    } else if (action === 'approve') {
      Object.assign(body, {revision: item.report?.revision, report_hash: item.report?.report_hash, approved_at: new Date().toISOString()});
    }
    try {
      if (action === 'revise') Object.assign(body, {payload: JSON.parse(values.payload), reason: values.reason});
      await caseRequest(`/api/cases/${item.id}/${action}`, {method: 'POST', body: JSON.stringify(body)});
      await loadCases();
      caseMessage('Recorded. Earlier evidence and revisions remain in history.');
    } catch (error) { caseMessage(error.message, true); }
  });
  details.append(form);
  const revisions = el('details');
  revisions.append(el('summary', '', `${item.revisions.length} immutable report revision(s)`));
  revisions.append(el('pre', '', JSON.stringify(item.revisions, null, 2)));
  details.append(revisions);
  return details;
}

