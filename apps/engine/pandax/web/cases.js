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
  let pendingKey;
  if (options.method === "POST") {
    const body = JSON.parse(options.body || "{}");
    const id = path.split("/")[3];
    if (CASE_VERSIONS.has(id)) body.expected_version = CASE_VERSIONS.get(id);
    pendingKey = 'case-request:' + path + ':' + JSON.stringify(body);
    body.request_id ||= sessionStorage.getItem(pendingKey) || crypto.randomUUID();
    sessionStorage.setItem(pendingKey, body.request_id);
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, {
    headers: {"Content-Type": "application/json"},
    ...options,
  });
  const payload = await response.json();
  if (pendingKey) sessionStorage.removeItem(pendingKey);
  if (!response.ok) throw new Error((typeof payload.detail === 'string' ? payload.detail : JSON.stringify(payload.detail)) || `Request failed (${response.status})`);
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
    head.append(el("h3", "", item.case_type === 'incident' ? item.state.incident.title : `${item.cve} — ${item.component} ${item.component_version}`));
    const statusClass = item.status === "measure_confirmed" ? "good" : item.status === "candidate_resolution" ? "blue" : "medium";
    head.append(el("span", `pill ${statusClass}`, item.status.replaceAll("_", " ")));
    card.append(head);
    card.append(el('p', 'sub', Object.entries(item.deadlines).map(([stage, due]) => `${stage}: ${due || 'pending'} (${item.clock_status[stage]})`).join(' · ')));
    card.append(el("p", "sub", item.source_run_id ? "Source evidence: " + item.source_run_id : "Operator-recorded incident; no source scan attached."));
    if (item.finding.summary) card.append(el("p", "", item.finding.summary));
    if (item.case_type === "vulnerability") {
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
    }

    if (item.candidate) {
      const candidate = el("div", "candidate");
      candidate.append(el("b", "", item.candidate.coverage_statement));
      candidate.append(el("p", "", item.candidate.explanation));
      card.append(candidate);
    }

    if (item.case_type === "vulnerability") {
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

    }
    const history = el("details");
    history.append(el("summary", "", `${item.events.length} recorded event(s)`));
    const events = el("ul");
    item.events.forEach(event => events.append(el("li", "", (event.payload.simulated ? "SIMULATED | " : "") + event.recorded_at + " recorded | " + event.occurred_at + " event time | " + event.event_type + " | " + (event.actor || "system"))));
    history.append(events);
    card.append(history);
    card.append(reviewForm(item));
    card.append(reportBuilder(item));
    card.append(submissionForm(item));
    if (item.state.simulated) card.prepend(el('p', 'pill medium', 'SIMULATED CASE — rehearsal only'));
    card.append(el('p', 'sub', item.readiness.status + (item.readiness.missing.length ? ': ' + item.readiness.missing.join(', ') : '')));
    if (item.report) {
      for (const format of ['html', 'json', 'checklist']) {
        const link = el('a', 'btn', `Export ${format}`);
        link.href = `/api/cases/${item.id}/export?format=${format}`;
        link.target = '_blank'; link.rel = 'noopener'; card.append(link);
      }
    }
    host.append(card);
  }
}

async function loadCases() {
  try {
    renderCases(await caseRequest("/api/cases"));
    const watches = await caseRequest("/api/advisory-watches");
    $("advisory-watch-status").textContent = watches.length
      ? watches.map(watch => `${watch.simulated ? "SIMULATED | " : ""}${watch.product_name} ${watch.product_version}: ${watch.case_count} case(s), ${watch.stale ? "STALE since " + watch.stale_since + " — " + watch.last_error : "current as of " + (watch.last_success_at || "first refresh pending")}`).join(" · ")
      : "No releases watched for new advisories.";
  } catch (error) {
    caseMessage(error.message, true);
  }
}

$("refresh-cases").addEventListener("click", loadCases);
$("watch-release").addEventListener("click", async () => {
  try {
    await caseRequest("/api/advisory-watches", {method: "POST", body: JSON.stringify({source_run_id: runId})});
    await loadCases();
    caseMessage("Current release inventory is watched. PandaX will refresh it hourly while the app runs.");
  } catch (error) { caseMessage(error.message, true); }
});
$("refresh-advisories").addEventListener("click", async () => {
  try {
    await caseRequest("/api/advisory-watches/refresh", {method: "POST", body: "{}"});
    await loadCases();
    caseMessage("Advisory refresh finished. Existing results were retained if a source was unavailable.");
  } catch (error) { caseMessage(error.message, true); }
});

function reviewForm(item) {
  const details = el('details');
  details.append(el('summary', '', 'Review facts and report'));
  details.append(el('pre', '', JSON.stringify(item.state, null, 2)));
  details.append(el('p', 'sub', item.approved ? 'Latest revision approved' : 'Review required — latest revision is not approved'));
  const form = el('form', 'case-grid');
  form.innerHTML = `
    <label>Action<select name="action">
      <option value="record-awareness">Record or correct factual dates</option>
      <option value="assess-incident">Update incident assessment</option>
      <option value="record-decision">Decide reportability</option>
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
    <label>Incident severity<input name="severity"></label><label>Incident impact<textarea name="impact"></textarea></label><label>Mitigation<textarea name="mitigation"></textarea></label><label>Likely root cause<textarea name="root_cause"></textarea></label>
    <button class="btn primary">Save reviewed action</button>`;
  const reviewVisibility = () => {
    const actions = {'record-awareness': ['occurred_at', 'detected_at', 'aware_at', 'evidence', 'reason'], 'record-decision': ['reportability', 'evidence', 'reason'], 'assess-incident': ['severity', 'impact', 'mitigation', 'root_cause', 'evidence', 'reason'], approve: []};
    for (const input of form.elements) {
      if (input.name && !['action', 'operator', 'authority_attestation'].includes(input.name)) input.closest('label').hidden = !actions[form.elements.action.value].includes(input.name);
    }
  };
  if (item.case_type !== 'incident') form.elements.action.querySelector('[value="assess-incident"]').remove();
  form.elements.action.addEventListener('change', reviewVisibility); reviewVisibility();
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
      if (action === 'assess-incident') Object.assign(body, Object.fromEntries(['severity', 'impact', 'mitigation', 'root_cause'].filter(key => values[key]).map(key => [key, values[key]])), {evidence: values.evidence, reason: values.reason});
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


const incidentIntake = el('details', 'card');
incidentIntake.append(el('summary', '', 'Open an incident case'));
const incidentForm = el('form', 'case-grid');
for (const key of ['title', 'product_name', 'product_version', 'severity', 'impact', 'operator', 'authority_attestation']) {
  const label = el('label', '', key.replaceAll('_', ' '));
  const input = el('input'); input.name = key; input.required = true;
  label.append(input); incidentForm.append(label);
}
const incidentSubmit = el('button', 'btn primary', 'Record incident');
const simulationLabel = el('label', 'attestation', 'Simulated rehearsal case');
const simulationInput = el('input'); simulationInput.type = 'checkbox'; simulationInput.name = 'simulated';
simulationLabel.prepend(simulationInput); incidentForm.append(simulationLabel);
incidentForm.append(incidentSubmit);
incidentForm.addEventListener('submit', async event => {
  event.preventDefault();
  try {
    await caseRequest('/api/cases/create-incident', {method: 'POST', body: JSON.stringify({...Object.fromEntries(new FormData(incidentForm)), simulated: simulationInput.checked})});
    incidentForm.reset(); await loadCases();
  } catch (error) { caseMessage(error.message, true); }
});
incidentIntake.append(incidentForm);
$('cases-body').before(incidentIntake);

function reportBuilder(item) {
  const details = el('details');
  details.append(el('summary', '', 'Prepare or revise a submission pack'));
  const form = el('form', 'case-grid');
  form.innerHTML = `<label>Stage<select name="stage"><option>early_warning</option><option>notification</option><option>final_report</option></select></label>
    <label>Named operator<input name="operator" required></label>
    <label>Authority attestation<input name="authority_attestation" required></label>`;
  const fields = el('div', 'case-grid');
  fields.style.gridColumn = '1 / -1'; form.append(fields);
  const button = el('button', 'btn primary', 'Save unreviewed revision'); form.append(button);
  let definition;
  async function loadFields() {
    try {
      button.disabled = true;
      definition = await caseRequest(`/api/case-fields/${item.case_type}/${form.elements.stage.value}`);
      fields.replaceChildren();
      for (const field of definition.fields) {
        const previous = item.report?.payload?.fields?.[field.key];
        const label = el('label', '', `${field.label} · ${field.requirement.replaceAll('_', ' ')}`);
        const input = el(field.choices ? 'select' : field.max_length > 255 ? 'textarea' : 'input');
        input.name = 'field-' + field.key;
        if (field.choices) {
          input.append(new Option('Not supplied', ''));
          for (const choice of field.choices) input.append(new Option(choice, choice));
        } else input.maxLength = field.max_length;
        const factual = {notification_type: item.case_type === 'incident' ? 'Incident' : 'Vulnerability', aware_at: item.state.aware_at, occurred_at: item.state.occurred_at, measure_available_at: item.measure_available_at};
        const seeds = {product_name: item.source_product.name, product_version: item.source_product.version, cve: item.cve, component: item.component};
        input.value = (field.factual ? factual[field.key] : previous?.value ?? seeds[field.key]) || '';
        if (field.factual) { input.disabled = true; label.append(el('small', '', ' Change through factual case actions.')); }
        label.append(input);
        if (field.requirement === 'if_available') {
          const unavailable = el('input'); unavailable.type = 'checkbox'; unavailable.name = 'unavailable-' + field.key;
          unavailable.checked = previous?.available === false;
          const check = el('label', 'attestation', 'I attest this information is unavailable'); check.prepend(unavailable); label.append(check);
        }
        fields.append(label);
      }
      button.disabled = false;
    } catch (error) { caseMessage(error.message, true); }
  }
  form.elements.stage.addEventListener('change', loadFields);
  details.addEventListener('toggle', () => { if (details.open && !definition) loadFields(); });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const values = new FormData(form); const supplied = {};
    for (const field of definition.fields) {
      if (field.factual) continue;
      supplied[field.key] = values.has('unavailable-' + field.key) ? {value: null, available: false} : {value: values.get('field-' + field.key) || null};
    }
    try {
      await caseRequest(`/api/cases/${item.id}/prepare-report`, {method: 'POST', body: JSON.stringify({stage: values.get('stage'), fields: supplied, operator: values.get('operator'), authority_attestation: values.get('authority_attestation')})});
      await loadCases(); caseMessage('Revision saved. Review missing inputs and approve the exact completed revision.');
    } catch (error) { caseMessage(error.message, true); }
  });
  details.append(form); return details;
}

function submissionForm(item) {
  const details = el('details'); details.append(el('summary', '', 'Submission records, receipts and snapshots'));
  const form = el('form', 'case-grid');
  form.innerHTML = `<label>Action<select name="action"><option value="record-submission">Record manual or simulated attempt</option><option value="attach-receipt">Attach acknowledgement receipt</option><option value="amend">Prepare amendment</option><option value="snapshot">Create sealed snapshot</option></select></label>
    <label>Named operator<input name="operator" required></label>
    <label>Authority attestation<input name="authority_attestation" required></label>
    <label>Result<select name="result"><option>submitted</option><option>failed</option></select></label>
    <label class="attestation"><input name="simulated" type="checkbox" checked>Simulated attempt (rehearsal only)</label>
    <label>Submission time (ISO with timezone)<input name="submitted_at" placeholder="2026-09-15T12:00:00Z"></label>
    <label>Platform reference<input name="platform_reference"></label>
    <label>Failure or amendment reason<textarea name="reason"></textarea></label>
    <label>Previous submission<select name="submission_id"></select></label>
    <label>Receipt file (maximum 5 MiB)<input name="receipt" type="file"></label>
    <label>Acknowledgement time (ISO with timezone)<input name="acknowledged_at"></label>
    <button class="btn primary">Record action</button>`;
  for (const prior of item.submissions) {
    form.elements.submission_id.append(new Option(`${prior.payload.simulated ? 'SIMULATED ' : ''}${prior.payload.stage} · ${prior.status} · ${prior.payload.platform_reference}`, prior.id));
    const history = el('p', 'sub', `${prior.payload.simulated ? 'SIMULATED · ' : ''}${prior.status} · ${prior.payload.submitted_at} · revision ${prior.revision} · ${prior.payload.platform_reference}`);
    for (const receipt of prior.receipts) {
      const link = el('a', 'btn', `Receipt ${receipt.sha256.slice(0, 12)}`);
      link.href = `/api/cases/${item.id}/receipts/${receipt.id}`; history.append(link);
    }
    details.append(history);
  }
  for (const snapshot of item.snapshots) {
    const link = el('a', 'btn', `Snapshot · revision ${snapshot.revision} · ${snapshot.sha256.slice(0, 12)}`);
    link.href = `/api/cases/${item.id}/snapshots/${snapshot.id}`; details.append(link);
  }
  const submissionVisibility = () => {
    const actions = {'record-submission': ['result', 'simulated', 'submitted_at', 'platform_reference', 'reason'], 'attach-receipt': ['submission_id', 'receipt', 'acknowledged_at'], amend: ['submission_id', 'reason'], snapshot: []};
    for (const input of form.elements) {
      if (input.name && !['action', 'operator', 'authority_attestation'].includes(input.name)) input.closest('label').hidden = !actions[form.elements.action.value].includes(input.name);
    }
  };
  form.elements.action.addEventListener('change', submissionVisibility); submissionVisibility();
  form.addEventListener('submit', async event => {
    event.preventDefault(); const values = Object.fromEntries(new FormData(form));
    const body = {operator: values.operator, authority_attestation: values.authority_attestation};
    try {
      if (values.action === 'record-submission') Object.assign(body, {revision: item.report?.revision, report_hash: item.report?.report_hash, result: values.result, simulated: form.elements.simulated.checked, submitted_at: values.submitted_at, platform_reference: values.platform_reference, failure_reason: values.reason});
      if (values.action === 'amend') Object.assign(body, {submission_id: values.submission_id, reason: values.reason, fields: {}});
      if (values.action === 'snapshot') body.revision = item.report?.revision;
      if (values.action === 'attach-receipt') {
        const file = form.elements.receipt.files[0];
        if (!file || file.size > 5 * 1024 * 1024) throw new Error('Choose a receipt file no larger than 5 MiB.');
        const encoded = await new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(reader.result.split(',')[1]); reader.onerror = reject; reader.readAsDataURL(file); });
        Object.assign(body, {submission_id: values.submission_id, filename: file.name, content_base64: encoded, acknowledged_at: values.acknowledged_at});
      }
      await caseRequest(`/api/cases/${item.id}/${values.action}`, {method: 'POST', body: JSON.stringify(body)});
      await loadCases(); caseMessage('Recorded locally. PandaX did not submit anything to a regulator.');
    } catch (error) { caseMessage(error.message, true); }
  });
  details.append(form); return details;
}

const importDetails = el('details', 'card'); importDetails.append(el('summary', '', 'Explicitly import a historical draft'));
const importForm = el('form', 'case-grid');
for (const key of ['source_run_id', 'cve', 'draft_file', 'operator']) {
  const label = el('label', '', key.replaceAll('_', ' ')); const input = el('input'); input.name = key; input.required = true;
  if (key === 'draft_file') input.placeholder = 'filings/example.json'; label.append(input); importForm.append(label);
}
importForm.append(el('button', 'btn', 'Import as unreviewed'));
importForm.addEventListener('submit', async event => {
  event.preventDefault();
  try { await caseRequest('/api/cases/import-draft', {method: 'POST', body: JSON.stringify(Object.fromEntries(new FormData(importForm)))}); await loadCases(); }
  catch (error) { caseMessage(error.message, true); }
});
importDetails.append(importForm); $('cases-body').before(importDetails);
