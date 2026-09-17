import { type FormEvent, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { usePermission } from "../auth/permissions";
import { useDemo } from "../data/DemoProvider";
import type { Finding } from "../data/types";
import { PageHeader, StatusPill, memberName, relativeDate, titleCase } from "./PageKit";
import { craReportingWindows, remediationDue } from "./findingDeadlines";
import { downloadFile } from "./downloadFile";
import { ExactTimerBadge } from "../components/ExactTimerBadge";
import { getFindingTimers } from "./exactTimers";
import "./pages.css";

type FindingView = "needs_action" | "all" | "critical_high" | "kev" | "reachable" | "low_noise" | "unreviewed" | "remediation";

const mainViews: { id: FindingView; label: string }[] = [
  { id: "needs_action", label: "Needs action" },
  { id: "unreviewed", label: "Unreviewed" },
  { id: "all", label: "All" },
];

const priorityRank = { urgent: 0, high: 1, normal: 2, low: 3 } as const;

export const DEFAULT_AUTO_TRIAGE_RATIONALE =
  "Automated triage: high-confidence non-reachability verified via static call-graph and component exposure analysis.";

export function FindingsPage() {
  const demo = useDemo();
  const canDecide = usePermission("decide_findings");
  const canGenerateReport = usePermission("generate_findings_report");
  const [params] = useSearchParams();
  const [view, setView] = useState<FindingView>(params.get("view") === "unreviewed" ? "unreviewed" : "needs_action");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [owner, setOwner] = useState("all");
  const [selected, setSelected] = useState<string[]>([]);
  const [rationale, setRationale] = useState("");
  const [batchDecision, setBatchDecision] = useState<"affected" | "not_affected">("affected");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [generatingState, setGeneratingState] = useState<{ releaseId: string; format: "pdf" | "json" } | undefined>();
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const productParam = params.get("product");
  const releaseParam = params.get("release");

  const eligibleFindings = useMemo(() => demo.findings
    .filter((item) => !productParam || item.productId === productParam)
    .filter((item) => !releaseParam || item.releaseId === releaseParam)
    .filter(lowNoiseRecommendation),
  [demo.findings, productParam, releaseParam]);

  const rows = useMemo(() => demo.findings
    .filter((item) => !productParam || item.productId === productParam)
    .filter((item) => !releaseParam || item.releaseId === releaseParam)
    .filter((item) => matchView(item, view))
    .filter((item) => severity === "all" || item.severity === severity)
    .filter((item) => owner === "all" || (owner === "unassigned" ? !item.assigneeId : item.assigneeId === owner))
    .filter((item) => !query || `${item.reference} ${item.title} ${item.component}`.toLowerCase().includes(query.toLowerCase()))
    .sort((left, right) => priorityRank[left.priority] - priorityRank[right.priority]),
  [demo.findings, owner, productParam, query, releaseParam, severity, view]);

  const toggle = (findingId: string) => {
    const chosen = demo.findings.find((item) => item.id === findingId);
    const first = demo.findings.find((item) => item.id === selected[0]);
    if (chosen && first && (chosen.productId !== first.productId || chosen.releaseId !== first.releaseId)) return;
    setSelected((current) => current.includes(findingId)
      ? current.filter((id) => id !== findingId)
      : [...current, findingId]);
  };

  const changeView = (next: FindingView) => {
    setView(next);
    setSelected([]);
    setConfirmed(false);
    setMessage("");
    setError("");
  };

  const autoTriage = async (findingIds: string[]) => {
    if (!canDecide || busy || findingIds.length === 0) return;
    setBusy(true);
    setMessage("");
    setError("");
    try {
      await demo.actions.decideFindings({
        findingIds,
        recommendationsOnly: true,
        rationale: DEFAULT_AUTO_TRIAGE_RATIONALE,
      });
      setMessage(`${findingIds.length} recommendation${findingIds.length === 1 ? "" : "s"} approved as not affected.`);
      setSelected([]);
      setRationale("");
      setConfirmed(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to auto-triage recommendations.");
    } finally {
      setBusy(false);
    }
  };

  const approve = async (event: FormEvent) => {
    event.preventDefault();
    const cleanRationale = rationale.trim();
    if (!canSubmitBatchApproval(selected.length, cleanRationale, confirmed, canDecide, busy)) return;
    setBusy(true);
    setMessage("");
    setError("");
    try {
      await demo.actions.decideFindings({ findingIds: selected, decision: batchDecision, rationale: cleanRationale });
      setMessage(`${selected.length} finding${selected.length === 1 ? "" : "s"} marked ${batchDecision === "affected" ? "affected" : "not affected"}.`);
      setSelected([]);
      setRationale("");
      setConfirmed(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to approve the selected recommendations.");
    } finally {
      setBusy(false);
    }
  };

  const selectedScope = demo.findings.find((item) => item.id === selected[0]);
  const generateReport = async (finding: Finding, format: "pdf" | "json" = "pdf") => {
    setGeneratingState({ releaseId: finding.releaseId, format });
    setError("");
    try {
      if (format === "pdf") {
        const file = await demo.actions.generateSecurityPdf(finding.productId, finding.releaseId);
        downloadFile(file, `actis-${finding.releaseId}-security-report.pdf`);
        setMessage("Product release security report (PDF) downloaded.");
      } else {
        const file = await demo.actions.generateFindingsReport(finding.productId, finding.releaseId);
        downloadFile(file, `actis-${finding.releaseId}-findings-report.json`);
        setMessage("Release findings report (JSON) downloaded. It includes the decisions and remediation status.");
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : `Could not generate the findings ${format.toUpperCase()} report.`);
    } finally {
      setGeneratingState(undefined);
    }
  };
  const reviewableRows = rows.filter((item) => item.status === "needs_review" && item.decisions.length === 0
    && (!selectedScope || (item.productId === selectedScope.productId && item.releaseId === selectedScope.releaseId)));
  const visibleBatch = reviewableRows.filter((item) => item.productId === reviewableRows[0]?.productId && item.releaseId === reviewableRows[0]?.releaseId);
  const allVisibleSelected = reviewableRows.length > 0 && reviewableRows.every((item) => selected.includes(item.id));

  return <main className="page">
    <PageHeader
      eyebrow="Vulnerability operations"
      title="Findings"
      description="Review what requires a decision or remediation. Priority combines exploit evidence, affectedness, reachability, and deadlines."
      actions={
        canDecide && eligibleFindings.length > 0 ? (
          <button
            type="button"
            className="button button-primary"
            disabled={busy}
            onClick={() => autoTriage(eligibleFindings.map((item) => item.id))}
          >
            {busy ? "Triaging…" : `Auto-triage low noise (${eligibleFindings.length})`}
          </button>
        ) : undefined
      }
    />
    <section className="panel">
      {message ? <div className="panel-pad notice" role="status">{message}</div> : null}
      {error ? <div className="panel-pad notice notice-warning" role="alert">{error}</div> : null}
      <nav className="tabs" aria-label="Finding views">
        {mainViews.map((item) => (
          <button aria-current={view === item.id ? "page" : undefined} className={view === item.id ? "active" : ""} style={{ border: 0, borderRadius: 0, background: "transparent" }} key={item.id} onClick={() => changeView(item.id)}>{item.label}</button>
        ))}
        {eligibleFindings.length > 0 ? (
          <button aria-current={view === "low_noise" ? "page" : undefined} className={view === "low_noise" ? "active" : ""} style={{ border: 0, borderRadius: 0, background: "transparent" }} onClick={() => changeView("low_noise")}>⚡ Low-noise review ({eligibleFindings.length})</button>
        ) : null}
      </nav>
      {view === "low_noise" ? <div className="panel-pad muted">High-confidence non-reachability recommendations remain visible until an authorized reviewer records a reasoned decision.</div> : null}
      <div className="toolbar">
        <input className="search-field" type="search" aria-label="Search findings" placeholder="Search CVE, component, or finding…" value={query} onChange={(event) => setQuery(event.target.value)} />
        <select className="select-field" aria-label="Severity" value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
        <select className="select-field" aria-label="Special focus" value={["critical_high", "kev", "reachable", "remediation"].includes(view) ? view : "all"} onChange={(event) => {
          const val = event.target.value;
          changeView(val === "all" ? "needs_action" : val as FindingView);
        }}>
          <option value="all">All focus</option>
          <option value="critical_high">Critical + High</option>
          <option value="kev">KEV / exploited</option>
          <option value="reachable">Reachable</option>
          <option value="remediation">Needs remediation</option>
        </select>
        <select className="select-field" aria-label="Owner" value={owner} onChange={(event) => setOwner(event.target.value)}><option value="all">All owners</option><option value="unassigned">Unassigned</option>{demo.state.members.filter((member) => member.status === "active").map((member) => <option key={member.id} value={member.id}>{member.name}</option>)}</select>
        {canDecide && reviewableRows.length > 0 && selected.length === 0 ? (
          <button
            type="button"
            className="button button-small"
            style={{ marginLeft: "auto" }}
            onClick={() => {
              setSelected(visibleBatch.map((item) => item.id));
              setConfirmed(false);
            }}
          >
            Select unreviewed ({visibleBatch.length})
          </button>
        ) : null}
      </div>
      <div className="data-table-wrap">
        <table className="data-table">
          <thead><tr><th><label><input type="checkbox" aria-label="Select all visible unreviewed findings from one release" checked={allVisibleSelected} onChange={() => setSelected(allVisibleSelected ? [] : visibleBatch.map((item) => item.id))} /> Select</label></th><th>Finding</th><th>Product / Release</th><th>Severity</th><th>Risk evidence</th><th>Status</th><th>Owner</th><th>Deadline</th></tr></thead>
          <tbody>{rows.map((finding) => {
            const product = demo.selectors.product(finding.productId);
            const release = demo.selectors.release(finding.releaseId);
            const timers = getFindingTimers(finding);
            return <tr key={finding.id} className={`finding-row priority-border-${finding.priority}`}>
              <td><input type="checkbox" aria-label={`Select ${finding.reference}`} disabled={!reviewableRows.includes(finding)} checked={selected.includes(finding.id)} onChange={() => toggle(finding.id)} /></td>
              <td><div className="cell-primary"><Link to={`/findings/${finding.id}`}>{finding.reference}</Link><small>{finding.title}</small><small>{finding.component} {finding.componentVersion}</small></div></td>
              <td><div className="cell-primary"><Link to={`/products/${finding.productId}`}>{product?.name}</Link><small>{release?.version}</small></div></td>
              <td><StatusPill value={finding.severity} /></td>
              <td>{riskEvidence(finding)}</td>
              <td>{finding.status === "needs_review" ? <Link to={`/findings/${finding.id}#risk-decision`} aria-label={`Review ${finding.reference}`} className="status-pill-link" title="Click to write review decision and rationale"><StatusPill value={finding.status} /></Link> : finding.status === "action_required" || finding.status === "in_remediation" ? <Link to={`/findings/${finding.id}#remediation`} aria-label={`Plan fix for ${finding.reference}`} className="status-pill-link" title="Click to plan and write fix details"><StatusPill value={finding.status} label={finding.status === "action_required" ? "Fix required" : undefined} /></Link> : <Link to={`/findings/${finding.id}`} className="status-pill-link" title="Click to view finding details"><StatusPill value={finding.status} /></Link>}</td>
              <td>{memberName(demo.state.members, finding.assigneeId)}</td>
              <td>
                {timers.mostUrgent ? <ExactTimerBadge timer={timers.mostUrgent} compact /> : <span className="muted">—</span>}
              </td>
            </tr>;
          })}</tbody>
        </table>
      </div>
      <div className="mobile-card-list">{rows.map((finding) => {
        const timers = getFindingTimers(finding);
        return <article className="mobile-card" key={finding.id}>
          <div className="inline-actions"><label><input type="checkbox" disabled={!reviewableRows.includes(finding)} checked={selected.includes(finding.id)} onChange={() => toggle(finding.id)} /> Select {finding.reference}</label><StatusPill value={finding.priority} />{finding.status === "needs_review" ? <Link to={`/findings/${finding.id}#risk-decision`} className="status-pill-link" title="Click to write review decision"><StatusPill value={finding.status} /></Link> : finding.status === "action_required" || finding.status === "in_remediation" ? <Link to={`/findings/${finding.id}#remediation`} className="status-pill-link" title="Click to plan fix"><StatusPill value={finding.status} label={finding.status === "action_required" ? "Fix required" : undefined} /></Link> : <StatusPill value={finding.status} />}</div>
          <div className="cell-primary">
            <Link to={`/findings/${finding.id}`}>{finding.reference} · {finding.title}</Link>
            <small>{demo.selectors.product(finding.productId)?.name} · {finding.component}</small>
            <small>{riskEvidence(finding)}</small>
            {timers.mostUrgent ? <div style={{ marginTop: "4px" }}><ExactTimerBadge timer={timers.mostUrgent} compact /></div> : null}
            {finding.status === "action_required" ? <Link to={`/findings/${finding.id}#remediation`}>Plan fix</Link> : null}
            {(finding.status === "action_required" || finding.status === "in_remediation") && canGenerateReport ? (
              <div className="inline-actions" style={{ marginTop: "4px" }}>
                <button
                  type="button"
                  className="button button-primary"
                  style={{ padding: "4px 8px", fontSize: "12px", minHeight: "30px" }}
                  disabled={Boolean(generatingState)}
                  onClick={() => void generateReport(finding, "pdf")}
                  title="Download formatted PDF security report"
                >
                  {generatingState?.releaseId === finding.releaseId && generatingState.format === "pdf" ? "Generating…" : "Download PDF report"}
                </button>
                <button
                  type="button"
                  className="button"
                  style={{ padding: "4px 8px", fontSize: "12px", minHeight: "30px" }}
                  disabled={Boolean(generatingState)}
                  onClick={() => void generateReport(finding, "json")}
                  title="Export raw findings JSON"
                >
                  {generatingState?.releaseId === finding.releaseId && generatingState.format === "json" ? "Exporting…" : "Export JSON"}
                </button>
              </div>
            ) : null}
          </div>
        </article>;
      })}</div>
      {selected.length > 0 ? (
        <form className="setting-section panel-pad batch-review-drawer" onSubmit={approve}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h2>Review {selected.length} selected finding{selected.length === 1 ? "" : "s"}</h2>
            <button type="button" className="text-button" onClick={() => setSelected([])}>Clear selection</button>
          </div>
          <p className="muted">Select findings from one release that you have reviewed together. Record whether they affect it; a not-affected decision closes a false alarm.</p>
          {!canDecide ? <div className="notice">Your role cannot record finding decisions.</div> : null}
          <div className="field"><label htmlFor="batch-decision">Decision</label><select id="batch-decision" className="select-field" value={batchDecision} disabled={!canDecide || busy} onChange={(event) => { setBatchDecision(event.target.value as "affected" | "not_affected"); setConfirmed(false); }}><option value="affected">Affected — needs remediation</option><option value="not_affected">Not affected — false alarm</option></select></div>
          <div className="field">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
              <label htmlFor="batch-rationale">Rationale</label>
              {selected.length > 0 && selected.every((id) => eligibleFindings.some((item) => item.id === id)) ? <button
                type="button"
                className="button"
                style={{ padding: "3px 8px", fontSize: "12px" }}
                disabled={!canDecide || busy}
                onClick={() => {
                  setBatchDecision("not_affected");
                  setRationale(DEFAULT_AUTO_TRIAGE_RATIONALE);
                  setConfirmed(false);
                }}
              >
                Use standard rationale
              </button> : null}
            </div>
            <textarea id="batch-rationale" className="textarea-field" required value={rationale} disabled={!canDecide || busy} onChange={(event) => setRationale(event.target.value)} placeholder="Explain your decision using evidence for every selected finding." />
          </div>
          <label><input type="checkbox" checked={confirmed} disabled={!canDecide || busy} onChange={(event) => setConfirmed(event.target.checked)} /> I reviewed each selected finding and its evidence for this decision.</label>
          <div className="inline-actions">
            <button className="button-primary" type="submit" disabled={!canSubmitBatchApproval(selected.length, rationale, confirmed, canDecide, busy)}>{busy ? "Saving…" : `Record decision for ${selected.length} selected`}</button>
            <button type="button" disabled={busy} onClick={() => { setSelected([]); setConfirmed(false); }}>Cancel</button>
          </div>
        </form>
      ) : null}
    </section>
    <p className="muted">Showing {rows.length} findings</p>
  </main>;
}

export function lowNoiseRecommendation(finding: Finding): boolean {
  return finding.reachabilityRecommendation === "not_reachable"
    && finding.reachabilityConfidence === "high"
    && finding.reachabilityReviewRequired
    && finding.decisions.length === 0;
}

export function canSubmitBatchApproval(selectedCount: number, rationale: string, confirmed: boolean, canDecide: boolean, busy = false): boolean {
  return selectedCount > 0 && Boolean(rationale.trim()) && confirmed && canDecide && !busy;
}

function matchView(finding: Finding, view: FindingView): boolean {
  if (view === "all") return true;
  if (view === "needs_action") return finding.status === "needs_review" || finding.status === "action_required" || finding.status === "in_remediation";
  if (view === "critical_high") return finding.severity === "critical" || finding.severity === "high";
  if (view === "kev") return finding.kev || finding.activelyExploited;
  if (view === "reachable") return finding.reachability === "reachable";
  if (view === "low_noise") return lowNoiseRecommendation(finding);
  if (view === "unreviewed") return finding.status === "needs_review";
  return finding.remediation.status !== "verified" && finding.affectedness === "confirmed";
}

function riskEvidence(finding: Finding): string {
  const signals = [
    finding.kev && "KEV",
    finding.activelyExploited && "Active exploitation",
    finding.affectedness === "confirmed" && "Affected",
    finding.reachability === "reachable" && "Reachable",
    finding.reachabilityRecommendation === "not_reachable" && `${titleCase(finding.reachabilityConfidence)}-confidence not-reachable recommendation`,
  ].filter(Boolean);
  return signals.join(" · ") || "Insufficient evidence";
}
