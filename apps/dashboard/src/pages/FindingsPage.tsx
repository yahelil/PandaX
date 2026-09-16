import { type FormEvent, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { usePermission } from "../auth/permissions";
import { useDemo } from "../data/DemoProvider";
import type { Finding } from "../data/types";
import { PageHeader, StatusPill, memberName, relativeDate, titleCase } from "./PageKit";
import "./pages.css";

type FindingView = "needs_action" | "all" | "critical_high" | "kev" | "reachable" | "low_noise" | "unreviewed" | "remediation";

const views: { id: FindingView; label: string }[] = [
  { id: "needs_action", label: "Needs action" },
  { id: "all", label: "All" },
  { id: "critical_high", label: "Critical + High" },
  { id: "kev", label: "KEV / exploited" },
  { id: "reachable", label: "Reachable" },
  { id: "low_noise", label: "Low-noise review" },
  { id: "unreviewed", label: "Unreviewed" },
  { id: "remediation", label: "Needs remediation" },
];

const priorityRank = { urgent: 0, high: 1, normal: 2, low: 3 } as const;

export function FindingsPage() {
  const demo = useDemo();
  const canDecide = usePermission("decide_findings");
  const [params] = useSearchParams();
  const [view, setView] = useState<FindingView>("needs_action");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [owner, setOwner] = useState("all");
  const [selected, setSelected] = useState<string[]>([]);
  const [rationale, setRationale] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const productParam = params.get("product");
  const releaseParam = params.get("release");

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

  const approve = async (event: FormEvent) => {
    event.preventDefault();
    const cleanRationale = rationale.trim();
    if (!canSubmitBatchApproval(selected.length, cleanRationale, confirmed, canDecide, busy)) return;
    setBusy(true);
    setMessage("");
    setError("");
    try {
      await demo.actions.decideFindings({ findingIds: selected, rationale: cleanRationale });
      setMessage(`${selected.length} recommendation${selected.length === 1 ? "" : "s"} approved as not affected.`);
      setSelected([]);
      setRationale("");
      setConfirmed(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to approve the selected recommendations.");
    } finally {
      setBusy(false);
    }
  };

  const allVisibleSelected = rows.length > 0 && rows.every((item) => selected.includes(item.id));

  return <main className="page">
    <PageHeader eyebrow="Vulnerability operations" title="Findings" description="Review what requires a decision or remediation. Priority combines exploit evidence, affectedness, reachability, and deadlines." />
    <section className="panel">
      <nav className="tabs" aria-label="Finding views">
        {views.map((item) => <button aria-current={view === item.id ? "page" : undefined} className={view === item.id ? "active" : ""} style={{ border: 0, borderRadius: 0, background: "transparent" }} key={item.id} onClick={() => changeView(item.id)}>{item.label}</button>)}
      </nav>
      {view === "low_noise" ? <div className="panel-pad muted">High-confidence non-reachability recommendations remain visible until an authorized reviewer records a reasoned decision.</div> : null}
      <div className="toolbar">
        <input className="search-field" type="search" aria-label="Search findings" placeholder="Search CVE, component, or finding…" value={query} onChange={(event) => setQuery(event.target.value)} />
        <select className="select-field" aria-label="Severity" value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
        <select className="select-field" aria-label="Owner" value={owner} onChange={(event) => setOwner(event.target.value)}><option value="all">All owners</option><option value="unassigned">Unassigned</option>{demo.state.members.filter((member) => member.status === "active").map((member) => <option key={member.id} value={member.id}>{member.name}</option>)}</select>
      </div>
      <div className="data-table-wrap">
        <table className="data-table">
          <thead><tr>{view === "low_noise" ? <th><label><input type="checkbox" aria-label="Select all visible recommendations" checked={allVisibleSelected} onChange={() => setSelected(allVisibleSelected ? [] : rows.map((item) => item.id))} /> Select</label></th> : null}<th>Priority</th><th>Finding</th><th>Product / Release</th><th>Severity</th><th>Risk evidence</th><th>Status</th><th>Owner</th><th>Due</th></tr></thead>
          <tbody>{rows.map((finding) => {
            const product = demo.selectors.product(finding.productId);
            const release = demo.selectors.release(finding.releaseId);
            return <tr key={finding.id}>
              {view === "low_noise" ? <td><input type="checkbox" aria-label={`Select ${finding.reference}`} checked={selected.includes(finding.id)} onChange={() => toggle(finding.id)} /></td> : null}
              <td><StatusPill value={finding.priority} /></td>
              <td><div className="cell-primary"><Link to={`/findings/${finding.id}`}>{finding.reference}</Link><small>{finding.title}</small><small>{finding.component} {finding.componentVersion}</small></div></td>
              <td><div className="cell-primary"><Link to={`/products/${finding.productId}`}>{product?.name}</Link><small>{release?.version}</small></div></td>
              <td><StatusPill value={finding.severity} /></td>
              <td>{riskEvidence(finding)}</td>
              <td><StatusPill value={finding.status} /></td>
              <td>{memberName(demo.state.members, finding.assigneeId)}</td>
              <td className={finding.priority === "urgent" ? "danger-text" : ""}>{relativeDate(finding.dueAt)}</td>
            </tr>;
          })}</tbody>
        </table>
      </div>
      <div className="mobile-card-list">{rows.map((finding) => <article className="mobile-card" key={finding.id}>
        <div className="inline-actions">{view === "low_noise" ? <label><input type="checkbox" checked={selected.includes(finding.id)} onChange={() => toggle(finding.id)} /> Select {finding.reference}</label> : null}<StatusPill value={finding.priority} /><StatusPill value={finding.status} /></div>
        <div className="cell-primary"><Link to={`/findings/${finding.id}`}>{finding.reference} · {finding.title}</Link><small>{demo.selectors.product(finding.productId)?.name} · {finding.component}</small><small>{riskEvidence(finding)}</small></div>
      </article>)}</div>
      {view === "low_noise" ? <form className="setting-section panel-pad" onSubmit={approve}>
        <h2>Approve selected recommendations</h2>
        {!canDecide ? <div className="notice">Only a Security Reviewer or Organization Admin can approve reachability recommendations.</div> : null}
        {message ? <div className="notice" role="status">{message}</div> : null}
        {error ? <div className="notice" role="alert">{error}</div> : null}
        <div className="field"><label htmlFor="batch-rationale">Rationale</label><textarea id="batch-rationale" className="textarea-field" required value={rationale} disabled={!canDecide || busy} onChange={(event) => setRationale(event.target.value)} placeholder="Explain why the selected findings can be approved as not affected." /></div>
        <label><input type="checkbox" checked={confirmed} disabled={!canDecide || busy} onChange={(event) => setConfirmed(event.target.checked)} /> I confirm the selected recommendations and evidence support a not-affected decision.</label>
        <div className="inline-actions"><button className="button-primary" type="submit" disabled={!canSubmitBatchApproval(selected.length, rationale, confirmed, canDecide, busy)}>{busy ? "Approving…" : `Approve selected (${selected.length})`}</button></div>
      </form> : null}
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
