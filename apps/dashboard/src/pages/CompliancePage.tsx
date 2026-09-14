import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useDemo } from "../data/DemoProvider";
import { MetricCard, PageHeader, StatusPill, memberName, relativeDate } from "./PageKit";
import "./pages.css";

type View = "all" | "deadlines" | "evidence" | "cases" | "approvals" | "monitoring";
const views: [View, string][] = [["all", "All work"], ["deadlines", "Deadlines"], ["evidence", "Missing evidence"], ["cases", "Reporting cases"], ["approvals", "Approvals"], ["monitoring", "Monitoring"]];

export function CompliancePage() {
  const demo = useDemo();
  const [params, setParams] = useSearchParams();
  const requested = params.get("view") as View;
  const view = views.some(([id]) => id === requested) ? requested : "all";
  const product = params.get("product") ?? "all";
  const release = params.get("release") ?? "all";
  const [status, setStatus] = useState("all");
  const scoped = useMemo(() => demo.complianceItems
    .filter((item) => product === "all" || item.productId === product)
    .filter((item) => release === "all" || item.releaseId === release), [demo.complianceItems, product, release]);
  const items = useMemo(() => scoped
    .filter((item) => status === "all" || item.status === status)
    .filter((item) => viewMatch(item.type, view))
    .sort((a, b) => ({ urgent: 0, high: 1, normal: 2, low: 3 }[a.priority] - { urgent: 0, high: 1, normal: 2, low: 3 }[b.priority]) || ((a.dueAt ? new Date(a.dueAt).getTime() : Infinity) - (b.dueAt ? new Date(b.dueAt).getTime() : Infinity))), [scoped, status, view]);
  const updateParams = (patch: Record<string, string | undefined>) => {
    const next = new URLSearchParams(params);
    Object.entries(patch).forEach(([key, value]) => value && value !== "all" ? next.set(key, value) : next.delete(key));
    setParams(next, { replace: true });
  };
  const urgent = scoped.filter((item) => item.priority === "urgent" && item.status !== "complete").length;
  const missing = scoped.filter((item) => item.type === "missing_evidence" && item.status !== "complete").length;
  const approvals = scoped.filter((item) => item.type === "approval" && item.status !== "complete").length;

  return <main className="page">
    <PageHeader eyebrow="EU Cyber Resilience Act" title="Compliance" description="Cross-product readiness, deadlines, reporting cases, evidence gaps, and approvals." />
    <section className="metrics-grid"><MetricCard label="Urgent obligations" value={urgent} detail="Immediate review required" tone="urgent" /><MetricCard label="Evidence gaps" value={missing} detail="Blocking readiness" tone="high" /><MetricCard label="Awaiting approval" value={approvals} detail="Authorized approver action" /></section>
    <section className="panel">
      <nav className="tabs" aria-label="Compliance views">{views.map(([id, label]) => <button key={id} className={view === id ? "active" : ""} style={{ border: 0, borderRadius: 0, background: "transparent" }} onClick={() => updateParams({ view: id })}>{label}</button>)}</nav>
      <div className="toolbar">
        <select className="select-field" value={product} onChange={(event) => updateParams({ product: event.target.value, release: undefined })} aria-label="Product"><option value="all">All products</option>{demo.products.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select>
        <select className="select-field" value={release} onChange={(event) => updateParams({ release: event.target.value })} aria-label="Release"><option value="all">All releases</option>{demo.releases.filter((item) => product === "all" || item.productId === product).map((item) => <option key={item.id} value={item.id}>{demo.selectors.product(item.productId)?.name} {item.version}</option>)}</select>
        <select className="select-field" value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Status"><option value="all">All statuses</option><option value="open">Open</option><option value="in_progress">In progress</option><option value="blocked">Blocked</option><option value="complete">Complete</option></select>
      </div>
      <div className="data-table-wrap"><table className="data-table"><thead><tr><th>Priority</th><th>Obligation</th><th>Product / Release</th><th>Requirement</th><th>Status</th><th>Owner</th><th>Due</th></tr></thead><tbody>{items.map((item) => { const itemProduct = demo.selectors.product(item.productId); const itemRelease = demo.selectors.release(item.releaseId); return <tr key={item.id}><td><StatusPill value={item.priority} /></td><td><div className="cell-primary"><Link to={item.targetUrl}>{item.title}</Link><small>{item.reason}</small></div></td><td><div className="cell-primary"><Link to={`/products/${item.productId}`}>{itemProduct?.name}</Link><small>{itemRelease?.version ?? "Product scope"}</small></div></td><td>{item.requirement}</td><td><StatusPill value={item.status} /></td><td>{memberName(demo.state.members, item.ownerId)}</td><td className={item.priority === "urgent" ? "danger-text" : ""}>{relativeDate(item.dueAt)}</td></tr>; })}</tbody></table></div>
      <div className="mobile-card-list">{items.map((item) => <article className="mobile-card" key={item.id}><div className="inline-actions"><StatusPill value={item.priority} /><StatusPill value={item.status} /></div><div className="cell-primary"><Link to={item.targetUrl}>{item.title}</Link><small>{demo.selectors.product(item.productId)?.name} · {item.requirement}</small></div></article>)}</div>
    </section>
    <p className="muted">Showing {items.length} compliance items, ordered by priority and deadline.</p>
  </main>;
}

function viewMatch(type: string, view: View) {
  if (view === "all") return true;
  if (view === "deadlines") return type === "deadline";
  if (view === "evidence") return type === "missing_evidence";
  if (view === "cases") return type === "reporting_case";
  if (view === "approvals") return type === "approval";
  return type === "readiness";
}
