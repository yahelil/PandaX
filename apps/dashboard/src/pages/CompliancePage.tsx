import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { useDemo } from "../data/DemoProvider";
import type { ComplianceItem, ComplianceLifecycleStatus, ComplianceUpdateCommand } from "../data/types";
import {
  allowedComplianceStatuses,
  compareCompliance,
  compliancePermissions,
  compliancePriority,
  isComplianceResolved,
  lifecycleStatus,
} from "./complianceWorkflow";
import { EmptyState, MetricCard, PageHeader, SectionHeader, StatusPill, formatDate, memberName, relativeDate, titleCase } from "./PageKit";
import "./pages.css";

type View = "all" | "deadlines" | "evidence" | "cases" | "approvals" | "monitoring";
type Sort = "priority" | "due" | "updated" | "status";
const views: [View, string][] = [["all", "All work"], ["deadlines", "Deadlines"], ["evidence", "Missing evidence"], ["cases", "Reporting cases"], ["approvals", "Approvals"], ["monitoring", "Monitoring"]];
const lifecycleStatuses: ComplianceLifecycleStatus[] = ["action_required", "in_progress", "pending_approval", "approved", "acknowledged", "resolved"];

export function CompliancePage() {
  const demo = useDemo();
  const [params, setParams] = useSearchParams();
  const requested = params.get("view") as View;
  const view = views.some(([id]) => id === requested) ? requested : "all";
  const product = params.get("product") ?? "all";
  const release = params.get("release") ?? "all";
  const selectedId = useMemo(() => {
    if (params.get("item")) return params.get("item")!;
    const legacyCase = params.get("case");
    return legacyCase ? demo.complianceItems.find((item) => item.type === "reporting_case" && item.targetUrl.includes(legacyCase))?.id : undefined;
  }, [demo.complianceItems, params]);
  const [status, setStatus] = useState("all");
  const [priority, setPriority] = useState("all");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<Sort>("priority");
  const [direction, setDirection] = useState<"asc" | "desc">("asc");

  const scoped = useMemo(() => demo.complianceItems
    .filter((item) => product === "all" || item.productId === product)
    .filter((item) => release === "all" || item.releaseId === release), [demo.complianceItems, product, release]);
  const items = useMemo(() => {
    const term = query.trim().toLowerCase();
    return scoped
      .filter((item) => status === "all" || lifecycleStatus(item) === status)
      .filter((item) => priority === "all" || item.priority === priority)
      .filter((item) => viewMatch(item.type, view))
      .filter((item) => !term || `${item.title} ${item.reason} ${item.requirement} ${demo.selectors.product(item.productId)?.name ?? "organization"}`.toLowerCase().includes(term))
      .sort((left, right) => compareCompliance(left, right, sort, direction));
  }, [demo.selectors, direction, priority, query, scoped, sort, status, view]);
  const updateParams = (patch: Record<string, string | undefined>) => {
    const next = new URLSearchParams(params);
    Object.entries(patch).forEach(([key, value]) => value && value !== "all" ? next.set(key, value) : next.delete(key));
    setParams(next, { replace: true });
  };
  const urgent = scoped.filter((item) => item.priority === "urgent" && !isComplianceResolved(item)).length;
  const missing = scoped.filter((item) => item.type === "missing_evidence" && !isComplianceResolved(item)).length;
  const approvals = scoped.filter((item) => lifecycleStatus(item) === "pending_approval").length;

  return <main className="page compliance-page">
    <PageHeader eyebrow="EU Cyber Resilience Act" title="Compliance" description="Cross-product readiness, deadlines, reporting cases, evidence gaps, and approvals." />
    <section className="metrics-grid"><MetricCard label="Urgent obligations" value={urgent} detail="Immediate review required" tone="urgent" /><MetricCard label="Evidence gaps" value={missing} detail="Blocking readiness" tone="high" /><MetricCard label="Awaiting approval" value={approvals} detail="Authorized approver action" /></section>
    <section className="panel">
      <nav className="tabs" aria-label="Compliance views">{views.map(([id, label]) => <button key={id} className={view === id ? "active" : ""} onClick={() => updateParams({ view: id })} aria-current={view === id ? "page" : undefined}>{label}</button>)}</nav>
      <div className="toolbar compliance-toolbar">
        <input className="search-field" value={query} onChange={(event) => setQuery(event.target.value)} aria-label="Search compliance work" placeholder="Search obligations, requirements, or products" />
        <select className="select-field" value={product} onChange={(event) => updateParams({ product: event.target.value, release: undefined, item: undefined, case: undefined })} aria-label="Product"><option value="all">All products</option>{demo.products.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select>
        <select className="select-field" value={release} onChange={(event) => updateParams({ release: event.target.value, item: undefined, case: undefined })} aria-label="Release"><option value="all">All releases</option>{demo.releases.filter((item) => product === "all" || item.productId === product).map((item) => <option key={item.id} value={item.id}>{demo.selectors.product(item.productId)?.name} {item.version}</option>)}</select>
        <select className="select-field" value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Lifecycle status"><option value="all">All statuses</option>{lifecycleStatuses.map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}</select>
        <select className="select-field" value={priority} onChange={(event) => setPriority(event.target.value)} aria-label="Priority"><option value="all">All priorities</option><option value="urgent">Critical</option><option value="high">High</option><option value="normal">Medium</option><option value="low">Low</option></select>
        <select className="select-field" value={sort} onChange={(event) => setSort(event.target.value as Sort)} aria-label="Sort compliance work"><option value="priority">Sort by priority</option><option value="due">Sort by deadline</option><option value="updated">Sort by last update</option><option value="status">Sort by status</option></select>
        <button className="button-small" onClick={() => setDirection((value) => value === "asc" ? "desc" : "asc")} aria-label={`Sort ${direction === "asc" ? "descending" : "ascending"}`}>{direction === "asc" ? "Ascending" : "Descending"}</button>
      </div>
      <div className="data-table-wrap"><table className="data-table"><thead><tr><th>Priority</th><th>Obligation</th><th>Scope</th><th>Requirement</th><th>Status</th><th>Owner</th><th>Due</th></tr></thead><tbody>{items.map((item) => { const itemProduct = demo.selectors.product(item.productId); const itemRelease = demo.selectors.release(item.releaseId); return <tr key={item.id} className={selectedId === item.id ? "selected-row" : undefined}><td><StatusPill value={item.priority} /></td><td><div className="cell-primary"><Link to={itemUrl(params, item.id)}>{item.title}</Link><small>{item.reason}</small></div></td><td><ScopeCell item={item} productName={itemProduct?.name} releaseVersion={itemRelease?.version} /></td><td>{item.requirement}</td><td><StatusPill value={lifecycleStatus(item)} /></td><td>{memberName(demo.state.members, item.ownerId)}</td><td className={item.priority === "urgent" && !isComplianceResolved(item) ? "danger-text" : ""}>{relativeDate(item.dueAt)}</td></tr>; })}</tbody></table></div>
      <div className="mobile-card-list">{items.map((item) => <article className="mobile-card" key={item.id}><div className="inline-actions"><StatusPill value={item.priority} /><StatusPill value={lifecycleStatus(item)} /></div><div className="cell-primary"><Link to={itemUrl(params, item.id)}>{item.title}</Link><small>{demo.selectors.product(item.productId)?.name ?? "Organization-wide"} · {item.requirement}</small></div></article>)}</div>
      {!items.length ? <EmptyState title="No matching compliance work" body="Change the scope or filters to include other obligations." /> : null}
    </section>
    <p className="muted">Showing {items.length} compliance items. Organization-wide obligations remain visible in the cross-product view.</p>
    {selectedId ? <ComplianceDetail key={selectedId} itemId={selectedId} onClose={() => updateParams({ item: undefined, case: undefined })} /> : null}
  </main>;
}

function ScopeCell({ item, productName, releaseVersion }: { item: ComplianceItem; productName?: string; releaseVersion?: string }) {
  if (!item.productId) return <div className="cell-primary"><strong>Organization-wide</strong><small>All products</small></div>;
  return <div className="cell-primary"><Link to={`/products/${item.productId}`}>{productName ?? "Unknown product"}</Link><small>{releaseVersion ?? "Product scope"}</small></div>;
}

function ComplianceDetail({ itemId, onClose }: { itemId: string; onClose: () => void }) {
  const demo = useDemo();
  const detailRef = useRef<HTMLElement>(null);
  const [item, setItem] = useState<ComplianceItem>();
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [success, setSuccess] = useState<string>();
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    detailRef.current?.scrollIntoView({ behavior: globalThis.matchMedia?.("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setError(undefined); setSuccess(undefined);
    demo.actions.loadComplianceDetail(itemId, { signal: controller.signal }).then((loaded) => {
      if (!controller.signal.aborted) { setItem(loaded); setError(loaded ? undefined : "This compliance item no longer exists."); setLoading(false); }
    }).catch((reason) => {
      if (!controller.signal.aborted) { setError(reason instanceof Error ? reason.message : "Unable to load compliance details."); setLoading(false); }
    });
    return () => controller.abort();
  }, [demo.actions, itemId, reloadKey]);

  if (loading) return <section ref={detailRef} className="panel compliance-detail" aria-busy="true"><SectionHeader title="Loading compliance case" description="Retrieving lifecycle and audit history." /><div className="panel-pad muted" role="status">Loading case details…</div></section>;
  if (!item) return <section ref={detailRef} className="panel compliance-detail"><SectionHeader title="Compliance case unavailable" action={<button onClick={onClose}>Close</button>} /><div className="panel-pad"><p className="danger-text" role="alert">{error}</p><button onClick={() => setReloadKey((value) => value + 1)}>Retry</button></div></section>;

  const permissions = compliancePermissions(demo.currentUser.roles, item);
  const product = demo.selectors.product(item.productId);
  const release = demo.selectors.release(item.releaseId);
  const relatedUrl = item.targetUrl.includes(`item=${encodeURIComponent(item.id)}`) ? undefined : item.targetUrl;

  const update = async (input: ComplianceUpdateCommand) => {
    setBusy(true); setError(undefined); setSuccess(undefined);
    try { const updated = await demo.actions.updateCompliance(input); setItem(updated); setSuccess("Compliance case updated and recorded in the audit history."); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to update the compliance case."); }
    finally { setBusy(false); }
  };
  const approve = async () => {
    setBusy(true); setError(undefined); setSuccess(undefined);
    try { const updated = await demo.actions.approveCompliance({ itemId: item.id, selfFilingRecordId: item.selfFilingRecordId, selfFilingRecordUrl: item.selfFilingRecordUrl }); setItem(updated); setSuccess("Approval recorded with the current case version."); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to approve the compliance case."); }
    finally { setBusy(false); }
  };

  return <section ref={detailRef} className="compliance-detail-grid" aria-label="Compliance case detail">
    <article className="panel compliance-detail">
      <SectionHeader title={item.title} description={`${item.type === "reporting_case" ? "Reporting case" : titleCase(item.type)} · ${item.requirement}`} action={<div className="inline-actions">{relatedUrl ? <Link className="button" to={relatedUrl}>Open related record</Link> : null}<button onClick={onClose}>Close</button></div>} />
      <div className="detail-badges panel-pad compliance-detail-badges"><StatusPill value={item.priority} /><StatusPill value={lifecycleStatus(item)} />{item.readiness ? <StatusPill value={item.readiness} /> : null}{item.reportingStage ? <StatusPill value={item.reportingStage} /> : null}</div>
      <dl className="definition-grid">
        <div><dt>Scope</dt><dd>{product ? `${product.name}${release ? ` ${release.version}` : ""}` : "Organization-wide"}</dd></div>
        <div><dt>Owner</dt><dd>{memberName(demo.state.members, item.ownerId)}</dd></div>
        <div><dt>Deadline</dt><dd>{item.dueAt ? `${formatDate(item.dueAt, true)} · ${relativeDate(item.dueAt)}` : "No deadline"}</dd></div>
        <div><dt>Source</dt><dd>{titleCase(item.requirement)}{item.sourceId ? ` · ${item.sourceId}` : ""}</dd></div>
        <div><dt>Version</dt><dd className="mono">{item.version ?? "Fixture"}</dd></div>
        <div><dt>Last updated</dt><dd>{formatDate(item.updatedAt, true)}</dd></div>
      </dl>
      <div className="panel-pad compliance-description"><h3>Assessment</h3><p>{item.reason}</p></div>
      {error ? <div className="notice compliance-error" role="alert">{error} {error.toLowerCase().includes("stale") || error.toLowerCase().includes("conflict") ? <button className="button-small" onClick={() => setReloadKey((value) => value + 1)}>Reload latest</button> : null}</div> : null}
      {success ? <div className="notice compliance-success" role="status">{success}</div> : null}
      <ComplianceForm key={`${item.id}-${item.version ?? lifecycleStatus(item)}`} item={item} members={demo.state.members} disabled={busy || !permissions.canEdit} onSubmit={update} />
      {lifecycleStatus(item) === "pending_approval" ? <div className="compliance-approval-bar"><div><strong>Independent approval required</strong><p>{permissions.canApprove ? "Approval uses the current version and becomes part of the audit trail." : "Only an organization admin or authorized approver can complete this action."}</p></div><button className="button-primary" disabled={busy || !permissions.canApprove} onClick={() => void approve()}>{busy ? "Saving…" : "Approve case"}</button></div> : null}
    </article>
    <aside className="panel compliance-audit">
      <SectionHeader title="Audit history" description="Immutable lifecycle events and version changes." />
      {item.audit?.length ? <ol className="timeline">{[...item.audit].reverse().map((entry) => <li key={entry.id}><strong>{titleCase(entry.action.replace(/^compliance\./, ""))}</strong><span>{memberName(demo.state.members, entry.actorId)} · {formatDate(entry.occurredAt, true)} · v{entry.itemVersion}</span><p>{auditSummary(entry.payload)}</p></li>)}</ol> : <EmptyState title="No audit events loaded" body="Audit events appear after the case is created or changed." />}
    </aside>
  </section>;
}

function ComplianceForm({ item, members, disabled, onSubmit }: { item: ComplianceItem; members: ReturnType<typeof useDemo>["state"]["members"]; disabled: boolean; onSubmit: (input: ComplianceUpdateCommand) => Promise<void> }) {
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const due = String(data.get("dueAt") ?? "");
    const owner = String(data.get("ownerId") ?? "");
    const nextStatus = data.get("status") as ComplianceLifecycleStatus;
    void onSubmit({
      itemId: item.id,
      title: String(data.get("title") ?? "").trim(),
      description: String(data.get("description") ?? "").trim(),
      priority: data.get("priority") as ComplianceUpdateCommand["priority"],
      status: nextStatus === lifecycleStatus(item) ? undefined : nextStatus,
      dueAt: due ? new Date(`${due}T00:00:00Z`).toISOString() : undefined,
      clearDueAt: !due && Boolean(item.dueAt),
      ownerId: owner || undefined,
      clearOwner: !owner && Boolean(item.ownerId),
      selfFilingRecordId: String(data.get("filingId") ?? "").trim() || undefined,
      selfFilingRecordUrl: String(data.get("filingUrl") ?? "").trim() || undefined,
    });
  };
  return <form className="form-grid compliance-form" onSubmit={submit}>
    <div className="field span-2"><label htmlFor={`compliance-title-${item.id}`}>Title</label><input id={`compliance-title-${item.id}`} className="input-field" name="title" required maxLength={240} defaultValue={item.title} disabled={disabled} /></div>
    <div className="field span-2"><label htmlFor={`compliance-description-${item.id}`}>Description</label><textarea id={`compliance-description-${item.id}`} className="textarea-field" name="description" maxLength={3000} defaultValue={item.reason} disabled={disabled} /></div>
    <div className="field"><label htmlFor={`compliance-priority-${item.id}`}>Priority</label><select id={`compliance-priority-${item.id}`} className="select-field" name="priority" defaultValue={compliancePriority(item)} disabled={disabled}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
    <div className="field"><label htmlFor={`compliance-status-${item.id}`}>Next lifecycle state</label><select id={`compliance-status-${item.id}`} className="select-field" name="status" defaultValue={lifecycleStatus(item)} disabled={disabled}>{allowedComplianceStatuses(item).map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}</select></div>
    <div className="field"><label htmlFor={`compliance-owner-${item.id}`}>Owner</label><select id={`compliance-owner-${item.id}`} className="select-field" name="ownerId" defaultValue={item.ownerId ?? ""} disabled={disabled}><option value="">Unassigned</option>{members.filter((member) => member.status === "active").map((member) => <option key={member.id} value={member.id}>{member.name}</option>)}</select></div>
    <div className="field"><label htmlFor={`compliance-due-${item.id}`}>Deadline</label><input id={`compliance-due-${item.id}`} className="input-field" name="dueAt" type="date" defaultValue={item.dueAt?.slice(0, 10) ?? ""} disabled={disabled} /></div>
    {item.type === "reporting_case" ? <><div className="field"><label htmlFor={`compliance-filing-${item.id}`}>Filing record ID</label><input id={`compliance-filing-${item.id}`} className="input-field" name="filingId" defaultValue={item.selfFilingRecordId ?? ""} disabled={disabled} /></div><div className="field"><label htmlFor={`compliance-filing-url-${item.id}`}>Filing evidence URL</label><input id={`compliance-filing-url-${item.id}`} className="input-field" name="filingUrl" type="url" defaultValue={item.selfFilingRecordUrl ?? ""} disabled={disabled} /></div></> : null}
    <div className="span-2 inline-actions"><button className="button-primary" type="submit" disabled={disabled}>{disabled ? "Read only" : "Save case"}</button>{disabled ? <span className="field-hint">Your current role can review this case but cannot change it.</span> : null}</div>
  </form>;
}

function itemUrl(params: URLSearchParams, id: string) {
  const next = new URLSearchParams(params);
  next.set("item", id); next.delete("case");
  return `/compliance?${next.toString()}`;
}

function auditSummary(payload: Record<string, unknown>) {
  const entries = Object.entries(payload).filter(([, value]) => value !== undefined);
  if (!entries.length) return "Lifecycle event recorded.";
  return entries.slice(0, 3).map(([key, value]) => `${titleCase(key)}: ${value === null ? "cleared" : typeof value === "object" ? "updated" : String(value)}`).join(" · ");
}

function viewMatch(type: string, view: View) {
  if (view === "all") return true;
  if (view === "deadlines") return type === "deadline";
  if (view === "evidence") return type === "missing_evidence";
  if (view === "cases") return type === "reporting_case";
  if (view === "approvals") return type === "approval";
  return type === "readiness";
}
