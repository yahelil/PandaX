import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { CheckCircle2, Download, FileCheck, FileCode, Scale, ShieldCheck, Upload, X } from "lucide-react";

import { usePermission } from "../auth";
import { useDemo } from "../data/DemoProvider";
import { createReleasePdf, type ReleasePdfKind } from "../data/releasePdf";
import type { ComplianceItem, ComplianceLifecycleStatus, ComplianceUpdateCommand, Product, Release } from "../data/types";
import {
  allowedComplianceStatuses,
  compareCompliance,
  compliancePermissions,
  compliancePriority,
  isComplianceResolved,
  lifecycleStatus,
} from "./complianceWorkflow";
import { downloadFile } from "./downloadFile";
import { EmptyState, MetricCard, PageHeader, SectionHeader, StatusPill, formatDate, memberName, relativeDate, titleCase } from "./PageKit";
import "./pages.css";

type View = "all" | "deadlines" | "evidence" | "cases" | "approvals" | "monitoring" | "documents";
type Sort = "priority" | "due" | "updated" | "status";
const views: [View, string][] = [
  ["all", "All work"],
  ["deadlines", "Deadlines"],
  ["evidence", "Missing evidence"],
  ["cases", "Reporting cases"],
  ["approvals", "Approvals"],
  ["monitoring", "Monitoring"],
  ["documents", "Documents"],
];
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
  const [actionModalItem, setActionModalItem] = useState<ComplianceItem | null>(null);

  const toggleSort = (key: Sort) => {
    if (sort === key) {
      setDirection((val) => val === "asc" ? "desc" : "asc");
    } else {
      setSort(key);
      setDirection("asc");
    }
  };

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
    {view === "documents" ? (
      <section className="metrics-grid">
        <MetricCard label="Available documents" value={demo.documents.filter((d) => (product === "all" || d.productId === product) && (release === "all" || d.releaseId === release)).length} detail="Regulatory and traceable files" />
        <MetricCard label="PDF records" value={demo.documents.filter((d) => (product === "all" || d.productId === product) && (release === "all" || d.releaseId === release) && d.format.toLowerCase().includes("pdf")).length} detail="Conformity, Annex VII, and reports" />
        <MetricCard label="Awaiting sign-off" value={demo.documents.filter((d) => (product === "all" || d.productId === product) && (release === "all" || d.releaseId === release) && d.status === "approval_required").length} detail="Authorized approver action" tone={demo.documents.some((d) => (product === "all" || d.productId === product) && (release === "all" || d.releaseId === release) && d.status === "approval_required") ? "high" : "good"} />
      </section>
    ) : (
      <section className="metrics-grid">
        <MetricCard label="Urgent obligations" value={urgent} detail="Immediate review required" tone="urgent" />
        <MetricCard label="Evidence gaps" value={missing} detail="Blocking readiness" tone="high" />
        <MetricCard label="Awaiting approval" value={approvals} detail="Authorized approver action" />
      </section>
    )}
    <section className="panel">
      <nav className="tabs" aria-label="Compliance views">{views.map(([id, label]) => <button key={id} className={view === id ? "active" : ""} onClick={() => updateParams({ view: id })} aria-current={view === id ? "page" : undefined}>{label}</button>)}</nav>
      <div className="toolbar compliance-toolbar">
        <input className="search-field" value={query} onChange={(event) => setQuery(event.target.value)} aria-label="Search compliance work" placeholder={view === "documents" ? "Search documents, types, formats, or products" : "Search obligations, requirements, or products"} />
        <select className="select-field" value={product} onChange={(event) => updateParams({ product: event.target.value, release: undefined, item: undefined, case: undefined })} aria-label="Product"><option value="all">All products</option>{demo.products.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select>
        <select className="select-field" value={release} onChange={(event) => updateParams({ release: event.target.value, item: undefined, case: undefined })} aria-label="Release"><option value="all">All releases</option>{demo.releases.filter((item) => product === "all" || item.productId === product).map((item) => <option key={item.id} value={item.id}>{demo.selectors.product(item.productId)?.name} {item.version}</option>)}</select>
        {view !== "documents" ? (
          <>
            <select className="select-field" value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Lifecycle status"><option value="all">All statuses</option>{lifecycleStatuses.map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}</select>
            <select className="select-field" value={priority} onChange={(event) => setPriority(event.target.value)} aria-label="Priority"><option value="all">All priorities</option><option value="urgent">Critical</option><option value="high">High</option><option value="normal">Medium</option><option value="low">Low</option></select>
          </>
        ) : null}
      </div>
      {view === "documents" ? (
        <ComplianceDocumentsTable product={product} release={release} query={query} />
      ) : (
        <>
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ cursor: "pointer", userSelect: "none" }} onClick={() => toggleSort("priority")} title="Click to sort by priority">Priority {sort === "priority" ? (direction === "asc" ? "↑" : "↓") : ""}</th>
                  <th>Obligation</th>
                  <th>Scope</th>
                  <th>Requirement</th>
                  <th style={{ cursor: "pointer", userSelect: "none" }} onClick={() => toggleSort("status")} title="Click to sort by status">Status {sort === "status" ? (direction === "asc" ? "↑" : "↓") : ""}</th>
                  <th>Owner</th>
                  <th style={{ cursor: "pointer", userSelect: "none" }} onClick={() => toggleSort("due")} title="Click to sort by deadline">Due {sort === "due" ? (direction === "asc" ? "↑" : "↓") : ""}</th>
                </tr>
              </thead>
              <tbody>{items.map((item) => { const itemProduct = demo.selectors.product(item.productId); const itemRelease = demo.selectors.release(item.releaseId); return <tr key={item.id} className={selectedId === item.id ? "selected-row" : undefined}><td><StatusPill value={item.priority} /></td><td><div className="cell-primary"><Link to={itemUrl(params, item.id)}>{item.title}</Link><small>{item.reason}</small></div></td><td><ScopeCell item={item} productName={itemProduct?.name} releaseVersion={itemRelease?.version} /></td><td>{item.requirement}</td><td><button type="button" className="status-pill-button" onClick={() => setActionModalItem(item)} title="Click to open window to upload/write what's needed" aria-label={`Open action window for ${item.title}: ${titleCase(lifecycleStatus(item))}`}><StatusPill value={lifecycleStatus(item)} /></button></td><td>{memberName(demo.state.members, item.ownerId)}</td><td className={item.priority === "urgent" && !isComplianceResolved(item) ? "danger-text" : ""}>{relativeDate(item.dueAt)}</td></tr>; })}</tbody>
            </table>
          </div>
          <div className="mobile-card-list">{items.map((item) => <article className="mobile-card" key={item.id}><div className="inline-actions"><StatusPill value={item.priority} /><button type="button" className="status-pill-button" onClick={() => setActionModalItem(item)} title="Click to open window to upload/write what's needed" aria-label={`Open action window for ${item.title}`}><StatusPill value={lifecycleStatus(item)} /></button></div><div className="cell-primary"><Link to={itemUrl(params, item.id)}>{item.title}</Link><small>{demo.selectors.product(item.productId)?.name ?? "Organization-wide"} · {item.requirement}</small></div></article>)}</div>
          {!items.length ? <EmptyState title="No matching compliance work" body="Change the scope or filters to include other obligations." /> : null}
        </>
      )}
    </section>
    {view === "documents" ? (
      <p className="muted">Showing regulatory documents and downloadable PDFs. Filter by product and release above.</p>
    ) : (
      <p className="muted">Showing {items.length} compliance items. Organization-wide obligations remain visible in the cross-product view.</p>
    )}
    {actionModalItem ? <ComplianceActionModal item={actionModalItem} onClose={() => setActionModalItem(null)} /> : null}
    {selectedId ? <ComplianceDetail key={selectedId} itemId={selectedId} onClose={() => updateParams({ item: undefined, case: undefined })} /> : null}
  </main>;
}

function ComplianceActionModal({ item, onClose }: { item: ComplianceItem; onClose: () => void }) {
  const demo = useDemo();
  const permissions = compliancePermissions(demo.currentUser.roles, item);
  const product = demo.selectors.product(item.productId);
  const release = demo.selectors.release(item.releaseId);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [notes, setNotes] = useState(item.reason ?? "");
  const [nextStatus, setNextStatus] = useState<ComplianceLifecycleStatus>(lifecycleStatus(item));
  const [ownerId, setOwnerId] = useState(item.ownerId ?? "");
  const [dueAt, setDueAt] = useState(item.dueAt?.slice(0, 10) ?? "");
  const [filingId, setFilingId] = useState(item.selfFilingRecordId ?? "");
  const [filingUrl, setFilingUrl] = useState(item.selfFilingRecordUrl ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [success, setSuccess] = useState<string>();
  const modalRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  useEffect(() => {
    modalRef.current?.focus();
  }, []);

  const handleSave = async (e?: FormEvent) => {
    if (e) e.preventDefault();
    if (!permissions.canEdit) return;
    setBusy(true);
    setError(undefined);
    setSuccess(undefined);
    try {
      let finalDescription = notes.trim();
      if (selectedFile) {
        const fileInfo = `[Attached Evidence: ${selectedFile.name} (${Math.round(selectedFile.size / 1024)} KB, ${new Date().toISOString().slice(0, 10)})]`;
        finalDescription = finalDescription ? `${finalDescription}\n\n${fileInfo}` : fileInfo;
      }
      await demo.actions.updateCompliance({
        itemId: item.id,
        title: item.title,
        description: finalDescription,
        status: nextStatus !== lifecycleStatus(item) ? nextStatus : undefined,
        ownerId: ownerId || undefined,
        clearOwner: !ownerId && Boolean(item.ownerId),
        dueAt: dueAt ? new Date(`${dueAt}T00:00:00Z`).toISOString() : undefined,
        clearDueAt: !dueAt && Boolean(item.dueAt),
        selfFilingRecordId: filingId.trim() || undefined,
        selfFilingRecordUrl: filingUrl.trim() || undefined,
      });
      setSuccess("Obligation updated with your changes and evidence.");
      setTimeout(() => {
        onClose();
      }, 750);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to save compliance action.");
    } finally {
      setBusy(false);
    }
  };

  const handleApprove = async () => {
    if (!permissions.canApprove) return;
    setBusy(true);
    setError(undefined);
    setSuccess(undefined);
    try {
      await demo.actions.approveCompliance({
        itemId: item.id,
        selfFilingRecordId: filingId.trim() || item.selfFilingRecordId,
        selfFilingRecordUrl: filingUrl.trim() || item.selfFilingRecordUrl,
      });
      setSuccess("Approval recorded in the audit history.");
      setTimeout(() => {
        onClose();
      }, 750);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to approve compliance case.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="compliance-modal-overlay"
      role="presentation"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={modalRef}
        className="compliance-modal-window"
        role="dialog"
        aria-modal="true"
        aria-labelledby={`compliance-modal-title-${item.id}`}
        tabIndex={-1}
      >
        <header className="compliance-modal-header">
          <div>
            <div style={{ display: "flex", gap: "8px", alignItems: "center", marginBottom: "6px" }}>
              <StatusPill value={lifecycleStatus(item)} />
              <StatusPill value={item.priority} />
              <span className="muted" style={{ fontSize: "12px" }}>
                {product ? `${product.name}${release ? ` ${release.version}` : ""}` : "Organization-wide"} · {item.requirement}
              </span>
            </div>
            <h2 id={`compliance-modal-title-${item.id}`} style={{ margin: 0, fontSize: "19px", fontWeight: 700 }}>
              {item.title}
            </h2>
          </div>
          <button
            type="button"
            className="icon-button"
            onClick={onClose}
            aria-label="Close window"
          >
            <X size={20} />
          </button>
        </header>

        {error ? <div className="notice compliance-error" role="alert">{error}</div> : null}
        {success ? <div className="notice compliance-success" role="status">{success}</div> : null}

        <div className="action-modal-callout">
          <strong>Obligation context & requirement</strong>
          <p style={{ margin: "4px 0 0", fontSize: "13px", color: "var(--text-muted)", lineHeight: 1.45 }}>{item.reason}</p>
        </div>

        {lifecycleStatus(item) === "pending_approval" ? (
          <div className="compliance-approval-bar" style={{ borderRadius: "8px" }}>
            <div>
              <strong>Independent approval required</strong>
              <p>
                {permissions.canApprove
                  ? "Your authorized role can approve this compliance case and commit it to the audit log."
                  : "Only an organization admin or authorized approver can sign off on this step."}
              </p>
            </div>
            <button
              type="button"
              className="button button-primary"
              disabled={busy || !permissions.canApprove}
              onClick={handleApprove}
            >
              {busy ? "Saving…" : "Approve case"}
            </button>
          </div>
        ) : null}

        <form onSubmit={handleSave} className="form-grid" style={{ gap: "14px" }}>
          {/* Section 1: Upload what's needed */}
          <div className="span-2">
            <label className="field-label" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
              <strong>Upload evidence / documentation</strong>
              <span className="muted" style={{ fontSize: "11px" }}>PDF, JSON, SBOM, ZIP, report or certificate</span>
            </label>
            <div
              className="compliance-upload-dropzone"
              onClick={() => fileInputRef.current?.click()}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                const f = e.dataTransfer.files?.[0];
                if (f) setSelectedFile(f);
              }}
            >
              <input
                ref={fileInputRef}
                type="file"
                style={{ display: "none" }}
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) setSelectedFile(f);
                }}
              />
              {selectedFile ? (
                <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "10px" }}>
                  <CheckCircle2 size={22} className="success-text" />
                  <div style={{ textAlign: "left" }}>
                    <strong style={{ display: "block", fontSize: "13px" }}>{selectedFile.name}</strong>
                    <span className="muted" style={{ fontSize: "11px" }}>
                      {(selectedFile.size / 1024).toFixed(1)} KB · Ready to record as evidence
                    </span>
                  </div>
                  <button
                    type="button"
                    className="button-small"
                    style={{ marginLeft: "12px" }}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedFile(null);
                    }}
                  >
                    Remove
                  </button>
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "6px" }}>
                  <Upload size={24} className="muted" />
                  <span style={{ fontSize: "13.5px", fontWeight: 650 }}>Click to browse or drag file here to attach proof</span>
                  <span className="muted" style={{ fontSize: "12px" }}>Upload test results, SBOM scan, vendor security advisory, or verification certificate</span>
                </div>
              )}
            </div>
          </div>

          {/* Section 2: Write what's needed */}
          <div className="span-2 field">
            <label htmlFor={`modal-notes-${item.id}`}>
              <strong>Write justification, action taken, or explanation</strong>
            </label>
            <textarea
              id={`modal-notes-${item.id}`}
              className="textarea-field"
              rows={3}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              disabled={busy || !permissions.canEdit}
              placeholder="Explain how this obligation was addressed, test findings, or actions taken..."
            />
          </div>

          {/* Section 3: Status & Owner */}
          <div className="field">
            <label htmlFor={`modal-status-${item.id}`}>Next lifecycle state</label>
            <select
              id={`modal-status-${item.id}`}
              className="select-field"
              value={nextStatus}
              disabled={busy || !permissions.canEdit}
              onChange={(e) => setNextStatus(e.target.value as ComplianceLifecycleStatus)}
            >
              {allowedComplianceStatuses(item).map((val) => (
                <option key={val} value={val}>
                  {titleCase(val)}
                </option>
              ))}
            </select>
          </div>

          <div className="field">
            <label htmlFor={`modal-owner-${item.id}`}>Owner</label>
            <select
              id={`modal-owner-${item.id}`}
              className="select-field"
              value={ownerId}
              disabled={busy || !permissions.canEdit}
              onChange={(e) => setOwnerId(e.target.value)}
            >
              <option value="">Unassigned</option>
              {demo.state.members
                .filter((m) => m.status === "active")
                .map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.name}
                  </option>
                ))}
            </select>
          </div>

          {item.type === "reporting_case" ? (
            <>
              <div className="field">
                <label htmlFor={`modal-filing-${item.id}`}>Filing record ID</label>
                <input
                  id={`modal-filing-${item.id}`}
                  className="input-field"
                  value={filingId}
                  disabled={busy || !permissions.canEdit}
                  onChange={(e) => setFilingId(e.target.value)}
                />
              </div>
              <div className="field">
                <label htmlFor={`modal-filing-url-${item.id}`}>Filing evidence URL</label>
                <input
                  id={`modal-filing-url-${item.id}`}
                  className="input-field"
                  type="url"
                  value={filingUrl}
                  disabled={busy || !permissions.canEdit}
                  onChange={(e) => setFilingUrl(e.target.value)}
                />
              </div>
            </>
          ) : null}

          <div className="span-2 inline-actions" style={{ marginTop: "12px", justifyContent: "space-between" }}>
            <div style={{ display: "flex", gap: "8px" }}>
              <button
                type="submit"
                className="button-primary"
                disabled={busy || !permissions.canEdit}
              >
                {busy ? "Saving…" : "Save & record action"}
              </button>
              <button type="button" onClick={onClose} disabled={busy}>
                Cancel
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
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
  if (view === "monitoring") return type === "readiness";
  return false;
}

function ComplianceDocumentsTable({ product, release, query }: { product: string; release: string; query: string }) {
  const demo = useDemo();
  const canGenerateReport = usePermission("generate_findings_report");
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();

  const download = async (key: string, operation: () => Promise<{ blob: Blob; filename?: string; contentType: string }>, fallback: string) => {
    setBusy(key);
    setError(undefined);
    try {
      downloadFile(await operation(), fallback);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Document could not be downloaded.");
    } finally {
      setBusy(undefined);
    }
  };

  const targetRelease = release !== "all" ? demo.selectors.release(release) : undefined;
  const fallbackProduct = demo.products[0];
  const targetProduct = targetRelease
    ? demo.selectors.product(targetRelease.productId)
    : product !== "all"
    ? demo.selectors.product(product)
    : fallbackProduct;

  const activeRelease =
    !targetRelease && targetProduct?.activeReleaseId
      ? demo.selectors.release(targetProduct.activeReleaseId)
      : targetProduct
      ? demo.releases.find((r) => r.productId === targetProduct.id)
      : undefined;
  const effectiveRelease = targetRelease ?? activeRelease;

  const latestCompleted =
    targetProduct && effectiveRelease
      ? demo.state.analysisJobs
          .filter(
            (job) =>
              job.draft.productId === targetProduct.id &&
              job.draft.releaseId === effectiveRelease.id &&
              job.status === "completed",
          )
          .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))[0]
      : undefined;

  const pdfEvidence = latestCompleted?.result?.evidence?.filter((item) => item.name.toLowerCase().endsWith(".pdf")) ?? [];

  const demoDraft = (kind: ReleasePdfKind, p: Product, r: Release) => {
    const bytes = createReleasePdf(kind, p, r, demo.findings.filter((item) => item.releaseId === r.id));
    return Promise.resolve({
      blob: new Blob([bytes.buffer as ArrayBuffer], { type: "application/pdf" }),
      contentType: "application/pdf",
      filename: `actis-${r.id}-${kind}-draft.pdf`,
    });
  };

  const term = query.trim().toLowerCase();
  const docs = demo.documents
    .filter((doc) => product === "all" || doc.productId === product)
    .filter((doc) => release === "all" || doc.releaseId === release)
    .filter((doc) => {
      if (!term) return true;
      const pName = demo.selectors.product(doc.productId)?.name ?? "";
      const rVer = demo.selectors.release(doc.releaseId)?.version ?? "";
      return `${doc.name} ${doc.type} ${doc.format} ${pName} ${rVer}`.toLowerCase().includes(term);
    });

  const hasReleasePdfs = Boolean(targetProduct && effectiveRelease && latestCompleted);

  return (
    <div>
      {error ? <p className="panel-pad danger-text" role="alert">{error}</p> : null}
      {targetProduct && effectiveRelease && latestCompleted ? (
        <div style={{ padding: "16px 20px 24px" }}>
          <div className="pipeline-stage-intro" style={{ marginBottom: 16 }}>
            <div className="pipeline-stage-badge pipeline-stage-badge--highlight">
              <FileCheck size={24} />
            </div>
            <div>
              <div className="inline-actions" style={{ marginBottom: 4 }}>
                <h3 style={{ margin: 0 }}>Official Legal & Conformity Documents</h3>
                <span className="status-pill status-ready">Ready for Download</span>
              </div>
              <p className="muted" style={{ margin: 0 }}>
                The pipeline compiles your verified SBOM, advisory scan, triage decisions, and technical evidence into official EU CRA regulatory documents and signed records for {targetProduct.name} v{effectiveRelease.version}. Download them immediately below:
              </p>
            </div>
          </div>

          <div className="pipeline-docs-grid">
            <div className="pipeline-doc-card">
              <div className="pipeline-doc-card__header">
                <div className="pipeline-doc-icon"><Scale size={20} /></div>
                <div>
                  <strong>EU Declaration of Conformity</strong>
                  <span className="pipeline-doc-badge">Article 24 CRA · PDF</span>
                </div>
              </div>
              <p className="pipeline-doc-desc">
                Official declaration attesting fulfillment of essential cybersecurity requirements specified in Annex I. Ready for manufacturer signature.
              </p>
              <div className="pipeline-doc-footer">
                <button
                  type="button"
                  className="button button-primary button-small"
                  disabled={Boolean(busy)}
                  onClick={() =>
                    void download(
                      "declaration",
                      () => demoDraft("declaration", targetProduct, effectiveRelease),
                      `actis-${effectiveRelease.id}-declaration-of-conformity-draft.pdf`
                    )
                  }
                >
                  <Download size={14} />
                  {busy === "declaration" ? "Generating…" : "Download PDF"}
                </button>
                <span className="muted" style={{ fontSize: 11 }}>Draft PDF</span>
              </div>
            </div>

            <div className="pipeline-doc-card">
              <div className="pipeline-doc-card__header">
                <div className="pipeline-doc-icon"><FileCheck size={20} /></div>
                <div>
                  <strong>Annex VII Technical Documentation</strong>
                  <span className="pipeline-doc-badge">Annex VII CRA · PDF</span>
                </div>
              </div>
              <p className="pipeline-doc-desc">
                Comprehensive technical documentation dossier containing design specs, SBOM baseline, vulnerability handling, and testing evidence.
              </p>
              <div className="pipeline-doc-footer">
                <button
                  type="button"
                  className="button button-primary button-small"
                  disabled={Boolean(busy)}
                  onClick={() =>
                    void download(
                      "technical",
                      () => demoDraft("technical", targetProduct, effectiveRelease),
                      `actis-${effectiveRelease.id}-annex-vii-technical-draft.pdf`
                    )
                  }
                >
                  <Download size={14} />
                  {busy === "technical" ? "Generating…" : "Download PDF"}
                </button>
                <span className="muted" style={{ fontSize: 11 }}>Draft PDF</span>
              </div>
            </div>

            <div className="pipeline-doc-card">
              <div className="pipeline-doc-card__header">
                <div className="pipeline-doc-icon"><ShieldCheck size={20} /></div>
                <div>
                  <strong>Product Release Security Report</strong>
                  <span className="pipeline-doc-badge">Audit Record · PDF</span>
                </div>
              </div>
              <p className="pipeline-doc-desc">
                Complete audit log of all identified components, CVE vulnerability findings, reachability analysis, and human triage decisions.
              </p>
              <div className="pipeline-doc-footer">
                <button
                  type="button"
                  className="button button-primary button-small"
                  disabled={Boolean(busy) || !canGenerateReport}
                  onClick={() =>
                    void download(
                      "security",
                      () => demo.actions.generateSecurityPdf(targetProduct.id, effectiveRelease.id),
                      `actis-${effectiveRelease.id}-security-report.pdf`
                    )
                  }
                >
                  <Download size={14} />
                  {busy === "security" ? "Generating…" : "Download PDF"}
                </button>
                <span className="muted" style={{ fontSize: 11 }}>Generated PDF</span>
              </div>
            </div>

            <div className="pipeline-doc-card">
              <div className="pipeline-doc-card__header">
                <div className="pipeline-doc-icon"><FileCode size={20} /></div>
                <div>
                  <strong>Traceable Evidence Package</strong>
                  <span className="pipeline-doc-badge">Audit Package · ZIP</span>
                </div>
              </div>
              <p className="pipeline-doc-desc">
                Cryptographically hashed bundle containing raw SBOM, machine-readable VEX, analyzer logs, and SHA-256 signatures for auditor review.
              </p>
              <div className="pipeline-doc-footer">
                <button
                  type="button"
                  className="button button-small"
                  disabled={Boolean(busy)}
                  onClick={() =>
                    void download(
                      "evidence-zip",
                      () => demo.actions.downloadReleaseReport(targetProduct.id, effectiveRelease.id, latestCompleted.id),
                      `actis-${effectiveRelease.id}-evidence.zip`
                    )
                  }
                >
                  <Download size={14} />
                  {busy === "evidence-zip" ? "Preparing…" : "Download ZIP"}
                </button>
                <span className="muted" style={{ fontSize: 11 }}>Evidence Bundle</span>
              </div>
            </div>
          </div>
        </div>
      ) : null}
      <div className="data-table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>Document</th>
              <th>Scope</th>
              <th>Format</th>
              <th>Status / State</th>
              <th>Updated</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {hasReleasePdfs && targetProduct && effectiveRelease && latestCompleted ? (
              <>
                <tr>
                  <td>
                    <div className="cell-primary">
                      <strong>Product release security report</strong>
                      <small>All findings, review decisions, remediation, and coverage for {targetProduct.name} {effectiveRelease.version}.</small>
                    </div>
                  </td>
                  <td>
                    <div className="cell-primary">
                      <Link to={`/products/${targetProduct.id}`}>{targetProduct.name}</Link>
                      <small><Link to={`/products/${targetProduct.id}/releases/${effectiveRelease.id}`}>{effectiveRelease.version}</Link></small>
                    </div>
                  </td>
                  <td>PDF</td>
                  <td>Generated on download</td>
                  <td>{formatDate(latestCompleted.updatedAt)}</td>
                  <td>
                    {canGenerateReport ? (
                      <button
                        type="button"
                        disabled={Boolean(busy)}
                        onClick={() =>
                          void download(
                            "security",
                            () => demo.actions.generateSecurityPdf(targetProduct.id, effectiveRelease.id),
                            `actis-${effectiveRelease.id}-security-report.pdf`,
                          )
                        }
                      >
                        {busy === "security" ? "Generating…" : "Download PDF"}
                      </button>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
                {demo.adapterStatus.mode === "fixture" && !pdfEvidence.length
                  ? ([
                      ["technical", "Annex VII technical documentation draft", "Manufacturer input required"],
                      ["declaration", "EU Declaration of Conformity draft", "Not issued - manufacturer approval required"],
                    ] as const).map(([kind, name, state]) => (
                      <tr key={kind}>
                        <td>
                          <div className="cell-primary">
                            <strong>{name}</strong>
                            <small>Local demo draft for {targetProduct.name} {effectiveRelease.version}.</small>
                          </div>
                        </td>
                        <td>
                          <div className="cell-primary">
                            <Link to={`/products/${targetProduct.id}`}>{targetProduct.name}</Link>
                            <small><Link to={`/products/${targetProduct.id}/releases/${effectiveRelease.id}`}>{effectiveRelease.version}</Link></small>
                          </div>
                        </td>
                        <td>PDF</td>
                        <td>{state}</td>
                        <td>{formatDate(latestCompleted.updatedAt)}</td>
                        <td>
                          <button
                            type="button"
                            disabled={Boolean(busy)}
                            onClick={() =>
                              void download(
                                kind,
                                () => demoDraft(kind, targetProduct, effectiveRelease),
                                `actis-${effectiveRelease.id}-${kind}-draft.pdf`,
                              )
                            }
                          >
                            {busy === kind ? "Preparing…" : "Download draft PDF"}
                          </button>
                        </td>
                      </tr>
                    ))
                  : null}
                {pdfEvidence.map((item) => (
                  <tr key={`${latestCompleted.id}-${item.sha256}`}>
                    <td>
                      <div className="cell-primary">
                        <strong>{item.name.replaceAll("_", " ")}</strong>
                        <small>{demo.adapterStatus.mode === "fixture" ? "Local demo draft for release." : "Generated by analysis pipeline."}</small>
                      </div>
                    </td>
                    <td>
                      <div className="cell-primary">
                        <Link to={`/products/${targetProduct.id}`}>{targetProduct.name}</Link>
                        <small><Link to={`/products/${targetProduct.id}/releases/${effectiveRelease.id}`}>{effectiveRelease.version}</Link></small>
                      </div>
                    </td>
                    <td>{demo.adapterStatus.mode === "fixture" ? "PDF" : "PDF/A-2b"}</td>
                    <td>Draft evidence</td>
                    <td>{formatDate(latestCompleted.updatedAt)}</td>
                    <td>
                      <button
                        type="button"
                        disabled={Boolean(busy)}
                        onClick={() =>
                          void download(
                            item.sha256,
                            () => demo.actions.downloadReleaseEvidenceFile(targetProduct.id, effectiveRelease.id, latestCompleted.id, item.sha256),
                            item.name,
                          )
                        }
                      >
                        {busy === item.sha256 ? "Downloading…" : "Download PDF"}
                      </button>
                    </td>
                  </tr>
                ))}
              </>
            ) : null}
            {docs.map((doc) => {
              const docProduct = demo.selectors.product(doc.productId);
              const docRelease = demo.selectors.release(doc.releaseId);
              return (
                <tr key={doc.id}>
                  <td>
                    <div className="cell-primary">
                      <Link to={`/documents/${doc.id}`}>{doc.name}</Link>
                      <small>{doc.type.replaceAll("_", " ")}</small>
                    </div>
                  </td>
                  <td>
                    {docProduct ? (
                      <div className="cell-primary">
                        <Link to={`/products/${docProduct.id}`}>{docProduct.name}</Link>
                        <small>{docRelease ? <Link to={`/products/${docProduct.id}/releases/${docRelease.id}`}>{docRelease.version}</Link> : "Product level"}</small>
                      </div>
                    ) : (
                      "Organization"
                    )}
                  </td>
                  <td>{doc.format}</td>
                  <td>
                    <StatusPill value={doc.status} /> · {doc.completeness.replaceAll("_", " ")}
                  </td>
                  <td>{formatDate(doc.updatedAt)}</td>
                  <td>
                    <button
                      type="button"
                      disabled={Boolean(busy)}
                      onClick={() =>
                        void download(
                          doc.id,
                          () => demo.actions.downloadDocument(doc.id),
                          `actis-${doc.id}.${doc.format.toLowerCase().includes("pdf") ? "pdf" : "json"}`,
                        )
                      }
                    >
                      {busy === doc.id ? "Downloading…" : "Download"}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {!hasReleasePdfs && !docs.length ? (
        <EmptyState
          title="No matching regulatory documents"
          body="Change the product, release, or search filters to find documents and PDFs."
        />
      ) : null}
    </div>
  );
}
