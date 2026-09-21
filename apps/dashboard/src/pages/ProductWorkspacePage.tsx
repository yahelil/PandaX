import { type FormEvent, useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { usePermission } from "../auth";
import { useDemo } from "../data/DemoProvider";
import { createReleasePdf, type ReleasePdfKind } from "../data/releasePdf";
import { Breadcrumbs, EmptyState, EvidenceMeter, FindingInsights, MetricCard, SectionHeader, StatusPill, formatDate, memberName } from "./PageKit";
import { craClassLabel } from "./craAssessment";
import { downloadFile } from "./downloadFile";
import { ExactTimerBadge } from "../components/ExactTimerBadge";
import { ProductScopeModal } from "../components/ProductScopeModal";
import { getProductMostUrgentTimer, getFindingTimers } from "./exactTimers";
import "./pages.css";

const tabs = ["overview", "releases", "findings", "documents"] as const;

export function ProductWorkspacePage() {
  const { productId = "" } = useParams();
  const [searchParams] = useSearchParams();
  const tab = tabs.includes(searchParams.get("tab") as typeof tabs[number]) ? searchParams.get("tab") as typeof tabs[number] : "overview";
  const demo = useDemo();
  const canRunAnalysis = usePermission("run_analysis");
  const product = demo.selectors.product(productId);
  if (!product) return <EmptyState title="Product not found" body="The product may have been removed or is outside your organization." action={<Link className="button" to="/products">Back to products</Link>} />;
  const findings = demo.findings.filter((finding) => finding.productId === product.id);
  const activeRelease = demo.selectors.release(product.activeReleaseId);
  const mostUrgentTimer = getProductMostUrgentTimer(product, demo.findings, demo.complianceItems);

  return <main className="page">
    <Breadcrumbs items={[{ label: "Products", to: "/products" }, { label: product.name }]} />
    <section className="panel">
      <div className="workspace-hero">
        <div className="workspace-title"><span className="product-avatar" aria-hidden="true">{product.name.split(" ").map((word) => word[0]).join("")}</span><div><h1>{product.name}</h1><p>{product.identifier} · {product.manufacturer}</p></div></div>
        <div className="inline-actions"><ExactTimerBadge timer={mostUrgentTimer} compact /><StatusPill value={product.readiness} /><StatusPill value={product.monitoringHealth} />{activeRelease && canRunAnalysis ? <Link className="button button-primary" to={`/products/${product.id}/releases/${activeRelease.id}/analyze`}>Analyze release</Link> : activeRelease ? <span className="button button-primary button-disabled" aria-disabled="true" title="Compliance Operator or Organization Admin permission required">Analyze release</span> : null}</div>
      </div>
      <nav className="tabs" aria-label="Product workspace">
        {tabs.map((name) => <Link className={tab === name ? "active" : ""} key={name} to={`/products/${product.id}?tab=${name}`}>{name[0].toUpperCase() + name.slice(1)}{name === "findings" && findings.length ? ` (${findings.length})` : ""}</Link>)}
      </nav>
    </section>

    {tab === "overview" ? <ProductOverview productId={product.id} /> : null}
    {tab === "releases" ? <><ActiveReleaseControl productId={product.id} /><ReleasesTable productId={product.id} /></> : null}
    {tab === "findings" ? <ProductFindings productId={product.id} /> : null}
    {tab === "documents" ? <ProductDocuments productId={product.id} /> : null}
  </main>;
}

function ProductOverview({ productId }: { productId: string }) {
  const demo = useDemo(); const product = demo.selectors.product(productId)!; const release = demo.selectors.release(product.activeReleaseId);
  const findings = demo.findings.filter((item) => item.productId === productId && item.status !== "resolved");
  const actions = demo.actionItems.filter((item) => item.productId === productId && item.status === "open");
  const analyses = demo.state.analysisJobs.filter((item) => item.draft.productId === productId);
  const mostUrgentTimer = getProductMostUrgentTimer(product, demo.findings, demo.complianceItems);
  const [reviewOpen, setReviewOpen] = useState(false);
  return <div className="overview-grid">
    <section className="metrics-grid wide"><MetricCard label="Open actions" value={actions.length} detail={actions.filter((item) => item.priority === "urgent").length ? `${actions.filter((item) => item.priority === "urgent").length} urgent` : "No urgent actions"} tone={actions.some((item) => item.priority === "urgent") ? "urgent" : "good"} /><MetricCard label="Active findings" value={findings.length} detail={`${findings.filter((item) => item.kev).length} in KEV`} /><MetricCard label="Most urgent deadline" value={mostUrgentTimer ? mostUrgentTimer.countdownText : "No deadline"} detail={mostUrgentTimer ? `${mostUrgentTimer.sourceLabel ? `${mostUrgentTimer.sourceLabel} · ` : ""}${mostUrgentTimer.exactDateText}` : "All obligations met"} tone={mostUrgentTimer ? (mostUrgentTimer.urgency === "urgent" ? "urgent" : mostUrgentTimer.urgency === "high" ? "high" : "good") : "good"} /></section>
    <section className="panel"><SectionHeader title="Product scope" description="Manufacturer and CRA classification." action={<button type="button" className="button button-small" onClick={() => setReviewOpen(true)}>Review CRA classification</button>} /><dl className="definition-grid"><div><dt>Product identifier</dt><dd className="mono">{product.identifier}</dd></div><div><dt>CRA class</dt><dd><button type="button" className="status-pill-button" onClick={() => setReviewOpen(true)} title="Click to review CRA scope and classification">{craClassLabel(product.craClass)}</button></dd></div><div><dt>Support until</dt><dd>{formatDate(product.supportUntil)}</dd></div><div><dt>Default owner</dt><dd>{memberName(demo.state.members, product.ownerId)}</dd></div><div><dt>Classification</dt><dd><button type="button" className="status-pill-button" onClick={() => setReviewOpen(true)} title="Click to review CRA scope and classification"><StatusPill value={product.classificationStatus} /></button></dd></div><div><dt>Tags</dt><dd>{product.tags.join(", ")}</dd></div></dl>{product.classificationAssessment ? <div className="classification-record"><div><span className="eyebrow">Assessment record</span><strong>{product.classificationAssessment.categoryLabel ?? "Standard product route"}</strong><p>{product.classificationAssessment.rationale}</p></div><dl><div><dt>Ruleset</dt><dd className="mono">{product.classificationAssessment.rulesetVersion}</dd></div><div><dt>Answers retained</dt><dd>{product.classificationAssessment.answers.length}</dd></div><div><dt>Completed</dt><dd>{formatDate(product.classificationAssessment.completedAt, true)}</dd></div></dl></div> : null}</section>
    <section className="panel"><SectionHeader title="Active release" description="Current supported production release." action={release ? <Link className="text-link" to={`/products/${product.id}/releases/${release.id}`}>Open release</Link> : null} />{release ? <dl className="definition-grid"><div><dt>Version</dt><dd>{release.version}</dd></div><div><dt>SBOM</dt><dd><StatusPill value={release.sbomStatus} /></dd></div><div><dt>Released</dt><dd>{formatDate(release.releaseDate)}</dd></div><div><dt>Coverage</dt><dd><EvidenceMeter value={release.coverage.identifiedComponents} total={release.coverage.components} /></dd></div><div><dt>Last analysis</dt><dd>{formatDate(release.lastAnalysisAt, true)}</dd></div><div><dt>Monitoring</dt><dd><StatusPill value={release.monitoringHealth} /></dd></div></dl> : <EmptyState title="No active release" body="Register a release to begin analysis and monitoring." />}</section>
    <FindingInsights findings={findings} analyses={analyses}/>
    <section className="panel wide"><SectionHeader title="Priority drivers" description="Why this product has its current readiness status." /><ul className="priority-list">{actions.slice(0,5).map((item) => <li className="priority-item" key={item.id}><span className={`priority-marker ${item.priority}`} /><div className="item-main"><Link to={item.targetUrl}>{item.title}</Link><p>{item.reason}</p></div><StatusPill value={item.priority} /></li>)}</ul>{!actions.length ? <EmptyState title="No open actions" body="This product has no outstanding compliance work." /> : null}</section>
    {reviewOpen ? <ProductScopeModal product={product} onClose={() => setReviewOpen(false)} /> : null}
  </div>;
}

function ActiveReleaseControl({ productId }: { productId: string }) {
  const demo = useDemo();
  const canManagePortfolio = usePermission("manage_portfolio");
  const product = demo.selectors.product(productId)!;
  const eligible = demo.releases.filter((release) => release.productId === productId && (release.status === "active" || release.status === "supported"));
  const [selection, setSelection] = useState(product.activeReleaseId ?? "");
  useEffect(() => setSelection(product.activeReleaseId ?? ""), [product.activeReleaseId, productId]);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string>();
  const select = async () => {
    setPending(true); setError(undefined);
    try { await demo.actions.selectActiveRelease(productId, selection); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not select the active release."); }
    finally { setPending(false); }
  };
  return <section className="panel panel-pad active-release-control">
    <div><h2>Active release</h2><p>Select the completed version shown as this product’s current release. Analyzing another version will not change this choice.</p></div>
    {eligible.length ? <div className="inline-actions"><select className="select-field" aria-label="Active release" value={selection} disabled={!canManagePortfolio || pending} onChange={(event) => setSelection(event.target.value)}><option value="" disabled>Choose a release</option>{eligible.map((release) => <option value={release.id} key={release.id}>{release.version} · {release.channel}</option>)}</select>{canManagePortfolio ? <button className="button-primary" disabled={pending || !selection || selection === product.activeReleaseId} onClick={() => void select()}>{pending ? "Saving…" : "Set active release"}</button> : null}</div> : <p className="muted">Complete an analysis before selecting an active release.</p>}
    {error ? <p className="danger-text" role="alert">{error}</p> : null}
  </section>;
}

function ReleasesTable({ productId }: { productId: string }) {
  const canManagePortfolio = usePermission("manage_portfolio");
  const demo = useDemo(); const navigate = useNavigate(); const releases = demo.releases.filter((item) => item.productId === productId); const [adding,setAdding]=useState(false); const [pending,setPending]=useState(false); const [error,setError]=useState<string>(); const product=demo.selectors.product(productId)!;
  const submit=async(event:FormEvent<HTMLFormElement>)=>{event.preventDefault();setPending(true);setError(undefined);const form=new FormData(event.currentTarget);try{const created=await demo.actions.createRelease({productId,version:String(form.get("version")),channel:String(form.get("channel")) as "stable",releaseDate:String(form.get("releaseDate")),supportedUntil:String(form.get("supportedUntil"))});navigate(`/products/${productId}/releases/${created.id}/analyze`)}catch(reason){setError(reason instanceof Error?reason.message:"Release could not be registered.")}finally{setPending(false)}};
  return <div className="page"><section className="panel"><SectionHeader title="Releases" description="Supported software baselines and their analysis coverage." action={<button className="button-primary" disabled={!canManagePortfolio} title={!canManagePortfolio ? "Org Admin or Compliance Operator permission required" : undefined} onClick={()=>setAdding((x)=>!x)}>Register release</button>} />{adding?<form className="form-grid panel-pad" onSubmit={submit}><div className="field"><label>Version</label><input className="input-field" name="version" required placeholder="2.5.0"/></div><div className="field"><label>Channel</label><select className="select-field" name="channel"><option value="stable">Stable</option><option value="lts">LTS</option><option value="beta">Beta</option></select></div><div className="field"><label>Release date</label><input className="input-field" name="releaseDate" type="date" required defaultValue={new Date().toISOString().slice(0,10)}/></div><div className="field"><label>Supported until</label><input className="input-field" name="supportedUntil" type="date" required defaultValue={product.supportUntil.slice(0,10)}/></div>{error?<p className="danger-text span-2" role="alert">{error}</p>:null}<div className="span-2 inline-actions"><button className="button-primary" disabled={pending}>{pending?"Registering release…":"Register and add evidence"}</button><button type="button" onClick={()=>setAdding(false)} disabled={pending}>Cancel</button></div></form>:null}<div className="data-table-wrap"><table className="data-table"><thead><tr><th>Version</th><th>Channel</th><th>Status</th><th>Readiness</th><th>SBOM</th><th>Components</th><th>Last analysis</th><th /></tr></thead><tbody>{releases.map((release) => <tr key={release.id}><td><Link to={`/products/${productId}/releases/${release.id}`}>{release.version}</Link></td><td>{release.channel.toUpperCase()}</td><td><StatusPill value={release.status} /></td><td><StatusPill value={release.readiness} /></td><td><StatusPill value={release.sbomStatus} /></td><td><EvidenceMeter value={release.coverage.identifiedComponents} total={release.coverage.components} /></td><td>{formatDate(release.lastAnalysisAt)}</td><td><Link className="text-link" to={`/products/${productId}/releases/${release.id}/analyze`}>Analyze</Link></td></tr>)}</tbody></table></div></section></div>;
}

function ProductFindings({ productId }: { productId: string }) {
  const demo = useDemo();
  const findings = demo.findings.filter((item) => item.productId === productId);
  return (
    <section className="panel">
      <SectionHeader
        title="Findings"
        description="Evidence-backed vulnerability decisions for this product."
        action={<Link className="text-link" to={`/findings?product=${productId}`}>Open full workspace</Link>}
      />
      <div className="data-table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>Finding</th>
              <th>Component</th>
              <th>Severity</th>
              <th>Evidence</th>
              <th>Status</th>
              <th>Deadline</th>
              <th>Owner</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => {
              const timers = getFindingTimers(finding);
              return (
                <tr key={finding.id}>
                  <td>
                    <div className="cell-primary">
                      <Link to={`/findings/${finding.id}`}>{finding.reference}</Link>
                      <small>{finding.title}</small>
                    </div>
                  </td>
                  <td>{finding.component} {finding.componentVersion}</td>
                  <td><StatusPill value={finding.severity} /></td>
                  <td>{finding.kev ? "KEV · " : ""}{finding.reachability.replaceAll("_", " ")}</td>
                  <td>
                    <Link
                      to={`/findings/${finding.id}${finding.status === "needs_review" ? "#risk-decision" : finding.status === "action_required" ? "#remediation" : ""}`}
                      className="status-pill-link"
                      title="Click to review or plan fix"
                    >
                      <StatusPill value={finding.status} label={finding.status === "action_required" ? "Fix required" : undefined} />
                    </Link>
                  </td>
                  <td>
                    {timers.earlyWarning ? (
                      <ExactTimerBadge timer={timers.earlyWarning} compact />
                    ) : (
                      <ExactTimerBadge timer={timers.remediation} compact />
                    )}
                  </td>
                  <td>{memberName(demo.state.members, finding.assigneeId)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ProductDocuments({ productId }: { productId: string }) {
  const demo = useDemo();
  const canGenerateReport = usePermission("generate_findings_report");
  const product = demo.selectors.product(productId);
  const activeRelease = product?.activeReleaseId ? demo.selectors.release(product.activeReleaseId) : undefined;
  const latestCompleted = activeRelease
    ? demo.state.analysisJobs
        .filter((job) => job.draft.productId === productId && job.draft.releaseId === activeRelease.id && job.status === "completed")
        .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))[0]
    : undefined;
  const docs = demo.documents.filter((doc) => doc.productId === productId);
  const pdfEvidence = latestCompleted?.result?.evidence?.filter((item) => item.name.toLowerCase().endsWith(".pdf")) ?? [];
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

  const demoDraft = (kind: ReleasePdfKind) => {
    if (!product || !activeRelease) return Promise.reject(new Error("Active release required"));
    const bytes = createReleasePdf(kind, product, activeRelease, demo.findings.filter((item) => item.releaseId === activeRelease.id));
    return Promise.resolve({
      blob: new Blob([bytes.buffer as ArrayBuffer], { type: "application/pdf" }),
      contentType: "application/pdf",
      filename: `actis-${activeRelease.id}-${kind}-draft.pdf`,
    });
  };

  const hasActiveReleasePdfs = Boolean(activeRelease && latestCompleted);

  return (
    <section className="panel">
      <SectionHeader
        title="Documents and proof"
        description="Versioned regulatory outputs, downloadable PDFs, and verification evidence."
      />
      {error ? <p className="panel-pad danger-text" role="alert">{error}</p> : null}
      <div className="data-table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>Document</th>
              <th>Format</th>
              <th>Status / State</th>
              <th>Updated</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {hasActiveReleasePdfs && activeRelease && latestCompleted ? (
              <>
                <tr>
                  <td>
                    <strong>Product release security report ({activeRelease.version})</strong>
                    <br />
                    <small>All findings, review decisions, remediation, and coverage for active release {activeRelease.version}.</small>
                  </td>
                  <td>PDF</td>
                  <td>Generated on download</td>
                  <td>{formatDate(latestCompleted.updatedAt)}</td>
                  <td>
                    {canGenerateReport ? (
                      <button
                        type="button"
                        disabled={Boolean(busy)}
                        onClick={() => void download("security", () => demo.actions.generateSecurityPdf(productId, activeRelease.id), `actis-${activeRelease.id}-security-report.pdf`)}
                      >
                        {busy === "security" ? "Generating…" : "Download PDF"}
                      </button>
                    ) : "—"}
                  </td>
                </tr>
                {demo.adapterStatus.mode === "fixture" && !pdfEvidence.length
                  ? ([
                      ["technical", `Annex VII technical documentation draft (${activeRelease.version})`, "Manufacturer input required"],
                      ["declaration", `EU Declaration of Conformity draft (${activeRelease.version})`, "Not issued - manufacturer approval required"],
                    ] as const).map(([kind, name, state]) => (
                      <tr key={kind}>
                        <td>
                          <strong>{name}</strong>
                          <br />
                          <small>Local demo draft for active release {activeRelease.version}.</small>
                        </td>
                        <td>PDF</td>
                        <td>{state}</td>
                        <td>{formatDate(latestCompleted.updatedAt)}</td>
                        <td>
                          <button
                            type="button"
                            disabled={Boolean(busy)}
                            onClick={() => void download(kind, () => demoDraft(kind), `actis-${activeRelease.id}-${kind}-draft.pdf`)}
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
                      <strong>{item.name.replaceAll("_", " ")} ({activeRelease.version})</strong>
                      <br />
                      <small>{demo.adapterStatus.mode === "fixture" ? "Local demo draft for active release." : "Generated by analysis pipeline."}</small>
                    </td>
                    <td>{demo.adapterStatus.mode === "fixture" ? "PDF" : "PDF/A-2b"}</td>
                    <td>Draft evidence</td>
                    <td>{formatDate(latestCompleted.updatedAt)}</td>
                    <td>
                      <button
                        type="button"
                        disabled={Boolean(busy)}
                        onClick={() => void download(item.sha256, () => demo.actions.downloadReleaseEvidenceFile(productId, activeRelease.id, latestCompleted.id, item.sha256), item.name)}
                      >
                        {busy === item.sha256 ? "Downloading…" : "Download PDF"}
                      </button>
                    </td>
                  </tr>
                ))}
              </>
            ) : null}
            {docs.map((doc) => (
              <tr key={doc.id}>
                <td>
                  <Link to={`/documents/${doc.id}`}>{doc.name}</Link>
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
                    onClick={() => void download(doc.id, () => demo.actions.downloadDocument(doc.id), `actis-${doc.id}.${doc.format.toLowerCase().includes("pdf") ? "pdf" : "json"}`)}
                  >
                    {busy === doc.id ? "Downloading…" : "Download"}
                  </button>
                </td>
              </tr>
            ))}
            {!hasActiveReleasePdfs && !docs.length ? (
              <tr>
                <td colSpan={5} className="muted">
                  No documents or completed release analyses found for this product.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  );
}
