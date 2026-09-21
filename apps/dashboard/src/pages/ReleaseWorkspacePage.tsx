import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useDemo } from "../data/DemoProvider";
import { usePermission } from "../auth";
import type { AnalysisJob, Product, Release, ReleaseMonitoringView } from "../data/types";
import { createReleasePdf, type ReleasePdfKind } from "../data/releasePdf";
import { Breadcrumbs, EmptyState, EvidenceMeter, FindingInsights, MetricCard, SectionHeader, StatusPill, formatDate, memberName, relativeDate } from "./PageKit";
import { downloadFile } from "./downloadFile";
import "./pages.css";

const releaseTabs = ["overview", "findings", "documents"] as const;

export function ReleaseWorkspacePage() {
  const { productId = "", releaseId = "" } = useParams();
  const [params] = useSearchParams();
  const demo = useDemo();
  const canGenerateReport = usePermission("generate_findings_report");
  const [downloading, setDownloading] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState<string>();
  const [generatingReport, setGeneratingReport] = useState(false);
  const [downloadError, setDownloadError] = useState<string>();
  const release = demo.selectors.release(releaseId);
  const product = demo.selectors.product(productId);
  const tab = releaseTabs.includes(params.get("tab") as typeof releaseTabs[number]) ? params.get("tab") as typeof releaseTabs[number] : "overview";
  if (!release || !product || release.productId !== product.id) return <EmptyState title="Release not found" body="This release is unavailable in the selected product." action={<Link className="button" to="/products">Back to products</Link>} />;
  const findings = demo.findings.filter((item) => item.releaseId === release.id);
  const unreviewedCount = findings.filter((item) => item.status === "needs_review").length;
  const latestCompleted = demo.state.analysisJobs.filter((job) => job.draft.productId === product.id && job.draft.releaseId === release.id && job.status === "completed")
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))[0];
  const pdfReports = latestCompleted?.result?.evidence?.filter((item) => item.name.toLowerCase().endsWith(".pdf")) ?? [];
  const downloadReport = async () => {
    if (!latestCompleted) return;
    setDownloading(true); setDownloadError(undefined);
    try {
      const file = await demo.actions.downloadReleaseReport(product.id, release.id, latestCompleted.id);
      downloadFile(file, `actis-${release.id}-evidence.zip`);
    } catch (cause) { setDownloadError(cause instanceof Error ? cause.message : "Could not download release evidence."); }
    finally { setDownloading(false); }
  };
  const generateReport = async () => {
    setGeneratingReport(true); setDownloadError(undefined);
    try {
      const file = await demo.actions.generateSecurityPdf(product.id, release.id);
      downloadFile(file, `actis-${release.id}-security-report.pdf`);
    } catch (cause) { setDownloadError(cause instanceof Error ? cause.message : "Could not generate the security report PDF."); }
    finally { setGeneratingReport(false); }
  };
  const downloadPdfReport = async (report: { name: string; sha256: string }) => {
    if (!latestCompleted) return;
    setDownloadingPdf(report.sha256); setDownloadError(undefined);
    try {
      const file = await demo.actions.downloadAnalysisEvidence(product.id, release.id, latestCompleted.id, report.sha256);
      downloadFile(file, report.name);
    } catch (cause) { setDownloadError(cause instanceof Error ? cause.message : "Could not download the PDF report."); }
    finally { setDownloadingPdf(undefined); }
  };

  return <main className="page">
    <Breadcrumbs items={[{ label: "Products", to: "/products" }, { label: product.name, to: `/products/${product.id}?tab=releases` }, { label: release.version }]} />
    <section className="panel">
      <div className="workspace-hero"><div className="workspace-title"><span className="product-avatar">{release.channel[0].toUpperCase()}</span><div><p className="eyebrow">{product.name} release</p><h1>{release.version}</h1><p>Released {formatDate(release.releaseDate)} · Supported until {formatDate(release.supportedUntil)}</p></div></div><div className="inline-actions"><StatusPill value={release.readiness} /><StatusPill value={release.monitoringHealth} />{canGenerateReport && latestCompleted ? <button type="button" className="button button-primary" disabled={generatingReport} onClick={() => void generateReport()}>{generatingReport ? "Generating…" : "Download security report PDF"}</button> : null}<Link className="button" to={`/products/${product.id}/releases/${release.id}/analyze`}>Analyze release</Link></div></div>
      <nav className="tabs" aria-label="Release workspace">{releaseTabs.map((name) => <Link className={tab === name ? "active" : ""} key={name} to={`/products/${product.id}/releases/${release.id}?tab=${name}`}>{name[0].toUpperCase() + name.slice(1)}</Link>)}</nav>
    </section>
    <p className="muted">Documents for {product.name} version {release.version} are drafts until the manufacturer supplies missing information and approves them. A security report is not a CRA notification or declaration of conformity.</p>
    {downloadError ? <p className="danger-text panel-pad" role="alert">{downloadError}</p> : null}
    {tab === "overview" ? <div className="overview-grid">
      <section className="metrics-grid wide"><MetricCard label="Open findings" value={findings.filter((item) => item.status !== "resolved").length} detail={`${findings.filter((item) => item.kev).length} listed in KEV`} tone={findings.some((item) => item.priority === "urgent") ? "urgent" : "good"} /><MetricCard label="Identified components" value={`${release.coverage.identifiedComponents}/${release.coverage.components}`} detail="From latest evidence" /><MetricCard label="Next deadline" value={relativeDate(product.nextDeadline)} detail={formatDate(product.nextDeadline)} tone={product.nextDeadline ? "high" : "good"} /></section>
      <section className="panel"><SectionHeader title="Analysis coverage" description="Latest known software composition and source coverage." /><dl className="definition-grid"><div><dt>SBOM status</dt><dd><StatusPill value={release.sbomStatus} /></dd></div><div><dt>Component identity</dt><dd><EvidenceMeter value={release.coverage.identifiedComponents} total={release.coverage.components} /></dd></div><div><dt>Advisory sources</dt><dd><EvidenceMeter value={release.coverage.advisorySourcesChecked} total={release.coverage.advisorySourcesExpected} /></dd></div><div><dt>Last analysis</dt><dd>{formatDate(release.lastAnalysisAt, true)}</dd></div></dl>{release.coverage.limitations.length ? <div className="panel-pad"><div className="coverage-callout"><strong>Coverage limitations</strong><br />{release.coverage.limitations.join(" ")}</div></div> : null}</section>
      <MonitoringPanel productId={product.id} releaseId={release.id} fallbackHealth={release.monitoringHealth} fallbackLastCheck={release.lastMonitoringCheckAt} />
      <FindingInsights findings={findings} analyses={demo.state.analysisJobs.filter((item) => item.draft.releaseId === release.id)}/>
      <section className="panel wide"><SectionHeader title="Received artifacts" description="Traceable evidence and generated reports for this release." action={latestCompleted ? <button type="button" disabled={downloading} onClick={() => void downloadReport()}>{downloading ? "Preparing…" : "Download analysis evidence"}</button> : null} />{unreviewedCount ? <p className="panel-pad notice">{unreviewedCount} finding{unreviewedCount === 1 ? "" : "s"} still need a decision. The findings report will identify them as awaiting review. <Link to={`/findings?product=${encodeURIComponent(product.id)}&release=${encodeURIComponent(release.id)}&view=unreviewed`}>Review findings</Link></p> : null}{pdfReports.length ? <div className="data-table-wrap"><table className="data-table"><caption>Release PDF documents</caption><thead><tr><th>Document</th><th>Format</th><th>Action</th></tr></thead><tbody>{pdfReports.map((report) => <tr key={report.sha256}><td className="cell-strong">{report.name.replaceAll("_", " ").replace(/\.pdf$/i, "")}</td><td>{demo.adapterStatus.mode === "fixture" ? "PDF draft" : "PDF/A-2b"}</td><td><button type="button" className="button" disabled={Boolean(downloadingPdf)} onClick={() => void downloadPdfReport(report)}>{downloadingPdf === report.sha256 ? "Downloading…" : "Download PDF"}</button></td></tr>)}</tbody></table></div> : null}<div className="data-table-wrap"><table className="data-table"><thead><tr><th>Artifact</th><th>Kind</th><th>Size</th><th>Received</th><th>SHA-256</th></tr></thead><tbody>{release.artifacts.map((artifact) => <tr key={artifact.id}><td className="cell-strong">{artifact.name}</td><td>{artifact.kind.replaceAll("_", " ")}</td><td>{artifact.sizeLabel}</td><td>{formatDate(artifact.receivedAt, true)}</td><td className="mono">{artifact.sha256.slice(0, 16)}…</td></tr>)}</tbody></table></div></section>
    </div> : null}
    {tab === "findings" ? <ReleaseFindings releaseId={release.id} /> : null}
    {tab === "documents" ? <ReleaseDocuments product={product} release={release} latestCompleted={latestCompleted} /> : null}
  </main>;
}

function MonitoringPanel({ productId, releaseId, fallbackHealth, fallbackLastCheck }: { productId: string; releaseId: string; fallbackHealth: "healthy" | "degraded" | "failed" | "inactive"; fallbackLastCheck?: string }) {
  const { actions } = useDemo();
  const [monitoring, setMonitoring] = useState<ReleaseMonitoringView>();
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [message, setMessage] = useState<string>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setError(undefined);
    actions.loadReleaseMonitoring(productId, releaseId, { signal: controller.signal })
      .then(setMonitoring)
      .catch((cause: unknown) => { if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Unable to load monitoring status."); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [actions, productId, releaseId]);

  const run = async () => {
    setRunning(true); setError(undefined); setMessage(undefined);
    try { setMonitoring(await actions.runReleaseMonitoring(productId, releaseId)); setMessage("Monitoring check completed and persisted."); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Monitoring check failed."); }
    finally { setRunning(false); }
  };
  const health = monitoring?.health ?? fallbackHealth;
  const lastCheck = monitoring?.lastCheckAt ?? fallbackLastCheck;

  return <section className="panel" aria-busy={loading || running}>
    <SectionHeader title="Continuous monitoring" description="Known components are rechecked against configured advisory sources." />
    <dl className="definition-grid"><div><dt>Status</dt><dd><StatusPill value={health} /></dd></div><div><dt>Last check</dt><dd>{loading ? "Loading…" : formatDate(lastCheck, true)}</dd></div><div><dt>Last success</dt><dd>{formatDate(monitoring?.lastSuccessAt, true)}</dd></div><div><dt>Next check</dt><dd>{formatDate(monitoring?.nextCheckAt, true)}</dd></div><div><dt>Cadence</dt><dd>{monitoring ? `Every ${monitoring.cadenceMinutes} minutes` : "—"}</dd></div><div><dt>Sources</dt><dd>{monitoring?.enabledSources.map((source) => source.replaceAll("_", " ").toUpperCase()).join(" · ") || "—"}</dd></div></dl>
    {monitoring?.limitations.length ? <div className="panel-pad"><div className="coverage-callout"><strong>Monitoring limitations</strong><br />{monitoring.limitations.join(" ")}</div></div> : null}
    <div className="panel-pad"><button className="button" disabled={loading || running || monitoring?.running} onClick={() => void run()}>{running || monitoring?.running ? "Checking…" : "Check now"}</button>{message ? <p className="success-text" role="status">{message}</p> : null}{error ? <p className="danger-text" role="alert">{error}</p> : null}</div>
    {monitoring?.recentEvents.length ? <div className="panel-pad"><strong>Recent monitoring events</strong><ul className="activity-list">{monitoring.recentEvents.slice(0, 4).map((event) => <li className="activity-item" key={event.id}><span className="activity-icon" aria-hidden="true">{event.eventType === "failed" ? "!" : "✓"}</span><div className="item-main"><strong>{event.message}</strong><p>{event.trigger === "manual" ? "Manual check" : "Scheduled check"} · {formatDate(event.occurredAt, true)}</p></div><StatusPill value={event.health} /></li>)}</ul></div> : null}
  </section>;
}

function ReleaseFindings({ releaseId }: { releaseId: string }) { const demo = useDemo(); const items = demo.findings.filter((item) => item.releaseId === releaseId); return <section className="panel"><SectionHeader title="Release findings" description="Prioritized by required action, not severity alone." /><div className="data-table-wrap"><table className="data-table"><thead><tr><th>Reference</th><th>Finding</th><th>Severity</th><th>Actionability</th><th>Status</th><th>Owner</th></tr></thead><tbody>{items.map((item) => <tr key={item.id}><td><Link to={`/findings/${item.id}`}>{item.reference}</Link></td><td>{item.title}</td><td><StatusPill value={item.severity} /></td><td>{[item.kev && "KEV", item.reachability === "reachable" && "Reachable", item.affectedness === "confirmed" && "Affected"].filter(Boolean).join(" · ") || "Review evidence"}</td><td>{item.status === "needs_review" ? <Link to={`/findings/${item.id}#risk-decision`}>Needs review</Link> : <StatusPill value={item.status} label={item.status === "action_required" ? "Fix required" : undefined} />}</td><td>{memberName(demo.state.members, item.assigneeId)}</td></tr>)}</tbody></table></div></section>; }
function ReleaseDocuments({ product, release, latestCompleted }: { product: Product; release: Release; latestCompleted?: AnalysisJob }) {
  const demo = useDemo();
  const canGenerateReport = usePermission("generate_findings_report");
  const items = demo.documents.filter((item) => item.releaseId === release.id);
  const pdfEvidence = latestCompleted?.result?.evidence?.filter((item) => item.name.toLowerCase().endsWith(".pdf")) ?? [];
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  const download = async (key: string, operation: () => Promise<{ blob: Blob; filename?: string; contentType: string }>, fallback: string) => {
    setBusy(key); setError(undefined);
    try { downloadFile(await operation(), fallback); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Document could not be downloaded."); }
    finally { setBusy(undefined); }
  };
  const demoDraft = (kind: ReleasePdfKind) => {
    const bytes = createReleasePdf(kind, product, release, demo.findings.filter((item) => item.releaseId === release.id));
    return Promise.resolve({ blob: new Blob([bytes.buffer as ArrayBuffer], { type: "application/pdf" }), contentType: "application/pdf",
      filename: `actis-${release.id}-${kind}-draft.pdf` });
  };
  return <section className="panel">
    <SectionHeader title={`Documents for ${product.name} ${release.version}`} description="Download each PDF for this exact release. Draft legal documents still require manufacturer review and approval." />
    {error ? <p className="panel-pad danger-text" role="alert">{error}</p> : null}
    {!latestCompleted ? <div className="panel-pad notice">Analyze this release before generating its documents. <Link to={`/products/${product.id}/releases/${release.id}/analyze`}>Add an SBOM</Link>.</div> : null}
    <div className="data-table-wrap"><table className="data-table"><thead><tr><th>Document</th><th>Format</th><th>State</th><th>Action</th></tr></thead><tbody>
      <tr><td><strong>Product release security report</strong><br /><small>All findings, review decisions, remediation, and coverage.</small></td><td>PDF</td><td>{latestCompleted ? "Generated on download" : "Waiting for analysis"}</td><td>{latestCompleted && canGenerateReport ? <button type="button" disabled={Boolean(busy)} onClick={() => void download("security", () => demo.actions.generateSecurityPdf(product.id, release.id), `actis-${release.id}-security-report.pdf`)}>{busy === "security" ? "Generating…" : "Download PDF"}</button> : "—"}</td></tr>
      {demo.adapterStatus.mode === "fixture" && latestCompleted && !pdfEvidence.length ? ([
        ["technical", "Annex VII technical documentation draft", "Manufacturer input required"],
        ["declaration", "EU Declaration of Conformity draft", "Not issued - manufacturer approval required"],
      ] as const).map(([kind, name, state]) => <tr key={kind}><td><strong>{name}</strong><br /><small>Local demo draft for this release.</small></td><td>PDF</td><td>{state}</td><td><button type="button" disabled={Boolean(busy)} onClick={() => void download(kind, () => demoDraft(kind), `actis-${release.id}-${kind}-draft.pdf`)}>{busy === kind ? "Preparing…" : "Download draft PDF"}</button></td></tr>) : null}
      {pdfEvidence.map((item) => <tr key={`${latestCompleted?.id}-${item.sha256}`}><td><strong>{item.name.replaceAll("_", " ")}</strong><br /><small>{demo.adapterStatus.mode === "fixture" ? "Local demo draft for this release." : "Generated by the analysis pipeline; review required before legal use."}</small></td><td>{demo.adapterStatus.mode === "fixture" ? "PDF" : "PDF/A-2b"}</td><td>Draft evidence</td><td><button type="button" disabled={Boolean(busy)} onClick={() => void download(item.sha256, () => demo.actions.downloadReleaseEvidenceFile(product.id, release.id, latestCompleted!.id, item.sha256), item.name)}>{busy === item.sha256 ? "Downloading…" : "Download PDF"}</button></td></tr>)}
      {items.filter((item) => !["Release report", "Product release security report"].includes(item.name)).map((item) => <tr key={item.id}><td><Link to={`/documents/${item.id}`}>{item.name}</Link></td><td>{item.format}</td><td>{item.status} · {item.completeness.replaceAll("_", " ")}</td><td><button type="button" disabled={Boolean(busy)} onClick={() => void download(item.id, () => demo.actions.downloadDocument(item.id), `actis-${item.id}.pdf`)}>{busy === item.id ? "Downloading…" : "Download"}</button></td></tr>)}
    </tbody></table></div>
  </section>;
}
