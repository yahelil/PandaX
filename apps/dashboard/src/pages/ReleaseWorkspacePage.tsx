import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useDemo } from "../data/DemoProvider";
import type { ReleaseMonitoringView } from "../data/types";
import { Breadcrumbs, EmptyState, EvidenceMeter, FindingInsights, MetricCard, SectionHeader, StatusPill, formatDate, memberName, relativeDate } from "./PageKit";
import "./pages.css";

const releaseTabs = ["overview", "findings", "compliance", "documents"] as const;

export function ReleaseWorkspacePage() {
  const { productId = "", releaseId = "" } = useParams();
  const [params] = useSearchParams();
  const demo = useDemo();
  const release = demo.selectors.release(releaseId);
  const product = demo.selectors.product(productId);
  const tab = releaseTabs.includes(params.get("tab") as typeof releaseTabs[number]) ? params.get("tab") as typeof releaseTabs[number] : "overview";
  if (!release || !product || release.productId !== product.id) return <EmptyState title="Release not found" body="This release is unavailable in the selected product." action={<Link className="button" to="/products">Back to products</Link>} />;
  const findings = demo.findings.filter((item) => item.releaseId === release.id);

  return <main className="page">
    <Breadcrumbs items={[{ label: "Products", to: "/products" }, { label: product.name, to: `/products/${product.id}?tab=releases` }, { label: release.version }]} />
    <section className="panel">
      <div className="workspace-hero"><div className="workspace-title"><span className="product-avatar">{release.channel[0].toUpperCase()}</span><div><p className="eyebrow">{product.name} release</p><h1>{release.version}</h1><p>Released {formatDate(release.releaseDate)} · Supported until {formatDate(release.supportedUntil)}</p></div></div><div className="inline-actions"><StatusPill value={release.readiness} /><StatusPill value={release.monitoringHealth} /><Link className="button button-primary" to={`/products/${product.id}/releases/${release.id}/analyze`}>Analyze release</Link></div></div>
      <nav className="tabs" aria-label="Release workspace">{releaseTabs.map((name) => <Link className={tab === name ? "active" : ""} key={name} to={`/products/${product.id}/releases/${release.id}?tab=${name}`}>{name[0].toUpperCase() + name.slice(1)}</Link>)}</nav>
    </section>
    {tab === "overview" ? <div className="overview-grid">
      <section className="metrics-grid wide"><MetricCard label="Open findings" value={findings.filter((item) => item.status !== "resolved").length} detail={`${findings.filter((item) => item.kev).length} listed in KEV`} tone={findings.some((item) => item.priority === "urgent") ? "urgent" : "good"} /><MetricCard label="Identified components" value={`${release.coverage.identifiedComponents}/${release.coverage.components}`} detail="From latest evidence" /><MetricCard label="Next deadline" value={relativeDate(product.nextDeadline)} detail={formatDate(product.nextDeadline)} tone={product.nextDeadline ? "high" : "good"} /></section>
      <section className="panel"><SectionHeader title="Analysis coverage" description="Latest known software composition and source coverage." /><dl className="definition-grid"><div><dt>SBOM status</dt><dd><StatusPill value={release.sbomStatus} /></dd></div><div><dt>Component identity</dt><dd><EvidenceMeter value={release.coverage.identifiedComponents} total={release.coverage.components} /></dd></div><div><dt>Advisory sources</dt><dd><EvidenceMeter value={release.coverage.advisorySourcesChecked} total={release.coverage.advisorySourcesExpected} /></dd></div><div><dt>Last analysis</dt><dd>{formatDate(release.lastAnalysisAt, true)}</dd></div></dl>{release.coverage.limitations.length ? <div className="panel-pad"><div className="coverage-callout"><strong>Coverage limitations</strong><br />{release.coverage.limitations.join(" ")}</div></div> : null}</section>
      <MonitoringPanel productId={product.id} releaseId={release.id} fallbackHealth={release.monitoringHealth} fallbackLastCheck={release.lastMonitoringCheckAt} />
      <FindingInsights findings={findings} analyses={demo.state.analysisJobs.filter((item) => item.draft.releaseId === release.id)}/>
      <section className="panel wide"><SectionHeader title="Received artifacts" description="Traceable evidence used in the latest analysis." /><div className="data-table-wrap"><table className="data-table"><thead><tr><th>Artifact</th><th>Kind</th><th>Size</th><th>Received</th><th>SHA-256</th></tr></thead><tbody>{release.artifacts.map((artifact) => <tr key={artifact.id}><td className="cell-strong">{artifact.name}</td><td>{artifact.kind.replaceAll("_", " ")}</td><td>{artifact.sizeLabel}</td><td>{formatDate(artifact.receivedAt, true)}</td><td className="mono">{artifact.sha256.slice(0, 16)}…</td></tr>)}</tbody></table></div></section>
    </div> : null}
    {tab === "findings" ? <ReleaseFindings releaseId={release.id} /> : null}
    {tab === "compliance" ? <ReleaseCompliance releaseId={release.id} /> : null}
    {tab === "documents" ? <ReleaseDocuments releaseId={release.id} /> : null}
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

function ReleaseFindings({ releaseId }: { releaseId: string }) { const demo = useDemo(); const items = demo.findings.filter((item) => item.releaseId === releaseId); return <section className="panel"><SectionHeader title="Release findings" description="Prioritized by required action, not severity alone." /><div className="data-table-wrap"><table className="data-table"><thead><tr><th>Reference</th><th>Finding</th><th>Severity</th><th>Actionability</th><th>Status</th><th>Owner</th></tr></thead><tbody>{items.map((item) => <tr key={item.id}><td><Link to={`/findings/${item.id}`}>{item.reference}</Link></td><td>{item.title}</td><td><StatusPill value={item.severity} /></td><td>{[item.kev && "KEV", item.reachability === "reachable" && "Reachable", item.affectedness === "confirmed" && "Affected"].filter(Boolean).join(" · ") || "Review evidence"}</td><td><StatusPill value={item.status} /></td><td>{memberName(demo.state.members, item.assigneeId)}</td></tr>)}</tbody></table></div></section>; }
function ReleaseCompliance({ releaseId }: { releaseId: string }) { const demo = useDemo(); const items = demo.complianceItems.filter((item) => item.releaseId === releaseId); const release = demo.selectors.release(releaseId); return <section className="panel"><SectionHeader title="Release compliance" description="CRA obligations attributable to this release." /><ul className="priority-list">{items.map((item) => <li className="priority-item" key={item.id}><span className={`priority-marker ${item.priority}`} /><div className="item-main"><Link to={`/compliance?product=${encodeURIComponent(item.productId ?? release?.productId ?? "")}&release=${encodeURIComponent(releaseId)}&item=${encodeURIComponent(item.id)}`}>{item.title}</Link><p>{item.requirement} · {item.reason}</p></div><div className="item-meta"><StatusPill value={item.lifecycleStatus ?? item.status} /><span>{relativeDate(item.dueAt)}</span></div></li>)}</ul>{!items.length ? <EmptyState title="No release obligations" body="No open compliance work is linked to this release." /> : null}</section>; }
function ReleaseDocuments({ releaseId }: { releaseId: string }) { const demo = useDemo(); const items = demo.documents.filter((item) => item.releaseId === releaseId); return <section className="panel"><SectionHeader title="Release documents" description="Generated outputs and traceable evidence." /><div className="data-table-wrap"><table className="data-table"><thead><tr><th>Document</th><th>Format</th><th>Version</th><th>Status</th><th>Completeness</th><th>Updated</th></tr></thead><tbody>{items.map((item) => <tr key={item.id}><td><Link to={`/documents/${item.id}`}>{item.name}</Link></td><td>{item.format}</td><td>v{item.version}</td><td><StatusPill value={item.status} /></td><td><StatusPill value={item.completeness} /></td><td>{formatDate(item.updatedAt)}</td></tr>)}</tbody></table></div></section>; }
