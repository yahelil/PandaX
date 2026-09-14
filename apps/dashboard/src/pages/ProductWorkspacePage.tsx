import { type FormEvent, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { usePermission } from "../auth";
import { useDemo } from "../data/DemoProvider";
import { Breadcrumbs, EmptyState, EvidenceMeter, FindingInsights, MetricCard, SectionHeader, StatusPill, formatDate, memberName, relativeDate } from "./PageKit";
import "./pages.css";

const tabs = ["overview", "releases", "findings", "compliance", "documents"] as const;

export function ProductWorkspacePage() {
  const { productId = "" } = useParams();
  const [searchParams] = useSearchParams();
  const tab = tabs.includes(searchParams.get("tab") as typeof tabs[number]) ? searchParams.get("tab") as typeof tabs[number] : "overview";
  const demo = useDemo();
  const canRunAnalysis = usePermission("run_analysis");
  const product = demo.selectors.product(productId);
  if (!product) return <EmptyState title="Product not found" body="The product may have been removed or is outside your organization." action={<Link className="button" to="/products">Back to products</Link>} />;
  const releases = demo.releases.filter((release) => release.productId === product.id);
  const findings = demo.findings.filter((finding) => finding.productId === product.id);
  const compliance = demo.complianceItems.filter((item) => item.productId === product.id);
  const documents = demo.documents.filter((document) => document.productId === product.id);
  const activeRelease = demo.selectors.release(product.activeReleaseId);

  return <main className="page">
    <Breadcrumbs items={[{ label: "Products", to: "/products" }, { label: product.name }]} />
    <section className="panel">
      <div className="workspace-hero">
        <div className="workspace-title"><span className="product-avatar" aria-hidden="true">{product.name.split(" ").map((word) => word[0]).join("")}</span><div><h1>{product.name}</h1><p>{product.identifier} · {product.manufacturer}</p></div></div>
        <div className="inline-actions"><StatusPill value={product.readiness} /><StatusPill value={product.monitoringHealth} />{activeRelease && canRunAnalysis ? <Link className="button button-primary" to={`/products/${product.id}/releases/${activeRelease.id}/analyze`}>Analyze release</Link> : activeRelease ? <span className="button button-primary button-disabled" aria-disabled="true" title="Compliance Operator or Organization Admin permission required">Analyze release</span> : null}</div>
      </div>
      <nav className="tabs" aria-label="Product workspace">
        {tabs.map((name) => <Link className={tab === name ? "active" : ""} key={name} to={`/products/${product.id}?tab=${name}`}>{name[0].toUpperCase() + name.slice(1)}{name === "findings" && findings.length ? ` (${findings.length})` : ""}</Link>)}
      </nav>
    </section>

    {tab === "overview" ? <ProductOverview productId={product.id} /> : null}
    {tab === "releases" ? <ReleasesTable productId={product.id} /> : null}
    {tab === "findings" ? <ProductFindings productId={product.id} /> : null}
    {tab === "compliance" ? <ProductCompliance productId={product.id} /> : null}
    {tab === "documents" ? <ProductDocuments productId={product.id} /> : null}
  </main>;
}

function ProductOverview({ productId }: { productId: string }) {
  const demo = useDemo(); const product = demo.selectors.product(productId)!; const release = demo.selectors.release(product.activeReleaseId);
  const findings = demo.findings.filter((item) => item.productId === productId && item.status !== "resolved");
  const actions = demo.actionItems.filter((item) => item.productId === productId && item.status === "open");
  const analyses = demo.state.analysisJobs.filter((item) => item.draft.productId === productId);
  return <div className="overview-grid">
    <section className="metrics-grid wide"><MetricCard label="Open actions" value={actions.length} detail={actions.filter((item) => item.priority === "urgent").length ? `${actions.filter((item) => item.priority === "urgent").length} urgent` : "No urgent actions"} tone={actions.some((item) => item.priority === "urgent") ? "urgent" : "good"} /><MetricCard label="Active findings" value={findings.length} detail={`${findings.filter((item) => item.kev).length} in KEV`} /><MetricCard label="Next obligation" value={relativeDate(product.nextDeadline)} detail={formatDate(product.nextDeadline)} tone={product.nextDeadline ? "high" : "good"} /></section>
    <section className="panel"><SectionHeader title="Product scope" description="Manufacturer and CRA classification." /><dl className="definition-grid"><div><dt>Product identifier</dt><dd className="mono">{product.identifier}</dd></div><div><dt>CRA class</dt><dd>{product.craClass.replaceAll("_", " ")}</dd></div><div><dt>Support until</dt><dd>{formatDate(product.supportUntil)}</dd></div><div><dt>Default owner</dt><dd>{memberName(demo.state.members, product.ownerId)}</dd></div><div><dt>Classification</dt><dd>{product.classificationStatus.replaceAll("_", " ")}</dd></div><div><dt>Tags</dt><dd>{product.tags.join(", ")}</dd></div></dl></section>
    <section className="panel"><SectionHeader title="Active release" description="Current supported production release." action={release ? <Link className="text-link" to={`/products/${product.id}/releases/${release.id}`}>Open release</Link> : null} />{release ? <dl className="definition-grid"><div><dt>Version</dt><dd>{release.version}</dd></div><div><dt>SBOM</dt><dd><StatusPill value={release.sbomStatus} /></dd></div><div><dt>Released</dt><dd>{formatDate(release.releaseDate)}</dd></div><div><dt>Coverage</dt><dd><EvidenceMeter value={release.coverage.identifiedComponents} total={release.coverage.components} /></dd></div><div><dt>Last analysis</dt><dd>{formatDate(release.lastAnalysisAt, true)}</dd></div><div><dt>Monitoring</dt><dd><StatusPill value={release.monitoringHealth} /></dd></div></dl> : <EmptyState title="No active release" body="Register a release to begin analysis and monitoring." />}</section>
    <FindingInsights findings={findings} analyses={analyses}/>
    <section className="panel wide"><SectionHeader title="Priority drivers" description="Why this product has its current readiness status." /><ul className="priority-list">{actions.slice(0,5).map((item) => <li className="priority-item" key={item.id}><span className={`priority-marker ${item.priority}`} /><div className="item-main"><Link to={item.targetUrl}>{item.title}</Link><p>{item.reason}</p></div><StatusPill value={item.priority} /></li>)}</ul>{!actions.length ? <EmptyState title="No open actions" body="This product has no outstanding compliance work." /> : null}</section>
  </div>;
}

function ReleasesTable({ productId }: { productId: string }) {
  const demo = useDemo(); const navigate = useNavigate(); const releases = demo.releases.filter((item) => item.productId === productId); const [adding,setAdding]=useState(false); const [pending,setPending]=useState(false); const [error,setError]=useState<string>(); const product=demo.selectors.product(productId)!;
  const submit=async(event:FormEvent<HTMLFormElement>)=>{event.preventDefault();setPending(true);setError(undefined);const form=new FormData(event.currentTarget);try{const created=await demo.actions.createRelease({productId,version:String(form.get("version")),channel:String(form.get("channel")) as "stable",releaseDate:String(form.get("releaseDate")),supportedUntil:String(form.get("supportedUntil"))});navigate(`/products/${productId}/releases/${created.id}/analyze`)}catch(reason){setError(reason instanceof Error?reason.message:"Release could not be registered.")}finally{setPending(false)}};
  return <div className="page"><section className="panel"><SectionHeader title="Releases" description="Supported software baselines and their analysis coverage." action={<button className="button-primary" onClick={()=>setAdding((x)=>!x)}>Register release</button>} />{adding?<form className="form-grid panel-pad" onSubmit={submit}><div className="field"><label>Version</label><input className="input-field" name="version" required placeholder="2.5.0"/></div><div className="field"><label>Channel</label><select className="select-field" name="channel"><option value="stable">Stable</option><option value="lts">LTS</option><option value="beta">Beta</option></select></div><div className="field"><label>Release date</label><input className="input-field" name="releaseDate" type="date" required defaultValue={new Date().toISOString().slice(0,10)}/></div><div className="field"><label>Supported until</label><input className="input-field" name="supportedUntil" type="date" required defaultValue={product.supportUntil.slice(0,10)}/></div>{error?<p className="danger-text span-2" role="alert">{error}</p>:null}<div className="span-2 inline-actions"><button className="button-primary" disabled={pending}>{pending?"Registering release…":"Register and add evidence"}</button><button type="button" onClick={()=>setAdding(false)} disabled={pending}>Cancel</button></div></form>:null}<div className="data-table-wrap"><table className="data-table"><thead><tr><th>Version</th><th>Channel</th><th>Status</th><th>Readiness</th><th>SBOM</th><th>Components</th><th>Last analysis</th><th /></tr></thead><tbody>{releases.map((release) => <tr key={release.id}><td><Link to={`/products/${productId}/releases/${release.id}`}>{release.version}</Link></td><td>{release.channel.toUpperCase()}</td><td><StatusPill value={release.status} /></td><td><StatusPill value={release.readiness} /></td><td><StatusPill value={release.sbomStatus} /></td><td><EvidenceMeter value={release.coverage.identifiedComponents} total={release.coverage.components} /></td><td>{formatDate(release.lastAnalysisAt)}</td><td><Link className="text-link" to={`/products/${productId}/releases/${release.id}/analyze`}>Analyze</Link></td></tr>)}</tbody></table></div></section></div>;
}

function ProductFindings({ productId }: { productId: string }) { const demo=useDemo(); const findings=demo.findings.filter((item)=>item.productId===productId); return <section className="panel"><SectionHeader title="Findings" description="Evidence-backed vulnerability decisions for this product." action={<Link className="text-link" to={`/findings?product=${productId}`}>Open full workspace</Link>} /><div className="data-table-wrap"><table className="data-table"><thead><tr><th>Finding</th><th>Component</th><th>Severity</th><th>Evidence</th><th>Status</th><th>Owner</th></tr></thead><tbody>{findings.map((finding)=><tr key={finding.id}><td><div className="cell-primary"><Link to={`/findings/${finding.id}`}>{finding.reference}</Link><small>{finding.title}</small></div></td><td>{finding.component} {finding.componentVersion}</td><td><StatusPill value={finding.severity}/></td><td>{finding.kev?"KEV · ":""}{finding.reachability.replaceAll("_"," ")}</td><td><StatusPill value={finding.status}/></td><td>{memberName(demo.state.members,finding.assigneeId)}</td></tr>)}</tbody></table></div></section>; }

function ProductCompliance({ productId }: { productId:string }) { const demo=useDemo();const items=demo.complianceItems.filter((item)=>item.productId===productId);return <section className="panel"><SectionHeader title="CRA obligations" description="Readiness, reporting, evidence, and approvals." action={<Link className="text-link" to={`/compliance?product=${productId}`}>Open compliance center</Link>}/><ul className="priority-list">{items.map((item)=><li className="priority-item" key={item.id}><span className={`priority-marker ${item.priority}`}/><div className="item-main"><Link to={`/compliance?product=${productId}&item=${encodeURIComponent(item.id)}`}>{item.title}</Link><p>{item.requirement} · {item.reason}</p></div><div className="item-meta"><StatusPill value={item.lifecycleStatus ?? item.status}/><span>{relativeDate(item.dueAt)}</span></div></li>)}</ul></section>; }

function ProductDocuments({ productId }: { productId:string }) {const demo=useDemo();const docs=demo.documents.filter((doc)=>doc.productId===productId);return <section className="panel"><SectionHeader title="Documents and proof" description="Versioned regulatory outputs and verification evidence."/><div className="data-table-wrap"><table className="data-table"><thead><tr><th>Document</th><th>Type</th><th>Version</th><th>Status</th><th>Completeness</th><th>Updated</th></tr></thead><tbody>{docs.map((doc)=><tr key={doc.id}><td><Link to={`/documents/${doc.id}`}>{doc.name}</Link></td><td>{doc.type.replaceAll("_"," ")}</td><td>v{doc.version}</td><td><StatusPill value={doc.status}/></td><td><StatusPill value={doc.completeness}/></td><td>{formatDate(doc.updatedAt)}</td></tr>)}</tbody></table></div></section>;}
