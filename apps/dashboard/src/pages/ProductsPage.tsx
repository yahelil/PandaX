import { type FormEvent, useMemo, useState } from "react";
import { AlertTriangle, ChevronLeft, ChevronRight, ClipboardCheck, Filter, Laptop, MoreVertical, Plus, Search, ShieldCheck } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { usePermission } from "../auth";
import { useDemo } from "../data/DemoProvider";
import type { CraClassificationAssessment, CreateProductInput, Product, ReleaseArtifact } from "../data/types";
import { CraAssessmentWizard } from "./CraAssessmentWizard";
import { craClassLabel } from "./craAssessment";
import { analysisInputAccept, analysisInputHint, validateSbomFormatVersion } from "./analysisInput";
import { formatDate, memberName } from "./PageKit";
import "./pages.css";
import "./devices.css";

type SortKey = "name" | "findings" | "assessment";
type ScopeStatus = "in_scope" | "out_of_scope" | "needs_review";
const pageSize = 10;

function scopeStatus(product: Product): ScopeStatus {
  return product.classificationAssessment?.scopeResult ?? "needs_review";
}

function scopeLabel(status: ScopeStatus): string {
  return status === "in_scope" ? "In scope" : status === "out_of_scope" ? "Out of scope" : "Needs review";
}

export function ProductsPage() {
  const demo = useDemo();
  const canManagePortfolio = usePermission("manage_portfolio");
  const navigate = useNavigate();
  const [adding, setAdding] = useState(false);
  const [query, setQuery] = useState("");
  const [scope, setScope] = useState("all");
  const [productClass, setProductClass] = useState("all");
  const [owner, setOwner] = useState("all");
  const [monitoring, setMonitoring] = useState("all");
  const [sort, setSort] = useState<SortKey>("name");
  const [moreFilters, setMoreFilters] = useState(false);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<string[]>([]);
  const [createPending, setCreatePending] = useState(false);
  const [createError, setCreateError] = useState<string>();
  const openFindings = useMemo(() => {
    const counts = new Map<string, number>();
    for (const finding of demo.findings) {
      if (finding.status !== "resolved") counts.set(finding.productId, (counts.get(finding.productId) ?? 0) + 1);
    }
    return counts;
  }, [demo.findings]);
  const latestAssessment = (product: Product) => [
    product.classificationAssessment?.completedAt,
    ...demo.releases.filter((release) => release.productId === product.id).map((release) => release.lastAnalysisAt),
  ].filter((date): date is string => Boolean(date)).sort().at(-1);
  const visible = useMemo(() => {
    const lower = query.trim().toLowerCase();
    return demo.products
      .filter((product) => !lower || `${product.name} ${product.identifier} ${product.manufacturer} ${product.tags.join(" ")}`.toLowerCase().includes(lower))
      .filter((product) => scope === "all" || scopeStatus(product) === scope)
      .filter((product) => productClass === "all" || product.craClass === productClass)
      .filter((product) => owner === "all" || (owner === "unassigned" ? !product.ownerId : product.ownerId === owner))
      .filter((product) => monitoring === "all" || product.monitoringHealth === monitoring)
      .sort((a, b) => sort === "findings" ? (openFindings.get(b.id) ?? 0) - (openFindings.get(a.id) ?? 0) || a.name.localeCompare(b.name)
        : sort === "assessment" ? (latestAssessment(b) ?? "").localeCompare(latestAssessment(a) ?? "") || a.name.localeCompare(b.name)
        : a.name.localeCompare(b.name));
  }, [demo.products, demo.releases, monitoring, openFindings, owner, productClass, query, scope, sort]);
  const pageCount = Math.max(1, Math.ceil(visible.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageProducts = visible.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const selectedOnPage = pageProducts.length > 0 && pageProducts.every((product) => selected.includes(product.id));
  const setFilter = (setter: (value: string) => void, value: string) => { setter(value); setPage(1); setSelected([]); };
  const toggleSelected = (id: string) => setSelected((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id]);
  const togglePage = () => setSelected((current) => selectedOnPage
    ? current.filter((id) => !pageProducts.some((product) => product.id === id))
    : [...new Set([...current, ...pageProducts.map((product) => product.id)])]);
  const productRelease = (product: Product) => demo.selectors.release(product.activeReleaseId)
    ?? demo.releases.filter((release) => release.productId === product.id).sort((a, b) => b.releaseDate.localeCompare(a.releaseDate))[0];

  return (
    <main className="page devices-page">
      <header className="devices-heading">
        <div><h1>Devices</h1><p>Manage the devices and products in scope for your cybersecurity assessments.</p></div>
        <button className="button button-primary" disabled={!canManagePortfolio} title={!canManagePortfolio ? "Org Admin or Compliance Operator permission required" : undefined} onClick={() => setAdding((value) => !value)}><Plus size={19} /> Add device</button>
      </header>
      <section className="devices-stats" aria-label="Device summary">
        <div className="devices-stat"><span className="devices-stat__icon devices-stat__icon--total"><Laptop size={26} /></span><div><span>Total devices</span><strong>{demo.products.length}</strong></div></div>
        <div className="devices-stat"><span className="devices-stat__icon devices-stat__icon--scope"><span className="devices-stat__dot" /></span><div><span>In scope</span><strong>{demo.products.filter((product) => scopeStatus(product) === "in_scope").length}</strong></div></div>
        <div className="devices-stat"><span className="devices-stat__icon devices-stat__icon--out"><span className="devices-stat__dot" /></span><div><span>Out of scope</span><strong>{demo.products.filter((product) => scopeStatus(product) === "out_of_scope").length}</strong></div></div>
        <div className="devices-stat"><span className="devices-stat__icon devices-stat__icon--findings"><AlertTriangle size={25} /></span><div><span>With open findings</span><strong>{demo.products.filter((product) => (openFindings.get(product.id) ?? 0) > 0).length}</strong></div></div>
      </section>
      {adding && canManagePortfolio ? <CreateProductPanel pending={createPending} error={createError} onCancel={() => setAdding(false)} onCreate={async (input, evidence) => {
        setCreatePending(true);
        setCreateError(undefined);
        try {
          const created = await demo.actions.createProduct(input);
          if (!evidence) {
            navigate(`/products/${created.id}`);
            return;
          }
          const release = await demo.actions.createRelease({
            productId: created.id,
            version: evidence.version,
            channel: "stable",
            releaseDate: new Date().toISOString().slice(0, 10),
            supportedUntil: input.supportUntil,
          });
          const job = await demo.actions.runAnalysis({
            productId: created.id,
            releaseId: release.id,
            version: release.version,
            channel: release.channel,
            inputKind: evidence.kind,
            fileName: evidence.file.name,
            fileSize: evidence.file.size,
            file: evidence.file,
            rawArtifactConsent: evidence.rawArtifactConsent,
          });
          navigate(`/analyses/${job.id}`);
        } catch (error) {
          setCreateError(error instanceof Error ? error.message : "Product could not be created.");
        } finally {
          setCreatePending(false);
        }
      }} members={demo.state.members} rawArtifactsAllowed={demo.state.settings.security.allowRawArtifacts} /> : null}
      <section className="panel devices-list">
        <div className="devices-toolbar" aria-label="Device filters">
          <label className="devices-search"><Search size={18} aria-hidden="true" /><input type="search" aria-label="Search devices" placeholder="Search devices..." value={query} onChange={(event) => setFilter(setQuery, event.target.value)} /></label>
          <select className="select-field" aria-label="Scope status" value={scope} onChange={(event) => setFilter(setScope, event.target.value)}><option value="all">All status</option><option value="in_scope">In scope</option><option value="out_of_scope">Out of scope</option><option value="needs_review">Needs review</option></select>
          <select className="select-field" aria-label="CRA class" value={productClass} onChange={(event) => setFilter(setProductClass, event.target.value)}><option value="all">All CRA classes</option><option value="default">Default</option><option value="important_i">Important I</option><option value="important_ii">Important II</option><option value="critical">Critical</option></select>
          <select className="select-field" aria-label="Owner" value={owner} onChange={(event) => setFilter(setOwner, event.target.value)}><option value="all">All owners</option><option value="unassigned">Unassigned</option>{demo.state.members.filter((member) => member.status === "active").map((member) => <option value={member.id} key={member.id}>{member.name}</option>)}</select>
          <button className="devices-more" type="button" aria-expanded={moreFilters} onClick={() => setMoreFilters((value) => !value)}><Filter size={17} /> More filters</button>
        </div>
        {moreFilters ? <div className="devices-extra-filters"><label>Monitoring <select className="select-field" value={monitoring} onChange={(event) => setFilter(setMonitoring, event.target.value)}><option value="all">All monitoring</option><option value="healthy">Healthy</option><option value="degraded">Degraded</option><option value="failed">Failed</option><option value="inactive">Inactive</option></select></label><label>Sort by <select className="select-field" value={sort} onChange={(event) => { setSort(event.target.value as SortKey); setPage(1); }}><option value="name">Name A–Z</option><option value="findings">Most findings</option><option value="assessment">Latest assessment</option></select></label><button type="button" onClick={() => { setQuery(""); setScope("all"); setProductClass("all"); setOwner("all"); setMonitoring("all"); setSort("name"); setPage(1); setSelected([]); }}>Clear filters</button></div> : null}
        {selected.length > 0 ? <div className="devices-selection" role="status">{selected.length} selected <button type="button" onClick={() => setSelected([])}>Clear selection</button></div> : null}
        <div className="data-table-wrap">
          <table className="data-table devices-table">
            <thead><tr><th><input type="checkbox" aria-label="Select devices on this page" checked={selectedOnPage} onChange={togglePage} /></th><th>Device name</th><th>Product / Version</th><th>CRA class</th><th>Status</th><th>Open findings</th><th>Last assessment</th><th>Owner</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>{pageProducts.map((product) => {
              const release = productRelease(product);
              const status = scopeStatus(product);
              const findings = openFindings.get(product.id) ?? 0;
              return <tr key={product.id}>
                <td><input type="checkbox" aria-label={`Select ${product.name}`} checked={selected.includes(product.id)} onChange={() => toggleSelected(product.id)} /></td>
                <td><Link className="devices-name" to={`/products/${product.id}`}>{product.name}</Link></td>
                <td>{release ? <Link className="devices-version" to={`/products/${product.id}/releases/${release.id}`}>{product.name} v{release.version}</Link> : <span className="devices-muted">No release yet</span>}</td>
                <td><span className={`devices-class devices-class--${product.craClass}`}>{craClassLabel(product.craClass)}</span></td>
                <td><span className={`devices-scope devices-scope--${status}`}><span />{scopeLabel(status)}</span></td>
                <td><Link className={findings ? "devices-finding-count devices-finding-count--open" : "devices-finding-count"} to={`/findings?product=${encodeURIComponent(product.id)}`}>{findings}</Link></td>
                <td>{formatDate(latestAssessment(product))}</td>
                <td>{memberName(demo.state.members, product.ownerId)}</td>
                <td><details className="devices-row-menu"><summary aria-label={`Actions for ${product.name}`}><MoreVertical size={18} /></summary><div><Link to={`/products/${product.id}`}>Open device</Link>{release ? <Link to={`/products/${product.id}/releases/${release.id}`}>Open release</Link> : null}<Link to={`/findings?product=${encodeURIComponent(product.id)}`}>View findings</Link></div></details></td>
              </tr>;
            })}{pageProducts.length === 0 ? <tr><td colSpan={9} className="devices-empty">No devices match these filters.</td></tr> : null}</tbody>
          </table>
        </div>
        <div className="mobile-card-list">{pageProducts.map((product) => <article className="mobile-card devices-mobile-card" key={product.id}>
          <div className="cell-primary"><Link to={`/products/${product.id}`}>{product.name}</Link><small>{product.identifier}</small></div>
          <span className={`devices-scope devices-scope--${scopeStatus(product)}`}><span />{scopeLabel(scopeStatus(product))}</span>
          <span>{openFindings.get(product.id) ?? 0} open findings · {formatDate(latestAssessment(product))}</span>
        </article>)}</div>
        <footer className="devices-footer"><span>Showing {pageProducts.length ? (currentPage - 1) * pageSize + 1 : 0}–{Math.min(currentPage * pageSize, visible.length)} of {visible.length} devices</span><nav aria-label="Device pages"><button type="button" aria-label="Previous page" disabled={currentPage === 1} onClick={() => setPage(currentPage - 1)}><ChevronLeft size={18} /></button>{Array.from({ length: pageCount }, (_, index) => <button type="button" key={index} aria-label={`Page ${index + 1}`} aria-current={currentPage === index + 1 ? "page" : undefined} onClick={() => setPage(index + 1)}>{index + 1}</button>)}<button type="button" aria-label="Next page" disabled={currentPage === pageCount} onClick={() => setPage(currentPage + 1)}><ChevronRight size={18} /></button></nav></footer>
      </section>
    </main>
  );
}
interface InitialEvidence {
  file: File;
  kind: ReleaseArtifact["kind"];
  version: string;
  rawArtifactConsent?: boolean;
}

function CreateProductPanel({ onCancel, onCreate, members, pending, error, rawArtifactsAllowed }: { onCancel: () => void; onCreate: (input: CreateProductInput, evidence?: InitialEvidence) => Promise<void>; members: ReturnType<typeof useDemo>["state"]["members"]; pending: boolean; error?: string; rawArtifactsAllowed: boolean }) {
  const [assessmentOpen, setAssessmentOpen] = useState(false);
  const [assessment, setAssessment] = useState<CraClassificationAssessment>();
  const [evidenceKind, setEvidenceKind] = useState<InitialEvidence["kind"]>("sbom");
  const [evidenceFile, setEvidenceFile] = useState<File | null>(null);
  const [rawArtifactConsent, setRawArtifactConsent] = useState(false);
  const [validationError, setValidationError] = useState<string>();
  const completeAssessment = (value: CraClassificationAssessment) => {
    setAssessment(value);
    setAssessmentOpen(false);
  };
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!assessment || assessment.scopeResult === "out_of_scope") return;
    const data = new FormData(event.currentTarget);
    setValidationError(undefined);
    if (evidenceFile && evidenceKind === "sbom") {
      if (!evidenceFile.name.toLowerCase().endsWith(".json")) {
        setValidationError("SBOM files must use a .json filename.");
        return;
      }
      try { await validateSbomFormatVersion(evidenceFile); }
      catch (cause) { setValidationError(cause instanceof Error ? cause.message : "SBOM format is unsupported."); return; }
    }
    const input = {
      name: String(data.get("name")), identifier: String(data.get("identifier")), manufacturer: String(data.get("manufacturer")),
      description: String(data.get("description")), craClass: assessment.recommendedClass, classificationStatus: assessment.classificationStatus,
      classificationAssessment: assessment, supportUntil: String(data.get("supportUntil")), ownerId: String(data.get("ownerId")) || undefined,
    } satisfies CreateProductInput;
    const version = String(data.get("version")).trim();
    await onCreate(input, evidenceFile ? { file: evidenceFile, kind: evidenceKind, version, rawArtifactConsent } : undefined);
  };
  return <section className="panel analysis-card create-product-panel">
    {assessmentOpen ? <CraAssessmentWizard initialAssessment={assessment} onCancel={() => setAssessmentOpen(false)} onComplete={completeAssessment} /> : null}
    <div hidden={assessmentOpen}>
      <h2>Add device</h2><p>Enter product details, review CRA classification, and add release evidence if available.</p>
      <form className="form-grid" onSubmit={submit}>
        <div className="field"><label htmlFor="product-name">Product name</label><input id="product-name" name="name" className="input-field" required placeholder="Industrial Sensor Gateway" /></div>
        <div className="field"><label htmlFor="product-id">Product identifier</label><input id="product-id" name="identifier" className="input-field" required placeholder="ACM-GTW-620" /></div>
        <div className="field"><label htmlFor="manufacturer">Manufacturer</label><input id="manufacturer" name="manufacturer" className="input-field" required defaultValue="Acme Devices GmbH" /></div>
        <div className="field"><label htmlFor="support-until">Support until</label><input id="support-until" name="supportUntil" className="input-field" type="date" required defaultValue="2031-12-31" /></div>
        <div className="field"><label htmlFor="owner">Default owner</label><select id="owner" name="ownerId" className="select-field"><option value="">Unassigned</option>{members.filter((member) => member.status === "active").map((member) => <option key={member.id} value={member.id}>{member.name}</option>)}</select></div>
        <div className="field span-2"><label htmlFor="description">Description</label><textarea id="description" name="description" className="textarea-field" placeholder="Describe the product, intended purpose, connected functionality, and users." /><span className="field-hint">The description provides context; classification comes from structured assessment answers.</span></div>
        <fieldset className="supplemental-evidence span-2">
          <legend>Initial release evidence <span className="muted">(optional)</span></legend>
          <p>Upload an SBOM or signed Collector ZIP to create the first release and start analysis. You can add evidence later.</p>
          <div className="supplemental-grid">
            <div className="field"><span className="field-label">Upload type</span><div className="upload-type-toggle" role="group" aria-label="Upload type"><button type="button" aria-pressed={evidenceKind === "sbom"} onClick={() => { setEvidenceKind("sbom"); setEvidenceFile(null); setRawArtifactConsent(false); setValidationError(undefined); }}>SBOM</button><button type="button" aria-pressed={evidenceKind === "collector_package"} onClick={() => { setEvidenceKind("collector_package"); setEvidenceFile(null); setRawArtifactConsent(false); setValidationError(undefined); }}>ZIP</button>{rawArtifactsAllowed ? <button type="button" aria-pressed={evidenceKind === "raw_artifact"} onClick={() => { setEvidenceKind("raw_artifact"); setEvidenceFile(null); setValidationError(undefined); }}>Build archive</button> : null}</div></div>
            <label><span>Product release version</span><input className="input-field" name="version" required={Boolean(evidenceFile)} placeholder="1.0.0" /><small>This names your product release. The SBOM format and version are detected automatically.</small></label>
          </div>
          <label className="upload-zone"><strong>{evidenceFile?.name ?? `Choose ${evidenceKind === "sbom" ? "SBOM" : evidenceKind === "collector_package" ? "ZIP" : "build archive"}`}</strong><input type="file" accept={analysisInputAccept(evidenceKind)} onChange={(event) => { setEvidenceFile(event.target.files?.[0] ?? null); setValidationError(undefined); }} /><p>{analysisInputHint(evidenceKind)}</p></label>
          {evidenceKind === "raw_artifact" ? <label className="notice notice-warning"><input type="checkbox" checked={rawArtifactConsent} onChange={(event) => setRawArtifactConsent(event.target.checked)} /> I confirm this artifact may be processed to identify components and security evidence.</label> : null}
        </fieldset>
        <div className="cra-assessment-launch span-2">
          <div className="cra-assessment-launch__icon" aria-hidden="true">{assessment ? <ShieldCheck size={22} /> : <ClipboardCheck size={22} />}</div>
          <div><span className="field-label">CRA classification</span>{assessment ? <><strong>{craClassLabel(assessment.recommendedClass)}</strong><p>{assessment.rationale}</p><small>{assessment.classificationStatus.replaceAll("_", " ")}</small></> : <><strong>Check and classify</strong><p>Review CRA product scope and select the category that describes your product.</p></>}</div>
          <button type="button" onClick={() => setAssessmentOpen(true)}>{assessment ? "Edit assessment" : "Start CRA assessment"}</button>
        </div>
        {validationError ? <p className="danger-text span-2" role="alert">{validationError}</p> : null}
        {error ? <p className="danger-text span-2" role="alert">{error}</p> : null}
        <div className="inline-actions span-2"><button className="button-primary" type="submit" disabled={pending || !assessment || assessment.scopeResult === "out_of_scope" || evidenceKind === "raw_artifact" && Boolean(evidenceFile) && !rawArtifactConsent}>{pending ? "Creating product…" : evidenceFile ? "Create and analyze" : "Create product"}</button><button type="button" onClick={onCancel} disabled={pending}>Cancel</button>{!assessment ? <span className="field-hint">Complete the CRA assessment before creating this product.</span> : null}</div>
      </form>
    </div>
  </section>;
}
