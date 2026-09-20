import { type FormEvent, useMemo, useState } from "react";
import { AlertTriangle, ChevronLeft, ChevronRight, ClipboardCheck, Filter, Laptop, MoreVertical, Plus, Search, ShieldCheck } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { usePermission } from "../auth";
import { useDemo } from "../data/DemoProvider";
import type { CraClassificationAssessment, CreateProductInput, Product, ReleaseArtifact } from "../data/types";
import { CraAssessmentWizard } from "./CraAssessmentWizard";
import { buildCraAssessment, craClassLabel } from "./craAssessment";
import { analysisInputAccept, analysisInputHint, validateSbomFormatVersion } from "./analysisInput";
import { LocalSbomGuide } from "./LocalSbomGuide";
import { formatDate, memberName } from "./PageKit";
import { ExactTimerBadge } from "../components/ExactTimerBadge";
import { ProductScopeModal } from "../components/ProductScopeModal";
import { getProductMostUrgentTimer } from "./exactTimers";
import "./pages.css";
import "./devices.css";

type SortKey = "name" | "findings" | "assessment";
type ScopeStatus = "in_scope" | "out_of_scope" | "needs_review";
const pageSize = 10;

export function scopeStatus(product: Product): ScopeStatus {
  return product.classificationAssessment?.scopeResult ?? "needs_review";
}

export function scopeLabel(status: ScopeStatus): string {
  return status === "in_scope" ? "In scope" : status === "out_of_scope" ? "Out of scope" : "Needs review";
}

export function ProductsPage() {
  const demo = useDemo();
  const canManagePortfolio = usePermission("manage_portfolio");
  const navigate = useNavigate();
  const [adding, setAdding] = useState(false);
  const [reviewProduct, setReviewProduct] = useState<Product | null>(null);
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
        <div><h1>Products</h1><p>Manage products and connected components in scope for your cybersecurity assessments.</p></div>
        <button className="button button-primary" disabled={!canManagePortfolio} title={!canManagePortfolio ? "Org Admin or Compliance Operator permission required" : undefined} onClick={() => setAdding((value) => !value)}><Plus size={19} /> Add product</button>
      </header>
      <section className="devices-stats" aria-label="Device summary">
        <div className="devices-stat"><span className="devices-stat__icon devices-stat__icon--total"><Laptop size={26} /></span><div><span>Total products</span><strong>{demo.products.length}</strong></div></div>
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
      }} members={demo.state.members} rawArtifactsAllowed={demo.state.settings.security.allowRawArtifacts} demoMode={demo.adapterStatus.mode === "fixture"} /> : null}
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
            <thead><tr><th><input type="checkbox" aria-label="Select devices on this page" checked={selectedOnPage} onChange={togglePage} /></th><th>Product</th><th>CRA class</th><th>Status</th><th>Open findings</th><th>Most urgent deadline</th><th>Last assessment</th><th>Owner</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>{pageProducts.map((product) => {
              const release = productRelease(product);
              const status = scopeStatus(product);
              const findings = openFindings.get(product.id) ?? 0;
              const mostUrgentTimer = getProductMostUrgentTimer(product, demo.findings, demo.complianceItems);
              return <tr key={product.id}>
                <td><input type="checkbox" aria-label={`Select ${product.name}`} checked={selected.includes(product.id)} onChange={() => toggleSelected(product.id)} /></td>
                <td>
                  <div className="cell-primary">
                    <Link className="devices-name" to={`/products/${product.id}`}>{product.name}</Link>
                    {release ? (
                      <Link className="devices-version" to={`/products/${product.id}/releases/${release.id}`}>
                        <small>v{release.version} ({release.channel})</small>
                      </Link>
                    ) : (
                      <small className="devices-muted">No release yet</small>
                    )}
                  </div>
                </td>
                <td><span className={`devices-class devices-class--${product.craClass}`}>{craClassLabel(product.craClass)}</span></td>
                <td><button type="button" className={`devices-scope devices-scope-button devices-scope--${status}`} onClick={() => setReviewProduct(product)} title="Click to open window to review CRA scope, classification, or upload evidence" aria-label={`Review CRA scope for ${product.name}: ${scopeLabel(status)}`}><span />{scopeLabel(status)}</button></td>
                <td><Link className={findings ? "devices-finding-count devices-finding-count--open" : "devices-finding-count"} to={`/findings?product=${encodeURIComponent(product.id)}`}>{findings}</Link></td>
                <td><ExactTimerBadge timer={mostUrgentTimer} compact /></td>
                <td>{formatDate(latestAssessment(product))}</td>
                <td>{memberName(demo.state.members, product.ownerId)}</td>
                <td><details className="devices-row-menu"><summary aria-label={`Actions for ${product.name}`}><MoreVertical size={18} /></summary><div><Link to={`/products/${product.id}`}>Open device</Link>{release ? <Link to={`/products/${product.id}/releases/${release.id}`}>Open release</Link> : null}<Link to={`/findings?product=${encodeURIComponent(product.id)}`}>View findings</Link><button type="button" onClick={() => setReviewProduct(product)} style={{ textAlign: "left", background: "none", border: "none", padding: "8px", borderRadius: "5px", cursor: "pointer", font: "inherit", fontSize: "12px", color: "inherit" }}>Review CRA scope</button></div></details></td>
              </tr>;
            })}{pageProducts.length === 0 ? <tr><td colSpan={9} className="devices-empty">No products match these filters.</td></tr> : null}</tbody>
          </table>
        </div>
        <div className="mobile-card-list">{pageProducts.map((product) => {
          const mostUrgentTimer = getProductMostUrgentTimer(product, demo.findings, demo.complianceItems);
          return <article className="mobile-card devices-mobile-card" key={product.id}>
            <div className="cell-primary"><Link to={`/products/${product.id}`}>{product.name}</Link><small>{product.identifier}</small></div>
            <button type="button" className={`devices-scope devices-scope-button devices-scope--${scopeStatus(product)}`} onClick={() => setReviewProduct(product)} title="Click to open window to review CRA scope, classification, or upload evidence" aria-label={`Review CRA scope for ${product.name}: ${scopeLabel(scopeStatus(product))}`}><span />{scopeLabel(scopeStatus(product))}</button>
            <ExactTimerBadge timer={mostUrgentTimer} compact />
            <span>{openFindings.get(product.id) ?? 0} open findings · {formatDate(latestAssessment(product))}</span>
          </article>;
        })}</div>
        <footer className="devices-footer"><span>Showing {pageProducts.length ? (currentPage - 1) * pageSize + 1 : 0}–{Math.min(currentPage * pageSize, visible.length)} of {visible.length} devices</span><nav aria-label="Device pages"><button type="button" aria-label="Previous page" disabled={currentPage === 1} onClick={() => setPage(currentPage - 1)}><ChevronLeft size={18} /></button>{Array.from({ length: pageCount }, (_, index) => <button type="button" key={index} aria-label={`Page ${index + 1}`} aria-current={currentPage === index + 1 ? "page" : undefined} onClick={() => setPage(index + 1)}>{index + 1}</button>)}<button type="button" aria-label="Next page" disabled={currentPage === pageCount} onClick={() => setPage(currentPage + 1)}><ChevronRight size={18} /></button></nav></footer>
      </section>
      {reviewProduct ? <ProductScopeModal product={reviewProduct} onClose={() => setReviewProduct(null)} /> : null}
    </main>
  );
}
interface InitialEvidence {
  file: File;
  kind: ReleaseArtifact["kind"];
  version: string;
  rawArtifactConsent?: boolean;
}

function CreateProductPanel({
  onCancel,
  onCreate,
  members,
  pending,
  error,
  rawArtifactsAllowed,
  demoMode,
}: {
  onCancel: () => void;
  onCreate: (input: CreateProductInput, evidence?: InitialEvidence) => Promise<void>;
  members: ReturnType<typeof useDemo>["state"]["members"];
  pending: boolean;
  error?: string;
  rawArtifactsAllowed: boolean;
  demoMode: boolean;
}) {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [name, setName] = useState("");
  const [identifier, setIdentifier] = useState("");
  const [manufacturer, setManufacturer] = useState("Acme Devices GmbH");
  const [supportUntil, setSupportUntil] = useState("2031-12-31");
  const [ownerId, setOwnerId] = useState("");
  const [description, setDescription] = useState("");
  const [showDescription, setShowDescription] = useState(false);

  const [assessmentOpen, setAssessmentOpen] = useState(false);
  const [assessment, setAssessment] = useState<CraClassificationAssessment>();

  const [evidenceKind, setEvidenceKind] = useState<InitialEvidence["kind"]>("sbom");
  const [evidenceFile, setEvidenceFile] = useState<File | null>(null);
  const [version, setVersion] = useState("1.0.0");
  const [rawArtifactConsent, setRawArtifactConsent] = useState(false);
  const [validationError, setValidationError] = useState<string>();

  const completeAssessment = (value: CraClassificationAssessment) => {
    setAssessment(value);
    setAssessmentOpen(false);
  };

  const setDefaultCraRoute = () => {
    const defaultAssessment = buildCraAssessment({
      scopeAnswers: {},
      scopeReviewed: true,
      categorySelections: {},
      completedAt: new Date().toISOString(),
      confirmed: true,
    });
    setAssessment(defaultAssessment);
  };

  const handleFinish = async () => {
    if (!assessment || assessment.scopeResult === "out_of_scope" || !evidenceFile) return;
    setValidationError(undefined);

    if (demoMode && evidenceKind !== "sbom") {
      setValidationError(
        "Archive and Collector analysis require the production engine. In this local demo, upload a JSON SBOM or create the product with an SBOM."
      );
      return;
    }

    if (evidenceKind === "sbom") {
      if (!evidenceFile.name.toLowerCase().endsWith(".json")) {
        setValidationError("SBOM files must use a .json filename.");
        return;
      }
      try {
        if (evidenceFile) await validateSbomFormatVersion(evidenceFile);
      } catch (cause) {
        setValidationError(cause instanceof Error ? cause.message : "SBOM format is unsupported.");
        return;
      }
    }

    const input = {
      name: name.trim(),
      identifier: identifier.trim(),
      manufacturer: manufacturer.trim(),
      description: description.trim(),
      craClass: assessment.recommendedClass,
      classificationStatus: assessment.classificationStatus,
      classificationAssessment: assessment,
      supportUntil: supportUntil.trim(),
      ownerId: ownerId || undefined,
    } satisfies CreateProductInput;

    const trimmedVersion = version.trim() || "1.0.0";
    await onCreate(input, {
      file: evidenceFile,
      kind: evidenceKind,
      version: trimmedVersion,
      rawArtifactConsent,
    });
  };

  return (
    <section className="panel analysis-card create-product-panel">
      {assessmentOpen ? (
        <CraAssessmentWizard
          initialAssessment={assessment}
          onCancel={() => setAssessmentOpen(false)}
          onComplete={completeAssessment}
        />
      ) : (
        <div>
          <div style={{ marginBottom: 16 }}>
            <h2>Add product</h2>
            <p className="muted" style={{ margin: "3px 0 0", fontSize: 13 }}>
              Register a product in your portfolio, review CRA classification, and attach your initial software baseline.
            </p>
          </div>

          <div className="stepper stepper--3" aria-label={`Step ${step} of 3`}>
            <div className={`step ${step === 1 ? "active" : step > 1 ? "done" : ""}`}>
              <span>1. Product details</span>
            </div>
            <div className={`step ${step === 2 ? "active" : step > 2 ? "done" : ""}`}>
              <span>2. CRA classification</span>
            </div>
            <div className={`step ${step === 3 ? "active" : ""}`}>
              <span>3. Upload SBOM</span>
            </div>
          </div>

          {step === 1 && (
            <div className="form-grid">
              <div className="field">
                <label htmlFor="product-name">Product name</label>
                <input
                  id="product-name"
                  name="name"
                  className="input-field"
                  required
                  placeholder="Industrial Sensor Gateway"
                  value={name}
                  onChange={(e) => {
                    setName(e.target.value);
                    setValidationError(undefined);
                  }}
                />
              </div>
              <div className="field">
                <label htmlFor="product-id">Product identifier</label>
                <input
                  id="product-id"
                  name="identifier"
                  className="input-field"
                  required
                  placeholder="ACM-GTW-620"
                  value={identifier}
                  onChange={(e) => {
                    setIdentifier(e.target.value);
                    setValidationError(undefined);
                  }}
                />
              </div>
              <div className="field">
                <label htmlFor="manufacturer">Manufacturer</label>
                <input
                  id="manufacturer"
                  name="manufacturer"
                  className="input-field"
                  required
                  value={manufacturer}
                  onChange={(e) => setManufacturer(e.target.value)}
                />
              </div>
              <div className="field">
                <label htmlFor="support-until">Support until</label>
                <input
                  id="support-until"
                  name="supportUntil"
                  className="input-field"
                  type="date"
                  required
                  value={supportUntil}
                  onChange={(e) => setSupportUntil(e.target.value)}
                />
              </div>
              <div className="field span-2">
                <label htmlFor="owner">Default owner</label>
                <select
                  id="owner"
                  name="ownerId"
                  className="select-field"
                  value={ownerId}
                  onChange={(e) => setOwnerId(e.target.value)}
                >
                  <option value="">Unassigned</option>
                  {members
                    .filter((member) => member.status === "active")
                    .map((member) => (
                      <option key={member.id} value={member.id}>
                        {member.name}
                      </option>
                    ))}
                </select>
              </div>
              <div className="field span-2">
                {!showDescription ? (
                  <button
                    type="button"
                    className="button button-small"
                    style={{ justifySelf: "start", color: "var(--text-muted)" }}
                    onClick={() => setShowDescription(true)}
                  >
                    + Add optional description
                  </button>
                ) : (
                  <>
                    <label htmlFor="description">
                      Description <span className="muted">(optional)</span>
                    </label>
                    <textarea
                      id="description"
                      name="description"
                      className="textarea-field"
                      rows={2}
                      placeholder="Describe the product, intended purpose, and deployment context."
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                    />
                  </>
                )}
              </div>
              <div className="inline-actions span-2" style={{ justifyContent: "space-between", marginTop: 14 }}>
                <button type="button" onClick={onCancel} disabled={pending}>
                  Cancel
                </button>
                <button
                  type="button"
                  className="button-primary"
                  disabled={!name.trim() || !identifier.trim()}
                  onClick={() => setStep(2)}
                >
                  Continue to CRA scope →
                </button>
              </div>
            </div>
          )}

          {step === 2 && (
            <div style={{ display: "grid", gap: 18 }}>
              <div>
                <p className="muted" style={{ margin: "0 0 14px", fontSize: 13 }}>
                  Determine your product’s CRA classification route under EU regulation. You can pick standard self-assessment or launch the guided wizard.
                </p>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 16 }}>
                <div
                  className={`wizard-card ${assessment?.recommendedClass === "default" && !assessment.categoryId ? "active" : ""}`}
                  style={{ cursor: "pointer", display: "flex", flexDirection: "column", justifyContent: "space-between", padding: 18 }}
                  onClick={setDefaultCraRoute}
                >
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                      <strong style={{ fontSize: 14 }}>Standard Product Route</strong>
                      <span className="devices-class devices-class--default">Default Class</span>
                    </div>
                    <p className="muted" style={{ fontSize: 12.5, margin: 0, lineHeight: 1.5 }}>
                      Internal production control (Module A self-assessment). For general products with digital elements that do not fall under Annex III or IV.
                    </p>
                  </div>
                  <div style={{ marginTop: 16 }}>
                    <button
                      type="button"
                      className={`button button-small ${assessment?.recommendedClass === "default" && !assessment.categoryId ? "button-primary" : ""}`}
                      onClick={(e) => {
                        e.stopPropagation();
                        setDefaultCraRoute();
                      }}
                    >
                      {assessment?.recommendedClass === "default" && !assessment.categoryId ? "✓ Selected (Standard)" : "Select Standard Route"}
                    </button>
                  </div>
                </div>

                <div
                  className={`wizard-card ${assessment && (assessment.recommendedClass !== "default" || assessment.categoryId) ? "active" : ""}`}
                  style={{ cursor: "pointer", display: "flex", flexDirection: "column", justifyContent: "space-between", padding: 18 }}
                  onClick={() => setAssessmentOpen(true)}
                >
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                      <strong style={{ fontSize: 14 }}>Guided CRA Assessment</strong>
                      {assessment && (assessment.recommendedClass !== "default" || assessment.categoryId) ? (
                        <span className={`devices-class devices-class--${assessment.recommendedClass}`}>
                          {craClassLabel(assessment.recommendedClass)}
                        </span>
                      ) : (
                        <span className="status-pill">Annex III / IV</span>
                      )}
                    </div>
                    <p className="muted" style={{ fontSize: 12.5, margin: 0, lineHeight: 1.5 }}>
                      {assessment && (assessment.recommendedClass !== "default" || assessment.categoryId)
                        ? assessment.rationale
                        : "Walk through CRA scope and category questions to evaluate if your product is Important I, Important II, or Critical."}
                    </p>
                  </div>
                  <div style={{ marginTop: 16 }}>
                    <button
                      type="button"
                      className={`button button-small ${assessment && (assessment.recommendedClass !== "default" || assessment.categoryId) ? "button-primary" : ""}`}
                      onClick={(e) => {
                        e.stopPropagation();
                        setAssessmentOpen(true);
                      }}
                    >
                      {assessment && (assessment.recommendedClass !== "default" || assessment.categoryId) ? "Re-run Assessment" : "Start Guided Assessment"}
                    </button>
                  </div>
                </div>
              </div>

              {assessment ? (
                <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "12px 16px", background: "var(--surface-subtle)", borderRadius: 10, border: "1px solid var(--border)" }}>
                  <ShieldCheck size={20} color="var(--success)" />
                  <span style={{ fontSize: 13 }}>
                    Current classification: <strong>{craClassLabel(assessment.recommendedClass)}</strong> ({assessment.categoryLabel ?? "Standard Route"})
                  </span>
                </div>
              ) : null}

              <div className="inline-actions" style={{ justifyContent: "space-between", marginTop: 14 }}>
                <button type="button" onClick={() => setStep(1)} disabled={pending}>
                  Back
                </button>
                <button
                  type="button"
                  className="button-primary"
                  disabled={pending || !assessment || assessment.scopeResult === "out_of_scope"}
                  onClick={() => setStep(3)}
                >
                  Next: Upload SBOM →
                </button>
              </div>
            </div>
          )}

          {step === 3 && (
            <div style={{ display: "grid", gap: 18 }}>
              <div>
                <p className="muted" style={{ margin: "0 0 14px", fontSize: 13 }}>
                  Provide the initial software bill of materials (SBOM) or release package for <strong>{name || "your product"}</strong>. Actis will identify components, evaluate CVEs, and produce compliance evidence.
                </p>
              </div>

              <fieldset className="supplemental-evidence span-2" style={{ display: "grid", gap: 18, padding: 20 }}>
                <legend style={{ fontSize: 13, fontWeight: 700 }}>Initial release evidence</legend>
                <p style={{ margin: 0, color: "var(--text-muted)", fontSize: 13 }}>
                  Choose existing evidence, create a privacy-preserving SBOM locally, or upload a source/build archive for server-side analysis.
                </p>

                {demoMode && evidenceKind !== "sbom" ? (
                  <div className="notice notice-warning">
                    Archive and Collector analysis require the production engine. In this local demo, upload a JSON SBOM to analyze.
                  </div>
                ) : null}

                <div className="supplemental-grid" style={{ gap: 16 }}>
                  <div className="field">
                    <span className="field-label" style={{ fontWeight: 600, fontSize: 12 }}>Evidence type</span>
                    <div className="upload-type-toggle" role="group" aria-label="Upload type">
                      <button type="button" aria-pressed={evidenceKind === "sbom"} onClick={() => { setEvidenceKind("sbom"); setEvidenceFile(null); setRawArtifactConsent(false); setValidationError(undefined); }}>Existing SBOM</button>
                      <button type="button" aria-pressed={evidenceKind === "collector_package"} onClick={() => { setEvidenceKind("collector_package"); setEvidenceFile(null); setRawArtifactConsent(false); setValidationError(undefined); }}>Signed Collector ZIP</button>
                      <button type="button" aria-pressed={evidenceKind === "raw_artifact"} disabled={!rawArtifactsAllowed} title={!rawArtifactsAllowed ? "Enable raw product artifacts in Security & Retention settings" : undefined} onClick={() => { setEvidenceKind("raw_artifact"); setEvidenceFile(null); setValidationError(undefined); }}>Source / build ZIP</button>
                    </div>
                    {!rawArtifactsAllowed ? (
                      <small>Source/build uploads are disabled by organization policy. Enable raw product artifacts in Security & Retention settings.</small>
                    ) : null}
                  </div>

                  <label>
                    <span style={{ fontWeight: 600, fontSize: 12 }}>Product release version</span>
                    <input
                      className="input-field"
                      name="version"
                      value={version}
                      onChange={(e) => setVersion(e.target.value)}
                      required
                      placeholder="1.0.0"
                    />
                    <small>This names your product release. The SBOM format and version are detected automatically.</small>
                  </label>
                </div>

                <label className="upload-zone" style={{ padding: "28px 20px" }}>
                  <strong style={{ fontSize: 14 }}>
                    {evidenceFile?.name ?? `Choose ${evidenceKind === "sbom" ? "SBOM" : evidenceKind === "collector_package" ? "ZIP" : "build archive"}`}
                  </strong>
                  <input
                    type="file"
                    accept={analysisInputAccept(evidenceKind)}
                    onChange={(event) => {
                      setEvidenceFile(event.target.files?.[0] ?? null);
                      setValidationError(undefined);
                    }}
                  />
                  <p>{analysisInputHint(evidenceKind)}</p>
                </label>

                {evidenceKind === "raw_artifact" ? (
                  <label className="notice notice-warning">
                    <input
                      type="checkbox"
                      checked={rawArtifactConsent}
                      onChange={(event) => setRawArtifactConsent(event.target.checked)}
                    />{" "}
                    I understand this archive may contain source code. I consent to uploading it to Actis for server-side component and security analysis.
                  </label>
                ) : null}

                <LocalSbomGuide
                  compact
                  productName={name}
                  productVersion={version}
                  onAttachSbom={(file: File) => {
                    setEvidenceKind("sbom");
                    setEvidenceFile(file);
                    setValidationError(undefined);
                  }}
                />
              </fieldset>

              {validationError ? (
                <p className="danger-text span-2" role="alert">
                  {validationError}
                </p>
              ) : null}
              {error ? (
                <p className="danger-text span-2" role="alert">
                  {error}
                </p>
              ) : null}

              <div className="inline-actions span-2" style={{ justifyContent: "space-between", marginTop: 14 }}>
                <button type="button" onClick={() => setStep(2)} disabled={pending}>
                  Back
                </button>
                <div style={{ display: "flex", gap: 10 }}>
                  <button type="button" onClick={onCancel} disabled={pending}>
                    Cancel
                  </button>
                  <button
                    className="button-primary"
                    type="button"
                    disabled={
                      pending ||
                      !assessment ||
                      assessment.scopeResult === "out_of_scope" ||
                      !evidenceFile ||
                      !version.trim() ||
                      (evidenceKind === "raw_artifact" && !rawArtifactConsent)
                    }
                    onClick={() => void handleFinish()}
                  >
                    {pending ? "Creating product…" : "Create and analyze"}
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
