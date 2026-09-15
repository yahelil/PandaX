import { type FormEvent, useMemo, useState } from "react";
import { ClipboardCheck, ShieldCheck } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { usePermission } from "../auth";
import { useDemo } from "../data/DemoProvider";
import type { CraClassificationAssessment, CreateProductInput, Product, ReleaseArtifact } from "../data/types";
import { CraAssessmentWizard } from "./CraAssessmentWizard";
import { craClassLabel } from "./craAssessment";
import { analysisInputAccept, analysisInputHint } from "./analysisInput";
import { PageHeader, StatusPill, formatDate, memberName, relativeDate } from "./PageKit";
import "./pages.css";

type SortKey = "name" | "readiness" | "actions" | "deadline";

export function ProductsPage() {
  const demo = useDemo();
  const canManagePortfolio = usePermission("manage_portfolio");
  const navigate = useNavigate();
  const [adding, setAdding] = useState(false);
  const [query, setQuery] = useState("");
  const [readiness, setReadiness] = useState("all");
  const [monitoring, setMonitoring] = useState("all");
  const [sort, setSort] = useState<SortKey>("actions");
  const [createPending, setCreatePending] = useState(false);
  const [createError, setCreateError] = useState<string>();
  const visible = useMemo(() => {
    const lower = query.toLowerCase();
    return demo.products
      .filter((product) => !lower || `${product.name} ${product.identifier} ${product.manufacturer} ${product.tags.join(" ")}`.toLowerCase().includes(lower))
      .filter((product) => readiness === "all" || product.readiness === readiness)
      .filter((product) => monitoring === "all" || product.monitoringHealth === monitoring)
      .sort((a, b) => compareProducts(a, b, sort));
  }, [demo.products, monitoring, query, readiness, sort]);

  return (
    <main className="page">
      <PageHeader
        eyebrow="Portfolio"
        title="Products"
        description="Cybersecurity readiness, monitoring, and regulatory obligations across your portfolio."
        actions={<button className="button button-primary" disabled={!canManagePortfolio} title={!canManagePortfolio ? "Org Admin or Compliance Operator permission required" : undefined} onClick={() => setAdding((value) => !value)}>Add product</button>}
      />
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
      <section className="panel">
        <div className="toolbar" aria-label="Product filters">
          <input className="search-field" type="search" aria-label="Search products" placeholder="Search products, identifiers, manufacturers…" value={query} onChange={(event) => setQuery(event.target.value)} />
          <select className="select-field" aria-label="Readiness" value={readiness} onChange={(event) => setReadiness(event.target.value)}>
            <option value="all">All readiness</option><option value="ready">Ready</option><option value="needs_attention">Needs attention</option><option value="incomplete_evidence">Incomplete evidence</option>
          </select>
          <select className="select-field" aria-label="Monitoring" value={monitoring} onChange={(event) => setMonitoring(event.target.value)}>
            <option value="all">All monitoring</option><option value="healthy">Healthy</option><option value="degraded">Degraded</option><option value="failed">Failed</option><option value="inactive">Inactive</option>
          </select>
          <select className="select-field" aria-label="Sort products" value={sort} onChange={(event) => setSort(event.target.value as SortKey)}>
            <option value="actions">Most actions</option><option value="deadline">Nearest deadline</option><option value="name">Name</option><option value="readiness">Readiness</option>
          </select>
        </div>
        <div className="data-table-wrap">
          <table className="data-table">
            <thead><tr><th>Product</th><th>Active release</th><th>CRA readiness</th><th>Monitoring</th><th>Actions</th><th>Next deadline</th><th>Owner</th></tr></thead>
            <tbody>{visible.map((product) => {
              const release = demo.selectors.release(product.activeReleaseId);
              return <tr key={product.id}>
                <td><div className="cell-primary"><Link to={`/products/${product.id}`}>{product.name}</Link><small>{product.identifier} · {product.manufacturer}</small></div></td>
                <td><Link to={`/products/${product.id}/releases/${release?.id}`}>{release?.version ?? "No release"}</Link></td>
                <td><StatusPill value={product.readiness} /></td>
                <td><StatusPill value={product.monitoringHealth} /></td>
                <td><strong className={product.actionCount > 2 ? "danger-text" : ""}>{product.actionCount}</strong></td>
                <td><div className="cell-primary"><span className={product.nextDeadline && new Date(product.nextDeadline) < new Date(Date.now() + 3 * 86_400_000) ? "danger-text" : ""}>{relativeDate(product.nextDeadline)}</span><small>{formatDate(product.nextDeadline)}</small></div></td>
                <td>{memberName(demo.state.members, product.ownerId)}</td>
              </tr>;
            })}</tbody>
          </table>
        </div>
        <div className="mobile-card-list">{visible.map((product) => <article className="mobile-card" key={product.id}>
          <div className="cell-primary"><Link to={`/products/${product.id}`}>{product.name}</Link><small>{product.identifier}</small></div>
          <div className="inline-actions"><StatusPill value={product.readiness} /><StatusPill value={product.monitoringHealth} /></div>
          <span>{product.actionCount} open actions · {relativeDate(product.nextDeadline)}</span>
        </article>)}</div>
      </section>
      <p className="muted">Showing {visible.length} of {demo.products.length} products</p>
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
  const sbomAnswer = assessment?.answers.find((answer) => answer.questionId === "sbom")?.answer;
  const hasSbom = sbomAnswer === "yes" || sbomAnswer === "partial";
  const completeAssessment = (value: CraClassificationAssessment) => {
    const declaredSbom = value.answers.find((answer) => answer.questionId === "sbom")?.answer;
    setAssessment(value);
    setAssessmentOpen(false);
    setEvidenceKind(declaredSbom === "yes" || declaredSbom === "partial" ? "sbom" : "collector_package");
    setEvidenceFile(null);
    setRawArtifactConsent(false);
  };
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!assessment || assessment.scopeResult === "out_of_scope") return;
    const data = new FormData(event.currentTarget);
    const input = {
      name: String(data.get("name")), identifier: String(data.get("identifier")), manufacturer: String(data.get("manufacturer")),
      description: String(data.get("description")), craClass: assessment.recommendedClass, classificationStatus: assessment.classificationStatus,
      classificationAssessment: assessment, supportUntil: String(data.get("supportUntil")), ownerId: String(data.get("ownerId")) || undefined,
    } satisfies CreateProductInput;
    const version = String(data.get("version")).trim();
    void onCreate(input, evidenceFile ? { file: evidenceFile, kind: evidenceKind, version, rawArtifactConsent } : undefined);
  };
  return <section className="panel analysis-card create-product-panel">
    {assessmentOpen ? <CraAssessmentWizard onCancel={() => setAssessmentOpen(false)} onComplete={completeAssessment} /> : null}
    <div hidden={assessmentOpen}>
      <h2>Add product</h2><p>Complete the guided CRA assessment, then register product identity and matching evidence.</p>
      <form className="form-grid" onSubmit={submit}>
        <div className="cra-assessment-launch span-2">
          <div className="cra-assessment-launch__icon" aria-hidden="true">{assessment ? <ShieldCheck size={22} /> : <ClipboardCheck size={22} />}</div>
          <div><span className="field-label">CRA classification</span>{assessment ? <><strong>{assessment.scopeResult === "out_of_scope" ? "Likely outside scope" : craClassLabel(assessment.recommendedClass)}</strong><p>{assessment.rationale}</p><small>Readiness {assessment.readinessScore}% · {assessment.actions.length} actions · {assessment.classificationStatus.replaceAll("_", " ")}</small></> : <><strong>Start here</strong><p>Answers determine classification and which evidence upload options appear.</p></>}</div>
          <button type="button" onClick={() => setAssessmentOpen(true)}>{assessment ? "Reassess" : "Start CRA assessment"}</button>
        </div>
        <div className="field"><label htmlFor="product-name">Product name</label><input id="product-name" name="name" className="input-field" required placeholder="Industrial Sensor Gateway" /></div>
        <div className="field"><label htmlFor="product-id">Product identifier</label><input id="product-id" name="identifier" className="input-field" required placeholder="ACM-GTW-620" /></div>
        <div className="field"><label htmlFor="manufacturer">Manufacturer</label><input id="manufacturer" name="manufacturer" className="input-field" required defaultValue="Acme Devices GmbH" /></div>
        <div className="field"><label htmlFor="support-until">Support until</label><input id="support-until" name="supportUntil" className="input-field" type="date" required defaultValue="2031-12-31" /></div>
        <div className="field"><label htmlFor="owner">Default owner</label><select id="owner" name="ownerId" className="select-field"><option value="">Unassigned</option>{members.filter((member) => member.status === "active").map((member) => <option key={member.id} value={member.id}>{member.name}</option>)}</select></div>
        <div className="field span-2"><label htmlFor="description">Description</label><textarea id="description" name="description" className="textarea-field" placeholder="Describe the product, intended purpose, connected functionality, and users." /><span className="field-hint">The description provides context; classification comes from structured assessment answers.</span></div>
        {assessment && assessment.scopeResult !== "out_of_scope" ? <fieldset className="supplemental-evidence span-2">
          <legend>Initial release evidence <span className="muted">(optional)</span></legend>
          <p>{hasSbom ? "You declared an SBOM. Upload it now to create the first release and start analysis." : "No SBOM was declared. Use a Collector ZIP or permitted product archive instead."}</p>
          <div className="supplemental-grid">
            <label><span>Evidence type</span><select className="select-field" value={evidenceKind} onChange={(event) => { setEvidenceKind(event.target.value as InitialEvidence["kind"]); setEvidenceFile(null); setRawArtifactConsent(false); }}>{hasSbom ? <option value="sbom">SBOM</option> : <><option value="collector_package">Collector ZIP</option>{rawArtifactsAllowed ? <option value="raw_artifact">Firmware / build archive</option> : null}</>}</select></label>
            <label><span>Release version</span><input className="input-field" name="version" required={Boolean(evidenceFile)} placeholder="1.0.0" /></label>
          </div>
          <label className="upload-zone"><strong>{evidenceFile?.name ?? `Choose ${evidenceKind === "sbom" ? "SBOM" : evidenceKind === "collector_package" ? "Collector ZIP" : "firmware or build archive"}`}</strong><input type="file" accept={analysisInputAccept(evidenceKind)} onChange={(event) => setEvidenceFile(event.target.files?.[0] ?? null)} /><p>{analysisInputHint(evidenceKind)}</p></label>
          {evidenceKind === "raw_artifact" ? <label className="notice notice-warning"><input type="checkbox" checked={rawArtifactConsent} onChange={(event) => setRawArtifactConsent(event.target.checked)} /> I confirm this artifact may be processed to identify components and security evidence.</label> : null}
        </fieldset> : null}
        {error ? <p className="danger-text span-2" role="alert">{error}</p> : null}
        <div className="inline-actions span-2"><button className="button-primary" type="submit" disabled={pending || !assessment || assessment.scopeResult === "out_of_scope" || evidenceKind === "raw_artifact" && Boolean(evidenceFile) && !rawArtifactConsent}>{pending ? "Creating product…" : evidenceFile ? "Create and analyze" : "Create product"}</button><button type="button" onClick={onCancel} disabled={pending}>Cancel</button>{!assessment ? <span className="field-hint">Complete the CRA assessment before creating this product.</span> : null}</div>
      </form>
    </div>
  </section>;
}

function compareProducts(a: Product, b: Product, sort: SortKey) {
  if (sort === "name") return a.name.localeCompare(b.name);
  if (sort === "actions") return b.actionCount - a.actionCount;
  if (sort === "deadline") return (a.nextDeadline ? new Date(a.nextDeadline).getTime() : Infinity) - (b.nextDeadline ? new Date(b.nextDeadline).getTime() : Infinity);
  return ({ needs_attention: 0, incomplete_evidence: 1, ready: 2 }[a.readiness] - { needs_attention: 0, incomplete_evidence: 1, ready: 2 }[b.readiness]);
}
