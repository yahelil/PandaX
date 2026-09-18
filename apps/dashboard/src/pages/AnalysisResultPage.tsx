import { Link, useParams } from "react-router-dom";
import { useDemo } from "../data/DemoProvider";
import { EmptyState, EvidenceMeter, PageHeader, StatusPill } from "./PageKit";
import "./pages.css";

export function AnalysisResultPage() {
  const { analysisId = "" } = useParams();
  const demo = useDemo();
  const job = demo.selectors.analysisJob(analysisId);
  if (!job) return <EmptyState title="Analysis not found" body="The analysis job is unavailable or has expired." action={<Link className="button" to="/products">Back to products</Link>} />;

  const release = demo.selectors.release(job.draft.releaseId);
  const product = demo.selectors.product(job.draft.productId);
  const complete = job.status === "completed";
  const failed = job.status === "failed";
  const releasePath = job.draft.releaseId
    ? `/products/${job.draft.productId}/releases/${job.draft.releaseId}`
    : `/products/${job.draft.productId}`;
  const pollingFailure = demo.adapterStatus.failure?.operation === "run_analysis"
    ? demo.adapterStatus.failure
    : undefined;

  return <main className="page analysis-shell">
    <PageHeader
      eyebrow="Release analysis"
      title={failed ? "Analysis failed" : complete ? "Analysis complete" : "Analysis in progress"}
      description={`${product?.name ?? "Product"} ${release?.version ?? job.draft.version} · ${job.stage}`}
    />
    <section className="panel analysis-card">
      <div className="detail-badges"><StatusPill value={job.status} /><span className="status-pill">{job.progress}%</span></div>
      <div className="progress-track" style={{ margin: "20px 0" }}><span style={{ width: `${job.progress}%` }} /></div>
      {failed ? <>
        <h2>This analysis did not complete</h2>
        <p role="alert">{job.error || "The analysis service did not provide a failure reason. Check the service logs for this job ID."}</p>
        <p>The uploaded evidence remains linked to this release. A new analysis requires a new upload.</p>
        <div className="inline-actions" style={{ marginTop: 22 }}>
          <Link className="button button-primary" to={`${releasePath}/analyze`}>Upload and try again</Link>
          <Link className="button" to={releasePath}>Open release</Link>
        </div>
      </> : complete && job.result ? <>
        <h2>Release contents established</h2>
        <p>Results are linked to this release. Coverage limits remain visible wherever these results inform a decision.</p>
        <div className="preview-summary">
          <div className="preview-stat"><span>Components analyzed</span><strong>{job.result.componentCount}</strong></div>
          <div className="preview-stat"><span>New findings</span><strong>{job.result.newFindings}</strong></div>
          <div className="preview-stat"><span>Changed findings</span><strong>{job.result.changedFindings}</strong></div>
        </div>
        <div style={{ marginTop: 18 }}><EvidenceMeter value={job.result.coverage.identifiedComponents} total={job.result.coverage.components} /></div>
        {job.result.coverage.limitations.map((limit) => <div className="coverage-callout" style={{ marginTop: 16 }} key={limit}><strong>Coverage limitation</strong><br />{limit}</div>)}
        <div className="inline-actions" style={{ marginTop: 22 }}>
          <Link className="button button-primary" to={`/findings?product=${job.draft.productId}&release=${job.result.releaseId}&view=unreviewed`}>Review findings</Link>
          <Link className="button" to={job.result.resultUrl}>Open release</Link>
          <Link className="button button-quiet" to={`${job.result.resultUrl}?tab=documents`}>Legal Documents</Link>
        </div>
      </> : complete ? <>
        <h2>Results unavailable</h2>
        <p role="alert">The service marked this analysis complete but did not return its result. Open the release or retry loading the workspace.</p>
        <Link className="button" to={releasePath}>Open release</Link>
      </> : <>
        <h2>{job.stage}</h2>
        {pollingFailure ? <p role="alert">Status updates are temporarily unavailable: {pollingFailure.message}. The dashboard will retry automatically. Wait for a final result before uploading again.</p>
          : <p>You may leave this page. Analysis continues and results remain linked to this release.</p>}
        <div className="preview-summary">
          <div className="preview-stat"><span>Input</span><strong>{job.draft.inputKind.replaceAll("_", " ")}</strong></div>
          <div className="preview-stat"><span>Evidence</span><strong>{job.draft.fileName}</strong></div>
          <div className="preview-stat"><span>Job</span><strong className="mono">{job.id}</strong></div>
        </div>
      </>}
    </section>
  </main>;
}
