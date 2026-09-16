import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";

import { useDemo } from "../data/DemoProvider";
import type { DocumentDownloadMetadata, DocumentRecord, TeamMember } from "../data/types";
import {
  Breadcrumbs,
  EmptyState,
  PageHeader,
  SectionHeader,
  StatusPill,
  formatDate,
  memberName,
  titleCase,
} from "./PageKit";
import { createDownloadManifest, documentPermissions } from "./documentWorkflow";
import "./DocumentDetailPage.css";
import "./pages.css";

type DocumentTab = "overview" | "revisions" | "approval" | "filing" | "audit";
type Feedback = { tone: "success" | "error"; text: string };

const sha256Pattern = /^[0-9a-f]{64}$/i;

function downloadManifest(metadata: DocumentDownloadMetadata): void {
  const blob = new Blob([createDownloadManifest(metadata)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = globalThis.document.createElement("a");
  link.href = url;
  link.download = `${metadata.filename}.download.json`;
  link.click();
  URL.revokeObjectURL(url);
}

function readableBytes(size: number): string {
  if (size < 1_000) return `${size} B`;
  if (size < 1_000_000) return `${(size / 1_000).toFixed(1)} KB`;
  return `${(size / 1_000_000).toFixed(1)} MB`;
}

export function DocumentDetailPage() {
  const { documentId = "" } = useParams();
  const demo = useDemo();
  const document = demo.selectors.document(documentId);
  const [tab, setTab] = useState<DocumentTab>("overview");
  const [busy, setBusy] = useState<string>();
  const [feedback, setFeedback] = useState<Feedback>();
  const [download, setDownload] = useState<DocumentDownloadMetadata>();
  const [downloadVersion, setDownloadVersion] = useState<number>();
  const [approvalComment, setApprovalComment] = useState("");
  const [revision, setRevision] = useState({ format: "PDF/A-2b" as DocumentRecord["format"], contentHash: "", storageLocator: "", sizeBytes: "", completeness: "complete" as DocumentRecord["completeness"] });
  const [filing, setFiling] = useState({ externalSubmissionReference: "", submittedAt: "", receiptEvidenceLocator: "", receiptContentHash: "" });

  useEffect(() => {
    const controller = new AbortController();
    setBusy("load");
    setFeedback(undefined);
    void demo.actions.loadDocumentDetail(documentId, { signal: controller.signal })
      .catch((error) => {
        if (!controller.signal.aborted) setFeedback({ tone: "error", text: error instanceof Error ? error.message : "Unable to load document details." });
      })
      .finally(() => { if (!controller.signal.aborted) setBusy(undefined); });
    return () => controller.abort();
  }, [demo.actions, documentId]);

  useEffect(() => {
    if (!document) return;
    setDownloadVersion(document.version);
    setRevision((current) => ({ ...current, format: document.format }));
  }, [document?.id, document?.version, document?.format]);

  const permissions = useMemo(
    () => document ? documentPermissions(demo.currentUser.roles, document) : undefined,
    [demo.currentUser.roles, document],
  );

  if (!document && busy === "load") {
    return <main className="page" aria-busy="true"><div className="panel empty-state"><h3>Loading document</h3><p>Retrieving the current revision and audit record.</p></div></main>;
  }

  if (!document) {
    return (
      <EmptyState
        title="Document not found"
        body={feedback?.text ?? "This revision may be unavailable or outside your organization."}
        action={<Link className="button" to="/compliance">Back to compliance</Link>}
      />
    );
  }

  const product = demo.selectors.product(document.productId);
  const release = demo.selectors.release(document.releaseId);
  const revisions = document.revisions?.length ? document.revisions : [{
    version: document.version, format: document.format,
    status: document.status === "self_filed" ? "approved" as const : document.status,
    completeness: document.completeness,
    contentHash: document.contentHash ?? "Metadata unavailable",
    storageLocator: document.storageLocator ?? "Metadata unavailable",
    sizeBytes: document.sizeBytes ?? 0,
    createdBy: document.updatedBy, createdAt: document.updatedAt,
  }];
  const selectedRevision = revisions.find((item) => item.version === downloadVersion) ?? revisions[0];

  const perform = async (key: string, task: () => Promise<unknown>, success: string) => {
    setBusy(key);
    setFeedback(undefined);
    try {
      await task();
      setFeedback({ tone: "success", text: success });
    } catch (error) {
      setFeedback({ tone: "error", text: error instanceof Error ? error.message : "The document workflow could not be updated." });
    } finally {
      setBusy(undefined);
    }
  };

  const prepareDownload = async () => {
    setBusy("download");
    setFeedback(undefined);
    try {
      const metadata = await demo.actions.getDocumentDownload(document.id, downloadVersion);
      setDownload(metadata);
      setFeedback({ tone: "success", text: `Download metadata verified for revision ${metadata.version}.` });
    } catch (error) {
      setFeedback({ tone: "error", text: error instanceof Error ? error.message : "Unable to prepare the download." });
    } finally {
      setBusy(undefined);
    }
  };

  const handleDownloadContent = async (metadata: DocumentDownloadMetadata) => {
    setBusy("download-content");
    setFeedback(undefined);
    try {
      const file = await demo.actions.downloadDocument(document.id, metadata.version);
      const url = URL.createObjectURL(file.blob);
      const link = globalThis.document.createElement("a");
      link.href = url;
      link.download = file.filename || metadata.filename;
      globalThis.document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setFeedback({ tone: "success", text: `Document ${file.filename || metadata.filename} downloaded successfully.` });
    } catch (error) {
      setFeedback({ tone: "error", text: error instanceof Error ? error.message : "Unable to download document content." });
    } finally {
      setBusy(undefined);
    }
  };

  const submitRevision = (event: FormEvent) => {
    event.preventDefault();
    if (!sha256Pattern.test(revision.contentHash)) {
      setFeedback({ tone: "error", text: "Content SHA-256 must contain exactly 64 hexadecimal characters." });
      return;
    }
    void perform("revision", () => Promise.resolve(demo.actions.addDocumentRevision({
      documentId: document.id,
      format: revision.format,
      contentHash: revision.contentHash.toLowerCase(),
      storageLocator: revision.storageLocator.trim(),
      sizeBytes: Number(revision.sizeBytes),
      completeness: revision.completeness,
    })), "New immutable revision registered.");
  };

  const submitFiling = (event: FormEvent) => {
    event.preventDefault();
    if (filing.receiptContentHash && !sha256Pattern.test(filing.receiptContentHash)) {
      setFeedback({ tone: "error", text: "Receipt SHA-256 must contain exactly 64 hexadecimal characters." });
      return;
    }
    void perform("filing", () => Promise.resolve(demo.actions.recordDocumentSelfFiling({
      documentId: document.id,
      externalSubmissionReference: filing.externalSubmissionReference.trim(),
      submittedAt: new Date(filing.submittedAt).toISOString(),
      receiptEvidenceLocator: filing.receiptEvidenceLocator.trim(),
      receiptContentHash: filing.receiptContentHash.trim().toLowerCase() || undefined,
    })), "External filing record added to the immutable audit trail.");
  };

  return (
    <main className="page document-workflow" aria-busy={Boolean(busy)}>
      <Breadcrumbs items={[
        { label: "Products", to: "/products" },
        { label: product?.name ?? "Product", to: `/products/${document.productId}?tab=documents` },
        { label: document.name },
      ]} />
      <PageHeader
        eyebrow={`${titleCase(document.type)} · Revision ${document.version}`}
        title={document.name}
        description={`${document.format} · Updated ${formatDate(document.updatedAt, true)} by ${memberName(demo.state.members, document.updatedBy)}`}
        actions={(
          <div className="inline-actions">
            <StatusPill value={document.status} />
            <StatusPill value={document.completeness} />
            <button type="button" className="button-primary" onClick={() => void prepareDownload()} disabled={busy === "download"}>
              {busy === "download" ? "Preparing…" : "Prepare download"}
            </button>
          </div>
        )}
      />

      {feedback ? <div className={`notice ${feedback.tone === "error" ? "document-error" : ""}`} role={feedback.tone === "error" ? "alert" : "status"}>{feedback.text}</div> : null}

      <section className="panel">
        <div className="tabs" role="tablist" aria-label="Document workflow">
          {(["overview", "revisions", "approval", "filing", "audit"] as DocumentTab[]).map((item) => (
            <button key={item} type="button" role="tab" aria-selected={tab === item} className={tab === item ? "active" : ""} onClick={() => setTab(item)}>{titleCase(item)}</button>
          ))}
        </div>
      </section>

      {tab === "overview" ? (
        <div className="split-layout">
          <section className="panel">
            <SectionHeader title="Document readiness" description="Current release evidence, controlled revision, and filing state." />
            <dl className="definition-grid">
              <div><dt>Product</dt><dd>{product?.name ?? "Unavailable"}</dd></div>
              <div><dt>Release</dt><dd>{release?.version ?? "Product scope"}</dd></div>
              <div><dt>Revision</dt><dd>v{document.version}</dd></div>
              <div><dt>Format</dt><dd>{document.format}</dd></div>
              <div><dt>Completeness</dt><dd><StatusPill value={document.completeness} /></dd></div>
              <div><dt>Approval</dt><dd><StatusPill value={document.status} /></dd></div>
            </dl>
            {document.completeness !== "complete" ? <div className="panel-pad"><div className="coverage-callout"><strong>Not ready for approval or filing</strong><br />Required evidence or coverage is incomplete. The limitation remains attached to every export.</div></div> : null}
          </section>

          <aside className="panel">
            <SectionHeader title="Controlled download" description="Verify the stored revision before retrieving content." />
            <div className="setting-section document-download-controls">
              <div className="field">
                <label htmlFor="download-revision">Revision</label>
                <select id="download-revision" className="select-field" value={downloadVersion ?? document.version} onChange={(event) => { setDownloadVersion(Number(event.target.value)); setDownload(undefined); }}>
                  {revisions.map((item) => <option key={item.version} value={item.version}>Revision {item.version} · {item.format}</option>)}
                </select>
              </div>
              <dl className="document-metadata">
                <div><dt>Size</dt><dd>{readableBytes(selectedRevision.sizeBytes)}</dd></div>
                <div><dt>SHA-256</dt><dd className="mono" title={selectedRevision.contentHash}>{selectedRevision.contentHash}</dd></div>
              </dl>
              <button type="button" onClick={() => void prepareDownload()} disabled={busy === "download"}>{busy === "download" ? "Verifying…" : "Verify download metadata"}</button>
              {download ? (
                <div className="document-download-result">
                  <strong>{download.filename}</strong>
                  <span>{download.contentType} · {readableBytes(download.sizeBytes)}</span>
                  <code title={download.storageLocator}>{download.storageLocator}</code>
                  {download.downloadType === "content_available" ? (
                    <>
                      <button
                        type="button"
                        className="button-small"
                        onClick={() => void handleDownloadContent(download)}
                        disabled={busy === "download-content"}
                      >
                        {busy === "download-content" ? "Downloading…" : "Download document"}
                      </button>
                      <button
                        type="button"
                        className="button-small"
                        onClick={() => downloadManifest(download)}
                      >
                        Export download manifest
                      </button>
                      <small>Authorized content verified against recorded digest and served from private storage.</small>
                    </>
                  ) : (
                    <>
                      <button type="button" className="button-small" onClick={() => downloadManifest(download)}>
                        Export download manifest
                      </button>
                      <small>Document bytes remain in configured evidence storage; the manifest preserves the verified locator and digest.</small>
                    </>
                  )}
                </div>
              ) : null}
            </div>
          </aside>
        </div>
      ) : null}

      {tab === "revisions" ? (
        <div className="split-layout">
          <section className="panel">
            <SectionHeader title="Revision history" description="Immutable content metadata for every registered revision." />
            <div className="data-table-wrap document-table-wrap">
              <table className="data-table document-table">
                <thead><tr><th>Revision</th><th>Status</th><th>Format</th><th>Evidence</th><th>Created</th></tr></thead>
                <tbody>{revisions.map((item) => <tr key={item.version}><td className="cell-strong">v{item.version}</td><td><StatusPill value={item.status} /></td><td>{item.format}</td><td><StatusPill value={item.completeness} /></td><td>{formatDate(item.createdAt, true)}<br /><small>{memberName(demo.state.members, item.createdBy)}</small></td></tr>)}</tbody>
              </table>
            </div>
          </section>
          <aside className="panel">
            <SectionHeader title="Register revision" description="Reference a stored, content-addressed artifact. Previous revisions remain immutable." />
            {permissions?.canRevise ? (
              <form className="setting-section" onSubmit={submitRevision}>
                <div className="field"><label htmlFor="revision-format">Format</label><select id="revision-format" className="select-field" value={revision.format} onChange={(event) => setRevision({ ...revision, format: event.target.value as DocumentRecord["format"] })}>{["PDF/A-2b", "CycloneDX JSON", "CSAF VEX", "ZIP", "JSON"].map((item) => <option key={item}>{item}</option>)}</select></div>
                <div className="field"><label htmlFor="revision-locator">Storage locator</label><input id="revision-locator" className="input-field" required value={revision.storageLocator} onChange={(event) => setRevision({ ...revision, storageLocator: event.target.value })} placeholder="s3://controlled-evidence/object" /></div>
                <div className="field"><label htmlFor="revision-hash">Content SHA-256</label><input id="revision-hash" className="input-field mono" required minLength={64} maxLength={64} value={revision.contentHash} onChange={(event) => setRevision({ ...revision, contentHash: event.target.value })} /></div>
                <div className="form-grid"><div className="field"><label htmlFor="revision-size">Size in bytes</label><input id="revision-size" className="input-field" type="number" required min="0" value={revision.sizeBytes} onChange={(event) => setRevision({ ...revision, sizeBytes: event.target.value })} /></div><div className="field"><label htmlFor="revision-completeness">Evidence state</label><select id="revision-completeness" className="select-field" value={revision.completeness} onChange={(event) => setRevision({ ...revision, completeness: event.target.value as DocumentRecord["completeness"] })}><option value="complete">Complete</option><option value="missing_inputs">Missing inputs</option><option value="limited_coverage">Limited coverage</option></select></div></div>
                <button type="submit" className="button-primary" disabled={busy === "revision"}>{busy === "revision" ? "Registering…" : "Register revision"}</button>
              </form>
            ) : <div className="panel-pad"><div className="notice">Your role can review revisions but cannot register one.</div></div>}
          </aside>
        </div>
      ) : null}

      {tab === "approval" ? (
        <div className="split-layout">
          <section className="panel">
            <SectionHeader title="Approval workflow" description="Submission and decision permissions follow organization roles." />
            <div className="setting-section">
              <div className="field"><label htmlFor="approval-comment">Decision comment</label><textarea id="approval-comment" className="textarea-field" value={approvalComment} onChange={(event) => setApprovalComment(event.target.value)} placeholder="Record the evidence reviewed or the reason for return." /></div>
              <div className="inline-actions">
                {document.status === "draft" ? <button type="button" className="button-primary" disabled={!permissions?.canRequestApproval || Boolean(busy)} onClick={() => void perform("approval-request", () => Promise.resolve(demo.actions.requestDocumentApproval(document.id, approvalComment)), "Approval requested for the current revision.")}>Request approval</button> : null}
                {document.status === "approval_required" ? <><button type="button" className="button-primary" disabled={!permissions?.canDecideApproval || Boolean(busy)} onClick={() => void perform("approve", () => Promise.resolve(demo.actions.approveDocument(document.id, approvalComment)), "Revision approved and audit history updated.")}>Approve revision</button><button type="button" className="button-danger" disabled={!permissions?.canDecideApproval || !approvalComment.trim() || Boolean(busy)} onClick={() => void perform("reject", () => Promise.resolve(demo.actions.rejectDocument(document.id, approvalComment)), "Revision returned for correction.")}>Reject revision</button></> : null}
              </div>
              {document.completeness !== "complete" ? <div className="coverage-callout">Approval is blocked until completeness is explicitly confirmed.</div> : null}
              {!permissions?.canDecideApproval && document.status === "approval_required" ? <div className="notice">Only an Authorized Approver can decide this request.</div> : null}
            </div>
          </section>
          <aside className="panel">
            <SectionHeader title="Approval history" description="Every request and decision is retained." />
            <Timeline entries={document.approvalHistory ?? document.audit.filter((entry) => ["approval_requested", "approved", "rejected"].includes(entry.action))} members={demo.state.members} empty="No approval events recorded." />
          </aside>
        </div>
      ) : null}

      {tab === "filing" ? (
        <div className="split-layout">
          <section className="panel">
            <SectionHeader title="Record external filing" description="Actis records a filing performed by your organization; it does not submit to an authority." />
            {permissions?.canRecordSelfFiling ? (
              <form className="setting-section" onSubmit={submitFiling}>
                <div className="field"><label htmlFor="filing-reference">Authority submission reference</label><input id="filing-reference" className="input-field" required value={filing.externalSubmissionReference} onChange={(event) => setFiling({ ...filing, externalSubmissionReference: event.target.value })} /></div>
                <div className="field"><label htmlFor="filing-submitted">Submitted at</label><input id="filing-submitted" className="input-field" type="datetime-local" required value={filing.submittedAt} onChange={(event) => setFiling({ ...filing, submittedAt: event.target.value })} /></div>
                <div className="field"><label htmlFor="filing-receipt">Receipt evidence locator</label><input id="filing-receipt" className="input-field" required value={filing.receiptEvidenceLocator} onChange={(event) => setFiling({ ...filing, receiptEvidenceLocator: event.target.value })} placeholder="s3://controlled-evidence/authority-receipt" /></div>
                <div className="field"><label htmlFor="filing-hash">Receipt SHA-256 (optional)</label><input id="filing-hash" className="input-field mono" minLength={64} maxLength={64} value={filing.receiptContentHash} onChange={(event) => setFiling({ ...filing, receiptContentHash: event.target.value })} /></div>
                <button type="submit" className="button-primary" disabled={busy === "filing"}>{busy === "filing" ? "Recording…" : "Record external filing"}</button>
              </form>
            ) : <div className="panel-pad"><div className="notice">{document.status !== "approved" ? "Approve the complete revision before recording an external filing." : "Your role can review this record but cannot add a filing."}</div></div>}
          </section>
          <aside className="panel">
            <SectionHeader title="Filing records" description="Operator-recorded authority receipts and references." />
            {document.selfFilings?.length ? <ul className="document-filing-list">{document.selfFilings.map((item) => <li key={item.id}><strong>{item.externalSubmissionReference}</strong><span>Revision {item.version} · submitted {formatDate(item.submittedAt, true)}</span><code title={item.receiptEvidenceLocator}>{item.receiptEvidenceLocator}</code><small>Recorded by {memberName(demo.state.members, item.recordedBy)} on {formatDate(item.recordedAt, true)}</small></li>)}</ul> : <div className="panel-pad muted">No external filing recorded.</div>}
          </aside>
        </div>
      ) : null}

      {tab === "audit" ? <section className="panel"><SectionHeader title="Audit history" description="Append-only activity across generation, revisions, approvals, exports, and filing records." /><Timeline entries={document.audit} members={demo.state.members} empty="No document events recorded." /></section> : null}
    </main>
  );
}

function Timeline({ entries, members, empty }: { entries: DocumentRecord["audit"]; members: TeamMember[]; empty: string }) {
  if (!entries.length) return <div className="panel-pad muted">{empty}</div>;
  return <ul className="timeline">{entries.map((entry) => <li key={entry.id}><strong>{titleCase(entry.action)}</strong><span>{memberName(members, entry.actorId)} · {formatDate(entry.at, true)}</span><p>{entry.detail}</p></li>)}</ul>;
}
