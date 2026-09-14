import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { useDemo } from "../data/DemoProvider";
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
import "./pages.css";

export function DocumentDetailPage() {
  const { documentId = "" } = useParams();
  const demo = useDemo();
  const document = demo.selectors.document(documentId);
  const [comment, setComment] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  if (!document) {
    return (
      <EmptyState
        title="Document not found"
        body="This revision may be unavailable or outside your organization."
        action={<Link className="button" to="/compliance">Back to compliance</Link>}
      />
    );
  }

  const product = demo.selectors.product(document.productId);
  const release = demo.selectors.release(document.releaseId);
  const canApprove = document.status === "approval_required" || document.status === "draft";

  const decide = async (event: FormEvent, approve: boolean) => {
    event.preventDefault();
    if (!approve && !comment.trim()) return;
    setBusy(true);
    setMessage("");
    try {
      if (approve) {
        await demo.actions.approveDocument(document.id, comment);
        setMessage("Document approved. The immutable audit record has been updated.");
      } else {
        await demo.actions.rejectDocument(document.id, comment);
        setMessage("Document rejected and returned for revision.");
      }
      setComment("");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to save the approval decision.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="page">
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
            <button onClick={() => setMessage(`Demo export prepared for ${document.name}.`)}>Export</button>
          </div>
        )}
      />
      {message ? <div className="notice" role="status">{message}</div> : null}

      <div className="split-layout">
        <div className="page">
          <section className="panel">
            <SectionHeader title="Document readiness" description="Generated from the current product, release, finding, and evidence state." />
            <dl className="definition-grid">
              <div><dt>Product</dt><dd>{product?.name}</dd></div>
              <div><dt>Release</dt><dd>{release?.version ?? "Product scope"}</dd></div>
              <div><dt>Revision</dt><dd>v{document.version}</dd></div>
              <div><dt>Format</dt><dd>{document.format}</dd></div>
              <div><dt>Completeness</dt><dd><StatusPill value={document.completeness} /></dd></div>
              <div><dt>Approval</dt><dd><StatusPill value={document.status} /></dd></div>
            </dl>
            {document.completeness !== "complete" ? (
              <div className="panel-pad">
                <div className="coverage-callout">
                  <strong>Not ready to file</strong><br />
                  Missing inputs or limited analysis coverage must remain visible to the approver.
                </div>
              </div>
            ) : null}
          </section>

          <section className="panel">
            <SectionHeader title="Approval" description="Only an Authorized Approver can approve regulated outputs." />
            {canApprove ? (
              <form className="setting-section">
                <div className="field">
                  <label htmlFor="comment">Approval comment</label>
                  <textarea
                    id="comment"
                    className="textarea-field"
                    value={comment}
                    onChange={(event) => setComment(event.target.value)}
                    placeholder="Optional for approval; required when rejecting."
                  />
                </div>
                <div className="inline-actions">
                  <button type="button" className="button-primary" onClick={(event) => { void decide(event, true) }} disabled={busy || document.completeness !== "complete"}>Approve revision</button>
                  <button type="button" className="button-danger" onClick={(event) => { void decide(event, false) }} disabled={busy || !comment.trim()}>Reject</button>
                </div>
              </form>
            ) : (
              <div className="panel-pad">
                <div className="notice">This revision is {titleCase(document.status).toLowerCase()}. Generate a new draft to make further changes.</div>
              </div>
            )}
          </section>
        </div>

        <aside className="panel">
          <SectionHeader title="Audit history" description="Append-only record for this document." />
          <ul className="timeline">
            {document.audit.map((entry) => (
              <li key={entry.id}>
                <strong>{titleCase(entry.action)}</strong>
                <span>{memberName(demo.state.members, entry.actorId)} · {formatDate(entry.at, true)}</span>
                <p>{entry.detail}</p>
              </li>
            ))}
          </ul>
        </aside>
      </div>
    </main>
  );
}
