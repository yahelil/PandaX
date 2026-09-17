import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ClipboardCheck,
  Download,
  ExternalLink,
  FileCheck,
  FileText,
  HelpCircle,
  Lock,
  Scale,
  ShieldAlert,
  ShieldCheck,
  Upload,
  X,
} from "lucide-react";
import { useDemo } from "../data/DemoProvider";
import type { CraClass, CraClassificationAssessment, Product } from "../data/types";
import { CraAssessmentWizard } from "../pages/CraAssessmentWizard";
import { CRA_RULESET_VERSION, craClassLabel } from "../pages/craAssessment";
import { ExactTimerBadge } from "./ExactTimerBadge";
import { getProductMostUrgentTimer } from "../pages/exactTimers";
import { formatDate, memberName } from "../pages/PageKit";

interface ProductScopeModalProps {
  product: Product;
  onClose: () => void;
}

type ScopeResult = "in_scope" | "out_of_scope" | "needs_review";

export function getConformityProcedure(craClass: CraClass): {
  module: string;
  title: string;
  description: string;
  notifiedBodyRequired: boolean;
} {
  switch (craClass) {
    case "critical":
      return {
        module: "Module B + C or European Cybersecurity Certificate",
        title: "Mandatory Notified Body Certification",
        description:
          "Critical products (Annex IV) require conformity assessment by an accredited Notified Body (Module B: EU-type examination + Module C: conformity to type) or a European cybersecurity certificate at assurance level 'substantial' or 'high'.",
        notifiedBodyRequired: true,
      };
    case "important_ii":
      return {
        module: "Module H or Module B + C",
        title: "Mandatory Third-Party Conformity Assessment",
        description:
          "Class II products (Annex III) require third-party assessment via a Notified Body: either Full Quality Assurance (Module H) or EU-type examination (Module B) followed by conformity to type (Module C).",
        notifiedBodyRequired: true,
      };
    case "important_i":
      return {
        module: "Module A (or Module B + C)",
        title: "Harmonised Standards / Third-Party Assessment",
        description:
          "Class I products (Annex III) can follow internal production control (Module A) provided harmonised standards or common specifications are fully applied. If not applied, third-party assessment (Module B + C) is mandatory.",
        notifiedBodyRequired: false,
      };
    case "default":
    default:
      return {
        module: "Module A (Internal Production Control)",
        title: "Standard Manufacturer Self-Assessment",
        description:
          "Standard products follow internal production control (Module A). The manufacturer self-assesses against Annex I essential cybersecurity requirements and issues the EU Declaration of Conformity.",
        notifiedBodyRequired: false,
      };
  }
}

export function ProductScopeModal({ product, onClose }: ProductScopeModalProps) {
  const demo = useDemo();
  const initialScope: ScopeResult = product.classificationAssessment?.scopeResult ?? "needs_review";
  const [isEditing, setIsEditing] = useState(initialScope === "needs_review");
  const [wizardOpen, setWizardOpen] = useState(false);

  const [scopeResult, setScopeResult] = useState<ScopeResult>(initialScope);
  const [craClass, setCraClass] = useState<CraClass>(product.craClass);
  const [classificationStatus, setClassificationStatus] = useState<Product["classificationStatus"]>(
    product.classificationStatus
  );
  const [rationale, setRationale] = useState(product.classificationAssessment?.rationale ?? "");
  const [ownerId, setOwnerId] = useState(product.ownerId ?? "");
  const [assessment, setAssessment] = useState<CraClassificationAssessment | undefined>(
    product.classificationAssessment
  );
  const [evidenceFile, setEvidenceFile] = useState<File | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string>();
  const [successMessage, setSuccessMessage] = useState<string>();
  const [isDragOver, setIsDragOver] = useState(false);

  const modalRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const openFindings = demo.findings.filter((f) => f.productId === product.id && f.status !== "resolved");
  const activeRelease = demo.selectors.release(product.activeReleaseId);
  const mostUrgentTimer = getProductMostUrgentTimer(product, demo.findings, demo.complianceItems);
  const conformity = getConformityProcedure(craClass);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !wizardOpen) {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose, wizardOpen]);

  const handleWizardComplete = (completedAssessment: CraClassificationAssessment) => {
    setAssessment(completedAssessment);
    setScopeResult(completedAssessment.scopeResult);
    setCraClass(completedAssessment.recommendedClass);
    setClassificationStatus(completedAssessment.classificationStatus);
    setRationale(completedAssessment.rationale);
    setWizardOpen(false);
    setIsEditing(true);
  };

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setEvidenceFile(e.dataTransfer.files[0]);
    }
  };

  const handleSubmit = async (e?: FormEvent) => {
    if (e) e.preventDefault();
    setPending(true);
    setError(undefined);

    try {
      const nowIso = new Date().toISOString();
      const finalAssessment: CraClassificationAssessment = assessment
        ? {
            ...assessment,
            scopeResult,
            recommendedClass: craClass,
            classificationStatus,
            rationale: rationale.trim() || assessment.rationale,
            confirmedAt: classificationStatus === "confirmed" ? nowIso : undefined,
          }
        : {
            rulesetVersion: CRA_RULESET_VERSION,
            completedAt: nowIso,
            confirmedAt: classificationStatus === "confirmed" ? nowIso : undefined,
            scopeResult,
            recommendedClass: craClass,
            classificationStatus,
            categoryLabel: craClass !== "default" ? craClassLabel(craClass) : "Standard product route",
            rationale:
              rationale.trim() ||
              `Scope evaluated as ${scopeResult.replaceAll("_", " ")} and categorized under ${craClassLabel(craClass)}.`,
            readinessScore: 100,
            answers: [
              {
                questionId: "scope-determination",
                question: "CRA product scope determination",
                answer: scopeResult,
                source: "CRA Art. 2",
              },
            ],
            actions: [],
          };

      await demo.actions.updateProduct({
        productId: product.id,
        craClass,
        classificationStatus,
        classificationAssessment: finalAssessment,
        ownerId: ownerId || undefined,
      });

      setSuccessMessage("Product determination updated successfully.");
      setIsEditing(false);
      setTimeout(() => setSuccessMessage(undefined), 3000);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Failed to update product CRA classification.");
    } finally {
      setPending(false);
    }
  };

  return (
    <div
      className="compliance-modal-overlay"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !wizardOpen) onClose();
      }}
    >
      <div
        ref={modalRef}
        className="compliance-modal-window"
        style={{ maxWidth: 780 }}
        role="dialog"
        aria-modal="true"
        aria-labelledby="product-scope-modal-title"
      >
        {/* Modal Header */}
        <div className="compliance-modal-header">
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
              <span className="eyebrow" style={{ margin: 0 }}>
                {initialScope === "in_scope"
                  ? "CRA Regulatory Profile & Conformity Dossier"
                  : initialScope === "out_of_scope"
                  ? "CRA Exemption Record & Justification"
                  : "CRA Scope & Classification Assessment"}
              </span>
              <span className={`devices-scope devices-scope--${scopeResult}`}>
                <span />
                {scopeResult === "in_scope"
                  ? "In scope"
                  : scopeResult === "out_of_scope"
                  ? "Out of scope"
                  : "Needs review"}
              </span>
            </div>
            <h2 id="product-scope-modal-title" style={{ margin: "2px 0" }}>
              {product.name}
            </h2>
            <p className="muted" style={{ margin: 0, fontSize: 13 }}>
              {product.identifier} · {product.manufacturer}
            </p>
          </div>
          <button
            type="button"
            className="icon-button"
            onClick={onClose}
            aria-label="Close review window"
          >
            <X size={20} />
          </button>
        </div>

        {/* Wizard View */}
        {wizardOpen ? (
          <div style={{ marginTop: 8 }}>
            <CraAssessmentWizard
              initialAssessment={assessment}
              onCancel={() => setWizardOpen(false)}
              onComplete={handleWizardComplete}
            />
          </div>
        ) : isEditing ? (
          /* ========================================================================= */
          /* ACTIVE ASSESSMENT / EDIT MODE (Always default for "Needs review")          */
          /* ========================================================================= */
          <form onSubmit={handleSubmit} style={{ display: "grid", gap: 16 }}>
            {initialScope === "needs_review" ? (
              <div
                className="action-modal-callout"
                style={{
                  borderLeftColor: "var(--warning)",
                  background: "var(--warning-bg, rgba(234, 154, 41, 0.1))",
                }}
              >
                <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
                  <AlertTriangle size={20} color="var(--warning)" style={{ flexShrink: 0, marginTop: 2 }} />
                  <div>
                    <strong style={{ display: "block", fontSize: 14 }}>
                      CRA Scope Evaluation Required
                    </strong>
                    <p style={{ margin: "2px 0 8px", fontSize: 12.5, color: "var(--text-muted)" }}>
                      This product is currently flagged as <strong>Needs review</strong>. Complete the scope determination and Annex category below to establish its official CRA compliance obligations and legal documents.
                    </p>
                    <button
                      type="button"
                      className="button button-small"
                      onClick={() => setWizardOpen(true)}
                      style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
                    >
                      <ClipboardCheck size={15} />
                      Launch Guided Annex Wizard
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="action-modal-callout" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
                <div>
                  <strong style={{ display: "block", fontSize: 13.5 }}>Editing CRA Determination</strong>
                  <span className="muted" style={{ fontSize: 12 }}>
                    Adjusting scope determination, CRA class, or owner assignment.
                  </span>
                </div>
                <button
                  type="button"
                  className="button button-small"
                  onClick={() => setWizardOpen(true)}
                  style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
                >
                  <ClipboardCheck size={15} />
                  Launch Guided Wizard
                </button>
              </div>
            )}

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
              <div>
                <label style={{ display: "block", fontSize: 12, fontWeight: 600, marginBottom: 4 }}>
                  Scope Determination
                </label>
                <select
                  className="select-field"
                  style={{ width: "100%" }}
                  value={scopeResult}
                  onChange={(e) => setScopeResult(e.target.value as ScopeResult)}
                >
                  <option value="needs_review">● Needs review (Scope evaluation pending)</option>
                  <option value="in_scope">● In scope (Connected EU market product)</option>
                  <option value="out_of_scope">● Out of scope (Exempted / Non-connected)</option>
                </select>
              </div>

              <div>
                <label style={{ display: "block", fontSize: 12, fontWeight: 600, marginBottom: 4 }}>
                  CRA Classification Class
                </label>
                <select
                  className="select-field"
                  style={{ width: "100%" }}
                  value={craClass}
                  onChange={(e) => setCraClass(e.target.value as CraClass)}
                >
                  <option value="default">Default (Standard conformity route · Module A)</option>
                  <option value="important_i">Important I (Annex III Class I)</option>
                  <option value="important_ii">Important II (Annex III Class II · Notified Body)</option>
                  <option value="critical">Critical (Annex IV · Mandatory certification)</option>
                </select>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
              <div>
                <label style={{ display: "block", fontSize: 12, fontWeight: 600, marginBottom: 4 }}>
                  Classification Status
                </label>
                <select
                  className="select-field"
                  style={{ width: "100%" }}
                  value={classificationStatus}
                  onChange={(e) => setClassificationStatus(e.target.value as Product["classificationStatus"])}
                >
                  <option value="confirmed">Confirmed (Verified & documented)</option>
                  <option value="review_required">Review required (Preliminary determination)</option>
                </select>
              </div>

              <div>
                <label style={{ display: "block", fontSize: 12, fontWeight: 600, marginBottom: 4 }}>
                  Assigned Owner
                </label>
                <select
                  className="select-field"
                  style={{ width: "100%" }}
                  value={ownerId}
                  onChange={(e) => setOwnerId(e.target.value)}
                >
                  <option value="">Unassigned</option>
                  {demo.state.members
                    .filter((member) => member.status === "active")
                    .map((member) => (
                      <option key={member.id} value={member.id}>
                        {member.name}
                      </option>
                    ))}
                </select>
              </div>
            </div>

            <div>
              <label style={{ display: "block", fontSize: 12, fontWeight: 600, marginBottom: 4 }}>
                Scope Justification & Review Notes ("Write what's needed")
              </label>
              <textarea
                className="textarea-field"
                rows={3}
                style={{ width: "100%", fontSize: 13 }}
                placeholder="Document justification for scope determination, architectural boundaries, and classification rationale..."
                value={rationale}
                onChange={(e) => setRationale(e.target.value)}
              />
              <span className="field-hint" style={{ fontSize: 11 }}>
                Provide the reasons for this determination. Retained in the official CRA technical documentation dossier.
              </span>
            </div>

            <div>
              <label style={{ display: "block", fontSize: 12, fontWeight: 600, marginBottom: 4 }}>
                Upload Scope Evidence or Assessment File ("Upload what's needed")
              </label>
              <div
                className="compliance-upload-dropzone"
                onDragOver={(e) => {
                  e.preventDefault();
                  setIsDragOver(true);
                }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={handleFileDrop}
                onClick={() => fileInputRef.current?.click()}
                style={{
                  borderStyle: isDragOver ? "solid" : "dashed",
                  borderColor: isDragOver ? "var(--accent)" : "var(--border)",
                  padding: "16px",
                }}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".json,.pdf,.zip,.txt,.docx"
                  style={{ display: "none" }}
                  onChange={(e) => {
                    if (e.target.files?.[0]) setEvidenceFile(e.target.files[0]);
                  }}
                />
                {evidenceFile ? (
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10 }}>
                    <FileCheck size={20} color="var(--success)" />
                    <div style={{ textAlign: "left" }}>
                      <strong>{evidenceFile.name}</strong>
                      <div className="muted" style={{ fontSize: 11 }}>
                        {(evidenceFile.size / 1024).toFixed(1)} KB · Ready to attach
                      </div>
                    </div>
                    <button
                      type="button"
                      className="icon-button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setEvidenceFile(null);
                      }}
                      title="Remove file"
                    >
                      <X size={16} />
                    </button>
                  </div>
                ) : (
                  <div>
                    <Upload size={22} style={{ color: "var(--accent)", marginBottom: 4 }} />
                    <p style={{ margin: 0, fontSize: 13, fontWeight: 600 }}>
                      Drop legal memo, SBOM, or assessment file here, or click to browse
                    </p>
                    <p className="muted" style={{ margin: "2px 0 0", fontSize: 11 }}>
                      Supports JSON SBOM, PDF legal opinion, Word, ZIP evidence package
                    </p>
                  </div>
                )}
              </div>
            </div>

            {error ? (
              <p className="danger-text" role="alert" style={{ margin: 0, fontSize: 13 }}>
                {error}
              </p>
            ) : null}

            <div className="inline-actions" style={{ justifyContent: "flex-end", marginTop: 8 }}>
              {initialScope !== "needs_review" ? (
                <button type="button" onClick={() => setIsEditing(false)} disabled={pending}>
                  Back to Profile
                </button>
              ) : null}
              <button type="button" onClick={onClose} disabled={pending}>
                Cancel
              </button>
              <button type="submit" className="button button-primary" disabled={pending}>
                {pending ? "Saving..." : "Confirm & Save Determination"}
              </button>
            </div>
          </form>
        ) : initialScope === "in_scope" ? (
          /* ========================================================================= */
          /* DEDICATED IN-SCOPE WINDOW: REGULATORY PROFILE & CONFORMITY DOSSIER        */
          /* ========================================================================= */
          <div style={{ display: "grid", gap: 16 }}>
            {/* Conformity Assessment Procedure Card */}
            <div
              style={{
                padding: "16px 18px",
                borderRadius: 10,
                border: "1px solid var(--border)",
                background: "var(--surface-subtle)",
              }}
            >
              <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12 }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                    <span className={`devices-class devices-class--${craClass}`}>
                      {craClassLabel(craClass)}
                    </span>
                    <strong style={{ fontSize: 15 }}>{conformity.title}</strong>
                  </div>
                  <p style={{ margin: "4px 0 0", fontSize: 13, color: "var(--text-muted)", lineHeight: 1.45 }}>
                    {conformity.description}
                  </p>
                </div>
                <div style={{ textAlign: "right", flexShrink: 0 }}>
                  <span
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 5,
                      padding: "4px 8px",
                      borderRadius: 6,
                      fontSize: 11.5,
                      fontWeight: 700,
                      background: conformity.notifiedBodyRequired ? "var(--warning-bg, #fff3e0)" : "var(--success-bg, #e8f5e9)",
                      color: conformity.notifiedBodyRequired ? "var(--warning)" : "var(--success)",
                    }}
                  >
                    {conformity.notifiedBodyRequired ? <ShieldAlert size={14} /> : <CheckCircle2 size={14} />}
                    {conformity.notifiedBodyRequired ? "Notified Body Required" : "Self-Assessment (Module A)"}
                  </span>
                  <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>
                    {conformity.module}
                  </div>
                </div>
              </div>
            </div>

            {/* Live Operational Metrics Card */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(3, 1fr)",
                gap: 12,
              }}
            >
              <div
                style={{
                  padding: "12px 14px",
                  borderRadius: 9,
                  border: "1px solid var(--border)",
                  background: "var(--surface)",
                }}
              >
                <span className="muted" style={{ fontSize: 11.5, display: "block" }}>
                  Active Vulnerabilities
                </span>
                <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginTop: 4 }}>
                  <strong style={{ fontSize: 20, color: openFindings.length ? "var(--danger)" : "var(--text)" }}>
                    {openFindings.length} open
                  </strong>
                  <Link
                    to={`/findings?product=${encodeURIComponent(product.id)}`}
                    style={{ fontSize: 12, color: "var(--accent)", textDecoration: "none", fontWeight: 600 }}
                  >
                    Review findings →
                  </Link>
                </div>
              </div>

              <div
                style={{
                  padding: "12px 14px",
                  borderRadius: 9,
                  border: "1px solid var(--border)",
                  background: "var(--surface)",
                }}
              >
                <span className="muted" style={{ fontSize: 11.5, display: "block" }}>
                  Active Baseline Release
                </span>
                <div style={{ marginTop: 4 }}>
                  <strong style={{ fontSize: 14 }}>
                    {activeRelease ? `v${activeRelease.version}` : "No release active"}
                  </strong>
                  <div className="muted" style={{ fontSize: 11 }}>
                    {activeRelease ? `${activeRelease.channel.toUpperCase()} · ${activeRelease.sbomStatus.toUpperCase()} SBOM` : "Pending release"}
                  </div>
                </div>
              </div>

              <div
                style={{
                  padding: "12px 14px",
                  borderRadius: 9,
                  border: "1px solid var(--border)",
                  background: "var(--surface)",
                }}
              >
                <span className="muted" style={{ fontSize: 11.5, display: "block" }}>
                  Most Urgent Obligation
                </span>
                <div style={{ marginTop: 4 }}>
                  {mostUrgentTimer ? (
                    <ExactTimerBadge timer={mostUrgentTimer} compact />
                  ) : (
                    <strong style={{ fontSize: 13, color: "var(--success)" }}>All obligations met</strong>
                  )}
                </div>
              </div>
            </div>

            {/* Retained Assessment Determination Rationale */}
            <div
              style={{
                padding: "14px 16px",
                borderRadius: 9,
                border: "1px solid var(--border)",
                background: "var(--surface)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                <span className="eyebrow" style={{ margin: 0, fontSize: 11 }}>
                  Scope Evaluation Rationale
                </span>
                <span className="muted" style={{ fontSize: 11 }}>
                  {assessment?.completedAt ? `Recorded ${formatDate(assessment.completedAt, true)}` : "Verified Determination"}
                </span>
              </div>
              <p style={{ margin: 0, fontSize: 13, lineHeight: 1.45, color: "var(--text)" }}>
                {rationale || assessment?.rationale || `Evaluated as an in-scope connected product placed on the EU single market, classified under CRA ${craClassLabel(craClass)}.`}
              </p>
              {assessment?.categoryLabel ? (
                <div className="notice" style={{ marginTop: 10, fontSize: 12 }}>
                  <strong>Matched core functionality:</strong> {assessment.categoryLabel}
                </div>
              ) : null}
            </div>

            {/* Supporting Evidence Attachment */}
            <div>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                <label style={{ fontSize: 12, fontWeight: 600 }}>
                  Attach Supporting Documents / Audit Records ("Upload what's needed")
                </label>
                {evidenceFile ? (
                  <span className="muted" style={{ fontSize: 11 }}>
                    1 file ready to save
                  </span>
                ) : null}
              </div>
              <div
                className="compliance-upload-dropzone"
                onDragOver={(e) => {
                  e.preventDefault();
                  setIsDragOver(true);
                }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={handleFileDrop}
                onClick={() => fileInputRef.current?.click()}
                style={{
                  borderStyle: isDragOver ? "solid" : "dashed",
                  borderColor: isDragOver ? "var(--accent)" : "var(--border)",
                  padding: "14px",
                }}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".json,.pdf,.zip,.txt,.docx"
                  style={{ display: "none" }}
                  onChange={(e) => {
                    if (e.target.files?.[0]) setEvidenceFile(e.target.files[0]);
                  }}
                />
                {evidenceFile ? (
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10 }}>
                    <FileCheck size={18} color="var(--success)" />
                    <div style={{ textAlign: "left" }}>
                      <strong>{evidenceFile.name}</strong>
                      <div className="muted" style={{ fontSize: 11 }}>
                        {(evidenceFile.size / 1024).toFixed(1)} KB · Will be attached to product file
                      </div>
                    </div>
                    <button
                      type="button"
                      className="icon-button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setEvidenceFile(null);
                      }}
                      title="Remove file"
                    >
                      <X size={16} />
                    </button>
                  </div>
                ) : (
                  <div>
                    <Upload size={20} style={{ color: "var(--accent)", marginBottom: 2 }} />
                    <p style={{ margin: 0, fontSize: 12.5, fontWeight: 600 }}>
                      Attach additional evidence: legal opinion, notified body certificate, or SBOM
                    </p>
                  </div>
                )}
              </div>
            </div>

            {successMessage ? (
              <p className="success-text" role="status" style={{ margin: 0, fontSize: 13 }}>
                ✓ {successMessage}
              </p>
            ) : null}

            {/* Modal Actions */}
            <div className="compliance-modal-footer" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingTop: 8, borderTop: "1px solid var(--border)" }}>
              <Link
                to={`/compliance?product=${encodeURIComponent(product.id)}&view=documents`}
                className="button button-secondary"
                style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 12.5 }}
              >
                <FileText size={15} />
                View Legal & Technical Documents
              </Link>
              <div className="inline-actions">
                <button
                  type="button"
                  onClick={() => setIsEditing(true)}
                  style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
                >
                  <Scale size={15} />
                  Edit Scope / Re-classify
                </button>
                {evidenceFile ? (
                  <button
                    type="button"
                    className="button button-primary"
                    disabled={pending}
                    onClick={() => void handleSubmit()}
                  >
                    {pending ? "Saving..." : "Save Attached Evidence"}
                  </button>
                ) : (
                  <button type="button" className="button button-primary" onClick={onClose}>
                    Done
                  </button>
                )}
              </div>
            </div>
          </div>
        ) : (
          /* ========================================================================= */
          /* DEDICATED OUT-OF-SCOPE WINDOW: EXEMPTION RECORD & GROUNDS                  */
          /* ========================================================================= */
          <div style={{ display: "grid", gap: 16 }}>
            <div
              className="action-modal-callout"
              style={{
                borderLeftColor: "var(--text-subtle)",
                background: "var(--surface-subtle)",
              }}
            >
              <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
                <ShieldCheck size={20} color="var(--text-subtle)" style={{ flexShrink: 0, marginTop: 2 }} />
                <div>
                  <strong style={{ display: "block", fontSize: 14 }}>
                    Official CRA Exemption Determination
                  </strong>
                  <p style={{ margin: "3px 0 0", fontSize: 12.5, color: "var(--text-muted)", lineHeight: 1.45 }}>
                    This product has been formally determined to be <strong>Out of scope</strong> of EU Regulation 2024/2847 (Cyber Resilience Act). It does not incur mandatory CRA CE-marking or Article 14 notification obligations.
                  </p>
                </div>
              </div>
            </div>

            <div
              style={{
                padding: "14px 16px",
                borderRadius: 9,
                border: "1px solid var(--border)",
                background: "var(--surface)",
              }}
            >
              <span className="eyebrow" style={{ margin: "0 0 6px", fontSize: 11 }}>
                Recorded Exemption Grounds & Rationale
              </span>
              <p style={{ margin: 0, fontSize: 13, lineHeight: 1.45, color: "var(--text)" }}>
                {rationale || assessment?.rationale || "Evaluated as outside the CRA regime (e.g. non-connected standalone device, non-commercial open-source, or governed by separate EU sectoral regulation)."}
              </p>
            </div>

            <div>
              <label style={{ display: "block", fontSize: 12, fontWeight: 600, marginBottom: 4 }}>
                Attach Legal Exemption Memo or Sectoral Clearance
              </label>
              <div
                className="compliance-upload-dropzone"
                onDragOver={(e) => {
                  e.preventDefault();
                  setIsDragOver(true);
                }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={handleFileDrop}
                onClick={() => fileInputRef.current?.click()}
                style={{
                  borderStyle: isDragOver ? "solid" : "dashed",
                  borderColor: isDragOver ? "var(--accent)" : "var(--border)",
                  padding: "14px",
                }}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".json,.pdf,.zip,.txt,.docx"
                  style={{ display: "none" }}
                  onChange={(e) => {
                    if (e.target.files?.[0]) setEvidenceFile(e.target.files[0]);
                  }}
                />
                {evidenceFile ? (
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10 }}>
                    <FileCheck size={18} color="var(--success)" />
                    <div style={{ textAlign: "left" }}>
                      <strong>{evidenceFile.name}</strong>
                      <div className="muted" style={{ fontSize: 11 }}>
                        {(evidenceFile.size / 1024).toFixed(1)} KB · Ready to save
                      </div>
                    </div>
                  </div>
                ) : (
                  <div>
                    <Upload size={20} style={{ color: "var(--accent)", marginBottom: 2 }} />
                    <p style={{ margin: 0, fontSize: 12.5, fontWeight: 600 }}>
                      Drop exemption memo or legal opinion here
                    </p>
                  </div>
                )}
              </div>
            </div>

            <div className="compliance-modal-footer" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingTop: 8, borderTop: "1px solid var(--border)" }}>
              <button
                type="button"
                onClick={() => {
                  setIsEditing(true);
                  setScopeResult("in_scope");
                }}
                style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
              >
                <Scale size={15} />
                Re-evaluate Scope (Move to In Scope)
              </button>
              <div className="inline-actions">
                {evidenceFile ? (
                  <button
                    type="button"
                    className="button button-primary"
                    disabled={pending}
                    onClick={() => void handleSubmit()}
                  >
                    {pending ? "Saving..." : "Save Exemption Memo"}
                  </button>
                ) : (
                  <button type="button" className="button button-primary" onClick={onClose}>
                    Done
                  </button>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
