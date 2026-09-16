import { AlertTriangle, ArrowLeft, CheckCircle2, ExternalLink, ShieldCheck, X } from "lucide-react";
import { forwardRef, useEffect, useMemo, useRef, useState } from "react";
import type { CraClassificationAssessment } from "../data/types";
import {
  CLASSIFICATION_GROUPS,
  CRA_CATEGORY_SOURCE_URL,
  CRA_SOURCE_URL,
  assessmentCompletionAction,
  buildCraAssessment,
  craClassLabel,
} from "./craAssessment";

type Phase = "scope" | "classification" | "result";

interface Props {
  onCancel: () => void;
  onComplete: (assessment: CraClassificationAssessment) => void;
  initialAssessment?: CraClassificationAssessment;
}

const PHASES: Phase[] = ["scope", "classification", "result"];

export function CraAssessmentWizard({ onCancel, onComplete, initialAssessment }: Props) {
  const [phase, setPhase] = useState<Phase>(initialAssessment ? "result" : "scope");
  const [classificationIndex, setClassificationIndex] = useState(0);
  const [categorySelections, setCategorySelections] = useState<Record<string, string>>(() => Object.fromEntries(
    initialAssessment?.answers.filter((answer) => answer.questionId.startsWith("category-")).map((answer) => [answer.questionId.slice("category-".length), answer.answer]) ?? [],
  ));
  const [completedAt, setCompletedAt] = useState(initialAssessment?.completedAt);
  const [confirmed, setConfirmed] = useState(Boolean(initialAssessment?.confirmedAt));
  const [scopeInfoOpen, setScopeInfoOpen] = useState(false);
  const containerRef = useRef<HTMLElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    containerRef.current?.scrollIntoView({ block: "start" });
    headingRef.current?.focus({ preventScroll: true });
  }, [phase, classificationIndex]);

  useEffect(() => {
    if (scopeInfoOpen) dialogRef.current?.focus();
  }, [scopeInfoOpen]);

  const assessment = useMemo(() => buildCraAssessment({
    scopeAnswers: {}, scopeReviewed: true, categorySelections, completedAt, confirmed,
  }), [categorySelections, completedAt, confirmed]);
  const completionAction = assessmentCompletionAction(assessment);

  const continueClassification = () => {
    const group = CLASSIFICATION_GROUPS[classificationIndex];
    const selection = categorySelections[group.id];
    if (!selection) return;
    if (group.categories.some((category) => category.id === selection) || classificationIndex === CLASSIFICATION_GROUPS.length - 1) {
      setCompletedAt(new Date().toISOString());
      setConfirmed(false);
      setPhase("result");
    } else {
      setClassificationIndex((index) => index + 1);
    }
  };

  const editAnswers = () => {
    const matchingIndex = CLASSIFICATION_GROUPS.findIndex((group) => group.categories.some((category) => category.id === categorySelections[group.id]));
    setClassificationIndex(matchingIndex >= 0 ? matchingIndex : CLASSIFICATION_GROUPS.length - 1);
    setPhase("classification");
  };

  const goBack = () => {
    if (phase === "scope") onCancel();
    else if (phase === "result") editAnswers();
    else if (classificationIndex === 0) setPhase("scope");
    else setClassificationIndex((index) => index - 1);
  };

  const phaseIndex = PHASES.indexOf(phase);
  return <section ref={containerRef} className="cra-assessment" aria-label="Guided CRA assessment">
    <header className="cra-assessment__header">
      <div><span className="eyebrow">Guided assessment</span><h2>CRA classification</h2><p>Review whether the CRA may apply, then choose the category that describes your product.</p></div>
      <button className="icon-button" type="button" onClick={onCancel} aria-label="Close CRA assessment"><X size={20} /></button>
    </header>
    <ol className="cra-assessment__steps" aria-label="Assessment progress">
      {PHASES.map((item, index) => <li key={item} className={index < phaseIndex ? "done" : index === phaseIndex ? "active" : ""} aria-current={index === phaseIndex ? "step" : undefined}>
        <span>{index < phaseIndex ? <CheckCircle2 size={16} /> : index + 1}</span>{item === "scope" ? "Check scope" : item === "classification" ? "Classify" : "Review"}
      </li>)}
    </ol>

    <div className="cra-assessment__body">
      {phase === "scope" ? <div className="cra-question">
        <span className="eyebrow">Before classification</span>
        <h3 ref={headingRef} tabIndex={-1}>Check if your product needs CRA assessment</h3>
        <p>CRA rules can apply to connected products containing software or firmware that are supplied on the EU market. Review the scope guide before continuing. This classification assumes your product is covered; it does not decide legal scope for you.</p>
        <button className="cra-scope-link" type="button" onClick={() => setScopeInfoOpen(true)}>Check which products are affected <ExternalLink size={15} /></button>
      </div> : null}
      {phase === "classification" ? <>
        <div className="cra-assessment__counter">CATEGORY {classificationIndex + 1} / {CLASSIFICATION_GROUPS.length}</div>
        <ClassificationQuestion ref={headingRef} index={classificationIndex} selections={categorySelections} onChange={(value) => {
          setCategorySelections((current) => ({ ...current, [CLASSIFICATION_GROUPS[classificationIndex].id]: value }));
          setConfirmed(false);
        }} />
      </> : null}
      {phase === "result" ? <AssessmentResult ref={headingRef} assessment={assessment} confirmed={confirmed} onConfirmed={setConfirmed} /> : null}
    </div>

    <footer className="cra-assessment__footer">
      <button type="button" onClick={goBack}><ArrowLeft size={17} /> Back</button>
      <div className="inline-actions">
        {phase === "scope" ? <button className="button-primary" type="button" onClick={() => setPhase("classification")}>Continue to classification</button> : null}
        {phase === "classification" ? <button className="button-primary" type="button" disabled={!categorySelections[CLASSIFICATION_GROUPS[classificationIndex].id]} onClick={continueClassification}>Continue</button> : null}
        {phase === "result" ? <><button type="button" onClick={editAnswers}>Edit category answers</button><button className="button-primary" type="button" disabled={completionAction.disabled} onClick={() => onComplete(buildCraAssessment({ scopeAnswers: {}, scopeReviewed: true, categorySelections, completedAt, confirmed }))}>{completionAction.label}</button></> : null}
      </div>
    </footer>

    {scopeInfoOpen ? <div className="cra-scope-overlay" onMouseDown={(event) => { if (event.target === event.currentTarget) setScopeInfoOpen(false); }}>
      <div ref={dialogRef} className="cra-scope-dialog" role="dialog" aria-modal="true" aria-labelledby="cra-scope-title" tabIndex={-1} onKeyDown={(event) => { if (event.key === "Escape") setScopeInfoOpen(false); }}>
        <div className="cra-scope-dialog__header"><h3 id="cra-scope-title">Which products may be covered?</h3><button className="icon-button" type="button" aria-label="Close scope guide" onClick={() => setScopeInfoOpen(false)}><X size={20} /></button></div>
        <p>The CRA generally concerns products with digital elements made available on the EU market whose intended or foreseeable use includes a connection to a device or network.</p>
        <ul>
          <li><strong>Often relevant:</strong> connected hardware, software, firmware, and components supplied commercially. An essential remote service designed for the product may also count.</li>
          <li><strong>Check exclusions:</strong> some medical, vehicle, aviation, and marine products are governed by separate EU rules. Standalone services and non-commercial open-source software need separate consideration.</li>
          <li><strong>Classification comes next:</strong> Annex III and IV list important and critical categories. Other covered products can follow the default route.</li>
        </ul>
        <p>This is a short guide, not a legal determination. If the scope is uncertain, consult the official regulation or a specialist.</p>
        <a href={CRA_SOURCE_URL} target="_blank" rel="noreferrer">Read the official CRA scope and annexes <ExternalLink size={15} /></a>
        <div className="inline-actions"><button className="button-primary" type="button" onClick={() => setScopeInfoOpen(false)}>Done</button></div>
      </div>
    </div> : null}
  </section>;
}

const ClassificationQuestion = forwardRef<HTMLHeadingElement, { index: number; selections: Record<string, string>; onChange: (value: string) => void }>(function ClassificationQuestion({ index, selections, onChange }, ref) {
  const group = CLASSIFICATION_GROUPS[index];
  return <div className="cra-question">
    <span className="eyebrow">Determine the Annex category</span>
    <h3 ref={ref} tabIndex={-1}>{group.title}</h3>
    <p>{group.help}</p>
    <div className="field cra-category-field">
      <label htmlFor={`cra-category-${group.id}`}>Core functionality</label>
      <select id={`cra-category-${group.id}`} className="select-field" value={selections[group.id] ?? ""} onChange={(event) => onChange(event.target.value)}>
        <option value="" disabled>Select a category</option>
        {group.categories.map((category) => <option key={category.id} value={category.id}>{category.label} — {category.source}</option>)}
        <option value="none">None of these categories</option>
        <option value="not_sure">Not sure — requires review</option>
      </select>
      <a href={CRA_CATEGORY_SOURCE_URL} target="_blank" rel="noreferrer">Official technical descriptions <ExternalLink size={13} /></a>
    </div>
  </div>;
});

const AssessmentResult = forwardRef<HTMLHeadingElement, { assessment: CraClassificationAssessment; confirmed: boolean; onConfirmed: (value: boolean) => void }>(function AssessmentResult({ assessment, confirmed, onConfirmed }, ref) {
  const needsReview = assessment.classificationStatus === "review_required" && assessment.answers.some((answer) => answer.answer === "not_sure");
  const critical = !needsReview && assessment.recommendedClass === "critical";
  return <div className="cra-result" aria-live="polite">
    <div className={`cra-result__hero ${critical ? "critical" : needsReview ? "warning" : "success"}`}>
      {critical || needsReview ? <AlertTriangle size={28} /> : <ShieldCheck size={28} />}
      <div><span className="eyebrow">Assessment result</span><h3 ref={ref} tabIndex={-1}>{needsReview ? "Specialist review required" : craClassLabel(assessment.recommendedClass)}</h3><p>{assessment.rationale}</p></div>
    </div>
    <div className="cra-result__metrics"><div><span>Recommended class</span><strong>{craClassLabel(assessment.recommendedClass)}</strong></div></div>
    {assessment.categoryLabel ? <p className="notice"><strong>Matched core functionality:</strong> {assessment.categoryLabel}</p> : null}
    {!needsReview ? <label className="cra-confirm"><input type="checkbox" checked={confirmed} onChange={(event) => onConfirmed(event.target.checked)} /><span><strong>Confirm classification</strong> I reviewed the category answers and confirm this recommendation. The assessment record will be retained.</span></label> : null}
    <p className="cra-disclaimer">Check CRA scope separately. This classification is decision support and does not replace the official legal text.</p>
  </div>;
});
