import { AlertTriangle, ArrowLeft, CheckCircle2, ExternalLink, RotateCcw, ShieldCheck, X } from "lucide-react";
import { forwardRef, useEffect, useMemo, useRef, useState } from "react";
import type { CraClassificationAssessment } from "../data/types";
import {
  CLASSIFICATION_GROUPS,
  CRA_CATEGORY_SOURCE_URL,
  CRA_SOURCE_URL,
  READINESS_QUESTIONS,
  SCOPE_QUESTIONS,
  buildCraAssessment,
  craClassLabel,
  scopeOutcome,
  type ReadinessAnswer,
  type ScopeAnswer,
} from "./craAssessment";

type Phase = "scope" | "classification" | "readiness" | "result";

interface Props {
  onCancel: () => void;
  onComplete: (assessment: CraClassificationAssessment) => void;
}

const PHASES: Phase[] = ["scope", "classification", "readiness", "result"];

export function CraAssessmentWizard({ onCancel, onComplete }: Props) {
  const [phase, setPhase] = useState<Phase>("scope");
  const [scopeIndex, setScopeIndex] = useState(0);
  const [classificationIndex, setClassificationIndex] = useState(0);
  const [readinessIndex, setReadinessIndex] = useState(0);
  const [scopeAnswers, setScopeAnswers] = useState<Record<string, ScopeAnswer>>({});
  const [categorySelections, setCategorySelections] = useState<Record<string, string>>({});
  const [readinessAnswers, setReadinessAnswers] = useState<Record<string, ReadinessAnswer>>({});
  const [completedAt, setCompletedAt] = useState<string>();
  const [confirmed, setConfirmed] = useState(false);
  const containerRef = useRef<HTMLElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    containerRef.current?.scrollIntoView({ block: "start" });
    headingRef.current?.focus({ preventScroll: true });
  }, [phase, scopeIndex, classificationIndex, readinessIndex]);

  const assessment = useMemo(() => buildCraAssessment({
    scopeAnswers,
    categorySelections,
    readinessAnswers,
    completedAt,
    confirmed,
  }), [categorySelections, completedAt, confirmed, readinessAnswers, scopeAnswers]);

  const finish = () => {
    setCompletedAt(new Date().toISOString());
    setPhase("result");
  };

  const answerScope = (answer: ScopeAnswer) => {
    const question = SCOPE_QUESTIONS[scopeIndex];
    const nextAnswers = { ...scopeAnswers, [question.id]: answer };
    setScopeAnswers(nextAnswers);
    if (answer === question.exclusionAnswer) {
      setCompletedAt(new Date().toISOString());
      setPhase("result");
    } else if (scopeIndex === SCOPE_QUESTIONS.length - 1) {
      setPhase("classification");
    } else {
      setScopeIndex((value) => value + 1);
    }
  };

  const continueClassification = () => {
    const group = CLASSIFICATION_GROUPS[classificationIndex];
    const selection = categorySelections[group.id];
    if (!selection) return;
    const matchedCategory = group.categories.some((category) => category.id === selection);
    if (matchedCategory || classificationIndex === CLASSIFICATION_GROUPS.length - 1) {
      setPhase("readiness");
      return;
    }
    setClassificationIndex((value) => value + 1);
  };

  const answerReadiness = (answer: ReadinessAnswer) => {
    const question = READINESS_QUESTIONS[readinessIndex];
    setReadinessAnswers((current) => ({ ...current, [question.id]: answer }));
    if (readinessIndex === READINESS_QUESTIONS.length - 1) finish();
    else setReadinessIndex((value) => value + 1);
  };

  const goBack = () => {
    if (phase === "scope") {
      if (scopeIndex === 0) onCancel();
      else setScopeIndex((value) => value - 1);
      return;
    }
    if (phase === "classification") {
      if (classificationIndex === 0) {
        setPhase("scope");
        setScopeIndex(SCOPE_QUESTIONS.length - 1);
      } else setClassificationIndex((value) => value - 1);
      return;
    }
    if (phase === "readiness") {
      if (readinessIndex === 0) setPhase("classification");
      else setReadinessIndex((value) => value - 1);
      return;
    }
    if (scopeOutcome(scopeAnswers) === "out_of_scope") {
      setPhase("scope");
      return;
    }
    setPhase("readiness");
    setReadinessIndex(READINESS_QUESTIONS.length - 1);
  };

  const restart = () => {
    setPhase("scope");
    setScopeIndex(0);
    setClassificationIndex(0);
    setReadinessIndex(0);
    setScopeAnswers({});
    setCategorySelections({});
    setReadinessAnswers({});
    setCompletedAt(undefined);
    setConfirmed(false);
  };

  const phaseIndex = PHASES.indexOf(phase);
  const currentCount = phase === "scope" ? SCOPE_QUESTIONS.length : phase === "classification" ? CLASSIFICATION_GROUPS.length : phase === "readiness" ? READINESS_QUESTIONS.length : 1;
  const currentIndex = phase === "scope" ? scopeIndex : phase === "classification" ? classificationIndex : phase === "readiness" ? readinessIndex : 0;

  return <section ref={containerRef} className="cra-assessment" aria-label="Guided CRA assessment">
    <header className="cra-assessment__header">
      <div><span className="eyebrow">Guided assessment</span><h2>CRA scope and classification</h2><p>Structured answers, exact category references, and an auditable recommendation.</p></div>
      <button className="icon-button" type="button" onClick={onCancel} aria-label="Close CRA assessment"><X size={20} /></button>
    </header>
    <ol className="cra-assessment__steps" aria-label="Assessment progress">
      {PHASES.map((item, index) => <li key={item} className={index < phaseIndex ? "done" : index === phaseIndex ? "active" : ""} aria-current={index === phaseIndex ? "step" : undefined}>
        <span>{index < phaseIndex ? <CheckCircle2 size={16} /> : index + 1}</span>{item[0].toUpperCase() + item.slice(1)}
      </li>)}
    </ol>

    <div className="cra-assessment__body">
      {phase !== "result" ? <div className="cra-assessment__counter">{phase.toUpperCase()} {currentIndex + 1} / {currentCount}</div> : null}
      {phase === "scope" ? <QuestionHeading ref={headingRef} title="Is this product covered by the CRA?" question={SCOPE_QUESTIONS[scopeIndex].question} help={SCOPE_QUESTIONS[scopeIndex].help} source={SCOPE_QUESTIONS[scopeIndex].source} /> : null}
      {phase === "classification" ? <ClassificationQuestion ref={headingRef} index={classificationIndex} selections={categorySelections} onChange={(value) => setCategorySelections((current) => ({ ...current, [CLASSIFICATION_GROUPS[classificationIndex].id]: value }))} /> : null}
      {phase === "readiness" ? <QuestionHeading ref={headingRef} title="How prepared is the product?" question={READINESS_QUESTIONS[readinessIndex].question} help={READINESS_QUESTIONS[readinessIndex].help} source={READINESS_QUESTIONS[readinessIndex].source} /> : null}

      {phase === "scope" ? <div className="cra-answer-grid">
        <AnswerButton label="Yes" selected={scopeAnswers[SCOPE_QUESTIONS[scopeIndex].id] === "yes"} onClick={() => answerScope("yes")} />
        <AnswerButton label="No" selected={scopeAnswers[SCOPE_QUESTIONS[scopeIndex].id] === "no"} onClick={() => answerScope("no")} />
        <AnswerButton label="Not sure" selected={scopeAnswers[SCOPE_QUESTIONS[scopeIndex].id] === "not_sure"} onClick={() => answerScope("not_sure")} />
      </div> : null}
      {phase === "readiness" ? <div className="cra-answer-grid">
        <AnswerButton label="Yes" selected={readinessAnswers[READINESS_QUESTIONS[readinessIndex].id] === "yes"} onClick={() => answerReadiness("yes")} />
        <AnswerButton label="Partially" selected={readinessAnswers[READINESS_QUESTIONS[readinessIndex].id] === "partial"} onClick={() => answerReadiness("partial")} />
        <AnswerButton label="No" selected={readinessAnswers[READINESS_QUESTIONS[readinessIndex].id] === "no"} onClick={() => answerReadiness("no")} />
      </div> : null}
      {phase === "result" ? <AssessmentResult ref={headingRef} assessment={assessment} confirmed={confirmed} onConfirmed={setConfirmed} /> : null}
    </div>

    <footer className="cra-assessment__footer">
      <button type="button" onClick={goBack}><ArrowLeft size={17} /> Back</button>
      <div className="inline-actions">
        {phase === "classification" ? <button className="button-primary" type="button" disabled={!categorySelections[CLASSIFICATION_GROUPS[classificationIndex].id]} onClick={continueClassification}>Continue</button> : null}
        {phase === "result" ? <button type="button" onClick={restart}><RotateCcw size={17} /> Start over</button> : null}
        {phase === "result" && assessment.scopeResult !== "out_of_scope" ? <button className="button-primary" type="button" onClick={() => onComplete(buildCraAssessment({ scopeAnswers, categorySelections, readinessAnswers, completedAt, confirmed }))}>Use assessment</button> : null}
        {phase === "result" && assessment.scopeResult === "out_of_scope" ? <button className="button-primary" type="button" onClick={onCancel}>Close assessment</button> : null}
      </div>
    </footer>
  </section>;
}

function AnswerButton({ label, selected, onClick }: { label: string; selected: boolean; onClick: () => void }) {
  return <button className={`cra-answer${selected ? " selected" : ""}`} type="button" onClick={onClick}>{label}</button>;
}

const QuestionHeading = forwardRef<HTMLHeadingElement, { title: string; question: string; help: string; source: string }>(function QuestionHeading({ title, question, help, source }, ref) {
  return <div className="cra-question">
  <span className="eyebrow">{title}</span>
  <h3 ref={ref} tabIndex={-1}>{question}</h3>
  <p>{help}</p>
  <a href={CRA_SOURCE_URL} target="_blank" rel="noreferrer">{source}<ExternalLink size={13} /></a>
</div>;
});

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
      <a href={CRA_CATEGORY_SOURCE_URL} target="_blank" rel="noreferrer">Official technical descriptions<ExternalLink size={13} /></a>
    </div>
  </div>;
});

const AssessmentResult = forwardRef<HTMLHeadingElement, { assessment: CraClassificationAssessment; confirmed: boolean; onConfirmed: (value: boolean) => void }>(function AssessmentResult({ assessment, confirmed, onConfirmed }, ref) {
  const outOfScope = assessment.scopeResult === "out_of_scope";
  const needsReview = assessment.scopeResult === "needs_review" || assessment.answers.some((answer) => answer.answer === "not_sure");
  return <div className="cra-result" aria-live="polite">
    <div className={`cra-result__hero ${outOfScope || needsReview ? "warning" : "success"}`}>
      {outOfScope || needsReview ? <AlertTriangle size={28} /> : <ShieldCheck size={28} />}
      <div><span className="eyebrow">Assessment result</span><h3 ref={ref} tabIndex={-1}>{outOfScope ? "Likely outside CRA product scope" : needsReview ? "Specialist review required" : craClassLabel(assessment.recommendedClass)}</h3><p>{assessment.rationale}</p></div>
    </div>
    {!outOfScope ? <div className="cra-result__metrics"><div><span>Recommended class</span><strong>{craClassLabel(assessment.recommendedClass)}</strong></div><div><span>Readiness</span><strong>{assessment.readinessScore}%</strong></div><div><span>Open actions</span><strong>{assessment.actions.length}</strong></div></div> : null}
    {assessment.categoryLabel ? <p className="notice"><strong>Matched core functionality:</strong> {assessment.categoryLabel}</p> : null}
    {assessment.actions.length ? <div><h4>Readiness actions</h4><ul className="cra-action-list">{assessment.actions.map((action) => <li key={action.id}><span className={`status-pill status-${action.state}`}>{action.state}</span><div><strong>{action.title}</strong><p>{action.source}</p></div></li>)}</ul></div> : !outOfScope ? <p className="notice">No readiness gaps were declared. Evidence still needs independent verification.</p> : null}
    {!outOfScope && !needsReview ? <label className="cra-confirm"><input type="checkbox" checked={confirmed} onChange={(event) => onConfirmed(event.target.checked)} /><span><strong>Confirm classification</strong> I reviewed the answers and confirm this recommendation. The assessment record and confirmation will be retained.</span></label> : null}
    <p className="cra-disclaimer">Decision support only. Verify intended purpose, exclusions, and the current legal text before relying on the result.</p>
  </div>;
});
