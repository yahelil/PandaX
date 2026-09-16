import type { CraClass, CraClassificationAssessment, CraAssessmentAnswer, CraAssessmentAction } from "../data/types";

export const CRA_RULESET_VERSION = "eu-cra-2025-2392-v1";
export const CRA_SOURCE_URL = "https://eur-lex.europa.eu/eli/reg/2024/2847/oj";
export const CRA_CATEGORY_SOURCE_URL = "https://eur-lex.europa.eu/eli/reg_impl/2025/2392/oj";

export type ScopeAnswer = "yes" | "no" | "not_sure";
export type ReadinessAnswer = "yes" | "partial" | "no";

export function craClassLabel(value: CraClass): string {
  return ({ default: "Default", important_i: "Important I", important_ii: "Important II", critical: "Critical" })[value];
}

export function assessmentCompletionAction(assessment: CraClassificationAssessment): { label: string; disabled: boolean } {
  const needsSpecialistReview = assessment.scopeResult === "needs_review" || assessment.answers.some((answer) => answer.answer === "not_sure");
  return needsSpecialistReview
    ? { label: "Save for specialist review", disabled: false }
    : { label: "Use assessment", disabled: assessment.classificationStatus !== "confirmed" };
}

export interface ScopeQuestion {
  id: string;
  question: string;
  help: string;
  source: string;
  exclusionAnswer: "yes" | "no";
}

export interface CraCategory {
  id: string;
  label: string;
  craClass: Exclude<CraClass, "default">;
  source: string;
}

export interface ReadinessQuestion {
  id: string;
  question: string;
  help: string;
  source: string;
  actionTitle: string;
}

export const SCOPE_QUESTIONS: ScopeQuestion[] = [
  {
    id: "digital-elements",
    question: "Does the product contain software, firmware, or an essential remote data-processing solution?",
    help: "A remote service counts when the product cannot perform one of its functions without it. Standalone services are assessed separately.",
    source: "CRA Art. 3(1)–(2)",
    exclusionAnswer: "no",
  },
  {
    id: "eu-commercial-market",
    question: "Will the product be supplied on the EU market in the course of a commercial activity?",
    help: "This includes paid products and commercially supplied components, regardless of where the manufacturer is established.",
    source: "CRA Art. 2(1), Art. 3(22)",
    exclusionAnswer: "no",
  },
  {
    id: "standalone-service",
    question: "Is it only a standalone cloud or SaaS service, with no covered product or essential remote-processing function?",
    help: "Cloud functionality remains relevant when it is designed by the manufacturer and is necessary for a product function.",
    source: "CRA Recitals 11–12",
    exclusionAnswer: "yes",
  },
  {
    id: "non-commercial-foss",
    question: "Is it free and open-source software supplied outside any commercial activity?",
    help: "Funding or contributions alone do not make software commercial. Open-source stewards are a distinct CRA role.",
    source: "CRA Art. 2(3), Recitals 17–20",
    exclusionAnswer: "yes",
  },
];

export const CRITICAL_CATEGORIES: CraCategory[] = [
  { id: "critical-security-box", label: "Hardware device with a security box", craClass: "critical", source: "CRA Annex IV(1)" },
  { id: "critical-smart-meter", label: "Smart meter gateway or device for advanced secure cryptoprocessing", craClass: "critical", source: "CRA Annex IV(2)" },
  { id: "critical-smartcard", label: "Smartcard, secure element, or similar device", craClass: "critical", source: "CRA Annex IV(3)" },
];

export const IMPORTANT_II_CATEGORIES: CraCategory[] = [
  { id: "ii-hypervisor-runtime", label: "Hypervisor or container runtime supporting virtualised execution", craClass: "important_ii", source: "CRA Annex III, Class II(1)" },
  { id: "ii-firewall-ids", label: "Firewall, intrusion detection, or intrusion prevention system", craClass: "important_ii", source: "CRA Annex III, Class II(2)" },
  { id: "ii-tamper-processor", label: "Tamper-resistant microprocessor", craClass: "important_ii", source: "CRA Annex III, Class II(3)" },
  { id: "ii-tamper-controller", label: "Tamper-resistant microcontroller", craClass: "important_ii", source: "CRA Annex III, Class II(4)" },
];

export const IMPORTANT_I_CATEGORIES: CraCategory[] = [
  "Identity or privileged-access management system|1",
  "Standalone or embedded browser|2",
  "Password manager|3",
  "Malware search, removal, or quarantine software|4",
  "Virtual private network product|5",
  "Network management system|6",
  "Security information and event management system|7",
  "Boot manager|8",
  "PKI or digital-certificate issuance software|9",
  "Physical or virtual network interface|10",
  "Operating system|11",
  "Router, internet modem, or switch|12",
  "Microprocessor with security-related functionality|13",
  "Microcontroller with security-related functionality|14",
  "ASIC or FPGA with security-related functionality|15",
  "Smart-home general-purpose virtual assistant|16",
  "Smart-home product with security functionality|17",
  "Internet-connected toy with social interaction or location tracking|18",
  "Health-monitoring wearable outside medical-device law, or child wearable|19",
].map((entry) => {
  const [label, item] = entry.split("|");
  return { id: `i-${item}`, label, craClass: "important_i" as const, source: `CRA Annex III, Class I(${item})` };
});

export const CLASSIFICATION_GROUPS = [
  { id: "critical", title: "Critical products", help: "Select a category only when it describes the product's core functionality.", categories: CRITICAL_CATEGORIES },
  { id: "important_ii", title: "Important Class II", help: "Class II products require third-party conformity assessment.", categories: IMPORTANT_II_CATEGORIES },
  { id: "important_i", title: "Important Class I", help: "Select the closest exact category. Integrating one of these functions does not automatically classify the whole product.", categories: IMPORTANT_I_CATEGORIES },
] as const;

export const READINESS_QUESTIONS: ReadinessQuestion[] = [
  { id: "sbom", question: "Do you maintain a machine-readable SBOM?", help: "Cover at least top-level dependencies in a commonly used format such as CycloneDX or SPDX.", source: "CRA Annex I, Part II(1)", actionTitle: "Produce and maintain a machine-readable SBOM" },
  { id: "vulnerability-process", question: "Do you have a documented vulnerability-handling process?", help: "The process should identify, document, remediate, test, and disclose vulnerabilities without undue delay.", source: "CRA Annex I, Part II", actionTitle: "Document the vulnerability-handling process" },
  { id: "disclosure-policy", question: "Is there a public coordinated vulnerability-disclosure policy and contact?", help: "Publish a clear reporting route, expected response process, and security contact.", source: "CRA Art. 13(6), Annex I Part II(5)", actionTitle: "Publish a disclosure policy and security contact" },
  { id: "technical-documentation", question: "Are technical documentation and the EU Declaration of Conformity prepared?", help: "The technical file must explain the product, risk assessment, design, standards, tests, and conformity route.", source: "CRA Arts. 28, 31; Annexes V and VII", actionTitle: "Prepare the technical file and EU Declaration of Conformity" },
  { id: "monitoring", question: "Do you continuously monitor components for newly disclosed vulnerabilities?", help: "Monitoring must continue during the support period and feed remediation and disclosure decisions.", source: "CRA Annex I, Part II(2)–(4)", actionTitle: "Establish continuous component monitoring" },
  { id: "secure-default", question: "Does the product ship with secure-by-default configuration?", help: "Avoid default passwords, unnecessary exposed services, and disabled security controls.", source: "CRA Annex I, Part I(2)(b)", actionTitle: "Review and document secure defaults" },
  { id: "security-updates", question: "Can you distribute security updates throughout a documented support period?", help: "Updates must be distributed securely and, where technically feasible, separately from functionality updates.", source: "CRA Art. 13(8); Annex I, Part II(7)–(8)", actionTitle: "Define the support period and secure update mechanism" },
];

export interface BuildAssessmentInput {
  scopeAnswers: Record<string, ScopeAnswer>;
  scopeReviewed?: boolean;
  categorySelections: Record<string, string>;
  readinessAnswers?: Record<string, ReadinessAnswer>;
  completedAt?: string;
  confirmed?: boolean;
}

export function scopeOutcome(answers: Record<string, ScopeAnswer>): CraClassificationAssessment["scopeResult"] {
  if (SCOPE_QUESTIONS.some((question) => answers[question.id] === question.exclusionAnswer)) return "out_of_scope";
  if (SCOPE_QUESTIONS.some((question) => answers[question.id] === "not_sure" || !answers[question.id])) return "needs_review";
  return "in_scope";
}

export function selectedCategory(selections: Record<string, string>): CraCategory | undefined {
  const categories = [...CRITICAL_CATEGORIES, ...IMPORTANT_II_CATEGORIES, ...IMPORTANT_I_CATEGORIES];
  return categories.find((category) => Object.values(selections).includes(category.id));
}

export function readinessScore(answers: Record<string, ReadinessAnswer>): number {
  if (!READINESS_QUESTIONS.length) return 0;
  const points = READINESS_QUESTIONS.reduce((total, question) => total + ({ yes: 100, partial: 50, no: 0 }[answers[question.id] ?? "no"]), 0);
  return Math.round(points / READINESS_QUESTIONS.length);
}

export function buildCraAssessment(input: BuildAssessmentInput): CraClassificationAssessment {
  const scopeResult = input.scopeReviewed ? "in_scope" : scopeOutcome(input.scopeAnswers);
  const readinessAnswers = input.readinessAnswers ?? {};
  const category = selectedCategory(input.categorySelections);
  const categoryUncertain = Object.values(input.categorySelections).includes("not_sure");
  const recommendedClass: CraClass = category?.craClass ?? "default";
  const answers: CraAssessmentAnswer[] = [
    ...(input.scopeReviewed ? [{ questionId: "scope-guidance", question: "Reviewed CRA product scope guidance", answer: "reviewed", source: "CRA Art. 2" }] : SCOPE_QUESTIONS.filter((question) => input.scopeAnswers[question.id]).map((question) => ({ questionId: question.id, question: question.question, answer: input.scopeAnswers[question.id], source: question.source }))),
    ...CLASSIFICATION_GROUPS.filter((group) => input.categorySelections[group.id]).map((group) => ({ questionId: `category-${group.id}`, question: group.title, answer: input.categorySelections[group.id], source: category?.id === input.categorySelections[group.id] ? category.source : "CRA Annexes III–IV" })),
    ...READINESS_QUESTIONS.filter((question) => readinessAnswers[question.id]).map((question) => ({ questionId: question.id, question: question.question, answer: readinessAnswers[question.id], source: question.source })),
  ];
  const actions: CraAssessmentAction[] = READINESS_QUESTIONS.flatMap((question) => {
    const answer = readinessAnswers[question.id];
    return answer && answer !== "yes" ? [{ id: question.id, title: question.actionTitle, detail: question.help, source: question.source, state: answer === "partial" ? "partial" as const : "missing" as const }] : [];
  });
  const needsReview = scopeResult !== "in_scope" || categoryUncertain;
  const rationale = scopeResult === "out_of_scope"
    ? "One or more scope answers indicate that this product is likely outside the CRA product regime."
    : category
      ? `The product's declared core functionality matches ${category.label}.`
      : categoryUncertain
        ? "No classification can be confirmed until the unresolved category answer is reviewed."
        : "No Annex III or Annex IV category was selected; the standard product route is recommended. CRA scope should be checked separately.";

  return {
    rulesetVersion: CRA_RULESET_VERSION,
    completedAt: input.completedAt ?? new Date().toISOString(),
    scopeResult,
    recommendedClass,
    classificationStatus: input.confirmed && !needsReview ? "confirmed" : "review_required",
    categoryId: category?.id,
    categoryLabel: category?.label,
    rationale,
    readinessScore: readinessScore(readinessAnswers),
    answers,
    actions,
    confirmedAt: input.confirmed && !needsReview ? (input.completedAt ?? new Date().toISOString()) : undefined,
  };
}
