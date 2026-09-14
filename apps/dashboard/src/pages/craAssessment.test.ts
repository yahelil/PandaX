import { describe, expect, it } from "vitest";
import {
  CLASSIFICATION_GROUPS,
  IMPORTANT_I_CATEGORIES,
  READINESS_QUESTIONS,
  SCOPE_QUESTIONS,
  buildCraAssessment,
  craClassLabel,
  readinessScore,
  scopeOutcome,
} from "./craAssessment";

const inScope = Object.fromEntries(SCOPE_QUESTIONS.map((question) => [question.id, question.exclusionAnswer === "yes" ? "no" : "yes"])) as Record<string, "yes" | "no">;

describe("CRA assessment", () => {
  it("uses the legal Roman-numeral class labels", () => {
    expect(craClassLabel("important_i")).toBe("Important I");
    expect(craClassLabel("important_ii")).toBe("Important II");
  });

  it("covers every current Annex III Class I category", () => {
    expect(IMPORTANT_I_CATEGORIES).toHaveLength(19);
    expect(CLASSIFICATION_GROUPS.flatMap((group) => group.categories)).toHaveLength(26);
  });

  it("stops on an explicit scope exclusion and preserves the reason", () => {
    const answers = { ...inScope, "standalone-service": "yes" as const };
    expect(scopeOutcome(answers)).toBe("out_of_scope");
    expect(buildCraAssessment({ scopeAnswers: answers, categorySelections: {}, readinessAnswers: {} }).scopeResult).toBe("out_of_scope");
  });

  it("recommends the highest selected exact category and requires review until confirmed", () => {
    const assessment = buildCraAssessment({
      scopeAnswers: inScope,
      categorySelections: { critical: "none", important_ii: "ii-firewall-ids" },
      readinessAnswers: Object.fromEntries(READINESS_QUESTIONS.map((question) => [question.id, "yes"])),
      completedAt: "2026-09-15T12:00:00.000Z",
      confirmed: true,
    });
    expect(assessment.recommendedClass).toBe("important_ii");
    expect(assessment.categoryLabel).toContain("Firewall");
    expect(assessment.classificationStatus).toBe("confirmed");
    expect(assessment.readinessScore).toBe(100);
    expect(assessment.actions).toEqual([]);
  });

  it("keeps partial readiness distinct from missing", () => {
    const answers = Object.fromEntries(READINESS_QUESTIONS.map((question, index) => [question.id, index === 0 ? "partial" : "no"])) as Record<string, "partial" | "no">;
    expect(readinessScore(answers)).toBe(7);
    const assessment = buildCraAssessment({ scopeAnswers: inScope, categorySelections: {}, readinessAnswers: answers });
    expect(assessment.actions[0].state).toBe("partial");
    expect(assessment.actions.slice(1).every((action) => action.state === "missing")).toBe(true);
  });
});
