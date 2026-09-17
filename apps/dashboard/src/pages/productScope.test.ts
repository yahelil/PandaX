import { describe, expect, it } from "vitest";
import { createDemoState } from "../data/fixtures";
import { FixtureAdapter } from "../data/fixtureAdapter";
import { scopeLabel, scopeStatus } from "./ProductsPage";

describe("product scope and CRA classification review", () => {
  it("determines scope status correctly for products with and without assessments", () => {
    const state = createDemoState();
    const productWithScope = state.products[0];
    expect(scopeStatus(productWithScope)).toBe(productWithScope.classificationAssessment?.scopeResult ?? "needs_review");

    const productWithoutAssessment = { ...productWithScope, classificationAssessment: undefined };
    expect(scopeStatus(productWithoutAssessment)).toBe("needs_review");
    expect(scopeLabel("needs_review")).toBe("Needs review");
    expect(scopeLabel("in_scope")).toBe("In scope");
    expect(scopeLabel("out_of_scope")).toBe("Out of scope");
  });

  it("updates product CRA scope, class, and assessment via adapter", async () => {
    const adapter = new FixtureAdapter(createDemoState());
    const initialProduct = adapter.getSnapshot().products[0];

    const updated = await adapter.updateProduct({
      productId: initialProduct.id,
      craClass: "important_ii",
      classificationStatus: "confirmed",
      classificationAssessment: {
        rulesetVersion: "eu-cra-2025-2392-v1",
        completedAt: new Date().toISOString(),
        confirmedAt: new Date().toISOString(),
        scopeResult: "in_scope",
        recommendedClass: "important_ii",
        classificationStatus: "confirmed",
        categoryLabel: "Firewall / IDS system",
        rationale: "Core functionality includes firewall and intrusion detection capabilities.",
        readinessScore: 100,
        answers: [],
        actions: [],
      },
    });

    expect(updated.craClass).toBe("important_ii");
    expect(updated.classificationStatus).toBe("confirmed");
    expect(updated.classificationAssessment?.scopeResult).toBe("in_scope");
    expect(scopeStatus(updated)).toBe("in_scope");
    expect(scopeLabel(scopeStatus(updated))).toBe("In scope");

    // Verify snapshot was mutated
    const inSnapshot = adapter.getSnapshot().products.find((p) => p.id === initialProduct.id);
    expect(inSnapshot?.craClass).toBe("important_ii");
    expect(inSnapshot?.classificationStatus).toBe("confirmed");
  });
});
