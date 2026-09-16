import { describe, expect, it } from "vitest";

import { createDemoState } from "../data/fixtures";
import { canSubmitBatchApproval, DEFAULT_AUTO_TRIAGE_RATIONALE, lowNoiseRecommendation } from "./FindingsPage";

describe("low-noise findings review", () => {
  it("selects only undecided, high-confidence non-reachability recommendations", () => {
    const findings = createDemoState().findings;

    expect(findings.filter(lowNoiseRecommendation).map((finding) => finding.id)).toEqual([
      "finding-gateway-cve-2026-30190",
    ]);
  });

  it("requires selection, rationale, explicit confirmation, and decision permission", () => {
    expect(canSubmitBatchApproval(1, "Reviewed signed build evidence.", true, true)).toBe(true);
    expect(canSubmitBatchApproval(0, "Reviewed signed build evidence.", true, true)).toBe(false);
    expect(canSubmitBatchApproval(1, "   ", true, true)).toBe(false);
    expect(canSubmitBatchApproval(1, "Reviewed signed build evidence.", false, true)).toBe(false);
    expect(canSubmitBatchApproval(1, "Reviewed signed build evidence.", true, false)).toBe(false);
    expect(canSubmitBatchApproval(1, "Reviewed signed build evidence.", true, true, true)).toBe(false);
  });

  it("provides an evidence-based default rationale for automated triage", () => {
    expect(DEFAULT_AUTO_TRIAGE_RATIONALE.length).toBeGreaterThan(20);
    expect(DEFAULT_AUTO_TRIAGE_RATIONALE).toContain("static call-graph");
    expect(canSubmitBatchApproval(1, DEFAULT_AUTO_TRIAGE_RATIONALE, true, true)).toBe(true);
  });
});
