import { describe, expect, it } from "vitest";
import { createDemoState } from "../data/fixtures";
import { craReportingWindows, remediationDue } from "./findingDeadlines";

describe("finding deadlines", () => {
  const findings = createDemoState().findings;

  it("keeps the recorded remediation date and supplies an internal fallback", () => {
    expect(remediationDue(findings[0])).toBe(findings[0].dueAt);
    const unreviewed = findings.find((item) => item.id === "finding-hub-cve-2026-27102")!;
    expect(remediationDue(unreviewed)).toBe("2026-09-28T10:00:00.000Z");
  });

  it("shows CRA notification windows only for confirmed active exploitation", () => {
    expect(craReportingWindows(findings[0])).toEqual({
      early: "2026-09-14T18:00:00.000Z",
      full: "2026-09-16T18:00:00.000Z",
    });
    expect(craReportingWindows(findings.find((item) => item.id === "finding-hub-cve-2026-27102")!)).toBeUndefined();
  });
});
