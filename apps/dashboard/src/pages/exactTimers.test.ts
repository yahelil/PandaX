import { describe, expect, it } from "vitest";
import { computeExactTimer, getFindingTimers, getProductMostUrgentTimer } from "./exactTimers";
import type { Finding, Product, ComplianceItem } from "../data/types";

describe("computeExactTimer", () => {
  const refTime = new Date("2026-09-18T12:00:00Z").getTime();

  it("returns undefined when date is missing or invalid", () => {
    expect(computeExactTimer(undefined, "Test", refTime)).toBeUndefined();
    expect(computeExactTimer("invalid-date", "Test", refTime)).toBeUndefined();
  });

  it("computes countdown with days and hours left", () => {
    const target = new Date("2026-09-20T15:00:00Z").toISOString();
    const result = computeExactTimer(target, "Internal Target", refTime);
    expect(result).toBeDefined();
    expect(result?.isOverdue).toBe(false);
    expect(result?.days).toBe(2);
    expect(result?.hours).toBe(3);
    expect(result?.countdownText).toBe("2d 3h left");
    expect(result?.urgency).toBe("high");
    expect(result?.sourceLabel).toBe("Internal Target");
  });

  it("computes countdown with hours and minutes left under 24h", () => {
    const target = new Date("2026-09-18T17:30:00Z").toISOString();
    const result = computeExactTimer(target, "24h Early Warning", refTime);
    expect(result).toBeDefined();
    expect(result?.isOverdue).toBe(false);
    expect(result?.days).toBe(0);
    expect(result?.hours).toBe(5);
    expect(result?.minutes).toBe(30);
    expect(result?.countdownText).toBe("5h 30m left");
    expect(result?.urgency).toBe("urgent");
  });

  it("computes countdown with minutes left under 1h", () => {
    const target = new Date("2026-09-18T12:45:00Z").toISOString();
    const result = computeExactTimer(target, "Urgent Notice", refTime);
    expect(result?.countdownText).toBe("45m left");
    expect(result?.urgency).toBe("urgent");
  });

  it("computes countdown for overdue dates", () => {
    const target = new Date("2026-09-17T08:00:00Z").toISOString();
    const result = computeExactTimer(target, "Overdue Task", refTime);
    expect(result?.isOverdue).toBe(true);
    expect(result?.countdownText).toBe("1d 4h overdue");
    expect(result?.urgency).toBe("urgent");
  });
});

describe("getFindingTimers", () => {
  const refTime = new Date("2026-09-18T12:00:00Z").getTime();

  it("computes CRA 24h and 72h windows for confirmed KEV finding", () => {
    const finding: Finding = {
      id: "f-1",
      productId: "p-1",
      releaseId: "r-1",
      reference: "CVE-2026-1001",
      title: "Exploited RCE",
      summary: "Sample",
      actionReason: "Action required",
      component: "libnet",
      componentVersion: "1.0",
      cvss: 9.8,
      severity: "critical",
      priority: "urgent",
      status: "action_required",
      introducedAt: "2026-09-18T00:00:00Z",
      updatedAt: "2026-09-18T00:00:00Z",
      kev: true,
      activelyExploited: true,
      affectedness: "confirmed",
      reachability: "reachable",
      reachabilityConfidence: "high",
      reachabilityReviewRequired: false,
      reachabilityRecommendation: "reachable",
      reachabilityReasonCodes: [],
      evidenceIds: [],
      decisions: [],
      remediation: { status: "not_started" },
    };

    const timers = getFindingTimers(finding, refTime);
    expect(timers.earlyWarning).toBeDefined();
    expect(timers.earlyWarning?.countdownText).toBe("12h 0m left");
    expect(timers.earlyWarning?.urgency).toBe("urgent");

    expect(timers.fullNotification).toBeDefined();
    expect(timers.fullNotification?.countdownText).toBe("2d 12h left");

    expect(timers.remediation).toBeDefined();
    expect(timers.mostUrgent?.sourceLabel).toBe("CRA 24h Early Warning");
  });

  it("does not compute CRA early warning for non-exploited finding", () => {
    const finding: Finding = {
      id: "f-2",
      productId: "p-1",
      releaseId: "r-1",
      reference: "CVE-2026-1002",
      title: "Low bug",
      summary: "Sample",
      actionReason: "Normal review",
      component: "libhelper",
      componentVersion: "2.0",
      cvss: 4.2,
      severity: "low",
      priority: "normal",
      status: "action_required",
      introducedAt: "2026-09-15T00:00:00Z",
      updatedAt: "2026-09-15T00:00:00Z",
      kev: false,
      activelyExploited: false,
      affectedness: "confirmed",
      reachability: "unknown",
      reachabilityConfidence: "low",
      reachabilityReviewRequired: true,
      reachabilityRecommendation: "review",
      reachabilityReasonCodes: [],
      evidenceIds: [],
      decisions: [],
      remediation: { status: "not_started" },
    };

    const timers = getFindingTimers(finding, refTime);
    expect(timers.earlyWarning).toBeUndefined();
    expect(timers.fullNotification).toBeUndefined();
    expect(timers.remediation).toBeDefined();
    expect(timers.mostUrgent?.sourceLabel).toBe("Remediation target");
  });
});

describe("getProductMostUrgentTimer", () => {
  const refTime = new Date("2026-09-18T12:00:00Z").getTime();

  const mockProduct: Product = {
    id: "p-1",
    slug: "secure-gateway",
    identifier: "PROD-1",
    name: "Secure Gateway",
    manufacturer: "Panda Corp",
    description: "Sample product",
    readiness: "needs_attention",
    monitoringHealth: "healthy",
    craClass: "important_i",
    classificationStatus: "confirmed",
    supportUntil: "2028-01-01T00:00:00Z",
    tags: ["network"],
    actionCount: 1,
    createdAt: "2026-01-01T00:00:00Z",
    nextDeadline: "2026-09-25T00:00:00Z",
  };

  it("finds the earliest deadline between product obligations and findings", () => {
    const finding: Finding = {
      id: "f-1",
      productId: "p-1",
      releaseId: "r-1",
      reference: "CVE-2026-1001",
      title: "Urgent issue",
      summary: "Sample",
      actionReason: "Action required",
      component: "libnet",
      componentVersion: "1.0",
      cvss: 9.8,
      severity: "critical",
      priority: "urgent",
      status: "action_required",
      introducedAt: "2026-09-18T06:00:00Z",
      updatedAt: "2026-09-18T06:00:00Z",
      kev: true,
      activelyExploited: true,
      affectedness: "confirmed",
      reachability: "reachable",
      reachabilityConfidence: "high",
      reachabilityReviewRequired: false,
      reachabilityRecommendation: "reachable",
      reachabilityReasonCodes: [],
      evidenceIds: [],
      decisions: [],
      remediation: { status: "not_started" },
    };

    const complianceItem: ComplianceItem = {
      id: "c-1",
      productId: "p-1",
      type: "deadline",
      title: "Quarterly review",
      requirement: "Article 10",
      priority: "normal",
      status: "open",
      dueAt: "2026-09-22T00:00:00Z",
      reason: "Routine audit",
      targetUrl: "/compliance",
    };

    const mostUrgent = getProductMostUrgentTimer(mockProduct, [finding], [complianceItem], refTime);
    expect(mostUrgent).toBeDefined();
    expect(mostUrgent?.sourceLabel).toBe("CVE-2026-1001 24h Early Warning");
    expect(mostUrgent?.countdownText).toBe("18h 0m left");
  });

  it("returns product nextDeadline if no open findings or earlier obligations exist", () => {
    const mostUrgent = getProductMostUrgentTimer(mockProduct, [], [], refTime);
    expect(mostUrgent).toBeDefined();
    expect(mostUrgent?.sourceLabel).toBe("Next obligation");
    expect(mostUrgent?.countdownText).toBe("6d 12h left");
  });
});
