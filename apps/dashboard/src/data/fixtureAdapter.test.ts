import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createDemoState, DEMO_IDS } from "./fixtures";
import { FixtureAdapter } from "./fixtureAdapter";
import type { AnalysisDraft } from "./types";

class MemoryStorage implements Storage {
  private readonly values = new Map<string, string>();

  get length() { return this.values.size; }
  clear() { this.values.clear(); }
  getItem(key: string) { return this.values.get(key) ?? null; }
  key(index: number) { return [...this.values.keys()][index] ?? null; }
  removeItem(key: string) { this.values.delete(key); }
  setItem(key: string, value: string) { this.values.set(key, value); }
}

const originalWindow = globalThis.window;

beforeEach(() => {
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { localStorage: new MemoryStorage() },
  });
});

afterEach(() => {
  vi.useRealTimers();
  if (originalWindow) {
    Object.defineProperty(globalThis, "window", { configurable: true, value: originalWindow });
  } else {
    Reflect.deleteProperty(globalThis, "window");
  }
});

describe("FixtureAdapter demo contract", () => {
  it("seeds five distinct presentation scenarios", () => {
    const state = createDemoState();

    expect(state.products).toHaveLength(5);
    expect(state.releases).toHaveLength(5);
    expect(state.products.find((item) => item.id === DEMO_IDS.smartCamera)).toMatchObject({ readiness: "ready", monitoringHealth: "healthy" });
    expect(state.findings.find((item) => item.productId === DEMO_IDS.homeHub && item.kev)).toMatchObject({ priority: "urgent", affectedness: "confirmed", reachability: "reachable" });
    expect(state.complianceItems.find((item) => item.productId === DEMO_IDS.smartLock && item.type === "deadline")).toMatchObject({ priority: "urgent" });
    expect(state.products.find((item) => item.id === DEMO_IDS.thermostat)).toMatchObject({ readiness: "incomplete_evidence" });
    expect(state.products.find((item) => item.id === DEMO_IDS.edgeGateway)).toMatchObject({ monitoringHealth: "degraded" });
  });

  it("persists mutations and resets to deterministic fixtures", () => {
    const adapter = new FixtureAdapter(createDemoState());
    adapter.updateSettings("appearance", { theme: "dark", density: "compact" });

    const restored = new FixtureAdapter();
    expect(restored.getSnapshot().settings.appearance).toEqual({ theme: "dark", density: "compact" });

    restored.reset();
    expect(restored.getSnapshot().settings.appearance).toEqual({ theme: "light", density: "comfortable" });
    expect(new FixtureAdapter().getSnapshot().products).toHaveLength(5);
  });

  it("records finding decisions, assignment, and remediation audit state", () => {
    const adapter = new FixtureAdapter(createDemoState());
    const findingId = "finding-hub-cve-2026-27102";

    adapter.assignFinding(findingId, DEMO_IDS.jane);
    const decided = adapter.recordFindingDecision({
      findingId,
      decision: "affected",
      rationale: "Production build flags confirm the reachable TLS path is enabled.",
    });
    const remediated = adapter.updateRemediation({
      findingId,
      status: "verified",
      plan: "Upgrade curl and retain signed regression evidence.",
      targetDate: "2026-09-16",
    });

    expect(decided).toMatchObject({ assigneeId: DEMO_IDS.jane, affectedness: "confirmed", status: "action_required" });
    expect(decided.decisions.at(-1)).toMatchObject({ decision: "affected", decidedBy: DEMO_IDS.jane });
    expect(remediated).toMatchObject({ status: "resolved", remediation: { status: "verified" } });
    expect(adapter.getSnapshot().actions.find((item) => item.targetUrl.endsWith(findingId))?.status).toBe("completed");
  });

  it("approves a document and retains an immutable-looking audit entry", () => {
    const adapter = new FixtureAdapter(createDemoState());
    const document = adapter.approveDocument("document-lock-report", "Regulatory content and evidence verified.");

    expect(document.status).toBe("approved");
    expect(document.audit[0]).toMatchObject({ action: "approved", actorId: DEMO_IDS.jane, detail: "Regulatory content and evidence verified." });
    expect(adapter.getApproval(document.id)).toMatchObject({ status: "approved", decidedBy: DEMO_IDS.jane });
    expect(adapter.getSnapshot().complianceItems.find((item) => item.type === "approval" && item.targetUrl.endsWith(document.id))?.status).toBe("complete");
  });

  it("acknowledges an alert without resolving the underlying action", () => {
    const adapter = new FixtureAdapter(createDemoState());
    adapter.acknowledgeNotification("notification-hub-kev");

    expect(adapter.getSnapshot().notifications.find((item) => item.id === "notification-hub-kev")?.acknowledgedAt).toBeTruthy();
    expect(adapter.getSnapshot().actions.find((item) => item.id === "action-hub-kev")?.status).toBe("open");
  });

  it("updates and approves compliance work with versioned audit events", async () => {
    const adapter = new FixtureAdapter(createDemoState(), false);
    const approvalId = "compliance-lock-approval";

    const loaded = await adapter.loadComplianceDetail(approvalId);
    const reassigned = adapter.updateCompliance({ itemId: approvalId, ownerId: DEMO_IDS.jane });
    const approved = adapter.approveCompliance({ itemId: approvalId, selfFilingRecordId: "filing-24h-1" });

    expect(loaded).toMatchObject({ lifecycleStatus: "pending_approval", version: 3 });
    expect(reassigned).toMatchObject({ ownerId: DEMO_IDS.jane, version: 4, lifecycleStatus: "pending_approval" });
    expect(approved).toMatchObject({ lifecycleStatus: "approved", version: 5, approvedBy: DEMO_IDS.jane, selfFilingRecordId: "filing-24h-1" });
    expect(approved.audit?.map((entry) => entry.action)).toEqual(["compliance.updated", "compliance.approved"]);
  });

  it("validates evidence and completes the simulated release analysis", async () => {
    vi.useFakeTimers();
    const adapter = new FixtureAdapter(createDemoState());
    const draft: AnalysisDraft = {
      productId: DEMO_IDS.thermostat,
      releaseId: DEMO_IDS.thermostatRelease,
      version: "3.0.0",
      channel: "stable",
      inputKind: "collector_package",
      fileName: "thermostat-3.0.0.collector.zip",
      fileSize: 1_280_000,
    };

    const previewPromise = adapter.previewAnalysis(draft);
    await vi.advanceTimersByTimeAsync(180);
    const preview = await previewPromise;
    expect(preview).toMatchObject({ valid: true, detectedFormat: "Signed Actis Collector package" });
    expect(preview.componentCount).toBeGreaterThan(100);

    const runPromise = adapter.runAnalysis(draft);
    await vi.advanceTimersByTimeAsync(180);
    const queued = await runPromise;
    expect(queued).toMatchObject({ status: "queued", progress: 5 });

    await vi.advanceTimersByTimeAsync(1_450);
    const completed = adapter.getAnalysisJob(queued.id);
    expect(completed).toMatchObject({ status: "completed", progress: 100 });
    expect(completed?.result).toMatchObject({ releaseId: DEMO_IDS.thermostatRelease, newFindings: 1, changedFindings: 1 });
    expect(adapter.getSnapshot().releases.find((item) => item.id === DEMO_IDS.thermostatRelease)).toMatchObject({ sbomStatus: "validated", monitoringHealth: "healthy", readiness: "ready" });
  });

  it("persists a realistic manual monitoring check", async () => {
    const adapter = new FixtureAdapter(createDemoState(), false);
    const release = adapter.getSnapshot().releases[0];

    const before = await adapter.loadReleaseMonitoring(release.productId, release.id);
    const after = await adapter.runReleaseMonitoring(release.productId, release.id);

    expect(before.enabledSources).toContain("cisa_kev");
    expect(after.lastCheckAt).toBeTruthy();
    expect(after.recentEvents[0]).toMatchObject({ trigger: "manual", eventType: "succeeded" });
    expect(adapter.getSnapshot().activities[0]).toMatchObject({ type: "monitoring", releaseId: release.id });
  });

  it("rejects raw artifacts until privacy consent is explicit", async () => {
    vi.useFakeTimers();
    const previewPromise = new FixtureAdapter(createDemoState()).previewAnalysis({
      productId: DEMO_IDS.homeHub,
      version: "1.8.1",
      channel: "stable",
      inputKind: "raw_artifact",
      fileName: "home-hub-1.8.1.zip",
      fileSize: 900_000,
      rawArtifactConsent: false,
    });
    await vi.advanceTimersByTimeAsync(180);
    await expect(previewPromise).resolves.toMatchObject({ valid: false, warnings: ["Confirm raw-artifact processing before continuing."] });
  });
});
