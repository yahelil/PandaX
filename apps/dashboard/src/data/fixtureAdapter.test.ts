import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createDemoState, DEMO_IDS } from "./fixtures";
import { FixtureAdapter } from "./fixtureAdapter";
import type { AnalysisDraft, Finding } from "./types";

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

  it("generates a release-specific security PDF in the local demo", async () => {
    const adapter = new FixtureAdapter(createDemoState());
    const release = adapter.getSnapshot().releases.find((item) => item.productId === DEMO_IDS.homeHub)!;
    const file = await adapter.generateSecurityPdf(DEMO_IDS.homeHub, release.id);
    const content = await file.blob.text();
    expect(file.contentType).toBe("application/pdf");
    expect(content.startsWith("%PDF-1.4")).toBe(true);
    expect(content).toContain("/Type /Pages");
    expect(content).toContain("Home Hub");
    expect(content).toContain(release.version);
    await expect(adapter.generateSecurityPdf(DEMO_IDS.homeHub, DEMO_IDS.cameraRelease)).rejects.toThrow("Release not found");
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

  it("exports a release findings report after a review decision", async () => {
    const adapter = new FixtureAdapter(createDemoState());
    const findingId = "finding-hub-cve-2026-27102";
    const finding = adapter.recordFindingDecision({
      findingId, decision: "affected", rationale: "Release image contains the vulnerable path.",
    });
    const file = await adapter.generateFindingsReport(finding.productId, finding.releaseId);
    const report = JSON.parse(await file.blob.text());
    expect(file.filename).toContain("findings-report.json");
    expect(report.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ reference: finding.reference, decision: "affected", status: "action_required" }),
    ]));
  });

  it("downloads a generated analysis PDF", async () => {
    const adapter = new FixtureAdapter(createDemoState());
    const job = adapter.getSnapshot().analysisJobs.find((item) => item.result?.evidence?.length);
    const evidence = job?.result?.evidence?.[0];
    expect(job && evidence).toBeTruthy();

    const file = await adapter.downloadAnalysisEvidence(job!.draft.productId!, job!.draft.releaseId!, job!.id, evidence!.sha256);
    expect(file).toMatchObject({ contentType: "application/pdf", filename: evidence!.name.replace(/\.pdf$/i, "-draft.pdf") });
    expect(await file.blob.slice(0, 5).text()).toBe("%PDF-");
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

  it("rejects Collector archives instead of inventing analysis results", async () => {
    vi.useFakeTimers();
    const adapter = new FixtureAdapter(createDemoState());
    const file = new Blob(["not-a-real-collector-package"], { type: "application/zip" });
    const draft: AnalysisDraft = {
      productId: DEMO_IDS.thermostat,
      releaseId: DEMO_IDS.thermostatRelease,
      version: "3.0.0",
      channel: "stable",
      inputKind: "collector_package",
      fileName: "thermostat-3.0.0.collector.zip",
      fileSize: file.size,
      file,
    };

    const previewPromise = adapter.previewAnalysis(draft);
    await vi.advanceTimersByTimeAsync(180);
    const preview = await previewPromise;
    expect(preview).toMatchObject({ valid: false, detectedFormat: "Not inspected", componentCount: 0, identifiedComponentCount: 0 });
    expect(preview.warnings[0]).toContain("require the production engine");
  });

  it("creates release-scoped findings from an uploaded SBOM", async () => {
    vi.useFakeTimers();
    const matched: Finding[] = [{
      id: "finding-upload-ghsa-29mw-wpgm-hmr9",
      reference: "GHSA-29mw-wpgm-hmr9",
      productId: DEMO_IDS.thermostat,
      releaseId: DEMO_IDS.thermostatRelease,
      title: "Prototype pollution in lodash",
      component: "lodash",
      componentVersion: "4.17.19",
      severity: "high",
      cvss: 7.4,
      status: "needs_review",
      priority: "high",
      kev: false,
      activelyExploited: false,
      affectedness: "unknown",
      reachability: "unknown",
      reachabilityRecommendation: "review",
      reachabilityConfidence: "low",
      reachabilityReasonCodes: ["sbom_component_match"],
      reachabilityReviewRequired: true,
      summary: "OSV returned this advisory for the exact versioned Package URL.",
      actionReason: "Review affectedness and runtime reachability.",
      introducedAt: "2026-09-16T00:00:00.000Z",
      updatedAt: "2026-09-16T00:00:00.000Z",
      decisions: [],
      remediation: { status: "not_started" },
      evidenceIds: [],
    }];
    const analyzer = vi.fn(async () => ({ components: 1, matchableComponents: 1, findings: matched }));
    const adapter = new FixtureAdapter(createDemoState(), false, analyzer);
    const file = new Blob([JSON.stringify({
      bomFormat: "CycloneDX", specVersion: "1.2",
      components: [{ name: "lodash", version: "4.17.19", purl: "pkg:npm/lodash@4.17.19" }],
    })], { type: "application/json" });

    const run = adapter.runAnalysis({
      productId: DEMO_IDS.thermostat,
      releaseId: DEMO_IDS.thermostatRelease,
      version: "3.0.0",
      channel: "stable",
      inputKind: "sbom",
      fileName: "bom.json",
      fileSize: file.size,
      file,
    });
    await vi.advanceTimersByTimeAsync(180);
    const queued = await run;
    await vi.advanceTimersByTimeAsync(1_450);

    expect(analyzer).toHaveBeenCalledWith(file, DEMO_IDS.thermostat, DEMO_IDS.thermostatRelease);
    expect(adapter.getAnalysisJob(queued.id)?.result?.newFindings).toBe(1);
    expect(adapter.getAnalysisJob(queued.id)?.result?.coverage).toMatchObject({ advisorySourcesChecked: 1, advisorySourcesExpected: 4 });
    expect(adapter.getSnapshot().releases.find((item) => item.id === DEMO_IDS.thermostatRelease)).toMatchObject({ monitoringHealth: "inactive", readiness: "incomplete_evidence" });
    expect(adapter.getSnapshot().findings).toContainEqual(expect.objectContaining({
      reference: "GHSA-29mw-wpgm-hmr9",
      productId: DEMO_IDS.thermostat,
      releaseId: DEMO_IDS.thermostatRelease,
    }));
  });

  it("reports demo monitoring as unavailable without creating events", async () => {
    const adapter = new FixtureAdapter(createDemoState(), false);
    const release = adapter.getSnapshot().releases[0];

    const before = await adapter.loadReleaseMonitoring(release.productId, release.id);
    const activityCount = adapter.getSnapshot().activities.length;

    expect(before).toMatchObject({ enabled: false, health: "inactive", enabledSources: [], recentEvents: [] });
    await expect(adapter.runReleaseMonitoring(release.productId, release.id)).rejects.toThrow("unavailable in demo mode");
    expect(adapter.getSnapshot().activities).toHaveLength(activityCount);
  });

  it("rejects raw artifacts because demo mode cannot inspect them", async () => {
    vi.useFakeTimers();
    const file = new Blob(["archive"], { type: "application/zip" });
    const previewPromise = new FixtureAdapter(createDemoState()).previewAnalysis({
      productId: DEMO_IDS.homeHub,
      version: "1.8.1",
      channel: "stable",
      inputKind: "raw_artifact",
      fileName: "home-hub-1.8.1.zip",
      fileSize: file.size,
      file,
      rawArtifactConsent: true,
    });
    await vi.advanceTimersByTimeAsync(180);
    await expect(previewPromise).resolves.toMatchObject({ valid: false, componentCount: 0, warnings: [expect.stringContaining("require the production engine")] });
  });

  it("automatically generates documents when an analysis completes and transitions to approval when remediated", async () => {
    vi.useFakeTimers();
    const analyzer = vi.fn(async () => ({ components: 1, matchableComponents: 1, findings: [] }));
    const adapter = new FixtureAdapter(createDemoState(), false, analyzer);
    const product = await adapter.createProduct({
      name: "GuyTest",
      identifier: "guy-test",
      manufacturer: "Acme",
      description: "Test device",
      craClass: "default",
      classificationStatus: "confirmed",
      ownerId: DEMO_IDS.jane,
    });
    const release = await adapter.createRelease({
      productId: product.id,
      version: "1.0.0",
      channel: "stable",
      releaseDate: "2026-09-17",
      supportedUntil: "2028-09-17",
    });

    const file = new File(
      [
        JSON.stringify({
          bomFormat: "CycloneDX",
          specVersion: "1.6",
          components: [{ name: "test-lib", version: "1.0.0", purl: "pkg:npm/test-lib@1.0.0" }],
        }),
      ],
      "bom.json",
      { type: "application/json" }
    );
    const run = adapter.runAnalysis({
      productId: product.id,
      releaseId: release.id,
      version: "1.0.0",
      channel: "stable",
      inputKind: "sbom",
      fileName: "bom.json",
      fileSize: file.size,
      file,
    });

    await vi.advanceTimersByTimeAsync(180);
    await run;
    await vi.advanceTimersByTimeAsync(1_500);

    const docs = adapter.getSnapshot().documents.filter((d) => d.productId === product.id);
    expect(docs).toHaveLength(2);
    expect(docs.map((d) => d.type).sort()).toEqual(["conformity", "cra_reporting_pack"].sort());
    expect(docs.every((d) => d.status === "approval_required")).toBe(true);

    const doc = docs.find((d) => d.type === "conformity")!;
    const download = await adapter.downloadDocument(doc.id, doc.version);
    expect(download.blob.size).toBeGreaterThan(0);
    expect(download.filename).toContain("eu-declaration-of-conformity");
  });
});
