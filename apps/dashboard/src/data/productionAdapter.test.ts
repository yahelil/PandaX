import { describe, expect, it, vi } from "vitest";

import { createDemoState } from "./fixtures";
import { FixtureAdapter } from "./fixtureAdapter";
import type { PortfolioApi } from "./portfolioApi";
import { PortfolioApiError } from "./portfolioApi";
import type { OperationsApi } from "./operationsApi";
import { createRuntimeDataAdapter, ProductionAdapter } from "./productionAdapter";
import type { ReleaseAnalysisJob, ReleaseMonitoringStatus, ReleaseOperationsApi } from "./releaseOperationsApi";
import type { Organization, Product, Release } from "./types";

const organization: Organization = {
  id: "organization-live",
  name: "Live Devices",
  legalName: "Live Devices GmbH",
  country: "DE",
  registrationNumber: "HRB-7001",
  defaultTimezone: "Europe/Berlin",
};

const product: Product = {
  id: "product-live",
  slug: "live-gateway",
  name: "Live Gateway",
  identifier: "LIVE-GTW-1",
  manufacturer: "Live Devices GmbH",
  description: "Industrial edge gateway monitored by Actis.",
  craClass: "important_i",
  classificationStatus: "confirmed",
  supportUntil: "2032-01-01",
  readiness: "needs_attention",
  monitoringHealth: "healthy",
  activeReleaseId: "release-live",
  actionCount: 1,
  tags: ["gateway"],
  createdAt: "2026-09-01T08:00:00Z",
};

const release: Release = {
  id: "release-live",
  productId: product.id,
  version: "4.2.0",
  channel: "stable",
  status: "active",
  releaseDate: "2026-09-01",
  supportedUntil: "2032-01-01",
  readiness: "needs_attention",
  monitoringHealth: "healthy",
  sbomStatus: "validated",
  coverage: { components: 88, identifiedComponents: 87, advisorySourcesChecked: 4, advisorySourcesExpected: 4, limitations: [] },
  artifacts: [],
  createdAt: "2026-09-01T08:00:00Z",
};

function api(overrides: Partial<PortfolioApi> = {}): PortfolioApi {
  return {
    listOrganizations: vi.fn(async () => [organization]),
    createOrganization: vi.fn(async () => organization),
    getOrganization: vi.fn(async () => organization),
    updateOrganization: vi.fn(async () => organization),
    listProducts: vi.fn(async () => [product]),
    createProduct: vi.fn(async () => product),
    getProduct: vi.fn(async () => product),
    updateProduct: vi.fn(async () => product),
    listReleases: vi.fn(async () => [release]),
    createRelease: vi.fn(async () => release),
    getRelease: vi.fn(async () => release),
    updateRelease: vi.fn(async () => release),
    ...overrides,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function releaseOperations(job: ReleaseAnalysisJob): ReleaseOperationsApi {
  const unsupported = vi.fn(async () => { throw new Error("not used"); });
  return {
    uploadSbom: vi.fn(async () => job),
    uploadAnalysisInput: vi.fn(async () => job),
    listAnalysisJobs: vi.fn(async () => [job]),
    getAnalysisJob: vi.fn(async () => job),
    runAnalysisJob: vi.fn(async () => job),
    listAnalysisEvents: vi.fn(async () => []),
    downloadEvidence: vi.fn(async () => ({ blob: new Blob(), contentType: "application/json" })),
    getMonitoring: unsupported,
    configureMonitoring: unsupported,
    runMonitoring: unsupported,
    listMonitoringEvents: vi.fn(async () => []),
  };
}

describe("ProductionAdapter", () => {
  it("keeps identical fixture mode unless every runtime setting exists", () => {
    expect(createRuntimeDataAdapter({ mode: "demo" }).getStatusSnapshot()).toEqual({ mode: "fixture", phase: "ready" });
    expect(() => createRuntimeDataAdapter({ mode: "production", apiUrl: "/api", organizationId: "organization-live" })).toThrow(/authenticated token provider/);
  });

  it("hydrates portfolio atomically while preserving not-yet-migrated domains", async () => {
    const initial = createDemoState();
    const adapter = new ProductionAdapter({
      organizationId: organization.id,
      portfolioApi: api(),
      fixtureAdapter: new FixtureAdapter(initial),
    });

    await adapter.initialize();

    expect(adapter.getSnapshot()).toMatchObject({ organization, products: [product], releases: [release] });
    expect(adapter.getSnapshot().findings).toEqual(initial.findings);
    expect(adapter.getSnapshot().complianceItems).toEqual(initial.complianceItems);
    expect(adapter.getSnapshot().documents).toEqual(initial.documents);
    expect(adapter.getSnapshot().settings).toEqual(initial.settings);
    expect(adapter.getStatusSnapshot()).toMatchObject({ mode: "production", phase: "ready" });
  });

  it("retains the production Home counters and monitoring summary", async () => {
    const home = {
      organizationId: organization.id,
      generatedAt: "2026-09-14T10:00:00Z",
      monitoring: { state: "stale" as const, supportedReleases: 4, configured: 3, healthy: 1, degraded: 1, failed: 0, stale: 1, inactive: 0, notConfigured: 1 },
      counters: { actionTotal: 9, findingsNeedingAction: 3, urgentFindings: 2, reachableKevFindings: 1, complianceActions: 4, overdueObligations: 1, dueSoonObligations: 2, missingEvidence: 1, pendingApprovals: 1, documentsNeedingAction: 1, monitoringIssues: 2 },
      actionQueue: [], recentChanges: [], dataWarnings: ["One release has stale monitoring data."],
    };
    const operationsApi = {
      getHome: vi.fn(async () => home),
      search: vi.fn(async () => ({ query: "", total: 0, groups: [] })),
      listNotifications: vi.fn(async () => []),
      markRead: vi.fn(), acknowledge: vi.fn(),
    } as unknown as OperationsApi;
    const adapter = new ProductionAdapter({ organizationId: organization.id, portfolioApi: api(), operationsApi, fixtureAdapter: new FixtureAdapter(createDemoState()) });

    await adapter.initialize();

    expect(adapter.getSnapshot().home).toEqual({ generatedAt: home.generatedAt, monitoring: home.monitoring, counters: home.counters, dataWarnings: home.dataWarnings });
  });

  it("retains existing read model and exposes typed state when hydration fails", async () => {
    const initial = createDemoState();
    const adapter = new ProductionAdapter({
      organizationId: organization.id,
      portfolioApi: api({ listProducts: vi.fn(async () => { throw new PortfolioApiError("Access denied", "forbidden", 403); }) }),
      fixtureAdapter: new FixtureAdapter(initial),
    });

    await adapter.initialize();

    expect(adapter.getSnapshot().products).toEqual(initial.products);
    expect(adapter.getStatusSnapshot()).toMatchObject({
      mode: "production",
      phase: "error",
      failure: { operation: "initialize", code: "forbidden", message: "Access denied", status: 403 },
    });
  });

  it("writes product remotely before updating the local read model", async () => {
    const pending = deferred<Product>();
    const portfolioApi = api({ createProduct: vi.fn(() => pending.promise) });
    const adapter = new ProductionAdapter({ organizationId: organization.id, portfolioApi, fixtureAdapter: new FixtureAdapter(createDemoState()) });

    const result = adapter.createProduct({
      name: product.name,
      identifier: product.identifier,
      manufacturer: product.manufacturer,
      craClass: product.craClass,
      classificationStatus: product.classificationStatus,
      supportUntil: product.supportUntil,
    });
    expect(adapter.getSnapshot().products.some((item) => item.id === product.id)).toBe(false);
    pending.resolve(product);

    await expect(result).resolves.toEqual(product);
    expect(adapter.getSnapshot().products).toContainEqual(product);
    expect(portfolioApi.createProduct).toHaveBeenCalledWith(organization.id, expect.objectContaining({
      supportEnd: product.supportUntil,
      classificationStatus: "confirmed",
    }));
  });

  it("does not mutate portfolio after rejected creates and records operation failure", async () => {
    const initial = createDemoState();
    const expected = new PortfolioApiError("Identifier exists", "conflict", 409);
    const adapter = new ProductionAdapter({
      organizationId: organization.id,
      portfolioApi: api({ createRelease: vi.fn(async () => { throw expected; }) }),
      fixtureAdapter: new FixtureAdapter(initial),
    });

    await expect(adapter.createRelease({
      productId: initial.products[0].id,
      version: "9.1.0",
      channel: "stable",
      releaseDate: "2026-09-14",
      supportedUntil: "2031-12-31",
    })).rejects.toBe(expected);

    expect(adapter.getSnapshot().releases).toEqual(initial.releases);
    expect(adapter.getStatusSnapshot()).toMatchObject({
      phase: "error",
      failure: { operation: "create_release", code: "conflict", status: 409 },
    });
  });

  it("uploads an SBOM once and maps the completed production analysis", async () => {
    const initial = createDemoState();
    const productId = initial.products[0].id;
    const releaseId = initial.releases.find((item) => item.productId === productId)!.id;
    const completed: ReleaseAnalysisJob = {
      id: "analysis-live", organizationId: organization.id, productId, releaseId,
      inputType: "sbom",
      filename: "sbom.cdx.json", mediaType: "application/json", sizeBytes: 2,
      sha256: "a".repeat(64),
      preview: { format: "CycloneDX", version: "1.6", components: 42, matchableComponents: 40, skippedComponents: 2, product: {} },
      inputMetadata: {},
      status: "completed", stage: "Analysis complete", progress: 100,
      result: { components: 42, findings: 5, kev: 1, incidents: 0, inputFormat: "CycloneDX", inputVersion: "1.6", coverageSummary: { new_findings: 3, changed_findings: 2, advisory_sources_checked: 4, advisory_sources_expected: 5 }, evidence: [] },
      createdAt: "2026-09-14T08:00:00Z", updatedAt: "2026-09-14T08:01:00Z", completedAt: "2026-09-14T08:01:00Z",
    };
    const releaseApi = releaseOperations(completed);
    const adapter = new ProductionAdapter({ organizationId: organization.id, portfolioApi: api(), releaseOperationsApi: releaseApi, fixtureAdapter: new FixtureAdapter(initial) });
    const file = new Blob(["{}"], { type: "application/json" });
    const draft = { productId, releaseId, version: "1.0.0", channel: "stable" as const, inputKind: "sbom" as const, fileName: "sbom.cdx.json", fileSize: file.size, file };

    await expect(adapter.previewAnalysis(draft)).resolves.toMatchObject({ valid: true, componentCount: 42, identifiedComponentCount: 40, digest: "a".repeat(64) });
    await expect(adapter.runAnalysis(draft)).resolves.toMatchObject({ id: "analysis-live", status: "completed", result: { newFindings: 3, changedFindings: 2, componentCount: 42 } });
    expect(releaseApi.uploadSbom).toHaveBeenCalledTimes(1);
    expect(releaseApi.runAnalysisJob).toHaveBeenCalledWith({ organizationId: organization.id, productId, releaseId }, "analysis-live");
    expect(adapter.getSnapshot().analysisJobs[0].result?.coverage).toMatchObject({ identifiedComponents: 40, advisorySourcesChecked: 4, advisorySourcesExpected: 5 });
  });

  it("uploads Collector inputs through production instead of falling back to fixtures", async () => {
    const initial = createDemoState();
    const productId = initial.products[0].id;
    const releaseId = initial.releases.find((item) => item.productId === productId)!.id;
    const job: ReleaseAnalysisJob = {
      id: "collector-live", organizationId: organization.id, productId, releaseId, inputType: "collector",
      filename: "collector.zip", mediaType: "application/zip", sizeBytes: 3, sha256: "b".repeat(64),
      preview: { format: "CycloneDX", version: "1.6", components: 8, matchableComponents: 8, skippedComponents: 0, product: {}, collector: { name: "Actis Collector" } },
      inputMetadata: { schema: "actis.collector/v1" }, status: "queued", stage: "Validation complete", progress: 0,
      createdAt: "2026-09-14T08:00:00Z", updatedAt: "2026-09-14T08:00:00Z",
    };
    const releaseApi = releaseOperations(job);
    const adapter = new ProductionAdapter({ organizationId: organization.id, portfolioApi: api(), releaseOperationsApi: releaseApi, fixtureAdapter: new FixtureAdapter(initial) });
    const file = new Blob(["zip"], { type: "application/zip" });
    const draft = { productId, releaseId, version: "1.0.0", channel: "stable" as const, inputKind: "collector_package" as const, fileName: "collector.zip", fileSize: file.size, file };

    await expect(adapter.previewAnalysis(draft)).resolves.toMatchObject({ valid: true, componentCount: 8, warnings: [] });

    expect(releaseApi.uploadAnalysisInput).toHaveBeenCalledWith(
      { organizationId: organization.id, productId, releaseId },
      expect.objectContaining({ inputType: "collector", filename: "collector.zip" }),
    );
    expect(releaseApi.uploadSbom).not.toHaveBeenCalled();
  });

  it("does not reuse an uploaded analysis when selected bytes change without changing name or size", async () => {
    const initial = createDemoState();
    const productId = initial.products[0].id;
    const releaseId = initial.releases.find((item) => item.productId === productId)!.id;
    const base: ReleaseAnalysisJob = {
      id: "analysis-a", organizationId: organization.id, productId, releaseId, inputType: "sbom",
      filename: "release.cdx.json", mediaType: "application/json", sizeBytes: 2, sha256: "a".repeat(64),
      preview: { format: "CycloneDX", version: "1.6", components: 1, matchableComponents: 1, skippedComponents: 0, product: {} },
      inputMetadata: {}, status: "queued", stage: "Validation complete", progress: 0,
      createdAt: "2026-09-14T08:00:00Z", updatedAt: "2026-09-14T08:00:00Z",
    };
    const releaseApi = releaseOperations(base);
    vi.mocked(releaseApi.uploadSbom)
      .mockResolvedValueOnce(base)
      .mockResolvedValueOnce({ ...base, id: "analysis-b", sha256: "b".repeat(64) });
    const adapter = new ProductionAdapter({ organizationId: organization.id, portfolioApi: api(), releaseOperationsApi: releaseApi, fixtureAdapter: new FixtureAdapter(initial) });
    const first = new Blob(["aa"], { type: "application/json" });
    const second = new Blob(["bb"], { type: "application/json" });
    const draft = { productId, releaseId, version: "1.0.0", channel: "stable" as const, inputKind: "sbom" as const, fileName: "release.cdx.json", fileSize: 2 };

    await expect(adapter.previewAnalysis({ ...draft, file: first })).resolves.toMatchObject({ digest: "a".repeat(64) });
    await expect(adapter.previewAnalysis({ ...draft, file: second })).resolves.toMatchObject({ digest: "b".repeat(64) });

    expect(releaseApi.uploadSbom).toHaveBeenCalledTimes(2);
  });

  it("restores persisted analysis jobs and resumes polling after reload", async () => {
    vi.useFakeTimers();
    try {
      const running: ReleaseAnalysisJob = {
        id: "analysis-running", organizationId: organization.id, productId: product.id, releaseId: release.id, inputType: "sbom",
        filename: "live.cdx.json", mediaType: "application/json", sizeBytes: 2, sha256: "c".repeat(64),
        preview: { format: "CycloneDX", version: "1.6", components: 1, matchableComponents: 1, skippedComponents: 0, product: {} },
        inputMetadata: {}, status: "running", stage: "Matching advisories", progress: 60,
        createdAt: "2026-09-14T08:00:00Z", updatedAt: "2026-09-14T08:00:30Z", startedAt: "2026-09-14T08:00:01Z",
      };
      const completed: ReleaseAnalysisJob = { ...running, status: "completed", stage: "Analysis complete", progress: 100, completedAt: "2026-09-14T08:01:00Z", result: { components: 1, findings: 0, kev: 0, incidents: 0, inputFormat: "CycloneDX", inputVersion: "1.6", coverageSummary: {}, evidence: [] } };
      const releaseApi = releaseOperations(running);
      releaseApi.getAnalysisJob = vi.fn(async () => completed);
      const adapter = new ProductionAdapter({ organizationId: organization.id, portfolioApi: api(), releaseOperationsApi: releaseApi, fixtureAdapter: new FixtureAdapter(createDemoState()) });

      await adapter.initialize();
      expect(adapter.getAnalysisJob(running.id)).toMatchObject({ id: running.id, status: "analyzing", draft: { inputKind: "sbom", fileName: "live.cdx.json" } });
      await vi.advanceTimersByTimeAsync(801);
      expect(adapter.getAnalysisJob(running.id)).toMatchObject({ status: "completed", result: { componentCount: 1 } });
    } finally {
      vi.useRealTimers();
    }
  });

  it("loads and runs persisted release monitoring with event history", async () => {
    const monitoring: ReleaseMonitoringStatus = {
      organizationId: organization.id, productId: product.id, releaseId: release.id,
      enabledSources: ["osv", "cisa_kev"], cadenceMinutes: 60, enabled: true,
      health: "degraded" as const, nextCheckAt: "2026-09-14T12:00:00Z", lastCheckAt: "2026-09-14T11:00:00Z", lastSuccessAt: "2026-09-14T10:00:00Z",
      consecutiveFailures: 0, coverage: { checked: 2 }, limitations: ["Vendor source delayed."], running: false,
      createdAt: "2026-09-14T08:00:00Z", updatedAt: "2026-09-14T11:00:00Z",
    };
    const event = { id: "event-1", runId: "run-1", sequence: 1, eventType: "succeeded" as const, trigger: "manual" as const, health: "degraded" as const, coverage: {}, limitations: monitoring.limitations, message: "Monitoring completed with limitations.", actorId: "user-1", occurredAt: "2026-09-14T11:00:00Z" };
    const releaseApi = releaseOperations({} as ReleaseAnalysisJob);
    releaseApi.getMonitoring = vi.fn(async () => monitoring);
    releaseApi.runMonitoring = vi.fn(async () => monitoring);
    releaseApi.listMonitoringEvents = vi.fn(async () => [event]);
    const adapter = new ProductionAdapter({ organizationId: organization.id, portfolioApi: api(), releaseOperationsApi: releaseApi, fixtureAdapter: new FixtureAdapter(createDemoState()) });

    await expect(adapter.loadReleaseMonitoring(product.id, release.id)).resolves.toMatchObject({ health: "degraded", enabledSources: ["osv", "cisa_kev"], recentEvents: [{ id: "event-1", trigger: "manual" }] });
    await expect(adapter.runReleaseMonitoring(product.id, release.id)).resolves.toMatchObject({ lastCheckAt: monitoring.lastCheckAt, limitations: monitoring.limitations });
    expect(releaseApi.runMonitoring).toHaveBeenCalledWith({ organizationId: organization.id, productId: product.id, releaseId: release.id });
  });
});
