import { describe, expect, it, vi } from "vitest";

import { featureUsed, pageViewed } from "./analytics";
import { createDemoState } from "./fixtures";
import { FixtureAdapter } from "./fixtureAdapter";
import { GovernanceApiError, type GovernanceApi, type GovernanceSettingsDto } from "./governanceApi";
import type { OperationsApi, OperationsHome, OperationsNotification } from "./operationsApi";
import type { PortfolioApi } from "./portfolioApi";
import { ProductionAdapter } from "./productionAdapter";

const initial = createDemoState();
const organization = initial.organization;

function portfolioApi(): PortfolioApi {
  return {
    listOrganizations: vi.fn(async () => [organization]),
    createOrganization: vi.fn(async () => organization),
    getOrganization: vi.fn(async () => organization),
    updateOrganization: vi.fn(async () => organization),
    listProducts: vi.fn(async () => []),
    createProduct: vi.fn(async () => initial.products[0]),
    getProduct: vi.fn(async () => initial.products[0]),
    updateProduct: vi.fn(async () => initial.products[0]),
    archiveProduct: vi.fn(async () => {}),
    listReleases: vi.fn(async () => []),
    createRelease: vi.fn(async () => initial.releases[0]),
    getRelease: vi.fn(async () => initial.releases[0]),
    updateRelease: vi.fn(async () => initial.releases[0]),
  };
}

function settings(enabled: boolean): GovernanceSettingsDto {
  return {
    organizationId: organization.id,
    version: 1,
    organizationProfile: {
      name: organization.name,
      legalName: organization.legalName,
      country: organization.country,
      registrationNumber: organization.registrationNumber,
      timezone: organization.defaultTimezone,
    },
    notifications: initial.settings.notifications,
    security: initial.settings.security,
    appearance: initial.settings.appearance,
    analytics: { enabled, retentionDays: 90 },
  };
}

function governanceApi(enabled: boolean, ingest = vi.fn(async () => ({ accepted: 1, dropped: 0 }))): GovernanceApi {
  return {
    listCompliance: vi.fn(async () => []),
    listDocuments: vi.fn(async () => []),
    getSettings: vi.fn(async () => settings(enabled)),
    listTeam: vi.fn(async () => []),
    listIntegrations: vi.fn(async () => []),
    ingestAnalytics: ingest,
  } as unknown as GovernanceApi;
}

describe("analytics event flow", () => {
  it("captures deterministic safe fixture events and honors opt-out", () => {
    const fixture = new FixtureAdapter(createDemoState(), false);
    fixture.trackAnalytics({
      ...featureUsed("search", "2026-09-14T10:00:00Z"),
      properties: { feature: "search", query: "jane@acme.test", token: "secret" },
    } as never);

    expect(fixture.getTrackedAnalytics()).toEqual([featureUsed("search", "2026-09-14T10:00:00Z")]);
    fixture.updateSettings("analytics", { enabled: false });
    fixture.trackAnalytics(pageViewed("home", "2026-09-14T10:01:00Z"));
    expect(fixture.getTrackedAnalytics()).toHaveLength(1);
  });

  it("waits for explicit production consent and exposes delivery failure without blocking", async () => {
    const ingest = vi.fn(async () => ({ accepted: 1, dropped: 0 }));
    const governance = governanceApi(true, ingest);
    const adapter = new ProductionAdapter({ organizationId: organization.id, portfolioApi: portfolioApi(), governanceApi: governance, fixtureAdapter: new FixtureAdapter(createDemoState(), false) });
    const event = pageViewed("home", "2026-09-14T10:00:00Z");

    await adapter.trackAnalytics(event);
    expect(ingest).not.toHaveBeenCalled();
    await adapter.initialize();
    await adapter.trackAnalytics({ ...event, properties: { area: "home", email: "jane@acme.test" } } as never);
    expect(ingest).toHaveBeenCalledWith(organization.id, [event]);

    ingest.mockRejectedValueOnce(new GovernanceApiError("offline", "network"));
    await expect(adapter.trackAnalytics(event)).resolves.toBeUndefined();
    expect(adapter.getStatusSnapshot()).toMatchObject({
      phase: "ready",
      analyticsFailure: { code: "network" },
    });
  });

  it("does not emit production events when organization analytics is disabled", async () => {
    const ingest = vi.fn(async () => ({ accepted: 1, dropped: 0 }));
    const adapter = new ProductionAdapter({ organizationId: organization.id, portfolioApi: portfolioApi(), governanceApi: governanceApi(false, ingest), fixtureAdapter: new FixtureAdapter(createDemoState(), false) });
    await adapter.initialize();
    await adapter.trackAnalytics(pageViewed("products", "2026-09-14T10:00:00Z"));
    expect(ingest).not.toHaveBeenCalled();
  });
});

const home: OperationsHome = {
  organizationId: organization.id,
  generatedAt: "2026-09-14T10:00:00Z",
  monitoring: { state: "healthy", supportedReleases: 1, configured: 1, healthy: 1, degraded: 0, failed: 0, stale: 0, inactive: 0, notConfigured: 0, cadenceMinutes: [60], sources: [{ source: "osv", state: "healthy", releaseCount: 1 }] },
  counters: { actionTotal: 1, findingsNeedingAction: 1, urgentFindings: 1, reachableKevFindings: 0, complianceActions: 0, overdueObligations: 0, dueSoonObligations: 0, missingEvidence: 0, pendingApprovals: 0, documentsNeedingAction: 0, monitoringIssues: 0 },
  actionQueue: [],
  recentChanges: [],
  dataWarnings: [],
};

const notification: OperationsNotification = {
  id: "notification-live", organizationId: organization.id, sourceFingerprint: "finding:critical",
  kind: "finding", priority: "critical", title: "Critical finding requires review", detail: "Review the new finding.",
  targetUrl: "/findings/finding-live", requiresAction: true,
  firstSeenAt: "2026-09-14T09:00:00Z", lastSeenAt: "2026-09-14T09:00:00Z",
  createdAt: "2026-09-14T09:00:00Z", updatedAt: "2026-09-14T09:00:00Z",
};

describe("production search and notification interactions", () => {
  it("uses backend search and read semantics without putting the workspace into loading state", async () => {
    const marked = { ...notification, readAt: "2026-09-14T10:02:00Z" };
    const operations = {
      getHome: vi.fn(async () => home),
      listNotifications: vi.fn(async () => [notification]),
      search: vi.fn(async () => ({ query: "camera", total: 1, groups: [{ category: "products" as const, results: [{ category: "products" as const, id: "product-live", title: "Smart Camera", subtitle: "CAM-200", productId: "product-live", rank: 0, url: "/products/product-live" }] }] })),
      markRead: vi.fn(async () => marked),
      acknowledge: vi.fn(async () => ({ ...marked, acknowledgedAt: "2026-09-14T10:03:00Z" })),
    } as unknown as OperationsApi;
    const adapter = new ProductionAdapter({ organizationId: organization.id, portfolioApi: portfolioApi(), operationsApi: operations, fixtureAdapter: new FixtureAdapter(createDemoState(), false) });
    await adapter.initialize();

    await expect(adapter.search("camera")).resolves.toEqual([expect.objectContaining({ type: "Product", title: "Smart Camera" })]);
    expect(adapter.getStatusSnapshot().phase).toBe("ready");
    await adapter.markNotificationRead(notification.id);
    expect(operations.markRead).toHaveBeenCalledWith(organization.id, notification.id);
    expect(adapter.getSnapshot().notifications[0]).toMatchObject({ id: notification.id, readAt: expect.any(String) });
  });
});
