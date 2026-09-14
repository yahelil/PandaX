import { describe, expect, it, vi } from "vitest";

import { createDemoState } from "./fixtures";
import { FixtureAdapter } from "./fixtureAdapter";
import type { PortfolioApi } from "./portfolioApi";
import { PortfolioApiError } from "./portfolioApi";
import { createRuntimeDataAdapter, ProductionAdapter } from "./productionAdapter";
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

describe("ProductionAdapter", () => {
  it("keeps identical fixture mode unless every runtime setting exists", () => {
    expect(createRuntimeDataAdapter({}).getStatusSnapshot()).toEqual({ mode: "fixture", phase: "ready" });
    expect(createRuntimeDataAdapter({ apiUrl: "/api", organizationId: "organization-live" }).getStatusSnapshot()).toEqual({ mode: "fixture", phase: "ready" });
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
});
