import { describe, expect, it, vi } from "vitest";

import { createPortfolioApi, PortfolioApiError } from "./portfolioApi";

const organizationDto = {
  id: "org/acme",
  name: "Acme Devices",
  legal_name: "Acme Devices GmbH",
  country: "DE",
  registration_number: "HRB-20481",
  timezone: "Europe/Berlin",
  created_at: "2026-09-01T08:00:00Z",
  updated_at: "2026-09-12T09:30:00Z",
};

const productDto = {
  id: "product-camera",
  organization_id: "org/acme",
  slug: "smart-camera",
  identifier: "ACME-CAM-2",
  name: "Smart Camera",
  manufacturer: "Acme Devices GmbH",
  description: "Connected indoor security camera.",
  cra_class: "important_i",
  classification_status: "confirmed",
  support_start: "2026-01-10",
  support_end: "2031-01-10",
  owner_id: "member-jane",
  readiness: "ready",
  monitoring_health: "healthy",
  active_release_id: "release-2.1",
  created_at: "2026-01-10T08:00:00Z",
  updated_at: "2026-09-12T09:30:00Z",
  action_count: 2,
  next_deadline: "2026-10-12T09:00:00Z",
  tags: ["hardware", "camera"],
};

const releaseDto = {
  id: "release-2.1",
  organization_id: "org/acme",
  product_id: "product-camera",
  version: "2.1.0",
  channel: "stable",
  status: "active",
  release_date: "2026-09-01",
  support_start: "2026-09-01",
  support_end: "2031-01-10",
  owner_id: "member-jane",
  readiness: "ready",
  monitoring_health: "healthy",
  sbom_status: "validated",
  created_at: "2026-09-01T08:00:00Z",
  updated_at: "2026-09-12T09:30:00Z",
  coverage: {
    components: 142,
    identified_components: 140,
    advisory_sources_checked: 7,
    advisory_sources_expected: 7,
    limitations: ["Two proprietary firmware modules lack package identifiers."],
  },
  last_analysis_at: "2026-09-12T09:30:00Z",
  last_monitoring_check_at: null,
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function fetchSequence(...responses: Response[]) {
  return vi.fn<typeof fetch>(async () => {
    const response = responses.shift();
    if (!response) throw new Error("unexpected fetch");
    return response;
  });
}

describe("portfolio API", () => {
  it("adds async bearer auth, encodes tenant paths, and maps backend fields", async () => {
    const fetcher = fetchSequence(json([productDto]), json(releaseDto));
    const client = createPortfolioApi({
      baseUrl: "https://engine.example.test/",
      getBearerToken: async () => " signed-token ",
      fetch: fetcher,
    });

    const products = await client.listProducts("org/acme");
    const release = await client.getRelease("org/acme", "camera product", "release/2.1");

    expect(fetcher).toHaveBeenNthCalledWith(1, "https://engine.example.test/v1/organizations/org%2Facme/products", expect.objectContaining({ method: "GET" }));
    const firstInit = fetcher.mock.calls[0][1] as RequestInit;
    expect(new Headers(firstInit.headers).get("Authorization")).toBe("Bearer signed-token");
    expect(products[0]).toMatchObject({
      id: "product-camera",
      craClass: "important_i",
      supportUntil: "2031-01-10",
      ownerId: "member-jane",
      activeReleaseId: "release-2.1",
      actionCount: 2,
      tags: ["hardware", "camera"],
    });
    expect(fetcher).toHaveBeenNthCalledWith(2, "https://engine.example.test/v1/organizations/org%2Facme/products/camera%20product/releases/release%2F2.1", expect.anything());
    expect(release).toMatchObject({
      id: "release-2.1",
      supportedUntil: "2031-01-10",
      coverage: { components: 142, identifiedComponents: 140, advisorySourcesChecked: 7 },
      artifacts: [],
      lastAnalysisAt: "2026-09-12T09:30:00Z",
    });
  });

  it("serializes create and update inputs as explicit snake-case contracts", async () => {
    const fetcher = fetchSequence(json(productDto, 201), json(releaseDto));
    const client = createPortfolioApi({ baseUrl: "/engine", fetch: fetcher });

    await client.createProduct("org-acme", {
      name: "Smart Camera",
      identifier: "ACME-CAM-2",
      manufacturer: "Acme Devices GmbH",
      craClass: "important_i",
      supportStart: "2026-01-10",
      supportEnd: "2031-01-10",
    });
    await client.updateRelease("org-acme", "product-camera", "release-2.1", {
      monitoringHealth: "degraded",
      sbomStatus: "partial",
      clearOwner: true,
    });

    expect(fetcher.mock.calls[0][0]).toBe("/engine/v1/organizations/org-acme/products");
    expect(JSON.parse(String(fetcher.mock.calls[0][1]?.body))).toEqual({
      name: "Smart Camera",
      identifier: "ACME-CAM-2",
      manufacturer: "Acme Devices GmbH",
      cra_class: "important_i",
      support_start: "2026-01-10",
      support_end: "2031-01-10",
    });
    expect(fetcher.mock.calls[1][1]).toMatchObject({ method: "PATCH" });
    expect(JSON.parse(String(fetcher.mock.calls[1][1]?.body))).toEqual({
      clear_owner: true,
      monitoring_health: "degraded",
      sbom_status: "partial",
    });
  });

  it("covers organization list, create, get, and update operations", async () => {
    const fetcher = fetchSequence(json([organizationDto]), json(organizationDto, 201), json(organizationDto), json(organizationDto));
    const client = createPortfolioApi({ baseUrl: "", fetch: fetcher });

    await expect(client.listOrganizations()).resolves.toEqual([expect.objectContaining({ legalName: "Acme Devices GmbH", defaultTimezone: "Europe/Berlin" })]);
    await client.createOrganization({ name: "Acme Devices", legalName: "Acme Devices GmbH", country: "DE", registrationNumber: "HRB-20481" });
    await client.getOrganization("org/acme");
    await client.updateOrganization("org/acme", { timezone: "UTC" });

    expect(fetcher.mock.calls.map(([url, init]) => [url, init?.method])).toEqual([
      ["/v1/organizations", "GET"],
      ["/v1/organizations", "POST"],
      ["/v1/organizations/org%2Facme", "GET"],
      ["/v1/organizations/org%2Facme", "PATCH"],
    ]);
  });

  it.each([
    [401, "unauthenticated"],
    [403, "forbidden"],
    [404, "not_found"],
    [409, "conflict"],
    [422, "validation"],
  ] as const)("maps HTTP %s into %s", async (status, code) => {
    const detail = status === 422 ? [{ msg: "support_end must follow support_start" }] : "portfolio error";
    const client = createPortfolioApi({ baseUrl: "", fetch: fetchSequence(json({ detail }, status)) });

    await expect(client.getOrganization("org-acme")).rejects.toMatchObject({
      name: "PortfolioApiError",
      code,
      status,
      message: status === 422 ? "support_end must follow support_start" : "portfolio error",
    });
  });

  it("maps aborts and network failures without leaking raw fetch errors", async () => {
    const controller = new AbortController();
    controller.abort();
    const aborted = createPortfolioApi({
      baseUrl: "",
      fetch: vi.fn<typeof fetch>(async () => { throw new DOMException("stopped", "AbortError"); }),
    });
    const offline = createPortfolioApi({
      baseUrl: "",
      fetch: vi.fn<typeof fetch>(async () => { throw new TypeError("ECONNREFUSED"); }),
    });

    await expect(aborted.listOrganizations({ signal: controller.signal })).rejects.toMatchObject({ code: "aborted" });
    await expect(offline.listOrganizations()).rejects.toMatchObject({ code: "network", message: "Portfolio service unavailable" });
  });

  it("rejects non-JSON, malformed JSON, and structurally invalid success bodies", async () => {
    const fetcher = fetchSequence(
      new Response("gateway html", { status: 200, headers: { "content-type": "text/html" } }),
      new Response("{broken", { status: 200, headers: { "content-type": "application/json" } }),
      json([{ ...organizationDto, legal_name: 42 }]),
    );
    const client = createPortfolioApi({ baseUrl: "", fetch: fetcher });

    await expect(client.listOrganizations()).rejects.toMatchObject({ code: "invalid_response", message: "Portfolio service returned a non-JSON response" });
    await expect(client.listOrganizations()).rejects.toMatchObject({ code: "invalid_response", message: "Portfolio service returned invalid JSON" });
    await expect(client.listOrganizations()).rejects.toBeInstanceOf(PortfolioApiError);
  });
});
