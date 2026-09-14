import { describe, expect, it, vi } from "vitest";

import { createOperationsApi, OperationsApiError } from "./operationsApi";

const homeDto = {
  organization_id: "org/acme",
  generated_at: "2026-09-14T12:00:00Z",
  monitoring: {
    state: "degraded",
    supported_releases: 4,
    configured: 3,
    healthy: 2,
    degraded: 1,
    failed: 0,
    stale: 0,
    inactive: 0,
    not_configured: 1,
    last_success_at: "2026-09-14T11:45:00Z",
  },
  counters: {
    action_total: 8,
    findings_needing_action: 3,
    urgent_findings: 1,
    reachable_kev_findings: 1,
    compliance_actions: 2,
    overdue_obligations: 1,
    due_soon_obligations: 1,
    missing_evidence: 1,
    pending_approvals: 1,
    documents_needing_action: 1,
    monitoring_issues: 2,
  },
  action_queue: [{
    id: "finding:finding-1",
    source_type: "finding",
    source_id: "finding-1",
    product_id: "product-camera",
    release_id: "release-2.1",
    product_name: "Smart Camera",
    release_version: "2.1",
    title: "Reachable authentication bypass",
    reason: "Known exploited vulnerability is reachable in this release",
    priority: "urgent",
    due_at: null,
    score: 1050,
    target_url: "/findings/finding-1?product=product-camera&release=release-2.1",
    updated_at: "2026-09-14T11:30:00Z",
  }],
  recent_changes: [{
    id: "event-1",
    source_type: "document",
    source_id: "document-1",
    product_id: "product-camera",
    release_id: null,
    title: "EU Declaration of Conformity",
    description: "Approval requested",
    actor_id: "member-jane",
    occurred_at: "2026-09-14T11:00:00Z",
    target_url: "/documents/document-1?product=product-camera",
  }],
  data_warnings: ["1 supported release(s) have no monitoring configuration."],
};

const searchDto = {
  query: "smart camera",
  total: 2,
  groups: [{
    category: "products",
    results: [{
      category: "products",
      id: "product-camera",
      title: "Smart Camera",
      subtitle: "CAM-200 · Acme Devices",
      product_id: "product-camera",
      release_id: null,
      priority: null,
      url: "/products/product-camera",
      rank: 0,
    }],
  }, {
    category: "findings",
    results: [{
      category: "findings",
      id: "finding-1",
      title: "Camera authentication bypass",
      subtitle: "CVE-2026-4100",
      product_id: "product-camera",
      release_id: "release-2.1",
      priority: "critical",
      url: "/findings/finding-1",
      rank: 1,
    }],
  }],
};

const notificationDto = {
  id: "notification/1",
  organization_id: "org/acme",
  source_fingerprint: "finding:CVE-2026-4100",
  kind: "finding",
  priority: "critical",
  title: "Reachable vulnerability requires review",
  detail: "Review CVE-2026-4100 for Smart Camera 2.1.",
  product_id: "product-camera",
  release_id: "release-2.1",
  target_url: "/findings/finding-1",
  requires_action: true,
  read_at: null,
  acknowledged_at: null,
  acknowledged_by: null,
  first_seen_at: "2026-09-14T09:00:00Z",
  last_seen_at: "2026-09-14T10:00:00Z",
  created_at: "2026-09-14T09:00:00Z",
  updated_at: "2026-09-14T10:00:00Z",
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

describe("operations API", () => {
  it("authenticates, encodes Home scope and limits, and maps snake case", async () => {
    const fetcher = fetchSequence(json(homeDto));
    const signal = new AbortController().signal;
    const api = createOperationsApi({
      baseUrl: "https://engine.example.test/",
      getBearerToken: async () => " signed-token ",
      fetch: fetcher,
    });

    const home = await api.getHome("org/acme", { queueLimit: 4, recentLimit: 6, signal });

    expect(fetcher).toHaveBeenCalledWith(
      "https://engine.example.test/v1/organizations/org%2Facme/home?queue_limit=4&recent_limit=6",
      expect.objectContaining({ method: "GET", signal }),
    );
    const headers = new Headers(fetcher.mock.calls[0][1]?.headers);
    expect(headers.get("Authorization")).toBe("Bearer signed-token");
    expect(headers.get("Accept")).toBe("application/json");
    expect(home).toMatchObject({
      organizationId: "org/acme",
      monitoring: { supportedReleases: 4, notConfigured: 1, lastSuccessAt: "2026-09-14T11:45:00Z" },
      counters: { actionTotal: 8, reachableKevFindings: 1, pendingApprovals: 1 },
      actionQueue: [{ sourceType: "finding", productId: "product-camera", dueAt: undefined, score: 1050 }],
      recentChanges: [{ sourceType: "document", actorId: "member-jane", releaseId: undefined }],
      dataWarnings: ["1 supported release(s) have no monitoring configuration."],
    });
  });

  it("sends repeated categorized search filters and validates grouped mapping", async () => {
    const fetcher = fetchSequence(json(searchDto));
    const api = createOperationsApi({ baseUrl: "/engine", fetch: fetcher });

    const result = await api.search("org-acme", "smart camera", {
      categories: ["products", "findings"],
      limit: 7,
    });

    expect(fetcher.mock.calls[0][0]).toBe(
      "/engine/v1/organizations/org-acme/search?q=smart+camera&category=products&category=findings&limit=7",
    );
    expect(result).toEqual({
      query: "smart camera",
      total: 2,
      groups: [
        expect.objectContaining({ category: "products", results: [expect.objectContaining({ productId: "product-camera", priority: undefined })] }),
        expect.objectContaining({ category: "findings", results: [expect.objectContaining({ releaseId: "release-2.1", rank: 1 })] }),
      ],
    });
  });

  it("lists, marks read, and acknowledges encoded notifications", async () => {
    const read = { ...notificationDto, read_at: "2026-09-14T10:15:00Z" };
    const acknowledged = {
      ...read,
      acknowledged_at: "2026-09-14T10:16:00Z",
      acknowledged_by: "member-jane",
    };
    const fetcher = fetchSequence(json([notificationDto]), json(read), json(acknowledged));
    const api = createOperationsApi({ baseUrl: "", fetch: fetcher });

    const listed = await api.listNotifications("org/acme", {
      view: "all", kind: "finding", priority: "critical", productId: "product/camera", limit: 10,
    });
    const marked = await api.markRead("org/acme", "notification/1");
    const result = await api.acknowledge("org/acme", "notification/1");

    expect(fetcher.mock.calls.map(([url, init]) => [url, init?.method])).toEqual([
      ["/v1/organizations/org%2Facme/notifications?view=all&kind=finding&priority=critical&product_id=product%2Fcamera&limit=10", "GET"],
      ["/v1/organizations/org%2Facme/notifications/notification%2F1/read", "POST"],
      ["/v1/organizations/org%2Facme/notifications/notification%2F1/acknowledge", "POST"],
    ]);
    expect(listed[0]).toMatchObject({ organizationId: "org/acme", requiresAction: true, readAt: undefined });
    expect(marked.readAt).toBe("2026-09-14T10:15:00Z");
    expect(result).toMatchObject({ acknowledgedAt: "2026-09-14T10:16:00Z", acknowledgedBy: "member-jane" });
  });

  it.each([
    [401, "unauthenticated"],
    [403, "forbidden"],
    [404, "not_found"],
    [409, "conflict"],
    [422, "validation"],
    [503, "http_error"],
  ] as const)("maps HTTP %s into %s", async (status, code) => {
    const detail = status === 422 ? [{ msg: "limit must be at most 50" }] : "operations error";
    const api = createOperationsApi({ baseUrl: "", fetch: fetchSequence(json({ detail }, status)) });

    await expect(api.getHome("org-acme")).rejects.toMatchObject({
      name: "OperationsApiError",
      code,
      status,
      message: status === 422 ? "limit must be at most 50" : "operations error",
    });
  });

  it("distinguishes aborts from network failures", async () => {
    const controller = new AbortController();
    controller.abort();
    const aborted = createOperationsApi({
      baseUrl: "",
      fetch: vi.fn<typeof fetch>(async () => { throw new DOMException("stopped", "AbortError"); }),
    });
    const offline = createOperationsApi({
      baseUrl: "",
      fetch: vi.fn<typeof fetch>(async () => { throw new TypeError("ECONNREFUSED"); }),
    });

    await expect(aborted.search("org-acme", "camera", { signal: controller.signal })).rejects.toMatchObject({ code: "aborted" });
    await expect(offline.listNotifications("org-acme")).rejects.toMatchObject({
      code: "network", message: "Operations service unavailable",
    });
  });

  it("rejects non-JSON, malformed JSON, and structurally inconsistent success bodies", async () => {
    const malformedSearch = { ...searchDto, total: 3 };
    const fetcher = fetchSequence(
      new Response("gateway html", { status: 200, headers: { "content-type": "text/html" } }),
      new Response("{broken", { status: 200, headers: { "content-type": "application/json" } }),
      json({ ...homeDto, counters: { ...homeDto.counters, action_total: -1 } }),
      json(malformedSearch),
    );
    const api = createOperationsApi({ baseUrl: "", fetch: fetcher });

    await expect(api.getHome("org-acme")).rejects.toMatchObject({ code: "invalid_response", message: "Operations service returned a non-JSON response" });
    await expect(api.getHome("org-acme")).rejects.toMatchObject({ code: "invalid_response", message: "Operations service returned invalid JSON" });
    await expect(api.getHome("org-acme")).rejects.toBeInstanceOf(OperationsApiError);
    await expect(api.search("org-acme", "camera")).rejects.toMatchObject({ code: "invalid_response", message: "search total does not match grouped results" });
  });
});
