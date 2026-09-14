import { describe, expect, it, vi } from "vitest";

import {
  createGovernanceApi,
  GovernanceApiError,
  mapCompliance,
  mapGovernanceSettings,
  mapIntegration,
  mapTeamMember,
} from "./governanceApi";

const complianceDto = {
  id: "obligation/1",
  organization_id: "org/acme",
  product_id: "product-camera",
  release_id: "release/2.1",
  kind: "missing_document",
  title: "Complete conformity evidence",
  description: "EU declaration needs approval evidence.",
  priority: "critical",
  status: "pending_approval",
  readiness: "review_required",
  due_at: "2026-10-12T09:00:00Z",
  owner_id: "member-jane",
  source_type: "cra_requirement",
  source_id: "cra-annex-v",
  reporting_stage: null,
  self_filing_record_id: null,
  self_filing_record_url: null,
  approved_by: null,
  approved_at: null,
  acknowledged_at: null,
  resolved_at: null,
  version: 3,
  created_at: "2026-09-01T08:00:00Z",
  updated_at: "2026-09-14T08:00:00Z",
};

const revisionDto = {
  id: "revision-1",
  organization_id: "org/acme",
  document_id: "document/1",
  revision: 1,
  format: "pdf_a_2b",
  content_hash: "a".repeat(64),
  storage_locator: "s3://actis-evidence/org-acme/document-1/revision-1.pdf",
  size_bytes: 4096,
  provenance: { generator: "actis-reporting-pack", release_id: "release/2.1" },
  created_by: "member-jane",
  created_at: "2026-09-14T08:30:00Z",
  status: "draft",
};

const documentDto = {
  id: "document/1",
  organization_id: "org/acme",
  product_id: "product-camera",
  release_id: "release/2.1",
  case_id: null,
  kind: "cra_reporting_pack",
  name: "Smart Camera 2.1 CRA reporting pack",
  current_revision: 1,
  created_by: "member-jane",
  created_at: "2026-09-14T08:30:00Z",
  updated_at: "2026-09-14T08:30:00Z",
  status: "draft",
  current: revisionDto,
};

const detailDto = {
  document: documentDto,
  revisions: [revisionDto],
  audit: [],
  approval_history: [],
  self_filings: [],
};

const filingDto = {
  id: "filing-1",
  organization_id: "org/acme",
  document_id: "document/1",
  revision: 1,
  external_submission_reference: "ENISA-2026-00419",
  submitted_at: "2026-09-14T10:00:00Z",
  receipt_evidence_locator: "s3://actis-evidence/org-acme/receipts/enisa-2026-00419.json",
  receipt_content_hash: "b".repeat(64),
  recorded_by: "member-jane",
  recorded_at: "2026-09-14T10:05:00Z",
  record_type: "operator_recorded_external_submission",
  actis_submitted_externally: false,
};

const settingsDto = {
  organization_id: "org/acme",
  version: 4,
  organization_profile: {
    name: "Acme Devices",
    legal_name: "Acme Devices GmbH",
    country: "DE",
    registration_number: "HRB-20481",
    timezone: "Europe/Berlin",
  },
  notifications: {
    urgent_findings: true,
    deadline_warnings: true,
    monitoring_failures: true,
    approval_requests: false,
    email_digest: "daily",
  },
  security: {
    session_timeout_minutes: 60,
    evidence_retention_months: 120,
    require_mfa: true,
    allow_raw_artifacts: false,
  },
  appearance: { theme: "system", density: "compact" },
  analytics: { enabled: true, retention_days: 30 },
  updated_by: "member-admin",
  updated_at: "2026-09-14T09:00:00Z",
};

const teamMemberDto = {
  id: "member/auditor",
  organization_id: "org/acme",
  subject: "oidc|auditor-1",
  name: "Alex Morgan",
  email: "alex@example.test",
  title: "Security reviewer",
  initials: "AM",
  roles: ["security_reviewer", "viewer"],
  status: "active",
  last_active_at: "2026-09-14T08:00:00Z",
  version: 2,
  created_at: "2026-09-01T08:00:00Z",
  updated_at: "2026-09-14T08:00:00Z",
};

const integrationDto = {
  id: "integration/jira",
  organization_id: "org/acme",
  name: "Jira Cloud",
  type: "jira",
  status: "connected",
  description: "Creates remediation tickets in the product security project.",
  configuration: { project_key: "SEC" },
  secret_reference: "vault://actis/org-acme/jira-oauth",
  last_sync_at: "2026-09-14T08:10:00Z",
  version: 7,
  created_at: "2026-09-01T08:00:00Z",
  updated_at: "2026-09-14T08:10:00Z",
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

describe("governance API", () => {
  it("authenticates, scopes compliance queries, maps data, and sends optimistic versions", async () => {
    const fetcher = fetchSequence(json([complianceDto]), json(complianceDto));
    const signal = new AbortController().signal;
    const api = createGovernanceApi({
      baseUrl: "https://engine.example.test/",
      getBearerToken: async () => " signed-token ",
      fetch: fetcher,
    });

    const items = await api.listCompliance("org/acme", {
      view: "action",
      productId: "product-camera",
      releaseId: "release/2.1",
      sort: "priority",
      direction: "desc",
    }, { signal });
    await api.updateCompliance("org/acme", "obligation/1", {
      expectedVersion: 3,
      status: "in_progress",
      ownerId: "member-alex",
    });

    expect(fetcher.mock.calls[0][0]).toBe("https://engine.example.test/v1/organizations/org%2Facme/compliance?view=action&product_id=product-camera&release_id=release%2F2.1&sort=priority&direction=desc");
    expect(fetcher.mock.calls[0][1]).toMatchObject({ method: "GET", signal });
    expect(new Headers(fetcher.mock.calls[0][1]?.headers).get("Authorization")).toBe("Bearer signed-token");
    expect(items[0]).toMatchObject({ organizationId: "org/acme", kind: "missing_document", version: 3 });
    expect(mapCompliance(items[0])).toMatchObject({ type: "missing_evidence", productId: "product-camera", priority: "urgent", status: "blocked" });
    expect(JSON.parse(String(fetcher.mock.calls[1][1]?.body))).toEqual({
      expected_version: 3,
      owner_id: "member-alex",
      status: "in_progress",
    });
  });

  it("keeps organization-level compliance transport data without inventing a product mapping", async () => {
    const api = createGovernanceApi({ baseUrl: "", fetch: fetchSequence(json({ ...complianceDto, product_id: null, release_id: null })) });
    const item = await api.getCompliance("org/acme", "obligation/1");

    expect(item.productId).toBeUndefined();
    expect(mapCompliance(item)).toBeUndefined();
  });

  it("serializes immutable document revisions and approval transitions", async () => {
    const pendingRevision = { ...revisionDto, status: "pending" };
    const fetcher = fetchSequence(json(detailDto, 201), json({ ...revisionDto, revision: 2 }, 201), json(pendingRevision));
    const api = createGovernanceApi({ baseUrl: "/engine", fetch: fetcher });

    await api.createDocument("org/acme", {
      productId: "product-camera",
      releaseId: "release/2.1",
      name: "Smart Camera 2.1 CRA reporting pack",
      kind: "cra_reporting_pack",
      format: "pdf_a_2b",
      contentHash: "a".repeat(64),
      storageLocator: "s3://actis-evidence/org-acme/document-1/revision-1.pdf",
      sizeBytes: 4096,
      provenance: { generator: "actis-reporting-pack" },
    });
    await api.addDocumentRevision("org/acme", "document/1", {
      expectedCurrentRevision: 1,
      format: "pdf_a_2b",
      contentHash: "c".repeat(64),
      storageLocator: "s3://actis-evidence/org-acme/document-1/revision-2.pdf",
      sizeBytes: 5000,
      provenance: { reason: "deadline evidence updated" },
    });
    await api.requestDocumentApproval("org/acme", "document/1", 2, "draft", "Evidence reviewed by product security.");

    expect(fetcher.mock.calls.map(([url, init]) => [url, init?.method])).toEqual([
      ["/engine/v1/organizations/org%2Facme/documents", "POST"],
      ["/engine/v1/organizations/org%2Facme/documents/document%2F1/revisions", "POST"],
      ["/engine/v1/organizations/org%2Facme/documents/document%2F1/revisions/2/approval-request", "POST"],
    ]);
    expect(JSON.parse(String(fetcher.mock.calls[1][1]?.body))).toMatchObject({
      expected_current_revision: 1,
      content_hash: "c".repeat(64),
      storage_locator: "s3://actis-evidence/org-acme/document-1/revision-2.pdf",
    });
    expect(JSON.parse(String(fetcher.mock.calls[2][1]?.body))).toEqual({
      comment: "Evidence reviewed by product security.",
      expected_status: "draft",
    });
  });

  it("records only operator-reported self-filings and preserves the external-submission disclaimer", async () => {
    const fetcher = fetchSequence(json(filingDto, 201));
    const api = createGovernanceApi({ baseUrl: "", fetch: fetcher });

    const filing = await api.recordSelfFiling("org/acme", "document/1", 1, {
      externalSubmissionReference: "ENISA-2026-00419",
      submittedAt: "2026-09-14T10:00:00Z",
      receiptEvidenceLocator: "s3://actis-evidence/org-acme/receipts/enisa-2026-00419.json",
      receiptContentHash: "b".repeat(64),
    });

    expect(filing).toMatchObject({ recordType: "operator_recorded_external_submission", actisSubmittedExternally: false });
    expect(JSON.parse(String(fetcher.mock.calls[0][1]?.body))).not.toHaveProperty("actis_submitted_externally");

    const invalid = createGovernanceApi({ baseUrl: "", fetch: fetchSequence(json({ ...filingDto, actis_submitted_externally: true })) });
    await expect(invalid.recordSelfFiling("org", "document", 1, {
      externalSubmissionReference: "external-1",
      submittedAt: "2026-09-14T10:00:00Z",
      receiptEvidenceLocator: "s3://receipts/1",
    })).rejects.toMatchObject({ code: "invalid_response", message: "self-filing response must state Actis did not submit externally" });
  });

  it("maps settings, team roles, and integrations while keeping transport-only fields separate", async () => {
    const fetcher = fetchSequence(json(settingsDto), json(teamMemberDto), json(integrationDto), json(settingsDto));
    const api = createGovernanceApi({ baseUrl: "", fetch: fetcher });

    const settings = await api.getSettings("org/acme");
    const member = await api.getTeamMember("org/acme", "member/auditor");
    const integration = await api.getIntegration("org/acme", "integration/jira");
    await api.updateSettings("org/acme", {
      expectedVersion: 4,
      organizationProfile: { legalName: "Acme Connected Devices GmbH" },
      notifications: { approvalRequests: true },
      security: { sessionTimeoutMinutes: 30 },
      analytics: { retentionDays: 14 },
    });

    expect(mapGovernanceSettings(settings)).toMatchObject({
      organization: { id: "org/acme", legalName: "Acme Devices GmbH", defaultTimezone: "Europe/Berlin" },
      settings: { appearance: { theme: "system", density: "compact" }, security: { evidenceRetentionMonths: 120 } },
    });
    expect(mapTeamMember(member)).toMatchObject({ roles: ["read_only_auditor"], status: "active" });
    expect(mapIntegration(integration)).toMatchObject({ id: "integration/jira", type: "jira", status: "connected" });
    expect(fetcher.mock.calls.slice(0, 3).map(([url]) => url)).toEqual([
      "/v1/organizations/org%2Facme/settings",
      "/v1/organizations/org%2Facme/team/member%2Fauditor",
      "/v1/organizations/org%2Facme/integrations/integration%2Fjira",
    ]);
    expect(JSON.parse(String(fetcher.mock.calls[3][1]?.body))).toEqual({
      analytics: { retention_days: 14 },
      expected_version: 4,
      notifications: { approval_requests: true },
      organization_profile: { legal_name: "Acme Connected Devices GmbH" },
      security: { session_timeout_minutes: 30 },
    });
  });

  it("sends only allowlisted analytics names and properties", async () => {
    const fetcher = fetchSequence(json({ accepted: 2, dropped: 0 }, 202), json([{ event_name: "page_viewed", count: 12 }]));
    const api = createGovernanceApi({ baseUrl: "", fetch: fetcher });

    await expect(api.ingestAnalytics("org/acme", [{
      eventName: "page_viewed",
      properties: { area: "documents" },
      occurredAt: "2026-09-14T10:00:00Z",
    }, {
      eventName: "error_observed",
      properties: { area: "compliance", errorCode: "forbidden" },
      occurredAt: "2026-09-14T10:01:00Z",
    }])).resolves.toEqual({ accepted: 2, dropped: 0 });
    await expect(api.getAnalyticsAggregates("org/acme", {
      since: "2026-09-01T00:00:00Z",
      until: "2026-09-14T23:59:59Z",
    })).resolves.toEqual([{ eventName: "page_viewed", count: 12 }]);

    expect(JSON.parse(String(fetcher.mock.calls[0][1]?.body))).toEqual({ events: [{
      event_name: "page_viewed",
      properties: { area: "documents" },
      occurred_at: "2026-09-14T10:00:00Z",
    }, {
      event_name: "error_observed",
      properties: { area: "compliance", error_code: "forbidden" },
      occurred_at: "2026-09-14T10:01:00Z",
    }] });
    expect(fetcher.mock.calls[1][0]).toBe("/v1/organizations/org%2Facme/analytics/aggregates?since=2026-09-01T00%3A00%3A00Z&until=2026-09-14T23%3A59%3A59Z");
  });

  it.each([
    [401, "unauthenticated"],
    [403, "forbidden"],
    [404, "not_found"],
    [409, "conflict"],
    [422, "validation"],
  ] as const)("maps governance HTTP %s into %s", async (status, code) => {
    const detail = status === 422 ? [{ msg: "expected_version is stale" }] : "governance error";
    const api = createGovernanceApi({ baseUrl: "", fetch: fetchSequence(json({ detail }, status)) });

    await expect(api.getSettings("org/acme")).rejects.toMatchObject({
      name: "GovernanceApiError",
      code,
      status,
      message: status === 422 ? "expected_version is stale" : "governance error",
    });
  });

  it("maps aborts and network failures without exposing raw fetch failures", async () => {
    const controller = new AbortController();
    controller.abort();
    const aborted = createGovernanceApi({
      baseUrl: "",
      fetch: vi.fn<typeof fetch>(async () => { throw new DOMException("stopped", "AbortError"); }),
    });
    const offline = createGovernanceApi({
      baseUrl: "",
      fetch: vi.fn<typeof fetch>(async () => { throw new TypeError("ECONNREFUSED"); }),
    });

    await expect(aborted.getSettings("org", { signal: controller.signal })).rejects.toMatchObject({ code: "aborted" });
    await expect(offline.getSettings("org")).rejects.toMatchObject({ code: "network", message: "Governance service unavailable" });
  });

  it("rejects non-JSON and structurally invalid successful responses", async () => {
    const fetcher = fetchSequence(
      new Response("gateway html", { status: 200, headers: { "content-type": "text/html" } }),
      json({ ...settingsDto, security: { ...settingsDto.security, require_mfa: "yes" } }),
    );
    const api = createGovernanceApi({ baseUrl: "", fetch: fetcher });

    await expect(api.getSettings("org")).rejects.toMatchObject({ code: "invalid_response", message: "Governance service returned a non-JSON response" });
    await expect(api.getSettings("org")).rejects.toBeInstanceOf(GovernanceApiError);
  });
});
