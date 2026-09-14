import { describe, expect, it, vi } from "vitest";

import {
  createFindingsApi,
  FindingApiError,
  mapFinding,
  type FindingAuditDto,
  type FindingDecisionDto,
  type FindingDetailDto,
  type FindingDto,
} from "./findingsApi";

const findingDto = {
  id: "finding/kev-1",
  organization_id: "org/acme",
  product_id: "home hub",
  release_id: "release/1.4",
  source_key: "osv:CVE-2021-44228:log4j",
  reference_id: "GHSA-jfh8-c2jp-5v3q",
  cve: "CVE-2021-44228",
  component: "log4j-core",
  purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
  component_version: "2.14.1",
  title: "Remote code execution in Log4j",
  description: "Attacker-controlled lookups can execute code in the affected logging path.",
  severity: "critical",
  cvss: 10,
  kev: true,
  epss: 0.975,
  reachability: "reachable",
  reachability_evidence: { paths: ["gateway -> logger"], method: "static_call_graph" },
  reachability_limitations: ["Runtime feature flags were not observed."],
  source: "osv",
  provenance: { advisory: "GHSA-jfh8-c2jp-5v3q", feed_revision: "2026-09-14" },
  first_seen_at: "2026-09-12T08:00:00Z",
  last_seen_at: "2026-09-14T09:00:00Z",
  status: "open",
  assignee_id: "member-jane",
  current_decision: "affected",
  decision_rationale: "Reachable from unauthenticated gateway input.",
  decision_by: "reviewer-1",
  decided_at: "2026-09-14T09:10:00Z",
  remediation_plan: "Upgrade log4j-core and rebuild the gateway image.",
  remediation_status: "in_progress",
  remediation_due_date: "2026-09-15",
  verification_evidence: [{ id: "evidence-test-42", kind: "test_run", sha256: "a".repeat(64) }],
  version: 4,
  created_at: "2026-09-12T08:00:00Z",
  updated_at: "2026-09-14T09:15:00Z",
} satisfies FindingDto;

const decisionDto = {
  id: "decision-1",
  finding_id: "finding/kev-1",
  organization_id: "org/acme",
  decision: "affected",
  rationale: "Reachable from unauthenticated gateway input.",
  actor_id: "reviewer-1",
  occurred_at: "2026-09-14T09:10:00Z",
  finding_version: 3,
} satisfies FindingDecisionDto;

const auditDto = {
  id: "audit-1",
  finding_id: "finding/kev-1",
  organization_id: "org/acme",
  action: "finding.decision_recorded",
  actor_id: "reviewer-1",
  payload: { decision: "affected", version: 3 },
  occurred_at: "2026-09-14T09:10:00Z",
} satisfies FindingAuditDto;

const detailDto = { ...findingDto, decision_history: [decisionDto], audit_history: [auditDto] } satisfies FindingDetailDto;

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

describe("findings API", () => {
  it("uses auth, encoded tenant scope, and default needs-action collection", async () => {
    const fetcher = fetchSequence(json([findingDto]));
    const api = createFindingsApi({
      baseUrl: "https://engine.example.test/",
      getBearerToken: async () => " signed-token ",
      fetch: fetcher,
    });

    const findings = await api.listFindings("org/acme");

    expect(fetcher).toHaveBeenCalledWith(
      "https://engine.example.test/v1/organizations/org%2Facme/findings",
      expect.objectContaining({ method: "GET" }),
    );
    const headers = new Headers(fetcher.mock.calls[0][1]?.headers);
    expect(headers.get("Authorization")).toBe("Bearer signed-token");
    expect(findings[0]).toMatchObject({
      id: "finding/kev-1",
      reference: "CVE-2021-44228",
      priority: "urgent",
      status: "action_required",
      affectedness: "confirmed",
      reachability: "reachable",
      remediation: { status: "in_progress", targetDate: "2026-09-15" },
      evidenceIds: ["evidence-test-42"],
      epss: 0.975,
      version: 4,
    });
    expect(findings[0].activelyExploited).toBe(false);
  });

  it("serializes release filters as repeated, explicit query parameters", async () => {
    const fetcher = fetchSequence(json([findingDto]));
    const api = createFindingsApi({ baseUrl: "/engine", fetch: fetcher });

    await api.listReleaseFindings("org/acme", "home hub", "release/1.4", {
      view: "all",
      severity: ["critical", "high"],
      status: ["needs_review", "open"],
      kev: true,
      reachability: "reachable",
      assigneeId: "Jane Doe",
      sort: "severity",
    });

    expect(fetcher.mock.calls[0][0]).toBe(
      "/engine/v1/organizations/org%2Facme/products/home%20hub/releases/release%2F1.4/findings" +
      "?view=all&severity=critical&severity=high&status=needs_review&status=open&kev=true&reachability=reachable&assignee_id=Jane+Doe&sort=severity",
    );
  });

  it("maps detail evidence, full decision history, and audit history", async () => {
    const fetcher = fetchSequence(json(detailDto), json(detailDto), json(detailDto));
    const api = createFindingsApi({ baseUrl: "", fetch: fetcher });

    const detail = await api.getFinding("org/acme", "home hub", "release/1.4", "finding/kev-1");
    const decisions = await api.getDecisionHistory("org/acme", "home hub", "release/1.4", "finding/kev-1");
    const audit = await api.getAuditHistory("org/acme", "home hub", "release/1.4", "finding/kev-1");

    expect(detail.decisionHistory).toEqual([{
      id: "decision-1",
      decision: "affected",
      rationale: "Reachable from unauthenticated gateway input.",
      decidedBy: "reviewer-1",
      decidedAt: "2026-09-14T09:10:00Z",
    }]);
    expect(detail.decisions).toEqual(detail.decisionHistory);
    expect(detail.reachabilityEvidence).toEqual({ paths: ["gateway -> logger"], method: "static_call_graph" });
    expect(detail.verificationEvidence[0]).toMatchObject({ kind: "test_run" });
    expect(decisions).toEqual(detail.decisionHistory);
    expect(audit[0]).toMatchObject({ action: "finding.decision_recorded", payload: { decision: "affected", version: 3 } });
  });

  it("sends assignment, decision, and remediation mutations without dropping semantics", async () => {
    const assigned = { ...findingDto, assignee_id: "member-alex", version: 5 };
    const decided = { ...detailDto, current_decision: "accepted_risk", status: "resolved", version: 6 };
    const verified = { ...detailDto, remediation_status: "verified", status: "resolved", version: 7 };
    const fetcher = fetchSequence(json(assigned), json(decided, 201), json(verified));
    const api = createFindingsApi({ baseUrl: "", fetch: fetcher });

    const assignment = await api.assignFinding("org", "product", "release", "finding", { assigneeId: "member-alex", expectedVersion: 4 });
    const decision = await api.recordDecision("org", "product", "release", "finding", {
      decision: "accepted_risk", rationale: "Compensating control approved through 2026-10-01.", expectedVersion: 5,
    });
    const remediation = await api.updateRemediation("org", "product", "release", "finding", {
      plan: "Upgrade and retest", status: "verified", dueDate: "2026-09-15",
      verificationEvidence: [{ kind: "test_run", id: "run-42" }], expectedVersion: 6,
    });

    expect(assignment.assigneeId).toBe("member-alex");
    expect(decision.status).toBe("accepted");
    expect(remediation.remediation.status).toBe("verified");
    expect(fetcher.mock.calls.map(([, init]) => init?.method)).toEqual(["PATCH", "POST", "PUT"]);
    expect(JSON.parse(String(fetcher.mock.calls[0][1]?.body))).toEqual({ assignee_id: "member-alex", expected_version: 4 });
    expect(JSON.parse(String(fetcher.mock.calls[1][1]?.body))).toEqual({
      decision: "accepted_risk", rationale: "Compensating control approved through 2026-10-01.", expected_version: 5,
    });
    expect(JSON.parse(String(fetcher.mock.calls[2][1]?.body))).toEqual({
      plan: "Upgrade and retest", status: "verified", due_date: "2026-09-15",
      verification_evidence: [{ kind: "test_run", id: "run-42" }], expected_version: 6,
    });
  });

  it.each([
    [401, "unauthenticated"],
    [403, "forbidden"],
    [404, "not_found"],
    [409, "conflict"],
    [422, "validation"],
  ] as const)("maps HTTP %s to %s", async (status, code) => {
    const detail = status === 422 ? [{ msg: "verification_evidence is required when verified" }] : "finding changed";
    const api = createFindingsApi({ baseUrl: "", fetch: fetchSequence(json({ detail }, status)) });

    await expect(api.getFinding("org", "product", "release", "finding")).rejects.toMatchObject({
      name: "FindingApiError",
      code,
      status,
      message: status === 422 ? "verification_evidence is required when verified" : "finding changed",
    });
  });

  it("maps abort and transport failures", async () => {
    const controller = new AbortController();
    controller.abort();
    const aborted = createFindingsApi({
      baseUrl: "",
      fetch: vi.fn<typeof fetch>(async () => { throw new DOMException("stopped", "AbortError"); }),
    });
    const offline = createFindingsApi({
      baseUrl: "",
      fetch: vi.fn<typeof fetch>(async () => { throw new TypeError("ECONNREFUSED"); }),
    });

    await expect(aborted.listFindings("org", undefined, { signal: controller.signal })).rejects.toMatchObject({ code: "aborted" });
    await expect(offline.listFindings("org")).rejects.toMatchObject({ code: "network", message: "Findings service unavailable" });
  });

  it("rejects malformed success payloads rather than casting them", async () => {
    const fetcher = fetchSequence(
      new Response("gateway", { status: 200, headers: { "content-type": "text/html" } }),
      new Response("{broken", { status: 200, headers: { "content-type": "application/json" } }),
      json([{ ...findingDto, reachability_evidence: [] }]),
      json([{ ...findingDto, epss: 1.5 }]),
    );
    const api = createFindingsApi({ baseUrl: "", fetch: fetcher });

    await expect(api.listFindings("org")).rejects.toMatchObject({ code: "invalid_response" });
    await expect(api.listFindings("org")).rejects.toMatchObject({ code: "invalid_response" });
    await expect(api.listFindings("org")).rejects.toBeInstanceOf(FindingApiError);
    await expect(api.listFindings("org")).rejects.toMatchObject({ code: "invalid_response", message: "epss must be between 0 and 1" });
  });

  it("maps DTOs independently for adapter reuse", () => {
    expect(mapFinding(findingDto)).toMatchObject({
      decisions: [{ decision: "affected", decidedBy: "reviewer-1" }],
      actionReason: "Reachable from unauthenticated gateway input.",
      provenance: { advisory: "GHSA-jfh8-c2jp-5v3q" },
    });
  });
});
