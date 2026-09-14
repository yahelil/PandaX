import { describe, expect, it, vi } from "vitest";

import { createReleaseOperationsApi, ReleaseOperationsApiError, type ReleaseScope } from "./releaseOperationsApi";

const digest = "a".repeat(64);
const scope: ReleaseScope = {
  organizationId: "org/acme",
  productId: "camera product",
  releaseId: "release/2.1",
};

const preview = {
  format: "CycloneDX",
  version: "1.6",
  components: 142,
  matchable_components: 140,
  skipped_components: 2,
  product: { name: "Smart Camera", version: "2.1" },
};

const queuedJob = {
  id: "job/1",
  organization_id: "org/acme",
  product_id: "camera product",
  release_id: "release/2.1",
  input_type: "sbom",
  filename: "camera.cdx.json",
  media_type: "application/vnd.cyclonedx+json",
  size_bytes: 4096,
  sha256: digest,
  preview,
  retained_until: "2036-09-14T09:00:00Z",
  input_metadata: {},
  consented_at: null,
  consent_actor_id: null,
  status: "queued",
  stage: "Validated input",
  progress: 10,
  result: null,
  error: null,
  created_at: "2026-09-14T09:00:00Z",
  updated_at: "2026-09-14T09:00:01Z",
  started_at: null,
  completed_at: null,
};

const completedJob = {
  ...queuedJob,
  status: "completed",
  stage: "Complete",
  progress: 100,
  result: {
    components: 142,
    findings: 4,
    kev: 1,
    incidents: 0,
    input_format: "CycloneDX",
    input_version: "1.6",
    coverage_summary: { complete: 5, limited: 1 },
    evidence: [{ name: "manifest.json", sha256: digest, href: `/evidence/${digest}` }],
  },
  started_at: "2026-09-14T09:00:02Z",
  completed_at: "2026-09-14T09:00:14Z",
  updated_at: "2026-09-14T09:00:14Z",
};

const monitoringDto = {
  organization_id: "org/acme",
  product_id: "camera product",
  release_id: "release/2.1",
  enabled_sources: ["osv", "cisa_kev", "vendor_advisory"],
  cadence_minutes: 60,
  enabled: true,
  health: "degraded",
  next_check_at: "2026-09-14T10:00:00Z",
  last_check_at: "2026-09-14T09:00:00Z",
  last_success_at: "2026-09-14T09:00:00Z",
  consecutive_failures: 0,
  coverage: { status: "partial", sources_checked: 2 },
  limitations: ["Vendor advisory endpoint unavailable"],
  running: false,
  created_at: "2026-09-13T09:00:00Z",
  updated_at: "2026-09-14T09:00:00Z",
};

const analysisEvent = {
  id: "event-analysis-1",
  job_id: "job/1",
  sequence: 1,
  kind: "analysis.uploaded",
  status: "queued",
  stage: "Validated input",
  progress: 10,
  message: "SBOM validated",
  details: { components: 142 },
  occurred_at: "2026-09-14T09:00:01Z",
};

const monitoringEvent = {
  id: "event-monitor-1",
  run_id: "run-1",
  sequence: 2,
  event_type: "succeeded",
  trigger: "manual",
  health: "degraded",
  coverage: { status: "partial" },
  limitations: ["Vendor advisory endpoint unavailable"],
  message: "Monitoring completed with limitations",
  actor_id: "member-jane",
  occurred_at: "2026-09-14T09:00:00Z",
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

const encodedBase = "/v1/organizations/org%2Facme/products/camera%20product/releases/release%2F2.1";

describe("release operations API", () => {
  it("uploads a multipart SBOM with bearer auth, idempotency, scope, and signal", async () => {
    const fetcher = fetchSequence(json(queuedJob, 201));
    const signal = new AbortController().signal;
    const api = createReleaseOperationsApi({
      baseUrl: "https://engine.example.test/",
      getBearerToken: async () => " signed-token ",
      fetch: fetcher,
    });
    const file = new Blob(["{\"bomFormat\":\"CycloneDX\"}"], { type: "application/json" });

    const job = await api.uploadSbom(scope, {
      file,
      filename: "camera.cdx.json",
      idempotencyKey: "upload-001",
    }, { signal });

    expect(fetcher.mock.calls[0][0]).toBe(`https://engine.example.test${encodedBase}/analysis-jobs`);
    const init = fetcher.mock.calls[0][1] as RequestInit;
    const headers = new Headers(init.headers);
    expect(init).toMatchObject({ method: "POST", signal });
    expect(headers.get("Authorization")).toBe("Bearer signed-token");
    expect(headers.get("Idempotency-Key")).toBe("upload-001");
    expect(headers.has("Content-Type")).toBe(false);
    expect(init.body).toBeInstanceOf(FormData);
    const uploaded = (init.body as FormData).get("sbom") as File;
    expect(uploaded.name).toBe("camera.cdx.json");
    expect(job).toMatchObject({
      organizationId: "org/acme", sizeBytes: 4096, status: "queued",
      preview: { matchableComponents: 140, skippedComponents: 2 },
      result: undefined, startedAt: undefined,
    });
  });

  it("uploads Collector and consented raw-artifact inputs through the typed endpoint", async () => {
    const collector = { ...queuedJob, input_type: "collector", filename: "collector.zip", preview: { ...preview, collector: { name: "Actis Collector", version: "1.2.0" } } };
    const raw = { ...queuedJob, input_type: "raw_artifact", filename: "firmware.bin", preview: { ...preview, format: "Raw artifact", version: "1", components: 0, matchable_components: 0, skipped_components: 0 }, consented_at: "2026-09-14T09:00:00Z", consent_actor_id: "reviewer-1" };
    const fetcher = fetchSequence(json(collector, 201), json(raw, 201));
    const api = createReleaseOperationsApi({ baseUrl: "", fetch: fetcher });

    await expect(api.uploadAnalysisInput(scope, { inputType: "collector", file: new Blob(["zip"]), filename: "collector.zip", idempotencyKey: "collector-1" })).resolves.toMatchObject({ inputType: "collector", preview: { collector: { name: "Actis Collector" } } });
    await expect(api.uploadAnalysisInput(scope, { inputType: "raw_artifact", file: new Blob(["firmware"]), filename: "firmware.bin", idempotencyKey: "raw-1", rawArtifactConsent: true })).resolves.toMatchObject({ inputType: "raw_artifact", consentActorId: "reviewer-1" });

    const [collectorForm, rawForm] = fetcher.mock.calls.map((call) => call[1]?.body as FormData);
    expect(fetcher.mock.calls.map(([url]) => url)).toEqual([`${encodedBase}/analysis-jobs/inputs`, `${encodedBase}/analysis-jobs/inputs`]);
    expect(collectorForm.get("input_type")).toBe("collector");
    expect(rawForm.get("raw_artifact_consent")).toBe("true");
  });

  it("lists, reads, runs, and maps job progress, result, and events", async () => {
    const running = { ...queuedJob, status: "running", progress: 20, started_at: "2026-09-14T09:00:02Z" };
    const fetcher = fetchSequence(json([queuedJob]), json(completedJob), json(running), json([analysisEvent]));
    const api = createReleaseOperationsApi({ baseUrl: "", fetch: fetcher });

    const listed = await api.listAnalysisJobs(scope);
    const completed = await api.getAnalysisJob(scope, "job/1");
    const started = await api.runAnalysisJob(scope, "job/1");
    const events = await api.listAnalysisEvents(scope, "job/1");

    expect(fetcher.mock.calls.map(([url, init]) => [url, init?.method])).toEqual([
      [`${encodedBase}/analysis-jobs`, "GET"],
      [`${encodedBase}/analysis-jobs/job%2F1`, "GET"],
      [`${encodedBase}/analysis-jobs/job%2F1/run`, "POST"],
      [`${encodedBase}/analysis-jobs/job%2F1/events`, "GET"],
    ]);
    expect(listed).toHaveLength(1);
    expect(completed.result).toEqual({
      components: 142, findings: 4, kev: 1, incidents: 0,
      inputFormat: "CycloneDX", inputVersion: "1.6",
      coverageSummary: { complete: 5, limited: 1 },
      evidence: [{ name: "manifest.json", sha256: digest, href: `/evidence/${digest}` }],
    });
    expect(started).toMatchObject({ status: "running", progress: 20 });
    expect(events[0]).toMatchObject({ jobId: "job/1", sequence: 1, occurredAt: "2026-09-14T09:00:01Z" });
  });

  it("downloads binary evidence with server filename metadata", async () => {
    const response = new Response(new Uint8Array([1, 2, 3]), {
      status: 200,
      headers: {
        "content-type": "application/octet-stream",
        "content-disposition": "attachment; filename*=UTF-8''signed%20manifest.json",
      },
    });
    const fetcher = fetchSequence(response);
    const api = createReleaseOperationsApi({ baseUrl: "", fetch: fetcher });

    const evidence = await api.downloadEvidence(scope, "job/1", digest);

    expect(fetcher.mock.calls[0][0]).toBe(`${encodedBase}/analysis-jobs/job%2F1/evidence/${digest}`);
    expect(evidence).toMatchObject({ contentType: "application/octet-stream", filename: "signed manifest.json" });
    expect(Array.from(new Uint8Array(await evidence.blob.arrayBuffer()))).toEqual([1, 2, 3]);
  });

  it("gets, configures, runs, and lists monitoring history", async () => {
    const healthy = { ...monitoringDto, health: "healthy", limitations: [] };
    const fetcher = fetchSequence(json(monitoringDto), json(monitoringDto), json(healthy, 201), json([monitoringEvent]));
    const api = createReleaseOperationsApi({ baseUrl: "/engine", fetch: fetcher });

    const current = await api.getMonitoring(scope);
    await api.configureMonitoring(scope, {
      enabledSources: ["osv", "cisa_kev", "vendor_advisory"], cadenceMinutes: 60, enabled: true,
    });
    const run = await api.runMonitoring(scope);
    const events = await api.listMonitoringEvents(scope);

    expect(fetcher.mock.calls.map(([url, init]) => [url, init?.method])).toEqual([
      [`/engine${encodedBase}/monitoring`, "GET"],
      [`/engine${encodedBase}/monitoring`, "PUT"],
      [`/engine${encodedBase}/monitoring/runs`, "POST"],
      [`/engine${encodedBase}/monitoring/runs`, "GET"],
    ]);
    expect(JSON.parse(String(fetcher.mock.calls[1][1]?.body))).toEqual({
      enabled_sources: ["osv", "cisa_kev", "vendor_advisory"],
      cadence_minutes: 60,
      enabled: true,
    });
    expect(current).toMatchObject({
      enabledSources: ["osv", "cisa_kev", "vendor_advisory"],
      cadenceMinutes: 60,
      consecutiveFailures: 0,
      limitations: ["Vendor advisory endpoint unavailable"],
    });
    expect(run.health).toBe("healthy");
    expect(events[0]).toMatchObject({ runId: "run-1", eventType: "succeeded", actorId: "member-jane" });
  });

  it.each([
    [401, "unauthenticated"],
    [403, "forbidden"],
    [404, "not_found"],
    [409, "conflict"],
    [422, "validation"],
    [500, "http_error"],
  ] as const)("maps HTTP %s into %s", async (status, code) => {
    const detail = status === 422 ? [{ msg: "expected CycloneDX or SPDX SBOM" }] : "release operation failed";
    const api = createReleaseOperationsApi({ baseUrl: "", fetch: fetchSequence(json({ detail }, status)) });

    await expect(api.getMonitoring(scope)).rejects.toMatchObject({
      name: "ReleaseOperationsApiError", code, status,
      message: status === 422 ? "expected CycloneDX or SPDX SBOM" : "release operation failed",
    });
  });

  it("distinguishes aborts from network failures", async () => {
    const controller = new AbortController();
    controller.abort();
    const aborted = createReleaseOperationsApi({
      baseUrl: "",
      fetch: vi.fn<typeof fetch>(async () => { throw new DOMException("stopped", "AbortError"); }),
    });
    const offline = createReleaseOperationsApi({
      baseUrl: "",
      fetch: vi.fn<typeof fetch>(async () => { throw new TypeError("ECONNREFUSED"); }),
    });

    await expect(aborted.listAnalysisJobs(scope, { signal: controller.signal })).rejects.toMatchObject({ code: "aborted" });
    await expect(offline.getMonitoring(scope)).rejects.toMatchObject({
      code: "network", message: "Release operations service unavailable",
    });
  });

  it("rejects non-JSON, malformed JSON, invalid job progress, and bad monitoring sources", async () => {
    const fetcher = fetchSequence(
      new Response("gateway html", { status: 200, headers: { "content-type": "text/html" } }),
      new Response("{broken", { status: 200, headers: { "content-type": "application/json" } }),
      json({ ...queuedJob, progress: 101 }),
      json({ ...monitoringDto, enabled_sources: ["unknown"] }),
    );
    const api = createReleaseOperationsApi({ baseUrl: "", fetch: fetcher });

    await expect(api.getAnalysisJob(scope, "job-1")).rejects.toMatchObject({ code: "invalid_response", message: "Release operations service returned a non-JSON response" });
    await expect(api.getAnalysisJob(scope, "job-1")).rejects.toMatchObject({ code: "invalid_response", message: "Release operations service returned invalid JSON" });
    await expect(api.getAnalysisJob(scope, "job-1")).rejects.toBeInstanceOf(ReleaseOperationsApiError);
    await expect(api.getMonitoring(scope)).rejects.toMatchObject({ code: "invalid_response", message: "enabled_sources contains an unsupported value" });
  });

  it("maps JSON errors from evidence downloads without treating them as blobs", async () => {
    const api = createReleaseOperationsApi({
      baseUrl: "",
      fetch: fetchSequence(json({ detail: "evidence not found" }, 404)),
    });

    await expect(api.downloadEvidence(scope, "job-1", digest)).rejects.toMatchObject({
      code: "not_found", status: 404, message: "evidence not found",
    });
  });
});
