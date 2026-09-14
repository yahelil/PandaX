export type ReleaseOperationsApiErrorCode =
  | "unauthenticated"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "validation"
  | "http_error"
  | "invalid_response"
  | "aborted"
  | "network";

export class ReleaseOperationsApiError extends Error {
  constructor(
    message: string,
    readonly code: ReleaseOperationsApiErrorCode,
    readonly status?: number,
    readonly details?: unknown,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "ReleaseOperationsApiError";
  }
}

export interface ReleaseOperationsApiConfig {
  baseUrl: string;
  getBearerToken?: () => string | undefined | Promise<string | undefined>;
  fetch?: typeof globalThis.fetch;
}

export interface ReleaseOperationsRequestOptions {
  signal?: AbortSignal;
}

export interface ReleaseScope {
  organizationId: string;
  productId: string;
  releaseId: string;
}

export type AnalysisJobStatus = "queued" | "running" | "completed" | "failed";

export interface SbomPreview {
  format: string;
  version: string;
  components: number;
  matchableComponents: number;
  skippedComponents: number;
  product: Record<string, unknown>;
}

export interface AnalysisEvidenceLink {
  name: string;
  sha256: string;
  href: string;
}

export interface ReleaseAnalysisResult {
  components: number;
  findings: number;
  kev: number;
  incidents: number;
  inputFormat: string;
  inputVersion: string;
  coverageSummary: Record<string, number>;
  evidence: AnalysisEvidenceLink[];
}

export interface ReleaseAnalysisJob {
  id: string;
  organizationId: string;
  productId: string;
  releaseId: string;
  filename: string;
  mediaType: string;
  sizeBytes: number;
  sha256: string;
  preview: SbomPreview;
  status: AnalysisJobStatus;
  stage: string;
  progress: number;
  result?: ReleaseAnalysisResult;
  error?: string;
  createdAt: string;
  updatedAt: string;
  startedAt?: string;
  completedAt?: string;
}

export interface AnalysisJobEvent {
  id: string;
  jobId: string;
  sequence: number;
  kind: string;
  status: AnalysisJobStatus;
  stage: string;
  progress: number;
  message: string;
  details: Record<string, unknown>;
  occurredAt: string;
}

export interface UploadSbomInput {
  file: Blob;
  filename: string;
  idempotencyKey: string;
}

export interface AnalysisEvidenceFile {
  blob: Blob;
  contentType: string;
  filename?: string;
}

export type MonitoringSource = "osv" | "cisa_kev" | "epss" | "native_advisory" | "vendor_advisory";
export type ReleaseMonitoringHealth = "healthy" | "degraded" | "failed" | "inactive";

export interface MonitoringConfigurationInput {
  enabledSources: MonitoringSource[];
  cadenceMinutes: number;
  enabled: boolean;
}

export interface ReleaseMonitoringStatus {
  organizationId: string;
  productId: string;
  releaseId: string;
  enabledSources: MonitoringSource[];
  cadenceMinutes: number;
  enabled: boolean;
  health: ReleaseMonitoringHealth;
  nextCheckAt?: string;
  lastCheckAt?: string;
  lastSuccessAt?: string;
  consecutiveFailures: number;
  coverage: Record<string, unknown>;
  limitations: string[];
  running: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface MonitoringRunEvent {
  id: string;
  runId: string;
  sequence: number;
  eventType: "started" | "succeeded" | "failed";
  trigger: "manual" | "scheduled";
  health: ReleaseMonitoringHealth;
  coverage: Record<string, unknown>;
  limitations: string[];
  message: string;
  actorId: string;
  occurredAt: string;
}

export interface ReleaseOperationsApi {
  uploadSbom(scope: ReleaseScope, input: UploadSbomInput, options?: ReleaseOperationsRequestOptions): Promise<ReleaseAnalysisJob>;
  listAnalysisJobs(scope: ReleaseScope, options?: ReleaseOperationsRequestOptions): Promise<ReleaseAnalysisJob[]>;
  getAnalysisJob(scope: ReleaseScope, jobId: string, options?: ReleaseOperationsRequestOptions): Promise<ReleaseAnalysisJob>;
  runAnalysisJob(scope: ReleaseScope, jobId: string, options?: ReleaseOperationsRequestOptions): Promise<ReleaseAnalysisJob>;
  listAnalysisEvents(scope: ReleaseScope, jobId: string, options?: ReleaseOperationsRequestOptions): Promise<AnalysisJobEvent[]>;
  downloadEvidence(scope: ReleaseScope, jobId: string, digest: string, options?: ReleaseOperationsRequestOptions): Promise<AnalysisEvidenceFile>;
  getMonitoring(scope: ReleaseScope, options?: ReleaseOperationsRequestOptions): Promise<ReleaseMonitoringStatus>;
  configureMonitoring(scope: ReleaseScope, input: MonitoringConfigurationInput, options?: ReleaseOperationsRequestOptions): Promise<ReleaseMonitoringStatus>;
  runMonitoring(scope: ReleaseScope, options?: ReleaseOperationsRequestOptions): Promise<ReleaseMonitoringStatus>;
  listMonitoringEvents(scope: ReleaseScope, options?: ReleaseOperationsRequestOptions): Promise<MonitoringRunEvent[]>;
}

type JsonRecord = Record<string, unknown>;

const jobStatuses = ["queued", "running", "completed", "failed"] as const;
const monitoringSources = ["osv", "cisa_kev", "epss", "native_advisory", "vendor_advisory"] as const;
const monitoringHealth = ["healthy", "degraded", "failed", "inactive"] as const;
const eventTypes = ["started", "succeeded", "failed"] as const;
const triggers = ["manual", "scheduled"] as const;
const digestPattern = /^[0-9a-f]{64}$/;

function invalid(message: string, details?: unknown): never {
  throw new ReleaseOperationsApiError(message, "invalid_response", undefined, details);
}

function object(value: unknown, label: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object`, value);
  return value as JsonRecord;
}

function string(item: JsonRecord, key: string): string {
  const value = item[key];
  if (typeof value !== "string") invalid(`${key} must be a string`, value);
  return value;
}

function optionalString(item: JsonRecord, key: string): string | undefined {
  const value = item[key];
  if (value === null) return undefined;
  if (typeof value !== "string") invalid(`${key} must be a string or null`, value);
  return value;
}

function timestamp(item: JsonRecord, key: string): string {
  const value = string(item, key);
  if (!Number.isFinite(Date.parse(value))) invalid(`${key} must be an ISO date-time`, value);
  return value;
}

function optionalTimestamp(item: JsonRecord, key: string): string | undefined {
  const value = optionalString(item, key);
  if (value !== undefined && !Number.isFinite(Date.parse(value))) invalid(`${key} must be an ISO date-time or null`, value);
  return value;
}

function number(item: JsonRecord, key: string): number {
  const value = item[key];
  if (typeof value !== "number" || !Number.isFinite(value)) invalid(`${key} must be a finite number`, value);
  return value;
}

function integer(item: JsonRecord, key: string, minimum = 0): number {
  const value = number(item, key);
  if (!Number.isInteger(value) || value < minimum) invalid(`${key} must be an integer of at least ${minimum}`, value);
  return value;
}

function boolean(item: JsonRecord, key: string): boolean {
  const value = item[key];
  if (typeof value !== "boolean") invalid(`${key} must be a boolean`, value);
  return value;
}

function member<const Values extends readonly string[]>(item: JsonRecord, key: string, values: Values): Values[number] {
  const value = string(item, key);
  if (!values.includes(value)) invalid(`${key} contains an unsupported value`, value);
  return value as Values[number];
}

function list<T>(value: unknown, label: string, parse: (item: unknown) => T): T[] {
  if (!Array.isArray(value)) invalid(`${label} must be an array`, value);
  return value.map(parse);
}

function stringList(item: JsonRecord, key: string): string[] {
  return list(item[key], key, (value) => {
    if (typeof value !== "string") invalid(`${key} must contain strings`, value);
    return value;
  });
}

function jsonObject(item: JsonRecord, key: string): Record<string, unknown> {
  return { ...object(item[key], key) };
}

function parsePreview(value: unknown): SbomPreview {
  const item = object(value, "SBOM preview");
  return {
    format: string(item, "format"), version: string(item, "version"),
    components: integer(item, "components"), matchableComponents: integer(item, "matchable_components"),
    skippedComponents: integer(item, "skipped_components"), product: jsonObject(item, "product"),
  };
}

function parseEvidence(value: unknown): AnalysisEvidenceLink {
  const item = object(value, "evidence link");
  const sha256 = string(item, "sha256");
  if (!digestPattern.test(sha256)) invalid("sha256 must be a lowercase SHA-256 digest", sha256);
  return { name: string(item, "name"), sha256, href: string(item, "href") };
}

function parseCoverageSummary(value: unknown): Record<string, number> {
  const item = object(value, "coverage_summary");
  const result: Record<string, number> = {};
  for (const [key, entry] of Object.entries(item)) {
    if (typeof entry !== "number" || !Number.isInteger(entry) || entry < 0) invalid("coverage_summary values must be non-negative integers", entry);
    result[key] = entry;
  }
  return result;
}

function parseResult(value: unknown): ReleaseAnalysisResult {
  const item = object(value, "analysis result");
  return {
    components: integer(item, "components"), findings: integer(item, "findings"),
    kev: integer(item, "kev"), incidents: integer(item, "incidents"),
    inputFormat: string(item, "input_format"), inputVersion: string(item, "input_version"),
    coverageSummary: parseCoverageSummary(item.coverage_summary),
    evidence: list(item.evidence, "evidence", parseEvidence),
  };
}

function parseJob(value: unknown): ReleaseAnalysisJob {
  const item = object(value, "analysis job");
  const sha256 = string(item, "sha256");
  if (!digestPattern.test(sha256)) invalid("sha256 must be a lowercase SHA-256 digest", sha256);
  const progress = integer(item, "progress");
  if (progress > 100) invalid("progress must not exceed 100", progress);
  const rawResult = item.result;
  if (rawResult !== null && (typeof rawResult !== "object" || Array.isArray(rawResult))) invalid("result must be an object or null", rawResult);
  return {
    id: string(item, "id"), organizationId: string(item, "organization_id"),
    productId: string(item, "product_id"), releaseId: string(item, "release_id"),
    filename: string(item, "filename"), mediaType: string(item, "media_type"),
    sizeBytes: integer(item, "size_bytes"), sha256, preview: parsePreview(item.preview),
    status: member(item, "status", jobStatuses), stage: string(item, "stage"), progress,
    result: rawResult === null ? undefined : parseResult(rawResult), error: optionalString(item, "error"),
    createdAt: timestamp(item, "created_at"), updatedAt: timestamp(item, "updated_at"),
    startedAt: optionalTimestamp(item, "started_at"), completedAt: optionalTimestamp(item, "completed_at"),
  };
}

function parseAnalysisEvent(value: unknown): AnalysisJobEvent {
  const item = object(value, "analysis event");
  const progress = integer(item, "progress");
  if (progress > 100) invalid("progress must not exceed 100", progress);
  return {
    id: string(item, "id"), jobId: string(item, "job_id"), sequence: integer(item, "sequence", 1),
    kind: string(item, "kind"), status: member(item, "status", jobStatuses),
    stage: string(item, "stage"), progress, message: string(item, "message"),
    details: jsonObject(item, "details"), occurredAt: timestamp(item, "occurred_at"),
  };
}

function parseMonitoringStatus(value: unknown): ReleaseMonitoringStatus {
  const item = object(value, "monitoring status");
  const sources = list(item.enabled_sources, "enabled_sources", (source) => {
    if (typeof source !== "string" || !monitoringSources.includes(source as MonitoringSource)) {
      invalid("enabled_sources contains an unsupported value", source);
    }
    return source as MonitoringSource;
  });
  return {
    organizationId: string(item, "organization_id"), productId: string(item, "product_id"),
    releaseId: string(item, "release_id"), enabledSources: sources,
    cadenceMinutes: integer(item, "cadence_minutes", 5), enabled: boolean(item, "enabled"),
    health: member(item, "health", monitoringHealth), nextCheckAt: optionalTimestamp(item, "next_check_at"),
    lastCheckAt: optionalTimestamp(item, "last_check_at"), lastSuccessAt: optionalTimestamp(item, "last_success_at"),
    consecutiveFailures: integer(item, "consecutive_failures"), coverage: jsonObject(item, "coverage"),
    limitations: stringList(item, "limitations"), running: boolean(item, "running"),
    createdAt: timestamp(item, "created_at"), updatedAt: timestamp(item, "updated_at"),
  };
}

function parseMonitoringEvent(value: unknown): MonitoringRunEvent {
  const item = object(value, "monitoring event");
  return {
    id: string(item, "id"), runId: string(item, "run_id"), sequence: integer(item, "sequence", 1),
    eventType: member(item, "event_type", eventTypes), trigger: member(item, "trigger", triggers),
    health: member(item, "health", monitoringHealth), coverage: jsonObject(item, "coverage"),
    limitations: stringList(item, "limitations"), message: string(item, "message"),
    actorId: string(item, "actor_id"), occurredAt: timestamp(item, "occurred_at"),
  };
}

function errorCode(status: number): ReleaseOperationsApiErrorCode {
  if (status === 401) return "unauthenticated";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 409) return "conflict";
  if (status === 422) return "validation";
  return "http_error";
}

function errorMessage(body: unknown, status: number): string {
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail?: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      const messages = detail.flatMap((entry) => entry && typeof entry === "object" && "msg" in entry && typeof entry.msg === "string" ? [entry.msg] : []);
      if (messages.length) return messages.join("; ");
    }
  }
  return `Release operations request failed (${status})`;
}

function compact(value: JsonRecord): JsonRecord {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined));
}

function responseFilename(response: Response): string | undefined {
  const disposition = response.headers.get("content-disposition") ?? "";
  const encoded = disposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  if (encoded) {
    try { return decodeURIComponent(encoded); } catch { return encoded; }
  }
  return disposition.match(/filename="?([^";]+)"?/i)?.[1];
}

export function createReleaseOperationsApi(config: ReleaseOperationsApiConfig): ReleaseOperationsApi {
  const baseUrl = config.baseUrl.replace(/\/+$/, "");
  const fetcher = config.fetch ?? globalThis.fetch;
  const id = encodeURIComponent;
  const releasePath = (scope: ReleaseScope) => (
    `/v1/organizations/${id(scope.organizationId)}/products/${id(scope.productId)}/releases/${id(scope.releaseId)}`
  );
  const jobsPath = (scope: ReleaseScope) => `${releasePath(scope)}/analysis-jobs`;
  const monitoringPath = (scope: ReleaseScope) => `${releasePath(scope)}/monitoring`;

  async function send(
    path: string,
    init: RequestInit,
    options?: ReleaseOperationsRequestOptions,
  ): Promise<Response> {
    const token = (await config.getBearerToken?.())?.trim();
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    if (token) headers.set("Authorization", `Bearer ${token}`);
    try {
      return await fetcher(`${baseUrl}${path}`, { ...init, headers, signal: options?.signal });
    } catch (cause) {
      const abortError = cause && typeof cause === "object" && "name" in cause && cause.name === "AbortError";
      if (options?.signal?.aborted || abortError) {
        throw new ReleaseOperationsApiError("Release operations request aborted", "aborted", undefined, undefined, { cause });
      }
      throw new ReleaseOperationsApiError("Release operations service unavailable", "network", undefined, undefined, { cause });
    }
  }

  async function jsonRequest(
    path: string,
    init: RequestInit,
    options?: ReleaseOperationsRequestOptions,
  ): Promise<unknown> {
    const response = await send(path, init, options);
    const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
    if (!contentType.includes("application/json") && !contentType.includes("+json")) {
      throw new ReleaseOperationsApiError("Release operations service returned a non-JSON response", "invalid_response", response.status);
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch (cause) {
      throw new ReleaseOperationsApiError("Release operations service returned invalid JSON", "invalid_response", response.status, undefined, { cause });
    }
    if (!response.ok) throw new ReleaseOperationsApiError(errorMessage(body, response.status), errorCode(response.status), response.status, body);
    return body;
  }

  async function evidenceRequest(
    path: string,
    options?: ReleaseOperationsRequestOptions,
  ): Promise<AnalysisEvidenceFile> {
    const response = await send(path, { method: "GET" }, options);
    if (!response.ok) {
      const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
      let body: unknown;
      if (contentType.includes("json")) {
        try { body = await response.json(); } catch { body = undefined; }
      }
      throw new ReleaseOperationsApiError(errorMessage(body, response.status), errorCode(response.status), response.status, body);
    }
    return {
      blob: await response.blob(),
      contentType: response.headers.get("content-type") || "application/octet-stream",
      filename: responseFilename(response),
    };
  }

  const jsonBody = (value: JsonRecord): RequestInit => ({
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(compact(value)),
  });

  return {
    async uploadSbom(scope, input, options) {
      const form = new FormData();
      form.append("sbom", input.file, input.filename);
      return parseJob(await jsonRequest(jobsPath(scope), {
        method: "POST", headers: { "Idempotency-Key": input.idempotencyKey }, body: form,
      }, options));
    },
    async listAnalysisJobs(scope, options) {
      return list(await jsonRequest(jobsPath(scope), { method: "GET" }, options), "analysis jobs", parseJob);
    },
    async getAnalysisJob(scope, jobId, options) {
      return parseJob(await jsonRequest(`${jobsPath(scope)}/${id(jobId)}`, { method: "GET" }, options));
    },
    async runAnalysisJob(scope, jobId, options) {
      return parseJob(await jsonRequest(`${jobsPath(scope)}/${id(jobId)}/run`, { method: "POST" }, options));
    },
    async listAnalysisEvents(scope, jobId, options) {
      return list(
        await jsonRequest(`${jobsPath(scope)}/${id(jobId)}/events`, { method: "GET" }, options),
        "analysis events", parseAnalysisEvent,
      );
    },
    async downloadEvidence(scope, jobId, digest, options) {
      return evidenceRequest(`${jobsPath(scope)}/${id(jobId)}/evidence/${id(digest)}`, options);
    },
    async getMonitoring(scope, options) {
      return parseMonitoringStatus(await jsonRequest(monitoringPath(scope), { method: "GET" }, options));
    },
    async configureMonitoring(scope, input, options) {
      return parseMonitoringStatus(await jsonRequest(monitoringPath(scope), jsonBody({
        enabled_sources: input.enabledSources,
        cadence_minutes: input.cadenceMinutes,
        enabled: input.enabled,
      }), options));
    },
    async runMonitoring(scope, options) {
      return parseMonitoringStatus(await jsonRequest(`${monitoringPath(scope)}/runs`, { method: "POST" }, options));
    },
    async listMonitoringEvents(scope, options) {
      return list(
        await jsonRequest(`${monitoringPath(scope)}/runs`, { method: "GET" }, options),
        "monitoring events", parseMonitoringEvent,
      );
    },
  };
}
