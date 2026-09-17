import { PortfolioApiError, type PortfolioApiErrorCode } from "./portfolioApi";
import type {
  DecisionKind,
  Finding,
  FindingDecision,
  FindingStatus,
  PriorityBand,
  Remediation,
  Severity,
} from "./types";

export type FindingApiErrorCode = PortfolioApiErrorCode;

export class FindingApiError extends PortfolioApiError {
  constructor(
    message: string,
    code: FindingApiErrorCode,
    status?: number,
    details?: unknown,
    options?: ErrorOptions,
  ) {
    super(message, code, status, details, options);
    this.name = "FindingApiError";
  }
}

export interface FindingRequestOptions {
  signal?: AbortSignal;
}

export interface FindingApiConfig {
  baseUrl: string;
  getBearerToken?: () => string | undefined | Promise<string | undefined>;
  fetch?: typeof globalThis.fetch;
}

export type ApiFindingStatus = "needs_review" | "open" | "in_progress" | "resolved";
export type ApiRemediationStatus = "not_planned" | "planned" | "in_progress" | "completed" | "verified";
export type Reachability = "reachable" | "not_reachable" | "unknown";
export type ReachabilityRecommendation = "reachable" | "not_reachable" | "review";
export type ReachabilityConfidence = "high" | "medium" | "low";

export interface FindingDecisionDto {
  id: string;
  finding_id: string;
  organization_id: string;
  decision: DecisionKind;
  rationale: string;
  actor_id: string;
  occurred_at: string;
  finding_version: number;
}

export interface FindingAuditDto {
  id: string;
  finding_id: string;
  organization_id: string;
  action: string;
  actor_id: string;
  payload: Record<string, unknown>;
  occurred_at: string;
}

export interface FindingDto {
  id: string;
  organization_id: string;
  product_id: string;
  release_id: string;
  source_key: string;
  reference_id: string;
  cve: string | null;
  component: string;
  purl: string | null;
  component_version: string;
  title: string;
  description: string;
  severity: Severity | "unknown";
  cvss: number | null;
  kev: boolean;
  epss: number | null;
  reachability: Reachability;
  recommendation_reachability: ReachabilityRecommendation | null;
  recommendation_confidence: ReachabilityConfidence | null;
  recommendation_reason_codes: string[];
  recommendation_review_required: boolean;
  reachability_evidence: Record<string, unknown>;
  reachability_limitations: string[];
  source: string;
  provenance: Record<string, unknown>;
  first_seen_at: string;
  last_seen_at: string;
  status: ApiFindingStatus;
  assignee_id: string | null;
  current_decision: DecisionKind | null;
  decision_rationale: string | null;
  decision_by: string | null;
  decided_at: string | null;
  remediation_plan: string | null;
  remediation_status: ApiRemediationStatus;
  remediation_due_date: string | null;
  verification_evidence: Record<string, unknown>[];
  version: number;
  created_at: string;
  updated_at: string;
}

export interface FindingDetailDto extends FindingDto {
  decision_history: FindingDecisionDto[];
  audit_history: FindingAuditDto[];
}

export interface FindingAuditEntry {
  id: string;
  action: string;
  actorId: string;
  at: string;
  payload: Record<string, unknown>;
}

export interface ManagedFinding extends Finding {
  organizationId: string;
  reportedSeverity: FindingDto["severity"];
  sourceKey: string;
  source: string;
  purl?: string;
  cvssScore: number | null;
  epss: number | null;
  reachabilityEvidence: Record<string, unknown>;
  reachabilityLimitations: string[];
  provenance: Record<string, unknown>;
  verificationEvidence: Record<string, unknown>[];
  currentDecision: DecisionKind | null;
  decisionRationale: string | null;
  decidedBy: string | null;
  decidedAt: string | null;
  remediationApiStatus: ApiRemediationStatus;
  version: number;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface FindingDetail extends ManagedFinding {
  decisionHistory: FindingDecision[];
  auditHistory: FindingAuditEntry[];
}

export interface FindingListFilters {
  view?: "needs_action" | "all";
  severity?: Array<Severity | "unknown">;
  status?: ApiFindingStatus[];
  kev?: boolean;
  reachability?: Reachability;
  assigneeId?: string;
  sort?: "priority" | "severity" | "newest" | "last_seen" | "due_date";
  productId?: string;
  releaseId?: string;
}

export interface AssignmentRequest {
  assigneeId: string | null;
  expectedVersion: number;
}

export interface DecisionRequest {
  decision: DecisionKind;
  rationale: string;
  expectedVersion: number;
}

export interface BatchDecisionRequest {
  items: Array<{ findingId: string; expectedVersion: number }>;
  rationale: string;
}

export interface ReviewedBatchDecisionRequest extends BatchDecisionRequest {
  decision: "affected" | "not_affected";
}

export interface VerificationEvidenceInput {
  [key: string]: unknown;
}

export interface RemediationRequest {
  plan?: string | null;
  status: ApiRemediationStatus;
  dueDate?: string | null;
  verificationEvidence?: VerificationEvidenceInput[];
  expectedVersion: number;
}

export interface FindingsApi {
  listFindings(organizationId: string, filters?: FindingListFilters, options?: FindingRequestOptions): Promise<ManagedFinding[]>;
  listReleaseFindings(organizationId: string, productId: string, releaseId: string, filters?: FindingListFilters, options?: FindingRequestOptions): Promise<ManagedFinding[]>;
  getFinding(organizationId: string, productId: string, releaseId: string, findingId: string, options?: FindingRequestOptions): Promise<FindingDetail>;
  assignFinding(organizationId: string, productId: string, releaseId: string, findingId: string, input: AssignmentRequest, options?: FindingRequestOptions): Promise<ManagedFinding>;
  recordDecision(organizationId: string, productId: string, releaseId: string, findingId: string, input: DecisionRequest, options?: FindingRequestOptions): Promise<FindingDetail>;
  approveRecommendations(organizationId: string, productId: string, releaseId: string, input: BatchDecisionRequest, options?: FindingRequestOptions): Promise<ManagedFinding[]>;
  decideBatch(organizationId: string, productId: string, releaseId: string, input: ReviewedBatchDecisionRequest, options?: FindingRequestOptions): Promise<ManagedFinding[]>;
  updateRemediation(organizationId: string, productId: string, releaseId: string, findingId: string, input: RemediationRequest, options?: FindingRequestOptions): Promise<FindingDetail>;
  getDecisionHistory(organizationId: string, productId: string, releaseId: string, findingId: string, options?: FindingRequestOptions): Promise<FindingDecision[]>;
  getAuditHistory(organizationId: string, productId: string, releaseId: string, findingId: string, options?: FindingRequestOptions): Promise<FindingAuditEntry[]>;
}

type JsonRecord = Record<string, unknown>;

const severities = ["critical", "high", "medium", "low", "unknown"] as const;
const apiStatuses = ["needs_review", "open", "in_progress", "resolved"] as const;
const decisions = ["affected", "not_affected", "accepted_risk", "deferred"] as const;
const remediationStatuses = ["not_planned", "planned", "in_progress", "completed", "verified"] as const;
const reachabilityStates = ["reachable", "not_reachable", "unknown"] as const;
const reachabilityRecommendations = ["reachable", "not_reachable", "review"] as const;
const reachabilityConfidences = ["high", "medium", "low"] as const;

function invalid(message: string, details?: unknown): never {
  throw new FindingApiError(message, "invalid_response", undefined, details);
}

function object(value: unknown, label: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object`, value);
  return Object.fromEntries(Object.entries(value));
}

function text(item: JsonRecord, key: string): string {
  const value = item[key];
  if (typeof value !== "string") invalid(`${key} must be a string`, value);
  return value;
}

function nullableText(item: JsonRecord, key: string): string | null {
  const value = item[key];
  if (value !== null && typeof value !== "string") invalid(`${key} must be a string or null`, value);
  return value;
}

function finite(item: JsonRecord, key: string): number {
  const value = item[key];
  if (typeof value !== "number" || !Number.isFinite(value)) invalid(`${key} must be a finite number`, value);
  return value;
}

function nullableFinite(item: JsonRecord, key: string): number | null {
  const value = item[key];
  if (value !== null && (typeof value !== "number" || !Number.isFinite(value))) invalid(`${key} must be a finite number or null`, value);
  return value;
}

function flag(item: JsonRecord, key: string): boolean {
  const value = item[key];
  if (typeof value !== "boolean") invalid(`${key} must be a boolean`, value);
  return value;
}

function member<const Values extends readonly string[]>(item: JsonRecord, key: string, values: Values): Values[number] {
  const value = text(item, key);
  if (!values.includes(value)) invalid(`${key} contains an unsupported value`, value);
  return value as Values[number];
}

function stringList(item: JsonRecord, key: string): string[] {
  const value = item[key];
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) invalid(`${key} must be a string array`, value);
  return value.map((entry) => String(entry));
}

function objectList(item: JsonRecord, key: string): JsonRecord[] {
  const value = item[key];
  if (!Array.isArray(value)) invalid(`${key} must be an array`, value);
  return value.map((entry) => object(entry, `${key} entry`));
}

function iso(value: string, key: string): string {
  if (!value || Number.isNaN(Date.parse(value))) invalid(`${key} must be an ISO date`, value);
  return value;
}

function nullableIso(value: string | null, key: string): string | null {
  return value === null ? null : iso(value, key);
}

function parseDecision(value: unknown): FindingDecisionDto {
  const item = object(value, "finding decision");
  const findingVersion = finite(item, "finding_version");
  if (!Number.isInteger(findingVersion) || findingVersion < 1) invalid("finding_version must be a positive integer", findingVersion);
  return {
    id: text(item, "id"), finding_id: text(item, "finding_id"), organization_id: text(item, "organization_id"),
    decision: member(item, "decision", decisions), rationale: text(item, "rationale"), actor_id: text(item, "actor_id"),
    occurred_at: iso(text(item, "occurred_at"), "occurred_at"), finding_version: findingVersion,
  };
}

function parseAudit(value: unknown): FindingAuditDto {
  const item = object(value, "finding audit entry");
  return {
    id: text(item, "id"), finding_id: text(item, "finding_id"), organization_id: text(item, "organization_id"),
    action: text(item, "action"), actor_id: text(item, "actor_id"), payload: object(item.payload, "audit payload"),
    occurred_at: iso(text(item, "occurred_at"), "occurred_at"),
  };
}

function parseFinding(value: unknown): FindingDto {
  const item = object(value, "finding");
  const version = finite(item, "version");
  if (!Number.isInteger(version) || version < 1) invalid("version must be a positive integer", version);
  const cvss = nullableFinite(item, "cvss");
  if (cvss !== null && (cvss < 0 || cvss > 10)) invalid("cvss must be between 0 and 10", cvss);
  const epss = nullableFinite(item, "epss");
  if (epss !== null && (epss < 0 || epss > 1)) invalid("epss must be between 0 and 1", epss);
  return {
    id: text(item, "id"), organization_id: text(item, "organization_id"), product_id: text(item, "product_id"),
    release_id: text(item, "release_id"), source_key: text(item, "source_key"), reference_id: text(item, "reference_id"),
    cve: nullableText(item, "cve"), component: text(item, "component"), purl: nullableText(item, "purl"),
    component_version: text(item, "component_version"), title: text(item, "title"), description: text(item, "description"),
    severity: member(item, "severity", severities), cvss, kev: flag(item, "kev"), epss,
    reachability: member(item, "reachability", reachabilityStates),
    recommendation_reachability: nullableMember(item, "recommendation_reachability", reachabilityRecommendations),
    recommendation_confidence: nullableMember(item, "recommendation_confidence", reachabilityConfidences),
    recommendation_reason_codes: stringList(item, "recommendation_reason_codes"),
    recommendation_review_required: flag(item, "recommendation_review_required"),
    reachability_evidence: object(item.reachability_evidence, "reachability_evidence"),
    reachability_limitations: stringList(item, "reachability_limitations"), source: text(item, "source"),
    provenance: object(item.provenance, "provenance"), first_seen_at: iso(text(item, "first_seen_at"), "first_seen_at"),
    last_seen_at: iso(text(item, "last_seen_at"), "last_seen_at"), status: member(item, "status", apiStatuses),
    assignee_id: nullableText(item, "assignee_id"), current_decision: nullableMember(item, "current_decision", decisions),
    decision_rationale: nullableText(item, "decision_rationale"), decision_by: nullableText(item, "decision_by"),
    decided_at: nullableIso(nullableText(item, "decided_at"), "decided_at"), remediation_plan: nullableText(item, "remediation_plan"),
    remediation_status: member(item, "remediation_status", remediationStatuses),
    remediation_due_date: nullableIso(nullableText(item, "remediation_due_date"), "remediation_due_date"),
    verification_evidence: objectList(item, "verification_evidence"), version,
    created_at: iso(text(item, "created_at"), "created_at"), updated_at: iso(text(item, "updated_at"), "updated_at"),
  };
}

function nullableMember<const Values extends readonly string[]>(item: JsonRecord, key: string, values: Values): Values[number] | null {
  const value = nullableText(item, key);
  if (value !== null && !values.includes(value)) invalid(`${key} contains an unsupported value`, value);
  return value as Values[number] | null;
}

function parseDetail(value: unknown): FindingDetailDto {
  const item = object(value, "finding detail");
  const decisionHistory = item.decision_history;
  const auditHistory = item.audit_history;
  if (!Array.isArray(decisionHistory)) invalid("decision_history must be an array", decisionHistory);
  if (!Array.isArray(auditHistory)) invalid("audit_history must be an array", auditHistory);
  return {
    ...parseFinding(item),
    decision_history: decisionHistory.map(parseDecision),
    audit_history: auditHistory.map(parseAudit),
  };
}

function parseList(value: unknown): FindingDto[] {
  if (!Array.isArray(value)) invalid("findings response must be an array", value);
  return value.map(parseFinding);
}

function mapDecision(dto: FindingDecisionDto): FindingDecision {
  return {
    id: dto.id,
    decision: dto.decision,
    rationale: dto.rationale,
    decidedBy: dto.actor_id,
    decidedAt: dto.occurred_at,
  };
}

function mapRemediation(status: ApiRemediationStatus, plan: string | null, dueDate: string | null): Remediation {
  const statuses: Record<ApiRemediationStatus, Remediation["status"]> = {
    not_planned: "not_started",
    planned: "planned",
    in_progress: "in_progress",
    completed: "verification_pending",
    verified: "verified",
  };
  return {
    status: statuses[status],
    plan: plan ?? undefined,
    targetDate: dueDate ?? undefined,
  };
}

function findingStatus(dto: FindingDto): FindingStatus {
  if (dto.status === "needs_review") return "needs_review";
  if (dto.status === "open") return "action_required";
  if (dto.status === "in_progress") return "in_remediation";
  return dto.current_decision === "accepted_risk" ? "accepted" : "resolved";
}

function priority(dto: FindingDto): PriorityBand {
  if (dto.kev && dto.reachability === "reachable") return "urgent";
  return { critical: "urgent", high: "high", medium: "normal", low: "low", unknown: "normal" }[dto.severity] as PriorityBand;
}

function currentDecision(dto: FindingDto): FindingDecision[] {
  if (!dto.current_decision || !dto.decision_rationale || !dto.decision_by || !dto.decided_at) return [];
  return [{
    id: `${dto.id}:current`, decision: dto.current_decision, rationale: dto.decision_rationale,
    decidedBy: dto.decision_by, decidedAt: dto.decided_at,
  }];
}

function evidenceIds(evidence: JsonRecord[]): string[] {
  return evidence.map((item, index) => {
    const candidate = item.id ?? item.sha256 ?? item.digest;
    return typeof candidate === "string" && candidate ? candidate : `verification:${index + 1}`;
  });
}

export function mapFinding(dto: FindingDto, history?: FindingDecisionDto[]): ManagedFinding {
  const severity: Severity = dto.severity === "unknown" ? "low" : dto.severity;
  return {
    id: dto.id,
    reference: dto.cve ?? dto.reference_id,
    productId: dto.product_id,
    releaseId: dto.release_id,
    title: dto.title,
    component: dto.component,
    componentVersion: dto.component_version,
    severity,
    cvss: dto.cvss ?? 0,
    status: findingStatus(dto),
    priority: priority(dto),
    kev: dto.kev,
    activelyExploited: dto.kev && dto.current_decision === "affected",
    affectedness: dto.current_decision === "affected" ? "confirmed" : dto.current_decision === "not_affected" ? "not_affected" : "unknown",
    reachability: dto.reachability,
    reachabilityRecommendation: dto.recommendation_reachability ?? "review",
    reachabilityConfidence: dto.recommendation_confidence ?? "low",
    reachabilityReasonCodes: dto.recommendation_reason_codes,
    reachabilityReviewRequired: dto.recommendation_review_required,
    summary: dto.description,
    actionReason: dto.decision_rationale ?? dto.reachability_limitations[0] ?? (dto.kev ? "Listed in CISA Known Exploited Vulnerabilities." : "Security review required."),
    introducedAt: dto.first_seen_at,
    updatedAt: dto.updated_at,
    dueAt: dto.remediation_due_date ?? undefined,
    assigneeId: dto.assignee_id ?? undefined,
    decisions: history ? history.map(mapDecision) : currentDecision(dto),
    remediation: mapRemediation(dto.remediation_status, dto.remediation_plan, dto.remediation_due_date),
    evidenceIds: evidenceIds(dto.verification_evidence),
    organizationId: dto.organization_id,
    reportedSeverity: dto.severity,
    sourceKey: dto.source_key,
    source: dto.source,
    purl: dto.purl ?? undefined,
    cvssScore: dto.cvss,
    epss: dto.epss,
    reachabilityEvidence: dto.reachability_evidence,
    reachabilityLimitations: dto.reachability_limitations,
    provenance: dto.provenance,
    verificationEvidence: dto.verification_evidence,
    currentDecision: dto.current_decision,
    decisionRationale: dto.decision_rationale,
    decidedBy: dto.decision_by,
    decidedAt: dto.decided_at,
    remediationApiStatus: dto.remediation_status,
    version: dto.version,
    firstSeenAt: dto.first_seen_at,
    lastSeenAt: dto.last_seen_at,
  };
}

export function mapFindingDetail(dto: FindingDetailDto): FindingDetail {
  return {
    ...mapFinding(dto, dto.decision_history),
    decisionHistory: dto.decision_history.map(mapDecision),
    auditHistory: dto.audit_history.map((entry) => ({
      id: entry.id, action: entry.action, actorId: entry.actor_id,
      at: entry.occurred_at, payload: entry.payload,
    })),
  };
}

function errorCode(status: number): FindingApiErrorCode {
  if (status === 401) return "unauthenticated";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 409) return "conflict";
  if (status === 422) return "validation";
  return "http_error";
}

function errorMessage(body: unknown, status: number): string {
  if (body && typeof body === "object" && "detail" in body) {
    const detail = Reflect.get(body, "detail");
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      const messages = detail.flatMap((item) => {
        if (!item || typeof item !== "object") return [];
        const message = Reflect.get(item, "msg");
        return typeof message === "string" ? [message] : [];
      });
      if (messages.length) return messages.join("; ");
    }
  }
  return `Findings request failed (${status})`;
}

function compact(value: JsonRecord): JsonRecord {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined));
}

function query(filters: FindingListFilters = {}): string {
  const result = new URLSearchParams();
  if (filters.view) result.set("view", filters.view);
  filters.severity?.forEach((value) => result.append("severity", value));
  filters.status?.forEach((value) => result.append("status", value));
  if (filters.kev !== undefined) result.set("kev", String(filters.kev));
  if (filters.reachability) result.set("reachability", filters.reachability);
  if (filters.assigneeId) result.set("assignee_id", filters.assigneeId);
  if (filters.sort) result.set("sort", filters.sort);
  if (filters.productId) result.set("product_id", filters.productId);
  if (filters.releaseId) result.set("release_id", filters.releaseId);
  const serialized = result.toString();
  return serialized ? `?${serialized}` : "";
}

export function createFindingsApi(config: FindingApiConfig): FindingsApi {
  const baseUrl = config.baseUrl.replace(/\/+$/, "");
  const fetcher = config.fetch ?? globalThis.fetch;

  async function request(path: string, init: RequestInit, options?: FindingRequestOptions): Promise<unknown> {
    const token = (await config.getBearerToken?.())?.trim();
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    if (init.body !== undefined) headers.set("Content-Type", "application/json");
    if (token) headers.set("Authorization", `Bearer ${token}`);
    let response: Response;
    try {
      response = await fetcher(`${baseUrl}${path}`, { ...init, headers, signal: options?.signal });
    } catch (cause) {
      if (options?.signal?.aborted || (cause instanceof DOMException && cause.name === "AbortError")) {
        throw new FindingApiError("Findings request aborted", "aborted", undefined, undefined, { cause });
      }
      throw new FindingApiError("Findings service unavailable", "network", undefined, undefined, { cause });
    }
    const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
    if (!contentType.includes("application/json") && !contentType.includes("+json")) {
      throw new FindingApiError("Findings service returned a non-JSON response", "invalid_response", response.status);
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch (cause) {
      throw new FindingApiError("Findings service returned invalid JSON", "invalid_response", response.status, undefined, { cause });
    }
    if (!response.ok) throw new FindingApiError(errorMessage(payload, response.status), errorCode(response.status), response.status, payload);
    return payload;
  }

  const id = encodeURIComponent;
  const organization = (organizationId: string) => `/v1/organizations/${id(organizationId)}`;
  const release = (organizationId: string, productId: string, releaseId: string) =>
    `${organization(organizationId)}/products/${id(productId)}/releases/${id(releaseId)}/findings`;
  const item = (organizationId: string, productId: string, releaseId: string, findingId: string) =>
    `${release(organizationId, productId, releaseId)}/${id(findingId)}`;
  const jsonBody = (value: JsonRecord) => JSON.stringify(compact(value));

  const api: FindingsApi = {
    async listFindings(organizationId, filters, options) {
      const path = `${organization(organizationId)}/findings${query(filters)}`;
      return parseList(await request(path, { method: "GET" }, options)).map((dto) => mapFinding(dto));
    },
    async listReleaseFindings(organizationId, productId, releaseId, filters, options) {
      return parseList(await request(`${release(organizationId, productId, releaseId)}${query(filters)}`, { method: "GET" }, options)).map((dto) => mapFinding(dto));
    },
    async getFinding(organizationId, productId, releaseId, findingId, options) {
      return mapFindingDetail(parseDetail(await request(item(organizationId, productId, releaseId, findingId), { method: "GET" }, options)));
    },
    async assignFinding(organizationId, productId, releaseId, findingId, input, options) {
      const payload = { assignee_id: input.assigneeId, expected_version: input.expectedVersion };
      return mapFinding(parseFinding(await request(`${item(organizationId, productId, releaseId, findingId)}/assignment`, { method: "PATCH", body: jsonBody(payload) }, options)));
    },
    async recordDecision(organizationId, productId, releaseId, findingId, input, options) {
      const payload = { decision: input.decision, rationale: input.rationale, expected_version: input.expectedVersion };
      return mapFindingDetail(parseDetail(await request(`${item(organizationId, productId, releaseId, findingId)}/decisions`, { method: "POST", body: jsonBody(payload) }, options)));
    },
    async approveRecommendations(organizationId, productId, releaseId, input, options) {
      const payload = {
        items: input.items.map((entry) => ({ finding_id: entry.findingId, expected_version: entry.expectedVersion })),
        rationale: input.rationale,
      };
      const path = `${release(organizationId, productId, releaseId)}/recommendations/approve`;
      return parseList(await request(path, { method: "POST", body: jsonBody(payload) }, options)).map((dto) => mapFinding(dto));
    },
    async decideBatch(organizationId, productId, releaseId, input, options) {
      const payload = {
        items: input.items.map((entry) => ({ finding_id: entry.findingId, expected_version: entry.expectedVersion })),
        rationale: input.rationale,
        decision: input.decision,
      };
      const path = `${release(organizationId, productId, releaseId)}/decisions/batch`;
      return parseList(await request(path, { method: "POST", body: jsonBody(payload) }, options)).map((dto) => mapFinding(dto));
    },
    async updateRemediation(organizationId, productId, releaseId, findingId, input, options) {
      const payload = {
        plan: input.plan, status: input.status, due_date: input.dueDate,
        verification_evidence: input.verificationEvidence ?? [], expected_version: input.expectedVersion,
      };
      return mapFindingDetail(parseDetail(await request(`${item(organizationId, productId, releaseId, findingId)}/remediation`, { method: "PUT", body: jsonBody(payload) }, options)));
    },
    async getDecisionHistory(organizationId, productId, releaseId, findingId, options) {
      return (await api.getFinding(organizationId, productId, releaseId, findingId, options)).decisionHistory;
    },
    async getAuditHistory(organizationId, productId, releaseId, findingId, options) {
      return (await api.getFinding(organizationId, productId, releaseId, findingId, options)).auditHistory;
    },
  };
  return api;
}
