export type OperationsApiErrorCode =
  | "unauthenticated"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "validation"
  | "http_error"
  | "invalid_response"
  | "aborted"
  | "network";

export class OperationsApiError extends Error {
  constructor(
    message: string,
    readonly code: OperationsApiErrorCode,
    readonly status?: number,
    readonly details?: unknown,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "OperationsApiError";
  }
}

export interface OperationsApiConfig {
  baseUrl: string;
  getBearerToken?: () => string | undefined | Promise<string | undefined>;
  fetch?: typeof globalThis.fetch;
}

export interface OperationsRequestOptions {
  signal?: AbortSignal;
}

export interface HomeRequestOptions extends OperationsRequestOptions {
  queueLimit?: number;
  recentLimit?: number;
}

export type HomeMonitoringState = "healthy" | "degraded" | "failed" | "stale" | "inactive" | "not_configured";
export type HomeActionSource = "finding" | "compliance" | "monitoring" | "document";
export type HomePriority = "urgent" | "high" | "normal" | "low";
export type RecentChangeSource = HomeActionSource | "portfolio";

export interface OperationsMonitoringSummary {
  state: HomeMonitoringState;
  supportedReleases: number;
  configured: number;
  healthy: number;
  degraded: number;
  failed: number;
  stale: number;
  inactive: number;
  notConfigured: number;
  lastSuccessAt?: string;
  lastCheckAt?: string;
  nextCheckAt?: string;
  cadenceMinutes: number[];
  sources: Array<{ source: string; state: Exclude<HomeMonitoringState, "not_configured">; releaseCount: number }>;
}

export interface OperationsActionCounters {
  actionTotal: number;
  findingsNeedingAction: number;
  urgentFindings: number;
  reachableKevFindings: number;
  complianceActions: number;
  overdueObligations: number;
  dueSoonObligations: number;
  missingEvidence: number;
  pendingApprovals: number;
  documentsNeedingAction: number;
  monitoringIssues: number;
}

export interface OperationsHomeAction {
  id: string;
  sourceType: HomeActionSource;
  sourceId: string;
  productId?: string;
  releaseId?: string;
  productName?: string;
  releaseVersion?: string;
  title: string;
  reason: string;
  priority: HomePriority;
  dueAt?: string;
  score: number;
  targetUrl: string;
  updatedAt: string;
}

export interface OperationsRecentChange {
  id: string;
  sourceType: RecentChangeSource;
  sourceId: string;
  productId?: string;
  releaseId?: string;
  title: string;
  description: string;
  actorId: string;
  occurredAt: string;
  targetUrl: string;
}

export interface OperationsHome {
  organizationId: string;
  generatedAt: string;
  monitoring: OperationsMonitoringSummary;
  counters: OperationsActionCounters;
  actionQueue: OperationsHomeAction[];
  recentChanges: OperationsRecentChange[];
  dataWarnings: string[];
}

export type SearchCategory = "products" | "releases" | "findings" | "compliance" | "documents";

export interface SearchRequestOptions extends OperationsRequestOptions {
  categories?: SearchCategory[];
  limit?: number;
}

export interface OperationsSearchResult {
  category: SearchCategory;
  id: string;
  title: string;
  subtitle: string;
  productId?: string;
  releaseId?: string;
  priority?: string;
  url: string;
  rank: number;
}

export interface OperationsSearchGroup {
  category: SearchCategory;
  results: OperationsSearchResult[];
}

export interface OperationsSearchResponse {
  query: string;
  total: number;
  groups: OperationsSearchGroup[];
}

export type OperationsNotificationKind = "finding" | "compliance" | "monitoring" | "document" | "analysis" | "system";
export type OperationsNotificationPriority = "critical" | "high" | "medium" | "low" | "info";
export type NotificationInboxView = "unread_action" | "unread" | "action" | "all";

export interface NotificationListOptions extends OperationsRequestOptions {
  view?: NotificationInboxView;
  kind?: OperationsNotificationKind;
  priority?: OperationsNotificationPriority;
  productId?: string;
  limit?: number;
}

export interface OperationsNotification {
  id: string;
  organizationId: string;
  sourceFingerprint: string;
  kind: OperationsNotificationKind;
  priority: OperationsNotificationPriority;
  title: string;
  detail: string;
  productId?: string;
  releaseId?: string;
  targetUrl: string;
  requiresAction: boolean;
  readAt?: string;
  acknowledgedAt?: string;
  acknowledgedBy?: string;
  firstSeenAt: string;
  lastSeenAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface OperationsApi {
  getHome(organizationId: string, options?: HomeRequestOptions): Promise<OperationsHome>;
  search(organizationId: string, query: string, options?: SearchRequestOptions): Promise<OperationsSearchResponse>;
  listNotifications(organizationId: string, options?: NotificationListOptions): Promise<OperationsNotification[]>;
  markRead(organizationId: string, notificationId: string, options?: OperationsRequestOptions): Promise<OperationsNotification>;
  acknowledge(organizationId: string, notificationId: string, options?: OperationsRequestOptions): Promise<OperationsNotification>;
}

type JsonRecord = Record<string, unknown>;

const monitoringStates = ["healthy", "degraded", "failed", "stale", "inactive", "not_configured"] as const;
const homeActionSources = ["finding", "compliance", "monitoring", "document"] as const;
const homePriorities = ["urgent", "high", "normal", "low"] as const;
const recentSources = [...homeActionSources, "portfolio"] as const;
const searchCategories = ["products", "releases", "findings", "compliance", "documents"] as const;
const notificationKinds = ["finding", "compliance", "monitoring", "document", "analysis", "system"] as const;
const notificationPriorities = ["critical", "high", "medium", "low", "info"] as const;

function invalid(message: string, details?: unknown): never {
  throw new OperationsApiError(message, "invalid_response", undefined, details);
}

function record(value: unknown, label: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object`, value);
  return value as JsonRecord;
}

function string(item: JsonRecord, key: string): string {
  const value = item[key];
  if (typeof value !== "string") invalid(`${key} must be a string`, value);
  return value;
}

function nullableString(item: JsonRecord, key: string): string | undefined {
  const value = item[key];
  if (value === null) return undefined;
  if (typeof value !== "string") invalid(`${key} must be a string or null`, value);
  return value;
}

function dateTime(item: JsonRecord, key: string): string {
  const value = string(item, key);
  if (!Number.isFinite(Date.parse(value))) invalid(`${key} must be an ISO date-time`, value);
  return value;
}

function nullableDateTime(item: JsonRecord, key: string): string | undefined {
  const value = nullableString(item, key);
  if (value !== undefined && !Number.isFinite(Date.parse(value))) invalid(`${key} must be an ISO date-time or null`, value);
  return value;
}

function number(item: JsonRecord, key: string, integer = false): number {
  const value = item[key];
  if (typeof value !== "number" || !Number.isFinite(value) || (integer && !Number.isInteger(value))) {
    invalid(`${key} must be a finite${integer ? " integer" : " number"}`, value);
  }
  return value;
}

function count(item: JsonRecord, key: string): number {
  const value = number(item, key, true);
  if (value < 0) invalid(`${key} must be non-negative`, value);
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

function array<T>(value: unknown, label: string, parse: (item: unknown) => T): T[] {
  if (!Array.isArray(value)) invalid(`${label} must be an array`, value);
  return value.map(parse);
}

function stringArray(item: JsonRecord, key: string): string[] {
  return array(item[key], key, (value) => {
    if (typeof value !== "string") invalid(`${key} must contain strings`, value);
    return value;
  });
}

function parseMonitoring(value: unknown): OperationsMonitoringSummary {
  const item = record(value, "monitoring");
  return {
    state: member(item, "state", monitoringStates),
    supportedReleases: count(item, "supported_releases"),
    configured: count(item, "configured"),
    healthy: count(item, "healthy"),
    degraded: count(item, "degraded"),
    failed: count(item, "failed"),
    stale: count(item, "stale"),
    inactive: count(item, "inactive"),
    notConfigured: count(item, "not_configured"),
    lastSuccessAt: nullableDateTime(item, "last_success_at"),
    lastCheckAt: nullableDateTime(item, "last_check_at"),
    nextCheckAt: nullableDateTime(item, "next_check_at"),
    cadenceMinutes: array(item.cadence_minutes, "cadence_minutes", (value) => {
      if (typeof value !== "number" || !Number.isInteger(value) || value < 5) invalid("cadence_minutes must contain valid intervals", value);
      return value;
    }),
    sources: array(item.sources, "monitoring sources", (value) => {
      const source = record(value, "monitoring source");
      return {
        source: string(source, "source"),
        state: member(source, "state", monitoringStates.filter((state) => state !== "not_configured")),
        releaseCount: count(source, "release_count"),
      };
    }),
  };
}

function parseCounters(value: unknown): OperationsActionCounters {
  const item = record(value, "action counters");
  return {
    actionTotal: count(item, "action_total"),
    findingsNeedingAction: count(item, "findings_needing_action"),
    urgentFindings: count(item, "urgent_findings"),
    reachableKevFindings: count(item, "reachable_kev_findings"),
    complianceActions: count(item, "compliance_actions"),
    overdueObligations: count(item, "overdue_obligations"),
    dueSoonObligations: count(item, "due_soon_obligations"),
    missingEvidence: count(item, "missing_evidence"),
    pendingApprovals: count(item, "pending_approvals"),
    documentsNeedingAction: count(item, "documents_needing_action"),
    monitoringIssues: count(item, "monitoring_issues"),
  };
}

function parseHomeAction(value: unknown): OperationsHomeAction {
  const item = record(value, "home action");
  return {
    id: string(item, "id"), sourceType: member(item, "source_type", homeActionSources),
    sourceId: string(item, "source_id"), productId: nullableString(item, "product_id"),
    releaseId: nullableString(item, "release_id"), productName: nullableString(item, "product_name"),
    releaseVersion: nullableString(item, "release_version"), title: string(item, "title"),
    reason: string(item, "reason"), priority: member(item, "priority", homePriorities),
    dueAt: nullableDateTime(item, "due_at"), score: number(item, "score", true),
    targetUrl: string(item, "target_url"), updatedAt: dateTime(item, "updated_at"),
  };
}

function parseRecentChange(value: unknown): OperationsRecentChange {
  const item = record(value, "recent change");
  return {
    id: string(item, "id"), sourceType: member(item, "source_type", recentSources),
    sourceId: string(item, "source_id"), productId: nullableString(item, "product_id"),
    releaseId: nullableString(item, "release_id"), title: string(item, "title"),
    description: string(item, "description"), actorId: string(item, "actor_id"),
    occurredAt: dateTime(item, "occurred_at"), targetUrl: string(item, "target_url"),
  };
}

function parseHome(value: unknown): OperationsHome {
  const item = record(value, "home response");
  return {
    organizationId: string(item, "organization_id"), generatedAt: dateTime(item, "generated_at"),
    monitoring: parseMonitoring(item.monitoring), counters: parseCounters(item.counters),
    actionQueue: array(item.action_queue, "action_queue", parseHomeAction),
    recentChanges: array(item.recent_changes, "recent_changes", parseRecentChange),
    dataWarnings: stringArray(item, "data_warnings"),
  };
}

function parseSearchResult(value: unknown): OperationsSearchResult {
  const item = record(value, "search result");
  const rank = number(item, "rank", true);
  if (rank < 0) invalid("rank must be non-negative", rank);
  return {
    category: member(item, "category", searchCategories), id: string(item, "id"),
    title: string(item, "title"), subtitle: string(item, "subtitle"),
    productId: nullableString(item, "product_id"), releaseId: nullableString(item, "release_id"),
    priority: nullableString(item, "priority"), url: string(item, "url"), rank,
  };
}

function parseSearchGroup(value: unknown): OperationsSearchGroup {
  const item = record(value, "search group");
  const category = member(item, "category", searchCategories);
  const results = array(item.results, "search results", parseSearchResult);
  if (results.some((result) => result.category !== category)) invalid("search result category does not match its group", value);
  return { category, results };
}

function parseSearch(value: unknown): OperationsSearchResponse {
  const item = record(value, "search response");
  const groups = array(item.groups, "search groups", parseSearchGroup);
  const total = count(item, "total");
  if (groups.reduce((sum, group) => sum + group.results.length, 0) !== total) {
    invalid("search total does not match grouped results", value);
  }
  return { query: string(item, "query"), total, groups };
}

function parseNotification(value: unknown): OperationsNotification {
  const item = record(value, "notification");
  return {
    id: string(item, "id"), organizationId: string(item, "organization_id"),
    sourceFingerprint: string(item, "source_fingerprint"), kind: member(item, "kind", notificationKinds),
    priority: member(item, "priority", notificationPriorities), title: string(item, "title"),
    detail: string(item, "detail"), productId: nullableString(item, "product_id"),
    releaseId: nullableString(item, "release_id"), targetUrl: string(item, "target_url"),
    requiresAction: boolean(item, "requires_action"), readAt: nullableDateTime(item, "read_at"),
    acknowledgedAt: nullableDateTime(item, "acknowledged_at"),
    acknowledgedBy: nullableString(item, "acknowledged_by"),
    firstSeenAt: dateTime(item, "first_seen_at"), lastSeenAt: dateTime(item, "last_seen_at"),
    createdAt: dateTime(item, "created_at"), updatedAt: dateTime(item, "updated_at"),
  };
}

function errorCode(status: number): OperationsApiErrorCode {
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
      const messages = detail.flatMap((item) => item && typeof item === "object" && "msg" in item && typeof item.msg === "string" ? [item.msg] : []);
      if (messages.length) return messages.join("; ");
    }
  }
  return `Operations request failed (${status})`;
}

function queryString(values: Array<[string, string | number | undefined]>): string {
  const query = new URLSearchParams();
  for (const [key, value] of values) if (value !== undefined) query.append(key, String(value));
  const encoded = query.toString();
  return encoded ? `?${encoded}` : "";
}

export function createOperationsApi(config: OperationsApiConfig): OperationsApi {
  const baseUrl = config.baseUrl.replace(/\/+$/, "");
  const fetcher = config.fetch ?? globalThis.fetch;
  const id = encodeURIComponent;
  const organizationPath = (organizationId: string) => `/v1/organizations/${id(organizationId)}`;

  async function request(path: string, method: "GET" | "POST", options?: OperationsRequestOptions): Promise<unknown> {
    const token = (await config.getBearerToken?.())?.trim();
    const headers = new Headers({ Accept: "application/json" });
    if (token) headers.set("Authorization", `Bearer ${token}`);
    let response: Response;
    try {
      response = await fetcher(`${baseUrl}${path}`, { method, headers, signal: options?.signal });
    } catch (cause) {
      const abortError = cause && typeof cause === "object" && "name" in cause && cause.name === "AbortError";
      if (options?.signal?.aborted || abortError) {
        throw new OperationsApiError("Operations request aborted", "aborted", undefined, undefined, { cause });
      }
      throw new OperationsApiError("Operations service unavailable", "network", undefined, undefined, { cause });
    }
    const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
    if (!contentType.includes("application/json") && !contentType.includes("+json")) {
      throw new OperationsApiError("Operations service returned a non-JSON response", "invalid_response", response.status);
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch (cause) {
      throw new OperationsApiError("Operations service returned invalid JSON", "invalid_response", response.status, undefined, { cause });
    }
    if (!response.ok) {
      throw new OperationsApiError(errorMessage(body, response.status), errorCode(response.status), response.status, body);
    }
    return body;
  }

  return {
    async getHome(organizationId, options) {
      const query = queryString([
        ["queue_limit", options?.queueLimit],
        ["recent_limit", options?.recentLimit],
      ]);
      return parseHome(await request(`${organizationPath(organizationId)}/home${query}`, "GET", options));
    },
    async search(organizationId, searchQuery, options) {
      const values: Array<[string, string | number | undefined]> = [["q", searchQuery]];
      for (const category of options?.categories ?? []) values.push(["category", category]);
      values.push(["limit", options?.limit]);
      return parseSearch(await request(`${organizationPath(organizationId)}/search${queryString(values)}`, "GET", options));
    },
    async listNotifications(organizationId, options) {
      const query = queryString([
        ["view", options?.view], ["kind", options?.kind], ["priority", options?.priority],
        ["product_id", options?.productId], ["limit", options?.limit],
      ]);
      const value = await request(`${organizationPath(organizationId)}/notifications${query}`, "GET", options);
      return array(value, "notifications", parseNotification);
    },
    async markRead(organizationId, notificationId, options) {
      return parseNotification(await request(
        `${organizationPath(organizationId)}/notifications/${id(notificationId)}/read`, "POST", options,
      ));
    },
    async acknowledge(organizationId, notificationId, options) {
      return parseNotification(await request(
        `${organizationPath(organizationId)}/notifications/${id(notificationId)}/acknowledge`, "POST", options,
      ));
    },
  };
}
