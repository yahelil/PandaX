import type {
  MonitoringHealth,
  Organization,
  Product,
  ReadinessStatus,
  Release,
} from "./types";

export type PortfolioApiErrorCode =
  | "unauthenticated"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "validation"
  | "http_error"
  | "invalid_response"
  | "aborted"
  | "network";

export class PortfolioApiError extends Error {
  constructor(
    message: string,
    readonly code: PortfolioApiErrorCode,
    readonly status?: number,
    readonly details?: unknown,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "PortfolioApiError";
  }
}

export interface PortfolioRequestOptions {
  signal?: AbortSignal;
}

export interface PortfolioApiConfig {
  baseUrl: string;
  getBearerToken?: () => string | undefined | Promise<string | undefined>;
  fetch?: typeof globalThis.fetch;
}

export interface OrganizationDto {
  id: string;
  name: string;
  legal_name: string;
  country: string;
  registration_number: string;
  timezone: string;
  created_at: string;
  updated_at: string;
}

export interface ProductDto {
  id: string;
  organization_id: string;
  slug: string;
  identifier: string;
  name: string;
  manufacturer: string;
  description: string;
  cra_class: Product["craClass"];
  classification_status: Product["classificationStatus"];
  support_start: string;
  support_end: string;
  owner_id: string | null;
  readiness: ReadinessStatus;
  monitoring_health: MonitoringHealth;
  active_release_id: string | null;
  created_at: string;
  updated_at: string;
  action_count: number;
  next_deadline: string | null;
  tags: string[];
}

export interface ReleaseCoverageDto {
  components: number;
  identified_components: number;
  advisory_sources_checked: number;
  advisory_sources_expected: number;
  limitations: string[];
}

export interface ReleaseDto {
  id: string;
  organization_id: string;
  product_id: string;
  version: string;
  channel: Release["channel"];
  status: Release["status"];
  release_date: string;
  support_start: string;
  support_end: string;
  owner_id: string | null;
  readiness: ReadinessStatus;
  monitoring_health: MonitoringHealth;
  sbom_status: Release["sbomStatus"];
  created_at: string;
  updated_at: string;
  coverage: ReleaseCoverageDto;
  last_analysis_at: string | null;
  last_monitoring_check_at: string | null;
}

export interface CreateOrganizationRequest {
  name: string;
  legalName: string;
  country: string;
  registrationNumber: string;
  timezone?: string;
}

export type UpdateOrganizationRequest = Partial<CreateOrganizationRequest>;

export interface CreatePortfolioProductRequest {
  name: string;
  identifier: string;
  manufacturer: string;
  slug?: string;
  description?: string;
  craClass: Product["craClass"];
  classificationStatus?: Product["classificationStatus"];
  supportStart: string;
  supportEnd: string;
  ownerId?: string;
}

export interface UpdatePortfolioProductRequest {
  slug?: string;
  identifier?: string;
  name?: string;
  manufacturer?: string;
  description?: string;
  craClass?: Product["craClass"];
  classificationStatus?: Product["classificationStatus"];
  supportStart?: string;
  supportEnd?: string;
  ownerId?: string;
  clearOwner?: boolean;
  readiness?: ReadinessStatus;
  monitoringHealth?: MonitoringHealth;
  activeReleaseId?: string | null;
}

export interface CreatePortfolioReleaseRequest {
  version: string;
  channel: Release["channel"];
  status?: Release["status"];
  releaseDate: string;
  supportStart: string;
  supportEnd: string;
  ownerId?: string;
}

export interface UpdatePortfolioReleaseRequest {
  version?: string;
  channel?: Release["channel"];
  status?: Release["status"];
  releaseDate?: string;
  supportStart?: string;
  supportEnd?: string;
  ownerId?: string;
  clearOwner?: boolean;
  readiness?: ReadinessStatus;
  monitoringHealth?: MonitoringHealth;
  sbomStatus?: Release["sbomStatus"];
}

export interface PortfolioApi {
  listOrganizations(options?: PortfolioRequestOptions): Promise<Organization[]>;
  createOrganization(input: CreateOrganizationRequest, options?: PortfolioRequestOptions): Promise<Organization>;
  getOrganization(organizationId: string, options?: PortfolioRequestOptions): Promise<Organization>;
  updateOrganization(organizationId: string, input: UpdateOrganizationRequest, options?: PortfolioRequestOptions): Promise<Organization>;
  listProducts(organizationId: string, options?: PortfolioRequestOptions): Promise<Product[]>;
  createProduct(organizationId: string, input: CreatePortfolioProductRequest, options?: PortfolioRequestOptions): Promise<Product>;
  getProduct(organizationId: string, productId: string, options?: PortfolioRequestOptions): Promise<Product>;
  updateProduct(organizationId: string, productId: string, input: UpdatePortfolioProductRequest, options?: PortfolioRequestOptions): Promise<Product>;
  listReleases(organizationId: string, productId: string, options?: PortfolioRequestOptions): Promise<Release[]>;
  createRelease(organizationId: string, productId: string, input: CreatePortfolioReleaseRequest, options?: PortfolioRequestOptions): Promise<Release>;
  getRelease(organizationId: string, productId: string, releaseId: string, options?: PortfolioRequestOptions): Promise<Release>;
  updateRelease(organizationId: string, productId: string, releaseId: string, input: UpdatePortfolioReleaseRequest, options?: PortfolioRequestOptions): Promise<Release>;
}

type JsonRecord = Record<string, unknown>;

const productClasses = ["default", "important_i", "important_ii", "critical"] as const;
const classificationStatuses = ["confirmed", "review_required"] as const;
const readinessStatuses = ["ready", "needs_attention", "incomplete_evidence"] as const;
const monitoringStates = ["healthy", "degraded", "failed", "inactive"] as const;
const releaseChannels = ["stable", "beta", "lts"] as const;
const releaseStatuses = ["active", "supported", "end_of_support", "draft"] as const;
const sbomStatuses = ["validated", "partial", "missing"] as const;

function invalid(message: string, details?: unknown): never {
  throw new PortfolioApiError(message, "invalid_response", undefined, details);
}

function record(value: unknown, label: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object`, value);
  return value as JsonRecord;
}

function string(recordValue: JsonRecord, key: string): string {
  const value = recordValue[key];
  if (typeof value !== "string") invalid(`${key} must be a string`, value);
  return value;
}

function nullableString(recordValue: JsonRecord, key: string): string | null {
  const value = recordValue[key];
  if (value !== null && typeof value !== "string") invalid(`${key} must be a string or null`, value);
  return value;
}

function number(recordValue: JsonRecord, key: string): number {
  const value = recordValue[key];
  if (typeof value !== "number" || !Number.isFinite(value)) invalid(`${key} must be a finite number`, value);
  return value;
}

function stringArray(recordValue: JsonRecord, key: string): string[] {
  const value = recordValue[key];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) invalid(`${key} must be a string array`, value);
  return value as string[];
}

function member<const Values extends readonly string[]>(recordValue: JsonRecord, key: string, values: Values): Values[number] {
  const value = string(recordValue, key);
  if (!values.includes(value)) invalid(`${key} contains an unsupported value`, value);
  return value as Values[number];
}

function parseOrganization(value: unknown): OrganizationDto {
  const item = record(value, "organization");
  return {
    id: string(item, "id"), name: string(item, "name"), legal_name: string(item, "legal_name"),
    country: string(item, "country"), registration_number: string(item, "registration_number"),
    timezone: string(item, "timezone"), created_at: string(item, "created_at"), updated_at: string(item, "updated_at"),
  };
}

function parseProduct(value: unknown): ProductDto {
  const item = record(value, "product");
  return {
    id: string(item, "id"), organization_id: string(item, "organization_id"), slug: string(item, "slug"),
    identifier: string(item, "identifier"), name: string(item, "name"), manufacturer: string(item, "manufacturer"),
    description: string(item, "description"), cra_class: member(item, "cra_class", productClasses),
    classification_status: member(item, "classification_status", classificationStatuses),
    support_start: string(item, "support_start"), support_end: string(item, "support_end"),
    owner_id: nullableString(item, "owner_id"), readiness: member(item, "readiness", readinessStatuses),
    monitoring_health: member(item, "monitoring_health", monitoringStates),
    active_release_id: nullableString(item, "active_release_id"), created_at: string(item, "created_at"),
    updated_at: string(item, "updated_at"), action_count: number(item, "action_count"),
    next_deadline: nullableString(item, "next_deadline"), tags: stringArray(item, "tags"),
  };
}

function parseCoverage(value: unknown): ReleaseCoverageDto {
  const item = record(value, "release coverage");
  return {
    components: number(item, "components"), identified_components: number(item, "identified_components"),
    advisory_sources_checked: number(item, "advisory_sources_checked"),
    advisory_sources_expected: number(item, "advisory_sources_expected"), limitations: stringArray(item, "limitations"),
  };
}

function parseRelease(value: unknown): ReleaseDto {
  const item = record(value, "release");
  return {
    id: string(item, "id"), organization_id: string(item, "organization_id"), product_id: string(item, "product_id"),
    version: string(item, "version"), channel: member(item, "channel", releaseChannels),
    status: member(item, "status", releaseStatuses), release_date: string(item, "release_date"),
    support_start: string(item, "support_start"), support_end: string(item, "support_end"),
    owner_id: nullableString(item, "owner_id"), readiness: member(item, "readiness", readinessStatuses),
    monitoring_health: member(item, "monitoring_health", monitoringStates), sbom_status: member(item, "sbom_status", sbomStatuses),
    created_at: string(item, "created_at"), updated_at: string(item, "updated_at"), coverage: parseCoverage(item.coverage),
    last_analysis_at: nullableString(item, "last_analysis_at"), last_monitoring_check_at: nullableString(item, "last_monitoring_check_at"),
  };
}

function parseList<T>(value: unknown, parse: (item: unknown) => T): T[] {
  if (!Array.isArray(value)) invalid("response must be an array", value);
  return value.map(parse);
}

export function mapOrganization(dto: OrganizationDto): Organization {
  return {
    id: dto.id, name: dto.name, legalName: dto.legal_name, country: dto.country,
    registrationNumber: dto.registration_number, defaultTimezone: dto.timezone,
  };
}

export function mapProduct(dto: ProductDto): Product {
  return {
    id: dto.id, slug: dto.slug, name: dto.name, identifier: dto.identifier, manufacturer: dto.manufacturer,
    description: dto.description, craClass: dto.cra_class, classificationStatus: dto.classification_status,
    supportUntil: dto.support_end, ownerId: dto.owner_id ?? undefined, readiness: dto.readiness,
    monitoringHealth: dto.monitoring_health, activeReleaseId: dto.active_release_id ?? undefined,
    actionCount: dto.action_count, nextDeadline: dto.next_deadline ?? undefined, tags: dto.tags, createdAt: dto.created_at,
  };
}

export function mapRelease(dto: ReleaseDto): Release {
  return {
    id: dto.id, productId: dto.product_id, version: dto.version, channel: dto.channel, status: dto.status,
    releaseDate: dto.release_date, supportedUntil: dto.support_end, readiness: dto.readiness,
    monitoringHealth: dto.monitoring_health, sbomStatus: dto.sbom_status,
    coverage: {
      components: dto.coverage.components, identifiedComponents: dto.coverage.identified_components,
      advisorySourcesChecked: dto.coverage.advisory_sources_checked,
      advisorySourcesExpected: dto.coverage.advisory_sources_expected, limitations: dto.coverage.limitations,
    },
    artifacts: [], lastAnalysisAt: dto.last_analysis_at ?? undefined,
    lastMonitoringCheckAt: dto.last_monitoring_check_at ?? undefined, createdAt: dto.created_at,
  };
}

function compact<T extends JsonRecord>(value: T): JsonRecord {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined));
}

function errorCode(status: number): PortfolioApiErrorCode {
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
  return `Portfolio request failed (${status})`;
}

export function createPortfolioApi(config: PortfolioApiConfig): PortfolioApi {
  const baseUrl = config.baseUrl.replace(/\/+$/, "");
  const fetcher = config.fetch ?? globalThis.fetch;

  async function request(path: string, init: RequestInit, options?: PortfolioRequestOptions): Promise<unknown> {
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
        throw new PortfolioApiError("Portfolio request aborted", "aborted", undefined, undefined, { cause });
      }
      throw new PortfolioApiError("Portfolio service unavailable", "network", undefined, undefined, { cause });
    }

    const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
    if (!contentType.includes("application/json") && !contentType.includes("+json")) {
      throw new PortfolioApiError("Portfolio service returned a non-JSON response", "invalid_response", response.status);
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch (cause) {
      throw new PortfolioApiError("Portfolio service returned invalid JSON", "invalid_response", response.status, undefined, { cause });
    }
    if (!response.ok) throw new PortfolioApiError(errorMessage(body, response.status), errorCode(response.status), response.status, body);
    return body;
  }

  const id = encodeURIComponent;
  const body = (value: JsonRecord): string => JSON.stringify(compact(value));
  const organizations = "/v1/organizations";
  const productPath = (organizationId: string) => `${organizations}/${id(organizationId)}/products`;
  const releasePath = (organizationId: string, productId: string) => `${productPath(organizationId)}/${id(productId)}/releases`;

  return {
    async listOrganizations(options) {
      return parseList(await request(organizations, { method: "GET" }, options), parseOrganization).map(mapOrganization);
    },
    async createOrganization(input, options) {
      const payload = { name: input.name, legal_name: input.legalName, country: input.country, registration_number: input.registrationNumber, timezone: input.timezone };
      return mapOrganization(parseOrganization(await request(organizations, { method: "POST", body: body(payload) }, options)));
    },
    async getOrganization(organizationId, options) {
      return mapOrganization(parseOrganization(await request(`${organizations}/${id(organizationId)}`, { method: "GET" }, options)));
    },
    async updateOrganization(organizationId, input, options) {
      const payload = { name: input.name, legal_name: input.legalName, country: input.country, registration_number: input.registrationNumber, timezone: input.timezone };
      return mapOrganization(parseOrganization(await request(`${organizations}/${id(organizationId)}`, { method: "PATCH", body: body(payload) }, options)));
    },
    async listProducts(organizationId, options) {
      return parseList(await request(productPath(organizationId), { method: "GET" }, options), parseProduct).map(mapProduct);
    },
    async createProduct(organizationId, input, options) {
      const payload = { name: input.name, identifier: input.identifier, manufacturer: input.manufacturer, slug: input.slug, description: input.description, cra_class: input.craClass, classification_status: input.classificationStatus, support_start: input.supportStart, support_end: input.supportEnd, owner_id: input.ownerId };
      return mapProduct(parseProduct(await request(productPath(organizationId), { method: "POST", body: body(payload) }, options)));
    },
    async getProduct(organizationId, productId, options) {
      return mapProduct(parseProduct(await request(`${productPath(organizationId)}/${id(productId)}`, { method: "GET" }, options)));
    },
    async updateProduct(organizationId, productId, input, options) {
      const payload = { slug: input.slug, identifier: input.identifier, name: input.name, manufacturer: input.manufacturer, description: input.description, cra_class: input.craClass, classification_status: input.classificationStatus, support_start: input.supportStart, support_end: input.supportEnd, owner_id: input.ownerId, clear_owner: input.clearOwner, readiness: input.readiness, monitoring_health: input.monitoringHealth, active_release_id: input.activeReleaseId };
      return mapProduct(parseProduct(await request(`${productPath(organizationId)}/${id(productId)}`, { method: "PATCH", body: body(payload) }, options)));
    },
    async listReleases(organizationId, productId, options) {
      return parseList(await request(releasePath(organizationId, productId), { method: "GET" }, options), parseRelease).map(mapRelease);
    },
    async createRelease(organizationId, productId, input, options) {
      const payload = { version: input.version, channel: input.channel, status: input.status, release_date: input.releaseDate, support_start: input.supportStart, support_end: input.supportEnd, owner_id: input.ownerId };
      return mapRelease(parseRelease(await request(releasePath(organizationId, productId), { method: "POST", body: body(payload) }, options)));
    },
    async getRelease(organizationId, productId, releaseId, options) {
      return mapRelease(parseRelease(await request(`${releasePath(organizationId, productId)}/${id(releaseId)}`, { method: "GET" }, options)));
    },
    async updateRelease(organizationId, productId, releaseId, input, options) {
      const payload = { version: input.version, channel: input.channel, status: input.status, release_date: input.releaseDate, support_start: input.supportStart, support_end: input.supportEnd, owner_id: input.ownerId, clear_owner: input.clearOwner, readiness: input.readiness, monitoring_health: input.monitoringHealth, sbom_status: input.sbomStatus };
      return mapRelease(parseRelease(await request(`${releasePath(organizationId, productId)}/${id(releaseId)}`, { method: "PATCH", body: body(payload) }, options)));
    },
  };
}
