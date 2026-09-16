import type { AppSettings, ComplianceAuditEntry, ComplianceItem, DocumentDownloadFile, Integration, Organization, TeamMember } from "./types";
import { sanitizeAnalyticsEvent } from "./analytics";

export type GovernanceErrorCode = "unauthenticated" | "forbidden" | "not_found" | "conflict" | "validation" | "http_error" | "invalid_response" | "aborted" | "network";
export class GovernanceApiError extends Error {
  constructor(message: string, readonly code: GovernanceErrorCode, readonly status?: number, readonly details?: unknown, options?: ErrorOptions) {
    super(message, options); this.name = "GovernanceApiError";
  }
}

export interface GovernanceRequestOptions { signal?: AbortSignal }
export interface GovernanceApiConfig {
  baseUrl: string;
  getBearerToken?: () => string | undefined | Promise<string | undefined>;
  fetch?: typeof globalThis.fetch;
}

export type ComplianceKind = "deadline" | "missing_evidence" | "missing_document" | "reporting_case" | "approval";
export type CompliancePriority = "critical" | "high" | "medium" | "low";
export type ComplianceStatus = "action_required" | "in_progress" | "pending_approval" | "approved" | "acknowledged" | "resolved";
export interface ComplianceDto {
  id: string; organizationId: string; productId?: string; releaseId?: string; kind: ComplianceKind;
  title: string; description: string; priority: CompliancePriority; status: ComplianceStatus;
  readiness: "ready" | "review_required" | "action_required"; dueAt?: string; ownerId?: string;
  sourceType: string; sourceId: string; reportingStage?: "early_warning" | "notification" | "final_report";
  selfFilingRecordId?: string; selfFilingRecordUrl?: string; approvedBy?: string; approvedAt?: string;
  acknowledgedAt?: string; resolvedAt?: string; version: number; createdAt: string; updatedAt: string;
}
export interface ComplianceFilters {
  view?: "action" | "all"; kind?: ComplianceKind; status?: ComplianceStatus; priority?: CompliancePriority;
  productId?: string; releaseId?: string; ownerId?: string; sort?: "due_at" | "priority" | "updated_at" | "status"; direction?: "asc" | "desc";
}
export interface UpdateComplianceInput {
  expectedVersion: number; title?: string; description?: string; priority?: CompliancePriority; status?: ComplianceStatus;
  dueAt?: string; clearDueAt?: boolean; ownerId?: string; clearOwner?: boolean;
  selfFilingRecordId?: string; selfFilingRecordUrl?: string;
}
export interface ApproveComplianceInput { expectedVersion: number; selfFilingRecordId?: string; selfFilingRecordUrl?: string }
export interface ComplianceAuditDto { id: string; organizationId: string; itemId: string; action: string; actorId: string; itemVersion: number; occurredAt: string; payload: Record<string, unknown> }

export type DocumentKind = "cra_reporting_pack" | "conformity" | "sbom" | "vex" | "evidence" | "verification";
export type DocumentFormat = "pdf_a_2b" | "cyclonedx_json" | "csaf_vex" | "zip" | "json";
export type DocumentStatus = "draft" | "pending" | "approved" | "rejected" | "superseded";
export interface DocumentRevisionDto {
  id: string; organizationId: string; documentId: string; revision: number; format: DocumentFormat;
  contentHash: string; storageLocator: string; sizeBytes: number; provenance: Record<string, unknown>;
  createdBy: string; createdAt: string; status: DocumentStatus;
}
export interface DocumentEventDto {
  id: string; organizationId: string; documentId: string; revision: number; sequence: number;
  eventType: string; actorId: string; reason?: string; occurredAt: string; details: Record<string, unknown>;
}
export interface SelfFilingDto {
  id: string; organizationId: string; documentId: string; revision: number; externalSubmissionReference: string;
  submittedAt: string; receiptEvidenceLocator: string; receiptContentHash?: string; recordedBy: string;
  recordedAt: string; recordType: "operator_recorded_external_submission"; actisSubmittedExternally: false;
}
export interface GovernanceDocumentDto {
  id: string; organizationId: string; productId: string; releaseId?: string; caseId?: string; kind: DocumentKind;
  name: string; currentRevision: number; createdBy: string; createdAt: string; updatedAt: string;
  status: DocumentStatus; current: DocumentRevisionDto;
}
export interface DocumentDetailDto { document: GovernanceDocumentDto; revisions: DocumentRevisionDto[]; audit: DocumentEventDto[]; approvalHistory: DocumentEventDto[]; selfFilings: SelfFilingDto[] }
export interface DocumentContentInput { format: DocumentFormat; contentHash: string; storageLocator: string; sizeBytes: number; provenance: Record<string, unknown> }
export interface CreateDocumentInput extends DocumentContentInput { productId: string; releaseId?: string; caseId?: string; name: string; kind: DocumentKind }
export interface AddDocumentRevisionInput extends DocumentContentInput { expectedCurrentRevision: number }
export interface DocumentFilters { productId?: string; releaseId?: string; kind?: DocumentKind; status?: DocumentStatus; sort?: "updated_desc" | "created_desc" | "name_asc" | "kind_asc" }
export interface DownloadMetadataDto { documentId: string; revision: number; filename: string; format: DocumentFormat; contentHash: string; sizeBytes: number; storageLocator: string; contentType: string; downloadType: "storage_metadata_only" | "content_available" }

export interface OrganizationProfileDto { name: string; legalName: string; country: string; registrationNumber: string; timezone: string }
export interface GovernanceSettingsDto {
  organizationId: string; version: number; organizationProfile: OrganizationProfileDto;
  notifications: { urgentFindings: boolean; deadlineWarnings: boolean; monitoringFailures: boolean; approvalRequests: boolean; emailDigest: "off" | "daily" | "weekly" };
  security: { sessionTimeoutMinutes: number; evidenceRetentionMonths: number; requireMfa: boolean; allowRawArtifacts: boolean };
  appearance: { theme: "light" | "dark" | "system"; density: "comfortable" | "compact" };
  analytics: { enabled: boolean; retentionDays: number }; updatedBy?: string; updatedAt?: string;
}
export interface UpdateSettingsInput {
  expectedVersion: number; organizationProfile?: Partial<OrganizationProfileDto>;
  notifications?: Partial<GovernanceSettingsDto["notifications"]>; security?: Partial<GovernanceSettingsDto["security"]>;
  appearance?: Partial<GovernanceSettingsDto["appearance"]>; analytics?: Partial<GovernanceSettingsDto["analytics"]>;
}
export type GovernanceRole = "org_admin" | "compliance_operator" | "authorized_approver" | "security_reviewer" | "viewer";
export interface GovernanceTeamMemberDto { id: string; organizationId: string; subject: string; name: string; email: string; title: string; initials: string; roles: GovernanceRole[]; status: "active" | "invited" | "disabled"; lastActiveAt?: string; version: number; createdAt: string; updatedAt: string }
export interface UpdateTeamMemberInput { expectedVersion: number; title?: string; roles?: GovernanceRole[]; status?: GovernanceTeamMemberDto["status"] }
export interface GovernanceIntegrationDto { id: string; organizationId: string; name: string; type: "email" | "webhook" | "collector" | "jira"; status: "connected" | "attention" | "not_connected"; description: string; configuration: Record<string, unknown>; secretReference?: string; lastSyncAt?: string; version: number; createdAt: string; updatedAt: string }
export interface UpdateIntegrationInput { expectedVersion: number; status?: GovernanceIntegrationDto["status"]; description?: string; configuration?: Record<string, unknown>; secretReference?: string | null; lastSyncAt?: string | null }
export interface SettingsAuditDto { id: string; organizationId: string; entityType: string; entityId: string; action: string; version: number; actorId: string; occurredAt: string; changes: Record<string, unknown> }

export type AnalyticsArea = "home" | "products" | "releases" | "findings" | "compliance" | "documents" | "settings";
export type PrivacySafeAnalyticsEvent =
  | { eventName: "page_viewed"; properties: { area: AnalyticsArea }; occurredAt: string }
  | { eventName: "workflow_completed"; properties: { workflow: "release_analysis" | "finding_decision" | "document_approval" | "self_filing_record"; result: "succeeded" | "failed" | "cancelled" }; occurredAt: string }
  | { eventName: "feature_used"; properties: { feature: "search" | "filter" | "theme" | "export" | "scope_selector" }; occurredAt: string }
  | { eventName: "error_observed"; properties: { area: "portfolio" | "analysis" | "monitoring" | "findings" | "compliance" | "documents" | "settings"; errorCode: "validation" | "unauthorized" | "forbidden" | "not_found" | "conflict" | "unavailable" | "timeout" }; occurredAt: string };
export interface AnalyticsIngestDto { accepted: number; dropped: number }
export interface AnalyticsAggregateDto { eventName: string; count: number }

export interface GovernanceApi {
  listCompliance(org: string, filters?: ComplianceFilters, options?: GovernanceRequestOptions): Promise<ComplianceDto[]>;
  getCompliance(org: string, item: string, options?: GovernanceRequestOptions): Promise<ComplianceDto>;
  updateCompliance(org: string, item: string, input: UpdateComplianceInput, options?: GovernanceRequestOptions): Promise<ComplianceDto>;
  approveCompliance(org: string, item: string, input: ApproveComplianceInput, options?: GovernanceRequestOptions): Promise<ComplianceDto>;
  listComplianceAudit(org: string, item: string, options?: GovernanceRequestOptions): Promise<ComplianceAuditDto[]>;
  listDocuments(org: string, filters?: DocumentFilters, options?: GovernanceRequestOptions): Promise<GovernanceDocumentDto[]>;
  createDocument(org: string, input: CreateDocumentInput, options?: GovernanceRequestOptions): Promise<DocumentDetailDto>;
  getDocument(org: string, document: string, options?: GovernanceRequestOptions): Promise<DocumentDetailDto>;
  addDocumentRevision(org: string, document: string, input: AddDocumentRevisionInput, options?: GovernanceRequestOptions): Promise<DocumentRevisionDto>;
  getDocumentRevision(org: string, document: string, revision: number, options?: GovernanceRequestOptions): Promise<DocumentRevisionDto>;
  getDownloadMetadata(org: string, document: string, revision: number, options?: GovernanceRequestOptions): Promise<DownloadMetadataDto>;
  downloadDocumentContent(org: string, document: string, revision: number, options?: GovernanceRequestOptions): Promise<DocumentDownloadFile>;
  requestDocumentApproval(org: string, document: string, revision: number, expectedStatus: DocumentStatus, comment?: string, options?: GovernanceRequestOptions): Promise<DocumentRevisionDto>;
  approveDocument(org: string, document: string, revision: number, expectedStatus: DocumentStatus, comment?: string, options?: GovernanceRequestOptions): Promise<DocumentRevisionDto>;
  rejectDocument(org: string, document: string, revision: number, expectedStatus: DocumentStatus, reason: string, options?: GovernanceRequestOptions): Promise<DocumentRevisionDto>;
  recordSelfFiling(org: string, document: string, revision: number, input: { externalSubmissionReference: string; submittedAt: string; receiptEvidenceLocator: string; receiptContentHash?: string }, options?: GovernanceRequestOptions): Promise<SelfFilingDto>;
  getSettings(org: string, options?: GovernanceRequestOptions): Promise<GovernanceSettingsDto>;
  updateSettings(org: string, input: UpdateSettingsInput, options?: GovernanceRequestOptions): Promise<GovernanceSettingsDto>;
  listTeam(org: string, options?: GovernanceRequestOptions): Promise<GovernanceTeamMemberDto[]>;
  getTeamMember(org: string, member: string, options?: GovernanceRequestOptions): Promise<GovernanceTeamMemberDto>;
  updateTeamMember(org: string, member: string, input: UpdateTeamMemberInput, options?: GovernanceRequestOptions): Promise<GovernanceTeamMemberDto>;
  listIntegrations(org: string, options?: GovernanceRequestOptions): Promise<GovernanceIntegrationDto[]>;
  getIntegration(org: string, integration: string, options?: GovernanceRequestOptions): Promise<GovernanceIntegrationDto>;
  updateIntegration(org: string, integration: string, input: UpdateIntegrationInput, options?: GovernanceRequestOptions): Promise<GovernanceIntegrationDto>;
  listSettingsAudit(org: string, options?: GovernanceRequestOptions): Promise<SettingsAuditDto[]>;
  ingestAnalytics(org: string, events: PrivacySafeAnalyticsEvent[], options?: GovernanceRequestOptions): Promise<AnalyticsIngestDto>;
  getAnalyticsAggregates(org: string, range?: { since?: string; until?: string }, options?: GovernanceRequestOptions): Promise<AnalyticsAggregateDto[]>;
}

type R = Record<string, unknown>;
const enums = {
  complianceKind: ["deadline", "missing_evidence", "missing_document", "reporting_case", "approval"], compliancePriority: ["critical", "high", "medium", "low"],
  complianceStatus: ["action_required", "in_progress", "pending_approval", "approved", "acknowledged", "resolved"], readiness: ["ready", "review_required", "action_required"],
  reportingStage: ["early_warning", "notification", "final_report"], documentKind: ["cra_reporting_pack", "conformity", "sbom", "vex", "evidence", "verification"],
  documentFormat: ["pdf_a_2b", "cyclonedx_json", "csaf_vex", "zip", "json"], documentStatus: ["draft", "pending", "approved", "rejected", "superseded"],
  roles: ["org_admin", "compliance_operator", "authorized_approver", "security_reviewer", "viewer"], teamStatus: ["active", "invited", "disabled"],
  integrationType: ["email", "webhook", "collector", "jira"], integrationStatus: ["connected", "attention", "not_connected"], digest: ["off", "daily", "weekly"], theme: ["light", "dark", "system"], density: ["comfortable", "compact"],
} as const;
function bad(message: string, details?: unknown): never { throw new GovernanceApiError(message, "invalid_response", undefined, details) }
function obj(value: unknown, label: string): R { if (!value || typeof value !== "object" || Array.isArray(value)) bad(`${label} must be an object`, value); return value as R }
function s(value: R, key: string): string { const item=value[key]; if (typeof item !== "string") bad(`${key} must be a string`, item); return item }
function ns(value: R, key: string): string | undefined { const item = value[key]; if (item !== null && item !== undefined && typeof item !== "string") bad(`${key} must be a string or null`, item); return item ?? undefined }
function n(value: R, key: string): number { const item = value[key]; if (typeof item !== "number" || !Number.isFinite(item)) bad(`${key} must be a finite number`, item); return item }
function b(value: R, key: string): boolean { const item=value[key]; if (typeof item !== "boolean") bad(`${key} must be boolean`, item); return item }
function e<const T extends readonly string[]>(value: R, key: string, allowed: T): T[number] { const item = s(value, key); if (!allowed.includes(item)) bad(`${key} has unsupported value`, item); return item as T[number] }
function rec(value: R, key: string): R { return obj(value[key], key) }
function list<T>(value: unknown, parser: (item: unknown) => T): T[] { if (!Array.isArray(value)) bad("response must be an array", value); return value.map(parser) }
function parseCompliance(value: unknown): ComplianceDto { const x=obj(value,"compliance item"); return { id:s(x,"id"),organizationId:s(x,"organization_id"),productId:ns(x,"product_id"),releaseId:ns(x,"release_id"),kind:e(x,"kind",enums.complianceKind),title:s(x,"title"),description:s(x,"description"),priority:e(x,"priority",enums.compliancePriority),status:e(x,"status",enums.complianceStatus),readiness:e(x,"readiness",enums.readiness),dueAt:ns(x,"due_at"),ownerId:ns(x,"owner_id"),sourceType:s(x,"source_type"),sourceId:s(x,"source_id"),reportingStage:x.reporting_stage==null?undefined:e(x,"reporting_stage",enums.reportingStage),selfFilingRecordId:ns(x,"self_filing_record_id"),selfFilingRecordUrl:ns(x,"self_filing_record_url"),approvedBy:ns(x,"approved_by"),approvedAt:ns(x,"approved_at"),acknowledgedAt:ns(x,"acknowledged_at"),resolvedAt:ns(x,"resolved_at"),version:n(x,"version"),createdAt:s(x,"created_at"),updatedAt:s(x,"updated_at") }; }
function parseComplianceAudit(value: unknown): ComplianceAuditDto { const x=obj(value,"compliance audit"); return {id:s(x,"id"),organizationId:s(x,"organization_id"),itemId:s(x,"item_id"),action:s(x,"action"),actorId:s(x,"actor_id"),itemVersion:n(x,"item_version"),occurredAt:s(x,"occurred_at"),payload:rec(x,"payload")}; }
function parseRevision(value: unknown): DocumentRevisionDto { const x=obj(value,"document revision"); return {id:s(x,"id"),organizationId:s(x,"organization_id"),documentId:s(x,"document_id"),revision:n(x,"revision"),format:e(x,"format",enums.documentFormat),contentHash:s(x,"content_hash"),storageLocator:s(x,"storage_locator"),sizeBytes:n(x,"size_bytes"),provenance:rec(x,"provenance"),createdBy:s(x,"created_by"),createdAt:s(x,"created_at"),status:e(x,"status",enums.documentStatus)}; }
function parseDocument(value: unknown): GovernanceDocumentDto { const x=obj(value,"document"); return {id:s(x,"id"),organizationId:s(x,"organization_id"),productId:s(x,"product_id"),releaseId:ns(x,"release_id"),caseId:ns(x,"case_id"),kind:e(x,"kind",enums.documentKind),name:s(x,"name"),currentRevision:n(x,"current_revision"),createdBy:s(x,"created_by"),createdAt:s(x,"created_at"),updatedAt:s(x,"updated_at"),status:e(x,"status",enums.documentStatus),current:parseRevision(x.current)}; }
function parseEvent(value: unknown): DocumentEventDto { const x=obj(value,"document event"); return {id:s(x,"id"),organizationId:s(x,"organization_id"),documentId:s(x,"document_id"),revision:n(x,"revision"),sequence:n(x,"sequence"),eventType:s(x,"event_type"),actorId:s(x,"actor_id"),reason:ns(x,"reason"),occurredAt:s(x,"occurred_at"),details:rec(x,"details")}; }
function parseFiling(value: unknown): SelfFilingDto { const x=obj(value,"self-filing record"); if (x.actis_submitted_externally !== false) bad("self-filing response must state Actis did not submit externally",x.actis_submitted_externally); return {id:s(x,"id"),organizationId:s(x,"organization_id"),documentId:s(x,"document_id"),revision:n(x,"revision"),externalSubmissionReference:s(x,"external_submission_reference"),submittedAt:s(x,"submitted_at"),receiptEvidenceLocator:s(x,"receipt_evidence_locator"),receiptContentHash:ns(x,"receipt_content_hash"),recordedBy:s(x,"recorded_by"),recordedAt:s(x,"recorded_at"),recordType:e(x,"record_type",["operator_recorded_external_submission"] as const),actisSubmittedExternally:false}; }
function parseDetail(value: unknown): DocumentDetailDto { const x=obj(value,"document detail"); return {document:parseDocument(x.document),revisions:list(x.revisions,parseRevision),audit:list(x.audit,parseEvent),approvalHistory:list(x.approval_history,parseEvent),selfFilings:list(x.self_filings,parseFiling)}; }
function parseDownload(value: unknown): DownloadMetadataDto { const x=obj(value,"download metadata"); return {documentId:s(x,"document_id"),revision:n(x,"revision"),filename:s(x,"filename"),format:e(x,"format",enums.documentFormat),contentHash:s(x,"content_hash"),sizeBytes:n(x,"size_bytes"),storageLocator:s(x,"storage_locator"),contentType:s(x,"content_type"),downloadType:e(x,"download_type",["storage_metadata_only","content_available"] as const)}; }
function parseSettings(value: unknown): GovernanceSettingsDto { const x=obj(value,"settings"),p=rec(x,"organization_profile"),no=rec(x,"notifications"),se=rec(x,"security"),ap=rec(x,"appearance"),an=rec(x,"analytics"); return {organizationId:s(x,"organization_id"),version:n(x,"version"),organizationProfile:{name:s(p,"name"),legalName:s(p,"legal_name"),country:s(p,"country"),registrationNumber:s(p,"registration_number"),timezone:s(p,"timezone")},notifications:{urgentFindings:b(no,"urgent_findings"),deadlineWarnings:b(no,"deadline_warnings"),monitoringFailures:b(no,"monitoring_failures"),approvalRequests:b(no,"approval_requests"),emailDigest:e(no,"email_digest",enums.digest)},security:{sessionTimeoutMinutes:n(se,"session_timeout_minutes"),evidenceRetentionMonths:n(se,"evidence_retention_months"),requireMfa:b(se,"require_mfa"),allowRawArtifacts:b(se,"allow_raw_artifacts")},appearance:{theme:e(ap,"theme",enums.theme),density:e(ap,"density",enums.density)},analytics:{enabled:b(an,"enabled"),retentionDays:n(an,"retention_days")},updatedBy:ns(x,"updated_by"),updatedAt:ns(x,"updated_at")}; }
function parseMember(value: unknown): GovernanceTeamMemberDto { const x=obj(value,"team member"),rawRoles=x.roles; if(!Array.isArray(rawRoles))bad("roles must be an array",rawRoles); const roles=rawRoles.map(role=>e({role},"role",enums.roles)); return {id:s(x,"id"),organizationId:s(x,"organization_id"),subject:s(x,"subject"),name:s(x,"name"),email:s(x,"email"),title:s(x,"title"),initials:s(x,"initials"),roles,status:e(x,"status",enums.teamStatus),lastActiveAt:ns(x,"last_active_at"),version:n(x,"version"),createdAt:s(x,"created_at"),updatedAt:s(x,"updated_at")}; }
function parseIntegration(value: unknown): GovernanceIntegrationDto { const x=obj(value,"integration"); return {id:s(x,"id"),organizationId:s(x,"organization_id"),name:s(x,"name"),type:e(x,"type",enums.integrationType),status:e(x,"status",enums.integrationStatus),description:s(x,"description"),configuration:rec(x,"configuration"),secretReference:ns(x,"secret_reference"),lastSyncAt:ns(x,"last_sync_at"),version:n(x,"version"),createdAt:s(x,"created_at"),updatedAt:s(x,"updated_at")}; }
function parseSettingsAudit(value: unknown): SettingsAuditDto { const x=obj(value,"settings audit"); return {id:s(x,"id"),organizationId:s(x,"organization_id"),entityType:s(x,"entity_type"),entityId:s(x,"entity_id"),action:s(x,"action"),version:n(x,"version"),actorId:s(x,"actor_id"),occurredAt:s(x,"occurred_at"),changes:rec(x,"changes")}; }

function compact(value: R): R { return Object.fromEntries(Object.entries(value).filter(([,item])=>item!==undefined)); }
function snakeSettings(input: UpdateSettingsInput): R { const section=(value:object|undefined,map:Record<string,string>)=>value?compact(Object.fromEntries(Object.entries(value).map(([k,v])=>[map[k]??k,v]))):undefined; return compact({expected_version:input.expectedVersion,organization_profile:section(input.organizationProfile,{legalName:"legal_name",registrationNumber:"registration_number"}),notifications:section(input.notifications,{urgentFindings:"urgent_findings",deadlineWarnings:"deadline_warnings",monitoringFailures:"monitoring_failures",approvalRequests:"approval_requests",emailDigest:"email_digest"}),security:section(input.security,{sessionTimeoutMinutes:"session_timeout_minutes",evidenceRetentionMonths:"evidence_retention_months",requireMfa:"require_mfa",allowRawArtifacts:"allow_raw_artifacts"}),appearance:section(input.appearance,{}),analytics:section(input.analytics,{retentionDays:"retention_days"})}); }
function content(input: DocumentContentInput): R { return {format:input.format,content_hash:input.contentHash,storage_locator:input.storageLocator,size_bytes:input.sizeBytes,provenance:input.provenance}; }
function errorCode(status:number):GovernanceErrorCode{return status===401?"unauthenticated":status===403?"forbidden":status===404?"not_found":status===409?"conflict":status===422?"validation":"http_error"}
function errorMessage(body:unknown,status:number):string{if(body&&typeof body==="object"&&"detail" in body){const d=(body as {detail?:unknown}).detail;if(typeof d==="string")return d;if(Array.isArray(d)){const m=d.flatMap(x=>x&&typeof x==="object"&&"msg" in x&&typeof x.msg==="string"?[x.msg]:[]);if(m.length)return m.join("; ")}}return `Governance request failed (${status})`}
function responseFilename(response: Response): string | undefined {
  const disposition = response.headers.get("content-disposition") ?? "";
  const encoded = disposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  if (encoded) {
    try { return decodeURIComponent(encoded); } catch { return encoded; }
  }
  return disposition.match(/filename="?([^";]+)"?/i)?.[1];
}

export function mapGovernanceSettings(dto: GovernanceSettingsDto): { organization: Organization; settings: AppSettings } { return {organization:{id:dto.organizationId,name:dto.organizationProfile.name,legalName:dto.organizationProfile.legalName,country:dto.organizationProfile.country,registrationNumber:dto.organizationProfile.registrationNumber,defaultTimezone:dto.organizationProfile.timezone},settings:{notifications:dto.notifications,security:dto.security,appearance:dto.appearance,analytics:dto.analytics}}; }
export function mapCompliance(dto: ComplianceDto, audit?: ComplianceAuditDto[]): ComplianceItem { const type:ComplianceItem["type"]=dto.kind==="missing_document"?"missing_evidence":dto.kind; return {id:dto.id,type,title:dto.title,requirement:dto.sourceType,productId:dto.productId,releaseId:dto.releaseId,priority:dto.priority==="critical"?"urgent":dto.priority==="medium"?"normal":dto.priority,status:dto.status==="resolved"||dto.status==="approved"?"complete":dto.status==="in_progress"||dto.status==="acknowledged"?"in_progress":dto.status==="pending_approval"?"blocked":"open",lifecycleStatus:dto.status,readiness:dto.readiness,dueAt:dto.dueAt,ownerId:dto.ownerId,reason:dto.description,targetUrl:`/compliance?item=${encodeURIComponent(dto.id)}`,sourceId:dto.sourceId,reportingStage:dto.reportingStage,selfFilingRecordId:dto.selfFilingRecordId,selfFilingRecordUrl:dto.selfFilingRecordUrl,approvedBy:dto.approvedBy,approvedAt:dto.approvedAt,acknowledgedAt:dto.acknowledgedAt,resolvedAt:dto.resolvedAt,version:dto.version,createdAt:dto.createdAt,updatedAt:dto.updatedAt,audit:audit?.map(mapComplianceAudit)}; }
export function mapComplianceAudit(dto: ComplianceAuditDto): ComplianceAuditEntry { return {id:dto.id,action:dto.action,actorId:dto.actorId,itemVersion:dto.itemVersion,occurredAt:dto.occurredAt,payload:dto.payload}; }
export function mapTeamMember(dto: GovernanceTeamMemberDto): TeamMember | undefined { if(dto.status==="disabled")return undefined; const roles:TeamMember["roles"]=[]; for(const source of dto.roles){const role=source==="viewer"?"read_only_auditor":source;if(!roles.includes(role))roles.push(role)} if(!roles.length)return undefined; return {id:dto.id,name:dto.name,email:dto.email,title:dto.title,initials:dto.initials,roles,status:dto.status,lastActiveAt:dto.lastActiveAt,version:dto.version}; }
export function mapIntegration(dto: GovernanceIntegrationDto): Integration { return {id:dto.id,name:dto.name,type:dto.type,status:dto.status,description:dto.description,configuration:dto.configuration,secretReference:dto.secretReference,lastSyncAt:dto.lastSyncAt,version:dto.version}; }

export function createGovernanceApi(config: GovernanceApiConfig): GovernanceApi {
  const base=config.baseUrl.replace(/\/+$/,""); const fetcher=config.fetch??globalThis.fetch; const enc=encodeURIComponent;
  async function request(path:string,init:RequestInit,options?:GovernanceRequestOptions):Promise<unknown>{const token=(await config.getBearerToken?.())?.trim();const headers=new Headers(init.headers);headers.set("Accept","application/json");if(init.body!==undefined)headers.set("Content-Type","application/json");if(token)headers.set("Authorization",`Bearer ${token}`);let response:Response;try{response=await fetcher(`${base}${path}`,{...init,headers,signal:options?.signal})}catch(cause){if(options?.signal?.aborted||(cause instanceof DOMException&&cause.name==="AbortError"))throw new GovernanceApiError("Governance request aborted","aborted",undefined,undefined,{cause});throw new GovernanceApiError("Governance service unavailable","network",undefined,undefined,{cause})}const ct=response.headers.get("content-type")?.toLowerCase()??"";if(!ct.includes("application/json")&&!ct.includes("+json"))throw new GovernanceApiError("Governance service returned a non-JSON response","invalid_response",response.status);let data:unknown;try{data=await response.json()}catch(cause){throw new GovernanceApiError("Governance service returned invalid JSON","invalid_response",response.status,undefined,{cause})}if(!response.ok)throw new GovernanceApiError(errorMessage(data,response.status),errorCode(response.status),response.status,data);return data}
  const json=(value:R)=>JSON.stringify(compact(value)); const org=(id:string)=>`/v1/organizations/${enc(id)}`; const item=(o:string,kind:string,id:string)=>`${org(o)}/${kind}/${enc(id)}`; const qs=(values:R)=>{const q=new URLSearchParams();Object.entries(values).forEach(([k,v])=>{if(v!==undefined)q.set(k,String(v))});const value=q.toString();return value?`?${value}`:""};
  const docRevision=(o:string,d:string,r:number)=>`${item(o,"documents",d)}/revisions/${r}`;
  return {
    async listCompliance(o,f={},x){return list(await request(`${org(o)}/compliance${qs({view:f.view,kind:f.kind,status:f.status,priority:f.priority,product_id:f.productId,release_id:f.releaseId,owner_id:f.ownerId,sort:f.sort,direction:f.direction})}`,{method:"GET"},x),parseCompliance)},
    async getCompliance(o,i,x){return parseCompliance(await request(item(o,"compliance",i),{method:"GET"},x))},
    async updateCompliance(o,i,v,x){return parseCompliance(await request(item(o,"compliance",i),{method:"PATCH",body:json({expected_version:v.expectedVersion,title:v.title,description:v.description,priority:v.priority,status:v.status,due_at:v.dueAt,clear_due_at:v.clearDueAt,owner_id:v.ownerId,clear_owner:v.clearOwner,self_filing_record_id:v.selfFilingRecordId,self_filing_record_url:v.selfFilingRecordUrl})},x))},
    async approveCompliance(o,i,v,x){return parseCompliance(await request(`${item(o,"compliance",i)}/approve`,{method:"POST",body:json({expected_version:v.expectedVersion,self_filing_record_id:v.selfFilingRecordId,self_filing_record_url:v.selfFilingRecordUrl})},x))},
    async listComplianceAudit(o,i,x){return list(await request(`${item(o,"compliance",i)}/audit`,{method:"GET"},x),parseComplianceAudit)},
    async listDocuments(o,f={},x){return list(await request(`${org(o)}/documents${qs({product_id:f.productId,release_id:f.releaseId,kind:f.kind,status:f.status,sort:f.sort})}`,{method:"GET"},x),parseDocument)},
    async createDocument(o,v,x){return parseDetail(await request(`${org(o)}/documents`,{method:"POST",body:json({...content(v),product_id:v.productId,release_id:v.releaseId,case_id:v.caseId,name:v.name,kind:v.kind})},x))},
    async getDocument(o,d,x){return parseDetail(await request(item(o,"documents",d),{method:"GET"},x))},
    async addDocumentRevision(o,d,v,x){return parseRevision(await request(`${item(o,"documents",d)}/revisions`,{method:"POST",body:json({...content(v),expected_current_revision:v.expectedCurrentRevision})},x))},
    async getDocumentRevision(o,d,r,x){return parseRevision(await request(docRevision(o,d,r),{method:"GET"},x))},
    async getDownloadMetadata(o,d,r,x){return parseDownload(await request(`${docRevision(o,d,r)}/download`,{method:"GET"},x))},
    async downloadDocumentContent(o,d,r,x){
      const token=(await config.getBearerToken?.())?.trim();
      const headers=new Headers();
      if(token)headers.set("Authorization",`Bearer ${token}`);
      let response:Response;
      try{
        response=await fetcher(`${base}${docRevision(o,d,r)}/download/content`,{method:"GET",headers,signal:x?.signal});
      }catch(cause){
        if(x?.signal?.aborted||(cause instanceof DOMException&&cause.name==="AbortError"))
          throw new GovernanceApiError("Governance request aborted","aborted",undefined,undefined,{cause});
        throw new GovernanceApiError("Governance service unavailable","network",undefined,undefined,{cause});
      }
      if(!response.ok){
        const ct=response.headers.get("content-type")?.toLowerCase()??"";
        let body:unknown;
        if(ct.includes("application/json")||ct.includes("+json")){
          try{body=await response.json()}catch{body=undefined}
        }
        throw new GovernanceApiError(errorMessage(body,response.status),errorCode(response.status),response.status,body);
      }
      return {
        blob:await response.blob(),
        contentType:response.headers.get("content-type")||"application/octet-stream",
        filename:responseFilename(response),
      };
    },
    async requestDocumentApproval(o,d,r,expectedStatus,comment,x){return parseRevision(await request(`${docRevision(o,d,r)}/approval-request`,{method:"POST",body:json({expected_status:expectedStatus,comment})},x))},
    async approveDocument(o,d,r,expectedStatus,comment,x){return parseRevision(await request(`${docRevision(o,d,r)}/approve`,{method:"POST",body:json({expected_status:expectedStatus,comment})},x))},
    async rejectDocument(o,d,r,expectedStatus,reason,x){return parseRevision(await request(`${docRevision(o,d,r)}/reject`,{method:"POST",body:json({expected_status:expectedStatus,reason})},x))},
    async recordSelfFiling(o,d,r,v,x){return parseFiling(await request(`${docRevision(o,d,r)}/self-filings`,{method:"POST",body:json({external_submission_reference:v.externalSubmissionReference,submitted_at:v.submittedAt,receipt_evidence_locator:v.receiptEvidenceLocator,receipt_content_hash:v.receiptContentHash})},x))},
    async getSettings(o,x){return parseSettings(await request(`${org(o)}/settings`,{method:"GET"},x))},
    async updateSettings(o,v,x){return parseSettings(await request(`${org(o)}/settings`,{method:"PATCH",body:json(snakeSettings(v))},x))},
    async listTeam(o,x){return list(await request(`${org(o)}/team`,{method:"GET"},x),parseMember)},
    async getTeamMember(o,m,x){return parseMember(await request(item(o,"team",m),{method:"GET"},x))},
    async updateTeamMember(o,m,v,x){return parseMember(await request(item(o,"team",m),{method:"PATCH",body:json({expected_version:v.expectedVersion,title:v.title,roles:v.roles,status:v.status})},x))},
    async listIntegrations(o,x){return list(await request(`${org(o)}/integrations`,{method:"GET"},x),parseIntegration)},
    async getIntegration(o,i,x){return parseIntegration(await request(item(o,"integrations",i),{method:"GET"},x))},
    async updateIntegration(o,i,v,x){return parseIntegration(await request(item(o,"integrations",i),{method:"PATCH",body:json({expected_version:v.expectedVersion,status:v.status,description:v.description,configuration:v.configuration,secret_reference:v.secretReference,last_sync_at:v.lastSyncAt})},x))},
    async listSettingsAudit(o,x){return list(await request(`${org(o)}/settings/audit`,{method:"GET"},x),parseSettingsAudit)},
    async ingestAnalytics(o,events,x){const safe=events.flatMap(event=>{const item=sanitizeAnalyticsEvent(event);return item?[item]:[]});const clientDropped=events.length-safe.length;if(!safe.length)return {accepted:0,dropped:clientDropped};const mapped=safe.map(event=>({event_name:event.eventName,properties:event.eventName==="error_observed"?{area:event.properties.area,error_code:event.properties.errorCode}:event.properties,occurred_at:event.occurredAt}));const y=obj(await request(`${org(o)}/analytics/events`,{method:"POST",body:json({events:mapped})},x),"analytics ingest");return {accepted:n(y,"accepted"),dropped:n(y,"dropped")+clientDropped}},
    async getAnalyticsAggregates(o,range={},x){return list(await request(`${org(o)}/analytics/aggregates${qs({since:range.since,until:range.until})}`,{method:"GET"},x),value=>{const y=obj(value,"analytics aggregate");return {eventName:s(y,"event_name"),count:n(y,"count")}})},
  };
}
