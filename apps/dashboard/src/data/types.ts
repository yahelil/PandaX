export type EntityId = string;
export type ISODate = string;

export type PriorityBand = "urgent" | "high" | "normal" | "low";
export type ReadinessStatus = "ready" | "needs_attention" | "incomplete_evidence";
export type MonitoringHealth = "healthy" | "degraded" | "failed" | "inactive";
export type Severity = "critical" | "high" | "medium" | "low";
export type CraClass = "default" | "important_i" | "important_ii" | "critical";
export type ClassificationStatus = "confirmed" | "review_required";
export type FindingStatus = "needs_review" | "action_required" | "in_remediation" | "accepted" | "resolved";
export type DecisionKind = "affected" | "not_affected" | "accepted_risk" | "deferred";
export type Role = "org_admin" | "compliance_operator" | "security_reviewer" | "authorized_approver" | "read_only_auditor";

export interface Scope {
  productId?: EntityId;
  releaseId?: EntityId;
}

export interface Organization {
  id: EntityId;
  name: string;
  legalName: string;
  country: string;
  registrationNumber: string;
  defaultTimezone: string;
}

export interface TeamMember {
  id: EntityId;
  name: string;
  email: string;
  title: string;
  initials: string;
  roles: Role[];
  status: "active" | "invited";
  lastActiveAt?: ISODate;
  version?: number;
}

export interface CraAssessmentAnswer {
  questionId: string;
  question: string;
  answer: string;
  source: string;
}

export interface CraAssessmentAction {
  id: string;
  title: string;
  detail: string;
  source: string;
  state: "partial" | "missing";
}

export interface CraClassificationAssessment {
  rulesetVersion: string;
  completedAt: ISODate;
  scopeResult: "in_scope" | "out_of_scope" | "needs_review";
  recommendedClass: CraClass;
  classificationStatus: ClassificationStatus;
  categoryId?: string;
  categoryLabel?: string;
  rationale: string;
  readinessScore: number;
  answers: CraAssessmentAnswer[];
  actions: CraAssessmentAction[];
  confirmedAt?: ISODate;
}

export interface Integration {
  id: EntityId;
  name: string;
  type: "email" | "webhook" | "collector" | "jira";
  status: "connected" | "attention" | "not_connected";
  description: string;
  configuration: Record<string, unknown>;
  secretReference?: string;
  lastSyncAt?: ISODate;
  version?: number;
}

export interface NotificationPreferences {
  urgentFindings: boolean;
  deadlineWarnings: boolean;
  monitoringFailures: boolean;
  approvalRequests: boolean;
  emailDigest: "off" | "daily" | "weekly";
}

export interface SecuritySettings {
  sessionTimeoutMinutes: number;
  evidenceRetentionMonths: number;
  requireMfa: boolean;
  allowRawArtifacts: boolean;
}

export interface AppearanceSettings {
  theme: "light" | "dark" | "system";
  density: "comfortable" | "compact";
}

export interface AnalyticsSettings {
  enabled: boolean;
  retentionDays: number;
}

export interface AppSettings {
  notifications: NotificationPreferences;
  security: SecuritySettings;
  appearance: AppearanceSettings;
  analytics: AnalyticsSettings;
}

export interface Product {
  id: EntityId;
  slug: string;
  name: string;
  identifier: string;
  manufacturer: string;
  description: string;
  craClass: CraClass;
  classificationStatus: ClassificationStatus;
  classificationAssessment?: CraClassificationAssessment;
  supportUntil: ISODate;
  ownerId?: EntityId;
  readiness: ReadinessStatus;
  monitoringHealth: MonitoringHealth;
  activeReleaseId?: EntityId;
  actionCount: number;
  nextDeadline?: ISODate;
  tags: string[];
  createdAt: ISODate;
}

export interface ReleaseCoverage {
  components: number;
  identifiedComponents: number;
  advisorySourcesChecked: number;
  advisorySourcesExpected: number;
  limitations: string[];
}

export interface ReleaseArtifact {
  id: EntityId;
  kind: "collector_package" | "sbom" | "raw_artifact";
  name: string;
  sha256: string;
  receivedAt: ISODate;
  sizeLabel: string;
}

export interface Release {
  id: EntityId;
  productId: EntityId;
  version: string;
  channel: "stable" | "beta" | "lts";
  status: "active" | "supported" | "end_of_support" | "draft";
  releaseDate: ISODate;
  supportedUntil: ISODate;
  readiness: ReadinessStatus;
  monitoringHealth: MonitoringHealth;
  sbomStatus: "validated" | "partial" | "missing";
  coverage: ReleaseCoverage;
  artifacts: ReleaseArtifact[];
  lastAnalysisAt?: ISODate;
  lastMonitoringCheckAt?: ISODate;
  createdAt: ISODate;
}

export interface ReleaseMonitoringEvent {
  id: EntityId;
  runId: EntityId;
  eventType: "started" | "succeeded" | "failed";
  trigger: "manual" | "scheduled";
  health: MonitoringHealth;
  message: string;
  actorId: EntityId;
  occurredAt: ISODate;
  limitations: string[];
}

export interface ReleaseMonitoringView {
  productId: EntityId;
  releaseId: EntityId;
  enabledSources: ("osv" | "cisa_kev" | "epss" | "native_advisory" | "vendor_advisory")[];
  cadenceMinutes: number;
  enabled: boolean;
  health: MonitoringHealth;
  nextCheckAt?: ISODate;
  lastCheckAt?: ISODate;
  lastSuccessAt?: ISODate;
  consecutiveFailures: number;
  limitations: string[];
  running: boolean;
  recentEvents: ReleaseMonitoringEvent[];
}

export interface FindingEvidence {
  id: EntityId;
  label: string;
  kind: "sbom" | "binary" | "runtime" | "vendor" | "advisory" | "decision";
  source: string;
  collectedAt: ISODate;
  digest?: string;
}

export interface FindingDecision {
  id: EntityId;
  decision: DecisionKind;
  rationale: string;
  decidedBy: EntityId;
  decidedAt: ISODate;
}

export interface Remediation {
  status: "not_started" | "planned" | "in_progress" | "verification_pending" | "verified";
  plan?: string;
  targetDate?: ISODate;
  completedAt?: ISODate;
}

export interface Finding {
  id: EntityId;
  reference: string;
  productId: EntityId;
  releaseId: EntityId;
  title: string;
  component: string;
  componentVersion: string;
  severity: Severity;
  cvss: number;
  status: FindingStatus;
  priority: PriorityBand;
  kev: boolean;
  activelyExploited: boolean;
  affectedness: "confirmed" | "not_affected" | "unknown";
  reachability: "reachable" | "not_reachable" | "unknown";
  reachabilityRecommendation: "reachable" | "not_reachable" | "review";
  reachabilityConfidence: "high" | "medium" | "low";
  reachabilityReasonCodes: string[];
  reachabilityReviewRequired: boolean;
  summary: string;
  actionReason: string;
  introducedAt: ISODate;
  updatedAt: ISODate;
  dueAt?: ISODate;
  assigneeId?: EntityId;
  decisions: FindingDecision[];
  remediation: Remediation;
  evidenceIds: EntityId[];
}

export type ActionItemType = "finding" | "deadline" | "monitoring" | "evidence" | "approval";

export interface ActionItem {
  id: EntityId;
  type: ActionItemType;
  priority: PriorityBand;
  title: string;
  reason: string;
  productId?: EntityId;
  releaseId?: EntityId;
  dueAt?: ISODate;
  ownerId?: EntityId;
  status: "open" | "acknowledged" | "completed";
  targetUrl: string;
  updatedAt: ISODate;
}

export type ComplianceLifecycleStatus = "action_required" | "in_progress" | "pending_approval" | "approved" | "acknowledged" | "resolved";

export interface ComplianceAuditEntry {
  id: EntityId;
  action: string;
  actorId: EntityId;
  itemVersion: number;
  occurredAt: ISODate;
  payload: Record<string, unknown>;
}

export interface ComplianceItem {
  id: EntityId;
  type: "readiness" | "deadline" | "missing_evidence" | "reporting_case" | "approval";
  title: string;
  requirement: string;
  productId?: EntityId;
  releaseId?: EntityId;
  priority: PriorityBand;
  status: "open" | "in_progress" | "blocked" | "complete";
  lifecycleStatus?: ComplianceLifecycleStatus;
  readiness?: "ready" | "review_required" | "action_required";
  dueAt?: ISODate;
  ownerId?: EntityId;
  reason: string;
  targetUrl: string;
  sourceId?: EntityId;
  reportingStage?: "early_warning" | "notification" | "final_report";
  selfFilingRecordId?: EntityId;
  selfFilingRecordUrl?: string;
  approvedBy?: EntityId;
  approvedAt?: ISODate;
  acknowledgedAt?: ISODate;
  resolvedAt?: ISODate;
  version?: number;
  createdAt?: ISODate;
  updatedAt?: ISODate;
  audit?: ComplianceAuditEntry[];
}

export interface ComplianceUpdateCommand {
  itemId: EntityId;
  title?: string;
  description?: string;
  priority?: "critical" | "high" | "medium" | "low";
  status?: ComplianceLifecycleStatus;
  dueAt?: ISODate;
  clearDueAt?: boolean;
  ownerId?: EntityId;
  clearOwner?: boolean;
  selfFilingRecordId?: EntityId;
  selfFilingRecordUrl?: string;
}

export interface ComplianceApprovalCommand {
  itemId: EntityId;
  selfFilingRecordId?: EntityId;
  selfFilingRecordUrl?: string;
}

export interface ReportingCase {
  id: EntityId;
  reference: string;
  productId: EntityId;
  releaseId: EntityId;
  findingId?: EntityId;
  type: "actively_exploited_vulnerability" | "severe_incident";
  status: "assessment" | "report_required" | "drafting" | "approval" | "self_filed" | "closed";
  openedAt: ISODate;
  initialNoticeDueAt: ISODate;
  finalReportDueAt?: ISODate;
  ownerId?: EntityId;
}

export interface Approval {
  id: EntityId;
  documentId: EntityId;
  status: "requested" | "approved" | "rejected";
  requestedBy: EntityId;
  requestedAt: ISODate;
  decidedBy?: EntityId;
  decidedAt?: ISODate;
  comment?: string;
}

export interface DocumentAuditEntry {
  id: EntityId;
  action: "generated" | "edited" | "approval_requested" | "approved" | "rejected" | "exported" | "self_filed";
  actorId: EntityId;
  at: ISODate;
  detail: string;
}

export interface DocumentRevision {
  version: number;
  format: DocumentRecord["format"];
  status: "draft" | "approval_required" | "approved" | "rejected" | "superseded";
  completeness: DocumentRecord["completeness"];
  contentHash: string;
  storageLocator: string;
  sizeBytes: number;
  createdBy: EntityId;
  createdAt: ISODate;
}

export interface DocumentSelfFiling {
  id: EntityId;
  version: number;
  externalSubmissionReference: string;
  submittedAt: ISODate;
  receiptEvidenceLocator: string;
  receiptContentHash?: string;
  recordedBy: EntityId;
  recordedAt: ISODate;
}

export interface DocumentDownloadMetadata {
  documentId: EntityId;
  version: number;
  filename: string;
  format: DocumentRecord["format"];
  contentHash: string;
  sizeBytes: number;
  storageLocator: string;
  contentType: string;
  downloadType: "storage_metadata_only" | "content_available";
}

export interface DocumentDownloadFile {
  blob: Blob;
  contentType: string;
  filename?: string;
}


export interface RegisterDocumentRevisionInput {
  documentId: EntityId;
  format: DocumentRecord["format"];
  contentHash: string;
  storageLocator: string;
  sizeBytes: number;
  completeness: DocumentRecord["completeness"];
}

export interface RecordDocumentSelfFilingInput {
  documentId: EntityId;
  externalSubmissionReference: string;
  submittedAt: ISODate;
  receiptEvidenceLocator: string;
  receiptContentHash?: string;
}

export interface DocumentRecord {
  id: EntityId;
  productId: EntityId;
  releaseId?: EntityId;
  caseId?: EntityId;
  name: string;
  type: "cra_reporting_pack" | "conformity" | "sbom" | "vex" | "evidence" | "verification";
  format: "PDF/A-2b" | "CycloneDX JSON" | "CSAF VEX" | "ZIP" | "JSON";
  version: number;
  status: "draft" | "approval_required" | "approved" | "self_filed" | "superseded";
  completeness: "complete" | "missing_inputs" | "limited_coverage";
  updatedAt: ISODate;
  updatedBy: EntityId;
  approvalId?: EntityId;
  audit: DocumentAuditEntry[];
  revisions?: DocumentRevision[];
  approvalHistory?: DocumentAuditEntry[];
  selfFilings?: DocumentSelfFiling[];
  contentHash?: string;
  storageLocator?: string;
  sizeBytes?: number;
}

export interface Activity {
  id: EntityId;
  type: "analysis" | "finding" | "decision" | "monitoring" | "document" | "member";
  title: string;
  detail: string;
  productId?: EntityId;
  releaseId?: EntityId;
  actorId?: EntityId;
  at: ISODate;
  targetUrl?: string;
}

export interface Notification {
  id: EntityId;
  type: "finding" | "deadline" | "monitoring" | "approval" | "document" | "analysis" | "system";
  priority: PriorityBand;
  title: string;
  body: string;
  targetUrl: string;
  createdAt: ISODate;
  readAt?: ISODate;
  acknowledgedAt?: ISODate;
}

export interface AnalysisDraft {
  productId: EntityId;
  releaseId?: EntityId;
  version: string;
  channel: Release["channel"];
  inputKind: ReleaseArtifact["kind"];
  fileName: string;
  fileSize: number;
  file?: Blob;
  runtimeTelemetry?: Blob;
  runtimeTelemetryName?: string;
  exposureContext?: Blob;
  exposureContextName?: string;
  rawArtifactConsent?: boolean;
  changedDigestConfirmed?: boolean;
}

export interface AnalysisPreview {
  valid: boolean;
  releaseId?: EntityId;
  detectedFormat: string;
  componentCount: number;
  identifiedComponentCount: number;
  warnings: string[];
  digest: string;
}

export interface AnalysisResult {
  releaseId: EntityId;
  newFindings: number;
  changedFindings: number;
  componentCount: number;
  coverage: ReleaseCoverage;
  resultUrl: string;
}

export interface AnalysisJob {
  id: EntityId;
  draft: AnalysisDraft;
  status: "queued" | "validating" | "analyzing" | "completed" | "failed";
  progress: number;
  stage: string;
  createdAt: ISODate;
  updatedAt: ISODate;
  result?: AnalysisResult;
  error?: string;
}

export interface HomeReadModel {
  generatedAt: ISODate;
  monitoring: {
    state: "healthy" | "degraded" | "failed" | "stale" | "inactive" | "not_configured";
    supportedReleases: number;
    configured: number;
    healthy: number;
    degraded: number;
    failed: number;
    stale: number;
    inactive: number;
    notConfigured: number;
    lastSuccessAt?: ISODate;
    lastCheckAt?: ISODate;
    nextCheckAt?: ISODate;
    cadenceMinutes: number[];
    sources: Array<{ source: string; state: "healthy" | "degraded" | "failed" | "stale" | "inactive"; releaseCount: number }>;
  };
  counters: {
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
  };
  dataWarnings: string[];
}

export interface DemoState {
  schemaVersion: 2;
  organization: Organization;
  currentUserId: EntityId;
  members: TeamMember[];
  integrations: Integration[];
  settings: AppSettings;
  products: Product[];
  releases: Release[];
  findings: Finding[];
  evidence: FindingEvidence[];
  actions: ActionItem[];
  complianceItems: ComplianceItem[];
  cases: ReportingCase[];
  approvals: Approval[];
  documents: DocumentRecord[];
  activities: Activity[];
  notifications: Notification[];
  analysisJobs: AnalysisJob[];
  home?: HomeReadModel;
}

export interface CreateProductInput {
  name: string;
  identifier: string;
  manufacturer: string;
  description?: string;
  craClass: Product["craClass"];
  classificationStatus: Product["classificationStatus"];
  classificationAssessment?: CraClassificationAssessment;
  supportUntil: ISODate;
  ownerId?: EntityId;
}

export interface CreateReleaseInput {
  productId: EntityId;
  version: string;
  channel: Release["channel"];
  releaseDate: ISODate;
  supportedUntil: ISODate;
}

export type OrganizationProfileUpdate = Partial<Pick<Organization, "name" | "legalName" | "country" | "registrationNumber" | "defaultTimezone">>;

export type ManagedRole = Role;

export interface TeamMemberUpdate {
  title?: string;
  roles?: ManagedRole[];
  status?: "active" | "invited";
}

export interface IntegrationUpdate {
  status?: Integration["status"];
  description?: string;
  configuration?: Record<string, unknown>;
  secretReference?: string | null;
}

export interface FindingDecisionInput {
  findingId: EntityId;
  decision: DecisionKind;
  rationale: string;
}

export interface FindingBatchDecisionInput {
  findingIds: EntityId[];
  decision?: "affected" | "not_affected";
  recommendationsOnly?: boolean;
  rationale: string;
}

export interface RemediationInput {
  findingId: EntityId;
  status: Remediation["status"];
  plan?: string;
  targetDate?: ISODate;
}
