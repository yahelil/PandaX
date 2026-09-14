export type EntityId = string;
export type ISODate = string;

export type PriorityBand = "urgent" | "high" | "normal" | "low";
export type ReadinessStatus = "ready" | "needs_attention" | "incomplete_evidence";
export type MonitoringHealth = "healthy" | "degraded" | "failed" | "inactive";
export type Severity = "critical" | "high" | "medium" | "low";
export type FindingStatus = "needs_review" | "action_required" | "in_remediation" | "accepted" | "resolved";
export type DecisionKind = "affected" | "not_affected" | "accepted_risk" | "deferred";
export type Role = "org_admin" | "compliance_operator" | "authorized_approver" | "read_only_auditor";

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
}

export interface Integration {
  id: EntityId;
  name: string;
  type: "email" | "webhook" | "collector" | "jira";
  status: "connected" | "attention" | "not_connected";
  description: string;
  lastSyncAt?: ISODate;
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

export interface AppSettings {
  notifications: NotificationPreferences;
  security: SecuritySettings;
  appearance: AppearanceSettings;
}

export interface Product {
  id: EntityId;
  slug: string;
  name: string;
  identifier: string;
  manufacturer: string;
  description: string;
  craClass: "default" | "important_i" | "important_ii" | "critical";
  classificationStatus: "confirmed" | "review_required";
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
  productId: EntityId;
  releaseId?: EntityId;
  dueAt?: ISODate;
  ownerId?: EntityId;
  status: "open" | "acknowledged" | "completed";
  targetUrl: string;
  updatedAt: ISODate;
}

export interface ComplianceItem {
  id: EntityId;
  type: "readiness" | "deadline" | "missing_evidence" | "reporting_case" | "approval";
  title: string;
  requirement: string;
  productId: EntityId;
  releaseId?: EntityId;
  priority: PriorityBand;
  status: "open" | "in_progress" | "blocked" | "complete";
  dueAt?: ISODate;
  ownerId?: EntityId;
  reason: string;
  targetUrl: string;
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
  type: "finding" | "deadline" | "monitoring" | "approval";
  priority: PriorityBand;
  title: string;
  body: string;
  targetUrl: string;
  createdAt: ISODate;
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
  rawArtifactConsent?: boolean;
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
}

export interface CreateProductInput {
  name: string;
  identifier: string;
  manufacturer: string;
  description?: string;
  craClass: Product["craClass"];
  classificationStatus: Product["classificationStatus"];
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

export interface FindingDecisionInput {
  findingId: EntityId;
  decision: DecisionKind;
  rationale: string;
}

export interface RemediationInput {
  findingId: EntityId;
  status: Remediation["status"];
  plan?: string;
  targetDate?: ISODate;
}
