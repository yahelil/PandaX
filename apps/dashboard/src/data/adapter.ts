import type {
  AnalysisDraft,
  AnalysisJob,
  AnalysisPreview,
  ComplianceApprovalCommand,
  RegisterDocumentRevisionInput,
  AppSettings,
  Approval,
  CreateProductInput,
  CreateReleaseInput,
  DemoState,
  DocumentRecord,
  DocumentDownloadMetadata,
  DocumentDownloadFile,
  EntityId,
  Finding,
  FindingDecisionInput,
  FindingBatchDecisionInput,
  Integration,
  IntegrationUpdate,
  Organization,
  OrganizationProfileUpdate,
  Product,
  Release,
  ReleaseMonitoringView,
  RecordDocumentSelfFilingInput,
  RemediationInput,
  ComplianceItem,
  ComplianceUpdateCommand,
  TeamMember,
  TeamMemberUpdate,
} from "./types";
import type { PrivacySafeAnalyticsEvent } from "./governanceApi";
import type { AnalysisEvidenceFile } from "./releaseOperationsApi";

export type DemoListener = () => void;

export type AdapterOperation =
  | "initialize" | "refresh" | "search" | "create_product" | "create_release"
  | "mark_notification_read" | "acknowledge_notification" | "ingest_analytics" | "assign_finding" | "decide_finding" | "batch_decide_findings"
  | "update_remediation" | "load_finding" | "approve_document"
  | "reject_document" | "load_document" | "download_document" | "download_document_content" | "request_document_approval"
  | "add_document_revision" | "self_file_document" | "update_settings" | "preview_analysis" | "run_analysis" | "run_monitoring"
  | "load_compliance" | "update_compliance" | "approve_compliance"
  | "update_organization" | "update_team_member" | "update_integration" | "select_active_release" | "download_release_report";

export type MaybePromise<T> = T | Promise<T>;

export interface WorkspaceSearchResult {
  id: string;
  type: "Product" | "Release" | "Finding" | "Compliance" | "Document";
  title: string;
  detail: string;
  to: string;
}

export interface AdapterFailure {
  operation: AdapterOperation;
  code: string;
  message: string;
  status?: number;
  occurredAt: string;
}

export interface AdapterStatus {
  mode: "fixture" | "production";
  phase: "loading" | "ready" | "error";
  lastSyncedAt?: string;
  failure?: AdapterFailure;
  analyticsFailure?: Pick<AdapterFailure, "code" | "status" | "occurredAt">;
}

export interface DataAdapter {
  getSnapshot(): DemoState;
  getStatusSnapshot(): AdapterStatus;
  subscribe(listener: DemoListener): () => void;
  subscribeStatus(listener: DemoListener): () => void;
  initialize(options?: { signal?: AbortSignal }): Promise<void>;
  refresh(options?: { signal?: AbortSignal }): Promise<void>;
  reset(): void;
  search(query: string, options?: { signal?: AbortSignal }): Promise<WorkspaceSearchResult[]>;
  trackAnalytics(event: PrivacySafeAnalyticsEvent): MaybePromise<void>;
  updateSettings<K extends keyof AppSettings>(section: K, patch: Partial<AppSettings[K]>): MaybePromise<void>;
  updateOrganization(patch: OrganizationProfileUpdate): MaybePromise<Organization>;
  updateTeamMember(memberId: EntityId, patch: TeamMemberUpdate): MaybePromise<TeamMember>;
  updateIntegration(integrationId: EntityId, patch: IntegrationUpdate): MaybePromise<Integration>;
  markNotificationRead(notificationId: EntityId): MaybePromise<void>;
  acknowledgeNotification(notificationId: EntityId): MaybePromise<void>;
  loadFindingDetail(findingId: EntityId, options?: { signal?: AbortSignal }): Promise<Finding | undefined>;
  assignFinding(findingId: EntityId, memberId?: EntityId): MaybePromise<Finding>;
  recordFindingDecision(input: FindingDecisionInput): MaybePromise<Finding>;
  recordFindingBatchDecision(input: FindingBatchDecisionInput): MaybePromise<Finding[]>;
  updateRemediation(input: RemediationInput): MaybePromise<Finding>;
  loadComplianceDetail(itemId: EntityId, options?: { signal?: AbortSignal }): Promise<ComplianceItem | undefined>;
  updateCompliance(input: ComplianceUpdateCommand): MaybePromise<ComplianceItem>;
  approveCompliance(input: ComplianceApprovalCommand): MaybePromise<ComplianceItem>;
  approveDocument(documentId: EntityId, comment?: string): MaybePromise<DocumentRecord>;
  rejectDocument(documentId: EntityId, comment: string): MaybePromise<DocumentRecord>;
  loadDocumentDetail(documentId: EntityId, options?: { signal?: AbortSignal }): Promise<DocumentRecord | undefined>;
  getDocumentDownload(documentId: EntityId, version?: number): Promise<DocumentDownloadMetadata>;
  downloadDocument(documentId: EntityId, version?: number): Promise<DocumentDownloadFile>;
  requestDocumentApproval(documentId: EntityId, comment?: string): MaybePromise<DocumentRecord>;
  addDocumentRevision(input: RegisterDocumentRevisionInput): MaybePromise<DocumentRecord>;
  recordDocumentSelfFiling(input: RecordDocumentSelfFilingInput): MaybePromise<DocumentRecord>;
  createProduct(input: CreateProductInput): Promise<Product>;
  createRelease(input: CreateReleaseInput): Promise<Release>;
  selectActiveRelease(productId: EntityId, releaseId: EntityId): Promise<Product>;
  downloadReleaseReport(productId: EntityId, releaseId: EntityId, jobId: EntityId): Promise<AnalysisEvidenceFile>;
  downloadAnalysisEvidence(productId: EntityId, releaseId: EntityId, jobId: EntityId, digest: string): Promise<AnalysisEvidenceFile>;
  generateFindingsReport(productId: EntityId, releaseId: EntityId): Promise<AnalysisEvidenceFile>;
  generateSecurityPdf(productId: EntityId, releaseId: EntityId): Promise<AnalysisEvidenceFile>;
  downloadReleaseEvidenceFile(productId: EntityId, releaseId: EntityId, jobId: EntityId, digest: string): Promise<AnalysisEvidenceFile>;
  previewAnalysis(draft: AnalysisDraft): Promise<AnalysisPreview>;
  runAnalysis(draft: AnalysisDraft): Promise<AnalysisJob>;
  getAnalysisJob(jobId: EntityId): AnalysisJob | undefined;
  getApproval(documentId: EntityId): Approval | undefined;
  loadReleaseMonitoring(productId: EntityId, releaseId: EntityId, options?: { signal?: AbortSignal }): Promise<ReleaseMonitoringView>;
  runReleaseMonitoring(productId: EntityId, releaseId: EntityId): Promise<ReleaseMonitoringView>;
}
