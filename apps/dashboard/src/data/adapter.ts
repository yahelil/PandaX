import type {
  AnalysisDraft,
  AnalysisJob,
  AnalysisPreview,
  AppSettings,
  Approval,
  CreateProductInput,
  CreateReleaseInput,
  DemoState,
  DocumentRecord,
  EntityId,
  Finding,
  FindingDecisionInput,
  Product,
  Release,
  RemediationInput,
} from "./types";

export type DemoListener = () => void;

export type AdapterOperation =
  | "initialize" | "refresh" | "search" | "create_product" | "create_release"
  | "acknowledge_notification" | "assign_finding" | "decide_finding"
  | "update_remediation" | "load_finding" | "approve_document"
  | "reject_document" | "update_settings" | "preview_analysis" | "run_analysis";

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
  updateSettings<K extends keyof AppSettings>(section: K, patch: Partial<AppSettings[K]>): MaybePromise<void>;
  acknowledgeNotification(notificationId: EntityId): MaybePromise<void>;
  loadFindingDetail(findingId: EntityId, options?: { signal?: AbortSignal }): Promise<Finding | undefined>;
  assignFinding(findingId: EntityId, memberId?: EntityId): MaybePromise<Finding>;
  recordFindingDecision(input: FindingDecisionInput): MaybePromise<Finding>;
  updateRemediation(input: RemediationInput): MaybePromise<Finding>;
  approveDocument(documentId: EntityId, comment?: string): MaybePromise<DocumentRecord>;
  rejectDocument(documentId: EntityId, comment: string): MaybePromise<DocumentRecord>;
  createProduct(input: CreateProductInput): Promise<Product>;
  createRelease(input: CreateReleaseInput): Promise<Release>;
  previewAnalysis(draft: AnalysisDraft): Promise<AnalysisPreview>;
  runAnalysis(draft: AnalysisDraft): Promise<AnalysisJob>;
  getAnalysisJob(jobId: EntityId): AnalysisJob | undefined;
  getApproval(documentId: EntityId): Approval | undefined;
}
