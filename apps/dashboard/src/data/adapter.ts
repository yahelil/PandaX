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

export type AdapterOperation = "initialize" | "refresh" | "create_product" | "create_release";

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
  updateSettings<K extends keyof AppSettings>(section: K, patch: Partial<AppSettings[K]>): void;
  acknowledgeNotification(notificationId: EntityId): void;
  assignFinding(findingId: EntityId, memberId?: EntityId): Finding;
  recordFindingDecision(input: FindingDecisionInput): Finding;
  updateRemediation(input: RemediationInput): Finding;
  approveDocument(documentId: EntityId, comment?: string): DocumentRecord;
  rejectDocument(documentId: EntityId, comment: string): DocumentRecord;
  createProduct(input: CreateProductInput): Promise<Product>;
  createRelease(input: CreateReleaseInput): Promise<Release>;
  previewAnalysis(draft: AnalysisDraft): Promise<AnalysisPreview>;
  runAnalysis(draft: AnalysisDraft): Promise<AnalysisJob>;
  getAnalysisJob(jobId: EntityId): AnalysisJob | undefined;
  getApproval(documentId: EntityId): Approval | undefined;
}
