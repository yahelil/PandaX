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

export interface DataAdapter {
  getSnapshot(): DemoState;
  subscribe(listener: DemoListener): () => void;
  reset(): void;
  updateSettings<K extends keyof AppSettings>(section: K, patch: Partial<AppSettings[K]>): void;
  acknowledgeNotification(notificationId: EntityId): void;
  assignFinding(findingId: EntityId, memberId?: EntityId): Finding;
  recordFindingDecision(input: FindingDecisionInput): Finding;
  updateRemediation(input: RemediationInput): Finding;
  approveDocument(documentId: EntityId, comment?: string): DocumentRecord;
  rejectDocument(documentId: EntityId, comment: string): DocumentRecord;
  createProduct(input: CreateProductInput): Product;
  createRelease(input: CreateReleaseInput): Release;
  previewAnalysis(draft: AnalysisDraft): Promise<AnalysisPreview>;
  runAnalysis(draft: AnalysisDraft): Promise<AnalysisJob>;
  getAnalysisJob(jobId: EntityId): AnalysisJob | undefined;
  getApproval(documentId: EntityId): Approval | undefined;
}
