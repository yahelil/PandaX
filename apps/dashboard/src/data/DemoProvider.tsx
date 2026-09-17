import {
  createContext,
  type PropsWithChildren,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useSyncExternalStore,
} from "react";

import type { AdapterStatus, DataAdapter, MaybePromise, UpdateProductInput, WorkspaceSearchResult } from "./adapter";
import type { PrivacySafeAnalyticsEvent } from "./governanceApi";
import type { AnalysisEvidenceFile } from "./releaseOperationsApi";
import { createFixtureAdapter } from "./fixtureAdapter";
import type {
  AnalysisDraft,
  AnalysisJob,
  AnalysisPreview,
  ComplianceApprovalCommand,
  RegisterDocumentRevisionInput,
  AppSettings,
  ComplianceItem,
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
  Scope,
  TeamMember,
  TeamMemberUpdate,
  ComplianceUpdateCommand,
} from "./types";

export interface DemoSelectors {
  product(id?: EntityId): Product | undefined;
  release(id?: EntityId): Release | undefined;
  releasesForProduct(productId?: EntityId): Release[];
  findingsForScope(scope?: Scope): Finding[];
  actionsForScope(scope?: Scope): DemoState["actions"];
  complianceForScope(scope?: Scope): ComplianceItem[];
  documentsForScope(scope?: Scope): DocumentRecord[];
  document(id?: EntityId): DocumentRecord | undefined;
  member(id?: EntityId): TeamMember | undefined;
  analysisJob(id?: EntityId): AnalysisJob | undefined;
}

export interface DemoActions {
  reset(): void;
  refresh(): Promise<void>;
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
  decideFinding(input: FindingDecisionInput): MaybePromise<Finding>;
  decideFindings(input: FindingBatchDecisionInput): MaybePromise<Finding[]>;
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
  updateProduct(input: UpdateProductInput): Promise<Product>;
  createRelease(input: CreateReleaseInput): Promise<Release>;
  selectActiveRelease(productId: EntityId, releaseId: EntityId): Promise<Product>;
  downloadReleaseReport(productId: EntityId, releaseId: EntityId, jobId: EntityId): Promise<AnalysisEvidenceFile>;
  downloadAnalysisEvidence(productId: EntityId, releaseId: EntityId, jobId: EntityId, digest: string): Promise<AnalysisEvidenceFile>;
  generateFindingsReport(productId: EntityId, releaseId: EntityId): Promise<AnalysisEvidenceFile>;
  generateSecurityPdf(productId: EntityId, releaseId: EntityId): Promise<AnalysisEvidenceFile>;
  downloadReleaseEvidenceFile(productId: EntityId, releaseId: EntityId, jobId: EntityId, digest: string): Promise<AnalysisEvidenceFile>;
  previewAnalysis(draft: AnalysisDraft): Promise<AnalysisPreview>;
  runAnalysis(draft: AnalysisDraft): Promise<AnalysisJob>;
  loadReleaseMonitoring(productId: EntityId, releaseId: EntityId, options?: { signal?: AbortSignal }): Promise<ReleaseMonitoringView>;
  runReleaseMonitoring(productId: EntityId, releaseId: EntityId): Promise<ReleaseMonitoringView>;
}

export interface DemoContextValue {
  state: DemoState;
  adapterStatus: AdapterStatus;
  currentUser: TeamMember;
  products: Product[];
  releases: Release[];
  findings: Finding[];
  actionItems: DemoState["actions"];
  complianceItems: ComplianceItem[];
  documents: DocumentRecord[];
  notifications: DemoState["notifications"];
  selectors: DemoSelectors;
  actions: DemoActions;
}

const DemoContext = createContext<DemoContextValue | null>(null);

export interface DemoProviderProps extends PropsWithChildren {
  adapter?: DataAdapter;
  currentUserOverride?: TeamMember;
}

function matchesScope(productId: EntityId | undefined, releaseId: EntityId | undefined, scope?: Scope): boolean {
  if (!scope) return true;
  if (scope.productId && scope.productId !== productId) return false;
  return !scope.releaseId || scope.releaseId === releaseId;
}

export function DemoProvider({ adapter: providedAdapter, currentUserOverride, children }: DemoProviderProps) {
  const adapterRef = useRef<DataAdapter | null>(null);
  if (!adapterRef.current) adapterRef.current = providedAdapter ?? createFixtureAdapter();
  const adapter = adapterRef.current;
  const state = useSyncExternalStore(adapter.subscribe, adapter.getSnapshot, adapter.getSnapshot);
  const adapterStatus = useSyncExternalStore(adapter.subscribeStatus, adapter.getStatusSnapshot, adapter.getStatusSnapshot);

  useEffect(() => {
    const controller = new AbortController();
    void adapter.initialize({ signal: controller.signal });
    return () => controller.abort();
  }, [adapter]);

  const selectors = useMemo<DemoSelectors>(() => ({
    product: (id) => state.products.find((item) => item.id === id),
    release: (id) => state.releases.find((item) => item.id === id),
    releasesForProduct: (productId) => productId ? state.releases.filter((item) => item.productId === productId) : state.releases,
    findingsForScope: (scope) => state.findings.filter((item) => matchesScope(item.productId, item.releaseId, scope)),
    actionsForScope: (scope) => state.actions.filter((item) => matchesScope(item.productId, item.releaseId, scope)),
    complianceForScope: (scope) => state.complianceItems.filter((item) => matchesScope(item.productId, item.releaseId, scope)),
    documentsForScope: (scope) => state.documents.filter((item) => matchesScope(item.productId, item.releaseId, scope)),
    document: (id) => state.documents.find((item) => item.id === id),
    member: (id) => state.members.find((item) => item.id === id),
    analysisJob: (id) => state.analysisJobs.find((item) => item.id === id),
  }), [state]);

  const actions = useMemo<DemoActions>(() => ({
    reset: adapter.reset,
    refresh: adapter.refresh,
    search: adapter.search,
    trackAnalytics: adapter.trackAnalytics,
    updateSettings: adapter.updateSettings,
    updateOrganization: adapter.updateOrganization,
    updateTeamMember: adapter.updateTeamMember,
    updateIntegration: adapter.updateIntegration,
    markNotificationRead: adapter.markNotificationRead,
    acknowledgeNotification: adapter.acknowledgeNotification,
    loadFindingDetail: adapter.loadFindingDetail,
    assignFinding: adapter.assignFinding,
    decideFinding: adapter.recordFindingDecision,
    decideFindings: adapter.recordFindingBatchDecision,
    updateRemediation: adapter.updateRemediation,
    loadComplianceDetail: adapter.loadComplianceDetail,
    updateCompliance: adapter.updateCompliance,
    approveCompliance: adapter.approveCompliance,
    approveDocument: adapter.approveDocument,
    rejectDocument: adapter.rejectDocument,
    loadDocumentDetail: adapter.loadDocumentDetail,
    getDocumentDownload: adapter.getDocumentDownload,
    downloadDocument: adapter.downloadDocument,
    requestDocumentApproval: adapter.requestDocumentApproval,
    addDocumentRevision: adapter.addDocumentRevision,
    recordDocumentSelfFiling: adapter.recordDocumentSelfFiling,
    createProduct: adapter.createProduct,
    updateProduct: adapter.updateProduct,
    createRelease: adapter.createRelease,
    selectActiveRelease: adapter.selectActiveRelease,
    downloadReleaseReport: adapter.downloadReleaseReport,
    downloadAnalysisEvidence: adapter.downloadAnalysisEvidence,
    generateFindingsReport: adapter.generateFindingsReport,
    generateSecurityPdf: adapter.generateSecurityPdf,
    downloadReleaseEvidenceFile: adapter.downloadReleaseEvidenceFile,
    previewAnalysis: adapter.previewAnalysis,
    runAnalysis: adapter.runAnalysis,
    loadReleaseMonitoring: adapter.loadReleaseMonitoring,
    runReleaseMonitoring: adapter.runReleaseMonitoring,
  }), [adapter]);

  const currentUser = currentUserOverride ?? state.members.find((item) => item.id === state.currentUserId);
  if (!currentUser) throw new Error("Demo current user is missing from team fixtures.");

  const value = useMemo<DemoContextValue>(() => ({
    state,
    adapterStatus,
    currentUser,
    products: state.products,
    releases: state.releases,
    findings: state.findings,
    actionItems: state.actions,
    complianceItems: state.complianceItems,
    documents: state.documents,
    notifications: state.notifications,
    selectors,
    actions,
  }), [actions, adapterStatus, currentUser, selectors, state]);

  return <DemoContext.Provider value={value}>{children}</DemoContext.Provider>;
}

export function useDemo(): DemoContextValue {
  const value = useContext(DemoContext);
  if (!value) throw new Error("useDemo must be used within DemoProvider.");
  return value;
}
