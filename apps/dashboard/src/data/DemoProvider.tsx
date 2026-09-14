import {
  createContext,
  type PropsWithChildren,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useSyncExternalStore,
} from "react";

import type { AdapterStatus, DataAdapter } from "./adapter";
import { createFixtureAdapter } from "./fixtureAdapter";
import type {
  AnalysisDraft,
  AnalysisJob,
  AnalysisPreview,
  AppSettings,
  ComplianceItem,
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
  Scope,
  TeamMember,
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
  updateSettings<K extends keyof AppSettings>(section: K, patch: Partial<AppSettings[K]>): void;
  acknowledgeNotification(notificationId: EntityId): void;
  assignFinding(findingId: EntityId, memberId?: EntityId): Finding;
  decideFinding(input: FindingDecisionInput): Finding;
  updateRemediation(input: RemediationInput): Finding;
  approveDocument(documentId: EntityId, comment?: string): DocumentRecord;
  rejectDocument(documentId: EntityId, comment: string): DocumentRecord;
  createProduct(input: CreateProductInput): Promise<Product>;
  createRelease(input: CreateReleaseInput): Promise<Release>;
  previewAnalysis(draft: AnalysisDraft): Promise<AnalysisPreview>;
  runAnalysis(draft: AnalysisDraft): Promise<AnalysisJob>;
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
}

function matchesScope(productId: EntityId, releaseId: EntityId | undefined, scope?: Scope): boolean {
  if (!scope) return true;
  if (scope.productId && scope.productId !== productId) return false;
  return !scope.releaseId || scope.releaseId === releaseId;
}

export function DemoProvider({ adapter: providedAdapter, children }: DemoProviderProps) {
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
    updateSettings: adapter.updateSettings,
    acknowledgeNotification: adapter.acknowledgeNotification,
    assignFinding: adapter.assignFinding,
    decideFinding: adapter.recordFindingDecision,
    updateRemediation: adapter.updateRemediation,
    approveDocument: adapter.approveDocument,
    rejectDocument: adapter.rejectDocument,
    createProduct: adapter.createProduct,
    createRelease: adapter.createRelease,
    previewAnalysis: adapter.previewAnalysis,
    runAnalysis: adapter.runAnalysis,
  }), [adapter]);

  const currentUser = state.members.find((item) => item.id === state.currentUserId);
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
