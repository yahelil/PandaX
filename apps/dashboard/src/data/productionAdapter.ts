import type { AdapterFailure, AdapterOperation, AdapterStatus, DataAdapter, DemoListener, WorkspaceSearchResult } from "./adapter";
import { createFindingsApi, FindingApiError, type FindingsApi, type ManagedFinding } from "./findingsApi";
import { createGovernanceApi, GovernanceApiError, mapCompliance, mapGovernanceSettings, mapIntegration, mapTeamMember, type DocumentDetailDto, type GovernanceApi } from "./governanceApi";
import { createOperationsApi, OperationsApiError, type OperationsApi, type OperationsHome, type OperationsNotification, type OperationsSearchResult } from "./operationsApi";
import { FixtureAdapter } from "./fixtureAdapter";
import { createPortfolioApi, PortfolioApiError, type PortfolioApi } from "./portfolioApi";
import { createReleaseOperationsApi, ReleaseOperationsApiError, type ReleaseAnalysisJob, type ReleaseOperationsApi, type ReleaseScope } from "./releaseOperationsApi";
import type { Activity, AnalysisDraft, AnalysisJob, AnalysisPreview, AppSettings, Approval, CreateProductInput, CreateReleaseInput, DocumentAuditEntry, DocumentRecord, EntityId, Finding, FindingDecisionInput, Notification, Product, Release, Remediation, RemediationInput } from "./types";

export type BearerTokenProvider = () => string | undefined | Promise<string | undefined>;

declare global {
  interface Window { __ACTIS_GET_BEARER_TOKEN__?: BearerTokenProvider }
}

export interface ProductionAdapterConfig {
  organizationId: string;
  portfolioApi: PortfolioApi;
  findingsApi?: FindingsApi;
  operationsApi?: OperationsApi;
  governanceApi?: GovernanceApi;
  releaseOperationsApi?: ReleaseOperationsApi;
  fixtureAdapter?: FixtureAdapter;
}

export interface RuntimePortfolioConfig {
  apiUrl?: string;
  organizationId?: string;
  getBearerToken?: BearerTokenProvider;
  fetch?: typeof globalThis.fetch;
}

function failure(operation: AdapterOperation, error: unknown): AdapterFailure {
  if (error instanceof PortfolioApiError || error instanceof FindingApiError || error instanceof OperationsApiError || error instanceof GovernanceApiError || error instanceof ReleaseOperationsApiError) {
    return { operation, code: error.code, message: error.message, status: error.status, occurredAt: new Date().toISOString() };
  }
  return { operation, code: "unexpected", message: error instanceof Error ? error.message : "Unexpected Actis service error", occurredAt: new Date().toISOString() };
}

function mapAction(item: OperationsHome["actionQueue"][number]) {
  return {
    id: item.id,
    type: item.sourceType === "compliance" ? "deadline" as const : item.sourceType === "document" ? "approval" as const : item.sourceType,
    priority: item.priority, title: item.title, reason: item.reason, productId: item.productId,
    releaseId: item.releaseId, dueAt: item.dueAt, status: "open" as const,
    targetUrl: item.targetUrl, updatedAt: item.updatedAt,
  };
}

function mapActivity(item: OperationsHome["recentChanges"][number]): Activity {
  const type: Activity["type"] = item.sourceType === "portfolio" ? "analysis" : item.sourceType === "compliance" ? "decision" : item.sourceType;
  return { id: item.id, type, title: item.title, detail: item.description, productId: item.productId, releaseId: item.releaseId, actorId: item.actorId, at: item.occurredAt, targetUrl: item.targetUrl };
}

function mapNotification(item: OperationsNotification): Notification {
  const priority: Notification["priority"] = item.priority === "critical" ? "urgent" : item.priority === "high" ? "high" : item.priority === "medium" ? "normal" : "low";
  const type: Notification["type"] = item.kind === "compliance" ? "deadline" : item.kind;
  return { id: item.id, type, priority, title: item.title, body: item.detail, targetUrl: item.targetUrl, createdAt: item.createdAt, acknowledgedAt: item.acknowledgedAt };
}

function mapSearch(item: OperationsSearchResult): WorkspaceSearchResult {
  const type = ({ products: "Product", releases: "Release", findings: "Finding", compliance: "Compliance", documents: "Document" } as const)[item.category];
  return { id: item.id, type, title: item.title, detail: item.subtitle, to: item.url };
}

function mapDocumentAudit(entry: DocumentDetailDto["audit"][number]): DocumentAuditEntry {
  const actions: Record<string, DocumentAuditEntry["action"]> = {
    revision_created: "generated", approval_requested: "approval_requested", approved: "approved",
    rejected: "rejected", superseded: "edited", self_filing_recorded: "self_filed",
  };
  return { id: entry.id, action: actions[entry.eventType] ?? "edited", actorId: entry.actorId, at: entry.occurredAt, detail: entry.reason ?? String(entry.details.message ?? entry.eventType.replaceAll("_", " ")) };
}

function mapDocument(detail: DocumentDetailDto): DocumentRecord {
  const item = detail.document;
  const format = ({ pdf_a_2b: "PDF/A-2b", cyclonedx_json: "CycloneDX JSON", csaf_vex: "CSAF VEX", zip: "ZIP", json: "JSON" } as const)[item.current.format];
  const status = ({ draft: "draft", pending: "approval_required", approved: "approved", rejected: "draft", superseded: "superseded" } as const)[item.status];
  const rawCompleteness = item.current.provenance.completeness;
  const completeness: DocumentRecord["completeness"] = rawCompleteness === "missing_inputs" || rawCompleteness === "limited_coverage" ? rawCompleteness : "complete";
  return { id: item.id, productId: item.productId, releaseId: item.releaseId, caseId: item.caseId, name: item.name, type: item.kind, format, version: item.currentRevision, status, completeness, updatedAt: item.updatedAt, updatedBy: item.current.createdBy, audit: detail.audit.map(mapDocumentAudit) };
}

function remediationStatus(status: Remediation["status"]) {
  return ({ not_started: "not_planned", planned: "planned", in_progress: "in_progress", verification_pending: "completed", verified: "verified" } as const)[status];
}

function mapAnalysisPreview(job: ReleaseAnalysisJob): AnalysisPreview {
  const warnings = [];
  if (job.preview.skippedComponents) warnings.push(`${job.preview.skippedComponents} components could not be matched to a package identifier.`);
  warnings.push("Runtime reachability requires Collector or equivalent evidence.");
  return {
    valid: true,
    releaseId: job.releaseId,
    detectedFormat: `${job.preview.format} ${job.preview.version}`.trim(),
    componentCount: job.preview.components,
    identifiedComponentCount: job.preview.matchableComponents,
    warnings,
    digest: job.sha256,
  };
}

function mapAnalysisJob(job: ReleaseAnalysisJob, draft: AnalysisDraft): AnalysisJob {
  const status: AnalysisJob["status"] = job.status === "running"
    ? (job.stage.toLowerCase().includes("valid") ? "validating" : "analyzing")
    : job.status;
  const summary = job.result?.coverageSummary;
  const sourceCount = summary?.advisory_sources_checked ?? 0;
  const limitations = [
    ...(job.preview.skippedComponents ? [`${job.preview.skippedComponents} components could not be matched to a package identifier.`] : []),
    "Runtime reachability requires Collector or equivalent evidence.",
  ];
  return {
    id: job.id,
    draft: { ...draft, releaseId: job.releaseId, file: undefined },
    status,
    progress: job.progress,
    stage: job.stage,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    error: job.error,
    result: job.result ? {
      releaseId: job.releaseId,
      newFindings: summary?.new_findings ?? job.result.findings,
      changedFindings: summary?.changed_findings ?? 0,
      componentCount: job.result.components,
      coverage: {
        components: job.result.components,
        identifiedComponents: job.preview.matchableComponents,
        advisorySourcesChecked: sourceCount,
        advisorySourcesExpected: summary?.advisory_sources_expected ?? sourceCount,
        limitations,
      },
      resultUrl: `/products/${job.productId}/releases/${job.releaseId}`,
    } : undefined,
  };
}

export class ProductionAdapter implements DataAdapter {
  private readonly fixture: FixtureAdapter;
  private readonly dataListeners = new Set<DemoListener>();
  private readonly statusListeners = new Set<DemoListener>();
  private readonly findingDetails = new Map<string, ManagedFinding>();
  private readonly documentDetails = new Map<string, DocumentDetailDto>();
  private readonly uploadedAnalysis = new Map<string, ReleaseAnalysisJob>();
  private readonly analysisTimers = new Map<string, ReturnType<typeof setTimeout>>();
  private settingsVersion?: number;
  private status: AdapterStatus = { mode: "production", phase: "loading" };
  private refreshRevision = 0;

  constructor(private readonly config: ProductionAdapterConfig) {
    this.fixture = config.fixtureAdapter ?? new FixtureAdapter(undefined, false);
    this.fixture.subscribe(() => this.dataListeners.forEach((listener) => listener()));
  }

  getSnapshot = () => this.fixture.getSnapshot();
  getStatusSnapshot = () => this.status;
  subscribe = (listener: DemoListener) => { this.dataListeners.add(listener); return () => this.dataListeners.delete(listener); };
  subscribeStatus = (listener: DemoListener) => { this.statusListeners.add(listener); return () => this.statusListeners.delete(listener); };
  initialize = async (options?: { signal?: AbortSignal }) => this.load("initialize", options);
  refresh = async (options?: { signal?: AbortSignal }) => this.load("refresh", options);
  reset = () => { this.analysisTimers.forEach(clearTimeout); this.analysisTimers.clear(); this.uploadedAnalysis.clear(); this.fixture.reset(); void this.refresh(); };

  search = async (query: string, options?: { signal?: AbortSignal }): Promise<WorkspaceSearchResult[]> => {
    if (!this.config.operationsApi) return this.fixture.search(query);
    if (query.trim().length < 2) return [];
    return this.mutation("search", async () => {
      const result = await this.config.operationsApi!.search(this.config.organizationId, query, { limit: 8, signal: options?.signal });
      return result.groups.flatMap((group) => group.results).sort((a, b) => a.rank - b.rank).slice(0, 8).map(mapSearch);
    });
  };

  updateSettings = async <K extends keyof AppSettings>(section: K, patch: Partial<AppSettings[K]>): Promise<void> => {
    if (!this.config.governanceApi || this.settingsVersion === undefined) return this.fixture.updateSettings(section, patch);
    await this.mutation("update_settings", async () => {
      const updated = await this.config.governanceApi!.updateSettings(this.config.organizationId, { expectedVersion: this.settingsVersion!, [section]: patch });
      this.settingsVersion = updated.version;
      this.fixture.replaceSettings(mapGovernanceSettings(updated).settings);
    });
  };

  acknowledgeNotification = async (notificationId: EntityId): Promise<void> => {
    if (!this.config.operationsApi) return this.fixture.acknowledgeNotification(notificationId);
    await this.mutation("acknowledge_notification", async () => {
      const item = await this.config.operationsApi!.acknowledge(this.config.organizationId, notificationId);
      this.fixture.acknowledgeNotification(item.id);
    });
  };

  loadFindingDetail = async (findingId: EntityId, options?: { signal?: AbortSignal }): Promise<Finding | undefined> => {
    if (!this.config.findingsApi) return this.fixture.loadFindingDetail(findingId);
    const scope = this.findingScope(findingId);
    return this.mutation("load_finding", async () => {
      const detail = await this.config.findingsApi!.getFinding(this.config.organizationId, scope.productId, scope.releaseId, findingId, options);
      this.findingDetails.set(detail.id, detail);
      this.fixture.upsertFinding(detail);
      return detail;
    });
  };

  assignFinding = async (findingId: EntityId, memberId?: EntityId): Promise<Finding> => {
    if (!this.config.findingsApi) return this.fixture.assignFinding(findingId, memberId);
    const scope = this.findingScope(findingId);
    return this.mutation("assign_finding", async () => {
      const updated = await this.config.findingsApi!.assignFinding(this.config.organizationId, scope.productId, scope.releaseId, findingId, { assigneeId: memberId ?? null, expectedVersion: scope.version });
      this.findingDetails.set(updated.id, updated); this.fixture.upsertFinding(updated); return updated;
    });
  };

  recordFindingDecision = async (input: FindingDecisionInput): Promise<Finding> => {
    if (!this.config.findingsApi) return this.fixture.recordFindingDecision(input);
    const scope = this.findingScope(input.findingId);
    return this.mutation("decide_finding", async () => {
      const updated = await this.config.findingsApi!.recordDecision(this.config.organizationId, scope.productId, scope.releaseId, input.findingId, { decision: input.decision, rationale: input.rationale, expectedVersion: scope.version });
      this.findingDetails.set(updated.id, updated); this.fixture.upsertFinding(updated); return updated;
    });
  };

  updateRemediation = async (input: RemediationInput): Promise<Finding> => {
    if (!this.config.findingsApi) return this.fixture.updateRemediation(input);
    const scope = this.findingScope(input.findingId);
    const evidence = this.getSnapshot().findings.find((item) => item.id === input.findingId)?.evidenceIds ?? [];
    return this.mutation("update_remediation", async () => {
      const updated = await this.config.findingsApi!.updateRemediation(this.config.organizationId, scope.productId, scope.releaseId, input.findingId, { plan: input.plan, status: remediationStatus(input.status), dueDate: input.targetDate, verificationEvidence: evidence.map((evidenceId) => ({ evidence_id: evidenceId })), expectedVersion: scope.version });
      this.findingDetails.set(updated.id, updated); this.fixture.upsertFinding(updated); return updated;
    });
  };

  approveDocument = async (documentId: EntityId, comment?: string): Promise<DocumentRecord> => this.config.governanceApi ? this.decideDocument(documentId, "approve", comment) : this.fixture.approveDocument(documentId, comment);
  rejectDocument = async (documentId: EntityId, comment: string): Promise<DocumentRecord> => this.config.governanceApi ? this.decideDocument(documentId, "reject", comment) : this.fixture.rejectDocument(documentId, comment);

  createProduct = async (input: CreateProductInput): Promise<Product> => this.mutation("create_product", async () => {
    const created = await this.config.portfolioApi.createProduct(this.config.organizationId, { name: input.name, identifier: input.identifier, manufacturer: input.manufacturer, description: input.description, craClass: input.craClass, classificationStatus: input.classificationStatus, supportStart: new Date().toISOString().slice(0, 10), supportEnd: input.supportUntil, ownerId: input.ownerId });
    this.fixture.upsertProduct(created); return created;
  });

  createRelease = async (input: CreateReleaseInput): Promise<Release> => this.mutation("create_release", async () => {
    const created = await this.config.portfolioApi.createRelease(this.config.organizationId, input.productId, { version: input.version, channel: input.channel, status: "draft", releaseDate: input.releaseDate, supportStart: input.releaseDate, supportEnd: input.supportedUntil });
    this.fixture.upsertRelease(created); return created;
  });

  previewAnalysis = async (draft: AnalysisDraft): Promise<AnalysisPreview> => {
    if (!this.supportsSbom(draft)) return this.fixture.previewAnalysis(draft);
    return this.mutation("preview_analysis", async () => {
      const uploaded = await this.uploadSbom(draft);
      return mapAnalysisPreview(uploaded);
    });
  };

  runAnalysis = async (draft: AnalysisDraft): Promise<AnalysisJob> => {
    if (!this.supportsSbom(draft)) return this.fixture.runAnalysis(draft);
    return this.mutation("run_analysis", async () => {
      const uploaded = this.uploadedAnalysis.get(this.analysisKey(draft)) ?? await this.uploadSbom(draft);
      const scope = this.analysisScope(draft);
      const started = await this.config.releaseOperationsApi!.runAnalysisJob(scope, uploaded.id);
      const mapped = mapAnalysisJob(started, draft);
      this.fixture.upsertAnalysisJob(mapped);
      if (started.status !== "completed" && started.status !== "failed") this.pollAnalysis(scope, draft, started.id);
      return mapped;
    });
  };
  getAnalysisJob = (jobId: EntityId): AnalysisJob | undefined => this.fixture.getAnalysisJob(jobId);
  getApproval = (documentId: EntityId): Approval | undefined => this.fixture.getApproval(documentId);

  private async load(operation: "initialize" | "refresh", options?: { signal?: AbortSignal }): Promise<void> {
    const revision = ++this.refreshRevision;
    this.setStatus({ mode: "production", phase: "loading", lastSyncedAt: this.status.lastSyncedAt });
    try {
      const portfolio = Promise.all([this.config.portfolioApi.getOrganization(this.config.organizationId, options), this.config.portfolioApi.listProducts(this.config.organizationId, options)]).then(async ([organization, products]) => ({ organization, products, releases: (await Promise.all(products.map((product) => this.config.portfolioApi.listReleases(this.config.organizationId, product.id, options)))).flat() }));
      const operations = this.config.operationsApi ? Promise.all([this.config.operationsApi.getHome(this.config.organizationId, { signal: options?.signal }), this.config.operationsApi.listNotifications(this.config.organizationId, { view: "unread_action", signal: options?.signal })]) : undefined;
      const findingList = this.config.findingsApi ? this.config.findingsApi.listFindings(this.config.organizationId, { view: "all" }, options) : undefined;
      const governance = this.config.governanceApi ? Promise.all([this.config.governanceApi.listCompliance(this.config.organizationId, { view: "all" }, options), this.config.governanceApi.listDocuments(this.config.organizationId, {}, options), this.config.governanceApi.getSettings(this.config.organizationId, options), this.config.governanceApi.listTeam(this.config.organizationId, options), this.config.governanceApi.listIntegrations(this.config.organizationId, options)]).then(async ([compliance, documents, settings, members, integrations]) => ({ compliance, settings, members, integrations, documentDetails: await Promise.all(documents.map((document) => this.config.governanceApi!.getDocument(this.config.organizationId, document.id, options))) })) : undefined;
      const [portfolioState, operationsState, findingsState, governanceState] = await Promise.all([portfolio, operations, findingList, governance]);
      if (revision !== this.refreshRevision) return;
      this.fixture.replacePortfolio(portfolioState.organization, portfolioState.products, portfolioState.releases);
      if (operationsState) {
        const [home, notifications] = operationsState;
        this.fixture.replaceOperationalState(
          home.actionQueue.map(mapAction),
          home.recentChanges.map(mapActivity),
          notifications.map(mapNotification),
          { generatedAt: home.generatedAt, monitoring: home.monitoring, counters: home.counters, dataWarnings: home.dataWarnings },
        );
      }
      if (findingsState) {
        findingsState.forEach((finding) => this.findingDetails.set(finding.id, finding));
        this.fixture.replaceFindings(findingsState);
      }
      if (governanceState) {
        this.settingsVersion = governanceState.settings.version;
        governanceState.documentDetails.forEach((detail) => this.documentDetails.set(detail.document.id, detail));
        this.fixture.replaceGovernanceState(
          governanceState.compliance.flatMap((item) => { const mapped = mapCompliance(item); return mapped ? [mapped] : []; }),
          governanceState.documentDetails.map(mapDocument), mapGovernanceSettings(governanceState.settings).settings,
          governanceState.members.flatMap((item) => { const mapped = mapTeamMember(item); return mapped ? [mapped] : []; }),
          governanceState.integrations.map(mapIntegration),
        );
      }
      this.markReady();
    } catch (error) {
      if (revision === this.refreshRevision) this.markFailed(operation, error);
    }
  }

  private findingScope(findingId: string): { productId: string; releaseId: string; version: number } {
    const details = this.findingDetails.get(findingId);
    const finding = this.getSnapshot().findings.find((item) => item.id === findingId);
    if (!finding) throw new Error(`Unknown finding: ${findingId}`);
    return { productId: finding.productId, releaseId: finding.releaseId, version: details?.version ?? 1 };
  }

  private supportsSbom(draft: AnalysisDraft): draft is AnalysisDraft & { releaseId: string; file: Blob } {
    return draft.inputKind === "sbom" && Boolean(draft.releaseId && draft.file && this.config.releaseOperationsApi);
  }

  private analysisScope(draft: AnalysisDraft & { releaseId: string }): ReleaseScope {
    return { organizationId: this.config.organizationId, productId: draft.productId, releaseId: draft.releaseId };
  }

  private analysisKey(draft: AnalysisDraft): string {
    return `${draft.productId}:${draft.releaseId ?? "new"}:${draft.fileName}:${draft.fileSize}`;
  }

  private async uploadSbom(draft: AnalysisDraft & { releaseId: string; file: Blob }): Promise<ReleaseAnalysisJob> {
    const key = this.analysisKey(draft);
    const existing = this.uploadedAnalysis.get(key);
    if (existing) return existing;
    const uploaded = await this.config.releaseOperationsApi!.uploadSbom(this.analysisScope(draft), {
      file: draft.file,
      filename: draft.fileName,
      idempotencyKey: `actis:${this.config.organizationId}:${key}`.slice(0, 240),
    });
    this.uploadedAnalysis.set(key, uploaded);
    return uploaded;
  }

  private pollAnalysis(scope: ReleaseScope, draft: AnalysisDraft, jobId: string): void {
    this.analysisTimers.set(jobId, setTimeout(() => {
      void this.config.releaseOperationsApi!.getAnalysisJob(scope, jobId).then((job) => {
        this.fixture.upsertAnalysisJob(mapAnalysisJob(job, draft));
        if (job.status === "completed" || job.status === "failed") this.analysisTimers.delete(jobId);
        else this.pollAnalysis(scope, draft, jobId);
      }).catch((error) => {
        this.analysisTimers.delete(jobId);
        this.markFailed("run_analysis", error);
      });
    }, 800));
  }

  private async decideDocument(documentId: string, decision: "approve" | "reject", comment?: string): Promise<DocumentRecord> {
    const detail = this.documentDetails.get(documentId);
    if (!detail) throw new Error(`Unknown production document: ${documentId}`);
    const current = detail.document.current;
    return this.mutation(decision === "approve" ? "approve_document" : "reject_document", async () => {
      if (decision === "approve") await this.config.governanceApi!.approveDocument(this.config.organizationId, documentId, current.revision, current.status, comment);
      else await this.config.governanceApi!.rejectDocument(this.config.organizationId, documentId, current.revision, current.status, comment ?? "Revision rejected");
      const updated = await this.config.governanceApi!.getDocument(this.config.organizationId, documentId);
      this.documentDetails.set(documentId, updated);
      const mapped = mapDocument(updated); this.fixture.upsertDocument(mapped); return mapped;
    });
  }

  private async mutation<T>(operation: AdapterOperation, task: () => Promise<T>): Promise<T> {
    this.setStatus({ mode: "production", phase: "loading", lastSyncedAt: this.status.lastSyncedAt });
    try { const result = await task(); this.markReady(); return result; }
    catch (error) { this.markFailed(operation, error); throw error; }
  }

  private markReady() { this.setStatus({ mode: "production", phase: "ready", lastSyncedAt: new Date().toISOString() }); }
  private markFailed(operation: AdapterOperation, error: unknown) { this.setStatus({ mode: "production", phase: "error", lastSyncedAt: this.status.lastSyncedAt, failure: failure(operation, error) }); }
  private setStatus(status: AdapterStatus) { this.status = status; this.statusListeners.forEach((listener) => listener()); }
}

export function createRuntimeDataAdapter(config: RuntimePortfolioConfig): DataAdapter {
  if (!config.apiUrl || !config.organizationId || !config.getBearerToken) return new FixtureAdapter();
  const shared = { baseUrl: config.apiUrl, getBearerToken: config.getBearerToken, fetch: config.fetch };
  return new ProductionAdapter({ organizationId: config.organizationId, portfolioApi: createPortfolioApi(shared), findingsApi: createFindingsApi(shared), operationsApi: createOperationsApi(shared), governanceApi: createGovernanceApi(shared), releaseOperationsApi: createReleaseOperationsApi(shared) });
}
