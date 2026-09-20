import type { AdapterFailure, AdapterOperation, AdapterStatus, DataAdapter, DemoListener, UpdateProductInput, WorkspaceSearchResult } from "./adapter";
import { sanitizeAnalyticsEvent } from "./analytics";
import { createFindingsApi, FindingApiError, type FindingsApi, type ManagedFinding } from "./findingsApi";
import { createGovernanceApi, GovernanceApiError, mapCompliance, mapGovernanceSettings, mapIntegration, mapTeamMember, type ComplianceDto, type DocumentDetailDto, type DocumentFormat, type DocumentRevisionDto, type GovernanceApi, type PrivacySafeAnalyticsEvent } from "./governanceApi";
import { createOperationsApi, OperationsApiError, type OperationsApi, type OperationsHome, type OperationsNotification, type OperationsSearchResult } from "./operationsApi";
import { FixtureAdapter } from "./fixtureAdapter";
import { createDemoState } from "./fixtures";
import { createPortfolioApi, PortfolioApiError, type PortfolioApi } from "./portfolioApi";
import { createReleaseOperationsApi, ReleaseOperationsApiError, type AnalysisEvidenceFile, type MonitoringRunEvent, type ReleaseAnalysisJob, type ReleaseMonitoringStatus, type ReleaseOperationsApi, type ReleaseScope } from "./releaseOperationsApi";
import type { Activity, AnalysisDraft, AnalysisJob, AnalysisPreview, AppSettings, Approval, ComplianceApprovalCommand, ComplianceItem, ComplianceUpdateCommand, CreateProductInput, CreateReleaseInput, DemoState, DocumentAuditEntry, DocumentDownloadFile, DocumentDownloadMetadata, DocumentRecord, DocumentRevision, EntityId, Finding, FindingBatchDecisionInput, FindingDecisionInput, Integration, IntegrationUpdate, Notification, Organization, OrganizationProfileUpdate, Product, RecordDocumentSelfFilingInput, RegisterDocumentRevisionInput, Release, ReleaseMonitoringView, Remediation, RemediationInput, TeamMember, TeamMemberUpdate } from "./types";

export type BearerTokenProvider = () => string | undefined | Promise<string | undefined>;

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
  mode: "demo" | "production";
  apiUrl?: string;
  organizationId?: string;
  getBearerToken?: BearerTokenProvider;
  fetch?: typeof globalThis.fetch;
}

function emptyProductionState(organizationId: string): DemoState {
  const defaults = createDemoState();
  return {
    ...defaults,
    organization: { id: organizationId, name: "Workspace", legalName: "", country: "", registrationNumber: "", defaultTimezone: "UTC" },
    currentUserId: "",
    members: [], integrations: [], products: [], releases: [], findings: [], evidence: [], actions: [],
    complianceItems: [], cases: [], approvals: [], documents: [], activities: [], notifications: [], analysisJobs: [],
    settings: { ...defaults.settings, analytics: { ...defaults.settings.analytics, enabled: false } },
  };
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
  return { id: item.id, type, priority, title: item.title, body: item.detail, targetUrl: item.targetUrl, createdAt: item.createdAt, readAt: item.readAt, acknowledgedAt: item.acknowledgedAt };
}

function mapMonitoring(status: ReleaseMonitoringStatus, events: MonitoringRunEvent[]): ReleaseMonitoringView {
  return {
    productId: status.productId,
    releaseId: status.releaseId,
    enabledSources: status.enabledSources,
    cadenceMinutes: status.cadenceMinutes,
    enabled: status.enabled,
    health: status.health,
    nextCheckAt: status.nextCheckAt,
    lastCheckAt: status.lastCheckAt,
    lastSuccessAt: status.lastSuccessAt,
    consecutiveFailures: status.consecutiveFailures,
    limitations: status.limitations,
    running: status.running,
    recentEvents: events.map((event) => ({ id: event.id, runId: event.runId, eventType: event.eventType, trigger: event.trigger, health: event.health, message: event.message, actorId: event.actorId, occurredAt: event.occurredAt, limitations: event.limitations })),
  };
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

const documentFormats = {
  pdf_a_2b: "PDF/A-2b",
  cyclonedx_json: "CycloneDX JSON",
  csaf_vex: "CSAF VEX",
  zip: "ZIP",
  json: "JSON",
} as const;

function documentFormat(format: DocumentFormat): DocumentRecord["format"] {
  return documentFormats[format];
}

function governanceDocumentFormat(format: DocumentRecord["format"]): DocumentFormat {
  const entry = Object.entries(documentFormats).find(([, label]) => label === format);
  if (!entry) throw new Error(`Unsupported document format: ${format}`);
  return entry[0] as DocumentFormat;
}

function documentCompleteness(provenance: Record<string, unknown>): DocumentRecord["completeness"] {
  const value = provenance.completeness;
  if (value === "complete" || value === "missing_inputs" || value === "limited_coverage") return value;
  return "missing_inputs";
}

function mapDocumentRevision(item: DocumentRevisionDto): DocumentRevision {
  const status: DocumentRevision["status"] = item.status === "pending" ? "approval_required" : item.status;
  return {
    version: item.revision,
    format: documentFormat(item.format),
    status,
    completeness: documentCompleteness(item.provenance),
    contentHash: item.contentHash,
    storageLocator: item.storageLocator,
    sizeBytes: item.sizeBytes,
    createdBy: item.createdBy,
    createdAt: item.createdAt,
  };
}

export function mapDocument(detail: DocumentDetailDto): DocumentRecord {
  const item = detail.document;
  const format = documentFormat(item.current.format);
  const hasCurrentFiling = detail.selfFilings.some((filing) => filing.revision === item.currentRevision);
  const status: DocumentRecord["status"] = hasCurrentFiling ? "self_filed" : ({ draft: "draft", pending: "approval_required", approved: "approved", rejected: "draft", superseded: "superseded" } as const)[item.status];
  return {
    id: item.id, productId: item.productId, releaseId: item.releaseId, caseId: item.caseId,
    name: item.name, type: item.kind, format, version: item.currentRevision, status,
    completeness: documentCompleteness(item.current.provenance), updatedAt: item.updatedAt,
    updatedBy: item.current.createdBy, audit: detail.audit.map(mapDocumentAudit),
    revisions: detail.revisions.map(mapDocumentRevision),
    approvalHistory: detail.approvalHistory.map(mapDocumentAudit),
    selfFilings: detail.selfFilings.map((filing) => ({ id: filing.id, version: filing.revision, externalSubmissionReference: filing.externalSubmissionReference, submittedAt: filing.submittedAt, receiptEvidenceLocator: filing.receiptEvidenceLocator, receiptContentHash: filing.receiptContentHash, recordedBy: filing.recordedBy, recordedAt: filing.recordedAt })),
    contentHash: item.current.contentHash, storageLocator: item.current.storageLocator, sizeBytes: item.current.sizeBytes,
  };
}

function remediationStatus(status: Remediation["status"]) {
  return ({ not_started: "not_planned", planned: "planned", in_progress: "in_progress", verification_pending: "completed", verified: "verified" } as const)[status];
}

function mapAnalysisPreview(job: ReleaseAnalysisJob): AnalysisPreview {
  const warnings = [];
  if (job.preview.skippedComponents) warnings.push(`${job.preview.skippedComponents} components could not be matched to a package identifier.`);
  if (job.inputType === "sbom") warnings.push("Runtime reachability requires Collector or equivalent evidence.");
  if (job.inputType === "raw_artifact") warnings.push("Component counts and coverage will be available after artifact analysis.");
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
  const status: AnalysisJob["status"] = job.status === "unsupported" ? "failed" : job.status === "running"
    ? (job.stage.toLowerCase().includes("valid") ? "validating" : "analyzing")
    : job.status;
  const summary = job.result?.coverageSummary;
  const { checked: sourceCount, expected: expectedSources } = advisoryCoverage(summary);
  const limitations = [
    ...((job.result?.skippedComponents ?? job.preview.skippedComponents) ? [`${job.result?.skippedComponents ?? job.preview.skippedComponents} components could not be matched to a package identifier.`] : []),
    ...(job.inputType === "sbom" ? ["Runtime reachability requires Collector or equivalent evidence."] : []),
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
        identifiedComponents: job.result.matchableComponents ?? job.preview.matchableComponents,
        advisorySourcesChecked: sourceCount,
        advisorySourcesExpected: expectedSources,
        limitations,
      },
      resultUrl: `/products/${job.productId}/releases/${job.releaseId}`,
      evidence: job.result.evidence.map((item) => ({ name: item.name, sha256: item.sha256 })),
    } : undefined,
  };
}

function advisoryCoverage(summary?: Record<string, number>): { checked: number; expected: number } {
  if (!summary) return { checked: 0, expected: 0 };
  if (summary.advisory_sources_checked !== undefined) return {
    checked: summary.advisory_sources_checked,
    expected: summary.advisory_sources_expected ?? summary.advisory_sources_checked,
  };
  const states = ["completed", "failed", "unknown", "unsupported", "unscanned"];
  return { checked: summary.completed ?? 0, expected: states.reduce((total, state) => total + (summary[state] ?? 0), 0) };
}

function projectRelease(release: Release, jobs: ReleaseAnalysisJob[], monitoring?: ReleaseMonitoringStatus): Release {
  const completed = jobs.filter((job) => job.status === "completed" && job.result)
    .sort((a, b) => (b.completedAt ?? "").localeCompare(a.completedAt ?? "") || b.id.localeCompare(a.id))[0];
  if (!completed?.result) return { ...release, monitoringHealth: monitoring?.health ?? release.monitoringHealth, lastMonitoringCheckAt: monitoring?.lastCheckAt ?? release.lastMonitoringCheckAt };
  const summary = completed.result.coverageSummary;
  const { checked, expected } = advisoryCoverage(summary);
  const skipped = completed.result.skippedComponents ?? completed.preview.skippedComponents;
  const limitations = [
    ...(skipped ? [`${skipped} components could not be matched to a package identifier.`] : []),
    ...(completed.inputType === "sbom" ? ["Runtime reachability requires Collector or equivalent evidence."] : []),
    ...(expected > checked ? ["Some advisory sources did not complete."] : []),
  ];
  return {
    ...release,
    sbomStatus: limitations.length ? "partial" : "validated",
    coverage: { components: completed.result.components, identifiedComponents: completed.result.matchableComponents ?? completed.preview.matchableComponents, advisorySourcesChecked: checked, advisorySourcesExpected: expected, limitations },
    artifacts: jobs.filter((job) => job.status === "completed").map((job) => ({ id: job.id, kind: job.inputType === "collector" ? "collector_package" as const : job.inputType, name: job.filename, sha256: job.sha256, receivedAt: job.completedAt ?? job.updatedAt, sizeLabel: `${Math.max(1, Math.round(job.sizeBytes / 1024))} KB` })),
    lastAnalysisAt: completed.completedAt ?? completed.updatedAt,
    monitoringHealth: monitoring?.health ?? release.monitoringHealth,
    lastMonitoringCheckAt: monitoring?.lastCheckAt ?? release.lastMonitoringCheckAt,
  };
}

export class ProductionAdapter implements DataAdapter {
  private readonly fixture: FixtureAdapter;
  private readonly dataListeners = new Set<DemoListener>();
  private readonly statusListeners = new Set<DemoListener>();
  private readonly findingDetails = new Map<string, ManagedFinding>();
  private readonly complianceDetails = new Map<string, ComplianceDto>();
  private readonly documentDetails = new Map<string, DocumentDetailDto>();
  private readonly uploadedAnalysis = new Map<string, ReleaseAnalysisJob>();
  private readonly analysisIdempotencyKeys = new Map<string, string>();
  private readonly analysisFileKeys = new WeakMap<Blob, string>();
  private readonly analysisTimers = new Map<string, ReturnType<typeof setTimeout>>();
  private settingsVersion?: number;
  private analyticsConsent?: boolean;
  private status: AdapterStatus = { mode: "production", phase: "loading" };
  private refreshRevision = 0;
  private portfolioHydrated = false;

  constructor(private readonly config: ProductionAdapterConfig) {
    this.fixture = config.fixtureAdapter ?? new FixtureAdapter(emptyProductionState(config.organizationId), false);
    this.fixture.subscribe(() => this.dataListeners.forEach((listener) => listener()));
  }

  getSnapshot = () => this.fixture.getSnapshot();
  getStatusSnapshot = () => this.status;
  subscribe = (listener: DemoListener) => { this.dataListeners.add(listener); return () => this.dataListeners.delete(listener); };
  subscribeStatus = (listener: DemoListener) => { this.statusListeners.add(listener); return () => this.statusListeners.delete(listener); };
  initialize = async (options?: { signal?: AbortSignal }) => this.load("initialize", options);
  refresh = async (options?: { signal?: AbortSignal }) => this.load("refresh", options);
  reset = () => { this.analysisTimers.forEach(clearTimeout); this.analysisTimers.clear(); this.uploadedAnalysis.clear(); this.analysisIdempotencyKeys.clear(); this.analyticsConsent = undefined; void this.refresh(); };

  search = async (query: string, options?: { signal?: AbortSignal }): Promise<WorkspaceSearchResult[]> => {
    if (!this.config.operationsApi) return this.fixture.search(query);
    if (query.trim().length < 2) return [];
    const result = await this.config.operationsApi.search(this.config.organizationId, query, { limit: 8, signal: options?.signal });
    return result.groups.flatMap((group) => group.results).sort((a, b) => a.rank - b.rank).slice(0, 8).map(mapSearch);
  };

  trackAnalytics = async (event: PrivacySafeAnalyticsEvent): Promise<void> => {
    const safe = sanitizeAnalyticsEvent(event);
    if (!safe || this.analyticsConsent !== true || !this.config.governanceApi) return;
    try {
      await this.config.governanceApi.ingestAnalytics(this.config.organizationId, [safe]);
      if (this.status.analyticsFailure) this.setStatus({ ...this.status, analyticsFailure: undefined });
    } catch (error) {
      const item = failure("ingest_analytics", error);
      this.setStatus({ ...this.status, analyticsFailure: { code: item.code, status: item.status, occurredAt: item.occurredAt } });
    }
  };

  updateSettings = async <K extends keyof AppSettings>(section: K, patch: Partial<AppSettings[K]>): Promise<void> => {
    if (!this.config.governanceApi || this.settingsVersion === undefined) throw new Error("Production settings are not ready.");
    await this.mutation("update_settings", async () => {
      const updated = await this.config.governanceApi!.updateSettings(this.config.organizationId, { expectedVersion: this.settingsVersion!, [section]: patch });
      this.settingsVersion = updated.version;
      const settings = mapGovernanceSettings(updated).settings;
      this.analyticsConsent = settings.analytics.enabled;
      this.fixture.replaceSettings(settings);
    });
  };

  updateOrganization = async (patch: OrganizationProfileUpdate): Promise<Organization> => {
    if (!this.config.governanceApi || this.settingsVersion === undefined) throw new Error("Production organization settings are not ready.");
    return this.mutation("update_organization", async () => {
      const { defaultTimezone, ...profile } = patch;
      const updated = await this.config.governanceApi!.updateSettings(this.config.organizationId, {
        expectedVersion: this.settingsVersion!,
        organizationProfile: { ...profile, timezone: defaultTimezone },
      });
      this.settingsVersion = updated.version;
      const mapped = mapGovernanceSettings(updated);
      this.fixture.replaceOrganization(mapped.organization);
      this.fixture.replaceSettings(mapped.settings);
      return mapped.organization;
    });
  };

  updateTeamMember = async (memberId: EntityId, patch: TeamMemberUpdate): Promise<TeamMember> => {
    if (!this.config.governanceApi) throw new Error("Production team management is not available.");
    const current = this.getSnapshot().members.find((item) => item.id === memberId);
    if (!current?.version) throw new Error(`Team member ${memberId} is not ready for editing.`);
    return this.mutation("update_team_member", async () => {
      const roles = patch.roles?.map((role) => role === "read_only_auditor" ? "viewer" as const : role);
      const updated = await this.config.governanceApi!.updateTeamMember(this.config.organizationId, memberId, { expectedVersion: current.version!, ...patch, roles });
      const mapped = mapTeamMember(updated);
      if (!mapped) throw new Error("Updated team member is not available in this workspace.");
      this.fixture.upsertTeamMember(mapped);
      return mapped;
    });
  };

  updateIntegration = async (integrationId: EntityId, patch: IntegrationUpdate): Promise<Integration> => {
    if (!this.config.governanceApi) throw new Error("Production integration management is not available.");
    const current = this.getSnapshot().integrations.find((item) => item.id === integrationId);
    if (!current?.version) throw new Error(`Integration ${integrationId} is not ready for editing.`);
    return this.mutation("update_integration", async () => {
      const updated = await this.config.governanceApi!.updateIntegration(this.config.organizationId, integrationId, { expectedVersion: current.version!, ...patch });
      const mapped = mapIntegration(updated);
      this.fixture.upsertIntegration(mapped);
      return mapped;
    });
  };

  markNotificationRead = async (notificationId: EntityId): Promise<void> => {
    if (!this.config.operationsApi) return this.fixture.markNotificationRead(notificationId);
    const item = await this.config.operationsApi.markRead(this.config.organizationId, notificationId);
    this.fixture.markNotificationRead(item.id);
  };

  acknowledgeNotification = async (notificationId: EntityId): Promise<void> => {
    if (!this.config.operationsApi) return this.fixture.acknowledgeNotification(notificationId);
    const item = await this.config.operationsApi.acknowledge(this.config.organizationId, notificationId);
    this.fixture.acknowledgeNotification(item.id);
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

  recordFindingBatchDecision = async (input: FindingBatchDecisionInput): Promise<Finding[]> => {
    if (!this.config.findingsApi) return this.fixture.recordFindingBatchDecision(input);
    const groups = new Map<string, { productId: string; releaseId: string; items: Array<{ findingId: string; expectedVersion: number }> }>();
    input.findingIds.forEach((findingId) => {
      const scope = this.findingScope(findingId);
      const key = `${scope.productId}\u0000${scope.releaseId}`;
      const group = groups.get(key) ?? { productId: scope.productId, releaseId: scope.releaseId, items: [] };
      group.items.push({ findingId, expectedVersion: scope.version });
      groups.set(key, group);
    });
    if (!input.recommendationsOnly && groups.size > 1) throw new Error("Select findings from one release for an atomic batch decision.");
    return this.mutation("batch_decide_findings", async () => {
      const updated = (await Promise.all([...groups.values()].map((group) => input.recommendationsOnly ? this.config.findingsApi!.approveRecommendations(
        this.config.organizationId,
        group.productId,
        group.releaseId,
        { items: group.items, rationale: input.rationale },
      ) : this.config.findingsApi!.decideBatch(
        this.config.organizationId,
        group.productId,
        group.releaseId,
        { items: group.items, rationale: input.rationale, decision: input.decision ?? "not_affected" },
      )))).flat();
      updated.forEach((finding) => {
        this.findingDetails.delete(finding.id);
        this.fixture.upsertFinding(finding);
      });
      return updated;
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

  loadComplianceDetail = async (itemId: EntityId, options?: { signal?: AbortSignal }): Promise<ComplianceItem | undefined> => {
    if (!this.config.governanceApi) return this.fixture.loadComplianceDetail(itemId);
    return this.mutation("load_compliance", async () => {
      const [item, audit] = await Promise.all([
        this.config.governanceApi!.getCompliance(this.config.organizationId, itemId, options),
        this.config.governanceApi!.listComplianceAudit(this.config.organizationId, itemId, options),
      ]);
      this.complianceDetails.set(item.id, item);
      const mapped = mapCompliance(item, audit);
      this.fixture.upsertCompliance(mapped);
      return mapped;
    });
  };

  updateCompliance = async (input: ComplianceUpdateCommand): Promise<ComplianceItem> => {
    if (!this.config.governanceApi) return this.fixture.updateCompliance(input);
    const current = this.requireComplianceDetail(input.itemId);
    return this.mutation("update_compliance", async () => {
      const updated = await this.config.governanceApi!.updateCompliance(this.config.organizationId, input.itemId, {
        expectedVersion: current.version,
        title: input.title,
        description: input.description,
        priority: input.priority,
        status: input.status,
        dueAt: input.dueAt,
        clearDueAt: input.clearDueAt,
        ownerId: input.ownerId,
        clearOwner: input.clearOwner,
        selfFilingRecordId: input.selfFilingRecordId,
        selfFilingRecordUrl: input.selfFilingRecordUrl,
      });
      return this.storeCompliance(updated);
    });
  };

  approveCompliance = async (input: ComplianceApprovalCommand): Promise<ComplianceItem> => {
    if (!this.config.governanceApi) return this.fixture.approveCompliance(input);
    const current = this.requireComplianceDetail(input.itemId);
    return this.mutation("approve_compliance", async () => {
      const updated = await this.config.governanceApi!.approveCompliance(this.config.organizationId, input.itemId, {
        expectedVersion: current.version,
        selfFilingRecordId: input.selfFilingRecordId,
        selfFilingRecordUrl: input.selfFilingRecordUrl,
      });
      return this.storeCompliance(updated);
    });
  };

  approveDocument = async (documentId: EntityId, comment?: string): Promise<DocumentRecord> => this.config.governanceApi ? this.decideDocument(documentId, "approve", comment) : this.fixture.approveDocument(documentId, comment);
  rejectDocument = async (documentId: EntityId, comment: string): Promise<DocumentRecord> => this.config.governanceApi ? this.decideDocument(documentId, "reject", comment) : this.fixture.rejectDocument(documentId, comment);

  loadDocumentDetail = async (documentId: EntityId, options?: { signal?: AbortSignal }): Promise<DocumentRecord | undefined> => {
    if (!this.config.governanceApi) return this.fixture.loadDocumentDetail(documentId);
    return this.mutation("load_document", async () => {
      const detail = await this.config.governanceApi!.getDocument(this.config.organizationId, documentId, options);
      return this.storeDocumentDetail(detail);
    });
  };

  getDocumentDownload = async (documentId: EntityId, version?: number): Promise<DocumentDownloadMetadata> => {
    if (!this.config.governanceApi) return this.fixture.getDocumentDownload(documentId, version);
    const detail = this.requireDocumentDetail(documentId);
    return this.mutation("download_document", async () => {
      const metadata = await this.config.governanceApi!.getDownloadMetadata(this.config.organizationId, documentId, version ?? detail.document.currentRevision);
      return { documentId: metadata.documentId, version: metadata.revision, filename: metadata.filename, format: documentFormat(metadata.format), contentHash: metadata.contentHash, sizeBytes: metadata.sizeBytes, storageLocator: metadata.storageLocator, contentType: metadata.contentType, downloadType: metadata.downloadType };
    });
  };

  downloadDocument = async (documentId: EntityId, version?: number): Promise<DocumentDownloadFile> => {
    if (!this.config.governanceApi) return this.fixture.downloadDocument(documentId, version);
    const detail = this.requireDocumentDetail(documentId);
    return this.mutation("download_document_content", async () => {
      return this.config.governanceApi!.downloadDocumentContent(
        this.config.organizationId,
        documentId,
        version ?? detail.document.currentRevision,
      );
    });
  };

  requestDocumentApproval = async (documentId: EntityId, comment?: string): Promise<DocumentRecord> => {
    if (!this.config.governanceApi) return this.fixture.requestDocumentApproval(documentId, comment);
    const detail = this.requireDocumentDetail(documentId);
    return this.mutation("request_document_approval", async () => {
      const current = detail.document.current;
      await this.config.governanceApi!.requestDocumentApproval(this.config.organizationId, documentId, current.revision, current.status, comment);
      return this.reloadDocument(documentId);
    });
  };

  addDocumentRevision = async (input: RegisterDocumentRevisionInput): Promise<DocumentRecord> => {
    if (!this.config.governanceApi) return this.fixture.addDocumentRevision(input);
    const detail = this.requireDocumentDetail(input.documentId);
    return this.mutation("add_document_revision", async () => {
      await this.config.governanceApi!.addDocumentRevision(this.config.organizationId, input.documentId, {
        expectedCurrentRevision: detail.document.currentRevision,
        format: governanceDocumentFormat(input.format),
        contentHash: input.contentHash,
        storageLocator: input.storageLocator,
        sizeBytes: input.sizeBytes,
        provenance: { completeness: input.completeness },
      });
      return this.reloadDocument(input.documentId);
    });
  };

  recordDocumentSelfFiling = async (input: RecordDocumentSelfFilingInput): Promise<DocumentRecord> => {
    if (!this.config.governanceApi) return this.fixture.recordDocumentSelfFiling(input);
    const detail = this.requireDocumentDetail(input.documentId);
    return this.mutation("self_file_document", async () => {
      await this.config.governanceApi!.recordSelfFiling(this.config.organizationId, input.documentId, detail.document.currentRevision, {
        externalSubmissionReference: input.externalSubmissionReference,
        submittedAt: input.submittedAt,
        receiptEvidenceLocator: input.receiptEvidenceLocator,
        receiptContentHash: input.receiptContentHash,
      });
      return this.reloadDocument(input.documentId);
    });
  };

  createProduct = async (input: CreateProductInput): Promise<Product> => this.mutation("create_product", async () => {
    const created = await this.config.portfolioApi.createProduct(this.config.organizationId, { name: input.name, identifier: input.identifier, manufacturer: input.manufacturer, description: input.description, craClass: input.craClass, classificationStatus: input.classificationStatus, classificationAssessment: input.classificationAssessment, supportStart: new Date().toISOString().slice(0, 10), supportEnd: input.supportUntil, ownerId: input.ownerId });
    this.fixture.upsertProduct(created); return created;
  });

  updateProduct = async (input: UpdateProductInput): Promise<Product> => this.mutation("update_product", async () => {
    const updated = await this.config.portfolioApi.updateProduct(this.config.organizationId, input.productId, {
      name: input.name,
      identifier: input.identifier,
      manufacturer: input.manufacturer,
      description: input.description,
      craClass: input.craClass,
      classificationStatus: input.classificationStatus,
      classificationAssessment: input.classificationAssessment,
      ownerId: input.ownerId,
      supportEnd: input.supportUntil,
    });
    this.fixture.upsertProduct(updated);
    return updated;
  });

  createRelease = async (input: CreateReleaseInput): Promise<Release> => this.mutation("create_release", async () => {
    const created = await this.config.portfolioApi.createRelease(this.config.organizationId, input.productId, { version: input.version, channel: input.channel, status: "draft", releaseDate: input.releaseDate, supportStart: input.releaseDate, supportEnd: input.supportedUntil });
    this.fixture.upsertRelease(created); return created;
  });

  selectActiveRelease = async (productId: EntityId, releaseId: EntityId): Promise<Product> => this.mutation("select_active_release", async () => {
    const product = await this.config.portfolioApi.updateProduct(this.config.organizationId, productId, { activeReleaseId: releaseId });
    this.fixture.upsertProduct(product);
    await this.refresh();
    if (this.status.phase === "error") throw new Error(this.status.failure?.message ?? "Could not refresh the selected release.");
    return product;
  });

  downloadReleaseReport = async (productId: EntityId, releaseId: EntityId, jobId: EntityId): Promise<AnalysisEvidenceFile> => {
    if (!this.config.releaseOperationsApi) throw new Error("Production evidence export is unavailable.");
    return this.config.releaseOperationsApi.downloadEvidenceBundle({ organizationId: this.config.organizationId, productId, releaseId }, jobId);
  };

  downloadAnalysisEvidence = async (productId: EntityId, releaseId: EntityId, jobId: EntityId, digest: string): Promise<AnalysisEvidenceFile> => {
    if (!this.config.releaseOperationsApi) throw new Error("Production evidence download is unavailable.");
    return this.config.releaseOperationsApi.downloadEvidence({ organizationId: this.config.organizationId, productId, releaseId }, jobId, digest);
  };

  generateFindingsReport = async (productId: EntityId, releaseId: EntityId): Promise<AnalysisEvidenceFile> => {
    if (!this.config.releaseOperationsApi) throw new Error("Production report generation is unavailable.");
    return this.config.releaseOperationsApi.generateFindingsReport({
      organizationId: this.config.organizationId, productId, releaseId,
    });
  };

  generateSecurityPdf = async (productId: EntityId, releaseId: EntityId): Promise<AnalysisEvidenceFile> => {
    if (!this.config.releaseOperationsApi) throw new Error("Production PDF generation is unavailable.");
    return this.config.releaseOperationsApi.generateSecurityPdf({
      organizationId: this.config.organizationId, productId, releaseId,
    });
  };

  downloadReleaseEvidenceFile = async (productId: EntityId, releaseId: EntityId, jobId: EntityId, digest: string): Promise<AnalysisEvidenceFile> => {
    return this.downloadAnalysisEvidence(productId, releaseId, jobId, digest);
  };

  previewAnalysis = async (draft: AnalysisDraft): Promise<AnalysisPreview> => {
    if (!this.supportsProductionAnalysis(draft)) throw new Error("A release, evidence file, and production analysis service are required.");
    return this.mutation("preview_analysis", async () => {
      const uploaded = await this.uploadAnalysis(draft);
      return mapAnalysisPreview(uploaded);
    });
  };

  runAnalysis = async (draft: AnalysisDraft): Promise<AnalysisJob> => {
    if (!this.supportsProductionAnalysis(draft)) throw new Error("A release, evidence file, and production analysis service are required.");
    return this.mutation("run_analysis", async () => {
      const uploaded = this.uploadedAnalysis.get(this.analysisKey(draft)) ?? await this.uploadAnalysis(draft);
      const scope = this.analysisScope(draft);
      const started = await this.config.releaseOperationsApi!.runAnalysisJob(scope, uploaded.id);
      const mapped = mapAnalysisJob(started, draft);
      this.fixture.upsertAnalysisJob(mapped);
      if (!this.isTerminalAnalysis(started)) this.pollAnalysis(scope, draft, started.id);
      return mapped;
    });
  };
  getAnalysisJob = (jobId: EntityId): AnalysisJob | undefined => this.fixture.getAnalysisJob(jobId);
  getApproval = (documentId: EntityId): Approval | undefined => this.fixture.getApproval(documentId);

  loadReleaseMonitoring = async (productId: EntityId, releaseId: EntityId, options?: { signal?: AbortSignal }): Promise<ReleaseMonitoringView> => {
    if (!this.config.releaseOperationsApi) throw new Error("Production monitoring service is unavailable.");
    const scope = { organizationId: this.config.organizationId, productId, releaseId };
    const [status, events] = await Promise.all([
      this.config.releaseOperationsApi.getMonitoring(scope, options),
      this.config.releaseOperationsApi.listMonitoringEvents(scope, options),
    ]);
    return mapMonitoring(status, events);
  };

  runReleaseMonitoring = async (productId: EntityId, releaseId: EntityId): Promise<ReleaseMonitoringView> => {
    if (!this.config.releaseOperationsApi) throw new Error("Production monitoring service is unavailable.");
    return this.mutation("run_monitoring", async () => {
      const scope = { organizationId: this.config.organizationId, productId, releaseId };
      const status = await this.config.releaseOperationsApi!.runMonitoring(scope);
      const events = await this.config.releaseOperationsApi!.listMonitoringEvents(scope);
      return mapMonitoring(status, events);
    });
  };

  private async load(operation: "initialize" | "refresh", options?: { signal?: AbortSignal }): Promise<void> {
    const revision = ++this.refreshRevision;
    this.setStatus({ mode: "production", phase: "loading", lastSyncedAt: this.status.lastSyncedAt });
    try {
      const portfolio = Promise.all([this.config.portfolioApi.getOrganization(this.config.organizationId, options), this.config.portfolioApi.listProducts(this.config.organizationId, options)]).then(async ([organization, products]) => {
        const releases = (await Promise.all(products.map((product) => this.config.portfolioApi.listReleases(this.config.organizationId, product.id, options)))).flat();
        return { organization, products, releases };
      });
      const releaseJobs = this.config.releaseOperationsApi
        ? portfolio.then(({ releases }) => Promise.all(releases.map(async (release) => {
              const scope = { organizationId: this.config.organizationId, productId: release.productId, releaseId: release.id };
              const jobs = await this.config.releaseOperationsApi!.listAnalysisJobs(scope, options);
              let monitoring: ReleaseMonitoringStatus | undefined;
              if (jobs.some((job) => job.status === "completed")) {
                try { monitoring = await this.config.releaseOperationsApi!.getMonitoring(scope, options); }
                catch (error) { if (!(error instanceof ReleaseOperationsApiError && error.code === "not_found")) throw error; }
              }
              return { release, jobs, monitoring };
            })))
        : undefined;
      const operations = this.config.operationsApi ? Promise.all([this.config.operationsApi.getHome(this.config.organizationId, { signal: options?.signal }), this.config.operationsApi.listNotifications(this.config.organizationId, { view: "unread_action", signal: options?.signal })]) : undefined;
      const findingList = this.config.findingsApi ? this.config.findingsApi.listFindings(this.config.organizationId, { view: "all" }, options) : undefined;
      const governance = this.config.governanceApi ? Promise.all([this.config.governanceApi.listCompliance(this.config.organizationId, { view: "all" }, options), this.config.governanceApi.listDocuments(this.config.organizationId, {}, options), this.config.governanceApi.getSettings(this.config.organizationId, options), this.config.governanceApi.listTeam(this.config.organizationId, options), this.config.governanceApi.listIntegrations(this.config.organizationId, options)]).then(async ([compliance, documents, settings, members, integrations]) => ({ compliance, settings, members, integrations, documentDetails: await Promise.all(documents.map((document) => this.config.governanceApi!.getDocument(this.config.organizationId, document.id, options))) })) : undefined;
      const ancillary = Promise.allSettled([releaseJobs, operations, findingList, governance]);
      const portfolioState = await portfolio;
      if (revision !== this.refreshRevision) return;
      const receivedProductIds = new Set(portfolioState.products.map((item) => item.id));
      const missingProducts = this.portfolioHydrated
        ? this.getSnapshot().products.filter((item) => !receivedProductIds.has(item.id))
        : [];
      if (missingProducts.length) {
        throw new PortfolioApiError(`The product service omitted ${missingProducts.length} existing product${missingProducts.length === 1 ? "" : "s"}. Existing data remains visible; check the deployment's API and organization settings before retrying.`, "invalid_response");
      }
      this.fixture.replacePortfolio(portfolioState.organization, portfolioState.products, portfolioState.releases);
      this.portfolioHydrated = true;
      this.markReady();
      const [releaseJobsResult, operationsResult, findingsResult, governanceResult] = await ancillary;
      if (revision !== this.refreshRevision) return;
      if (releaseJobsResult.status === "fulfilled" && releaseJobsResult.value) {
        const scopedJobs = releaseJobsResult.value;
        const currentReleases = new Map(this.getSnapshot().releases.map((release) => [release.id, release]));
        const projectedReleases = scopedJobs.map(({ release, jobs, monitoring }) => projectRelease(currentReleases.get(release.id) ?? release, jobs, monitoring));
        projectedReleases.forEach((release) => this.fixture.upsertRelease(release));
        const analysisJobs = scopedJobs.flatMap(({ jobs }) => jobs);
        this.fixture.replaceAnalysisJobs(analysisJobs.map((job) => mapAnalysisJob(job, this.draftForJob(job, projectedReleases))));
        analysisJobs.filter((job) => !this.isTerminalAnalysis(job) && job.status === "running").forEach((job) => {
          if (!this.analysisTimers.has(job.id)) this.pollAnalysis(this.analysisScope(this.draftForJob(job, projectedReleases) as AnalysisDraft & { releaseId: string }), this.draftForJob(job, projectedReleases), job.id);
        });
      }
      if (operationsResult.status === "fulfilled" && operationsResult.value) {
        const operationsState = operationsResult.value;
        const [home, notifications] = operationsState;
        this.fixture.replaceOperationalState(
          home.actionQueue.map(mapAction),
          home.recentChanges.map(mapActivity),
          notifications.map(mapNotification),
          { generatedAt: home.generatedAt, monitoring: home.monitoring, counters: home.counters, dataWarnings: home.dataWarnings },
        );
      }
      if (findingsResult.status === "fulfilled" && findingsResult.value) {
        const findingsState = findingsResult.value;
        findingsState.forEach((finding) => this.findingDetails.set(finding.id, finding));
        this.fixture.replaceFindings(findingsState);
      }
      if (governanceResult.status === "fulfilled" && governanceResult.value) {
        const governanceState = governanceResult.value;
        this.settingsVersion = governanceState.settings.version;
        this.analyticsConsent = governanceState.settings.analytics.enabled;
        governanceState.documentDetails.forEach((detail) => this.documentDetails.set(detail.document.id, detail));
        governanceState.compliance.forEach((item) => this.complianceDetails.set(item.id, item));
        this.fixture.replaceGovernanceState(
          governanceState.compliance.map((item) => mapCompliance(item)),
          governanceState.documentDetails.map(mapDocument), mapGovernanceSettings(governanceState.settings).settings,
          governanceState.members.flatMap((item) => { const mapped = mapTeamMember(item); return mapped ? [mapped] : []; }),
          governanceState.integrations.map(mapIntegration),
        );
        this.fixture.replaceOrganization(mapGovernanceSettings(governanceState.settings).organization);
      }
      const rejected = [releaseJobsResult, operationsResult, findingsResult, governanceResult].find((result) => result.status === "rejected");
      if (rejected?.status === "rejected") this.markFailed(operation, rejected.reason);
      else this.markReady();
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

  private supportsProductionAnalysis(draft: AnalysisDraft): draft is AnalysisDraft & { releaseId: string; file: Blob } {
    return Boolean(draft.releaseId && draft.file && this.config.releaseOperationsApi);
  }

  private analysisScope(draft: AnalysisDraft & { releaseId: string }): ReleaseScope {
    return { organizationId: this.config.organizationId, productId: draft.productId, releaseId: draft.releaseId };
  }

  private analysisKey(draft: AnalysisDraft): string {
    return [
      draft.productId,
      draft.releaseId ?? "new",
      draft.inputKind,
      this.analysisFileKey(draft.file),
      this.analysisFileKey(draft.runtimeTelemetry),
      this.analysisFileKey(draft.exposureContext),
    ].join(":");
  }

  private analysisFileKey(file?: Blob): string {
    if (!file) return "none";
    const key = this.analysisFileKeys.get(file) ?? crypto.randomUUID();
    this.analysisFileKeys.set(file, key);
    return key;
  }

  private async uploadAnalysis(draft: AnalysisDraft & { releaseId: string; file: Blob }): Promise<ReleaseAnalysisJob> {
    const key = this.analysisKey(draft);
    const existing = this.uploadedAnalysis.get(key);
    if (existing) return existing;
    const idempotencyKey = this.analysisIdempotencyKeys.get(key) ?? `actis:${crypto.randomUUID()}`;
    this.analysisIdempotencyKeys.set(key, idempotencyKey);
    const input = {
      file: draft.file,
      filename: draft.fileName,
      idempotencyKey,
      changedDigestConfirmed: draft.changedDigestConfirmed,
      runtimeTelemetry: draft.runtimeTelemetry,
      runtimeTelemetryFilename: draft.runtimeTelemetryName,
      exposureContext: draft.exposureContext,
      exposureContextFilename: draft.exposureContextName,
    };
    const uploaded = draft.inputKind === "sbom"
      ? await this.config.releaseOperationsApi!.uploadSbom(this.analysisScope(draft), input)
      : await this.config.releaseOperationsApi!.uploadAnalysisInput(this.analysisScope(draft), {
          ...input,
          inputType: draft.inputKind === "collector_package" ? "collector" : "raw_artifact",
          rawArtifactConsent: draft.rawArtifactConsent,
        });
    this.uploadedAnalysis.set(key, uploaded);
    return uploaded;
  }

  private draftForJob(job: ReleaseAnalysisJob, releases = this.getSnapshot().releases): AnalysisDraft {
    const release = releases.find((item) => item.id === job.releaseId && item.productId === job.productId);
    return {
      productId: job.productId,
      releaseId: job.releaseId,
      version: release?.version ?? "Unknown",
      channel: release?.channel ?? "stable",
      inputKind: job.inputType === "collector" ? "collector_package" : job.inputType,
      fileName: job.filename,
      fileSize: job.sizeBytes,
      rawArtifactConsent: Boolean(job.consentedAt),
    };
  }

  private isTerminalAnalysis(job: ReleaseAnalysisJob): boolean {
    return job.status === "completed" || job.status === "failed" || job.status === "unsupported";
  }

  private pollAnalysis(scope: ReleaseScope, draft: AnalysisDraft, jobId: string, failures = 0): void {
    const delay = failures === 0 ? 800 : Math.min(30_000, 1_000 * 2 ** Math.min(failures - 1, 5));
    this.analysisTimers.set(jobId, setTimeout(() => {
      void this.config.releaseOperationsApi!.getAnalysisJob(scope, jobId).then((job) => {
        this.fixture.upsertAnalysisJob(mapAnalysisJob(job, draft));
        if (this.status.failure?.operation === "run_analysis") this.markReady();
        if (this.isTerminalAnalysis(job)) { this.analysisTimers.delete(jobId); setTimeout(() => { void this.refresh(); }, 250); }
        else this.pollAnalysis(scope, draft, jobId);
      }).catch((error) => {
        this.analysisTimers.delete(jobId);
        this.markFailed("run_analysis", error);
        this.pollAnalysis(scope, draft, jobId, failures + 1);
      });
    }, delay));
  }

  private async decideDocument(documentId: string, decision: "approve" | "reject", comment?: string): Promise<DocumentRecord> {
    const detail = this.documentDetails.get(documentId);
    if (!detail) throw new Error(`Unknown production document: ${documentId}`);
    const current = detail.document.current;
    return this.mutation(decision === "approve" ? "approve_document" : "reject_document", async () => {
      if (decision === "approve") await this.config.governanceApi!.approveDocument(this.config.organizationId, documentId, current.revision, current.status, comment);
      else await this.config.governanceApi!.rejectDocument(this.config.organizationId, documentId, current.revision, current.status, comment ?? "Revision rejected");
      return this.reloadDocument(documentId);
    });
  }

  private requireDocumentDetail(documentId: string): DocumentDetailDto {
    const detail = this.documentDetails.get(documentId);
    if (!detail) throw new Error(`Unknown production document: ${documentId}`);
    return detail;
  }

  private requireComplianceDetail(itemId: string): ComplianceDto {
    const detail = this.complianceDetails.get(itemId);
    if (!detail) throw new Error(`Unknown production compliance item: ${itemId}`);
    return detail;
  }

  private async storeCompliance(item: ComplianceDto): Promise<ComplianceItem> {
    this.complianceDetails.set(item.id, item);
    const audit = await this.config.governanceApi!.listComplianceAudit(this.config.organizationId, item.id);
    const mapped = mapCompliance(item, audit);
    this.fixture.upsertCompliance(mapped);
    return mapped;
  }

  private storeDocumentDetail(detail: DocumentDetailDto): DocumentRecord {
    this.documentDetails.set(detail.document.id, detail);
    const mapped = mapDocument(detail);
    this.fixture.upsertDocument(mapped);
    return mapped;
  }

  private async reloadDocument(documentId: string): Promise<DocumentRecord> {
    const updated = await this.config.governanceApi!.getDocument(this.config.organizationId, documentId);
    return this.storeDocumentDetail(updated);
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
  if (config.mode === "demo") return new FixtureAdapter();
  if (!config.apiUrl || !config.organizationId || !config.getBearerToken) {
    throw new Error("Production data access requires API URL, organization, and an authenticated token provider.");
  }
  const shared = { baseUrl: config.apiUrl, getBearerToken: config.getBearerToken, fetch: config.fetch };
  return new ProductionAdapter({ organizationId: config.organizationId, portfolioApi: createPortfolioApi(shared), findingsApi: createFindingsApi(shared), operationsApi: createOperationsApi(shared), governanceApi: createGovernanceApi(shared), releaseOperationsApi: createReleaseOperationsApi(shared) });
}
