import type { AdapterStatus, DataAdapter, DemoListener, WorkspaceSearchResult } from "./adapter";
import { sanitizeAnalyticsEvent } from "./analytics";
import { createDemoState, DEMO_IDS } from "./fixtures";
import { analyzeSbomWithOsv, type SbomAnalysis, type SbomAnalyzer } from "./osvSbom";
import type { PrivacySafeAnalyticsEvent } from "./governanceApi";
import type { AnalysisEvidenceFile } from "./releaseOperationsApi";
import type {
  RegisterDocumentRevisionInput,
  AnalysisDraft,
  AnalysisJob,
  AnalysisPreview,
  ComplianceApprovalCommand,
  AppSettings,
  ComplianceItem,
  Approval,
  CreateProductInput,
  CreateReleaseInput,
  DemoState,
  DocumentRecord,
  DocumentDownloadMetadata,
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
  TeamMember,
  TeamMemberUpdate,
  ComplianceUpdateCommand,
} from "./types";

const STORAGE_KEY = "actis.demo-state.v1";

function now(): string {
  return new Date().toISOString();
}

function slugify(value: string): string {
  return value.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
}

function digestFor(draft: AnalysisDraft): string {
  let hash = 2166136261;
  const input = `${draft.productId}:${draft.version}:${draft.fileName}:${draft.fileSize}`;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `${(hash >>> 0).toString(16).padStart(8, "0")}8d44c7a0…${draft.fileSize.toString(16).padStart(4, "0")}`;
}

function withAnalyticsSettings(state: DemoState): DemoState {
  const legacy = state as DemoState & { settings: AppSettings & { analytics?: AppSettings["analytics"] } };
  return {
    ...state,
    settings: {
      ...state.settings,
      analytics: legacy.settings.analytics ?? { enabled: true, retentionDays: 90 },
    },
  };
}

function loadInitialState(): DemoState {
  if (typeof window === "undefined") return createDemoState();
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return createDemoState();
    const parsed = JSON.parse(raw) as DemoState;
    return parsed.schemaVersion === 2 ? withAnalyticsSettings(parsed) : createDemoState();
  } catch {
    return createDemoState();
  }
}

export class FixtureAdapter implements DataAdapter {
  private state: DemoState;
  private readonly listeners = new Set<DemoListener>();
  private readonly timers = new Set<ReturnType<typeof setTimeout>>();
  private readonly analyticsEvents: PrivacySafeAnalyticsEvent[] = [];
  private readonly status: AdapterStatus = { mode: "fixture", phase: "ready" };

  constructor(initialState?: DemoState, private readonly persist = true, private readonly sbomAnalyzer: SbomAnalyzer = analyzeSbomWithOsv) {
    this.state = withAnalyticsSettings(initialState ? structuredClone(initialState) : loadInitialState());
  }

  getStatusSnapshot = (): AdapterStatus => this.status;

  subscribeStatus = (_listener: DemoListener): (() => void) => () => undefined;

  initialize = async (): Promise<void> => undefined;

  refresh = async (): Promise<void> => undefined;

  getSnapshot = (): DemoState => this.state;

  subscribe = (listener: DemoListener): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  search = async (query: string): Promise<WorkspaceSearchResult[]> => {
    const term = query.trim().toLowerCase();
    if (term.length < 2) return [];
    const matches = (value: string) => value.toLowerCase().includes(term);
    return [
      ...this.state.products.filter((item) => matches(`${item.name} ${item.identifier} ${item.manufacturer}`)).map((item) => ({
        id: item.id, type: "Product" as const, title: item.name,
        detail: `${item.identifier} · ${item.readiness.replaceAll("_", " ")}`, to: `/products/${item.id}`,
      })),
      ...this.state.releases.filter((item) => {
        const product = this.state.products.find((candidate) => candidate.id === item.productId);
        return matches(`${product?.name ?? ""} ${item.version} ${item.channel}`);
      }).map((item) => ({
        id: item.id, type: "Release" as const,
        title: `${this.state.products.find((candidate) => candidate.id === item.productId)?.name ?? "Product"} v${item.version}`,
        detail: `${item.channel} · monitoring ${item.monitoringHealth}`,
        to: `/products/${item.productId}/releases/${item.id}`,
      })),
      ...this.state.findings.filter((item) => matches(`${item.reference} ${item.title} ${item.component}`)).map((item) => ({
        id: item.id, type: "Finding" as const, title: item.reference,
        detail: `${item.title} · ${item.priority}`, to: `/findings/${item.id}`,
      })),
      ...this.state.complianceItems.filter((item) => matches(`${item.title} ${item.reason} ${item.requirement}`)).map((item) => ({
        id: item.id, type: "Compliance" as const, title: item.title,
        detail: `${item.requirement} · ${item.status.replaceAll("_", " ")}`, to: item.targetUrl,
      })),
      ...this.state.documents.filter((item) => matches(`${item.name} ${item.type} ${item.format}`)).map((item) => ({
        id: item.id, type: "Document" as const, title: item.name,
        detail: `${item.format} · ${item.status.replaceAll("_", " ")}`, to: `/documents/${item.id}`,
      })),
    ].slice(0, 8);
  };

  reset = (): void => {
    this.timers.forEach(clearTimeout);
    this.timers.clear();
    this.analyticsEvents.length = 0;
    this.commit(createDemoState());
  };

  trackAnalytics = (event: PrivacySafeAnalyticsEvent): void => {
    if (!this.state.settings.analytics.enabled) return;
    const safe = sanitizeAnalyticsEvent(event);
    if (safe) this.analyticsEvents.push(structuredClone(safe));
  };

  getTrackedAnalytics = (): readonly PrivacySafeAnalyticsEvent[] => structuredClone(this.analyticsEvents);

  updateSettings = <K extends keyof AppSettings>(section: K, patch: Partial<AppSettings[K]>): void => {
    this.mutate((state) => {
      state.settings = {
        ...state.settings,
        [section]: { ...state.settings[section], ...patch },
      } as AppSettings;
    });
  };

  updateOrganization = (patch: OrganizationProfileUpdate): Organization => {
    let updated!: Organization;
    this.mutate((state) => {
      state.organization = { ...state.organization, ...patch };
      updated = structuredClone(state.organization);
    });
    return updated;
  };

  updateTeamMember = (memberId: EntityId, patch: TeamMemberUpdate): TeamMember => {
    let updated!: TeamMember;
    this.mutate((state) => {
      const member = state.members.find((item) => item.id === memberId);
      if (!member) throw new Error(`Unknown team member: ${memberId}`);
      if (patch.roles && !patch.roles.length) throw new Error("At least one role is required.");
      Object.assign(member, patch, { version: (member.version ?? 1) + 1 });
      updated = structuredClone(member);
    });
    return updated;
  };

  updateIntegration = (integrationId: EntityId, patch: IntegrationUpdate): Integration => {
    let updated!: Integration;
    this.mutate((state) => {
      const integration = state.integrations.find((item) => item.id === integrationId);
      if (!integration) throw new Error(`Unknown integration: ${integrationId}`);
      const { secretReference, ...values } = patch;
      Object.assign(integration, values, { version: (integration.version ?? 1) + 1 });
      if (secretReference === null) delete integration.secretReference;
      else if (secretReference !== undefined) integration.secretReference = secretReference;
      updated = structuredClone(integration);
    });
    return updated;
  };

  markNotificationRead = (notificationId: EntityId): void => {
    this.mutate((state) => {
      const notification = state.notifications.find((item) => item.id === notificationId);
      if (notification && !notification.readAt) notification.readAt = now();
    });
  };

  acknowledgeNotification = (notificationId: EntityId): void => {
    this.mutate((state) => {
      const notification = state.notifications.find((item) => item.id === notificationId);
      if (notification && !notification.acknowledgedAt) {
        const acknowledgedAt = now();
        notification.readAt ??= acknowledgedAt;
        notification.acknowledgedAt = acknowledgedAt;
      }
    });
  };

  loadFindingDetail = async (findingId: EntityId): Promise<Finding | undefined> => {
    const finding = this.state.findings.find((item) => item.id === findingId);
    return finding ? structuredClone(finding) : undefined;
  };

  assignFinding = (findingId: EntityId, memberId?: EntityId): Finding => {
    let updated!: Finding;
    this.mutate((state) => {
      const finding = this.requireFinding(state, findingId);
      finding.assigneeId = memberId;
      finding.updatedAt = now();
      const action = state.actions.find((item) => item.targetUrl.endsWith(findingId));
      if (action) action.ownerId = memberId;
      state.activities.unshift({
        id: `activity-assignment-${state.activities.length + 1}`,
        type: "finding",
        title: memberId ? "Finding assigned" : "Finding unassigned",
        detail: memberId ? `${finding.reference} was assigned for review.` : `${finding.reference} is now unassigned.`,
        productId: finding.productId,
        releaseId: finding.releaseId,
        actorId: state.currentUserId,
        at: finding.updatedAt,
        targetUrl: `/findings/${finding.id}`,
      });
      updated = structuredClone(finding);
    });
    return updated;
  };

  recordFindingDecision = (input: FindingDecisionInput): Finding => {
    let updated!: Finding;
    this.mutate((state) => {
      const finding = this.requireFinding(state, input.findingId);
      const decidedAt = now();
      finding.decisions.push({
        id: `decision-${finding.id}-${finding.decisions.length + 1}`,
        decision: input.decision,
        rationale: input.rationale.trim(),
        decidedBy: state.currentUserId,
        decidedAt,
      });
      finding.affectedness = input.decision === "affected" ? "confirmed" : input.decision === "not_affected" ? "not_affected" : finding.affectedness;
      finding.status = input.decision === "not_affected"
        ? "resolved"
        : input.decision === "affected"
          ? "action_required"
          : input.decision === "accepted_risk"
            ? "accepted"
            : "needs_review";
      finding.updatedAt = decidedAt;
      state.activities.unshift({
        id: `activity-decision-${state.activities.length + 1}`,
        type: "decision",
        title: `Decision recorded for ${finding.reference}`,
        detail: input.rationale.trim(),
        productId: finding.productId,
        releaseId: finding.releaseId,
        actorId: state.currentUserId,
        at: decidedAt,
        targetUrl: `/findings/${finding.id}`,
      });
      if (input.decision === "not_affected") {
        state.actions.filter((item) => item.targetUrl.endsWith(finding.id)).forEach((item) => { item.status = "completed"; });
      }
      updated = structuredClone(finding);
    });
    return updated;
  };

  recordFindingBatchDecision = (input: FindingBatchDecisionInput): Finding[] => {
    const rationale = input.rationale.trim();
    if (!rationale) throw new Error("A rationale is required for batch approval.");
    return input.findingIds.map((findingId) => this.recordFindingDecision({
      findingId,
      decision: "not_affected",
      rationale,
    }));
  };

  updateRemediation = (input: RemediationInput): Finding => {
    let updated!: Finding;
    this.mutate((state) => {
      const finding = this.requireFinding(state, input.findingId);
      finding.remediation = {
        status: input.status,
        plan: input.plan?.trim() || finding.remediation.plan,
        targetDate: input.targetDate || finding.remediation.targetDate,
        completedAt: input.status === "verified" ? now() : finding.remediation.completedAt,
      };
      finding.status = input.status === "verified" ? "resolved" : input.status === "not_started" ? finding.status : "in_remediation";
      finding.updatedAt = now();
      if (input.status === "verified") {
        state.actions.filter((item) => item.targetUrl.endsWith(finding.id)).forEach((item) => { item.status = "completed"; });
      }
      updated = structuredClone(finding);
    });
    return updated;
  };

  loadComplianceDetail = async (itemId: EntityId): Promise<ComplianceItem | undefined> => {
    const item = this.state.complianceItems.find((candidate) => candidate.id === itemId);
    return item ? structuredClone(item) : undefined;
  };

  updateCompliance = (input: ComplianceUpdateCommand): ComplianceItem => {
    let updated!: ComplianceItem;
    this.mutate((state) => {
      const item = this.requireCompliance(state, input.itemId);
      const changedAt = now();
      const payload: Record<string, unknown> = {};
      if (input.title !== undefined) { item.title = input.title.trim(); payload.title = item.title; }
      if (input.description !== undefined) { item.reason = input.description.trim(); payload.description = item.reason; }
      if (input.priority !== undefined) {
        item.priority = input.priority === "critical" ? "urgent" : input.priority === "medium" ? "normal" : input.priority;
        payload.priority = input.priority;
      }
      if (input.status !== undefined) {
        item.lifecycleStatus = input.status;
        item.status = input.status === "resolved" || input.status === "approved" ? "complete" : input.status === "action_required" ? "open" : input.status === "pending_approval" ? "blocked" : "in_progress";
        if (input.status === "acknowledged") item.acknowledgedAt = changedAt;
        if (input.status === "resolved") item.resolvedAt = changedAt;
        payload.status = input.status;
      }
      if (input.clearDueAt) { item.dueAt = undefined; payload.dueAt = null; }
      else if (input.dueAt !== undefined) { item.dueAt = input.dueAt; payload.dueAt = input.dueAt; }
      if (input.clearOwner) { item.ownerId = undefined; payload.ownerId = null; }
      else if (input.ownerId !== undefined) { item.ownerId = input.ownerId; payload.ownerId = input.ownerId; }
      if (input.selfFilingRecordId !== undefined) item.selfFilingRecordId = input.selfFilingRecordId;
      if (input.selfFilingRecordUrl !== undefined) item.selfFilingRecordUrl = input.selfFilingRecordUrl;
      item.version = (item.version ?? 0) + 1;
      item.updatedAt = changedAt;
      item.audit = [...(item.audit ?? []), { id: `compliance-audit-${item.id}-${item.version}`, action: "compliance.updated", actorId: state.currentUserId, itemVersion: item.version, occurredAt: changedAt, payload }];
      updated = structuredClone(item);
    });
    return updated;
  };

  approveCompliance = (input: ComplianceApprovalCommand): ComplianceItem => {
    let updated!: ComplianceItem;
    this.mutate((state) => {
      const item = this.requireCompliance(state, input.itemId);
      const approvedAt = now();
      item.lifecycleStatus = "approved";
      item.status = "complete";
      item.approvedBy = state.currentUserId;
      item.approvedAt = approvedAt;
      item.selfFilingRecordId = input.selfFilingRecordId ?? item.selfFilingRecordId;
      item.selfFilingRecordUrl = input.selfFilingRecordUrl ?? item.selfFilingRecordUrl;
      item.version = (item.version ?? 0) + 1;
      item.updatedAt = approvedAt;
      item.audit = [...(item.audit ?? []), { id: `compliance-audit-${item.id}-${item.version}`, action: "compliance.approved", actorId: state.currentUserId, itemVersion: item.version, occurredAt: approvedAt, payload: { selfFilingRecordId: input.selfFilingRecordId, selfFilingRecordUrl: input.selfFilingRecordUrl } }];
      updated = structuredClone(item);
    });
    return updated;
  };

  approveDocument = (documentId: EntityId, comment?: string): DocumentRecord => this.decideDocument(documentId, "approved", comment);

  rejectDocument = (documentId: EntityId, comment: string): DocumentRecord => this.decideDocument(documentId, "rejected", comment);

  loadDocumentDetail = async (documentId: EntityId): Promise<DocumentRecord | undefined> => {
    const document = this.state.documents.find((item) => item.id === documentId);
    return document ? structuredClone(document) : undefined;
  };

  getDocumentDownload = async (documentId: EntityId, version?: number): Promise<DocumentDownloadMetadata> => {
    const document = this.state.documents.find((item) => item.id === documentId);
    if (!document) throw new Error(`Unknown document: ${documentId}`);
    const selected = document.revisions?.find((item) => item.version === (version ?? document.version));
    const format = selected?.format ?? document.format;
    const extension = format === "PDF/A-2b" ? "pdf" : format === "ZIP" ? "zip" : "json";
    const contentType = format === "PDF/A-2b" ? "application/pdf" : format === "ZIP" ? "application/zip" : "application/json";
    return {
      documentId,
      version: selected?.version ?? document.version,
      filename: `${slugify(document.name)}-v${selected?.version ?? document.version}.${extension}`,
      format,
      contentHash: selected?.contentHash ?? document.contentHash ?? "fixture-metadata-not-persisted",
      sizeBytes: selected?.sizeBytes ?? document.sizeBytes ?? 0,
      storageLocator: selected?.storageLocator ?? document.storageLocator ?? `fixture://documents/${documentId}/revisions/${selected?.version ?? document.version}`,
      contentType,
      downloadType: "storage_metadata_only",
    };
  };

  requestDocumentApproval = (documentId: EntityId, comment?: string): DocumentRecord => {
    let updated!: DocumentRecord;
    this.mutate((state) => {
      const document = state.documents.find((item) => item.id === documentId);
      if (!document) throw new Error(`Unknown document: ${documentId}`);
      if (document.status !== "draft") throw new Error("Only a draft revision can be submitted for approval.");
      if (document.completeness !== "complete") throw new Error("Complete all required evidence before requesting approval.");
      const requestedAt = now();
      document.status = "approval_required";
      document.updatedAt = requestedAt;
      document.updatedBy = state.currentUserId;
      document.audit.unshift({ id: `audit-${document.id}-${document.audit.length + 1}`, action: "approval_requested", actorId: state.currentUserId, at: requestedAt, detail: comment?.trim() || "Approval requested for the current revision." });
      const approval: Approval = { id: `approval-${document.id}-${document.version}`, documentId, status: "requested", requestedBy: state.currentUserId, requestedAt };
      state.approvals = state.approvals.filter((item) => item.documentId !== documentId);
      state.approvals.push(approval);
      document.approvalId = approval.id;
      updated = structuredClone(document);
    });
    return updated;
  };

  addDocumentRevision = (input: RegisterDocumentRevisionInput): DocumentRecord => {
    let updated!: DocumentRecord;
    this.mutate((state) => {
      const document = state.documents.find((item) => item.id === input.documentId);
      if (!document) throw new Error(`Unknown document: ${input.documentId}`);
      const createdAt = now();
      const previousVersion = document.version;
      document.version += 1;
      document.format = input.format;
      document.status = "draft";
      document.completeness = input.completeness;
      document.contentHash = input.contentHash;
      document.storageLocator = input.storageLocator;
      document.sizeBytes = input.sizeBytes;
      document.updatedAt = createdAt;
      document.updatedBy = state.currentUserId;
      document.revisions = [
        { version: document.version, format: input.format, status: "draft", completeness: input.completeness, contentHash: input.contentHash, storageLocator: input.storageLocator, sizeBytes: input.sizeBytes, createdBy: state.currentUserId, createdAt },
        ...(document.revisions ?? []),
      ];
      document.audit.unshift({ id: `audit-${document.id}-${document.audit.length + 1}`, action: "edited", actorId: state.currentUserId, at: createdAt, detail: `Revision ${document.version} superseded revision ${previousVersion}.` });
      updated = structuredClone(document);
    });
    return updated;
  };

  recordDocumentSelfFiling = (input: RecordDocumentSelfFilingInput): DocumentRecord => {
    let updated!: DocumentRecord;
    this.mutate((state) => {
      const document = state.documents.find((item) => item.id === input.documentId);
      if (!document) throw new Error(`Unknown document: ${input.documentId}`);
      if (document.status !== "approved") throw new Error("Only an approved revision can be recorded as externally filed.");
      const recordedAt = now();
      document.status = "self_filed";
      document.updatedAt = recordedAt;
      document.updatedBy = state.currentUserId;
      document.selfFilings = [{ id: `filing-${document.id}-${document.version}`, version: document.version, externalSubmissionReference: input.externalSubmissionReference, submittedAt: input.submittedAt, receiptEvidenceLocator: input.receiptEvidenceLocator, receiptContentHash: input.receiptContentHash, recordedBy: state.currentUserId, recordedAt }, ...(document.selfFilings ?? [])];
      document.audit.unshift({ id: `audit-${document.id}-${document.audit.length + 1}`, action: "self_filed", actorId: state.currentUserId, at: recordedAt, detail: `External filing ${input.externalSubmissionReference} recorded. Actis did not submit it.` });
      updated = structuredClone(document);
    });
    return updated;
  };

  createProduct = async (input: CreateProductInput): Promise<Product> => {
    let created!: Product;
    this.mutate((state) => {
      const suffix = state.products.length + 1;
      created = {
        id: `product-${slugify(input.name)}-${suffix}`,
        slug: `${slugify(input.name)}-${suffix}`,
        name: input.name.trim(),
        identifier: input.identifier.trim(),
        manufacturer: input.manufacturer.trim(),
        description: input.description?.trim() || "Product description not yet provided.",
        craClass: input.craClass,
        classificationStatus: input.classificationStatus,
        classificationAssessment: input.classificationAssessment,
        supportUntil: input.supportUntil,
        ownerId: input.ownerId,
        readiness: "incomplete_evidence",
        monitoringHealth: "inactive",
        activeReleaseId: undefined,
        actionCount: 1,
        tags: [],
        createdAt: now(),
      };
      state.products.push(created);
      state.activities.unshift({ id: `activity-product-${suffix}`, type: "analysis", title: "Product registered", detail: `${created.name} is ready for its first release.`, productId: created.id, actorId: state.currentUserId, at: created.createdAt, targetUrl: `/products/${created.id}` });
    });
    return structuredClone(created);
  };

  createRelease = async (input: CreateReleaseInput): Promise<Release> => {
    let created!: Release;
    this.mutate((state) => {
      const product = state.products.find((item) => item.id === input.productId);
      if (!product) throw new Error(`Unknown product: ${input.productId}`);
      const suffix = state.releases.filter((item) => item.productId === input.productId).length + 1;
      created = {
        id: `release-${slugify(product.name)}-${slugify(input.version)}-${suffix}`,
        productId: product.id,
        version: input.version.trim(),
        channel: input.channel,
        status: "draft",
        releaseDate: input.releaseDate,
        supportedUntil: input.supportedUntil,
        readiness: "incomplete_evidence",
        monitoringHealth: "inactive",
        sbomStatus: "missing",
        coverage: { components: 0, identifiedComponents: 0, advisorySourcesChecked: 0, advisorySourcesExpected: 4, limitations: ["Analysis has not run for this release."] },
        artifacts: [],
        createdAt: now(),
      };
      state.releases.push(created);
      product.activeReleaseId ??= created.id;
      state.activities.unshift({ id: `activity-release-${state.activities.length + 1}`, type: "analysis", title: "Release registered", detail: `${product.name} ${created.version} is ready for evidence input.`, productId: product.id, releaseId: created.id, actorId: state.currentUserId, at: created.createdAt, targetUrl: `/products/${product.id}/releases/${created.id}` });
    });
    return structuredClone(created);
  };

  selectActiveRelease = async (productId: EntityId, releaseId: EntityId): Promise<Product> => {
    this.mutate((state) => {
      const product = state.products.find((item) => item.id === productId);
      const release = state.releases.find((item) => item.id === releaseId && item.productId === productId);
      if (!product || !release || release.status === "draft" || release.status === "end_of_support") throw new Error("Only a completed supported release can be active.");
      const previous = state.releases.find((item) => item.id === product.activeReleaseId);
      if (previous && previous.id !== releaseId && previous.status === "active") previous.status = "supported";
      product.activeReleaseId = releaseId;
      release.status = "active";
    });
    return structuredClone(this.state.products.find((item) => item.id === productId)!);
  };

  downloadReleaseReport = async (productId: EntityId, releaseId: EntityId, jobId: EntityId): Promise<AnalysisEvidenceFile> => {
    const job = this.state.analysisJobs.find((item) => item.id === jobId && item.draft.productId === productId && item.draft.releaseId === releaseId && item.status === "completed");
    if (!job) throw new Error("Completed release analysis not found.");
    return { blob: new Blob([JSON.stringify(job.result, null, 2)], { type: "application/json" }), contentType: "application/json", filename: `actis-${releaseId}-report.json` };
  };

  previewAnalysis = async (draft: AnalysisDraft): Promise<AnalysisPreview> => {
    await new Promise((resolve) => setTimeout(resolve, 180));
    const extensionValid = /\.(json|zip|spdx|cdx)$/i.test(draft.fileName);
    const consentValid = draft.inputKind !== "raw_artifact" || draft.rawArtifactConsent === true;
    const seed = Math.max(42, Math.min(386, Math.round(draft.fileSize / 8_000) + 61));
    return {
      valid: extensionValid && consentValid && draft.fileSize > 0,
      releaseId: draft.releaseId,
      detectedFormat: draft.inputKind === "collector_package" ? "Signed Actis Collector package" : draft.inputKind === "sbom" ? (draft.fileName.toLowerCase().includes("spdx") ? "SPDX 2.3 JSON" : "CycloneDX 1.6 JSON") : "Firmware archive",
      componentCount: seed,
      identifiedComponentCount: Math.round(seed * (draft.inputKind === "raw_artifact" ? 0.91 : 0.97)),
      warnings: [
        ...(!extensionValid ? ["Use a JSON, ZIP, SPDX, or CycloneDX input."] : []),
        ...(!consentValid ? ["Confirm raw-artifact processing before continuing."] : []),
        ...(draft.inputKind === "sbom" ? ["Runtime reachability requires Collector or equivalent evidence."] : []),
      ],
      digest: digestFor(draft),
    };
  };

  runAnalysis = async (draft: AnalysisDraft): Promise<AnalysisJob> => {
    const preview = await this.previewAnalysis(draft);
    if (!preview.valid) throw new Error(preview.warnings[0] || "Input validation failed.");

    let releaseId = draft.releaseId;
    if (!releaseId) {
      const product = this.state.products.find((item) => item.id === draft.productId);
      if (!product) throw new Error(`Unknown product: ${draft.productId}`);
      const createdRelease = await this.createRelease({ productId: draft.productId, version: draft.version, channel: draft.channel, releaseDate: now().slice(0, 10), supportedUntil: product.supportUntil });
      releaseId = createdRelease.id;
    }

    const createdAt = now();
    const job: AnalysisJob = {
      id: `analysis-${this.state.analysisJobs.length + 1}`,
      draft: { ...draft, releaseId },
      status: "queued",
      progress: 5,
      stage: "Securing uploaded evidence",
      createdAt,
      updatedAt: createdAt,
    };
    this.mutate((state) => { state.analysisJobs.unshift(job); });
    this.scheduleJob(job.id, 280, "validating", 28, "Validating package identity and provenance");
    this.scheduleJob(job.id, 780, "analyzing", 67, "Matching components against advisory sources");
    const sbomAnalysis = draft.inputKind === "sbom" && draft.file
      ? this.sbomAnalyzer(draft.file, draft.productId, releaseId)
      : undefined;
    this.scheduleCompletion(job.id, 1450, preview, releaseId, sbomAnalysis);
    return structuredClone(job);
  };

  getAnalysisJob = (jobId: EntityId): AnalysisJob | undefined => {
    const job = this.state.analysisJobs.find((item) => item.id === jobId);
    return job ? structuredClone(job) : undefined;
  };

  upsertAnalysisJob = (job: AnalysisJob): void => {
    this.mutate((state) => {
      const index = state.analysisJobs.findIndex((item) => item.id === job.id);
      if (index === -1) state.analysisJobs.unshift(structuredClone(job));
      else state.analysisJobs[index] = structuredClone(job);
    });
  };

  replaceAnalysisJobs = (jobs: AnalysisJob[]): void => {
    this.mutate((state) => { state.analysisJobs = structuredClone(jobs); });
  };

  getApproval = (documentId: EntityId): Approval | undefined => {
    const approval = this.state.approvals.find((item) => item.documentId === documentId);
    return approval ? structuredClone(approval) : undefined;
  };

  loadReleaseMonitoring = async (productId: EntityId, releaseId: EntityId): Promise<ReleaseMonitoringView> => {
    const release = this.state.releases.find((item) => item.id === releaseId && item.productId === productId);
    if (!release) throw new Error("Release monitoring scope not found.");
    const occurredAt = release.lastMonitoringCheckAt ?? release.createdAt;
    return {
      productId, releaseId,
      enabledSources: ["osv", "cisa_kev", "epss", "native_advisory"],
      cadenceMinutes: 60,
      enabled: release.status !== "end_of_support",
      health: release.monitoringHealth,
      nextCheckAt: release.lastMonitoringCheckAt ? new Date(new Date(release.lastMonitoringCheckAt).getTime() + 3_600_000).toISOString() : undefined,
      lastCheckAt: release.lastMonitoringCheckAt,
      lastSuccessAt: release.monitoringHealth === "failed" ? undefined : release.lastMonitoringCheckAt,
      consecutiveFailures: release.monitoringHealth === "failed" ? 2 : 0,
      limitations: release.coverage.limitations,
      running: false,
      recentEvents: [{ id: `monitoring-${releaseId}`, runId: `run-${releaseId}`, eventType: release.monitoringHealth === "failed" ? "failed" : "succeeded", trigger: "scheduled", health: release.monitoringHealth, message: release.monitoringHealth === "healthy" ? "Scheduled monitoring completed." : "Monitoring completed with coverage limitations.", actorId: "system", occurredAt, limitations: release.coverage.limitations }],
    };
  };

  runReleaseMonitoring = async (productId: EntityId, releaseId: EntityId): Promise<ReleaseMonitoringView> => {
    const checkedAt = now();
    this.mutate((state) => {
      const release = state.releases.find((item) => item.id === releaseId && item.productId === productId);
      if (!release) throw new Error("Release monitoring scope not found.");
      release.lastMonitoringCheckAt = checkedAt;
      state.activities.unshift({ id: `activity-monitoring-${Date.now()}`, type: "monitoring", title: "Manual monitoring completed", detail: `${release.version} was checked against configured advisory sources.`, productId, releaseId, actorId: state.currentUserId, at: checkedAt, targetUrl: `/products/${productId}/releases/${releaseId}` });
    });
    const result = await this.loadReleaseMonitoring(productId, releaseId);
    result.recentEvents[0] = { ...result.recentEvents[0], id: `monitoring-manual-${Date.now()}`, runId: `run-manual-${Date.now()}`, trigger: "manual", actorId: this.state.currentUserId, occurredAt: checkedAt, message: "Manual monitoring completed." };
    return result;
  };

  replacePortfolio = (organization: DemoState["organization"], products: Product[], releases: Release[]): void => {
    this.mutate((state) => {
      state.organization = structuredClone(organization);
      state.products = structuredClone(products);
      state.releases = structuredClone(releases);
    });
  };

  upsertProduct = (product: Product): void => {
    this.mutate((state) => {
      const index = state.products.findIndex((item) => item.id === product.id);
      if (index < 0) state.products.push(structuredClone(product));
      else state.products[index] = structuredClone(product);
    });
  };

  upsertRelease = (release: Release): void => {
    this.mutate((state) => {
      const index = state.releases.findIndex((item) => item.id === release.id);
      if (index < 0) state.releases.push(structuredClone(release));
      else state.releases[index] = structuredClone(release);
    });
  };

  replaceOperationalState = (
    actions: DemoState["actions"],
    activities: DemoState["activities"],
    notifications: DemoState["notifications"],
    home?: DemoState["home"],
  ): void => {
    this.mutate((state) => {
      state.actions = structuredClone(actions);
      state.activities = structuredClone(activities);
      state.notifications = structuredClone(notifications);
      state.home = home ? structuredClone(home) : undefined;
    });
  };

  replaceFindings = (findings: Finding[]): void => {
    this.mutate((state) => { state.findings = structuredClone(findings); });
  };

  upsertFinding = (finding: Finding): void => {
    this.mutate((state) => {
      const index = state.findings.findIndex((item) => item.id === finding.id);
      if (index < 0) state.findings.push(structuredClone(finding));
      else state.findings[index] = structuredClone(finding);
    });
  };

  replaceGovernanceState = (
    complianceItems: DemoState["complianceItems"],
    documents: DemoState["documents"],
    settings: DemoState["settings"],
    members: DemoState["members"],
    integrations: DemoState["integrations"],
  ): void => {
    this.mutate((state) => {
      state.complianceItems = structuredClone(complianceItems);
      state.documents = structuredClone(documents);
      state.settings = structuredClone(settings);
      state.members = structuredClone(members);
      state.integrations = structuredClone(integrations);
      if (!state.members.some((item) => item.id === state.currentUserId)) {
        const current = state.members.find((item) => item.status === "active");
        if (current) state.currentUserId = current.id;
      }
    });
  };

  replaceSettings = (settings: AppSettings): void => {
    this.mutate((state) => { state.settings = structuredClone(settings); });
  };

  replaceOrganization = (organization: Organization): void => {
    this.mutate((state) => { state.organization = structuredClone(organization); });
  };

  upsertTeamMember = (member: TeamMember): void => {
    this.mutate((state) => {
      const index = state.members.findIndex((item) => item.id === member.id);
      if (index < 0) state.members.push(structuredClone(member));
      else state.members[index] = structuredClone(member);
    });
  };

  upsertIntegration = (integration: Integration): void => {
    this.mutate((state) => {
      const index = state.integrations.findIndex((item) => item.id === integration.id);
      if (index < 0) state.integrations.push(structuredClone(integration));
      else state.integrations[index] = structuredClone(integration);
    });
  };

  upsertCompliance = (item: ComplianceItem): void => {
    this.mutate((state) => {
      const index = state.complianceItems.findIndex((candidate) => candidate.id === item.id);
      if (index < 0) state.complianceItems.push(structuredClone(item));
      else state.complianceItems[index] = structuredClone(item);
    });
  };

  upsertDocument = (document: DocumentRecord): void => {
    this.mutate((state) => {
      const index = state.documents.findIndex((item) => item.id === document.id);
      if (index < 0) state.documents.push(structuredClone(document));
      else state.documents[index] = structuredClone(document);
    });
  };

  private decideDocument(documentId: EntityId, decision: "approved" | "rejected", comment?: string): DocumentRecord {
    let updated!: DocumentRecord;
    this.mutate((state) => {
      const document = state.documents.find((item) => item.id === documentId);
      if (!document) throw new Error(`Unknown document: ${documentId}`);
      const decidedAt = now();
      document.status = decision === "approved" ? "approved" : "draft";
      document.updatedAt = decidedAt;
      document.updatedBy = state.currentUserId;
      document.audit.unshift({ id: `audit-${document.id}-${document.audit.length + 1}`, action: decision, actorId: state.currentUserId, at: decidedAt, detail: comment?.trim() || (decision === "approved" ? "Approved for controlled export and self-filing." : "Returned to the owner for revision.") });
      const approval = state.approvals.find((item) => item.documentId === documentId);
      if (approval) {
        approval.status = decision;
        approval.decidedBy = state.currentUserId;
        approval.decidedAt = decidedAt;
        approval.comment = comment?.trim();
      }
      state.actions.filter((item) => item.type === "approval" && item.targetUrl.endsWith(documentId)).forEach((item) => { item.status = decision === "approved" ? "completed" : "open"; });
      const compliance = state.complianceItems.find((item) => item.type === "approval" && item.targetUrl.endsWith(documentId));
      if (compliance) compliance.status = decision === "approved" ? "complete" : "blocked";
      state.activities.unshift({ id: `activity-document-${state.activities.length + 1}`, type: "document", title: decision === "approved" ? "Document approved" : "Document returned for revision", detail: `${document.name} revision ${document.version}.`, productId: document.productId, releaseId: document.releaseId, actorId: state.currentUserId, at: decidedAt, targetUrl: `/documents/${document.id}` });
      updated = structuredClone(document);
    });
    return updated;
  }

  private scheduleJob(jobId: string, delay: number, status: AnalysisJob["status"], progress: number, stage: string): void {
    const timer = setTimeout(() => {
      this.timers.delete(timer);
      this.mutate((state) => {
        const job = state.analysisJobs.find((item) => item.id === jobId);
        if (!job || job.status === "completed" || job.status === "failed") return;
        job.status = status;
        job.progress = progress;
        job.stage = stage;
        job.updatedAt = now();
      });
    }, delay);
    this.timers.add(timer);
  }

  private scheduleCompletion(jobId: string, delay: number, preview: AnalysisPreview, releaseId: string, sbomAnalysis?: Promise<SbomAnalysis>): void {
    const timer = setTimeout(async () => {
      this.timers.delete(timer);
      let analyzed: SbomAnalysis | undefined;
      try { analyzed = await sbomAnalysis; }
      catch (error) {
        this.mutate((state) => {
          const job = state.analysisJobs.find((item) => item.id === jobId);
          if (!job) return;
          job.status = "failed";
          job.progress = 100;
          job.stage = "Advisory matching failed";
          job.error = error instanceof Error ? error.message : "OSV advisory matching failed.";
          job.updatedAt = now();
        });
        return;
      }
      this.mutate((state) => {
        const job = state.analysisJobs.find((item) => item.id === jobId);
        const release = state.releases.find((item) => item.id === releaseId);
        if (!job || !release) return;
        const completedAt = now();
        const limitations = job.draft.inputKind === "sbom" ? ["Runtime reachability was not measured from SBOM-only input."] : [];
        const product = state.products.find((item) => item.id === release.productId);
        release.status = !product?.activeReleaseId || product.activeReleaseId === release.id ? "active" : "supported";
        release.sbomStatus = limitations.length ? "partial" : "validated";
        release.monitoringHealth = "healthy";
        release.readiness = limitations.length ? "incomplete_evidence" : "ready";
        const componentCount = analyzed?.components ?? preview.componentCount;
        const identifiedComponentCount = analyzed?.matchableComponents ?? preview.identifiedComponentCount;
        release.coverage = { components: componentCount, identifiedComponents: identifiedComponentCount, advisorySourcesChecked: 4, advisorySourcesExpected: 4, limitations };
        release.lastAnalysisAt = completedAt;
        release.lastMonitoringCheckAt = completedAt;
        release.artifacts.unshift({ id: `artifact-${job.id}`, kind: job.draft.inputKind, name: job.draft.fileName, sha256: preview.digest, receivedAt: completedAt, sizeLabel: `${Math.max(1, Math.round(job.draft.fileSize / 1024))} KB` });
        if (product) {
          if (!product.activeReleaseId) product.activeReleaseId = release.id;
          if (product.activeReleaseId === release.id) {
            product.readiness = release.readiness;
            product.monitoringHealth = release.monitoringHealth;
          }
        }
        job.status = "completed";
        job.progress = 100;
        job.stage = limitations.length ? "Completed with coverage limitations" : "Analysis complete";
        job.updatedAt = completedAt;
        if (analyzed) {
          state.findings = state.findings.filter((finding) => finding.releaseId !== releaseId || !finding.id.startsWith(`finding-${releaseId}-`));
          state.findings.push(...analyzed.findings);
        }
        job.result = { releaseId, newFindings: analyzed?.findings.length ?? 1, changedFindings: analyzed ? 0 : 1, componentCount, coverage: release.coverage, resultUrl: `/products/${release.productId}/releases/${release.id}` };
        state.activities.unshift({ id: `activity-${job.id}`, type: "analysis", title: job.stage, detail: `${componentCount} components analyzed for release ${release.version}.`, productId: release.productId, releaseId: release.id, actorId: state.currentUserId, at: completedAt, targetUrl: job.result.resultUrl });
      });
    }, delay);
    this.timers.add(timer);
  }

  private requireFinding(state: DemoState, findingId: string): Finding {
    const finding = state.findings.find((item) => item.id === findingId);
    if (!finding) throw new Error(`Unknown finding: ${findingId}`);
    return finding;
  }

  private requireCompliance(state: DemoState, itemId: string): ComplianceItem {
    const item = state.complianceItems.find((candidate) => candidate.id === itemId);
    if (!item) throw new Error(`Unknown compliance item: ${itemId}`);
    return item;
  }

  private mutate(change: (draft: DemoState) => void): void {
    const draft = structuredClone(this.state);
    change(draft);
    this.commit(draft);
  }

  private commit(next: DemoState): void {
    this.state = next;
    if (this.persist && typeof window !== "undefined") {
      try { window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next)); } catch { /* Demo remains usable without persistence. */ }
    }
    this.listeners.forEach((listener) => listener());
  }
}

export function createFixtureAdapter(initialState?: DemoState): FixtureAdapter {
  return new FixtureAdapter(initialState);
}

export { DEMO_IDS };
