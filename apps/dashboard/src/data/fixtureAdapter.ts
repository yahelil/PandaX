import type { AdapterStatus, DataAdapter, DemoListener, UpdateProductInput, WorkspaceSearchResult } from "./adapter";
import { sanitizeAnalyticsEvent } from "./analytics";
import { createDemoState, DEMO_IDS } from "./fixtures";
import { analyzeSbomWithOsv, inspectSbom, type SbomAnalysis, type SbomAnalyzer } from "./osvSbom";
import { createReleasePdf } from "./releasePdf";
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

async function sha256(file: Blob): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return [...new Uint8Array(bytes)].map((value) => value.toString(16).padStart(2, "0")).join("");
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

function escapePdfText(str: string): string {
  const sanitized = String(str || "").replace(/[^\x20-\x7E]/g, " ");
  return sanitized.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}

export interface FixturePdfFinding {
  id: string;
  reference?: string;
  severity?: string;
  title: string;
  component?: string;
  componentVersion?: string;
  reachability?: string;
  status?: string;
}

export interface FixturePdfInput {
  title: string;
  documentId: string;
  productId: string;
  productName?: string;
  version: number;
  status: string;
  completeness: string;
  format: string;
  generatedAt: string;
  findings: FixturePdfFinding[];
}

export function createFixturePdf(input: FixturePdfInput | string, legacyLines?: string[]): Uint8Array {
  const enc = new TextEncoder();

  let title = "";
  let docId = "";
  let productId = "";
  let version = 1;
  let status = "DRAFT";
  let completeness = "COMPLETE";
  let generatedAt = new Date().toISOString();
  let format = "PDF/A-2b";
  let findings: FixturePdfFinding[] = [];

  if (typeof input === "string") {
    title = input;
    docId = "doc-demo";
    productId = "prod-demo";
    if (legacyLines && legacyLines.length > 0) {
      for (const line of legacyLines) {
        if (line.startsWith("Document ID: ")) docId = line.replace("Document ID: ", "");
        else if (line.startsWith("Product ID: ")) productId = line.replace("Product ID: ", "");
        else if (line.startsWith("Revision: ")) version = Number(line.replace("Revision: ", "")) || 1;
        else if (line.startsWith("Status: ")) status = line.replace("Status: ", "").toUpperCase();
        else if (line.startsWith("Completeness: ")) completeness = line.replace("Completeness: ", "").toUpperCase();
        else if (line.startsWith("Generated: ")) generatedAt = line.replace("Generated: ", "");
        else if (line.startsWith("Format: ")) format = line.replace("Format: ", "");
        else if (line.startsWith("- [")) {
          findings.push({ id: line, title: line, severity: line.includes("CRITICAL") ? "critical" : line.includes("HIGH") ? "high" : "medium" });
        }
      }
    }
  } else {
    title = input.title;
    docId = input.documentId;
    productId = input.productName ? `${input.productName} (${input.productId})` : input.productId;
    version = input.version;
    status = (input.status || "draft").toUpperCase();
    completeness = (input.completeness || "complete").toUpperCase();
    generatedAt = input.generatedAt || new Date().toISOString();
    format = input.format || "PDF/A-2b";
    findings = input.findings || [];
  }

  const stream: string[] = [];

  // Top header banner (Dark Navy)
  stream.push("0.08 0.13 0.24 rg");
  stream.push("50 712 512 44 re f");

  stream.push("BT");
  stream.push("1 1 1 rg");
  stream.push("/F2 13 Tf");
  stream.push("65 734 Td");
  stream.push("(PANDAX CYBER COMPLIANCE & GOVERNANCE ENGINE) Tj");
  stream.push("0.75 0.82 0.95 rg");
  stream.push("/F1 8 Tf");
  stream.push("0 -13 Td");
  stream.push("(OFFICIAL REGULATORY EVIDENCE REPORT  |  CONFIDENTIAL) Tj");
  stream.push("ET");

  // Document Title
  stream.push("BT");
  stream.push("0.10 0.12 0.16 rg");
  stream.push("/F2 17 Tf");
  stream.push("50 675 Td");
  stream.push(`(${escapePdfText(title)}) Tj`);
  stream.push("ET");

  // Top separator rule
  stream.push("0.80 0.84 0.90 RG 1 w");
  stream.push("50 660 m 562 660 l S");

  // Metadata Card background & border
  stream.push("0.96 0.97 0.98 rg");
  stream.push("50 535 512 110 re f");
  stream.push("0.82 0.85 0.90 RG 0.75 w");
  stream.push("50 535 512 110 re S");

  // Metadata Column 1 Labels
  stream.push("BT");
  stream.push("0.45 0.50 0.58 rg");
  stream.push("/F2 8 Tf");
  stream.push("16 TL");
  stream.push("65 623 Td");
  stream.push("(DOCUMENT ID:) Tj T*");
  stream.push("(PRODUCT REF:) Tj T*");
  stream.push("(REVISION / STATUS:) Tj T*");
  stream.push("(EVIDENCE COMPLETENESS:) Tj T*");
  stream.push("(FORMAT SPECIFICATION:) Tj T*");
  stream.push("(GENERATION DATE:) Tj T*");
  stream.push("ET");

  // Metadata Column 1 Values
  stream.push("BT");
  stream.push("0.12 0.15 0.20 rg");
  stream.push("/F1 8.5 Tf");
  stream.push("16 TL");
  stream.push("195 623 Td");
  stream.push(`(${escapePdfText(docId)}) Tj T*`);
  stream.push(`(${escapePdfText(productId)}) Tj T*`);
  stream.push(`(Revision ${version}  -  ${escapePdfText(status)}) Tj T*`);
  stream.push(`(${escapePdfText(completeness)}) Tj T*`);
  stream.push(`(${escapePdfText(format)} (ISO 19005-2 compliance)) Tj T*`);
  stream.push(`(${escapePdfText(generatedAt)}) Tj T*`);
  stream.push("ET");

  // Findings Section Header
  stream.push("BT");
  stream.push("0.10 0.12 0.16 rg");
  stream.push("/F2 12 Tf");
  stream.push("50 495 Td");
  stream.push(`(Associated Security Findings (${findings.length})) Tj`);
  stream.push("ET");

  stream.push("0.80 0.84 0.90 RG 0.5 w");
  stream.push("50 485 m 562 485 l S");

  // Findings Cards
  let curY = 425;
  if (findings.length === 0) {
    stream.push("0.98 0.98 0.99 rg");
    stream.push(`50 ${curY} 512 45 re f`);
    stream.push("0.88 0.90 0.92 RG 0.5 w");
    stream.push(`50 ${curY} 512 45 re S`);
    stream.push("BT");
    stream.push("0.35 0.40 0.45 rg");
    stream.push("/F1 9 Tf");
    stream.push(`65 ${curY + 18} Td`);
    stream.push("(No unresolved security findings recorded against this product revision.) Tj");
    stream.push("ET");
  } else {
    for (const f of findings.slice(0, 3)) {
      const isCritical = (f.severity || "").toLowerCase() === "critical";
      const isHigh = (f.severity || "").toLowerCase() === "high";
      const badgeR = isCritical ? "0.82 0.15 0.15" : isHigh ? "0.85 0.35 0.10" : "0.20 0.45 0.80";

      stream.push("0.98 0.98 0.99 rg");
      stream.push(`50 ${curY} 512 50 re f`);
      stream.push("0.88 0.90 0.93 RG 0.5 w");
      stream.push(`50 ${curY} 512 50 re S`);

      stream.push(`${badgeR} rg`);
      stream.push(`50 ${curY} 4 50 re f`);

      stream.push("BT");
      stream.push(`${badgeR} rg`);
      stream.push("/F2 8.5 Tf");
      stream.push(`65 ${curY + 33} Td`);
      stream.push(`([${escapePdfText((f.severity || "UNKNOWN").toUpperCase())}]  ${escapePdfText(f.reference || f.id)}) Tj`);

      stream.push("0.10 0.12 0.16 rg");
      stream.push("/F2 9.5 Tf");
      stream.push("0 -13 Td");
      stream.push(`(${escapePdfText(f.title)}) Tj`);

      stream.push("0.45 0.50 0.55 rg");
      stream.push("/F1 8 Tf");
      stream.push("0 -11 Td");
      const comp = f.component ? `${f.component} ${f.componentVersion || ""}` : "System";
      const reach = f.reachability || "unknown";
      const statusText = f.status || "needs_review";
      stream.push(`(Component: ${escapePdfText(comp)}   |   Reachability: ${escapePdfText(reach)}   |   Status: ${escapePdfText(statusText)}) Tj`);
      stream.push("ET");

      curY -= 60;
    }

    if (findings.length > 3) {
      stream.push("BT");
      stream.push("0.45 0.50 0.55 rg");
      stream.push("/F1 8 Tf");
      stream.push(`65 ${curY + 45} Td`);
      stream.push(`(... and ${findings.length - 3} additional security findings catalogued in evidence storage.) Tj`);
      stream.push("ET");
    }
  }

  // Regulatory Notice box at bottom
  stream.push("0.94 0.96 0.99 rg");
  stream.push("50 85 512 48 re f");
  stream.push("0.72 0.80 0.92 RG 0.5 w");
  stream.push("50 85 512 48 re S");

  stream.push("BT");
  stream.push("0.20 0.32 0.55 rg");
  stream.push("/F2 8 Tf");
  stream.push("65 118 Td");
  stream.push("(REGULATORY COMPLIANCE NOTICE) Tj");
  stream.push("/F1 7.5 Tf");
  stream.push("10 TL");
  stream.push("T*");
  stream.push("(This document certifies technical findings, verification evidence, and conformity decisions recorded at generation time.) Tj T*");
  stream.push("(Maintained under controlled revision management compliant with EU Cyber Resilience Act (CRA) Article 14 and ISO standards.) Tj");
  stream.push("ET");

  // Footer
  stream.push("0.85 0.88 0.92 RG 0.5 w");
  stream.push("50 55 m 562 55 l S");

  stream.push("BT");
  stream.push("0.50 0.55 0.60 rg");
  stream.push("/F1 7.5 Tf");
  stream.push("50 42 Td");
  stream.push("(PandaX Product Security Platform  --  Automated Evidence & CRA Verification Pack  --  Page 1 of 1) Tj");
  stream.push("ET");

  const contentStream = stream.join("\n");
  const streamBytes = enc.encode(contentStream);
  const headerBytes = enc.encode("%PDF-1.4\n%\xFF\xFF\xFF\xFF\n");

  const obj1 = enc.encode("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
  const obj2 = enc.encode("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
  const obj3 = enc.encode("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>\nendobj\n");
  const obj4 = enc.encode("4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");
  const obj5 = enc.encode("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n");
  const obj6Prefix = enc.encode(`6 0 obj\n<< /Length ${streamBytes.length} >>\nstream\n`);
  const obj6Suffix = enc.encode("\nendstream\nendobj\n");

  const obj6 = new Uint8Array(obj6Prefix.length + streamBytes.length + obj6Suffix.length);
  obj6.set(obj6Prefix, 0);
  obj6.set(streamBytes, obj6Prefix.length);
  obj6.set(obj6Suffix, obj6Prefix.length + streamBytes.length);

  const objects = [obj1, obj2, obj3, obj4, obj5, obj6];
  const offsets: number[] = [];
  let currentOffset = headerBytes.length;
  for (const obj of objects) {
    offsets.push(currentOffset);
    currentOffset += obj.length;
  }

  const xrefOffset = currentOffset;
  let xref = "xref\n0 7\n0000000000 65535 f \n";
  for (const offset of offsets) {
    xref += `${offset.toString().padStart(10, "0")} 00000 n \n`;
  }
  const trailer = `trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  const footerBytes = enc.encode(xref + trailer);

  const totalLength = currentOffset + footerBytes.length;
  const result = new Uint8Array(totalLength);
  let pos = 0;
  result.set(headerBytes, pos);
  pos += headerBytes.length;
  for (const obj of objects) {
    result.set(obj, pos);
    pos += obj.length;
  }
  result.set(footerBytes, pos);

  return result;
}

export const FIXTURE_ZIP_BYTES = new Uint8Array([0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

export class FixtureAdapter implements DataAdapter {
  private state: DemoState;
  private readonly listeners = new Set<DemoListener>();
  private readonly timers = new Set<ReturnType<typeof setTimeout>>();
  private readonly analyticsEvents: PrivacySafeAnalyticsEvent[] = [];
  private readonly status: AdapterStatus = { mode: "fixture", phase: "ready" };

  constructor(initialState?: DemoState, private readonly persist = true, private readonly sbomAnalyzer: SbomAnalyzer = analyzeSbomWithOsv) {
    this.state = withAnalyticsSettings(initialState ? structuredClone(initialState) : loadInitialState());
    for (const doc of this.state.documents) {
      if (!doc.sizeBytes) {
        doc.sizeBytes = this.generateDocumentBlob(doc, doc.version, doc.format).size;
      }
    }
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
        this.syncDocumentStatusAfterResolution(state, finding.productId, finding.releaseId);
      }
      updated = structuredClone(finding);
    });
    return updated;
  };

  recordFindingBatchDecision = (input: FindingBatchDecisionInput): Finding[] => {
    const rationale = input.rationale.trim();
    if (!rationale) throw new Error("A rationale is required for batch approval.");
    if (!input.findingIds.length || new Set(input.findingIds).size !== input.findingIds.length) {
      throw new Error("Select distinct findings to review.");
    }
    for (const findingId of input.findingIds) {
      const finding = this.state.findings.find((item) => item.id === findingId);
      if (!finding || finding.status !== "needs_review" || finding.decisions.length) {
        throw new Error("Only unreviewed findings can be decided in a batch.");
      }
    }
    return input.findingIds.map((findingId) => this.recordFindingDecision({
      findingId,
      decision: input.decision ?? "not_affected",
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
      if (input.targetDate) finding.dueAt = input.targetDate;
      finding.status = input.status === "verified" ? "resolved" : input.status === "not_started" ? finding.status : "in_remediation";
      finding.updatedAt = now();
      if (input.status === "verified") {
        state.actions.filter((item) => item.targetUrl.endsWith(finding.id)).forEach((item) => { item.status = "completed"; });
        this.syncDocumentStatusAfterResolution(state, finding.productId, finding.releaseId);
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

  private generateDocumentBlob(document: DocumentRecord, version: number, format: DocumentRecord["format"]): Blob {
    if (format === "PDF/A-2b") {
      const findings = this.state.findings.filter((item) => item.productId === document.productId);
      const product = this.state.products.find((item) => item.id === document.productId);
      const pdfBytes = createFixturePdf({
        title: document.name,
        documentId: document.id,
        productId: document.productId,
        productName: product?.name,
        version,
        status: document.status,
        completeness: document.completeness,
        format,
        generatedAt: document.updatedAt || now(),
        findings: findings.map((f) => ({
          id: f.id,
          reference: f.reference,
          severity: f.severity,
          title: f.title,
          component: f.component,
          componentVersion: f.componentVersion,
          reachability: f.reachability,
          status: f.status,
        })),
      });
      return new Blob([pdfBytes.buffer as ArrayBuffer], { type: "application/pdf" });
    }

    if (format === "ZIP") {
      return new Blob([FIXTURE_ZIP_BYTES.buffer as ArrayBuffer], { type: "application/zip" });
    }

    const findings = this.state.findings.filter((item) => item.productId === document.productId);
    const payload = JSON.stringify({
      document_id: document.id,
      name: document.name,
      revision: version,
      format,
      generated_at: now(),
      findings,
    }, null, 2);
    return new Blob([payload], { type: "application/json" });
  }

  loadDocumentDetail = async (documentId: EntityId): Promise<DocumentRecord | undefined> => {
    const document = this.state.documents.find((item) => item.id === documentId);
    if (!document) return undefined;
    if (!document.sizeBytes) {
      document.sizeBytes = this.generateDocumentBlob(document, document.version, document.format).size;
    }
    return structuredClone(document);
  };

  getDocumentDownload = async (documentId: EntityId, version?: number): Promise<DocumentDownloadMetadata> => {
    const document = this.state.documents.find((item) => item.id === documentId);
    if (!document) throw new Error(`Unknown document: ${documentId}`);
    const selected = document.revisions?.find((item) => item.version === (version ?? document.version));
    const targetVersion = selected?.version ?? document.version;
    const format = selected?.format ?? document.format;
    const extension = format === "PDF/A-2b" ? "pdf" : format === "ZIP" ? "zip" : "json";
    const contentType = format === "PDF/A-2b" ? "application/pdf" : format === "ZIP" ? "application/zip" : "application/json";
    const blob = this.generateDocumentBlob(document, targetVersion, format);
    const sizeBytes = selected?.sizeBytes || blob.size;
    document.sizeBytes = sizeBytes;
    return {
      documentId,
      version: targetVersion,
      filename: `${slugify(document.name)}-v${targetVersion}.${extension}`,
      format,
      contentHash: selected?.contentHash ?? document.contentHash ?? "fixture-metadata-not-persisted",
      sizeBytes,
      storageLocator: selected?.storageLocator ?? document.storageLocator ?? `fixture://documents/${documentId}/revisions/${targetVersion}`,
      contentType,
      downloadType: "content_available",
    };
  };

  downloadDocument = async (documentId: EntityId, version?: number): Promise<DocumentDownloadFile> => {
    const document = this.state.documents.find((item) => item.id === documentId);
    if (!document) throw new Error(`Unknown document: ${documentId}`);
    const selected = document.revisions?.find((item) => item.version === (version ?? document.version));
    const targetVersion = selected?.version ?? document.version;
    const format = selected?.format ?? document.format;
    const extension = format === "PDF/A-2b" ? "pdf" : format === "ZIP" ? "zip" : "json";
    const contentType = format === "PDF/A-2b" ? "application/pdf" : format === "ZIP" ? "application/zip" : "application/json";
    const filename = `${slugify(document.name)}-v${targetVersion}.${extension}`;
    const blob = this.generateDocumentBlob(document, targetVersion, format);
    if (!document.sizeBytes) {
      document.sizeBytes = blob.size;
    }
    return {
      blob,
      contentType,
      filename,
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

  updateProduct = async (input: UpdateProductInput): Promise<Product> => {
    let updated!: Product;
    this.mutate((state) => {
      const product = state.products.find((item) => item.id === input.productId);
      if (!product) throw new Error(`Unknown product: ${input.productId}`);
      if (input.name !== undefined) product.name = input.name.trim();
      if (input.identifier !== undefined) product.identifier = input.identifier.trim();
      if (input.manufacturer !== undefined) product.manufacturer = input.manufacturer.trim();
      if (input.description !== undefined) product.description = input.description.trim();
      if (input.craClass !== undefined) product.craClass = input.craClass;
      if (input.classificationStatus !== undefined) product.classificationStatus = input.classificationStatus;
      if (input.classificationAssessment !== undefined) product.classificationAssessment = input.classificationAssessment;
      if (input.ownerId !== undefined) product.ownerId = input.ownerId || undefined;
      if (input.supportUntil !== undefined) product.supportUntil = input.supportUntil;
      state.activities.unshift({
        id: `activity-product-update-${state.activities.length + 1}`,
        type: "analysis",
        title: "Product CRA assessment updated",
        detail: `${product.name} scope and CRA classification updated to ${product.craClass}.`,
        productId: product.id,
        actorId: state.currentUserId,
        at: now(),
        targetUrl: `/products/${product.id}`,
      });
      updated = structuredClone(product);
    });
    return updated;
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
    return { blob: new Blob([JSON.stringify(job.result, null, 2)], { type: "application/json" }), contentType: "application/json", filename: `actis-${releaseId}-analysis-result.json` };
  };

  downloadAnalysisEvidence = async (productId: EntityId, releaseId: EntityId, jobId: EntityId, digest: string): Promise<AnalysisEvidenceFile> => {
    const job = this.state.analysisJobs.find((item) => item.id === jobId && item.draft.productId === productId && item.draft.releaseId === releaseId && item.status === "completed");
    const evidence = job?.result?.evidence?.find((item) => item.sha256 === digest);
    if (!job || !evidence) throw new Error("Generated analysis document not found.");
    const product = this.state.products.find((item) => item.id === productId);
    const release = this.state.releases.find((item) => item.id === releaseId && item.productId === productId);
    if (!product || !release || !evidence.name.toLowerCase().endsWith(".pdf")) throw new Error("Generated analysis document not found.");
    const kind = evidence.name.startsWith("AnnexVII") ? "technical" : "declaration";
    const findings = this.state.findings.filter((item) => item.productId === productId && item.releaseId === releaseId);
    const content = createReleasePdf(kind, product, release, findings);
    return { blob: new Blob([content.buffer as ArrayBuffer], { type: "application/pdf" }), contentType: "application/pdf", filename: evidence.name.replace(/\.pdf$/i, "-draft.pdf") };
  };

  generateFindingsReport = async (productId: EntityId, releaseId: EntityId): Promise<AnalysisEvidenceFile> => {
    const release = this.state.releases.find((item) => item.id === releaseId && item.productId === productId);
    const product = this.state.products.find((item) => item.id === productId);
    if (!release || !product) throw new Error("Release not found.");
    const findings = this.state.findings.filter((item) => item.productId === productId && item.releaseId === releaseId);
    const content = JSON.stringify({
      subject: { product: product.name, release: release.version },
      generatedAt: now(),
      summary: { total: findings.length, awaitingDecision: findings.filter((item) => item.status === "needs_review").length },
      findings: findings.map((item) => ({ reference: item.reference, title: item.title, severity: item.severity,
        status: item.status, decision: item.decisions.at(-1)?.decision ?? null,
        rationale: item.decisions.at(-1)?.rationale ?? null, remediation: item.remediation })),
      notice: "This report records findings and decisions; it is not a CRA filing or conformity assessment.",
    }, null, 2);
    return { blob: new Blob([content], { type: "application/json" }), contentType: "application/json",
      filename: `actis-${releaseId}-findings-report.json` };
  };

  generateSecurityPdf = async (productId: EntityId, releaseId: EntityId): Promise<AnalysisEvidenceFile> => {
    const release = this.state.releases.find((item) => item.id === releaseId && item.productId === productId);
    const product = this.state.products.find((item) => item.id === productId);
    if (!release || !product) throw new Error("Release not found.");
    const findings = this.state.findings.filter((item) => item.productId === productId && item.releaseId === releaseId);
    const bytes = createReleasePdf("security", product, release, findings);
    return { blob: new Blob([bytes.buffer as ArrayBuffer], { type: "application/pdf" }),
      contentType: "application/pdf", filename: `actis-${slugify(product.name)}-${slugify(release.version)}-security-report.pdf` };
  };

  downloadReleaseEvidenceFile = (productId: EntityId, releaseId: EntityId, jobId: EntityId, digest: string): Promise<AnalysisEvidenceFile> =>
    this.downloadAnalysisEvidence(productId, releaseId, jobId, digest);

  previewAnalysis = async (draft: AnalysisDraft): Promise<AnalysisPreview> => {
    await new Promise((resolve) => setTimeout(resolve, 180));
    if (!draft.file || draft.fileSize <= 0) throw new Error("Choose an evidence file before validation.");
    if (draft.inputKind !== "sbom") {
      return {
        valid: false,
        releaseId: draft.releaseId,
        detectedFormat: "Not inspected",
        componentCount: 0,
        identifiedComponentCount: 0,
        warnings: ["Archive and Collector analysis require the production engine. Demo mode supports JSON SBOM analysis only."],
        digest: await sha256(draft.file),
      };
    }
    const inspection = await inspectSbom(draft.file);
    return {
      valid: inspection.matchableComponents > 0,
      releaseId: draft.releaseId,
      detectedFormat: inspection.format,
      componentCount: inspection.components,
      identifiedComponentCount: inspection.matchableComponents,
      warnings: [
        ...(inspection.matchableComponents === 0 ? ["No components contain a usable, versioned Package URL (purl)."] : []),
        "Demo mode checks OSV only. CISA KEV, EPSS, vendor advisories, and continuous monitoring require the production engine.",
        "Runtime reachability was not measured from SBOM-only input.",
      ],
      digest: await sha256(draft.file),
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
    return {
      productId, releaseId,
      enabledSources: [],
      cadenceMinutes: 60,
      enabled: false,
      health: "inactive",
      consecutiveFailures: 0,
      limitations: ["Continuous monitoring requires the production engine and is unavailable in demo mode."],
      running: false,
      recentEvents: [],
    };
  };

  runReleaseMonitoring = async (productId: EntityId, releaseId: EntityId): Promise<ReleaseMonitoringView> => {
    await this.loadReleaseMonitoring(productId, releaseId);
    throw new Error("Continuous monitoring is unavailable in demo mode. Connect the production engine to run advisory checks.");
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
        const limitations = [
          "Demo analysis checked OSV only; CISA KEV, EPSS, and vendor advisory sources were not checked.",
          "Runtime reachability was not measured from SBOM-only input.",
          "Continuous monitoring is unavailable in demo mode.",
        ];
        const product = state.products.find((item) => item.id === release.productId);
        release.status = !product?.activeReleaseId || product.activeReleaseId === release.id ? "active" : "supported";
        release.sbomStatus = limitations.length ? "partial" : "validated";
        release.monitoringHealth = "inactive";
        release.readiness = "incomplete_evidence";
        const componentCount = analyzed?.components ?? preview.componentCount;
        const identifiedComponentCount = analyzed?.matchableComponents ?? preview.identifiedComponentCount;
        release.coverage = { components: componentCount, identifiedComponents: identifiedComponentCount, advisorySourcesChecked: 1, advisorySourcesExpected: 4, limitations };
        release.lastAnalysisAt = completedAt;
        release.lastMonitoringCheckAt = undefined;
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

        const findingsForRelease = state.findings.filter((item) => item.releaseId === releaseId);
        const unresolved = findingsForRelease.filter((item) => item.status !== "resolved");
        const docStatus: DocumentRecord["status"] = unresolved.length === 0 ? "approval_required" : "draft";

        const docId = `document-${release.id}-doc`;
        const annexId = `document-${release.id}-annex-vii`;
        const hasDoc = state.documents.some((item) => item.id === docId || (item.releaseId === release.id && item.type === "conformity"));
        const hasAnnex = state.documents.some((item) => item.id === annexId || (item.releaseId === release.id && item.type === "cra_reporting_pack"));

        if (!hasDoc) {
          const docRecord: DocumentRecord = {
            id: docId,
            productId: release.productId,
            releaseId: release.id,
            name: `EU Declaration of Conformity — ${product?.name || "Product"} ${release.version}`,
            type: "conformity",
            format: "PDF/A-2b",
            version: 1,
            status: docStatus,
            completeness: "complete",
            updatedAt: completedAt,
            updatedBy: state.currentUserId,
            audit: [
              {
                id: `audit-${release.id}-doc-1`,
                action: "generated",
                actorId: state.currentUserId,
                at: completedAt,
                detail: "Generated automatically from completed SBOM analysis.",
              },
            ],
            revisions: [
              {
                version: 1,
                format: "PDF/A-2b",
                status: docStatus,
                completeness: "complete",
                contentHash: `auto-generated-${release.id}-pack`,
                storageLocator: `memory://documents/${docId}-v1.pdf`,
                sizeBytes: 15420,
                createdBy: state.currentUserId,
                createdAt: completedAt,
              },
            ],
          };
          docRecord.sizeBytes = this.generateDocumentBlob(docRecord, 1, "PDF/A-2b").size;
          if (docRecord.revisions?.[0]) docRecord.revisions[0].sizeBytes = docRecord.sizeBytes;
          state.documents.push(docRecord);
        }

        if (!hasAnnex) {
          const annexRecord: DocumentRecord = {
            id: annexId,
            productId: release.productId,
            releaseId: release.id,
            name: `Annex VII Technical Documentation — ${product?.name || "Product"} ${release.version}`,
            type: "cra_reporting_pack",
            format: "PDF/A-2b",
            version: 1,
            status: docStatus,
            completeness: "complete",
            updatedAt: completedAt,
            updatedBy: state.currentUserId,
            audit: [
              {
                id: `audit-${release.id}-annex-vii-1`,
                action: "generated",
                actorId: state.currentUserId,
                at: completedAt,
                detail: "Generated automatically from completed SBOM analysis.",
              },
            ],
            revisions: [
              {
                version: 1,
                format: "PDF/A-2b",
                status: docStatus,
                completeness: "complete",
                contentHash: `auto-generated-${release.id}-annex-vii`,
                storageLocator: `memory://documents/${annexId}-v1.pdf`,
                sizeBytes: 24800,
                createdBy: state.currentUserId,
                createdAt: completedAt,
              },
            ],
          };
          annexRecord.sizeBytes = this.generateDocumentBlob(annexRecord, 1, "PDF/A-2b").size;
          if (annexRecord.revisions?.[0]) annexRecord.revisions[0].sizeBytes = annexRecord.sizeBytes;
          state.documents.push(annexRecord);
        }

        if (!hasDoc || !hasAnnex) {
          state.activities.unshift({
            id: `activity-doc-${release.id}`,
            type: "document",
            title: "Documents generated",
            detail: `EU Declaration of Conformity and Annex VII Technical Documentation generated for ${release.version}.`,
            productId: release.productId,
            releaseId: release.id,
            actorId: state.currentUserId,
            at: completedAt,
            targetUrl: `/documents/${docId}`,
          });
        }

        job.result = { releaseId, newFindings: analyzed?.findings.length ?? 0, changedFindings: 0, componentCount, coverage: release.coverage, resultUrl: `/products/${release.productId}/releases/${release.id}` };
        state.activities.unshift({ id: `activity-${job.id}`, type: "analysis", title: job.stage, detail: `${componentCount} components analyzed for release ${release.version}.`, productId: release.productId, releaseId: release.id, actorId: state.currentUserId, at: completedAt, targetUrl: job.result.resultUrl });
      });
    }, delay);
    this.timers.add(timer);
  }

  private syncDocumentStatusAfterResolution(state: DemoState, productId: string, releaseId?: string): void {
    const findings = state.findings.filter((f) => f.productId === productId && (!releaseId || f.releaseId === releaseId));
    const hasUnresolved = findings.some((f) => f.status !== "resolved");
    if (hasUnresolved) return;

    const targetDocs = state.documents.filter(
      (d) => d.productId === productId && (!releaseId || d.releaseId === releaseId) && d.status === "draft"
    );
    for (const doc of targetDocs) {
      doc.status = "approval_required";
      if (doc.revisions) {
        const rev = doc.revisions.find((r) => r.version === doc.version);
        if (rev) rev.status = "approval_required";
      }
      doc.audit.unshift({
        id: `audit-${doc.id}-approved-${now()}`,
        action: "approval_requested",
        actorId: state.currentUserId,
        at: now(),
        detail: "All security findings remediated; ready for conformity approval.",
      });
      const actionId = `action-approval-${doc.id}`;
      if (!state.actions.some((a) => a.id === actionId)) {
        state.actions.unshift({
          id: actionId,
          type: "approval",
          priority: "urgent",
          title: `Approve ${doc.name}`,
          reason: "Security findings remediated; document is ready for authorized approval.",
          productId: doc.productId,
          releaseId: doc.releaseId,
          dueAt: new Date(Date.now() + 86400000).toISOString(),
          ownerId: state.currentUserId,
          status: "open",
          targetUrl: `/documents/${doc.id}`,
          updatedAt: now(),
        });
      }
    }
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
