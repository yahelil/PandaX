import { describe, expect, it } from "vitest";

import { createDemoState } from "./fixtures";
import { FixtureAdapter } from "./fixtureAdapter";
import type { DocumentDetailDto } from "./governanceApi";
import { mapDocument } from "./productionAdapter";

describe("document adapter workflow", () => {
  it("runs approval, download metadata, self-filing, and revision transitions", async () => {
    const adapter = new FixtureAdapter(createDemoState());
    const draft = adapter.getSnapshot().documents.find((item) => item.id === "document-hub-vex")!;

    expect(adapter.requestDocumentApproval(draft.id, "Evidence reviewed").status).toBe("approval_required");
    expect(adapter.approveDocument(draft.id, "Approved").status).toBe("approved");
    await expect(adapter.getDocumentDownload(draft.id)).resolves.toMatchObject({
      documentId: draft.id,
      version: draft.version,
      downloadType: "storage_metadata_only",
    });
    expect(adapter.recordDocumentSelfFiling({
      documentId: draft.id,
      externalSubmissionReference: "ENISA-2026-0014",
      submittedAt: "2026-09-14T11:00:00Z",
      receiptEvidenceLocator: "s3://evidence/enisa-2026-0014.json",
    })).toMatchObject({ status: "self_filed", selfFilings: [{ externalSubmissionReference: "ENISA-2026-0014" }] });

    const revised = adapter.addDocumentRevision({
      documentId: draft.id,
      format: "CSAF VEX",
      contentHash: "a".repeat(64),
      storageLocator: "s3://evidence/home-hub-vex-v2.json",
      sizeBytes: 4096,
      completeness: "limited_coverage",
    });
    expect(revised).toMatchObject({ version: draft.version + 1, status: "draft", completeness: "limited_coverage" });
  });

  it("fails closed when production provenance omits completeness", () => {
    const revision = {
      id: "revision-1", organizationId: "org-1", documentId: "document-1", revision: 1,
      format: "pdf_a_2b" as const, contentHash: "b".repeat(64), storageLocator: "s3://evidence/report.pdf",
      sizeBytes: 2048, provenance: {}, createdBy: "member-1", createdAt: "2026-09-14T10:00:00Z", status: "draft" as const,
    };
    const detail: DocumentDetailDto = {
      document: { id: "document-1", organizationId: "org-1", productId: "product-1", kind: "cra_reporting_pack", name: "CRA report", currentRevision: 1, createdBy: "member-1", createdAt: revision.createdAt, updatedAt: revision.createdAt, status: "draft", current: revision },
      revisions: [revision], audit: [], approvalHistory: [], selfFilings: [],
    };

    expect(mapDocument(detail)).toMatchObject({ completeness: "missing_inputs", revisions: [{ completeness: "missing_inputs" }] });
  });
});
