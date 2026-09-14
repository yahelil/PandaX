import { describe, expect, it } from "vitest";

import type { DocumentDownloadMetadata, DocumentRecord, Role } from "../data/types";
import { createDownloadManifest, documentPermissions } from "./documentWorkflow";

const base = { status: "draft", completeness: "complete" } satisfies Pick<DocumentRecord, "status" | "completeness">;

describe("document workflow permissions", () => {
  it.each([
    [["compliance_operator"], base, { canRevise: true, canRequestApproval: true, canDecideApproval: false, canRecordSelfFiling: false }],
    [["authorized_approver"], { status: "approval_required", completeness: "complete" }, { canRevise: false, canRequestApproval: false, canDecideApproval: true, canRecordSelfFiling: false }],
    [["read_only_auditor"], { status: "approved", completeness: "complete" }, { canRevise: false, canRequestApproval: false, canDecideApproval: false, canRecordSelfFiling: false }],
    [["org_admin"], { status: "approved", completeness: "complete" }, { canRevise: true, canRequestApproval: false, canDecideApproval: false, canRecordSelfFiling: true }],
  ] as Array<[Role[], Pick<DocumentRecord, "status" | "completeness">, Partial<ReturnType<typeof documentPermissions>>]>) (
    "enforces backend roles for %j",
    (roles, document, expected) => expect(documentPermissions(roles, document)).toMatchObject(expected),
  );

  it("blocks approval and submission while evidence is incomplete", () => {
    expect(documentPermissions(["org_admin", "authorized_approver"], { status: "approval_required", completeness: "missing_inputs" })).toMatchObject({
      canRequestApproval: false,
      canDecideApproval: false,
      canRecordSelfFiling: false,
    });
  });
});

it("exports exact download metadata without claiming document bytes", () => {
  const metadata: DocumentDownloadMetadata = {
    documentId: "document-1", version: 4, filename: "report.pdf", format: "PDF/A-2b",
    contentHash: "a".repeat(64), sizeBytes: 9042, storageLocator: "s3://evidence/report.pdf",
    contentType: "application/pdf", downloadType: "storage_metadata_only",
  };
  expect(JSON.parse(createDownloadManifest(metadata))).toEqual({
    document_id: "document-1", revision: 4, filename: "report.pdf", format: "PDF/A-2b",
    content_type: "application/pdf", size_bytes: 9042, sha256: "a".repeat(64),
    storage_locator: "s3://evidence/report.pdf", retrieval: "storage_metadata_only",
  });
});
