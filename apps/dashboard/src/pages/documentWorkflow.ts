import type { DocumentDownloadMetadata, DocumentRecord, Role } from "../data/types";

export interface DocumentPermissions {
  canRead: boolean;
  canRevise: boolean;
  canRequestApproval: boolean;
  canDecideApproval: boolean;
  canRecordSelfFiling: boolean;
}

export function documentPermissions(
  roles: Role[],
  document: Pick<DocumentRecord, "status" | "completeness">,
): DocumentPermissions {
  const canRead = roles.length > 0;
  const canWrite = roles.includes("org_admin") || roles.includes("compliance_operator");
  const canApprove = roles.includes("authorized_approver");
  return {
    canRead,
    canRevise: canWrite,
    canRequestApproval: canWrite && document.status === "draft" && document.completeness === "complete",
    canDecideApproval: canApprove && document.status === "approval_required" && document.completeness === "complete",
    canRecordSelfFiling: canWrite && document.status === "approved" && document.completeness === "complete",
  };
}

export function createDownloadManifest(metadata: DocumentDownloadMetadata): string {
  return JSON.stringify({
    document_id: metadata.documentId,
    revision: metadata.version,
    filename: metadata.filename,
    format: metadata.format,
    content_type: metadata.contentType,
    size_bytes: metadata.sizeBytes,
    sha256: metadata.contentHash,
    storage_locator: metadata.storageLocator,
    retrieval: metadata.downloadType,
  }, null, 2);
}

