import type { ReleaseArtifact } from "../data/types";

const accepted: Record<ReleaseArtifact["kind"], string> = {
  collector_package: ".zip,application/zip,application/x-zip-compressed",
  sbom: ".json,application/json,application/vnd.cyclonedx+json,application/spdx+json",
  raw_artifact: ".zip,.tar,.tar.gz,.tgz,application/zip,application/x-zip-compressed,application/x-tar,application/gzip,application/x-gzip",
};

const hints: Record<ReleaseArtifact["kind"], string> = {
  collector_package: "Accepted: signed Actis Collector ZIP",
  sbom: "Supported JSON SBOMs: CycloneDX 1.2 or 1.6, and SPDX 2.2 or 2.3. The format and version are detected from the file.",
  raw_artifact: "Accepted: source or build ZIP, TAR, TAR.GZ, or TGZ up to 50 MB. The archive is uploaded to Actis for analysis.",
};

export function analysisInputAccept(kind: ReleaseArtifact["kind"]): string {
  return accepted[kind];
}

export function analysisInputHint(kind: ReleaseArtifact["kind"]): string {
  return hints[kind];
}

export async function validateSbomFormatVersion(file: Blob): Promise<void> {
  let document: unknown;
  try { document = JSON.parse((await file.text()).replace(/^\uFEFF/, "")); }
  catch { throw new Error("SBOM must be a valid JSON file."); }
  if (!document || typeof document !== "object" || Array.isArray(document)) throw new Error("SBOM must contain a JSON object.");
  const fields = document as Record<string, unknown>;
  if (fields.bomFormat === "CycloneDX") {
    if (fields.specVersion === "1.2" || fields.specVersion === "1.6") return;
    throw new Error("Unsupported CycloneDX version. Use CycloneDX JSON 1.2 or 1.6.");
  }
  if (typeof fields.spdxVersion === "string") {
    if (fields.spdxVersion === "SPDX-2.2" || fields.spdxVersion === "SPDX-2.3") return;
    throw new Error("Unsupported SPDX version. Use SPDX JSON 2.2 or 2.3.");
  }
  throw new Error("Unsupported SBOM format. Use CycloneDX JSON 1.2 or 1.6, or SPDX JSON 2.2 or 2.3.");
}
