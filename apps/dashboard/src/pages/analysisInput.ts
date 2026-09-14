import type { ReleaseArtifact } from "../data/types";

const accepted: Record<ReleaseArtifact["kind"], string> = {
  collector_package: ".zip,application/zip,application/x-zip-compressed",
  sbom: ".json,.spdx,.cdx,application/json,application/vnd.cyclonedx+json,application/spdx+json",
  raw_artifact: ".zip,.tar,.tar.gz,.tgz,.bin,.img,application/zip,application/x-zip-compressed,application/x-tar,application/gzip,application/x-gzip,application/octet-stream",
};

const hints: Record<ReleaseArtifact["kind"], string> = {
  collector_package: "Accepted: signed Actis Collector ZIP",
  sbom: "Accepted: CycloneDX JSON or SPDX JSON",
  raw_artifact: "Accepted: ZIP, TAR, TAR.GZ, TGZ, BIN, or IMG up to 50 MiB",
};

export function analysisInputAccept(kind: ReleaseArtifact["kind"]): string {
  return accepted[kind];
}

export function analysisInputHint(kind: ReleaseArtifact["kind"]): string {
  return hints[kind];
}
