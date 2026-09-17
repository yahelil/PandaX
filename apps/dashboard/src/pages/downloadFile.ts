import type { AnalysisEvidenceFile } from "../data/releaseOperationsApi";

export function downloadFile(file: AnalysisEvidenceFile, fallbackName: string): void {
  const url = URL.createObjectURL(file.blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = file.filename || fallbackName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
