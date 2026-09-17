import type { Finding } from "../data/types";

const DAY = 86_400_000;

function plusHours(value: string, hours: number): string {
  return new Date(new Date(value).getTime() + hours * 3_600_000).toISOString();
}

export function remediationDue(finding: Finding): string {
  if (finding.dueAt) return finding.dueAt;
  const days = finding.priority === "urgent" || finding.priority === "high" ? 14 : 30;
  return new Date(new Date(finding.introducedAt).getTime() + days * DAY).toISOString();
}

export function craReportingWindows(finding: Finding): { early: string; full: string } | undefined {
  if (finding.affectedness !== "confirmed" || !(finding.activelyExploited || finding.kev)) return undefined;
  return { early: plusHours(finding.introducedAt, 24), full: plusHours(finding.introducedAt, 72) };
}
