import type { Finding, Severity } from "./types";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_DETAIL_URL = "https://api.osv.dev/v1/vulns/";

interface Component {
  name: string;
  version: string;
  purl: string;
}

interface OsvDetail {
  id: string;
  aliases?: string[];
  summary?: string;
  severity?: { type?: string; score?: string }[];
  database_specific?: { severity?: string };
}

export interface SbomAnalysis {
  components: number;
  matchableComponents: number;
  findings: Finding[];
}

export type SbomAnalyzer = (file: Blob, productId: string, releaseId: string) => Promise<SbomAnalysis>;

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("SBOM must contain a JSON object.");
  return value as Record<string, unknown>;
}

function componentsFrom(document: Record<string, unknown>): Component[] {
  const rows = document.bomFormat === "CycloneDX" ? document.components : document.packages;
  if (!Array.isArray(rows)) throw new Error("SBOM does not contain a component inventory.");
  return rows.flatMap((value) => {
    const item = object(value);
    const externalRefs = Array.isArray(item.externalRefs) ? item.externalRefs : [];
    const purlRef = externalRefs.map(object).find((ref) => String(ref.referenceType ?? "").toLowerCase() === "purl");
    const purl = String(item.purl ?? purlRef?.referenceLocator ?? "");
    return purl.startsWith("pkg:") && purl.includes("@") ? [{
      name: String(item.name ?? "Unknown component"),
      version: String(item.version ?? item.versionInfo ?? ""),
      purl,
    }] : [];
  });
}

function severity(detail: OsvDetail): { severity: Severity; cvss: number } {
  const named = detail.database_specific?.severity?.toLowerCase();
  if (named === "critical") return { severity: "critical", cvss: 9 };
  if (named === "high") return { severity: "high", cvss: 7 };
  if (named === "moderate" || named === "medium") return { severity: "medium", cvss: 5 };
  return { severity: "low", cvss: 3 };
}

async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  if (!response.ok) throw new Error(`OSV request failed (${response.status}).`);
  return response.json() as Promise<T>;
}

async function details(ids: string[]): Promise<Map<string, OsvDetail>> {
  const result = new Map<string, OsvDetail>();
  for (let start = 0; start < ids.length; start += 8) {
    const chunk = ids.slice(start, start + 8);
    const values = await Promise.all(chunk.map((id) => json<OsvDetail>(`${OSV_DETAIL_URL}${encodeURIComponent(id)}`)));
    values.forEach((value) => result.set(value.id, value));
  }
  return result;
}

export const analyzeSbomWithOsv: SbomAnalyzer = async (file, productId, releaseId) => {
  const document = object(JSON.parse(await file.text()));
  const sourceRows = document.bomFormat === "CycloneDX" ? document.components : document.packages;
  const componentCount = Array.isArray(sourceRows) ? sourceRows.length : 0;
  const components = componentsFrom(document);
  if (!components.length) throw new Error("SBOM has no components with a usable, versioned Package URL (purl).");
  const results: { vulns?: { id: string }[] }[] = [];
  for (let start = 0; start < components.length; start += 1_000) {
    const chunk = components.slice(start, start + 1_000);
    const response = await json<{ results: { vulns?: { id: string }[] }[] }>(OSV_BATCH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries: chunk.map((component) => ({ package: { purl: component.purl } })) }),
    });
    if (!Array.isArray(response.results) || response.results.length !== chunk.length) {
      throw new Error("OSV returned an incomplete response.");
    }
    results.push(...response.results);
  }
  const matches = results.flatMap((entry, index) => (entry.vulns ?? []).map((item) => ({
    id: item.id,
    component: components[index],
  })));
  const byId = await details([...new Set(matches.map((match) => match.id))]);
  const now = new Date().toISOString();
  const findings = matches.map(({ id, component }, index): Finding => {
    const detail = byId.get(id) ?? { id };
    const rating = severity(detail);
    const reference = detail.aliases?.find((alias) => alias.startsWith("CVE-")) ?? id;
    return {
      id: `finding-${releaseId}-${index + 1}`,
      reference,
      productId,
      releaseId,
      title: detail.summary?.trim() || `OSV advisory for ${component.name}`,
      component: component.name,
      componentVersion: component.version,
      ...rating,
      status: "needs_review",
      priority: rating.severity === "critical" ? "urgent" : rating.severity === "high" ? "high" : rating.severity === "medium" ? "normal" : "low",
      kev: false,
      activelyExploited: false,
      affectedness: "unknown",
      reachability: "unknown",
      reachabilityRecommendation: "review",
      reachabilityConfidence: "low",
      reachabilityReasonCodes: ["sbom_component_match"],
      reachabilityReviewRequired: true,
      summary: detail.summary?.trim() || `OSV returned ${id} for ${component.purl}.`,
      actionReason: "Review affectedness and runtime reachability.",
      introducedAt: now,
      updatedAt: now,
      decisions: [],
      remediation: { status: "not_started" },
      evidenceIds: [],
    };
  });
  return { components: componentCount, matchableComponents: components.length, findings };
};
