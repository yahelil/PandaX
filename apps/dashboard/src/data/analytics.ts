import type { AnalyticsArea, PrivacySafeAnalyticsEvent } from "./governanceApi";

type AnalyticsEventName = PrivacySafeAnalyticsEvent["eventName"];

const areas = new Set<AnalyticsArea>([
  "home", "products", "releases", "findings", "compliance", "documents", "settings",
]);
const workflows = new Set(["release_analysis", "finding_decision", "document_approval", "self_filing_record"]);
const results = new Set(["succeeded", "failed", "cancelled"]);
const features = new Set(["search", "filter", "theme", "export", "scope_selector"]);
const errorAreas = new Set(["portfolio", "analysis", "monitoring", "findings", "compliance", "documents", "settings"]);
const errorCodes = new Set(["validation", "unauthorized", "forbidden", "not_found", "conflict", "unavailable", "timeout"]);

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function timestamp(value: unknown): string | undefined {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) return undefined;
  return value;
}

/**
 * Rebuilds an event from the analytics allowlist. Unknown keys are intentionally
 * discarded so runtime callers cannot attach search text, entity IDs, filenames,
 * user data, or secrets even when TypeScript is bypassed.
 */
export function sanitizeAnalyticsEvent(value: unknown): PrivacySafeAnalyticsEvent | undefined {
  const event = record(value);
  const properties = record(event?.properties);
  const occurredAt = timestamp(event?.occurredAt);
  if (!event || !properties || !occurredAt || typeof event.eventName !== "string") return undefined;

  switch (event.eventName as AnalyticsEventName) {
    case "page_viewed":
      return typeof properties.area === "string" && areas.has(properties.area as AnalyticsArea)
        ? { eventName: "page_viewed", properties: { area: properties.area as AnalyticsArea }, occurredAt }
        : undefined;
    case "workflow_completed":
      return typeof properties.workflow === "string" && workflows.has(properties.workflow)
        && typeof properties.result === "string" && results.has(properties.result)
        ? { eventName: "workflow_completed", properties: {
          workflow: properties.workflow as "release_analysis" | "finding_decision" | "document_approval" | "self_filing_record",
          result: properties.result as "succeeded" | "failed" | "cancelled",
        }, occurredAt }
        : undefined;
    case "feature_used":
      return typeof properties.feature === "string" && features.has(properties.feature)
        ? { eventName: "feature_used", properties: {
          feature: properties.feature as "search" | "filter" | "theme" | "export" | "scope_selector",
        }, occurredAt }
        : undefined;
    case "error_observed":
      return typeof properties.area === "string" && errorAreas.has(properties.area)
        && typeof properties.errorCode === "string" && errorCodes.has(properties.errorCode)
        ? { eventName: "error_observed", properties: {
          area: properties.area as "portfolio" | "analysis" | "monitoring" | "findings" | "compliance" | "documents" | "settings",
          errorCode: properties.errorCode as "validation" | "unauthorized" | "forbidden" | "not_found" | "conflict" | "unavailable" | "timeout",
        }, occurredAt }
        : undefined;
    default:
      return undefined;
  }
}

export function analyticsAreaForPath(pathname: string): AnalyticsArea | undefined {
  if (pathname === "/") return "home";
  if (pathname.startsWith("/findings")) return "findings";
  if (pathname.startsWith("/compliance")) return "compliance";
  if (pathname.startsWith("/documents")) return "documents";
  if (pathname.startsWith("/settings")) return "settings";
  if (pathname.startsWith("/analyses") || pathname.includes("/releases/")) return "releases";
  if (pathname.startsWith("/products")) return "products";
  return undefined;
}

export function pageViewed(area: AnalyticsArea, occurredAt = new Date().toISOString()): PrivacySafeAnalyticsEvent {
  return { eventName: "page_viewed", properties: { area }, occurredAt };
}

export function featureUsed(feature: "search" | "filter" | "theme" | "export" | "scope_selector", occurredAt = new Date().toISOString()): PrivacySafeAnalyticsEvent {
  return { eventName: "feature_used", properties: { feature }, occurredAt };
}
