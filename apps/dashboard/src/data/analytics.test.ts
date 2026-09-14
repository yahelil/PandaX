import { describe, expect, it } from "vitest";

import { analyticsAreaForPath, featureUsed, pageViewed, sanitizeAnalyticsEvent } from "./analytics";

describe("privacy-safe dashboard analytics", () => {
  it("rebuilds events from the allowlist and strips identifying data", () => {
    const input = {
      eventName: "feature_used",
      properties: {
        feature: "search",
        query: "jane@acme.test CVE-2026-1234",
        productId: "product-private",
        accessToken: "secret",
      },
      occurredAt: "2026-09-14T10:00:00Z",
      userId: "member-jane",
    };

    expect(sanitizeAnalyticsEvent(input)).toEqual({
      eventName: "feature_used",
      properties: { feature: "search" },
      occurredAt: "2026-09-14T10:00:00Z",
    });
  });

  it("drops unknown names, property values, and invalid timestamps", () => {
    expect(sanitizeAnalyticsEvent({ eventName: "search_performed", properties: {}, occurredAt: "2026-09-14T10:00:00Z" })).toBeUndefined();
    expect(sanitizeAnalyticsEvent({ eventName: "feature_used", properties: { feature: "email_export" }, occurredAt: "2026-09-14T10:00:00Z" })).toBeUndefined();
    expect(sanitizeAnalyticsEvent({ eventName: "page_viewed", properties: { area: "products" }, occurredAt: "not-a-date" })).toBeUndefined();
  });

  it("reduces routes to coarse areas without retaining entity IDs", () => {
    expect(analyticsAreaForPath("/")).toBe("home");
    expect(analyticsAreaForPath("/products/product-secret/releases/release-private")).toBe("releases");
    expect(analyticsAreaForPath("/findings/finding-sensitive")).toBe("findings");
    expect(analyticsAreaForPath("/unknown/member-jane")).toBeUndefined();
  });

  it("constructs deterministic typed events when a timestamp is supplied", () => {
    const occurredAt = "2026-09-14T10:00:00Z";
    expect(pageViewed("home", occurredAt)).toEqual({ eventName: "page_viewed", properties: { area: "home" }, occurredAt });
    expect(featureUsed("search", occurredAt)).toEqual({ eventName: "feature_used", properties: { feature: "search" }, occurredAt });
  });
});
