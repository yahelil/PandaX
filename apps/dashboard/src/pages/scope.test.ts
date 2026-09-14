import { describe, expect, it } from "vitest";
import { matchesScope, scopedPath, scopeFromParams } from "./scope";

describe("workspace scope", () => {
  it("reads product and release scope and filters exact targets", () => {
    const scope = scopeFromParams(new URLSearchParams("product=product-1&release=release-2"));
    expect(scope).toEqual({ productId: "product-1", releaseId: "release-2" });
    expect(matchesScope({ productId: "product-1", releaseId: "release-2" }, scope)).toBe(true);
    expect(matchesScope({ productId: "product-1", releaseId: "release-3" }, scope)).toBe(false);
    expect(matchesScope({ productId: "product-2", releaseId: "release-2" }, scope)).toBe(false);
  });

  it("preserves scope when linking to a filtered workspace", () => {
    expect(scopedPath("/compliance", { productId: "product/1", releaseId: "release 2" }, { view: "monitoring" }))
      .toBe("/compliance?view=monitoring&product=product%2F1&release=release+2");
  });
});
