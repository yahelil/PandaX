import { describe, expect, it } from "vitest";

import { homeSetupMode } from "./homeSetup";

describe("Home setup presentation", () => {
  it("replaces Home only for an unscoped organization without products", () => {
    expect(homeSetupMode({ isScoped: false, hasProduct: false })).toBe("replace");
  });

  it("shows operational Home without a setup checklist once products exist", () => {
    expect(homeSetupMode({ isScoped: false, hasProduct: true })).toBe("hidden");
  });

  it("hides organization setup in a product-scoped view", () => {
    expect(homeSetupMode({ isScoped: true, hasProduct: true })).toBe("hidden");
  });
});
