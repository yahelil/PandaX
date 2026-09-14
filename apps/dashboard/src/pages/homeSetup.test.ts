import { describe, expect, it } from "vitest";

import { homeSetupMode } from "./homeSetup";

describe("Home setup presentation", () => {
  it("replaces Home only for an unscoped organization without products", () => {
    expect(homeSetupMode({ isScoped: false, hasProduct: false, setupComplete: false })).toBe("replace");
  });

  it("keeps operational Home visible while an established organization finishes setup", () => {
    expect(homeSetupMode({ isScoped: false, hasProduct: true, setupComplete: false })).toBe("supplemental");
  });

  it("hides organization setup in scoped and completed views", () => {
    expect(homeSetupMode({ isScoped: true, hasProduct: true, setupComplete: false })).toBe("hidden");
    expect(homeSetupMode({ isScoped: false, hasProduct: true, setupComplete: true })).toBe("hidden");
  });
});
