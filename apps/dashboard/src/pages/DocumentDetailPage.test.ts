import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const source = readFileSync(new URL("./DocumentDetailPage.tsx", import.meta.url), "utf8");

describe("document detail states", () => {
  it("renders explicit loading, recoverable error, and busy states", () => {
    expect(source).toContain("Loading document");
    expect(source).toContain('role={feedback.tone === "error" ? "alert" : "status"}');
    expect(source).toContain('aria-busy={Boolean(busy)}');
    expect(source).toContain('disabled={busy === "download"}');
  });

  it("does not present fixture-only export wording", () => {
    expect(source).not.toContain("Demo export");
    expect(source).toContain("Export download manifest");
    expect(source).toContain("Document bytes remain in configured evidence storage");
  });
});

