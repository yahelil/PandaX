import { describe, expect, it } from "vitest";
import { createDemoState } from "../data/fixtures";
import { createReleasePdf } from "../data/releasePdf";

describe("CRA Compliance Pipeline", () => {
  it("generates EU Declaration of Conformity draft PDF with valid PDF header", () => {
    const state = createDemoState();
    const product = state.products[0];
    const release = state.releases.find((r) => r.productId === product.id)!;
    const findings = state.findings.filter((f) => f.releaseId === release.id);

    const pdfBytes = createReleasePdf("declaration", product, release, findings);
    expect(pdfBytes).toBeInstanceOf(Uint8Array);
    expect(pdfBytes.length).toBeGreaterThan(100);

    // Verify PDF header magic bytes "%PDF-"
    const header = String.fromCharCode(...pdfBytes.slice(0, 5));
    expect(header).toBe("%PDF-");
  });

  it("generates Annex VII Technical Documentation draft PDF with valid PDF header", () => {
    const state = createDemoState();
    const product = state.products[0];
    const release = state.releases.find((r) => r.productId === product.id)!;
    const findings = state.findings.filter((f) => f.releaseId === release.id);

    const pdfBytes = createReleasePdf("technical", product, release, findings);
    expect(pdfBytes).toBeInstanceOf(Uint8Array);
    expect(pdfBytes.length).toBeGreaterThan(100);

    const header = String.fromCharCode(...pdfBytes.slice(0, 5));
    expect(header).toBe("%PDF-");
  });

  it("generates Product Security Report draft PDF with valid PDF header", () => {
    const state = createDemoState();
    const product = state.products[0];
    const release = state.releases.find((r) => r.productId === product.id)!;
    const findings = state.findings.filter((f) => f.releaseId === release.id);

    const pdfBytes = createReleasePdf("security", product, release, findings);
    expect(pdfBytes).toBeInstanceOf(Uint8Array);
    expect(pdfBytes.length).toBeGreaterThan(100);

    const header = String.fromCharCode(...pdfBytes.slice(0, 5));
    expect(header).toBe("%PDF-");
    const content = new TextDecoder().decode(pdfBytes);
    expect(content).toContain("Regulation \\(EU\\) 2024/2847");
    expect(content).toContain("Annex I");
    expect(content).toContain("11 September 2026");
    expect(content).not.toContain("0.09 0.16 0.29 rg");
  });
});
