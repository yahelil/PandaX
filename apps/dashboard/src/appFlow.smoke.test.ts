import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { createDemoState, DEMO_IDS } from "./data/fixtures";
import { FixtureAdapter } from "./data/fixtureAdapter";

const source = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");

describe("application flow smoke contracts", () => {
  it("keeps every core workspace destination in the real route tree", () => {
    const app = source("./App.tsx");

    for (const route of [
      '<Route index element={<HomePage />} />',
      '<Route path="products" element={<ProductsPage />} />',
      '<Route path="products/:productId" element={<ProductWorkspacePage />} />',
      '<Route path="products/:productId/releases/:releaseId" element={<ReleaseWorkspacePage />} />',
      '<Route path="products/:productId/releases/:releaseId/analyze" element={<AnalysisPage />} />',
      '<Route path="findings" element={<FindingsPage />} />',
      '<Route path="findings/:findingId" element={<FindingDetailPage />} />',
      '<Route path="compliance" element={<CompliancePage />} />',
      '<Route path="documents/:documentId" element={<DocumentDetailPage />} />',
      '<Route path="settings/:section" element={<SettingsPage />} />',
    ]) {
      expect(app, route).toContain(route);
    }
  });

  it("keeps navigation, bypass target, landmark ownership, and global controls named", () => {
    const shell = source("./components/AppShell.tsx");
    const sidebar = source("./components/Sidebar.tsx");
    const topbar = source("./components/Topbar.tsx");
    const search = source("./components/HeaderSearch.tsx");

    expect(shell).toContain('href="#main-content"');
    expect(shell).toContain('<div id="main-content"');
    expect(sidebar).toContain('aria-label="Primary navigation"');
    for (const destination of ["Home", "Products", "Findings", "Compliance"]) {
      expect(sidebar).toContain(`label: '${destination}'`);
    }
    expect(sidebar).toContain("<span>Settings</span>");
    expect(topbar).toContain('aria-label="Open navigation"');
    expect(search).toContain('aria-label="Search products, releases, findings, and documents"');
    expect(source("./components/NotificationsMenu.tsx")).toContain('aria-label="Action-required notifications"');
    expect(source("./components/UserMenu.tsx")).toContain('aria-label="Open account menu"');

    for (const page of ["HomePage", "ProductsPage", "ProductWorkspacePage", "FindingDetailPage", "CompliancePage", "SettingsPage"]) {
      expect(source(`./pages/${page}.tsx`), page).toContain("<main");
    }
  });

  it("preserves explicit light/dark state and an accessible theme toggle", async () => {
    const adapter = new FixtureAdapter(createDemoState(), false);
    expect(adapter.getSnapshot().settings.appearance.theme).toBe("light");

    await adapter.updateSettings("appearance", { theme: "dark" });

    expect(adapter.getSnapshot().settings.appearance.theme).toBe("dark");
    expect(source("./components/ThemeProvider.tsx")).toContain("document.documentElement.dataset.theme = theme");
    expect(source("./components/ThemeToggle.tsx")).toContain("aria-label={`Use ${theme === 'dark' ? 'light' : 'dark'} theme`}");
  });

  it("registers a product and release that resolve through product workspace links", async () => {
    const adapter = new FixtureAdapter(createDemoState(), false);
    const product = await adapter.createProduct({
      name: "Industrial Sensor Gateway",
      identifier: "ACM-GTW-620",
      manufacturer: "Acme Devices GmbH",
      description: "Monitors safety-critical factory sensors and forwards signed telemetry.",
      craClass: "important_ii",
      classificationStatus: "review_required",
      supportUntil: "2032-12-31",
      ownerId: DEMO_IDS.jane,
    });
    const release = await adapter.createRelease({
      productId: product.id,
      version: "1.0.0",
      channel: "stable",
      releaseDate: "2026-09-14",
      supportedUntil: "2032-12-31",
    });

    expect(adapter.getSnapshot().products).toContainEqual(expect.objectContaining({
      id: product.id,
      name: "Industrial Sensor Gateway",
      activeReleaseId: release.id,
    }));
    expect(adapter.getSnapshot().releases).toContainEqual(expect.objectContaining({
      id: release.id,
      productId: product.id,
      sbomStatus: "missing",
    }));
    const workspace = source("./pages/ProductWorkspacePage.tsx");
    expect(workspace).toContain("`/products/${product.id}/releases/${release.id}`");
    expect(workspace).toContain("navigate(`/products/${productId}/releases/${created.id}/analyze`)");
  });

  it("persists a representative finding decision and remediation workflow", async () => {
    const adapter = new FixtureAdapter(createDemoState(), false);
    const findingId = "finding-hub-cve-2026-27102";
    const decided = await adapter.recordFindingDecision({
      findingId,
      decision: "affected",
      rationale: "Production build evidence confirms the reachable TLS validation path is enabled.",
    });
    const remediated = await adapter.updateRemediation({
      findingId,
      status: "planned",
      plan: "Upgrade curl, rebuild the release, and retain signed regression evidence.",
      targetDate: "2026-09-18",
    });

    expect(decided).toMatchObject({ affectedness: "confirmed", status: "action_required" });
    expect(decided.decisions.at(-1)).toMatchObject({
      decision: "affected",
      rationale: "Production build evidence confirms the reachable TLS validation path is enabled.",
    });
    expect(remediated).toMatchObject({
      remediation: {
        status: "planned",
        plan: "Upgrade curl, rebuild the release, and retain signed regression evidence.",
        targetDate: "2026-09-18",
      },
    });
    const detail = source("./pages/FindingDetailPage.tsx");
    for (const control of ['htmlFor="decision"', 'htmlFor="rationale"', 'htmlFor="plan"', 'htmlFor="target"']) {
      expect(detail).toContain(control);
    }
    expect(detail).toContain("Record decision");
    expect(detail).toContain("Save remediation plan");
  });
});
