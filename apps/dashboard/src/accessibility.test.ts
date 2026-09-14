import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const source = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");

describe("dashboard accessibility contracts", () => {
  it("keeps one page-level main landmark behind the bypass target", () => {
    const shell = source("./components/AppShell.tsx");
    expect(shell).toContain('href="#main-content"');
    expect(shell).toContain('<div id="main-content"');
    expect(shell).not.toContain('<main id="main-content"');

    for (const page of [
      "HomePage",
      "ProductsPage",
      "ProductWorkspacePage",
      "ReleaseWorkspacePage",
      "AnalysisPage",
      "AnalysisResultPage",
      "FindingsPage",
      "FindingDetailPage",
      "CompliancePage",
      "DocumentDetailPage",
      "SettingsPage",
      "NotFoundPage",
    ]) {
      expect(source(`./pages/${page}.tsx`), page).toContain("<main");
    }
  });

  it("names global controls and groups appearance choices", () => {
    expect(source("./components/HeaderSearch.tsx")).toContain('aria-label="Search products, releases, findings, and documents"');
    expect(source("./components/NotificationsMenu.tsx")).toContain('aria-label="Action-required notifications"');
    expect(source("./components/ThemeToggle.tsx")).toContain("aria-label={`Use ${theme === 'dark' ? 'light' : 'dark'} theme`}");

    const settings = source("./pages/SettingsPage.tsx");
    expect(settings).toContain("<fieldset");
    expect(settings).toContain("<legend>Theme</legend>");
    expect(settings).toContain('htmlFor="appearance-density"');
  });

  it("retains visible focus and reduced-motion safeguards", () => {
    const styles = source("./styles/global.css");
    expect(styles).toContain(":focus-visible");
    expect(styles).toContain("prefers-reduced-motion: reduce");
  });
});
