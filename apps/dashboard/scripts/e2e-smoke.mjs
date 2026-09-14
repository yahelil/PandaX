import { spawn } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright-core";

const dashboardRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const viteEntry = createRequire(import.meta.url).resolve("vite");
const viteBin = resolve(dirname(viteEntry), "../../bin/vite.js");
const port = Number.parseInt(process.env.ACTIS_E2E_PORT ?? "4178", 10);
const baseUrl = `http://127.0.0.1:${port}`;
const visualDir = process.env.ACTIS_E2E_VISUAL_DIR;
const browserCandidates = [
  process.env.ACTIS_E2E_BROWSER,
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/microsoft-edge",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
].filter(Boolean);
const executablePath = browserCandidates.find(existsSync);

if (!executablePath) {
  throw new Error("No supported system Chromium browser found. Set ACTIS_E2E_BROWSER to its executable path.");
}
if (!Number.isInteger(port) || port < 1 || port > 65_535) {
  throw new Error("ACTIS_E2E_PORT must be a valid TCP port.");
}

const serverOutput = [];
const server = spawn(process.execPath, [
  viteBin,
  "preview",
  "--configLoader", "runner",
  "--host", "127.0.0.1",
  "--port", String(port),
  "--strictPort",
], {
  cwd: dashboardRoot,
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true,
});
server.stdout.on("data", (chunk) => serverOutput.push(String(chunk)));
server.stderr.on("data", (chunk) => serverOutput.push(String(chunk)));

let browser;
try {
  await waitForPreview(server);
  browser = await chromium.launch({ executablePath, headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  await context.addInitScript(() => {
    globalThis.__actisVitals = { lcp: 0, cls: 0, longTaskMs: 0 };
    if (PerformanceObserver.supportedEntryTypes.includes("largest-contentful-paint")) {
      new PerformanceObserver((list) => {
        const entries = list.getEntries();
        globalThis.__actisVitals.lcp = entries.at(-1)?.startTime ?? 0;
      }).observe({ type: "largest-contentful-paint", buffered: true });
    }
    if (PerformanceObserver.supportedEntryTypes.includes("layout-shift")) {
      new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) if (!entry.hadRecentInput) globalThis.__actisVitals.cls += entry.value;
      }).observe({ type: "layout-shift", buffered: true });
    }
    if (PerformanceObserver.supportedEntryTypes.includes("longtask")) {
      new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) globalThis.__actisVitals.longTaskMs += entry.duration;
      }).observe({ type: "longtask", buffered: true });
    }
  });
  const page = await context.newPage();
  const browserErrors = [];
  page.on("console", (message) => {
    if (message.type() === "error") browserErrors.push(`console: ${message.text()}`);
  });
  page.on("pageerror", (error) => browserErrors.push(`page: ${error.message}`));

  await page.goto(baseUrl, { waitUntil: "networkidle" });
  await assertCoreShell(page);
  await assertSingleMain(page, "Home");
  await assertAccessibilityBasics(page, "Home");
  await assertKeyboardAccess(page);
  await assertThemeContrast(page, "light");
  for (const width of [640, 768, 1024, 1440, 1920]) {
    await page.setViewportSize({ width, height: 1000 });
    await assertNoHorizontalOverflow(page, `Home at ${width}px`);
    if (visualDir) {
      mkdirSync(visualDir, { recursive: true });
      await page.screenshot({ path: join(visualDir, `home-${width}.png`), fullPage: true });
    }
  }
  await page.setViewportSize({ width: 1440, height: 1000 });

  const themeToggle = page.getByRole("button", { name: "Use dark theme" });
  await assertVisible(themeToggle, "light-theme toggle");
  await themeToggle.click();
  await page.locator("html[data-theme='dark']").waitFor();
  await assertVisible(page.getByRole("button", { name: "Use light theme" }), "dark-theme toggle");
  await assertThemeContrast(page, "dark");

  await page.getByRole("link", { name: /^Products$/ }).click();
  await page.waitForURL(`${baseUrl}/products`);
  await assertSingleMain(page, "Products");
  await assertAccessibilityBasics(page, "Products");
  await assertVisible(page.getByRole("heading", { name: "Products", exact: true }), "Products heading");
  await assertVisible(page.getByRole("searchbox", { name: "Search products" }), "product search");

  await page.getByRole("link", { name: "Home Hub", exact: true }).first().click();
  await page.waitForURL(`${baseUrl}/products/product-home-hub`);
  await assertSingleMain(page, "Product workspace");
  await assertVisible(page.getByRole("heading", { name: "Home Hub", exact: true }), "Home Hub heading");
  await assertVisible(page.getByRole("heading", { name: "Finding insights", exact: true }), "conditional finding insights");
  await assertVisible(page.getByRole("heading", { name: "Analysis history", exact: true }), "immutable analysis history");
  await assertAccessibilityBasics(page, "Product workspace");
  if (visualDir) {
    await page.screenshot({ path: join(visualDir, "product-home-hub-dark-1440.png"), fullPage: true });
  }
  await page.getByRole("link", { name: /^Releases$/ }).click();
  await page.getByRole("link", { name: "1.8.0", exact: true }).click();
  await page.waitForURL(`${baseUrl}/products/product-home-hub/releases/release-hub-1-8-0`);
  await assertSingleMain(page, "Release workspace");
  await assertVisible(page.getByRole("link", { name: "Analyze release" }), "release analysis action");
  await page.getByRole("link", { name: "Analyze release" }).click();
  await page.waitForURL(`${baseUrl}/products/product-home-hub/releases/release-hub-1-8-0/analyze`);
  await assertSingleMain(page, "Analysis input");
  await assertAccessibilityBasics(page, "Analysis input");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.locator(".upload-zone input[type=file]").setInputFiles({
    name: "home-hub-1.8.0.zip", mimeType: "application/zip", buffer: Buffer.from("PK Actis collector evidence"),
  });
  await page.getByRole("button", { name: "Review and validate" }).click();
  const digestConfirmation = page.getByLabel(/changed release contents create a new immutable analysis snapshot/i);
  if (await digestConfirmation.count()) await digestConfirmation.check();
  await page.getByRole("button", { name: "Validate evidence" }).click();
  await page.getByRole("button", { name: "Continue" }).waitFor();
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Run analysis" }).click();
  await page.waitForURL(new RegExp(`${baseUrl}/analyses/analysis-`));
  await assertVisible(page.getByRole("heading", { name: "Analysis complete" }), "completed analysis", 5_000);
  await assertAccessibilityBasics(page, "Analysis result");

  await page.getByRole("complementary", { name: "Primary navigation" })
    .getByRole("link", { name: /^Findings / })
    .click();
  await page.waitForURL(`${baseUrl}/findings`);
  await assertSingleMain(page, "Findings");
  await page.getByRole("link", { name: "CVE-2026-27102", exact: true }).first().click();
  await page.waitForURL(`${baseUrl}/findings/finding-hub-cve-2026-27102`);
  await assertSingleMain(page, "Finding detail");
  await page.getByLabel("Decision").selectOption("affected");
  await page.getByLabel("Rationale").fill("Production build evidence confirms the reachable TLS validation path is enabled.");
  await page.getByRole("button", { name: "Record decision" }).click();
  await assertVisible(page.getByText("Decision recorded in the audit history."), "finding decision confirmation");
  await page.getByLabel("Plan").fill("Upgrade curl, rebuild the release, and retain signed regression evidence.");
  await page.getByLabel("Target date").fill("2026-09-18");
  await page.getByRole("button", { name: "Save remediation plan" }).click();
  await assertVisible(page.getByText("Remediation plan updated."), "remediation confirmation");

  await page.getByRole("complementary", { name: "Primary navigation" }).getByRole("link", { name: /^Compliance / }).click();
  await page.waitForURL(`${baseUrl}/compliance`);
  await assertSingleMain(page, "Compliance");
  await assertAccessibilityBasics(page, "Compliance");
  await assertVisible(page.getByRole("textbox", { name: "Search compliance work" }), "compliance search");
  await page.getByRole("button", { name: "Deadlines" }).click();
  await assertVisible(page.getByText("Submit initial incident notification", { exact: true }).first(), "deadline case");

  await page.getByRole("complementary", { name: "Primary navigation" }).getByRole("link", { name: /^Products$/ }).click();
  await page.getByRole("link", { name: "Smart Camera", exact: true }).first().click();
  await page.getByRole("navigation", { name: "Product workspace" }).getByRole("link", { name: "Documents" }).click();
  await page.getByRole("link", { name: "EU Declaration of Conformity — Smart Camera 2.4.1" }).click();
  await assertSingleMain(page, "Document detail");
  await assertAccessibilityBasics(page, "Document detail");
  await assertVisible(page.getByRole("button", { name: "Prepare download" }), "verified document download");
  await assertVisible(page.getByRole("tab", { name: "Audit" }), "document audit history tab");

  await page.getByRole("complementary", { name: "Primary navigation" }).getByRole("link", { name: /^Settings$/ }).click();
  await page.waitForURL(`${baseUrl}/settings/organization`);
  await page.getByRole("navigation", { name: "Settings sections" }).getByRole("link", { name: "Appearance" }).click();
  await assertSingleMain(page, "Settings");
  await assertAccessibilityBasics(page, "Settings");
  await assertVisible(page.getByRole("heading", { name: "Appearance" }), "appearance settings");
  await assertPerformanceBudgets(page);

  if (browserErrors.length) {
    throw new Error(`Browser emitted errors:\n${browserErrors.join("\n")}`);
  }

  console.log(`Actis dashboard E2E smoke passed with ${executablePath}`);
} finally {
  await browser?.close();
  server.kill();
}

async function waitForPreview(process) {
  const deadline = Date.now() + 12_000;
  while (Date.now() < deadline) {
    if (process.exitCode !== null) {
      throw new Error(`Dashboard preview exited before startup.\n${serverOutput.join("")}`);
    }
    try {
      const response = await fetch(baseUrl);
      if (response.ok) return;
    } catch {
      // Preview startup is asynchronous.
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));
  }
  throw new Error(`Dashboard preview did not start within 12 seconds.\n${serverOutput.join("")}`);
}

async function assertCoreShell(page) {
  await assertVisible(page.getByRole("complementary", { name: "Primary navigation" }), "primary navigation");
  await assertVisible(page.getByRole("searchbox", { name: "Search products, releases, findings, and documents" }), "workspace search");
  await assertVisible(page.getByRole("button", { name: "Action-required notifications" }), "notifications");
  await assertVisible(page.getByRole("button", { name: "Open account menu" }), "account menu");
  await assertVisible(page.getByRole("link", { name: "Skip to main content" }), "skip link");
}

async function assertSingleMain(page, label) {
  const count = await page.getByRole("main").count();
  if (count !== 1) throw new Error(`${label} must expose exactly one main landmark; found ${count}.`);
}

async function assertVisible(locator, label, timeout = 1_500) {
  try {
    await locator.first().waitFor({ state: "visible", timeout });
  } catch {
    throw new Error(`${label} is missing or not visible.`);
  }
}

async function assertNoHorizontalOverflow(page, label) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
  if (overflow) throw new Error(`${label} has horizontal page overflow.`);
}

async function assertAccessibilityBasics(page, label) {
  const failures = await page.evaluate(() => {
    const duplicateIds = [...document.querySelectorAll("[id]")].map((item) => item.id).filter((id, index, ids) => ids.indexOf(id) !== index);
    const unnamedControls = [...document.querySelectorAll("button,a[href],input,select,textarea")].filter((item) => {
      const element = item;
      return !((element.getAttribute("aria-label") || element.getAttribute("title") || element.textContent || "").trim() || (element instanceof HTMLInputElement && element.labels?.length));
    });
    const unnamedImages = [...document.querySelectorAll("img")].filter((item) => !item.hasAttribute("alt") && item.getAttribute("aria-hidden") !== "true");
    const unlabeledFields = [...document.querySelectorAll("input,select,textarea")].filter((item) => item.type !== "hidden" && !(item.labels?.length || item.getAttribute("aria-label") || item.getAttribute("aria-labelledby")));
    const positiveTabIndex = [...document.querySelectorAll("[tabindex]")].filter((item) => Number(item.getAttribute("tabindex")) > 0);
    const invalidReferences = [...document.querySelectorAll("[aria-labelledby],[aria-describedby]")].flatMap((item) => ["aria-labelledby", "aria-describedby"].flatMap((attribute) => (item.getAttribute(attribute) ?? "").split(/\s+/).filter(Boolean).filter((id) => !document.getElementById(id))));
    return {
      language: document.documentElement.lang,
      mainHeadings: document.querySelectorAll("main h1").length,
      duplicateIds,
      unnamedControls: unnamedControls.length,
      unnamedImages: unnamedImages.length,
      unlabeledFields: unlabeledFields.length,
      positiveTabIndex: positiveTabIndex.length,
      invalidReferences,
    };
  });
  if (failures.language !== "en" || failures.mainHeadings !== 1 || failures.duplicateIds.length || failures.unnamedControls || failures.unnamedImages || failures.unlabeledFields || failures.positiveTabIndex || failures.invalidReferences.length) {
    throw new Error(`${label} accessibility basics failed: ${JSON.stringify(failures)}`);
  }
}

async function assertKeyboardAccess(page) {
  await page.evaluate(() => {
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    window.scrollTo(0, 0);
  });
  await page.keyboard.press("Tab");
  const result = await page.evaluate(() => {
    const active = document.activeElement;
    const style = active ? getComputedStyle(active) : null;
    return { text: active?.textContent?.trim(), outline: style?.outlineStyle, width: style?.outlineWidth };
  });
  if (result.text !== "Skip to main content" || result.outline === "none" || result.width === "0px") {
    throw new Error(`Keyboard skip navigation or visible focus failed: ${JSON.stringify(result)}`);
  }
  await page.keyboard.press("Enter");
  const mainFocused = await page.evaluate(() => {
    const target = document.getElementById("main-content");
    return document.activeElement === target && Boolean(target?.querySelector("main"));
  });
  if (!mainFocused) throw new Error("Skip navigation did not move keyboard focus to main content.");
}

async function assertThemeContrast(page, theme) {
  const ratios = await page.evaluate(() => {
    const root = getComputedStyle(document.documentElement);
    const parse = (value) => {
      const match = value.trim().match(/^#([0-9a-f]{6})$/i);
      if (!match) throw new Error(`Expected a six-digit color token, got ${value}`);
      return [0, 2, 4].map((offset) => Number.parseInt(match[1].slice(offset, offset + 2), 16) / 255);
    };
    const luminance = (rgb) => rgb.map((value) => value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4).reduce((sum, value, index) => sum + value * [.2126, .7152, .0722][index], 0);
    const ratio = (foreground, background) => {
      const values = [luminance(parse(root.getPropertyValue(foreground))), luminance(parse(root.getPropertyValue(background)))].sort((a, b) => b - a);
      return (values[0] + .05) / (values[1] + .05);
    };
    return { text: ratio("--text", "--surface"), muted: ratio("--text-muted", "--surface"), accent: ratio("--accent", "--surface") };
  });
  for (const [token, ratio] of Object.entries(ratios)) if (ratio < 4.5) throw new Error(`${theme} ${token} contrast is ${ratio.toFixed(2)}; expected at least 4.5.`);
}

async function assertPerformanceBudgets(page) {
  await page.waitForTimeout(100);
  const metrics = await page.evaluate(() => {
    const navigation = performance.getEntriesByType("navigation")[0];
    return { ...globalThis.__actisVitals, domContentLoaded: navigation?.domContentLoadedEventEnd ?? 0, domNodes: document.querySelectorAll("*").length };
  });
  if (metrics.lcp > 5_000 || metrics.cls > .1 || metrics.longTaskMs > 1_500 || metrics.domContentLoaded > 5_000 || metrics.domNodes > 3_000) {
    throw new Error(`Performance budget exceeded: ${JSON.stringify(metrics)}`);
  }
  console.log(`Performance budgets passed: ${JSON.stringify(metrics)}`);
}
