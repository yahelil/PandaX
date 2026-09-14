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
  for (const width of [768, 1024, 1440, 1920]) {
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

async function assertVisible(locator, label) {
  if (await locator.count() < 1 || !await locator.first().isVisible()) {
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
    return { duplicateIds, unnamedControls: unnamedControls.length, unnamedImages: unnamedImages.length };
  });
  if (failures.duplicateIds.length || failures.unnamedControls || failures.unnamedImages) {
    throw new Error(`${label} accessibility basics failed: ${JSON.stringify(failures)}`);
  }
}
