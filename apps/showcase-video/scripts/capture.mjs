import {mkdir} from 'node:fs/promises';
import {chromium} from 'playwright-core';

const baseUrl = process.env.PANDAX_URL ?? 'http://127.0.0.1:8000';
const chromePath = process.env.CHROME_PATH ?? 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const output = new URL('../public/captures/', import.meta.url);
await mkdir(output, {recursive: true});

const browser = await chromium.launch({headless: true, executablePath: chromePath});
const page = await browser.newPage({viewport: {width: 1440, height: 900}, deviceScaleFactor: 1});
await page.goto(baseUrl, {waitUntil: 'networkidle'});
await page.selectOption('#run-history', {index: 2});
await page.waitForFunction(() => document.querySelector('#decision-title')?.textContent !== 'No result selected');

for (const view of ['overview', 'findings', 'inventory', 'deadlines', 'documents', 'evidence']) {
  const route = {overview: 'overview', findings: 'vulns', inventory: 'artifacts', deadlines: 'article14', documents: 'reports', evidence: 'audit'}[view];
  await page.locator(`.nav[data-view="${route}"]`).click();
  await page.waitForTimeout(300);
  await page.screenshot({path: new URL(`${view}.png`, output).pathname.slice(1), fullPage: false});
}

await browser.close();
console.log(`Captured PandaX UI from ${baseUrl}`);
