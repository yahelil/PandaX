import {mkdir} from 'node:fs/promises';
import {chromium} from 'playwright-core';

const baseUrl = process.env.ACTIS_URL ?? 'http://127.0.0.1:4175';
const chromePath = process.env.CHROME_PATH ?? 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const output = new URL('../public/captures/', import.meta.url);
await mkdir(output, {recursive: true});

const browser = await chromium.launch({headless: true, executablePath: chromePath});
const page = await browser.newPage({viewport: {width: 1440, height: 900}, deviceScaleFactor: 1});
const ready = async () => { await page.waitForLoadState('networkidle'); await page.evaluate(() => document.fonts.ready); await page.waitForTimeout(240); };
const shot = async (name, path) => { await page.goto(`${baseUrl}${path}`, {waitUntil: 'networkidle'}); await ready(); await page.screenshot({path: new URL(`${name}.png`, output).pathname.slice(1), fullPage: false}); };

await page.goto(baseUrl, {waitUntil: 'networkidle'});
await page.evaluate(() => localStorage.removeItem('actis.demo-state.v1'));
await shot('actis-home', '/');
await shot('actis-products', '/products');
await shot('actis-product', '/products/product-home-hub');
await shot('actis-release', '/products/product-home-hub/releases/release-hub-1-8-0');
await shot('actis-finding', '/findings/finding-hub-cve-2026-38114');
await shot('actis-compliance', '/compliance?product=product-home-hub&release=release-hub-1-8-0');
await shot('actis-document', '/documents/document-hub-vex');
await page.getByRole('button', {name: 'Approve revision'}).click();
await page.getByText('Document approved. The immutable audit record has been updated.').waitFor();
await ready();
await page.screenshot({path: new URL('actis-document-approved.png', output).pathname.slice(1), fullPage: false});

await page.goto(`${baseUrl}/products/product-home-hub/releases/release-hub-1-8-0/analyze`, {waitUntil: 'networkidle'});
await ready();
await page.screenshot({path: new URL('actis-analysis-start.png', output).pathname.slice(1), fullPage: false});
await page.getByRole('radio', {name: /SBOM/}).check();
await page.getByRole('button', {name: 'Continue'}).click();
await page.locator('input[type="file"]').setInputFiles({name:'home-hub-1.8.0.cdx.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify({bomFormat:'CycloneDX',specVersion:'1.6',components:[{name:'openssl',version:'3.0.12'}]}))});
await page.getByRole('button', {name: 'Review and validate'}).click();
await page.getByRole('button', {name: 'Validate evidence'}).click();
await page.getByText('Detected format').waitFor();
await ready();
await page.screenshot({path: new URL('actis-analysis-preview.png', output).pathname.slice(1), fullPage: false});
await page.getByRole('button', {name: 'Continue'}).click();
await page.getByRole('button', {name: 'Run analysis'}).click();
await page.getByRole('heading', {name: 'Analysis in progress'}).waitFor();
await page.waitForTimeout(850);
await page.screenshot({path: new URL('actis-analysis-progress.png', output).pathname.slice(1), fullPage: false});
await page.getByRole('heading', {name: 'Analysis complete'}).waitFor({timeout:6000});
await ready();
await page.screenshot({path: new URL('actis-analysis-result.png', output).pathname.slice(1), fullPage: false});

await page.goto(`${baseUrl}/?product=product-home-hub&release=release-hub-1-8-0`, {waitUntil:'networkidle'});
await ready();
const darkButton = page.getByRole('button', {name:'Use dark theme'});
if (await darkButton.isVisible()) await darkButton.click();
await ready();
await page.screenshot({path: new URL('actis-home-dark.png', output).pathname.slice(1), fullPage:false});
await browser.close();
console.log(`Captured current Actis dashboard from ${baseUrl} at 1440x900`);
