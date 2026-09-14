import {mkdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {chromium} from 'playwright-core';

const baseUrl = process.env.ACTIS_URL ?? 'http://127.0.0.1:4176';
const chromePath = process.env.CHROME_PATH ?? 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const outputUrl = new URL('../public/client-demo/', import.meta.url);
const output = fileURLToPath(outputUrl);
await mkdir(output, {recursive: true});

const browser = await chromium.launch({headless: true, executablePath: chromePath});
const page = await browser.newPage({viewport: {width: 1920, height: 1080}, deviceScaleFactor: 1, colorScheme: 'light'});
const ready = async () => {
  await page.waitForLoadState('networkidle');
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(180);
};
const shot = async (name, path, hover) => {
  await page.goto(`${baseUrl}${path}`, {waitUntil: 'networkidle'});
  await ready();
  if (hover?.role) await page.getByRole(hover.role, {name: hover.name, exact: true}).hover();
  else if (hover?.name) await page.getByText(hover.name, {exact: true}).hover();
  await page.screenshot({path: fileURLToPath(new URL(`${name}.png`, outputUrl)), fullPage: false});
};

await page.goto(baseUrl, {waitUntil: 'networkidle'});
await page.evaluate(() => localStorage.removeItem('actis.demo-state.v1'));
await shot('portfolio', '/products/client-demo');
await shot('portfolio-home-hover', '/products/client-demo', {role: 'link', name: 'Home Hub'});
await shot('product', '/products/client-demo/home-hub?product=product-home-hub');
await shot('product-register-hover', '/products/client-demo/home-hub?product=product-home-hub', {role: 'link', name: 'Register new release'});
await shot('upload-empty', '/products/client-demo/upload?product=product-home-hub');
await shot('upload-empty-hover', '/products/client-demo/upload?product=product-home-hub', {name: 'Select release file'});
await shot('upload-selected', '/products/client-demo/upload?product=product-home-hub&selected=1');
await shot('upload-selected-hover', '/products/client-demo/upload?product=product-home-hub&selected=1', {role: 'link', name: 'Upload & analyze'});
await shot('alert', '/products/client-demo/alert?product=product-home-hub&release=release-hub-1-8-0');
await shot('alert-hover', '/products/client-demo/alert?product=product-home-hub&release=release-hub-1-8-0', {role: 'link', name: 'Review finding'});
for (const second of [59, 58, 57, 56]) {
  await shot(`finding-${second}`, `/findings/client-demo?product=product-home-hub&release=release-hub-1-8-0&clock=23%3A59%3A${second}`);
}
await shot('finding-documents-hover', '/findings/client-demo?product=product-home-hub&release=release-hub-1-8-0&clock=23%3A59%3A56', {role: 'link', name: 'Documents'});
await shot('documents', '/compliance/client-demo?product=product-home-hub&release=release-hub-1-8-0&clock=23%3A59%3A54');
await shot('documents-hover', '/compliance/client-demo?product=product-home-hub&release=release-hub-1-8-0&clock=23%3A59%3A54', {role: 'button', name: 'Download'});
await browser.close();
console.log(`Captured client demo from ${baseUrl} at 1920x1080`);
