import { chromium } from 'playwright-core';
import fs from 'node:fs/promises';
import path from 'node:path';

const edgePath = 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
const baseUrl = process.argv[2] ?? process.env.BAKULA_UI_URL ?? 'http://127.0.0.1:8099/';
const outDir = process.argv[3] ?? 'D:/Bakula/bakula-program/workspace_fullstack';

await fs.mkdir(outDir, { recursive: true });
const browser = await chromium.launch({ executablePath: edgePath, headless: true });
const results = [];

async function checkViewport(name, viewport, url = baseUrl) {
  const context = await browser.newContext({ viewport, deviceScaleFactor: 1 });
  const page = await context.newPage();
  await page.goto(url, { waitUntil: 'networkidle' });
  await page.waitForSelector('#app .panel-shell', { timeout: 20000 });
  await page.waitForTimeout(600);
  const state = await page.evaluate(() => ({
    scrollHeight: document.documentElement.scrollHeight,
    innerHeight: window.innerHeight,
    innerWidth: window.innerWidth,
    graphNodes: document.querySelectorAll('[data-node-id]').length,
    focus: new URL(window.location.href).searchParams.get('focus'),
  }));
  const screenshot = path.join(outDir, `ui-visual-${name}.png`);
  await page.screenshot({ path: screenshot, fullPage: false });
  results.push({ name, url, viewport, screenshot, ...state, fitsViewport: state.scrollHeight <= state.innerHeight + 2 });
  await context.close();
}

await checkViewport('desktop', { width: 1600, height: 1000 });
await checkViewport('tablet', { width: 1180, height: 820 });
await checkViewport('mobile', { width: 430, height: 932 });

const hoverContext = await browser.newContext({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 1 });
const hoverPage = await hoverContext.newPage();
await hoverPage.goto(`${baseUrl}?focus=topology`, { waitUntil: 'networkidle' });
await hoverPage.waitForSelector('[data-node-id]', { timeout: 20000 });
await hoverPage.hover('[data-node-id]');
await hoverPage.waitForTimeout(300);
const tooltipVisible = await hoverPage.evaluate(() => document.querySelector('.graph-tooltip')?.classList.contains('is-visible') ?? false);
const hoverScreenshot = path.join(outDir, 'ui-visual-hover-topology.png');
await hoverPage.screenshot({ path: hoverScreenshot, fullPage: false });
results.push({ name: 'hover-topology', url: `${baseUrl}?focus=topology`, screenshot: hoverScreenshot, tooltipVisible });
await hoverContext.close();

await browser.close();
const reportPath = path.join(outDir, 'ui-visual-check.json');
await fs.writeFile(reportPath, JSON.stringify(results, null, 2), 'utf8');
console.log(reportPath);
console.log(JSON.stringify(results, null, 2));
