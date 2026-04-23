import { chromium } from 'playwright-core';
import fs from 'node:fs/promises';
import path from 'node:path';

const edgePath = 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
const baseUrl = process.argv[2] ?? process.env.BAKULA_UI_URL ?? 'http://127.0.0.1:8099/';
const outDir = process.argv[3] ?? 'D:/Bakula/bakula-program/workspace_fullstack';

await fs.mkdir(outDir, { recursive: true });

const browser = await chromium.launch({ executablePath: edgePath, headless: true });
const page = await browser.newPage({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 1 });

await page.goto(baseUrl, { waitUntil: 'networkidle' });
await page.waitForSelector('.workspace-grid');
await page.waitForSelector('.control-panel');
await page.waitForTimeout(600);

const controlCheck = await page.evaluate(() => {
  const panel = document.querySelector('.control-panel');
  const text = panel?.textContent ?? '';
  return {
    text,
    hasActions:
      /Start|Reset|Reload|Live|Manual/.test(text),
  };
});

const desktopShot = path.join(outDir, 'ui-proof-desktop.png');
await page.screenshot({ path: desktopShot, fullPage: false });

await page.click('[data-chat-toggle]');
await page.waitForSelector('#chatLog');
await page.click('[data-chat-prompt="Co mám řešit jako první?"]');
await page.waitForFunction(() => document.querySelectorAll('.chat-bubble').length >= 3, undefined, { timeout: 60000 });
await page.waitForFunction(() => !document.querySelector('.chat-bubble.is-loading'), undefined, { timeout: 60000 });
await page.waitForFunction(() => !document.querySelector('.chat-bubble.is-streaming'), undefined, { timeout: 60000 });
await page.waitForTimeout(500);

await page.fill('#chatInput', 'rozepsany dotaz bez odeslani');
await page.focus('#chatInput');
await page.waitForTimeout(4600);
const typingStability = await page.evaluate(() => {
  const input = document.querySelector('#chatInput');
  return {
    focused: document.activeElement === input,
    value: input?.value ?? '',
  };
});

const chatCheck = await page.evaluate(() => {
  const log = document.querySelector('#chatLog');
  const hero = document.querySelector('#auditHeroBlock');
  const controlPanel = document.querySelector('.control-panel');
  if (!log || !hero || !controlPanel) return null;
  const rect = log.getBoundingClientRect();
  const controlRect = controlPanel.getBoundingClientRect();
  const heroRect = hero.getBoundingClientRect();
  return {
    bubbles: document.querySelectorAll('.chat-bubble').length,
    scrolledToBottom: Math.abs(log.scrollTop - (log.scrollHeight - log.clientHeight)) <= 8,
    hasSourceChips: document.querySelectorAll('.chat-source-row .tiny-chip').length > 0,
    controlWithinViewport: controlRect.bottom <= window.innerHeight + 2,
    chatWithinViewport: rect.bottom <= window.innerHeight + 2,
    heroWithinViewport: heroRect.bottom <= window.innerHeight + 2,
    noRightPanelTextOverflow: Array.from(document.querySelectorAll('.right-stage .detail-card strong, .right-stage .tiny-chip, .right-stage .mode-chip, .chat-bubble'))
      .every((item) => item.scrollWidth <= item.clientWidth + 2 || getComputedStyle(item).whiteSpace !== 'nowrap'),
  };
});

const beforeE = new URL(page.url()).searchParams.get('focus') ?? '';
await page.keyboard.press('E');
await page.waitForTimeout(150);
const afterE = new URL(page.url()).searchParams.get('focus') ?? '';

const chatShot = path.join(outDir, 'ui-proof-chat.png');
await page.screenshot({ path: chatShot, fullPage: false });

const output = {
  baseUrl,
  controlCheck,
  chatCheck,
  keyboardCheck: {
    eDoesNotToggleFocus: beforeE === afterE,
  },
  typingStability,
  screenshots: {
    desktop: desktopShot,
    chat: chatShot,
  },
};

if (!chatCheck?.noRightPanelTextOverflow) {
  throw new Error('Right panel text overflow detected.');
}
if (beforeE !== afterE) {
  throw new Error('Keyboard shortcut E still toggles focus.');
}
if (!typingStability.focused || typingStability.value !== 'rozepsany dotaz bez odeslani') {
  throw new Error('Chat input lost focus or content during live refresh.');
}

const reportPath = path.join(outDir, 'ui-helpdesk-check.json');
await fs.writeFile(reportPath, JSON.stringify(output, null, 2), 'utf8');
console.log(reportPath);
console.log(JSON.stringify(output, null, 2));

await browser.close();
