import { chromium } from 'playwright-core';

const browser = await chromium.launch({ executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
const baseUrl = process.argv[2] ?? process.env.BAKULA_UI_URL ?? 'http://127.0.0.1:8099/';
await page.goto(baseUrl, { waitUntil: 'networkidle' });
await page.waitForSelector('.workspace-grid');
const data = await page.evaluate(() => {
  const pick = (sel) => {
    const el = document.querySelector(sel);
    if (!el) return null;
    const r = el.getBoundingClientRect();
    return { sel, x: r.x, y: r.y, right: r.right, bottom: r.bottom, width: r.width, height: r.height, within: r.x >= 0 && r.y >= 0 && r.right <= window.innerWidth && r.bottom <= window.innerHeight };
  };
  const overlap = (a, b) => !(a.right <= b.x || b.right <= a.x || a.bottom <= b.y || b.bottom <= a.y);
  const left = pick('.left-rail');
  const center = pick('.center-stage');
  const right = pick('.right-stage');
  const hero = pick('#auditHeroBlock');
  const tabs = pick('#auditTabsBlock');
  const detail = pick('#auditDetailBlock');
  const checks = Array.from(document.querySelectorAll('[data-check-wrap="true"]')).map((el) => ({
    text: el.textContent?.slice(0, 50) ?? '',
    scrollW: el.scrollWidth,
    clientW: el.clientWidth,
    overflow: el.scrollWidth > el.clientWidth + 1,
  }));
  return {
    left, center, right, hero, tabs, detail,
    overlaps: {
      heroTabs: hero && tabs ? overlap(hero, tabs) : null,
      tabsDetail: tabs && detail ? overlap(tabs, detail) : null,
    },
    textOverflow: checks.filter((item) => item.overflow),
  };
});
console.log(JSON.stringify(data, null, 2));
await browser.close();
