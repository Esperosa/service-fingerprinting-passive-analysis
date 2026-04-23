import { chromium } from "playwright-core";
import fs from "node:fs/promises";
import path from "node:path";

const edgePath = "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
const baseUrl = process.argv[2] ?? process.env.BAKULA_UI_URL ?? "http://127.0.0.1:8099/";
const outDir = process.argv[3] ?? "D:/Bakula/bakula-program/workspace_fullstack";

await fs.mkdir(outDir, { recursive: true });

const browser = await chromium.launch({ executablePath: edgePath, headless: true });

async function auditViewport(name, viewport) {
  const context = await browser.newContext({ viewport, deviceScaleFactor: 1 });
  const page = await context.newPage();
  await page.goto(baseUrl, { waitUntil: "networkidle" });
  await page.waitForSelector(".workspace-grid", { timeout: 20000 });
  await page.waitForTimeout(500);

  const metrics = await page.evaluate(async () => {
    const rect = (sel) => {
      const el = document.querySelector(sel);
      if (!el) return null;
      const r = el.getBoundingClientRect();
      return { top: r.top, left: r.left, right: r.right, bottom: r.bottom, width: r.width, height: r.height };
    };
    const within = (box) => !!box && box.top >= 0 && box.left >= 0 && box.right <= window.innerWidth && box.bottom <= window.innerHeight;
    const overlaps = (a, b) => !!a && !!b && !(a.right <= b.left || b.right <= a.left || a.bottom <= b.top || b.bottom <= a.top);

    const hero = rect("#auditHeroBlock");
    const tabs = rect("#auditTabsBlock");
    const detail = rect("#auditDetailBlock");
    const focus = document.querySelector(".detail-focus-card");
    const focusCopy = focus?.querySelector(".detail-focus-copy");
    const focusOverflow = focusCopy ? focusCopy.scrollHeight > focusCopy.clientHeight + 2 : false;
    const assistantButton = document.querySelector(".audit-assistant-button");
    const progressCard = document.querySelector(".map-progress-card");
    const processRunning = progressCard?.classList.contains("is-running") ?? false;

    return {
      scrollHeight: document.documentElement.scrollHeight,
      innerHeight: window.innerHeight,
      innerWidth: window.innerWidth,
      fitsViewport: document.documentElement.scrollHeight <= window.innerHeight + 2,
      within: {
        hero: within(hero),
        tabs: tabs ? within(tabs) : true,
        detail: detail ? within(detail) : true,
      },
      overlaps: {
        heroTabs: overlaps(hero, tabs),
        tabsDetail: overlaps(tabs, detail),
      },
      textOverflow: [...document.querySelectorAll("[data-check-wrap='true']")]
        .filter((el) => el.scrollWidth > el.clientWidth + 2 || el.scrollHeight > el.clientHeight + 2)
        .slice(0, 8)
        .map((el) => el.textContent?.trim() ?? ""),
      focusOverflow,
      assistantButtonVisible: !!assistantButton,
      visibleGraphTitles: [...document.querySelectorAll(".graph-node-title")]
        .filter((el) => Number.parseFloat(getComputedStyle(el).opacity || "0") > 0.55).length,
      focusedEdges: document.querySelectorAll(".graph-edge-group.is-focused").length,
      dimmedEdges: document.querySelectorAll(".graph-edge-group.is-dimmed").length,
      graphNodes: document.querySelectorAll("[data-node-id]").length,
      graphEdges: document.querySelectorAll("[data-edge-id]").length,
      agentProbes: document.querySelectorAll(".graph-agent-probe").length,
      processRunning,
      progressCardVisible: !!progressCard && within(rect(".map-progress-card")),
    };
  });

  const shot = path.join(outDir, `ui-regression-${name}.png`);
  await page.screenshot({ path: shot, fullPage: false });
  await context.close();
  return { name, viewport, screenshot: shot, ...metrics };
}

const viewports = [
  { name: "desktop-1600", viewport: { width: 1600, height: 1000 } },
  { name: "laptop-1366", viewport: { width: 1366, height: 768 } },
  { name: "desktop-1920", viewport: { width: 1920, height: 1080 } },
  { name: "ultrawide-2560", viewport: { width: 2560, height: 1080 } },
];

const viewportResults = [];
for (const item of viewports) viewportResults.push(await auditViewport(item.name, item.viewport));

const readerContext = await browser.newContext({ viewport: { width: 1366, height: 768 }, deviceScaleFactor: 1 });
const readerPage = await readerContext.newPage();
await readerPage.goto(baseUrl, { waitUntil: "networkidle" });
await readerPage.waitForSelector(".center-mode-switch [data-center-mode='reader']", { timeout: 20000 });
const mapSwitchCenter = await readerPage.evaluate(() => {
  const rect = document.querySelector(".center-mode-switch")?.getBoundingClientRect();
  return rect ? rect.left + rect.width / 2 : 0;
});
await readerPage.click(".center-mode-switch [data-center-mode='reader']");
await readerPage.waitForSelector("[data-reader-surface='audit']", { timeout: 20000 });
await readerPage.click(".mode-chip[data-detail-scope='all']");
await readerPage.waitForTimeout(350);
const readerState = await readerPage.evaluate(() => {
  const article = document.querySelector(".reader-article");
  const articleRect = article?.getBoundingClientRect();
  const title = document.querySelector(".reader-card h2");
  const switchRect = document.querySelector(".center-mode-switch")?.getBoundingClientRect();
  const focusWrap = document.querySelector(".detail-focus-wrap");
  const lead = document.querySelector(".reader-hero p");
  return {
    readerVisible: !!document.querySelector("[data-reader-surface='audit']"),
    graphVisible: !!document.querySelector("[data-graph-surface='topology']"),
    articleWidth: articleRect?.width ?? 0,
    articleHeight: articleRect?.height ?? 0,
    switchCenter: switchRect ? switchRect.left + switchRect.width / 2 : 0,
    rightCards: document.querySelectorAll(".right-stage .detail-card").length,
    hasOwnList: !!document.querySelector(".reader-list"),
    rightFocusHidden: focusWrap ? getComputedStyle(focusWrap).display === "none" : false,
    title: title?.textContent?.trim() ?? "",
    titleOverflow: title ? title.scrollHeight > title.clientHeight + 2 || title.scrollWidth > title.clientWidth + 2 : false,
    allScopeActive: document.querySelector(".mode-chip[data-detail-scope='all']")?.classList.contains("is-active") ?? false,
    leadLength: lead?.textContent?.trim().length ?? 0,
    sectionCount: document.querySelectorAll(".reader-section").length,
    stepCount: document.querySelectorAll(".reader-steps li").length,
    factCount: document.querySelectorAll(".reader-fact-panel div").length,
  };
});
await readerPage.click(".tab-chip[data-detail-panel='assets']");
await readerPage.waitForTimeout(250);
await readerPage.click(".right-stage .detail-card[data-select-asset]");
await readerPage.waitForTimeout(250);
const readerAssetState = await readerPage.evaluate(() => ({
  activePanel: document.querySelector(".tab-chip.is-active")?.getAttribute("data-detail-panel") ?? null,
  rightCards: document.querySelectorAll(".right-stage .detail-card").length,
  title: document.querySelector(".reader-card h2")?.textContent?.trim() ?? "",
  readerVisible: !!document.querySelector("[data-reader-surface='audit']"),
}));
const readerShot = path.join(outDir, "ui-regression-reader.png");
await readerPage.screenshot({ path: readerShot, fullPage: false });
await readerContext.close();

const auditContext = await browser.newContext({ viewport: { width: 1366, height: 768 }, deviceScaleFactor: 1 });
const auditPage = await auditContext.newPage();
await auditPage.goto(baseUrl, { waitUntil: "networkidle" });
await auditPage.waitForSelector(".audit-focus-button", { timeout: 20000 });
const auditBefore = await auditPage.evaluate(() => ({
  rightWidth: document.querySelector(".right-stage")?.getBoundingClientRect().width ?? 0,
  focusParam: new URL(location.href).searchParams.get("focus"),
}));
await auditPage.click(".audit-focus-button");
await auditPage.waitForFunction(() => new URL(location.href).searchParams.get("focus") === "audit", undefined, { timeout: 10000 });
await auditPage.waitForTimeout(420);
const auditExpanded = await auditPage.evaluate(() => {
  const title = document.querySelector(".detail-focus-copy strong");
  const summary = document.querySelector(".detail-focus-copy p");
  const focusCard = document.querySelector(".detail-focus-card");
  const right = document.querySelector(".right-stage");
  const rightRect = right?.getBoundingClientRect();
  const focusRect = focusCard?.getBoundingClientRect();
  return {
    before: null,
    rightWidth: rightRect?.width ?? 0,
    focusWidth: focusRect?.width ?? 0,
    focusHeight: focusRect?.height ?? 0,
    title: title?.textContent?.trim() ?? "",
    summary: summary?.textContent?.trim() ?? "",
    focusParam: new URL(location.href).searchParams.get("focus"),
    buttonActive: document.querySelector(".audit-focus-button")?.classList.contains("is-active") ?? false,
    titleOverflow: title ? title.scrollHeight > title.clientHeight + 2 || title.scrollWidth > title.clientWidth + 2 : false,
  };
});
auditExpanded.before = auditBefore;
const auditExpandedShot = path.join(outDir, "ui-regression-audit-expanded.png");
await auditPage.screenshot({ path: auditExpandedShot, fullPage: false });
await auditContext.close();

const interactionContext = await browser.newContext({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 1 });
const page = await interactionContext.newPage();
await page.goto(baseUrl, { waitUntil: "networkidle" });
await page.waitForSelector("[data-node-id]", { timeout: 20000 });
const firstNodeId = await page.locator("[data-node-id]").evaluateAll((nodes) => {
  const ids = nodes
    .map((node) => node.getAttribute("data-node-id"))
    .filter(Boolean);
  return ids.find((id) => id && !id.startsWith("hub:") && !id.startsWith("flow:")) ?? ids[0] ?? null;
});
if (firstNodeId) {
  await page.locator(`[data-node-id="${firstNodeId}"]`).first().evaluate((node) => {
    node.dispatchEvent(new MouseEvent("mouseenter", { bubbles: true, cancelable: true, composed: true }));
    node.dispatchEvent(new MouseEvent("mousemove", { bubbles: true, cancelable: true, composed: true, clientX: 640, clientY: 320 }));
  });
  await page.waitForTimeout(140);
  await page.locator(`[data-node-id="${firstNodeId}"]`).first().evaluate((node) => {
    node.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, composed: true }));
  });
}
await page.waitForTimeout(350);
const nodeState = await page.evaluate(() => ({
  activePanel: document.querySelector(".tab-chip.is-active")?.getAttribute("data-detail-panel") ?? null,
  focusTitle: document.querySelector(".detail-focus-copy strong")?.textContent?.trim() ?? null,
  listCount: document.querySelectorAll(".detail-scroll .detail-card").length,
}));
const nodeShot = path.join(outDir, "ui-regression-node.png");
await page.screenshot({ path: nodeShot, fullPage: false });

await page.goto(`${baseUrl}?focus=topology`, { waitUntil: "networkidle" });
await page.waitForSelector("[data-edge-id]", { state: "attached", timeout: 20000 });
const firstEdgeId = await page.locator("[data-edge-id]").first().getAttribute("data-edge-id");
if (firstEdgeId) {
  await page.locator(`[data-edge-id="${firstEdgeId}"]`).first().evaluate((edge) => {
    edge.dispatchEvent(new MouseEvent("mouseenter", { bubbles: true, cancelable: true, composed: true }));
    edge.dispatchEvent(new MouseEvent("mousemove", { bubbles: true, cancelable: true, composed: true, clientX: 720, clientY: 360 }));
  });
  await page.waitForTimeout(140);
  await page.locator(`[data-edge-id="${firstEdgeId}"]`).first().evaluate((node) => {
    node.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, composed: true }));
  });
}
await page.waitForTimeout(350);
const edgeState = await page.evaluate(() => ({
  activePanel: document.querySelector(".tab-chip.is-active")?.getAttribute("data-detail-panel") ?? null,
  focusTitle: document.querySelector(".detail-focus-copy strong")?.textContent?.trim() ?? null,
  listCount: document.querySelectorAll(".detail-scroll .detail-card").length,
}));
const edgeShot = path.join(outDir, "ui-regression-edge.png");
await page.screenshot({ path: edgeShot, fullPage: false });

await page.goto(baseUrl, { waitUntil: "networkidle" });
await page.waitForSelector("[data-chat-toggle]", { timeout: 20000 });
await page.click("[data-chat-toggle]");
await page.waitForSelector("#chatInput");
const prompts = [
  "Co mám řešit jako první?",
  "Co znamená vybrané riziko a co mám dělat?",
  "no ale jak to opravím",
  "Co mám udělat já jako další krok?",
];
for (const prompt of prompts) {
  await page.fill("#chatInput", prompt);
  await page.click("[data-chat-send]");
  await page.waitForFunction(() => !document.querySelector(".chat-bubble.is-loading"), undefined, { timeout: 60000 });
  await page.waitForFunction(() => !document.querySelector(".chat-bubble.is-streaming"), undefined, { timeout: 60000 });
  await page.waitForTimeout(160);
}
const chatState = await page.evaluate(() => {
  const log = document.querySelector("#chatLog");
  const input = document.querySelector("#chatInput");
  return {
    bubbles: document.querySelectorAll(".chat-bubble").length,
    scrolledToBottom: !!log && Math.abs(log.scrollTop - (log.scrollHeight - log.clientHeight)) <= 10,
    inputWithinViewport: !!input && input.getBoundingClientRect().bottom <= window.innerHeight + 2,
    logScrollable: !!log && log.scrollHeight > log.clientHeight,
  };
});
const chatShot = path.join(outDir, "ui-regression-chat.png");
await page.screenshot({ path: chatShot, fullPage: false });

await page.goto(baseUrl, { waitUntil: "networkidle" });
await page.waitForSelector("[data-graph-surface='topology']", { timeout: 20000 });
await page.waitForSelector("[data-detail-panel]", { timeout: 20000 });
const keyboardBefore = await page.evaluate(() => {
  const graph = document.querySelector("#graphTransform");
  const style = graph ? getComputedStyle(graph) : null;
  return {
    zoom: style?.getPropertyValue("--zoom").trim() ?? null,
    panX: style?.getPropertyValue("--pan-x").trim() ?? null,
    activePanel: document.querySelector(".tab-chip.is-active")?.getAttribute("data-detail-panel") ?? null,
    chatVisible: !!document.querySelector("#chatInput"),
  };
});
await page.keyboard.press("+");
await page.keyboard.press("ArrowRight");
await page.keyboard.press("2");
await page.waitForTimeout(220);
const keyboardPanelState = await page.evaluate(() => ({
  activePanel: document.querySelector(".tab-chip.is-active")?.getAttribute("data-detail-panel") ?? null,
  chatVisible: !!document.querySelector("#chatInput"),
}));
await page.keyboard.press("v");
await page.keyboard.press("c");
await page.waitForTimeout(220);
const keyboardListState = await page.evaluate(() => ({
  listView: document.querySelector(".detail-panel-body")?.classList.contains("is-list-view") ?? false,
  listChipActive: document.querySelector(".audit-mode-grid [data-detail-view='list']")?.classList.contains("is-active") ?? false,
  allScopeActive: document.querySelector(".audit-mode-grid [data-detail-scope='all']")?.classList.contains("is-active") ?? false,
  focusHidden: getComputedStyle(document.querySelector(".detail-focus-wrap")).display === "none",
}));
const listShot = path.join(outDir, "ui-regression-list.png");
await page.screenshot({ path: listShot, fullPage: false });
await page.keyboard.press("a");
await page.waitForTimeout(300);
const keyboardState = await page.evaluate(() => {
  const graph = document.querySelector("#graphTransform");
  const style = graph ? getComputedStyle(graph) : null;
  return {
    zoom: style?.getPropertyValue("--zoom").trim() ?? null,
    panX: style?.getPropertyValue("--pan-x").trim() ?? null,
    activePanel: document.querySelector(".tab-chip.is-active")?.getAttribute("data-detail-panel") ?? null,
    chatVisible: !!document.querySelector("#chatInput"),
  };
});
const keyboardShot = path.join(outDir, "ui-regression-keyboard.png");
await page.screenshot({ path: keyboardShot, fullPage: false });

await interactionContext.close();

const animationContext = await browser.newContext({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 1 });
const animationPage = await animationContext.newPage();
await animationPage.route("**/api/automation/status", async (route) => {
  await route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({
      process_running: true,
      progress_pct: 42,
      progress_ratio: 0.42,
      current_phase: "validation",
      current_phase_label: "Validace",
      latest_run_id: null,
      agents: [
        { role: "traffic-agent", status: "running", summary: "Sleduje provoz" },
        { role: "cve-intel-agent", status: "running", summary: "Ověřuje CVE" },
        { role: "pentest-agent", status: "running", summary: "Testuje služby" },
        { role: "decision-agent", status: "running", summary: "Skládá prioritu" },
      ],
      phases: [],
    }),
  });
});
await animationPage.goto(baseUrl, { waitUntil: "networkidle" });
await animationPage.waitForSelector(".graph-agent-probe", { timeout: 20000 });
await animationPage.evaluate(() => {
  document.querySelector(".graph-svg")?.setAttribute("data-stability-check", "keep");
});
const firstProbePositions = await animationPage.evaluate(() =>
  [...document.querySelectorAll(".graph-agent-probe")].map((probe) => {
    const rect = probe.getBoundingClientRect();
    return { left: rect.left, top: rect.top, width: rect.width, height: rect.height };
  }),
);
await animationPage.waitForTimeout(1200);
const animationState = await animationPage.evaluate((first) => {
  const surface = document.querySelector("[data-graph-surface='topology']")?.getBoundingClientRect();
  const positions = [...document.querySelectorAll(".graph-agent-probe")].map((probe) => {
    const rect = probe.getBoundingClientRect();
    return { left: rect.left, top: rect.top, width: rect.width, height: rect.height };
  });
  const moved = positions.some((pos, index) => {
    const before = first[index];
    return before && Math.hypot(pos.left - before.left, pos.top - before.top) > 4;
  });
  const stuckInCorner = positions.some((pos) => {
    if (!surface) return true;
    return pos.left <= surface.left + 4 && pos.top <= surface.top + 4;
  });
  return {
    probes: positions.length,
    moved,
    stuckInCorner,
    graphStillMounted: document.querySelector(".graph-svg")?.getAttribute("data-stability-check") === "keep",
  };
}, firstProbePositions);
await animationPage.waitForTimeout(4500);
animationState.graphStillMountedAfterRefresh = await animationPage.evaluate(() =>
  document.querySelector(".graph-svg")?.getAttribute("data-stability-check") === "keep",
);
await animationContext.close();

await browser.close();

const output = {
  baseUrl,
  viewportResults,
  interactions: {
    reader: { ...readerState, mapSwitchCenter, switchShift: Math.abs(readerState.switchCenter - mapSwitchCenter), assetPanel: readerAssetState, screenshot: readerShot },
    auditExpanded: { ...auditExpanded, screenshot: auditExpandedShot },
    node: { ...nodeState, screenshot: nodeShot },
    edge: { ...edgeState, screenshot: edgeShot },
    chat: { ...chatState, screenshot: chatShot },
    keyboard: { before: keyboardBefore, panelShortcut: keyboardPanelState, listShortcut: { ...keyboardListState, screenshot: listShot }, ...keyboardState, screenshot: keyboardShot },
    animation: animationState,
  },
};

const reportPath = path.join(outDir, "ui-regression-check.json");
await fs.writeFile(reportPath, JSON.stringify(output, null, 2), "utf8");
const failures = [
  ...viewportResults
    .filter((item) => !item.fitsViewport || item.textOverflow.length || item.overlaps.heroTabs || item.overlaps.tabsDetail || !item.progressCardVisible || (item.processRunning ? item.agentProbes < 3 : item.agentProbes !== 0))
    .map((item) => `${item.name} nemá čistý layout`),
  !readerState.readerVisible || readerState.graphVisible ? "středový přepínač neotevřel čtecí režim" : "",
  readerState.articleWidth < 640 || readerState.articleHeight < 520 || readerState.rightCards < 3 ? "středový reader nemá použitelnou čtecí plochu nebo pravý seznam" : "",
  Math.abs(readerState.switchCenter - mapSwitchCenter) > 4 ? "přepínač mapa/čtení mění vodorovnou pozici" : "",
  readerState.hasOwnList || !readerState.rightFocusHidden ? "reader pořád kopíruje pravý panel místo čistého čtení" : "",
  readerState.leadLength < 80 || readerState.sectionCount < 4 || readerState.stepCount < 3 || readerState.factCount < 3 ? "reader nemá dost výkladových informací pro ne-technického čtenáře" : "",
  readerState.titleOverflow || !readerState.allScopeActive ? "středový reader ořezává text nebo nepřepnul na vše" : "",
  readerAssetState.activePanel !== "assets" || readerAssetState.rightCards < 3 || !readerAssetState.title || !readerAssetState.readerVisible ? "pravý panel nepřepnul text ve středové čtečce" : "",
  auditExpanded.focusParam !== "audit" || !auditExpanded.buttonActive ? "tlačítko nezvětšilo auditní panel" : "",
  auditExpanded.rightWidth < auditBefore.rightWidth * 1.42 || auditExpanded.focusWidth < 500 ? "zvětšený auditní panel je pořád úzký" : "",
  auditExpanded.title.includes("…") || auditExpanded.titleOverflow || auditExpanded.summary.length < 40 ? "zvětšený auditní detail je pořád nečitelně oříznutý" : "",
  nodeState.activePanel !== "assets" || nodeState.focusTitle === "Bez detailu" ? "klik na uzel neotevřel detail zařízení" : "",
  edgeState.activePanel !== "findings" || edgeState.focusTitle === "Bez detailu" ? "klik na hranu neotevřel navázané riziko" : "",
  !chatState.inputWithinViewport || !chatState.scrolledToBottom ? "chat není správně ukotvený" : "",
  keyboardPanelState.activePanel !== "assets" ? "klávesa 2 nepřepnula panel zařízení" : "",
  !keyboardListState.listView || !keyboardListState.listChipActive || !keyboardListState.allScopeActive || !keyboardListState.focusHidden ? "klávesy V/C nepřepnuly seznam a vše" : "",
  !keyboardState.chatVisible ? "klávesa A neotevřela AI panel" : "",
  animationState.probes < 3 || !animationState.moved || animationState.stuckInCorner ? "agentní animace neběží plynule po cestách" : "",
  !animationState.graphStillMounted || !animationState.graphStillMountedAfterRefresh ? "live refresh přemountoval SVG topologii" : "",
].filter(Boolean);
if (failures.length) throw new Error(`UI regrese selhala: ${failures.join("; ")}`);
console.log(reportPath);
console.log(JSON.stringify(output, null, 2));
