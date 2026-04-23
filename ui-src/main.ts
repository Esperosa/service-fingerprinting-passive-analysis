
import {
  Activity,
  AlertTriangle,
  Bot,
  ChevronRight,
  CircleDashed,
  Download,
  Gauge,
  GitCompare,
  Layers,
  Maximize2,
  Minimize2,
  Network,
  Play,
  Radar,
  RefreshCw,
  RotateCcw,
  ScanLine,
  Shield,
  ShieldAlert,
  Sparkles,
  Waves,
  Wifi,
  ZoomIn,
  ZoomOut,
  createIcons,
} from "lucide";
import {
  applyResponsiveLayoutVars,
  computeGraphOrbitMetrics,
  computeGraphSceneSize,
  type ResponsiveMetrics,
} from "./responsive";
import { renderLeftRail as renderLeftRailView } from "./render/left-rail";
import { renderCenterStage as renderCenterStageView } from "./render/center-stage";
import { renderRightStage as renderRightStageView } from "./render/right-panel";
import { renderCompactGuide as renderCompactGuideView, renderCompactGrid as renderCompactGridView, renderCompactHeader as renderCompactHeaderView } from "./render/compact";

type FocusMode = "topology" | "audit";
type DetailPanel = "findings" | "assets" | "lanes" | "triage" | "diff";
type DetailScope = "context" | "all";
type DetailView = "detail" | "list";
type CenterMode = "map" | "reader";
type PentestMode = "off" | "smart" | "aggressive";
type RunIndexEntry = { run_id: string; nazev: string; hosts_total: number; services_total: number; cves_total: number };
type VerificationReport = { summary: { total: number; passed: number; failed: number } } | null;
type AutomationLatest = {
  summary: {
    cycles_total: number;
    tooling_coverage_ratio: number;
    service_identity_coverage_ratio: number;
    automation_agents_total: number;
    automation_rounds_total: number;
    forensic_targets_total: number;
    mas_parallelism_ratio: number;
    mas_queue_wait_ms_avg: number;
    mas_agent_sla_ratio: number;
    mas_consensus_score: number;
    mas_consensus_state: string;
    run_ids: string[];
  };
  agents: Array<{ agent_id: string; role: string; status: string; summary: string }>;
  capabilities: Array<{ capability_id: string; label: string; available: boolean; activated: boolean }>;
} | null;
type AutomationStatus = {
  state: string;
  current_cycle: number;
  total_cycles: number;
  progress_pct: number;
  progress_ratio: number;
  current_phase: string;
  current_phase_label: string;
  message: string;
  latest_run_id?: string | null;
  process_running?: boolean;
  phases: Array<{ phase_id: string; label: string; status: string; progress_pct: number; summary: string }>;
  agents: Array<{ agent_id: string; role: string; status: string; summary: string }>;
} | null;
type ReadinessReport = {
  status: string;
  grade: string;
  score: number;
  blockers: string[];
  next_steps: string[];
  checks: Array<{ check_id: string; label: string; status: string; score: number; evidence: string[]; next_step: string }>;
} | null;
type Report = Record<string, any>;
type MetaResponse = { auth_required?: boolean };
type SeverityBucket = "high" | "medium" | "low";
type IssueCounts = { high: number; medium: number; low: number; total: number; findingIds: string[] };
type GraphNode = {
  id: string;
  title: string;
  subtitle: string;
  layerLabel: string;
  kind: "hub" | "host" | "core" | "client" | "external";
  nodeType: string;
  x: number;
  y: number;
  sev: string;
  tags: string[];
  details: string[];
  services: Array<{ label: string; severity: string }>;
  connected: string[];
  trafficPackets: number;
  trafficBytes: number;
  issueCounts: IssueCounts;
  riskScore?: number;
  riskColor?: string;
};
type GraphEdge = { id: string; source: string; target: string; relation: string; confidence: string; packets: number; bytes: number; active: boolean; issueCounts: IssueCounts; riskScore?: number; riskColor?: string };
type FlowFindingRecord = {
  nodeId: string;
  sourceNodeId: string;
  dstIp: string;
  dstPort: string;
  protocol: string;
  packets: number;
  bytes: number;
  url: string;
  severity: string;
};
type GuideCard = { eyebrow: string; title: string; summary: string; actions: string[]; tone: string };
type ChatMessage = { role: "assistant" | "user"; text: string; sources?: string[]; streaming?: boolean };

type LayoutMode = "desktop" | "desktop-topology" | "desktop-audit" | "compact" | "compact-topology" | "compact-audit";

const rootNode = document.querySelector<HTMLDivElement>("#app");
if (!rootNode) throw new Error("UI root #app nebyl nalezen.");
const root: HTMLDivElement = rootNode;

const DETAIL_META: Record<DetailPanel, { title: string; icon: string; accent: string }> = {
  findings: { title: "Rizika", icon: "shield-alert", accent: "#fb7185" },
  assets: { title: "Stanice", icon: "wifi", accent: "#38bdf8" },
  lanes: { title: "Sběr", icon: "waves", accent: "#22c55e" },
  triage: { title: "Kroky", icon: "sparkles", accent: "#fbbf24" },
  diff: { title: "Změny", icon: "git-compare", accent: "#38bdf8" },
};

const state = {
  runs: [] as RunIndexEntry[],
  report: null as Report | null,
  verification: null as VerificationReport,
  automationLatest: null as AutomationLatest,
  automationStatus: null as AutomationStatus,
  aiStatus: null as any,
  readiness: null as ReadinessReport,
  authRequired: false,
  authDismissed: false,
  apiTokenPresent: false,
  pentestMode: readPentestMode(),
  activeRunId: null as string | null,
  detailPanel: "findings" as DetailPanel,
  detailScope: "context" as DetailScope,
  detailView: "detail" as DetailView,
  centerMode: "map" as CenterMode,
  loading: true,
  error: null as string | null,
  liveMode: true,
  lastUpdatedAt: null as string | null,
  graphNodes: [] as GraphNode[],
  graphEdges: [] as GraphEdge[],
  selectedGraphNodeId: null as string | null,
  selectedGraphEdgeId: null as string | null,
  selectedFindingId: null as string | null,
  selectedAssetId: null as string | null,
  selectedActionId: null as string | null,
  rightMode: "detail" as "detail" | "chat",
  chatMessages: [] as ChatMessage[],
  chatDraft: "",
  chatBusy: false,
  chatInputFocused: false,
  zoom: 1,
  panX: 0,
  panY: 0,
  shellMode: null as LayoutMode | null,
  refreshHandle: null as number | null,
  renderHandle: null as number | null,
  progressAnimationHandle: null as number | null,
  visibleProgress: 0,
  scrollMemory: {
    hostRail: 0,
    runRail: 0,
    detail: 0,
    chat: 0,
  },
  detailScrollLock: null as number | null,
  chatScrollLock: false,
  layout: null as ResponsiveMetrics | null,
};

void init();

async function init() {
  await refreshData(true, false);
  setupAutoRefresh();
  setupKeyboardControls();
  window.addEventListener("resize", () => scheduleRender());
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && state.liveMode && !isChatComposing()) void refreshData(false, true);
  });
}

function setupAutoRefresh() {
  if (state.refreshHandle) window.clearInterval(state.refreshHandle);
  state.refreshHandle = window.setInterval(() => {
    if (state.liveMode && !document.hidden && !isChatComposing()) void refreshData(false, true);
  }, 4000);
}

function isChatComposing() {
  const active = document.activeElement as HTMLElement | null;
  return state.rightMode === "chat" && (
    state.chatBusy ||
    state.chatInputFocused ||
    active?.id === "chatInput" ||
    state.chatDraft.trim().length > 0
  );
}

function setupKeyboardControls() {
  window.addEventListener("keydown", (event) => {
    const target = event.target as HTMLElement | null;
    const typing = target?.matches("input, textarea, select, [contenteditable='true']");
    if (typing && event.key !== "Escape") return;

    const key = event.key.toLowerCase();
    const handled = () => {
      event.preventDefault();
      event.stopPropagation();
    };

    if (key === "escape") {
      state.rightMode = "detail";
      setFocusQuery(null);
      renderApp();
      handled();
      return;
    }
    if (key === "r") {
      void refreshData(false, false);
      handled();
      return;
    }
    if (key === "s") {
      void restartAutomation();
      handled();
      return;
    }
    if (key === "l") {
      state.liveMode = !state.liveMode;
      renderApp();
      handled();
      return;
    }
    if (key === "p") {
      cyclePentestMode();
      renderApp();
      handled();
      return;
    }
    if (key === "a") {
      state.rightMode = state.rightMode === "chat" ? "detail" : "chat";
      if (state.rightMode === "chat") state.chatScrollLock = true;
      renderApp();
      handled();
      return;
    }
    if (key === "m") {
      state.centerMode = state.centerMode === "map" ? "reader" : "map";
      renderApp();
      handled();
      return;
    }
    if (key === "v") {
      state.detailView = state.detailView === "detail" ? "list" : "detail";
      state.rightMode = "detail";
      renderApp();
      handled();
      return;
    }
    if (key === "c") {
      state.detailScope = state.detailScope === "context" ? "all" : "context";
      state.rightMode = "detail";
      renderApp();
      handled();
      return;
    }
    if (key === "/") {
      state.rightMode = "chat";
      state.chatScrollLock = true;
      renderApp();
      window.requestAnimationFrame(() => root.querySelector<HTMLTextAreaElement>("#chatInput")?.focus());
      handled();
      return;
    }
    if (key === "+" || key === "=") {
      state.zoom = clamp(state.zoom + 0.14, 0.7, 3.2);
      updateGraphZoom();
      handled();
      return;
    }
    if (key === "-" || key === "_") {
      state.zoom = clamp(state.zoom - 0.14, 0.7, 3.2);
      updateGraphZoom();
      handled();
      return;
    }
    if (key === "0") {
      state.zoom = 1;
      state.panX = 0;
      state.panY = 0;
      updateGraphZoom();
      handled();
      return;
    }
    const panStep = event.shiftKey ? 80 : 34;
    if (key === "arrowleft" || key === "arrowright" || key === "arrowup" || key === "arrowdown") {
      if (key === "arrowleft") state.panX += panStep;
      if (key === "arrowright") state.panX -= panStep;
      if (key === "arrowup") state.panY += panStep;
      if (key === "arrowdown") state.panY -= panStep;
      updateGraphZoom();
      handled();
      return;
    }

    const panels: Record<string, DetailPanel> = {
      "1": "findings",
      "2": "assets",
      "3": "lanes",
      "4": "triage",
      "5": "diff",
    };
    const panel = panels[key];
    if (panel) {
      rememberDetailScroll();
      state.detailPanel = panel;
      state.rightMode = "detail";
      renderApp();
      handled();
    }
  });
}

async function refreshData(initial = false, silent = false) {
  if (silent && isChatComposing()) return;
  const previousActiveRunId = state.activeRunId;
  if (!silent) {
    state.loading = true;
    renderApp();
  }
  let fullRenderNeeded = initial || !silent;
  try {
    const meta = await fetchJson<MetaResponse>("/api/meta");
    state.authRequired = Boolean(meta.auth_required);
    state.authDismissed = isTokenPromptDismissed();
    state.apiTokenPresent = Boolean(getStoredToken());
    const previousRuns = state.runs;
    const followLatest =
      state.liveMode &&
      (!previousActiveRunId || previousActiveRunId === previousRuns[0]?.run_id);
    const [runs, verification, automationLatest, automationStatus, aiStatus, readiness] = await Promise.all([
      fetchJson<RunIndexEntry[]>("/api/runs"),
      fetchJson<VerificationReport>("/api/verification/latest").catch(() => null),
      fetchJson<AutomationLatest>("/api/automation/latest").catch(() => null),
      fetchJson<AutomationStatus>("/api/automation/status").catch(() => null),
      fetchJson<any>("/api/ai/status").catch(() => null),
      fetchJson<ReadinessReport>("/api/readiness").catch(() => null),
    ]);
    state.runs = runs;
    state.verification = verification;
    state.automationLatest = automationLatest;
    state.automationStatus = automationStatus;
    state.aiStatus = aiStatus;
    state.readiness = readiness;
    const preferredLiveRunId =
      automationStatus?.latest_run_id && runs.some((run) => run.run_id === automationStatus.latest_run_id)
        ? automationStatus.latest_run_id
        : runs[0]?.run_id ?? null;
    state.activeRunId = followLatest
      ? preferredLiveRunId
      : (state.activeRunId && runs.some((run) => run.run_id === state.activeRunId) ? state.activeRunId : null) ??
        runs[0]?.run_id ??
        null;
    state.report = state.activeRunId
      ? await fetchJson<Report>(`/api/runs/${encodeURIComponent(state.activeRunId)}`)
      : null;
    fullRenderNeeded = fullRenderNeeded || previousActiveRunId !== state.activeRunId;
    state.lastUpdatedAt = new Date().toISOString();
    state.error = null;
    if (initial || !state.selectedGraphNodeId) resetSelections();
  } catch (error) {
    state.error = error instanceof Error ? error.message : String(error);
  } finally {
    state.loading = false;
    if (!fullRenderNeeded && state.centerMode === "map" && root.querySelector("[data-graph-surface='topology']")) {
      patchRealtimeUi();
    } else {
      renderApp();
    }
  }
}

async function switchRun(runId: string) {
  state.loading = true;
  renderApp();
  try {
    state.report = await fetchJson<Report>(`/api/runs/${encodeURIComponent(runId)}`);
    state.activeRunId = runId;
    state.lastUpdatedAt = new Date().toISOString();
    state.error = null;
    resetSelections();
  } catch (error) {
    state.error = error instanceof Error ? error.message : String(error);
  } finally {
    state.loading = false;
    renderApp();
  }
}

function resetSelections() {
  state.detailPanel = "findings";
  state.selectedGraphNodeId = null;
  state.selectedGraphEdgeId = null;
  state.selectedFindingId = null;
  state.selectedAssetId = null;
  state.selectedActionId = null;
  state.detailScope = "context";
  state.detailView = "detail";
  state.centerMode = "map";
  state.rightMode = "detail";
  state.chatMessages = [];
  state.chatDraft = "";
  state.chatBusy = false;
  state.chatInputFocused = false;
  state.zoom = 1;
  state.panX = 0;
  state.panY = 0;
}

async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url, { headers: buildAuthHeaders() });
  if (response.status === 401 && requestToken()) {
    const retry = await fetch(url, { headers: buildAuthHeaders() });
    if (!retry.ok) throw new Error(`Načtení ${url} selhalo (${retry.status}).`);
    return (await retry.json()) as T;
  }
  if (!response.ok) throw new Error(`Načtení ${url} selhalo (${response.status}).`);
  return (await response.json()) as T;
}

function buildAuthHeaders(): HeadersInit {
  const token = getStoredToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function getStoredToken() {
  return window.localStorage.getItem("bakulaApiToken")?.trim() ?? "";
}

function requestToken() {
  if (isTokenPromptDismissed()) return false;
  const token = window.prompt("Zadej API token pro Bakula UI:", getStoredToken())?.trim() ?? "";
  if (!token) {
    dismissTokenPrompt();
    return false;
  }
  window.localStorage.setItem("bakulaApiToken", token);
  window.localStorage.removeItem("bakulaApiTokenDismissed");
  state.authDismissed = false;
  state.apiTokenPresent = true;
  return true;
}

function dismissTokenPrompt() {
  window.localStorage.setItem("bakulaApiTokenDismissed", "1");
  state.authDismissed = true;
  state.apiTokenPresent = false;
}

function isTokenPromptDismissed() {
  return window.localStorage.getItem("bakulaApiTokenDismissed") === "1";
}

function clearStoredToken() {
  window.localStorage.removeItem("bakulaApiToken");
  dismissTokenPrompt();
}

function renderApp() {
  state.layout = applyResponsiveLayoutVars(document.documentElement, window.innerWidth, window.innerHeight);
  captureScrollMemory();
  const mode = getLayoutMode();
  ensureShell(mode);
  syncWorkspaceClasses(mode);
  fill("modeSwitchMount", renderModeSwitch());
  if (mode.startsWith("desktop")) {
    fill("leftRail", renderLeftRail());
    fill("centerStage", renderCenterStage());
    fill("rightStage", renderRightStage());
  } else if (mode === "compact") {
    fill("compactHeader", renderCompactHeader());
    fill("compactGrid", renderCompactGrid());
    fill("compactGuide", renderCompactGuide());
  } else if (mode === "compact-topology") {
    fill("compactFocus", renderCenterStage());
  } else if (mode === "compact-audit") {
    fill("compactFocus", renderRightStage());
  }
  bindUi();
  restoreScrollMemory();
  createIcons({ icons: { Activity, AlertTriangle, Bot, ChevronRight, CircleDashed, Download, Gauge, GitCompare, Layers, Maximize2, Minimize2, Network, Play, Radar, RefreshCw, RotateCcw, ScanLine, Shield, ShieldAlert, Sparkles, Waves, Wifi, ZoomIn, ZoomOut } });
  syncProgressBaseline();
}

function scheduleRender() {
  if (state.renderHandle != null) window.cancelAnimationFrame(state.renderHandle);
  state.renderHandle = window.requestAnimationFrame(() => {
    state.renderHandle = null;
    renderApp();
  });
}

function syncWorkspaceClasses(mode: LayoutMode) {
  const workspace = root.querySelector<HTMLElement>(".workspace-grid");
  if (!workspace) return;
  workspace.classList.toggle("is-focus-topology", mode === "desktop-topology");
  workspace.classList.toggle("is-focus-audit", mode === "desktop-audit");
  workspace.classList.toggle("is-reader-mode", state.centerMode === "reader");
}

function captureScrollMemory() {
  const hostRail = root.querySelector<HTMLElement>("[data-scroll-key='hostRail']");
  const runRail = root.querySelector<HTMLElement>("[data-scroll-key='runRail']");
  const detail = root.querySelector<HTMLElement>("[data-scroll-key='detail']");
  const chat = root.querySelector<HTMLElement>("[data-scroll-key='chat']");
  if (hostRail) state.scrollMemory.hostRail = hostRail.scrollTop;
  if (runRail) state.scrollMemory.runRail = runRail.scrollTop;
  if (detail && state.detailScrollLock == null) state.scrollMemory.detail = detail.scrollTop;
  if (chat && !state.chatScrollLock) state.scrollMemory.chat = chat.scrollTop;
}

function restoreScrollMemory() {
  const apply = () => {
    const hostRail = root.querySelector<HTMLElement>("[data-scroll-key='hostRail']");
    const runRail = root.querySelector<HTMLElement>("[data-scroll-key='runRail']");
    const detail = root.querySelector<HTMLElement>("[data-scroll-key='detail']");
    const chat = root.querySelector<HTMLElement>("[data-scroll-key='chat']");
    if (hostRail) hostRail.scrollTop = state.scrollMemory.hostRail;
    if (runRail) runRail.scrollTop = state.scrollMemory.runRail;
    if (detail) detail.scrollTop = state.scrollMemory.detail;
    if (chat) chat.scrollTop = state.chatScrollLock ? chat.scrollHeight : state.scrollMemory.chat;
  };
  apply();
  window.requestAnimationFrame(() => {
    apply();
    window.requestAnimationFrame(() => {
      apply();
      window.setTimeout(() => {
        apply();
        state.detailScrollLock = null;
        state.chatScrollLock = false;
      }, 0);
    });
  });
}

function getLayoutMode(): LayoutMode {
  const focus = requestedFocus();
  if (window.innerWidth < 980) {
    if (focus === "topology") return "compact-topology";
    if (focus === "audit") return "compact-audit";
    return state.report ? "compact-topology" : "compact";
  }
  if (focus === "topology") return "desktop-topology";
  if (focus === "audit") return "desktop-audit";
  return "desktop";
}

function ensureShell(mode: LayoutMode) {
  if (state.shellMode === mode && root.querySelector("#appShell")) return;
  state.shellMode = mode;
  if (mode.startsWith("desktop")) {
    root.innerHTML = `
      <main id="appShell" class="app-shell">
        <div id="modeSwitchMount" class="mode-switch-mount"></div>
        <section class="workspace-grid ${mode === "desktop-topology" ? "is-focus-topology" : ""} ${mode === "desktop-audit" ? "is-focus-audit" : ""}">
          <aside class="panel-shell left-rail"><div id="leftRail" class="panel-frame rail-frame"></div></aside>
          <section class="panel-shell center-stage"><div id="centerStage" class="panel-frame center-frame"></div></section>
          <aside class="panel-shell right-stage"><div id="rightStage" class="panel-frame right-frame"></div></aside>
        </section>
      </main>
    `;
    return;
  }

  if (mode === "compact") {
    root.innerHTML = `
      <main id="appShell" class="app-shell compact-shell">
        <div id="modeSwitchMount" class="mode-switch-mount"></div>
        <section class="panel-shell compact-header"><div id="compactHeader" class="panel-frame compact-header-frame"></div></section>
        <section id="compactGrid" class="compact-grid"></section>
        <section class="panel-shell compact-guide"><div id="compactGuide" class="panel-frame"></div></section>
      </main>
    `;
    return;
  }

  root.innerHTML = `
    <main id="appShell" class="app-shell compact-shell">
      <div id="modeSwitchMount" class="mode-switch-mount"></div>
      <section class="panel-shell compact-focus"><div id="compactFocus" class="panel-frame compact-focus-frame"></div></section>
    </main>
  `;
}

function renderModeSwitch() {
  if (!state.report) return "";
  return `
    <div class="center-mode-switch" aria-label="Hlavní režim">
      <button type="button" class="center-mode-button ${state.centerMode === "map" ? "is-active" : ""}" data-center-mode="map" title="Mapa sítě"><i data-lucide="network" class="h-4 w-4"></i><span>Mapa</span></button>
      <button type="button" class="center-mode-button ${state.centerMode === "reader" ? "is-active" : ""}" data-center-mode="reader" title="Textové čtení"><i data-lucide="scan-line" class="h-4 w-4"></i><span>Čtení</span></button>
    </div>
  `;
}

function fill(id: string, html: string) {
  const element = root.querySelector<HTMLElement>(`#${id}`);
  if (element && element.innerHTML !== html) element.innerHTML = html;
}

function patchRealtimeUi() {
  state.layout = applyResponsiveLayoutVars(document.documentElement, window.innerWidth, window.innerHeight);
  syncWorkspaceClasses(getLayoutMode());
  const running = Boolean(state.automationStatus?.process_running);
  const card = root.querySelector<HTMLElement>("[data-progress-card]");
  if (card) card.classList.toggle("is-running", running);
  const phase = state.automationStatus?.current_phase_label ?? state.automationStatus?.current_phase ?? (running ? "Běh" : "Připraveno");
  const phaseEl = root.querySelector<HTMLElement>("[data-progress-phase]");
  if (phaseEl) phaseEl.textContent = phase;
  animateProgressTo(currentProgress());
  root.querySelectorAll<HTMLElement>(".live-dot").forEach((dot) => dot.classList.toggle("is-live", state.liveMode));
}

function syncProgressBaseline() {
  const progress = currentProgress();
  state.visibleProgress = progress;
  const bar = root.querySelector<HTMLElement>("[data-progress-bar]");
  const value = root.querySelector<HTMLElement>("[data-progress-value]");
  if (bar) {
    bar.dataset.progress = String(progress);
    bar.style.width = `${progress}%`;
  }
  if (value) value.textContent = `${progress}%`;
}

function currentProgress() {
  const latestRatio = Number(state.automationLatest?.summary?.tooling_coverage_ratio ?? 0) * 100;
  return Math.round(clamp(state.automationStatus?.progress_pct ?? latestRatio, 0, 100));
}

function animateProgressTo(target: number) {
  const bar = root.querySelector<HTMLElement>("[data-progress-bar]");
  const value = root.querySelector<HTMLElement>("[data-progress-value]");
  if (!bar || !value) return;
  const start = Number.isFinite(state.visibleProgress) ? state.visibleProgress : Number(bar.dataset.progress ?? target);
  const delta = target - start;
  if (Math.abs(delta) < 0.2) {
    state.visibleProgress = target;
    bar.dataset.progress = String(target);
    bar.style.width = `${target}%`;
    value.textContent = `${target}%`;
    return;
  }
  if (state.progressAnimationHandle != null) window.cancelAnimationFrame(state.progressAnimationHandle);
  const started = performance.now();
  const duration = 1800;
  const ease = (t: number) => 1 - Math.pow(1 - t, 3);
  const tick = (now: number) => {
    const t = clamp((now - started) / duration, 0, 1);
    const next = start + delta * ease(t);
    state.visibleProgress = next;
    bar.dataset.progress = next.toFixed(2);
    bar.style.width = `${next}%`;
    value.textContent = `${Math.round(next)}%`;
    if (t < 1) {
      state.progressAnimationHandle = window.requestAnimationFrame(tick);
    } else {
      state.progressAnimationHandle = null;
      state.visibleProgress = target;
      bar.dataset.progress = String(target);
      bar.style.width = `${target}%`;
      value.textContent = `${target}%`;
    }
  };
  state.progressAnimationHandle = window.requestAnimationFrame(tick);
}

function renderLeftRail() {
  return renderLeftRailView(createViewContext());
}

function renderCenterStage() {
  const report = state.report;
  if (!report) return emptyState("Čekám na data.");
  const mode = getLayoutMode();
  const expanded = mode === "desktop-topology" || mode === "compact-topology";
  const dims = computeGraphSceneSize(state.layout ?? applyResponsiveLayoutVars(document.documentElement, window.innerWidth, window.innerHeight), expanded);
  const graph = buildGraph(report, dims.width, dims.height);
  state.graphNodes = graph.nodes;
  state.graphEdges = graph.edges;
  if (!state.selectedGraphNodeId && graph.nodes.length) {
    state.selectedGraphNodeId =
      [...graph.nodes]
        .filter((node) => node.kind !== "hub" && node.kind !== "external")
        .sort((left, right) => (right.riskScore ?? 0) - (left.riskScore ?? 0))[0]?.id ??
      graph.nodes.find((node) => node.kind === "core")?.id ??
      graph.nodes[0].id;
  }
  return renderCenterStageView(createViewContext());
}

function renderRightStage() {
  ensureChatSeed();
  return renderRightStageView(createViewContext());
}

function renderCompactHeader() {
  return renderCompactHeaderView(createViewContext());
}

function renderCompactGrid() {
  return renderCompactGridView(createViewContext());
}

function renderCompactGuide() {
  return renderCompactGuideView(createViewContext());
}

function createViewContext() {
  return {
    state,
    DETAIL_META,
    applyResponsiveLayoutVars,
    computeGraphSceneSize,
    getSelectedNode,
    getSelectedFinding,
    getSelectedAsset,
    getSelectedAction,
    getVisibleFindings,
    getAssets,
    getLanes,
    getTriage,
    getTopologyEdges,
    getFlowFindings,
    getRelatedFindingsForNode,
    findingKey,
    actionKey,
    computeRisk,
    assetCounts,
    buildGuide,
    escapeHtml,
    escapeAttr,
    cssLength,
    trim,
    compact,
    formatBytes,
    severity,
    levelOf,
    providerLabel,
    modeLabel,
    displayRunName,
    detailEyebrow,
    assetTypeLabel,
    confidenceLabel,
    displayFindingTitle,
    humanizeFinding,
    localizeUiText,
    recommendedSteps,
    relativeTime,
    pill,
    nodeGlyph,
    emptyState,
    requestedFocus,
    riskScoreFromIssueCounts,
    riskColorForScore,
  };
}

function cssLength(value: number) {
  return `${(value / 16).toFixed(4).replace(/\.?0+$/, "")}rem`;
}

function ensureChatSeed() {
  if (state.chatMessages.length) return;
  const model = state.aiStatus?.selected_model ? ` Model: ${state.aiStatus.selected_model}.` : "";
  state.chatMessages = [{ role: "assistant", text: `Skoky je připravený nad aktuálním během. Vyber nález nebo zařízení a ptej se na postup opravy, ověření nebo dopad.${model}` }];
}

async function submitChatPrompt(prompt: string) {
  if (!prompt) return;
  ensureChatSeed();
  state.rightMode = "chat";
  state.chatBusy = true;
  state.chatScrollLock = true;
  state.scrollMemory.chat = Number.MAX_SAFE_INTEGER;
  const streamingIndex = state.chatMessages.length + 1;
  state.chatMessages = [...state.chatMessages, { role: "user", text: prompt }, { role: "assistant", text: "", sources: ["stream"], streaming: true }];
  state.chatDraft = "";
  renderApp();
  scrollChatToBottom();
  try {
    const answer = await askAssistantStream(prompt, (chunk) => {
      const current = state.chatMessages[streamingIndex];
      if (!current) return;
      current.text += chunk;
      current.streaming = true;
      state.chatScrollLock = true;
      patchChatMessage(streamingIndex);
      scrollChatToBottom();
    });
    const current = state.chatMessages[streamingIndex];
    if (current) {
      current.text = answer.answer || current.text || answerChatPrompt(prompt);
      current.sources = answer.sources;
      current.streaming = false;
    }
  } catch (error) {
    const current = state.chatMessages[streamingIndex];
    if (current) {
      current.text = answerChatPrompt(prompt);
      current.sources = ["local-fallback"];
      current.streaming = false;
    } else {
      state.chatMessages = [...state.chatMessages, { role: "assistant", text: answerChatPrompt(prompt), sources: ["local-fallback"] }];
    }
    state.error = error instanceof Error ? error.message : String(error);
  } finally {
    state.chatBusy = false;
    state.chatScrollLock = true;
    renderApp();
    scrollChatToBottom();
  }
}

function patchChatMessage(index: number) {
  const message = state.chatMessages[index];
  const textNode = root.querySelector<HTMLElement>(`[data-chat-index="${index}"] [data-chat-text]`);
  if (!message || !textNode) {
    scheduleRender();
    return;
  }
  textNode.textContent = message.text || (message.streaming ? "Píšu odpověď…" : "");
}

function answerChatPrompt(prompt: string) {
  const normalized = prompt.toLowerCase();
  if (normalized.includes("první") || normalized.includes("prior")) {
    const finding = getSelectedFinding() ?? getVisibleFindings()[0] ?? (state.report?.findings ?? [])[0];
    return finding ? `${displayFindingTitle(finding)}. ${humanizeFinding(finding)} ${recommendedSteps(finding)[0]}` : "Teď nemám žádný nález, který by šel upřednostnit.";
  }
  if (normalized.includes("riziko")) {
    const finding = getSelectedFinding() ?? getVisibleFindings()[0] ?? (state.report?.findings ?? [])[0];
    return finding ? `${displayFindingTitle(finding)}. ${humanizeFinding(finding)} Doporučený začátek: ${recommendedSteps(finding)[0]}` : "Vyber riziko v záložce Rizika a vysvětlím ho.";
  }
  if (normalized.includes("zařízení") || normalized.includes("stanic")) {
    const asset = getSelectedAsset();
    const node = getSelectedNode();
    const related = node ? getRelatedFindingsForNode(node.id) : [];
    if (asset) return `${asset.name ?? asset.asset_id} je vidět přes ${asset.source ?? "inventář"}. ${[asset.ip, asset.vendor, asset.model].filter(Boolean).join(" · ") || "Bez přesnější identifikace."}${related.length ? ` Navázaná rizika: ${related.slice(0, 2).map((item: any) => displayFindingTitle(item)).join(" · ")}.` : ""}`;
    if (node) return `${node.title} je ${node.layerLabel}. Vazeb: ${node.connected.length}. ${node.details[0] ?? ""}${related.length ? ` Nejdůležitější navázané riziko: ${displayFindingTitle(related[0])}.` : ""}`;
    return "Vyber zařízení vlevo nebo v topologii.";
  }
  if (normalized.includes("krok") || normalized.includes("udělat")) {
    const action = getSelectedAction() ?? getTriage(state.report)[0];
    if (action) return `${localizeUiText(action.title ?? "Doporučený krok")}. ${localizeUiText(action.rationale ?? "Bez doprovodného důvodu.")}`;
    const guide = buildGuide();
    return guide.actions.join(" ");
  }
  const guide = buildGuide();
  return `${guide.summary} ${guide.actions[0] ?? ""}`;
}

async function askAssistant(prompt: string) {
  if (!state.activeRunId) return { answer: answerChatPrompt(prompt), sources: [] as string[] };
  const response = await fetch(`/api/runs/${encodeURIComponent(state.activeRunId)}/assistant`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...buildAuthHeaders(),
    },
    body: JSON.stringify({
      prompt,
      detail_panel: state.detailPanel,
      selected_node_id: state.selectedGraphNodeId,
      selected_finding_id: state.selectedFindingId,
      selected_asset_id: state.selectedAssetId,
      selected_action_id: state.selectedActionId,
      history: state.chatMessages.slice(-6).map((item) => ({ role: item.role, text: item.text })),
    }),
  });
  if (!response.ok) throw new Error(`Helpdesk neodpověděl (${response.status}).`);
  const payload = await response.json() as { answer?: string; mode?: string; sources?: Array<{ label?: string; url?: string | null }> };
  const sourceLabels = (payload.sources ?? []).map((item) => item.label || item.url || "").filter(Boolean);
  if (payload.mode) sourceLabels.unshift(`engine:${payload.mode}`);
  return {
    answer: payload.answer?.trim() || answerChatPrompt(prompt),
    sources: sourceLabels,
  };
}

async function askAssistantStream(prompt: string, onChunk: (chunk: string) => void) {
  if (!state.activeRunId) return { answer: answerChatPrompt(prompt), sources: [] as string[] };
  const requestBody = {
    prompt,
    detail_panel: state.detailPanel,
    selected_node_id: state.selectedGraphNodeId,
    selected_finding_id: state.selectedFindingId,
    selected_asset_id: state.selectedAssetId,
    selected_action_id: state.selectedActionId,
    history: state.chatMessages
      .filter((item) => !item.streaming && item.text.trim())
      .slice(-8)
      .map((item) => ({ role: item.role, text: item.text })),
  };
  const response = await fetch(`/api/runs/${encodeURIComponent(state.activeRunId)}/assistant/stream`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...buildAuthHeaders(),
    },
    body: JSON.stringify(requestBody),
  });
  if (!response.ok || !response.body) {
    return askAssistant(prompt);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let answer = "";
  const sources: string[] = [];
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      if (!line.trim().startsWith("data:")) continue;
      const raw = line.replace(/^data:\s*/, "");
      if (raw === "[DONE]") continue;
      const event = JSON.parse(raw) as { type: string; text?: string; mode?: string; sources?: string[]; error?: string };
      if (event.type === "chunk" && event.text) {
        answer += event.text;
        onChunk(event.text);
      }
      if (event.type === "done") {
        if (event.mode) sources.unshift(`engine:${event.mode}`);
        sources.push(...(event.sources ?? []));
      }
      if (event.type === "error") throw new Error(event.error || "Helpdesk stream selhal.");
    }
  }
  if (!answer.trim()) return askAssistant(prompt);
  return { answer: answer.trim(), sources };
}

function scrollChatToBottom() {
  const apply = () => {
    const log = root.querySelector<HTMLElement>("#chatLog");
    if (log) log.scrollTop = log.scrollHeight;
  };
  apply();
  window.requestAnimationFrame(() => {
    apply();
    window.requestAnimationFrame(() => {
      apply();
      window.setTimeout(apply, 0);
      window.setTimeout(apply, 80);
      window.setTimeout(apply, 180);
      window.setTimeout(apply, 320);
    });
  });
}

function buildGuide(): GuideCard {
  const report = state.report;
  if (!report) return { eyebrow: "bez dat", title: "Čekám na běh", summary: "Jakmile bude dostupný report, přeložím ho do lidské řeči.", actions: ["Spusť nebo načti běh."], tone: "neutral" };
  if (state.detailPanel === "findings") {
    const finding = getSelectedFinding() ?? (report.findings ?? [])[0];
    if (finding) return { eyebrow: levelOf(finding.severity) === "high" ? "priorita" : "kontrola", title: displayFindingTitle(finding), summary: humanizeFinding(finding), actions: recommendedSteps(finding), tone: levelOf(finding.severity) };
  }
  if (state.detailPanel === "triage") {
    const action = getSelectedAction() ?? getTriage(report)[0];
    if (action) return { eyebrow: "další krok", title: action.title ?? "Doporučení", summary: action.rationale ?? "Tenhle krok má rychle potvrdit, jestli je potřeba jít hlouběji.", actions: (action.recommended_tools ?? []).slice(0, 3).map((tool: string) => `Použij ${tool}.`), tone: levelOf(action.priority) };
  }
  if (state.detailPanel === "assets") {
    const asset = getSelectedAsset();
    const node = getSelectedNode();
    if (asset || node) return { eyebrow: "orientace", title: asset?.name ?? node?.title ?? "Zařízení", summary: `Tohle zařízení je v síti vidět přes ${asset?.source ?? node?.subtitle ?? "inventář"}. Nejdřív ověř roli zařízení a jeho vazby.`, actions: ["Ověř, že role zařízení odpovídá realitě.", "Porovnej napojené objekty s očekávaným místem v síti.", "Když je to správa nebo síťový prvek, ověř přístupová pravidla."], tone: levelOf(asset?.confidence ?? node?.sev ?? "neutral") };
  }
  const risk = computeRisk(report);
  return { eyebrow: "souhrn", title: "Co z běhu plyne", summary: risk.className === "severity-high" ? "Je tu alespoň jeden bod, který má smysl řešit hned. Zbytek seřaď podle priority za ním." : "Síť nepůsobí jako akutní havárie, ale jsou tu místa, která stojí za ověření a zpevnění.", actions: ["Začni nejvyšší prioritou vpravo.", "Pak si v topologii ověř, že zařízení sedí na očekávané místo.", "Nakonec projdi doporučené kroky a potvrď, co je skutečně potřeba řešit."], tone: risk.className.replace("severity-", "") };
}

function humanizeFinding(finding: any) {
  const text = `${finding.title ?? ""} ${finding.rationale ?? ""}`.toLowerCase();
  if (finding.finding_type === "plaintext_management_protocol") {
    const service = String(finding.service_key ?? "");
    if (service.includes("/tcp/23") || text.includes("telnet")) return "Telnet přenáší přihlašovací údaje i správcovské příkazy bez šifrování. V běžné síti je citlivý na odposlech a převzetí relace.";
    if (service.includes("/tcp/21") || text.includes("ftp")) return "FTP používá nešifrovaný řídicí kanál a často přenáší přihlašovací údaje bez ochrany. Je potřeba ověřit, jestli přes něj netečou citlivá data.";
    return "Služba používá nešifrovaný přístupový protokol. Bez další ochrany může prozrazovat citlivá data nebo řídicí informace.";
  }
  if (text.includes("openssh") && text.includes("outdated")) return "Na hostu je vidět zastaralá verze OpenSSH. Dává smysl ověřit verzi a rozhodnout, jestli je potřeba aktualizace.";
  if (text.includes("contains vulnerabilities") || text.includes("vulnerabilities with high priority")) return "Služba odpovídá verzi, která je navázaná na známé zranitelnosti. To je signál k prioritnímu ověření a případnému patchi.";
  if (text.includes("swagger")) return "Na službě je vidět vývojářské rozhraní. To bývá vhodné držet jen interně.";
  if (text.includes("metrics")) return "Služba prozrazuje interní technické informace. Samy o sobě nemusí být škodlivé, ale dávají zbytečný kontext navíc.";
  if (text.includes("basic auth") || text.includes("basic-auth")) return "Přihlášení spoléhá na slabší přenosovou ochranu. To snižuje důvěru v bezpečnost přístupu.";
  if (text.includes("directory")) return "Server ukazuje obsah složky přímo v prohlížeči. To může odhalit soubory nebo strukturu služby.";
  if (text.includes("exploited") || text.includes("kev")) return "Tahle slabina není jen teoretická. Existuje signál, že je reálně zneužívaná.";
  if (text.includes("management") || text.includes("admin")) return "Je vidět správcovské rozhraní. To by mělo být dostupné co nejméně lidem i sítím.";
  if (text.includes("gap") || text.includes("identification")) return "Služba odpovídá, ale její identita není dost přesná. Není to důkaz průšvihu, spíš mezera v jistotě.";
  if (finding.rationale) return localizeUiText(finding.rationale);
  return "Systém našel bod, který stojí za ověření. Neříká automaticky, že jde o incident, ale dává důvod ke kontrole.";
}

function displayFindingTitle(finding: any) {
  const title = String(finding.title ?? "Riziko");
  const text = `${title} ${finding.rationale ?? ""}`.toLowerCase();
  const service = String(finding.service_key ?? "").replace("/tcp/", ":").replace("/udp/", ":");
  const target = service || String(finding.host_key ?? "");
  if (finding.finding_type === "plaintext_management_protocol") {
    if (service.endsWith(":23") || text.includes("telnet")) return target ? `Nešifrovaný Telnet na ${target}` : "Nešifrovaný Telnet";
    if (service.endsWith(":21") || text.includes("ftp")) return target ? `Nešifrované FTP na ${target}` : "Nešifrované FTP";
    return target ? `Nešifrovaný správcovský protokol na ${target}` : "Nešifrovaný správcovský protokol";
  }
  if (finding.finding_type === "high_risk_cve_exposure") return target ? `CVE riziko na ${target}` : "Služba s navázanými CVE";
  if (finding.finding_type === "known_exploited_vulnerability") return target ? `CISA KEV na ${target}` : "Zneužívaná známá zranitelnost";
  if (finding.finding_type === "probable_exploitation_interest") return target ? `Vyšší EPSS na ${target}` : "Zvýšený zájem útočníků";
  if (finding.finding_type === "management_surface_exposure") return target ? `Správcovská plocha na ${target}` : "Viditelná správcovská plocha";
  if (finding.finding_type === "identification_gap") return target ? `Neúplná identita ${target}` : "Neúplná identita služby";
  if (finding.finding_type === "external_flow_observed") return title.replace("Live vrstva", "Živá vrstva");
  if (text.includes("openssh") && text.includes("outdated")) return target ? `Zastaralý OpenSSH na ${target}` : "Zastaralá verze OpenSSH";
  if (text.includes("basic auth") || text.includes("basic-auth")) return target ? `Slabé přihlášení na ${target}` : "Slabě chráněné přihlášení";
  if (text.includes("swagger")) return target ? `Swagger na ${target}` : "Vystavené Swagger rozhraní";
  if (text.includes("metrics")) return target ? `Metriky na ${target}` : "Veřejně dostupné technické metriky";
  if (text.includes("directory")) return target ? `Výpis adresáře na ${target}` : "Zapnutý výpis adresáře";
  if (text.includes("management") || text.includes("admin")) return target ? `Správa na ${target}` : "Viditelné správcovské rozhraní";
  if (text.includes("kev") || text.includes("known exploited")) return target ? `CISA KEV na ${target}` : "Zneužívaná známá zranitelnost";
  if (text.includes("identification") || text.includes("gap")) return target ? `Neúplná identita ${target}` : "Neúplná identita služby";
  if (text.includes("contains vulnerabilities") || text.includes("vulnerabilities")) return target ? `Zranitelnosti na ${target}` : "Služba s navázanými zranitelnostmi";
  return title;
}

function recommendedSteps(finding: any) {
  const text = `${finding.title ?? ""} ${finding.rationale ?? ""}`.toLowerCase();
  if (text.includes("swagger")) return ["Omez rozhraní jen na interní síť.", "Zapni autentizaci nebo proxy před službou.", "Ověř, že rozhraní není potřeba veřejně."];
  if (text.includes("metrics")) return ["Ponech endpoint jen interně.", "Zkontroluj, co endpoint prozrazuje o službě.", "Doplň přístupové omezení."];
  if (text.includes("basic auth") || text.includes("basic-auth")) return ["Přesuň přístup na HTTPS.", "Zvaž silnější přihlášení nebo reverzní proxy.", "Ověř, kdo má mít k rozhraní přístup."];
  if (text.includes("directory")) return ["Vypni listing adresářů.", "Projdi veřejné cesty a citlivé soubory.", "Zkontroluj, že se nepublikuje build nebo záloha."];
  if (text.includes("exploited") || text.includes("kev")) return ["Ověř verzi a dostupnost patche.", "Upřednostni to před běžnou údržbou.", "Sleduj, zda se k hostu neváže další podezřelá aktivita."];
  return ["Ověř, že služba je opravdu potřebná.", "Zúž přístup jen na nutné zdroje.", "Doplň nebo zpřesni identitu a nastavení služby."];
}

function bindUi() {
  const holdPosition = (element: HTMLElement) => {
    element.onpointerdown = (event) => event.preventDefault();
    element.onmousedown = (event) => event.preventDefault();
  };
  root.querySelectorAll<HTMLElement>("[data-run-id]").forEach((element) => { holdPosition(element); element.onclick = (event) => { event.preventDefault(); const id = element.dataset.runId; if (id && id !== state.activeRunId) void switchRun(id); }; });
  root.querySelectorAll<HTMLElement>("[data-select-node]").forEach((element) => { holdPosition(element); element.onclick = (event) => { event.preventDefault(); const id = element.dataset.selectNode; if (!id) return; focusNodeContext(id, "assets"); renderApp(); }; });
  root.querySelectorAll<HTMLElement>("[data-detail-panel]").forEach((element) => { holdPosition(element); element.onclick = (event) => {
    event.preventDefault();
    const panel = element.dataset.detailPanel as DetailPanel | undefined;
    if (!panel) return;
    rememberDetailScroll();
    state.detailPanel = panel;
    if (element.dataset.detailScope === "context" || element.dataset.detailScope === "all") state.detailScope = element.dataset.detailScope;
    if (element.dataset.detailView === "detail" || element.dataset.detailView === "list") state.detailView = element.dataset.detailView;
    if (element.dataset.centerMode === "map" || element.dataset.centerMode === "reader") state.centerMode = element.dataset.centerMode;
    state.rightMode = "detail";
    renderApp();
  }; });
  root.querySelectorAll<HTMLElement>("[data-center-mode]").forEach((element) => { if (element.dataset.detailPanel || element.dataset.detailScope || element.dataset.detailView) return; holdPosition(element); element.onclick = (event) => {
    event.preventDefault();
    const mode = element.dataset.centerMode as CenterMode | undefined;
    if (!mode) return;
    state.centerMode = mode;
    renderApp();
  }; });
  root.querySelectorAll<HTMLElement>("[data-detail-scope]").forEach((element) => { holdPosition(element); element.onclick = (event) => {
    event.preventDefault();
    const scope = element.dataset.detailScope as DetailScope | undefined;
    if (!scope) return;
    rememberDetailScroll();
    state.detailScope = scope;
    if (element.dataset.centerMode === "map" || element.dataset.centerMode === "reader") state.centerMode = element.dataset.centerMode;
    state.rightMode = "detail";
    renderApp();
  }; });
  root.querySelectorAll<HTMLElement>("[data-detail-view]").forEach((element) => { holdPosition(element); element.onclick = (event) => {
    event.preventDefault();
    const view = element.dataset.detailView as DetailView | undefined;
    if (!view) return;
    rememberDetailScroll();
    state.detailView = view;
    if (element.dataset.centerMode === "map" || element.dataset.centerMode === "reader") state.centerMode = element.dataset.centerMode;
    state.rightMode = "detail";
    renderApp();
  }; });
  root.querySelectorAll<HTMLElement>("[data-select-finding]").forEach((element) => { holdPosition(element); element.onclick = (event) => {
    event.preventDefault();
    const id = element.dataset.selectFinding;
    if (!id) return;
    rememberDetailScroll();
    state.selectedFindingId = id;
    state.detailPanel = "findings";
    if (element.closest(".right-stage")) state.centerMode = "reader";
    renderApp();
  }; });
  root.querySelectorAll<HTMLElement>("[data-select-asset]").forEach((element) => { holdPosition(element); element.onclick = (event) => {
    event.preventDefault();
    const id = element.dataset.selectAsset;
    if (!id) return;
    rememberDetailScroll();
    state.selectedAssetId = id;
    state.detailPanel = "assets";
    if (element.closest(".right-stage")) state.centerMode = "reader";
    renderApp();
  }; });
  root.querySelectorAll<HTMLElement>("[data-select-action]").forEach((element) => { holdPosition(element); element.onclick = (event) => {
    event.preventDefault();
    const id = element.dataset.selectAction;
    if (!id) return;
    rememberDetailScroll();
    state.selectedActionId = id;
    state.detailPanel = "triage";
    if (element.closest(".right-stage")) state.centerMode = "reader";
    renderApp();
  }; });
  root.querySelectorAll<HTMLElement>("[data-refresh]").forEach((element) => { holdPosition(element); element.onclick = (event) => { event.preventDefault(); void refreshData(false, false); }; });
  root.querySelectorAll<HTMLElement>("[data-live-toggle]").forEach((element) => { holdPosition(element); element.onclick = (event) => { event.preventDefault(); state.liveMode = !state.liveMode; renderApp(); }; });
  root.querySelectorAll<HTMLElement>("[data-pentest-toggle]").forEach((element) => { holdPosition(element); element.onclick = (event) => { event.preventDefault(); cyclePentestMode(); renderApp(); }; });
  root.querySelectorAll<HTMLElement>("[data-automation-start]").forEach((element) => { holdPosition(element); element.onclick = (event) => { event.preventDefault(); void restartAutomation(); }; });
  root.querySelectorAll<HTMLElement>("[data-automation-reset]").forEach((element) => { holdPosition(element); element.onclick = (event) => { event.preventDefault(); void resetAutomation(); }; });
  root.querySelectorAll<HTMLElement>("[data-token-set]").forEach((element) => { holdPosition(element); element.onclick = (event) => {
    event.preventDefault();
    window.localStorage.removeItem("bakulaApiTokenDismissed");
    state.authDismissed = false;
    requestToken();
    renderApp();
  }; });
  root.querySelectorAll<HTMLElement>("[data-token-clear]").forEach((element) => { holdPosition(element); element.onclick = (event) => {
    event.preventDefault();
    clearStoredToken();
    renderApp();
  }; });
  root.querySelectorAll<HTMLElement>("[data-focus]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      const requested = (element.dataset.focus as FocusMode | undefined) ?? null;
      const current = requestedFocus();
      setFocusQuery(requested && current === requested ? null : requested);
      renderApp();
    };
  });
  root.querySelectorAll<HTMLElement>("[data-focus-clear]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      setFocusQuery(null);
      renderApp();
    };
  });
  root.querySelectorAll<HTMLElement>("[data-export]").forEach((element) => { holdPosition(element); element.onclick = (event) => { event.preventDefault(); const format = element.dataset.export as "json" | "md" | "txt" | undefined; if (format) void exportCurrent(format); }; });
  root.querySelectorAll<HTMLElement>("[data-zoom]").forEach((element) => { holdPosition(element); element.onclick = (event) => {
    event.preventDefault();
    const dir = element.dataset.zoom;
    if (dir === "reset") {
      state.zoom = 1;
      state.panX = 0;
      state.panY = 0;
    } else {
      state.zoom = clamp(dir === "in" ? state.zoom + 0.14 : state.zoom - 0.14, 0.7, 3.2);
    }
    updateGraphZoom();
  }; });
  root.querySelectorAll<HTMLElement>("[data-chat-toggle]").forEach((element) => { holdPosition(element); element.onclick = (event) => {
    event.preventDefault();
    state.rightMode = state.rightMode === "chat" ? "detail" : "chat";
    if (state.rightMode === "chat") state.chatScrollLock = true;
    renderApp();
  }; });
  root.querySelectorAll<HTMLElement>("[data-chat-prompt]").forEach((element) => { holdPosition(element); element.onclick = (event) => {
    event.preventDefault();
    const prompt = element.dataset.chatPrompt;
    if (!prompt) return;
    void submitChatPrompt(prompt);
  }; });
  const chatInput = root.querySelector<HTMLTextAreaElement>("#chatInput");
  if (chatInput) {
    const sizeChatInput = () => {
      chatInput.style.height = "auto";
      const maxHeight = Math.round(clamp(window.innerHeight * 0.22, 136, 228));
      chatInput.style.height = cssLength(Math.min(chatInput.scrollHeight, maxHeight));
    };
    sizeChatInput();
    chatInput.oninput = () => {
      state.chatDraft = chatInput.value;
      sizeChatInput();
    };
    chatInput.onfocus = () => {
      state.chatInputFocused = true;
      state.chatScrollLock = true;
      window.requestAnimationFrame(() => scrollChatToBottom());
    };
    chatInput.onblur = () => {
      state.chatInputFocused = false;
    };
    chatInput.onkeydown = (event) => {
      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        void submitChatPrompt(chatInput.value.trim());
      }
    };
  }
  root.querySelectorAll<HTMLElement>("[data-chat-send]").forEach((element) => { holdPosition(element); element.onclick = (event) => { event.preventDefault(); void submitChatPrompt(state.chatDraft.trim()); }; });
  bindGraphInteractions();
}

function rememberDetailScroll() {
  const detail = root.querySelector<HTMLElement>("[data-scroll-key='detail']");
  if (detail) {
    state.scrollMemory.detail = detail.scrollTop;
    state.detailScrollLock = detail.scrollTop;
  }
}

function focusNodeContext(nodeId: string, panel: DetailPanel = "assets", preferFindings = false) {
  state.selectedGraphNodeId = nodeId;
  state.selectedGraphEdgeId = null;
  state.detailScope = "context";
  state.detailView = "detail";
  const node = state.graphNodes.find((item) => item.id === nodeId) ?? null;
  const resolvedPanel = node?.kind === "hub" ? "findings" : panel;
  const asset = getAssets(state.report).find((item: any) => item.asset_id === nodeId || item.linked_host_key === nodeId || item.ip === nodeId) ?? null;
  state.selectedAssetId = asset?.asset_id ?? null;
  state.selectedActionId = null;
  const related = getRelatedFindingsForNode(nodeId);
  const fallbackFinding = state.report?.findings?.[0] ?? null;
  state.selectedFindingId = related[0] ? findingKey(related[0], 0) : fallbackFinding ? findingKey(fallbackFinding, 0) : null;
  state.detailPanel = preferFindings && related.length ? "findings" : resolvedPanel;
}

function focusEdgeContext(edgeId: string) {
  state.selectedGraphEdgeId = edgeId;
  state.selectedGraphNodeId = null;
  state.detailScope = "context";
  state.detailView = "detail";
  state.selectedAssetId = null;
  state.selectedActionId = null;
  const related = getRelatedFindingsForEdge(edgeId);
  const fallbackFinding = state.report?.findings?.[0] ?? null;
  state.selectedFindingId = related[0] ? findingKey(related[0], 0) : fallbackFinding ? findingKey(fallbackFinding, 0) : null;
  state.detailPanel = related.length ? "findings" : "lanes";
}

async function exportCurrent(format: "json" | "md" | "txt") {
  if (!state.activeRunId) return;
  try {
    const response = await fetch(`/api/runs/${encodeURIComponent(state.activeRunId)}/export/${format}`, { headers: buildAuthHeaders() });
    if (!response.ok) throw new Error(`Export ${format} selhal (${response.status}).`);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    const disposition = response.headers.get("content-disposition");
    anchor.href = url;
    anchor.download = disposition?.match(/filename="([^"]+)"/)?.[1] ?? `${state.activeRunId}.${format}`;
    anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1500);
  } catch (error) {
    state.error = error instanceof Error ? error.message : String(error);
    renderApp();
  }
}

async function restartAutomation() {
  try {
    const response = await fetch(automationRestartUrl(), {
      method: "POST",
      headers: buildAuthHeaders(),
    });
    if (!response.ok) throw new Error(`Restart autopilota selhal (${response.status}).`);
    state.liveMode = true;
    state.error = null;
    await refreshData(false, true);
  } catch (error) {
    state.error = error instanceof Error ? error.message : String(error);
    renderApp();
  }
}

function automationRestartUrl() {
  if (state.pentestMode === "off") return "/api/automation/restart";
  return `/api/automation/restart?pentest=${encodeURIComponent(state.pentestMode)}`;
}

function readPentestMode(): PentestMode {
  const value = window.localStorage.getItem("bakulaPentestMode");
  return value === "off" || value === "aggressive" ? value : "smart";
}

function cyclePentestMode() {
  state.pentestMode = state.pentestMode === "off"
    ? "smart"
    : state.pentestMode === "smart"
      ? "aggressive"
      : "off";
  window.localStorage.setItem("bakulaPentestMode", state.pentestMode);
}

async function resetAutomation() {
  try {
    const response = await fetch("/api/automation/reset", {
      method: "POST",
      headers: buildAuthHeaders(),
    });
    if (!response.ok) throw new Error(`Reset autopilota selhal (${response.status}).`);
    state.error = null;
    await refreshData(false, true);
  } catch (error) {
    state.error = error instanceof Error ? error.message : String(error);
    renderApp();
  }
}

function bindGraphInteractions() {
  const surface = root.querySelector<HTMLElement>("[data-graph-surface='topology']");
  const tooltip = root.querySelector<HTMLElement>("#graphTooltip");
  if (!surface || !tooltip) return;
  const hideTooltip = () => tooltip.classList.remove("is-visible");
  const anchorOf = (element: Element) => {
    const rect = element.getBoundingClientRect();
    return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
  };
  const placeTooltipAtAnchor = (
    anchorX: number,
    anchorY: number,
    html: string,
    widthFactor: number,
    heightFactor: number,
  ) => {
    const rect = surface.getBoundingClientRect();
    const margin = clamp(Math.min(rect.width, rect.height) * 0.02, 10, 20);
    const tooltipWidth = clamp(rect.width * widthFactor, 220, 340);
    const tooltipHeight = clamp(rect.height * heightFactor, 132, 236);
    const horizontalOffset =
      anchorX >= rect.left + rect.width / 2
        ? -(tooltipWidth + margin * 0.62)
        : margin * 0.82;
    const verticalOffset =
      anchorY >= rect.top + rect.height / 2
        ? -(tooltipHeight * 0.72)
        : -(tooltipHeight * 0.28);

    const x = clamp(
      anchorX - rect.left + horizontalOffset,
      margin,
      rect.width - tooltipWidth - margin,
    );
    const y = clamp(
      anchorY - rect.top + verticalOffset,
      margin,
      rect.height - tooltipHeight - margin,
    );
    const originX = clamp(
      ((anchorX - rect.left - x) / Math.max(tooltipWidth, 1)) * 100,
      0,
      100,
    );
    const originY = clamp(
      ((anchorY - rect.top - y) / Math.max(tooltipHeight, 1)) * 100,
      0,
      100,
    );

    tooltip.style.setProperty("--tip-x", cssLength(x));
    tooltip.style.setProperty("--tip-y", cssLength(y));
    tooltip.style.setProperty("--tip-origin-x", `${originX.toFixed(1)}%`);
    tooltip.style.setProperty("--tip-origin-y", `${originY.toFixed(1)}%`);
    tooltip.innerHTML = html;
    tooltip.classList.add("is-visible");
  };
  let dragging = false;
  let pointerId = 0;
  let startX = 0;
  let startY = 0;
  let basePanX = state.panX;
  let basePanY = state.panY;
  surface.style.cursor = "grab";
  surface.onwheel = (event) => {
    event.preventDefault();
    state.zoom = clamp(state.zoom + (event.deltaY < 0 ? 0.12 : -0.12), 0.7, 3.2);
    updateGraphZoom();
  };
  surface.onpointerdown = (event) => {
    const target = event.target as HTMLElement | null;
    if (target?.closest("[data-node-id], [data-edge-id], button")) return;
    dragging = true;
    pointerId = event.pointerId;
    startX = event.clientX;
    startY = event.clientY;
    basePanX = state.panX;
    basePanY = state.panY;
    surface.setPointerCapture(pointerId);
    surface.style.cursor = "grabbing";
  };
  surface.onpointermove = (event) => {
    if (!dragging) return;
    const rect = surface.getBoundingClientRect();
    const viewport = root.querySelector<HTMLElement>("#graphTransform");
    const sceneWidth = Number(viewport?.dataset.sceneWidth ?? rect.width);
    const sceneHeight = Number(viewport?.dataset.sceneHeight ?? rect.height);
    const panLimitX = Math.max(
      (sceneWidth * state.zoom - rect.width) / 2 + rect.width * 0.08,
      rect.width * 0.12,
    );
    const panLimitY = Math.max(
      (sceneHeight * state.zoom - rect.height) / 2 + rect.height * 0.08,
      rect.height * 0.12,
    );
    state.panX = clamp(basePanX + (event.clientX - startX), -panLimitX, panLimitX);
    state.panY = clamp(basePanY + (event.clientY - startY), -panLimitY, panLimitY);
    updateGraphZoom();
  };
  surface.onpointerup = () => {
    dragging = false;
    surface.style.cursor = "grab";
  };
  surface.onpointercancel = () => {
    dragging = false;
    surface.style.cursor = "grab";
  };
  surface.querySelectorAll<SVGElement>("[data-node-id]").forEach((nodeElement) => {
    const nodeId = nodeElement.getAttribute("data-node-id") ?? "";
    const node = state.graphNodes.find((item) => item.id === nodeId);
    if (!node) return;
    const place = () => {
      const shell =
        nodeElement.querySelector("circle.graph-node-shell") ??
        nodeElement.querySelector("circle") ??
        nodeElement;
      const anchor = anchorOf(shell);
      placeTooltipAtAnchor(
        anchor.x,
        anchor.y,
        `<div class="tooltip-title">${escapeHtml(node.title)}</div><div class="tooltip-sub">${escapeHtml(node.layerLabel)} · ${escapeHtml(node.subtitle)}</div><div class="tooltip-list">${compact([
        node.issueCounts.total ? `rizika ${node.issueCounts.total}` : "",
        node.trafficPackets ? `pakety ${node.trafficPackets} · ${formatBytes(node.trafficBytes)}` : "",
        ...node.details.slice(0, 3),
      ]).map((item) => `<div>${escapeHtml(item)}</div>`).join("")}</div>`,
        0.24,
        0.24,
      );
    };
    nodeElement.onmouseenter = () => place();
    nodeElement.onfocus = () => place();
    nodeElement.onmouseleave = hideTooltip;
    nodeElement.onblur = hideTooltip;
    nodeElement.onclick = (event) => {
      event.stopPropagation();
      const panel = node.kind === "hub" ? "findings" : node.kind === "external" ? "lanes" : "assets";
      focusNodeContext(nodeId, panel);
      renderApp();
    };
    nodeElement.onkeydown = (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      const panel = node.kind === "hub" ? "findings" : node.kind === "external" ? "lanes" : "assets";
      focusNodeContext(nodeId, panel);
      renderApp();
    };
  });
  surface.querySelectorAll<SVGGElement>("[data-edge-id]").forEach((edgeElement) => {
    const edgeId = edgeElement.getAttribute("data-edge-id") ?? "";
    const edge = state.graphEdges.find((item) => item.id === edgeId);
    if (!edge) return;
    const place = () => {
      const path =
        edgeElement.querySelector("path.graph-edge") ?? edgeElement;
      const anchor = anchorOf(path);
      placeTooltipAtAnchor(
        anchor.x,
        anchor.y,
        `<div class="tooltip-title">${escapeHtml(edge.relation)}</div><div class="tooltip-sub">${escapeHtml(edge.source)} → ${escapeHtml(edge.target)}</div><div class="tooltip-list"><div>${edge.packets} paketů · ${formatBytes(edge.bytes)}</div><div>${edge.active ? "živý tok" : "statická vazba"} · ${edge.issueCounts.total} navázaných rizik</div><div>${edge.confidence} jistota</div></div>`,
        0.22,
        0.2,
      );
    };
    edgeElement.onmouseenter = () => place();
    edgeElement.onfocus = () => place();
    edgeElement.onmouseleave = hideTooltip;
    edgeElement.onblur = hideTooltip;
    edgeElement.onclick = (event) => { event.stopPropagation(); focusEdgeContext(edgeId); renderApp(); };
    edgeElement.onkeydown = (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      focusEdgeContext(edgeId);
      renderApp();
    };
  });
  surface.onmouseleave = hideTooltip;
}

function updateGraphZoom() {
  const viewport = root.querySelector<HTMLElement>("#graphTransform");
  if (viewport) {
    viewport.style.setProperty("--pan-x", cssLength(state.panX));
    viewport.style.setProperty("--pan-y", cssLength(state.panY));
    viewport.style.setProperty("--zoom", state.zoom.toFixed(2));
  }
}

function emptyIssueCounts(): IssueCounts {
  return { high: 0, medium: 0, low: 0, total: 0, findingIds: [] };
}

function registerIssue(counts: IssueCounts, finding: any) {
  const id = String(finding.finding_id ?? `${finding.title ?? "finding"}:${counts.total}`);
  if (counts.findingIds.includes(id)) return;
  const bucket = levelOf(finding.severity) as SeverityBucket | "neutral";
  if (bucket === "high" || bucket === "medium" || bucket === "low") counts[bucket] += 1;
  counts.total += 1;
  counts.findingIds.push(id);
}

function findingTouchesNode(
  finding: any,
  node: GraphNode,
  assets: any[],
  flows: FlowFindingRecord[],
) {
  if (finding.host_key === node.id || finding.service_key === node.id) return true;
  if (finding.service_key && node.id === String(finding.host_key ?? "")) return true;
  const matchedAsset = assets.find((asset: any) => asset.asset_id === node.id || asset.linked_host_key === node.id || asset.ip === node.id);
  if (matchedAsset) {
    if (finding.host_key === matchedAsset.ip || finding.host_key === matchedAsset.linked_host_key) return true;
    if (finding.service_key && String(finding.service_key).includes(String(matchedAsset.ip ?? ""))) return true;
  }
  const flow = flows.find(
    (item: FlowFindingRecord) => item.nodeId === node.id || item.sourceNodeId === node.id,
  );
  if (flow) {
    if (finding.host_key === flow.sourceNodeId) return true;
    const evidenceJoined = (finding.evidence ?? []).join(" ").toLowerCase();
    if (evidenceJoined.includes(String(flow.dstIp).toLowerCase()) || evidenceJoined.includes(String(flow.sourceNodeId).toLowerCase())) return true;
  }
  const nodeNeedles = compact([node.id, node.title, node.subtitle, ...(node.details ?? []), matchedAsset?.ip, matchedAsset?.mac]).map((item) => String(item).toLowerCase());
  const evidence = (finding.evidence ?? []).map((item: string) => String(item).toLowerCase());
  return nodeNeedles.some((needle) => evidence.some((entry: string) => entry.includes(needle)));
}

function buildGraph(report: Report, width: number, height: number) {
  const hostRecords = (report.hosts ?? []).sort((a: any, b: any) =>
    String(a.ip).localeCompare(String(b.ip)),
  );
  const rawAssets = getAssets(report);
  const normalizedAssets = rawAssets.length
    ? rawAssets
    : hostRecords.map((host: any) => ({
        asset_id: `host:${host.host_key}`,
        asset_type: "endpoint",
        name: host.hostname ?? host.ip,
        source: "host-only",
        confidence: "medium",
        ip: host.ip,
        mac: host.mac,
        vendor: host.vendor,
        linked_host_key: host.host_key,
        observations: [],
      }));
  const hostByKey = new Map(hostRecords.map((host: any) => [host.host_key, host]));
  const hostByIp = new Map(hostRecords.map((host: any) => [host.ip, host]));
  const flows: FlowFindingRecord[] = getFlowFindings(report).slice(0, 8);
  const cx = width / 2;
  const cy = height / 2;
  const orbit = computeGraphOrbitMetrics(width, height);
  const nodes: GraphNode[] = [];
  const hubId = "hub:scope";

  nodes.push({
    id: hubId,
    title: report.run?.scope?.join(", ") ?? "Scope",
    subtitle: `${providerLabel(report.run?.provider ?? "provider")} · ${modeLabel(report.run?.enrichment_mode ?? "mode")}`,
    layerLabel: "řídicí vrstva",
    kind: "hub",
    nodeType: "scope",
    x: cx,
    y: cy,
    sev: "neutral",
    tags: compact([report.run?.profile, report.run?.provider]),
    details: compact([
      `hosté ${report.summary?.hosts_total ?? 0}`,
      `služby ${report.summary?.services_total ?? 0}`,
      `nálezy ${report.summary?.findings_total ?? 0}`,
    ]),
    services: [],
    connected: [],
    trafficPackets: 0,
    trafficBytes: 0,
    issueCounts: emptyIssueCounts(),
  });

  const mappedHostKeys = new Set<string>();
  const assetNodes: GraphNode[] = normalizedAssets.map((asset: any) => {
    const linkedHost =
      (asset.linked_host_key && hostByKey.get(asset.linked_host_key)) ||
      (asset.ip && hostByIp.get(asset.ip)) ||
      null;
    if (linkedHost?.host_key) mappedHostKeys.add(linkedHost.host_key);
    const nodeKind = resolveNodeKindForAsset(asset, linkedHost);
    const services = (linkedHost?.services ?? [])
      .filter((service: any) => service.port_state === "open")
      .slice(0, 4)
      .map((service: any) => ({
        label: `${service.inventory?.service_name ?? service.port}/${service.port}`,
        severity: service.priorita ?? "neutral",
      }));
    return {
      id: asset.asset_id,
      title: asset.name ?? asset.asset_id,
      subtitle: `${assetTypeLabel(asset.asset_type)} · ${asset.ip ?? asset.source ?? "zdroj"}`,
      layerLabel: resolveLayerLabel(nodeKind, asset.asset_type),
      kind: nodeKind,
      nodeType: asset.asset_type,
      x: cx,
      y: cy,
      sev: linkedHost
        ? (linkedHost.services ?? []).some((service: any) => levelOf(service.priorita) === "high")
          ? "high"
          : (linkedHost.services ?? []).some((service: any) => levelOf(service.priorita) === "medium")
            ? "medium"
            : "low"
        : levelOf(asset.confidence),
      tags: buildAssetTags(asset, linkedHost),
      details: buildAssetDetails(asset, linkedHost),
      services,
      connected: [],
      trafficPackets: 0,
      trafficBytes: 0,
      issueCounts: emptyIssueCounts(),
      riskScore: 0,
      riskColor: "#34d399",
    } as GraphNode;
  });

  const orphanHosts: GraphNode[] = hostRecords
    .filter((host: any) => !mappedHostKeys.has(host.host_key))
    .map((host: any) => ({
      id: host.host_key,
      title: host.hostname || host.ip,
      subtitle: host.ip,
      layerLabel: "host vrstva",
      kind: "host" as const,
      nodeType: hostGlyphType(host),
      x: cx,
      y: cy,
      sev: (host.services ?? []).some((service: any) => levelOf(service.priorita) === "high")
        ? "high"
        : (host.services ?? []).some((service: any) => levelOf(service.priorita) === "medium")
          ? "medium"
          : "low",
      tags: compact([host.hostname, host.ip, host.vendor]),
      details: compact([
        `služby ${(host.services ?? []).filter((service: any) => service.port_state === "open").length}`,
        `vysoká priorita ${(host.services ?? []).filter((service: any) => levelOf(service.priorita) === "high").length}`,
        host.mac,
      ]),
      services: (host.services ?? [])
        .filter((service: any) => service.port_state === "open")
        .slice(0, 4)
        .map((service: any) => ({
          label: `${service.inventory?.service_name ?? service.port}/${service.port}`,
          severity: service.priorita ?? "neutral",
        })),
      connected: [],
      trafficPackets: 0,
      trafficBytes: 0,
      issueCounts: emptyIssueCounts(),
      riskScore: 0,
      riskColor: "#34d399",
    }));

  const flowNodes: GraphNode[] = flows.map((flow: FlowFindingRecord) => ({
    id: flow.nodeId,
    title: flow.dstIp,
    subtitle: flow.url ? trim(flow.url, 52) : "externí tok",
    layerLabel: "tok / externí cíl",
    kind: "external" as const,
    nodeType: "external-flow",
    x: cx,
    y: cy,
    sev: flow.severity,
    tags: compact([flow.protocol, flow.dstPort ? `:${flow.dstPort}` : "", flow.url]),
    details: compact([
      `pakety ${flow.packets}`,
      `objem ${formatBytes(flow.bytes)}`,
    ]),
    services: [],
    connected: [],
    trafficPackets: flow.packets,
    trafficBytes: flow.bytes,
    issueCounts: emptyIssueCounts(),
    riskScore: 0,
    riskColor: "#38bdf8",
  }));

  const coreNodes: GraphNode[] = assetNodes
    .filter((node: GraphNode) => node.kind === "core")
    .sort((a: GraphNode, b: GraphNode) => a.title.localeCompare(b.title));
  const hostNodes: GraphNode[] = [...assetNodes.filter((node: GraphNode) => node.kind === "host"), ...orphanHosts]
    .sort((a: GraphNode, b: GraphNode) => a.title.localeCompare(b.title));
  const clientNodes: GraphNode[] = assetNodes
    .filter((node: GraphNode) => node.kind === "client")
    .sort((a: GraphNode, b: GraphNode) => a.title.localeCompare(b.title));

  layoutRing(coreNodes, cx, cy, orbit.ringRadii[0], -90);
  layoutRing(hostNodes, cx, cy, orbit.ringRadii[1], -112);
  layoutRing(clientNodes, cx, cy, orbit.ringRadii[2], -78);
  layoutRing(flowNodes, cx, cy, orbit.ringRadii[3], -132);

  nodes.push(...coreNodes, ...hostNodes, ...clientNodes, ...flowNodes);

  const visible = new Set(nodes.map((node) => node.id));
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const edges = new Map<string, GraphEdge>();
  const addEdge = (
    source: string,
    target: string,
    relation: string,
    confidence = "medium",
    packets = 0,
    bytes = 0,
    active = false,
  ) => {
    if (!visible.has(source) || !visible.has(target) || source === target) return;
    const key = [source, target].sort().join("::");
    if (!edges.has(key)) {
      edges.set(key, {
        id: key,
        source,
        target,
        relation,
        confidence,
        packets,
        bytes,
        active,
        issueCounts: emptyIssueCounts(),
      });
    } else {
      const current = edges.get(key)!;
      current.packets = Math.max(current.packets, packets);
      current.bytes = Math.max(current.bytes, bytes);
      current.active = current.active || active;
    }
    nodeMap.get(source)?.connected.push(target);
    nodeMap.get(target)?.connected.push(source);
    nodeMap.get(source)!.trafficPackets += packets;
    nodeMap.get(source)!.trafficBytes += bytes;
    nodeMap.get(target)!.trafficPackets += packets;
    nodeMap.get(target)!.trafficBytes += bytes;
  };

  coreNodes.forEach((node: GraphNode) => addEdge(hubId, node.id, "core", "medium"));
  getTopologyEdges(report).forEach((edge: any) =>
    addEdge(
      edge.source_asset_id,
      edge.target_asset_id,
      edge.relation ?? "relation",
      edge.confidence ?? "medium",
    ),
  );
  hostNodes.forEach((node: GraphNode) => {
    const linkedAsset = coreNodes.find((candidate: GraphNode) =>
      candidate.details.some((detail: string) =>
        node.details.some((nodeDetail: string) =>
          detail.toLowerCase().includes(nodeDetail.toLowerCase()),
        ),
      ),
    );
    addEdge(linkedAsset?.id ?? hubId, node.id, linkedAsset ? "inventory" : "scope", linkedAsset ? "medium" : "low");
  });
  clientNodes.forEach((node: GraphNode) => {
    const linked = coreNodes.find((candidate: GraphNode) => {
      const lowerCandidate = candidate.title.toLowerCase();
      return node.details.some((item: string) => item.toLowerCase().includes(lowerCandidate));
    });
    addEdge(node.id, linked?.id ?? coreNodes[0]?.id ?? hubId, "visibility", linked ? "medium" : "low");
  });
  flows.forEach((flow: FlowFindingRecord) => {
    const preferredSource = normalizedAssets.find((asset: any) =>
      asset.linked_host_key === flow.sourceNodeId || asset.ip === flow.sourceNodeId,
    );
    const sourceId = preferredSource?.asset_id ?? flow.sourceNodeId;
    if (!visible.has(sourceId) || !visible.has(flow.nodeId)) return;
    addEdge(sourceId, flow.nodeId, "flow", "medium", flow.packets, flow.bytes, true);
  });

  const findings = report.findings ?? [];
  nodes.forEach((node) => {
    node.issueCounts = emptyIssueCounts();
  });
  findings.forEach((finding: any) => {
    nodes.forEach((node) => {
      if (findingTouchesNode(finding, node, normalizedAssets, flows)) {
        registerIssue(node.issueCounts, finding);
      }
    });
  });
  edges.forEach((edge) => {
    edge.issueCounts = emptyIssueCounts();
    const sourceNode = nodeMap.get(edge.source);
    const targetNode = nodeMap.get(edge.target);
    if (!sourceNode || !targetNode) return;
    findings.forEach((finding: any) => {
      if (
        findingTouchesNode(finding, sourceNode, normalizedAssets, flows) ||
        findingTouchesNode(finding, targetNode, normalizedAssets, flows)
      ) {
        registerIssue(edge.issueCounts, finding);
      }
    });
  });
  nodes.forEach((node) => {
    node.connected = Array.from(new Set(node.connected));
    node.riskScore = riskScoreFromIssueCounts(node.issueCounts);
    node.riskColor = riskColorForScore(node.riskScore);
    if (!node.issueCounts.total && node.kind !== "hub") {
      node.sev = "low";
    }
  });
  edges.forEach((edge) => {
    edge.riskScore = riskScoreFromIssueCounts(edge.issueCounts);
    edge.riskColor = riskColorForScore(edge.riskScore);
  });
  return { nodes, edges: Array.from(edges.values()) };
}

function layoutRing(nodes: GraphNode[], cx: number, cy: number, radius: number, startAngleDeg: number) {
  if (!nodes.length) return;
  const step = (Math.PI * 2) / Math.max(nodes.length, 1);
  const start = (startAngleDeg * Math.PI) / 180;
  nodes.forEach((node, index) => {
    const angle = start + step * index;
    node.x = cx + Math.cos(angle) * radius;
    node.y = cy + Math.sin(angle) * radius;
  });
}

function resolveNodeKindForAsset(asset: any, linkedHost: any) {
  if (["router", "switch", "firewall", "network-device", "access-point"].includes(asset.asset_type)) {
    return "core" as const;
  }
  if (asset.asset_type === "wireless-client") {
    return "client" as const;
  }
  const openServices = (linkedHost?.services ?? []).filter((service: any) => service.port_state === "open");
  return openServices.length ? ("host" as const) : ("client" as const);
}

function resolveLayerLabel(kind: GraphNode["kind"], assetType: string) {
  if (kind === "hub") return "řídicí vrstva";
  if (kind === "core") return assetType === "access-point" ? "přístupová vrstva" : "síťová vrstva";
  if (kind === "host") return "servisní vrstva";
  if (kind === "client") return "koncová vrstva";
  return "tok / externí cíl";
}

function buildAssetTags(asset: any, linkedHost: any) {
  return compact([
    asset.source,
    asset.vendor,
    asset.location,
    linkedHost?.hostname,
  ]);
}

function buildAssetDetails(asset: any, linkedHost: any) {
  const openServices = (linkedHost?.services ?? [])
    .filter((service: any) => service.port_state === "open")
    .slice(0, 4)
    .map((service: any) => `${service.port}/${service.proto}`);
  return compact([
    asset.ip,
    asset.mac,
    asset.vendor,
    asset.model,
    openServices.length ? `otevřeno ${openServices.join(", ")}` : "",
    ...(asset.observations ?? []).slice(0, 2),
  ]);
}

function getSelectedNode() {
  if (!state.graphNodes.length) return null;
  if (!state.selectedGraphNodeId) {
    state.selectedGraphNodeId =
      [...state.graphNodes]
        .filter((node) => node.kind !== "hub" && node.kind !== "external")
        .sort((left, right) => (right.riskScore ?? 0) - (left.riskScore ?? 0))[0]?.id ??
      state.graphNodes.find((node) => node.kind === "core")?.id ??
      state.graphNodes[0].id;
  }
  return state.graphNodes.find((node) => node.id === state.selectedGraphNodeId) ?? state.graphNodes[0] ?? null;
}
function getSelectedFinding(pool?: any[]) { const findings = pool ?? getVisibleFindings(); const id = state.selectedFindingId ?? (findings[0] ? findingKey(findings[0], 0) : null); return findings.find((finding: any) => findingKey(finding) === id) ?? findings[0] ?? null; }
function getSelectedAsset() { const assets = getAssets(state.report); if (state.selectedAssetId) return assets.find((asset: any) => asset.asset_id === state.selectedAssetId) ?? null; const nodeId = state.selectedGraphNodeId; if (nodeId) return assets.find((asset: any) => asset.asset_id === nodeId) ?? assets.find((asset: any) => asset.linked_host_key === nodeId || asset.ip === nodeId) ?? null; return assets[0] ?? null; }
function getSelectedAction() { const actions = getTriage(state.report); if (!actions.length) return null; const id = state.selectedActionId ?? actionKey(actions[0], 0); return actions.find((action: any) => actionKey(action) === id) ?? actions[0] ?? null; }
function findingKey(finding: any, index = 0) {
  if (!finding) return `finding:${index}`;
  return String(
    finding.finding_id ??
      [
        finding.title ?? "finding",
        finding.finding_type ?? "",
        finding.host_key ?? "",
        finding.service_key ?? "",
        finding.severity ?? "",
        (finding.evidence ?? []).slice(0, 2).join("|"),
      ].join("::"),
  );
}
function actionKey(action: any, index = 0) {
  if (!action) return `action:${index}`;
  return String(
    action.action_id ??
      [
        action.title ?? "action",
        action.priority ?? "",
        action.target_service_key ?? "",
        action.target_asset_id ?? "",
        action.next_step ?? "",
      ].join("::"),
  );
}
function getAssets(report: Report | null) {
  const explicitAssets = [...(report?.networkAssets ?? report?.network_assets ?? [])];
  const hosts = report?.hosts ?? [];
  if (!hosts.length) return explicitAssets;
  const covered = new Set(
    explicitAssets.flatMap((asset: any) =>
      compact([asset.asset_id, asset.linked_host_key, asset.host_key, asset.ip]),
    ),
  );
  const hostAssets = hosts
    .filter((host: any) => !covered.has(String(host.host_key ?? "")) && !covered.has(String(host.ip ?? "")))
    .map((host: any, index: number) => hostToAsset(host, index));
  return [...explicitAssets, ...hostAssets];
}

function hostToAsset(host: any, index: number) {
  const openServices = (host.services ?? []).filter((service: any) => service.port_state === "open");
  const highServices = openServices.filter((service: any) => levelOf(service.priorita) === "high").length;
  const assetId = String(host.host_key ?? host.ip ?? `host:${index + 1}`);
  return {
    asset_id: assetId,
    asset_type: "endpoint",
    name: host.hostname || host.ip || assetId,
    source: "nmap",
    confidence: highServices ? "high" : "medium",
    ip: host.ip,
    mac: host.mac,
    vendor: host.vendor,
    model: host.os_name,
    linked_host_key: host.host_key ?? assetId,
    status: host.status ?? "observed",
    observations: compact([
      openServices.length ? `otevřené služby ${openServices.length}` : "",
      highServices ? `vysoká priorita ${highServices}` : "",
      host.os_name,
    ]),
  };
}
function getTopologyEdges(report: Report | null) { return report?.topologyEdges ?? report?.topology_edges ?? []; }
function getLanes(report: Report | null) { return report?.monitoringLanes ?? report?.monitoring_lanes ?? []; }
function getTriage(report: Report | null) { return report?.triageActions ?? report?.triage_actions ?? []; }
function getFlowFindings(report: Report | null): FlowFindingRecord[] {
  return (report?.findings ?? [])
    .filter((finding: any) => finding.finding_type === "external_flow_observed")
    .map((finding: any, index: number) => {
      const evidence = new Map<string, string>();
      (finding.evidence ?? []).forEach((item: string) => {
        const [key, ...rest] = String(item).split("=");
        if (key && rest.length) evidence.set(key, rest.join("="));
      });
      const dstIp = evidence.get("dst_ip") ?? `externi-${index + 1}`;
      return {
        nodeId: `flow:${dstIp}`,
        sourceNodeId: finding.host_key ?? evidence.get("src_ip") ?? "",
        dstIp,
        dstPort: evidence.get("dst_port") ?? "",
        protocol: evidence.get("protocol") ?? "",
        packets: Number(evidence.get("packets") ?? 0),
        bytes: Number(evidence.get("bytes") ?? 0),
        url: evidence.get("url") && evidence.get("url") !== "-" ? evidence.get("url") ?? "" : "",
        severity: levelOf(finding.severity),
      };
    })
    .filter((item: FlowFindingRecord) => item.sourceNodeId.length > 0);
}
function getVisibleFindings() {
  const findings = state.report?.findings ?? [];
  if (state.detailScope === "all") return findings;
  if (state.selectedGraphEdgeId) {
    const relatedIds = new Set(getRelatedFindingsForEdge(state.selectedGraphEdgeId).map((item: any) => findingKey(item)));
    const filtered = findings.filter((finding: any) => relatedIds.has(findingKey(finding)));
    if (filtered.length) return filtered;
  }
  if (state.selectedGraphNodeId) {
    const relatedIds = new Set(getRelatedFindingsForNode(state.selectedGraphNodeId).map((item: any) => findingKey(item)));
    const filtered = findings.filter((finding: any) => relatedIds.has(findingKey(finding)));
    if (filtered.length) return filtered;
  }
  return findings;
}
function getRelatedFindingsForNode(nodeId: string | null) {
  if (!nodeId || !state.report) return [];
  const node = state.graphNodes.find((item) => item.id === nodeId) ?? null;
  const assets = getAssets(state.report);
  const flows = getFlowFindings(state.report);
  if (node) {
    return (state.report.findings ?? []).filter((finding: any) => findingTouchesNode(finding, node, assets, flows));
  }
  const asset = assets.find((item: any) => item.asset_id === nodeId || item.linked_host_key === nodeId || item.ip === nodeId) ?? null;
  const evidenceNeedles = compact([nodeId, asset?.ip, asset?.mac, asset?.name, asset?.linked_host_key]).map((item) => String(item).toLowerCase());
  return (state.report.findings ?? []).filter((finding: any) => {
    if (finding.host_key === nodeId || finding.service_key === nodeId) return true;
    if (asset && (finding.host_key === asset.ip || finding.host_key === asset.linked_host_key || String(finding.service_key ?? "").includes(String(asset.ip ?? "")))) return true;
    const evidence = (finding.evidence ?? []).map((item: string) => String(item).toLowerCase());
    return evidenceNeedles.some((needle: string) => evidence.some((entry: string) => entry.includes(needle)));
  });
}
function getRelatedFindingsForEdge(edgeId: string | null) {
  if (!edgeId) return [];
  const edge = state.graphEdges.find((item) => item.id === edgeId);
  if (!edge) return [];
  const assets = getAssets(state.report);
  const flows = getFlowFindings(state.report);
  const leftNode = state.graphNodes.find((item) => item.id === edge.source) ?? null;
  const rightNode = state.graphNodes.find((item) => item.id === edge.target) ?? null;
  const map = new Map<string, any>();
  (state.report?.findings ?? []).forEach((finding: any, index: number) => {
    const leftMatch = leftNode ? findingTouchesNode(finding, leftNode, assets, flows) : false;
    const rightMatch = rightNode ? findingTouchesNode(finding, rightNode, assets, flows) : false;
    if (leftMatch || rightMatch) map.set(findingKey(finding, index), finding);
  });
  return Array.from(map.values());
}
function assetCounts(assets: any[]) { return { accessPoints: assets.filter((item) => item.asset_type === "access-point").length, clients: assets.filter((item) => item.asset_type === "wireless-client").length, switches: assets.filter((item) => ["switch", "router", "firewall", "network-device"].includes(item.asset_type)).length }; }
function riskScoreFromIssueCounts(counts: IssueCounts | null | undefined) {
  if (!counts || !counts.total) return 0;
  const weighted = counts.high * 1 + counts.medium * 0.62 + counts.low * 0.28;
  return clamp(weighted / Math.max(1, counts.total + counts.high * 0.35), 0, 1);
}
function riskColorForScore(score: number) {
  if (score <= 0) return "#34d399";
  if (score >= 1) return "#fb7185";
  const clamped = clamp(score, 0, 1);
  const hue = 148 - clamped * 138;
  const sat = 72 + clamped * 10;
  const light = 56 + (1 - clamped) * 2;
  return `hsl(${hue.toFixed(1)} ${sat.toFixed(1)}% ${light.toFixed(1)}%)`;
}
function computeRisk(report: Report | null) { if (!report) return { className: "severity-neutral", label: "Bez dat", icon: "circle-dashed" }; const findings = report.findings ?? []; if (findings.some((finding: any) => levelOf(finding.severity) === "high")) return { className: "severity-high", label: "Priorita", icon: "shield-alert" }; if (findings.some((finding: any) => levelOf(finding.severity) === "medium")) return { className: "severity-medium", label: "Pozor", icon: "alert-triangle" }; return { className: "severity-low", label: "Klid", icon: "shield" }; }
function pill(label: string, value: number, icon: string) { return `<span class="tiny-chip"><i data-lucide="${icon}" class="h-3.5 w-3.5"></i>${escapeHtml(label)} · ${value}</span>`; }
function emptyState(message: string) { return `<div class="empty-state">${escapeHtml(message)}</div>`; }
function severity(value: string) { const normalized = levelOf(value); if (normalized === "high") return "severity-high"; if (normalized === "medium") return "severity-medium"; if (normalized === "low") return "severity-low"; return "severity-neutral"; }
function levelOf(value: string) { const normalized = String(value ?? "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, ""); if (normalized.includes("vysok") || normalized === "high" || normalized === "critical") return "high"; if (normalized.includes("stred") || normalized === "medium" || normalized === "partial") return "medium"; if (normalized.includes("niz") || normalized === "low" || normalized === "ok") return "low"; return "neutral" as const; }
function detailEyebrow(type: string) {
  const normalized = String(type ?? "").toLowerCase();
  if (normalized.includes("greenbone")) return "audit";
  if (normalized.includes("flow")) return "živý tok";
  if (normalized.includes("config")) return "konfigurace";
  if (normalized.includes("cve")) return "riziko";
  return "nález";
}
function assetTypeLabel(type: string) { if (type === "access-point") return "AP"; if (type === "wireless-client") return "Wi‑Fi klient"; if (type === "switch") return "switch"; if (type === "router") return "router"; if (type === "endpoint") return "endpoint"; if (type === "network-device") return "síťový prvek"; return type; }
function confidenceLabel(value: string) {
  const normalized = String(value ?? "").toLowerCase();
  if (normalized.includes("high")) return "jistota vysoká";
  if (normalized.includes("medium")) return "jistota střední";
  if (normalized.includes("low")) return "jistota nízká";
  return normalized ? `jistota ${normalized}` : "";
}
function hostGlyphType(host: any) { const services = (host.services ?? []).map((service: any) => Number(service.port)); if (services.includes(80) || services.includes(443)) return "web"; if (services.includes(21) || services.includes(22) || services.includes(23)) return "správa"; return "server"; }
function nodeGlyph(node: GraphNode) { if (node.kind === "hub") return "●"; if (node.kind === "external") return "WAN"; if (node.nodeType === "access-point") return "AP"; if (node.nodeType === "switch") return "SW"; if (node.nodeType === "router") return "RT"; if (node.nodeType === "wireless-client") return "WF"; if (node.nodeType === "endpoint") return "PC"; if (node.nodeType === "web") return "WEB"; if (node.nodeType === "správa") return "ADM"; return node.kind === "host" ? "SRV" : "NET"; }
function providerLabel(value: string) { return String(value).toLowerCase() === "demo" ? "demo" : value; }
function modeLabel(value: string) { const normalized = String(value).toLowerCase(); return normalized === "live" ? "živě" : normalized === "audit" ? "audit" : value; }
function displayRunName(value: string) { return String(value) === "Full visibility stack" ? "Plný přehled sítě" : value; }
function localizeUiText(value: string) {
  return String(value)
    .replace(/\bLive vrstva\b/g, "Živá vrstva")
    .replace(/\bLIVE\b/g, "ŽIVĚ")
    .replace(/\blive\b/g, "živě");
}
function relativeTime(value: string | null) { if (!value) return "offline"; const diff = Date.now() - new Date(value).getTime(); const seconds = Math.max(0, Math.round(diff / 1000)); if (seconds < 5) return "právě"; if (seconds < 60) return `${seconds}s`; if (seconds < 3600) return `${Math.round(seconds / 60)}m`; return `${Math.round(seconds / 3600)}h`; }
function formatBytes(value: number) { if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`; if (value >= 1024) return `${Math.round(value / 1024)} kB`; return `${value} B`; }
function compact(values: Array<string | undefined | null>) { return values.filter((value): value is string => Boolean(value && String(value).trim())).map((value) => String(value)); }
function trim(value: string, max: number) { return value.length > max ? `${value.slice(0, max - 1)}…` : value; }
function clamp(value: number, min: number, max: number) { return Math.max(min, Math.min(max, value)); }
function escapeHtml(value: unknown) { return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;"); }
function escapeAttr(value: unknown) { return escapeHtml(value); }
function requestedFocus() {
  const focus = new URL(window.location.href).searchParams.get("focus");
  if (focus === "topology" || focus === "audit") return focus as FocusMode;
  return null;
}
function setFocusQuery(panel: FocusMode | null) { const url = new URL(window.location.href); if (panel) url.searchParams.set("focus", panel); else url.searchParams.delete("focus"); window.history.replaceState({}, "", url); }
