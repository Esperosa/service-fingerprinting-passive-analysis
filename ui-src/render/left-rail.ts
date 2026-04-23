import type { UiRenderCtx } from "./context";

export function renderLeftRail(ctx: UiRenderCtx) {
  return `
    ${renderStatusPanel(ctx)}
    ${renderControlPanel(ctx)}
    ${renderDataPanel(ctx)}
    ${renderDiagnosticsPanel(ctx)}
    ${renderExportPanel(ctx)}
    ${renderRunsPanel(ctx)}
  `;
}

function renderStatusPanel(ctx: UiRenderCtx) {
  const run = ctx.state.report?.run;
  const status = ctx.state.automationStatus;
  const live = Boolean(ctx.state.liveMode);
  const running = Boolean(status?.process_running);
  return `
    <section class="rail-card rail-status-card">
      <div class="rail-section-head">
        <span>Stav</span>
        <span class="rail-dot ${live ? "is-live" : ""}" title="${ctx.escapeAttr(ctx.relativeTime(ctx.state.lastUpdatedAt))}"></span>
      </div>
      <button type="button" class="rail-primary-run" data-focus-clear title="${ctx.escapeAttr(ctx.displayRunName(run?.nazev ?? "Bakula"))}">
        <i data-lucide="radar" class="h-4 w-4"></i>
        <span>${ctx.escapeHtml(ctx.trim(ctx.displayRunName(run?.nazev ?? "Bakula"), 24))}</span>
      </button>
      <div class="rail-mini-grid">
        <span title="Realtime">${live ? "Live" : "Ručně"}</span>
        <span title="Autopilot">${running ? "Běh" : "Klid"}</span>
      </div>
    </section>
  `;
}

function renderControlPanel(ctx: UiRenderCtx) {
  const status = ctx.state.automationStatus;
  const running = Boolean(status?.process_running);
  const pentestLabel = ctx.state.pentestMode === "aggressive" ? "Hard" : ctx.state.pentestMode === "smart" ? "Smart" : "Vyp.";
  const pentestTitle = ctx.state.pentestMode === "aggressive"
    ? "Agresivnější autorizovaný pentest [P]"
    : ctx.state.pentestMode === "smart"
      ? "Interní smart pentest [P]"
      : "Pentest vypnutý [P]";
  const tokenControl = ctx.state.authRequired
    ? ctx.state.apiTokenPresent
      ? actionButton(ctx, "shield", "API", "Token je uložený. Kliknutím ho vypneš pro UI.", "data-token-clear", false, true)
      : actionButton(ctx, "shield", "Bez API", "Token je volitelný. Kliknutím ho můžeš doplnit pro chráněné akce.", "data-token-set", false, false)
    : "";
  return `
    <section class="rail-card rail-control-card control-panel">
      <div class="rail-section-head"><span>Ovládání</span><span>kbd</span></div>
      <div class="rail-action-grid">
        ${actionButton(ctx, "play", "Start", "Spustit autopilot", "data-automation-start", running)}
        ${actionButton(ctx, "rotate-ccw", "Reset", "Reset autopilota", "data-automation-reset", false)}
        ${actionButton(ctx, "refresh-cw", "Obnovit", "Načíst znovu [R]", "data-refresh", false)}
        ${actionButton(ctx, "activity", ctx.state.liveMode ? "Live" : "Ručně", "Přepnout realtime [L]", "data-live-toggle", false, ctx.state.liveMode)}
        ${actionButton(ctx, "shield-alert", pentestLabel, pentestTitle, "data-pentest-toggle", false, ctx.state.pentestMode !== "off")}
        ${tokenControl}
      </div>
    </section>
  `;
}

function actionButton(ctx: UiRenderCtx, icon: string, label: string, title: string, attr: string, disabled: boolean, active = false) {
  return `<button type="button" class="rail-action ${active ? "is-active" : ""}" ${attr} title="${ctx.escapeAttr(title)}" ${disabled ? "disabled" : ""}><i data-lucide="${icon}" class="h-3.5 w-3.5"></i><span>${ctx.escapeHtml(label)}</span></button>`;
}

function renderDataPanel(ctx: UiRenderCtx) {
  const summary = ctx.state.report?.summary ?? {};
  const risk = ctx.computeRisk(ctx.state.report);
  return `
    <section class="rail-card rail-data-card">
      <div class="rail-section-head"><span>Stav</span><span>${ctx.escapeHtml(risk.label)}</span></div>
      <div class="rail-stat-grid">
        ${statButton(ctx, "network", "Host", summary.hosts_total ?? 0, "assets")}
        ${statButton(ctx, "shield-alert", "Risk", summary.findings_total ?? 0, "findings")}
        ${statButton(ctx, "activity", "Sig", summary.events_total ?? 0, "lanes")}
        ${statButton(ctx, "radar", "CVE", summary.cves_total ?? 0, "findings")}
        ${statButton(ctx, "waves", "Tok", summary.flow_events_total ?? summary.topology_edges_total ?? 0, "lanes")}
        ${statButton(ctx, "sparkles", "Krok", summary.triage_actions_total ?? 0, "triage")}
      </div>
    </section>
  `;
}

function statButton(ctx: UiRenderCtx, icon: string, label: string, value: number, panel: string) {
  return `
    <button type="button" class="rail-stat" data-detail-panel="${ctx.escapeAttr(panel)}" data-detail-scope="all" data-detail-view="list" data-center-mode="reader" title="${ctx.escapeAttr(`${label}: ${value}`)}">
      <i data-lucide="${icon}" class="h-3.5 w-3.5"></i>
      <strong>${value}</strong>
      <span>${ctx.escapeHtml(label)}</span>
    </button>
  `;
}

function renderDiagnosticsPanel(ctx: UiRenderCtx) {
  const status = ctx.state.automationStatus;
  const latest = ctx.state.automationLatest;
  const summary = ctx.state.report?.summary ?? {};
  const progress = clamp(status?.progress_pct ?? Math.round((latest?.summary.tooling_coverage_ratio ?? 0) * 100), 0, 100);
  const consensus = clamp(Math.round(Number(summary.mas_consensus_score ?? latest?.summary.mas_consensus_score ?? 0) * 100), 0, 100);
  const parallelism = clamp(Math.round(Number(summary.mas_parallelism_ratio ?? latest?.summary.mas_parallelism_ratio ?? 0) * 100), 0, 100);
  const queue = Math.max(0, Math.round(Number(summary.mas_queue_wait_ms_avg ?? latest?.summary.mas_queue_wait_ms_avg ?? 0)));
  const readiness = ctx.state.readiness;
  const readinessPct = clamp(Math.round(Number(readiness?.score ?? 0) * 100), 0, 100);
  const readinessGrade = readiness?.grade ?? "-";
  const blockers = readiness?.blockers?.length ?? 0;
  const aiReady = ctx.state.aiStatus?.status === "ready";
  return `
    <section class="rail-card rail-diag-card">
      <div class="rail-section-head"><span>Diagnostika</span><span>${ctx.escapeHtml(readinessGrade)}</span></div>
      ${diagLine("Průběh", progress)}
      ${diagLine("Prod", readinessPct)}
      <div class="rail-mini-grid">
        <span title="Konsenzus">C ${consensus}%</span>
        <span title="Paralelismus">P ${parallelism}%</span>
        <span title="Fronta">Q ${queue}</span>
        <span title="${ctx.escapeAttr(readiness?.next_steps?.[0] ?? "Production readiness")}">B ${blockers}</span>
        <span title="Lokální AI">${aiReady ? "AI ok" : "AI lim"}</span>
      </div>
    </section>
  `;
}

function diagLine(label: string, value: number) {
  return `<div class="rail-diag-line"><span>${label}</span><div class="progress-line"><span style="width:${value}%"></span></div></div>`;
}

function renderExportPanel(ctx: UiRenderCtx) {
  return `
    <section class="rail-card rail-export-card">
      <div class="rail-section-head"><span>Export</span><span>run</span></div>
      <div class="rail-action-grid">
        ${exportButton(ctx, "json", "JSON")}
        ${exportButton(ctx, "md", "MD")}
        ${exportButton(ctx, "txt", "TXT")}
      </div>
    </section>
  `;
}

function exportButton(ctx: UiRenderCtx, format: "json" | "md" | "txt", label: string) {
  return `<button type="button" class="rail-action" data-export="${format}" ${ctx.state.report ? "" : "disabled"} title="${ctx.escapeAttr(`Export ${label}`)}"><i data-lucide="download" class="h-3.5 w-3.5"></i><span>${label}</span></button>`;
}

function renderRunsPanel(ctx: UiRenderCtx) {
  const runs = ctx.state.runs.slice(0, 4);
  if (!runs.length) return "";
  return `
    <section class="rail-card rail-runs-card">
      <div class="rail-section-head"><span>Běhy</span><span>${ctx.state.runs.length}</span></div>
      <div class="rail-run-list">
        ${runs.map((run: any, index: number) => `<button type="button" class="rail-run-row ${run.run_id === ctx.state.activeRunId ? "is-active" : ""}" data-run-id="${ctx.escapeAttr(run.run_id)}" title="${ctx.escapeAttr(ctx.displayRunName(run.nazev))}"><span>${index + 1}</span><strong>${ctx.escapeHtml(ctx.trim(ctx.displayRunName(run.nazev), 18))}</strong></button>`).join("")}
      </div>
    </section>
  `;
}

const clamp = (value: number, min: number, max: number) => Math.max(min, Math.min(max, value));
