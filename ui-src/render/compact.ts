import type { UiRenderCtx } from "./context";

export function renderCompactHeader(ctx: UiRenderCtx) {
  const summary = ctx.state.report?.summary ?? {};
  return `${renderBrandCompact(ctx)}<div class="compact-metrics">${miniMetric(ctx, "network", summary.hosts_total ?? 0, "Hosté")}${miniMetric(ctx, "shield-alert", summary.findings_total ?? 0, "Rizika")}${miniMetric(ctx, "wifi", summary.network_assets_total ?? 0, "Stanice")}${miniMetric(ctx, "waves", summary.monitoring_lanes_total ?? 0, "Sběr")}</div>${renderControlDockCompact(ctx)}`;
}

export function renderCompactGrid(ctx: UiRenderCtx) {
  const summary = ctx.state.report?.summary ?? {};
  return `${compactFocusCard(ctx, "topology", "Síť", summary.topology_edges_total ?? 0, "network")}${compactFocusCard(ctx, "audit", "Audit", summary.findings_total ?? 0, "shield-alert")}${compactInfoCard(ctx, "Hosté", summary.hosts_total ?? 0, "network")}${compactInfoCard(ctx, "Kroky", summary.triage_actions_total ?? 0, "sparkles")}`;
}

export function renderCompactGuide(ctx: UiRenderCtx) {
  const guide = ctx.buildGuide();
  return `
    <div class="speech-card ${ctx.severity(guide.tone)}">
      <div class="speech-head"><span class="speech-mark"><i data-lucide="bot" class="h-4 w-4"></i></span><span class="speech-eyebrow">${ctx.escapeHtml(guide.eyebrow)}</span></div>
      <strong class="speech-title" data-check-wrap="true">${ctx.escapeHtml(guide.title)}</strong>
      <p class="speech-copy">${ctx.escapeHtml(guide.summary)}</p>
    </div>
  `;
}

function renderBrandCompact(ctx: UiRenderCtx) {
  const run = ctx.state.report?.run;
  return `
    <section class="rail-card brand-card">
      <div class="brand-box">
        <div class="brand-mark"><i data-lucide="radar" class="h-5 w-5"></i></div>
        <div class="brand-copy">
          <div class="brand-row">
            <strong class="brand-title" data-check-wrap="true">${ctx.escapeHtml(ctx.displayRunName(run?.nazev ?? "Bakula"))}</strong>
            <span class="live-pill ${ctx.state.liveMode ? "is-live" : ""}"><span class="live-dot ${ctx.state.liveMode ? "is-live" : ""}"></span>${ctx.relativeTime(ctx.state.lastUpdatedAt)}</span>
          </div>
        </div>
      </div>
    </section>
  `;
}

function miniMetric(ctx: UiRenderCtx, icon: string, value: number, label: string) {
  return `<div class="mini-metric"><span class="metric-icon"><i data-lucide="${icon}" class="h-4 w-4"></i></span><strong>${value}</strong><span>${ctx.escapeHtml(label)}</span></div>`;
}

function renderControlDockCompact(ctx: UiRenderCtx) {
  return `
    <div class="control-row">
      <button type="button" class="icon-button" data-focus="topology" title="Zvětšit topologii"><i data-lucide="network" class="h-4 w-4"></i></button>
      <button type="button" class="icon-button" data-focus="audit" title="Zvětšit auditní panel"><i data-lucide="shield-alert" class="h-4 w-4"></i></button>
      <button type="button" class="icon-button ${ctx.state.liveMode ? "is-live" : ""}" data-live-toggle title="Obnovit běh"><i data-lucide="activity" class="h-4 w-4"></i></button>
      <button type="button" class="icon-button" data-refresh title="Načíst znovu"><i data-lucide="refresh-cw" class="h-4 w-4"></i></button>
    </div>
  `;
}

function compactFocusCard(ctx: UiRenderCtx, focus: string, label: string, value: number, icon: string) {
  return `<button type="button" class="panel-shell compact-card focus-card" data-focus="${focus}"><div class="panel-frame compact-card-frame"><span class="metric-icon"><i data-lucide="${icon}" class="h-4 w-4"></i></span><strong>${value}</strong><span>${ctx.escapeHtml(label)}</span></div></button>`;
}

function compactInfoCard(ctx: UiRenderCtx, label: string, value: number, icon: string) {
  return `<div class="panel-shell compact-card"><div class="panel-frame compact-card-frame"><span class="metric-icon"><i data-lucide="${icon}" class="h-4 w-4"></i></span><strong>${value}</strong><span>${ctx.escapeHtml(label)}</span></div></div>`;
}
