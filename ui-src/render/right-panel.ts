import type { UiRenderCtx } from "./context";

export function renderRightStage(ctx: UiRenderCtx) {
  return ctx.state.rightMode === "chat"
    ? `<div class="right-stack is-chat"><div id="auditHeroBlock" class="audit-hero-block">${renderAuditHero(ctx)}</div><div id="auditChatBlock" class="audit-chat-block">${renderAuditChat(ctx)}</div></div>`
    : `<div class="right-stack"><div id="auditHeroBlock" class="audit-hero-block">${renderAuditHero(ctx)}</div><div id="auditTabsBlock" class="audit-tabs-block">${renderAuditTabs(ctx)}</div><div id="auditDetailBlock" class="audit-detail-block">${renderAuditDetail(ctx)}</div></div>`;
}

function renderAuditHero(ctx: UiRenderCtx) {
  const summary = ctx.state.report?.summary ?? {};
  const expanded = ctx.requestedFocus() === "audit";
  return `
    <div class="audit-hero-shell">
      <button type="button" class="audit-assistant-button" data-chat-toggle title="${ctx.state.rightMode === "chat" ? "Zpět na panel" : "Otevřít chat"}" aria-label="${ctx.state.rightMode === "chat" ? "Zpět na auditní panel" : "Otevřít auditní chat"}">
        <i data-lucide="bot" class="h-5 w-5"></i>
      </button>
      <button type="button" class="audit-focus-button ${expanded ? "is-active" : ""}" data-focus="audit" title="${expanded ? "Zmenšit panel" : "Zvětšit panel"}" aria-label="${expanded ? "Zmenšit auditní panel" : "Zvětšit auditní panel"}">
        <i data-lucide="${expanded ? "minimize-2" : "maximize-2"}" class="h-4 w-4"></i>
      </button>
      <div class="audit-hero-card">
        ${auditMetric(ctx, "shield-alert", summary.findings_total ?? 0, "Nálezy")}
        ${auditMetric(ctx, "activity", summary.events_total ?? 0, "Signály")}
        ${auditMetric(ctx, "radar", summary.cves_total ?? 0, "CVE")}
      </div>
    </div>
  `;
}

function auditMetric(ctx: UiRenderCtx, icon: string, value: number, label: string) {
  return `<span class="audit-metric" title="${ctx.escapeAttr(label)}" aria-label="${ctx.escapeAttr(`${label}: ${value}`)}"><i data-lucide="${icon}" class="h-3.5 w-3.5"></i><strong>${value}</strong></span>`;
}

function renderAuditTabs(ctx: UiRenderCtx) {
  return `
    <div class="audit-tabs">
      <div class="audit-tab-grid">
        ${Object.keys(ctx.DETAIL_META).map((panel) => {
          const meta = ctx.DETAIL_META[panel];
          return `<button type="button" class="tab-chip ${ctx.state.detailPanel === panel ? "is-active" : ""}" data-detail-panel="${panel}" title="${ctx.escapeAttr(meta.title)}" aria-label="${ctx.escapeAttr(meta.title)}"><i data-lucide="${meta.icon}" class="h-4 w-4"></i><span>${ctx.escapeHtml(meta.title)}</span></button>`;
        }).join("")}
      </div>
      <div class="audit-mode-grid" aria-label="Režim pravého panelu">
        ${modeButton(ctx, "scan-line", "Detail", "detail", "detailView")}
        ${modeButton(ctx, "layers", "Seznam", "list", "detailView")}
        ${modeButton(ctx, "radar", "Kontext", "context", "detailScope")}
        ${modeButton(ctx, "network", "Vše", "all", "detailScope")}
      </div>
    </div>
  `;
}

function modeButton(ctx: UiRenderCtx, icon: string, label: string, value: string, field: "detailView" | "detailScope") {
  const active = ctx.state[field] === value;
  const dataAttr = field === "detailView" ? "data-detail-view" : "data-detail-scope";
  return `<button type="button" class="mode-chip ${active ? "is-active" : ""}" ${dataAttr}="${ctx.escapeAttr(value)}" title="${ctx.escapeAttr(label)}"><i data-lucide="${icon}" class="h-3.5 w-3.5"></i><span>${ctx.escapeHtml(label)}</span></button>`;
}

function renderAuditChat(ctx: UiRenderCtx) {
  const ai = ctx.state.aiStatus;
  const aiStatus = ai?.status ?? "unknown";
  const aiReady = aiStatus === "ready";
  const aiLabel = aiReady ? "lokální AI" : aiStatus === "base-ready" ? "AI profil chybí" : aiStatus === "missing-model" ? "model chybí" : aiStatus === "ollama-not-running" ? "Ollama neběží" : "fallback";
  return `
    <div class="chat-shell classic-chat-shell">
      <div class="ai-status-strip ${aiReady ? "is-ready" : "is-limited"}" title="${ctx.escapeAttr([ai?.gpu_runtime_hint, ...(ai?.next_steps ?? [])].filter(Boolean).join(" "))}">
        <span><i data-lucide="bot" class="h-3.5 w-3.5"></i>${ctx.escapeHtml(aiLabel)}</span>
        <code>${ctx.escapeHtml(ai?.selected_model ?? "deterministický režim")}</code>
      </div>
      <div class="chat-log" id="chatLog" data-scroll-key="chat">
        ${ctx.state.chatMessages.map((message: any, index: number) => `
          <div class="chat-bubble ${message.role === "assistant" ? "is-assistant" : "is-user"} ${message.streaming ? "is-streaming" : ""}" data-chat-index="${index}">
            <div data-chat-text>${ctx.escapeHtml(message.text || (message.streaming ? "Píšu odpověď…" : ""))}</div>
            ${message.sources?.length ? `<div class="chat-source-row">${message.sources.slice(0, 3).map((source: string) => `<span class="tiny-chip">${ctx.escapeHtml(source)}</span>`).join("")}</div>` : ""}
          </div>
        `).join("")}
        ${ctx.state.chatBusy && !ctx.state.chatMessages.some((message: any) => message.streaming) ? `<div class="chat-bubble is-assistant is-loading">Připravuji odpověď…</div>` : ""}
      </div>
      <div class="chat-compose">
        <div class="chat-quick-row compact">
          <button type="button" class="chat-quick" data-chat-prompt="Co mám řešit jako první?">Priorita</button>
          <button type="button" class="chat-quick" data-chat-prompt="Co znamená vybrané riziko?">Riziko</button>
          <button type="button" class="chat-quick" data-chat-prompt="Co je to za zařízení?">Zařízení</button>
          <button type="button" class="chat-quick" data-chat-prompt="Jaký je další krok?">Krok</button>
        </div>
        <div class="chat-input-row">
          <textarea id="chatInput" class="chat-input" rows="2" placeholder="Dotaz k vybranému nálezu nebo zařízení">${ctx.escapeHtml(ctx.state.chatDraft)}</textarea>
          <button type="button" class="chat-send" data-chat-send title="Odeslat" ${ctx.state.chatBusy ? "disabled" : ""}><i data-lucide="chevron-right" class="h-4 w-4"></i></button>
        </div>
      </div>
    </div>
  `;
}

function renderAuditDetail(ctx: UiRenderCtx) {
  switch (ctx.state.detailPanel) {
    case "findings": return renderFindingsDetail(ctx);
    case "assets": return renderAssetsDetail(ctx);
    case "lanes": return renderLanesDetail(ctx);
    case "triage": return renderTriageDetail(ctx);
    case "diff": return renderDiffDetail(ctx);
    default: return ctx.emptyState("Bez panelu.");
  }
}

function renderFindingsDetail(ctx: UiRenderCtx) {
  const findings = ctx.getVisibleFindings();
  const total = (ctx.state.report?.findings ?? []).length;
  const selected = ctx.getSelectedFinding(findings);
  const selectedKey = selected ? ctx.findingKey(selected) : null;
  return detailPanelWrap(ctx, "Rizika", findings.length, total, selected ? renderFindingFocus(ctx, selected) : emptyFocus(ctx, "Na tomhle výřezu nejsou žádná rizika."), findings.length ? findings.map((finding: any, index: number) => findingCard(ctx, finding, index, selectedKey != null && ctx.findingKey(finding) === selectedKey)).join("") : ctx.emptyState("Bez navázaných rizik."));
}

function renderAssetsDetail(ctx: UiRenderCtx) {
  const assets = ctx.getAssets(ctx.state.report);
  const selected = ctx.getSelectedAsset();
  return detailPanelWrap(ctx, "Stanice", assets.length, assets.length, selected ? renderAssetFocus(ctx, selected) : emptyFocus(ctx, "Načtený běh nemá inventář zařízení."), assets.length ? assets.map((asset: any) => assetCard(ctx, asset, selected && asset.asset_id === selected.asset_id)).join("") : ctx.emptyState("Bez zařízení."));
}

function renderLanesDetail(ctx: UiRenderCtx) {
  const lanes = ctx.getLanes(ctx.state.report);
  const selected = lanes[0];
  return detailPanelWrap(ctx, "Sběr", lanes.length, lanes.length, selected ? renderLaneFocus(ctx, selected) : emptyFocus(ctx, "Na tomhle běhu nejsou sběrné lane."), lanes.length ? lanes.map((lane: any) => laneCard(ctx, lane, lane === selected)).join("") : ctx.emptyState("Bez sběrných lane."));
}

function renderTriageDetail(ctx: UiRenderCtx) {
  const actions = ctx.getTriage(ctx.state.report);
  const selected = ctx.getSelectedAction();
  const selectedKey = selected ? ctx.actionKey(selected) : null;
  return detailPanelWrap(ctx, "Kroky", actions.length, actions.length, selected ? renderActionFocus(ctx, selected) : emptyFocus(ctx, "Nad tímto během není doporučený další krok."), actions.length ? actions.map((action: any, index: number) => triageCard(ctx, action, index, selectedKey != null && ctx.actionKey(action) === selectedKey)).join("") : ctx.emptyState("Bez navazujících kroků."));
}

function renderDiffDetail(ctx: UiRenderCtx) {
  const diff = ctx.state.report?.diff ?? ctx.state.report?.changes ?? [];
  const rows = Array.isArray(diff) ? diff.slice(0, 6).map((item: any) => ({ title: ctx.localizeUiText(item.title ?? item.kind ?? "Změna"), sub: ctx.localizeUiText(item.summary ?? item.value ?? "Bez detailu"), tone: ctx.levelOf(item.severity ?? item.priority ?? "medium") })) : [];
  const selected = rows[0];
  return detailPanelWrap(ctx, "Změny", rows.length, rows.length, selected ? renderDiffFocus(ctx, selected) : emptyFocus(ctx, "Na tomhle běhu není diff proti předchozímu stavu."), rows.length ? rows.map((row, index) => `<div class="detail-card ${ctx.severity(row.tone)} ${index === 0 ? "is-active" : "is-collapsed"}" title="${ctx.escapeAttr(row.title)}"><strong>${ctx.escapeHtml(ctx.trim(row.title, 52))}</strong></div>`).join("") : ctx.emptyState("Bez změn."));
}

function detailPanelWrap(ctx: UiRenderCtx, label: string, count: number, total: number, focus: string, content: string) {
  const suffix = ctx.state.detailScope === "context" && total && total !== count ? `${count}/${total}` : String(count);
  return `
    <div class="detail-panel-body ${ctx.state.detailView === "list" ? "is-list-view" : ""}">
      <div class="detail-panel-head">
        <span>${ctx.escapeHtml(label)}</span>
        <strong>${ctx.escapeHtml(suffix)}</strong>
      </div>
      <div class="detail-focus-wrap">${focus}</div>
      <div class="detail-scroll" data-scroll-key="detail">${content}</div>
    </div>
  `;
}

function emptyFocus(ctx: UiRenderCtx, message: string) {
  return `<div class="detail-focus-card severity-neutral"><div class="detail-focus-copy"><strong>Bez detailu</strong><p>${ctx.escapeHtml(message)}</p></div></div>`;
}

function renderFindingFocus(ctx: UiRenderCtx, finding: any) {
  const evidence = (finding.evidence ?? []).slice(0, 4);
  const summary = finding.finding_type === "plaintext_management_protocol"
    ? ctx.humanizeFinding(finding)
    : finding.rationale ?? ctx.humanizeFinding(finding);
  return renderDetailFocusCard(ctx, {
    tone: ctx.levelOf(finding.severity),
    eyebrow: ctx.detailEyebrow(finding.finding_type ?? "finding"),
    title: ctx.displayFindingTitle(finding),
    summary: ctx.localizeUiText(summary),
    recommendation: ctx.localizeUiText(finding.recommendation ?? ctx.recommendedSteps(finding).join(" ")),
    chips: ctx.compact([finding.host_key, finding.service_key, ctx.confidenceLabel(finding.confidence)]),
    evidence,
  });
}

function renderAssetFocus(ctx: UiRenderCtx, asset: any) {
  const related = ctx.getRelatedFindingsForNode(asset.asset_id);
  return renderDetailFocusCard(ctx, {
    tone: related[0] ? ctx.levelOf(related[0].severity) : ctx.levelOf(asset.confidence),
    eyebrow: ctx.assetTypeLabel(asset.asset_type),
    title: asset.name ?? asset.asset_id,
    summary: ctx.compact([asset.ip, asset.vendor, asset.model, asset.location, asset.status ? `stav ${asset.status}` : ""]).join(" · ") || "Zařízení je v inventáři bez doplňkových údajů.",
    recommendation: related[0] ? `Navázaná rizika: ${related.slice(0, 3).map((item: any) => ctx.displayFindingTitle(item)).join(" · ")}` : "Na tomhle zařízení teď není navázaný konkrétní nález. Využij přehled vazeb a roli zařízení v síti.",
    chips: ctx.compact([asset.source, asset.confidence, `${related.length} rizik`]),
    evidence: (asset.observations ?? []).slice(0, 4),
  });
}

function renderLaneFocus(ctx: UiRenderCtx, lane: any) {
  return renderDetailFocusCard(ctx, {
    tone: lane.status === "ok" ? "low" : lane.status === "partial" ? "medium" : "high",
    eyebrow: ctx.localizeUiText(lane.lane_type ?? "sběr"),
    title: ctx.localizeUiText(lane.title ?? "Sběrač"),
    summary: ctx.compact([ctx.localizeUiText(lane.summary ?? ""), lane.source ? `zdroj ${lane.source}` : "", lane.status ? `stav ${lane.status}` : ""]).join(" · ") || "Sběrný modul bez doplňujícího komentáře.",
    recommendation: ctx.localizeUiText(lane.recommendation ?? "Ověř navázání vstupního zdroje, dostupnost dat a konzistenci časového okna."),
    chips: ctx.compact([lane.source, lane.status, lane.mode]),
    evidence: (lane.details ?? lane.observations ?? []).slice(0, 4),
  });
}

function renderActionFocus(ctx: UiRenderCtx, action: any) {
  return renderDetailFocusCard(ctx, {
    tone: ctx.levelOf(action.priority),
    eyebrow: "další krok",
    title: ctx.localizeUiText(action.title ?? "Doporučený krok"),
    summary: ctx.localizeUiText(action.rationale ?? "Krok bez doplňujícího zdůvodnění."),
    recommendation: ctx.compact([ctx.localizeUiText(action.next_step ?? ""), (action.recommended_tools ?? []).length ? `nástroje ${(action.recommended_tools ?? []).join(", ")}` : ""]).join(" · ") || "Proveď krok a znovu porovnej výsledek se zbytkem běhu.",
    chips: ctx.compact([action.priority, action.target_service_key, action.target_asset_id]),
    evidence: (action.evidence ?? []).slice(0, 4),
  });
}

function renderDiffFocus(ctx: UiRenderCtx, row: { title: string; sub: string; tone: string }) {
  return renderDetailFocusCard(ctx, {
    tone: row.tone,
    eyebrow: "změna",
    title: row.title,
    summary: row.sub,
    recommendation: "Použij změnu jako vstup pro ověření, jestli jde o očekávaný posun nebo o nový problém v síti.",
    chips: [row.sub],
    evidence: [],
  });
}

function renderDetailFocusCard(ctx: UiRenderCtx, input: { tone: string; eyebrow: string; title: string; summary: string; recommendation: string; chips: string[]; evidence: string[]; }) {
  const expanded = ctx.requestedFocus() === "audit";
  const title = input.title;
  const summary = input.summary || input.recommendation;
  return `
    <section class="detail-focus-card ${ctx.severity(input.tone)}">
      <div class="detail-focus-head">
        <span class="speech-mark"><i data-lucide="scan-line" class="h-4 w-4"></i></span>
        <span class="speech-eyebrow">${ctx.escapeHtml(input.eyebrow)}</span>
      </div>
      <div class="detail-focus-copy">
        <strong data-check-wrap="true" title="${ctx.escapeAttr(input.title)}">${ctx.escapeHtml(title)}</strong>
        <p>${ctx.escapeHtml(summary)}</p>
      </div>
      ${input.chips.length ? `<div class="detail-focus-chips">${input.chips.map((item) => `<span class="tiny-chip">${ctx.escapeHtml(String(item))}</span>`).join("")}</div>` : ""}
      ${input.evidence.length ? `<div class="detail-signal-bars">${input.evidence.slice(0, 5).map((item, index) => `<span title="${ctx.escapeAttr(String(item))}" style="--bar:${Math.max(28, 100 - index * 14)}%"></span>`).join("")}</div>` : ""}
    </section>
  `;
}

function findingCard(ctx: UiRenderCtx, finding: any, index: number, expanded: boolean) {
  const id = ctx.findingKey(finding, index);
  const title = ctx.displayFindingTitle(finding);
  return `<button type="button" class="detail-card ${expanded ? "is-active" : "is-collapsed"} ${ctx.severity(finding.severity)}" data-select-finding="${ctx.escapeAttr(id)}" title="${ctx.escapeAttr(title)}"><strong>${ctx.escapeHtml(title)}</strong></button>`;
}

function assetCard(ctx: UiRenderCtx, asset: any, expanded: boolean) {
  const title = String(asset.name ?? asset.asset_id);
  return `<button type="button" class="detail-card ${expanded ? "is-active" : "is-collapsed"}" data-select-asset="${ctx.escapeAttr(asset.asset_id)}" title="${ctx.escapeAttr(title)}"><strong>${ctx.escapeHtml(title)}</strong></button>`;
}

function laneCard(ctx: UiRenderCtx, lane: any, expanded: boolean) {
  const tone = lane.status === "ok" ? "low" : lane.status === "partial" ? "medium" : "high";
  const title = ctx.localizeUiText(lane.title ?? "Senzor");
  return `<div class="detail-card ${ctx.severity(tone)} ${expanded ? "is-active" : "is-collapsed"}" title="${ctx.escapeAttr(title)}"><strong>${ctx.escapeHtml(title)}</strong></div>`;
}

function triageCard(ctx: UiRenderCtx, action: any, index: number, expanded: boolean) {
  const id = ctx.actionKey(action, index);
  const title = ctx.localizeUiText(action.title ?? "Doporučený krok");
  return `<button type="button" class="detail-card ${expanded ? "is-active" : "is-collapsed"} ${ctx.severity(action.priority)}" data-select-action="${ctx.escapeAttr(id)}" title="${ctx.escapeAttr(title)}"><strong>${ctx.escapeHtml(title)}</strong></button>`;
}
