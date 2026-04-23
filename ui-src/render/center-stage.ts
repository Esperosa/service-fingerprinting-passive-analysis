import type { UiRenderCtx } from "./context";
import { renderGraphSvg } from "./graph";

export function renderCenterStage(ctx: UiRenderCtx) {
  const report = ctx.state.report;
  if (!report) return `<div class="empty-state">Bez reportu.</div>`;
  if (ctx.state.centerMode === "reader") return renderReaderStage(ctx);
  const nodes = ctx.state.graphNodes;
  const edges = ctx.state.graphEdges;
  const expanded = ctx.requestedFocus() === "topology";
  const dims = ctx.computeGraphSceneSize(ctx.state.layout ?? ctx.applyResponsiveLayoutVars(document.documentElement, window.innerWidth, window.innerHeight), expanded);
  const graph = renderGraphSvg(
    ctx,
    nodes,
    edges,
    dims.width,
    dims.height,
    ctx.state.selectedGraphNodeId,
    ctx.state.selectedGraphEdgeId,
  );
  const status = ctx.state.automationStatus;
  const latest = ctx.state.automationLatest;
  const progress = clamp(status?.progress_pct ?? Math.round(Number(latest?.summary?.tooling_coverage_ratio ?? 0) * 100), 0, 100);
  const phase = status?.current_phase_label ?? status?.current_phase ?? (status?.process_running ? "Běh" : "Připraveno");
  const running = Boolean(status?.process_running);
  const agentCount = status?.agents?.length ?? latest?.summary?.automation_agents_total ?? ctx.state.report?.summary?.automation_agents_total ?? 0;
  return `
    <div class="stage-shell graph-shell">
      <section class="graph-surface" data-graph-surface="topology">
        <div class="stage-head map-topbar" aria-label="Stav mapy">
          <div class="map-brand">
            <span class="brand-mark"><i data-lucide="radar" class="h-5 w-5"></i></span>
            <span class="live-dot ${ctx.state.liveMode ? "is-live" : ""}"></span>
          </div>
          <div class="stage-actions map-zoom-strip">
          <button type="button" class="icon-button" data-zoom="reset" title="Zarovnat scénu"><i data-lucide="circle-dashed" class="h-4 w-4"></i></button>
          <button type="button" class="icon-button" data-zoom="out" title="Oddálit"><i data-lucide="zoom-out" class="h-4 w-4"></i></button>
          <button type="button" class="icon-button" data-zoom="in" title="Přiblížit"><i data-lucide="zoom-in" class="h-4 w-4"></i></button>
          </div>
        </div>
        <div class="graph-viewport">
          <div
            id="graphTransform"
            class="graph-transform"
            data-scene-width="${dims.width}"
            data-scene-height="${dims.height}"
            style="--scene-width:${ctx.cssLength(dims.width)};--scene-height:${ctx.cssLength(dims.height)};--pan-x:${ctx.cssLength(ctx.state.panX)};--pan-y:${ctx.cssLength(ctx.state.panY)};--zoom:${ctx.state.zoom};"
          >
            ${graph}
          </div>
        </div>
        <div class="map-progress-card ${running ? "is-running" : ""}" data-progress-card aria-label="Progress běhu">
          <div class="map-progress-head">
            <strong data-progress-phase>${ctx.escapeHtml(phase)}</strong>
            <span data-progress-value>${progress}%</span>
          </div>
          <div class="map-progress-line"><span data-progress-bar data-progress="${progress}" style="width:${progress}%"></span></div>
          <div class="map-progress-meta">
            <span class="tiny-chip"><i data-lucide="sparkles" class="h-3.5 w-3.5"></i>${agentCount}</span>
            <span class="tiny-chip"><i data-lucide="shield-alert" class="h-3.5 w-3.5"></i>${ctx.state.pentestMode === "aggressive" ? "Hard" : ctx.state.pentestMode === "smart" ? "Smart" : "Vyp."}</span>
            <span class="tiny-chip"><i data-lucide="activity" class="h-3.5 w-3.5"></i>${ctx.state.liveMode ? "Live" : "Ručně"}</span>
          </div>
        </div>
        ${renderMobileControls(ctx)}
        <div id="graphTooltip" class="graph-tooltip"></div>
      </section>
    </div>
  `;
}

const clamp = (value: number, min: number, max: number) => Math.max(min, Math.min(max, value));

function renderReaderStage(ctx: UiRenderCtx) {
  const dataset = buildReaderDataset(ctx);
  const meta = ctx.DETAIL_META[ctx.state.detailPanel] ?? { icon: "scan-line", title: "Detail" };
  const scope = ctx.state.detailScope === "all" ? "vše" : "kontext";
  return `
    <div class="reader-shell">
      <section class="reader-surface" data-reader-surface="audit">
        <div class="reader-document-shell">
          <div class="reader-document-meta">
            <span class="reader-kicker"><i data-lucide="${meta.icon}" class="h-4 w-4"></i>${ctx.escapeHtml(meta.title)}</span>
            <span>${ctx.escapeHtml(dataset.label)}</span>
            <strong>${dataset.count}</strong>
            <span>${ctx.escapeHtml(scope)}</span>
          </div>
          <article class="reader-article" data-scroll-key="detail">
            ${dataset.article}
          </article>
        </div>
      </section>
    </div>
  `;
}

function buildReaderDataset(ctx: UiRenderCtx) {
  switch (ctx.state.detailPanel) {
    case "assets": return buildAssetReader(ctx);
    case "lanes": return buildLaneReader(ctx);
    case "triage": return buildTriageReader(ctx);
    case "diff": return buildDiffReader(ctx);
    case "findings":
    default: return buildFindingReader(ctx);
  }
}

function buildFindingReader(ctx: UiRenderCtx) {
  const items = ctx.getVisibleFindings();
  const selected = ctx.getSelectedFinding(items);
  return {
    label: ctx.state.detailScope === "all" ? "Všechny nálezy" : "Nálezy v kontextu",
    count: items.length,
    article: selected ? findingArticle(ctx, selected) : ctx.emptyState("Vyber nález v pravém panelu."),
  };
}

function buildAssetReader(ctx: UiRenderCtx) {
  const items = ctx.getAssets(ctx.state.report);
  const selected = ctx.getSelectedAsset();
  return {
    label: "Zařízení",
    count: items.length,
    article: selected ? assetArticle(ctx, selected) : ctx.emptyState("Vyber zařízení v pravém panelu."),
  };
}

function buildLaneReader(ctx: UiRenderCtx) {
  const items = ctx.getLanes(ctx.state.report);
  const selected = items[0];
  return {
    label: "Sběr a telemetrie",
    count: items.length,
    article: selected ? laneArticle(ctx, selected) : ctx.emptyState("Bez sběrných lane."),
  };
}

function buildTriageReader(ctx: UiRenderCtx) {
  const items = ctx.getTriage(ctx.state.report);
  const selected = ctx.getSelectedAction();
  return {
    label: "Doporučené kroky",
    count: items.length,
    article: selected ? actionArticle(ctx, selected) : ctx.emptyState("Bez doporučených kroků."),
  };
}

function buildDiffReader(ctx: UiRenderCtx) {
  const items = ctx.state.report?.diff?.changed_services ?? ctx.state.report?.changes ?? [];
  return {
    label: "Změny",
    count: Array.isArray(items) ? items.length : 0,
    article: Array.isArray(items) && items[0] ? genericArticle(ctx, "Změna", items[0].service_key ?? items[0].title ?? "Změna", items[0].summary ?? items[0].change_type ?? "", "", Object.entries(items[0]).map(([key, value]) => `${key}=${String(value)}`)) : ctx.emptyState("Bez změn."),
  };
}

function findingArticle(ctx: UiRenderCtx, finding: any) {
  const summary = finding.finding_type === "plaintext_management_protocol"
    ? ctx.humanizeFinding(finding)
    : finding.rationale ?? ctx.humanizeFinding(finding);
  const target = findingTarget(ctx, finding);
  const recommendation = ctx.localizeUiText(finding.recommendation ?? ctx.recommendedSteps(finding).join(" "));
  const steps = findingSteps(ctx, finding, recommendation);
  return readerArticle(ctx, {
    eyebrow: ctx.detailEyebrow(finding.finding_type ?? "finding"),
    title: ctx.displayFindingTitle(finding),
    lead: plainFindingLead(ctx, finding, summary),
    tone: ctx.severity(finding.severity),
    facts: [
      ["Týká se", target],
      ["Závažnost", severityLabel(ctx, finding.severity)],
      ["Jistota", ctx.confidenceLabel(finding.confidence)],
      ["Typ", ctx.detailEyebrow(finding.finding_type ?? "finding")],
    ],
    sections: [
      { title: "Co přesně se děje", body: ctx.localizeUiText(summary) },
      { title: "Proč to vadí", body: findingImpact(ctx, finding) },
      { title: "Co udělat teď", steps },
      { title: "Jak poznám, že je hotovo", steps: findingVerification(ctx, finding) },
    ],
    evidence: [
      ...ctx.compact([finding.host_key ? `host=${finding.host_key}` : "", finding.service_key ? `služba=${finding.service_key}` : ""]),
      ...(finding.evidence ?? []),
    ],
    footnote: "Výklad je složený lokálně z reportu a pravidel programu. AI chat vpravo může stejný kontext ještě převyprávět podle otázky.",
  });
}

function assetArticle(ctx: UiRenderCtx, asset: any) {
  const related = ctx.getRelatedFindingsForNode(asset.asset_id);
  const title = asset.name ?? asset.asset_id;
  const relatedTitles = related.map((item: any) => ctx.displayFindingTitle(item));
  return readerArticle(ctx, {
    eyebrow: ctx.assetTypeLabel(asset.asset_type),
    title,
    lead: `${title} je zařízení nebo prvek, který program našel v síťových datech. Tady je přeložené, co o něm víme a proč se na něj dívat.`,
    tone: related[0] ? ctx.severity(related[0].severity) : ctx.severity(asset.confidence),
    facts: [
      ["IP adresa", asset.ip ?? "neuvedeno"],
      ["Zdroj", asset.source ?? "inventář"],
      ["Typ", ctx.assetTypeLabel(asset.asset_type)],
      ["Jistota", String(asset.confidence ?? "neuvedeno")],
    ],
    sections: [
      {
        title: "Co je to za prvek",
        body: ctx.compact([asset.ip, asset.vendor, asset.model, asset.location, asset.status ? `stav ${asset.status}` : ""]).join(" · ") || "Program zatím nemá víc popisných údajů, takže je potřeba ověřit vlastníka a účel zařízení.",
      },
      {
        title: "Proč mě zajímá",
        body: related.length
          ? `Na zařízení jsou navázaná rizika: ${relatedTitles.join(" · ")}. To neznamená automaticky incident, ale říká to, že se tenhle prvek má řešit před běžnou inventurou.`
          : "Na zařízení není přímo navázaný konkrétní nález. I tak je důležité vědět, komu patří a jestli jeho viditelné služby odpovídají očekávání.",
      },
      {
        title: "Co udělat teď",
        steps: [
          "Ověř vlastníka zařízení a jeho roli v síti.",
          related[0] ? `Začni navázaným rizikem: ${ctx.displayFindingTitle(related[0])}.` : "Zkontroluj, zda otevřené služby odpovídají roli zařízení.",
          "Když jde o správu, server nebo síťový prvek, omez přístup jen z nutných segmentů.",
        ],
      },
    ],
    evidence: ctx.compact([asset.source, asset.mac, asset.linked_host_key, ...(asset.observations ?? [])]),
  });
}

function laneArticle(ctx: UiRenderCtx, lane: any) {
  return readerArticle(ctx, {
    eyebrow: ctx.localizeUiText(lane.lane_type ?? "sběr"),
    title: ctx.localizeUiText(lane.title ?? "Sběrač"),
    lead: "Tahle část říká, odkud program bere data a jestli jsou použitelná pro rozhodnutí.",
    tone: ctx.severity(lane.status === "ok" ? "low" : lane.status),
    facts: [
      ["Zdroj", lane.source ?? "neuvedeno"],
      ["Stav", lane.status ?? "neuvedeno"],
      ["Režim", lane.mode ?? "neuvedeno"],
    ],
    sections: [
      {
        title: "Co zdroj dodal",
        body: ctx.compact([ctx.localizeUiText(lane.summary ?? ""), lane.source ? `zdroj ${lane.source}` : "", lane.status ? `stav ${lane.status}` : ""]).join(" · ") || "Sběrný modul nemá doplňující komentář.",
      },
      {
        title: "Co udělat teď",
        steps: [
          ctx.localizeUiText(lane.recommendation ?? "Ověř navázání vstupního zdroje, dostupnost dat a konzistenci časového okna."),
          "Když zdroj chybí nebo je částečný, neber výsledek jako kompletní obraz sítě.",
        ],
      },
    ],
    evidence: ctx.compact([lane.source, lane.status, lane.mode, ...(lane.details ?? lane.observations ?? [])]),
  });
}

function actionArticle(ctx: UiRenderCtx, action: any) {
  return readerArticle(ctx, {
    eyebrow: "další krok",
    title: ctx.localizeUiText(action.title ?? "Doporučený krok"),
    lead: "Tohle je navržený praktický krok. Je psaný jako úkol, ne jako technický detail.",
    tone: ctx.severity(action.priority),
    facts: [
      ["Priorita", severityLabel(ctx, action.priority)],
      ["Služba", action.target_service_key ?? "neuvedeno"],
      ["Zařízení", action.target_asset_id ?? "neuvedeno"],
      ["Nástroje", (action.recommended_tools ?? []).join(", ") || "neuvedeno"],
    ],
    sections: [
      { title: "Proč ten krok dává smysl", body: ctx.localizeUiText(action.rationale ?? "Krok nemá doplňující zdůvodnění.") },
      {
        title: "Co udělat teď",
        steps: ctx.compact([
          ctx.localizeUiText(action.next_step ?? ""),
          ...(action.recommended_tools ?? []).map((tool: string) => `Použij nebo ověř nástroj: ${tool}.`),
          "Po změně spusť nový běh a porovnej, jestli nález zmizel nebo se změnila priorita.",
        ]),
      },
    ],
    evidence: ctx.compact([action.priority, action.target_service_key, action.target_asset_id, ...(action.evidence ?? [])]),
  });
}

function genericArticle(ctx: UiRenderCtx, eyebrow: string, title: string, summary: string, recommendation: string, evidence: string[], tone = "severity-neutral") {
  return readerArticle(ctx, {
    eyebrow,
    title,
    lead: summary || "Program našel položku, kterou je potřeba zařadit do kontextu běhu.",
    tone,
    sections: [
      summary ? { title: "Co se změnilo", body: summary } : null,
      recommendation ? { title: "Co udělat teď", body: recommendation } : null,
    ].filter(Boolean),
    evidence,
  });
}

function readerArticle(ctx: UiRenderCtx, input: { eyebrow: string; title: string; lead: string; tone?: string; facts?: string[][]; sections?: any[]; evidence?: string[]; footnote?: string; }) {
  const facts = input.facts ?? [];
  const sections = input.sections ?? [];
  const evidence = input.evidence ?? [];
  return `
    <section class="reader-card ${input.tone ?? "severity-neutral"}">
      <div class="reader-article-head">
        <span>${ctx.escapeHtml(input.eyebrow)}</span>
        <i data-lucide="scan-line" class="h-5 w-5"></i>
      </div>
      <div class="reader-hero">
        <h2>${ctx.escapeHtml(input.title)}</h2>
        <p>${ctx.escapeHtml(input.lead)}</p>
      </div>
      <div class="reader-content-grid">
        <div class="reader-main-copy">
          ${sections.map((section) => readerSection(ctx, section)).join("")}
          ${evidence.length ? `<section class="reader-section reader-evidence"><strong>Důkazy a kontext</strong><p>Tohle jsou technické stopy, ze kterých program vychází. Nejsou nutné k pochopení problému, ale pomáhají dohledat přesné místo.</p><div class="reader-evidence-grid">${evidence.map((item) => `<code>${ctx.escapeHtml(String(item))}</code>`).join("")}</div></section>` : ""}
          ${input.footnote ? `<p class="reader-footnote">${ctx.escapeHtml(input.footnote)}</p>` : ""}
        </div>
        ${facts.length ? `<aside class="reader-fact-panel"><strong>Rychlá orientace</strong>${facts.map(([label, value]) => `<div><span>${ctx.escapeHtml(label)}</span><b>${ctx.escapeHtml(String(value || "neuvedeno"))}</b></div>`).join("")}</aside>` : ""}
      </div>
    </section>
  `;
}

function readerSection(ctx: UiRenderCtx, section: any) {
  if (!section) return "";
  if (section.steps?.length) {
    return `<section class="reader-section reader-steps"><strong>${ctx.escapeHtml(section.title)}</strong><ol>${section.steps.map((step: string) => `<li>${ctx.escapeHtml(step)}</li>`).join("")}</ol></section>`;
  }
  return `<section class="reader-section"><strong>${ctx.escapeHtml(section.title)}</strong><p class="reader-summary">${ctx.escapeHtml(section.body ?? "")}</p></section>`;
}

function findingTarget(ctx: UiRenderCtx, finding: any) {
  return ctx.compact([finding.service_key, finding.host_key]).join(" · ") || "neuvedeno";
}

function severityLabel(ctx: UiRenderCtx, value: any) {
  const level = ctx.levelOf(value);
  if (level === "high") return "vysoká";
  if (level === "medium") return "střední";
  if (level === "low") return "nízká";
  return "neurčená";
}

function plainFindingLead(ctx: UiRenderCtx, finding: any, summary: string) {
  const target = findingTarget(ctx, finding);
  const severity = severityLabel(ctx, finding.severity);
  return `Program našel problém na ${target}. Priorita je ${severity}. V praxi to znamená: ${ctx.localizeUiText(summary)}`;
}

function findingImpact(ctx: UiRenderCtx, finding: any) {
  const text = `${finding.finding_type ?? ""} ${finding.title ?? ""} ${finding.rationale ?? ""}`.toLowerCase();
  if (text.includes("plaintext") || text.includes("telnet") || text.includes("ftp")) {
    return "Přihlášení nebo řídicí komunikace může jít po síti čitelně. Kdo má možnost provoz odposlechnout, může získat údaje nebo pochopit, jak se služba ovládá.";
  }
  if (text.includes("cve") || text.includes("vulnerab") || text.includes("kev") || text.includes("epss")) {
    return "Služba vypadá jako verze, pro kterou existují známé bezpečnostní slabiny. Neznamená to automaticky prolomení, ale je potřeba ověřit verzi, dostupnost záplaty a viditelnost služby.";
  }
  if (text.includes("swagger") || text.includes("metrics") || text.includes("directory") || text.includes("management") || text.includes("admin")) {
    return "Služba zbytečně ukazuje rozhraní nebo informace, které mají být spíš interní. Útočníkovi to může pomoct najít další cestu nebo lépe pochopit systém.";
  }
  if (text.includes("traffic") || text.includes("packet") || text.includes("timeout") || text.includes("flow")) {
    return "Síťový provoz se chová jinak, než je pro daný cíl očekávané. Může jít o chybu konfigurace, přetížení, skenování nebo běžný provoz, který je potřeba vysvětlit.";
  }
  if (text.includes("identification") || text.includes("gap") || text.includes("uncertainty")) {
    return "Program nemá dost přesnou identitu služby nebo zařízení. Bez toho se hůř rozhoduje, jestli je nález skutečně rizikový a kdo ho má řešit.";
  }
  return "Nález je signál ke kontrole. Sám o sobě nemusí znamenat incident, ale ukazuje místo, kde je dobré ověřit nastavení, vlastníka a reálný dopad.";
}

function findingSteps(ctx: UiRenderCtx, finding: any, recommendation: string) {
  const text = `${finding.finding_type ?? ""} ${finding.title ?? ""} ${finding.rationale ?? ""}`.toLowerCase();
  const target = findingTarget(ctx, finding);
  const steps = [
    `Najdi vlastníka nebo správce cíle ${target}.`,
    recommendation,
  ];
  if (text.includes("telnet")) {
    steps.push("Vypni Telnet, pokud není nezbytný, a nahraď ho SSH.");
    steps.push("Povol port 23 jen z nutného správcovského segmentu, ideálně vůbec.");
  } else if (text.includes("ftp")) {
    steps.push("Ověř, jestli se přes FTP posílají přihlašovací údaje nebo citlivé soubory.");
    steps.push("Nahraď FTP za SFTP nebo FTPS a omez port 21 jen na nutné zdroje.");
  } else if (text.includes("cve") || text.includes("vulnerab") || text.includes("kev") || text.includes("epss")) {
    steps.push("Ověř skutečnou verzi služby na serveru, ne jen banner z Nmapu.");
    steps.push("Najdi vendor advisory nebo balíčkovou aktualizaci a naplánuj patch.");
    steps.push("Do opravy omez přístup ke službě firewallem nebo segmentací.");
  } else if (text.includes("swagger") || text.includes("metrics") || text.includes("directory") || text.includes("management") || text.includes("admin")) {
    steps.push("Zkontroluj, jestli rozhraní musí být dostupné z této sítě.");
    steps.push("Přidej autentizaci, reverzní proxy nebo omezení jen na interní správce.");
  } else if (text.includes("traffic") || text.includes("packet") || text.includes("timeout") || text.includes("flow")) {
    steps.push("Porovnej čas a cíl s legitimní aktivitou v síti.");
    steps.push("Když provoz nemá vysvětlení, ověř zdrojový host a logy služby.");
  }
  return uniqueText(steps.filter(Boolean)).slice(0, 6);
}

function findingVerification(ctx: UiRenderCtx, finding: any) {
  const text = `${finding.finding_type ?? ""} ${finding.title ?? ""} ${finding.rationale ?? ""}`.toLowerCase();
  const steps = ["Spusť nový běh a ověř, že se nález už neobjeví nebo klesne jeho priorita."];
  if (finding.service_key) steps.push(`Ověř službu ${finding.service_key} znovu aktivním skenem.`);
  if (text.includes("plaintext") || text.includes("telnet") || text.includes("ftp")) steps.push("V pasivní části zkontroluj, že už nejsou vidět nešifrované přihlašovací nebo řídicí relace.");
  if (text.includes("cve") || text.includes("vulnerab")) steps.push("Zkontroluj, že banner/verze a CVE vazba po opravě odpovídají nové verzi.");
  return uniqueText(steps).slice(0, 4);
}

function uniqueText(items: string[]) {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = item.trim().toLowerCase();
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function renderMobileControls(ctx: UiRenderCtx) {
  const summary = ctx.state.report?.summary ?? {};
  return `
    <div class="mobile-control-strip" aria-label="Mobilní ovládání">
      <div class="mobile-stat-row">
        <span class="tiny-chip"><i data-lucide="network" class="h-3.5 w-3.5"></i>${summary.hosts_total ?? 0}</span>
        <span class="tiny-chip"><i data-lucide="shield-alert" class="h-3.5 w-3.5"></i>${summary.findings_total ?? 0}</span>
        <span class="tiny-chip"><i data-lucide="activity" class="h-3.5 w-3.5"></i>${summary.events_total ?? 0}</span>
      </div>
      <div class="mobile-action-row">
        <button type="button" class="icon-button ${ctx.state.liveMode ? "is-live" : ""}" data-live-toggle title="Realtime"><i data-lucide="activity" class="h-4 w-4"></i></button>
        <button type="button" class="icon-button" data-refresh title="Načíst znovu"><i data-lucide="refresh-cw" class="h-4 w-4"></i></button>
        <button type="button" class="icon-button" data-automation-start title="Spustit autopilot"><i data-lucide="play" class="h-4 w-4"></i></button>
        <button type="button" class="icon-button" data-focus="audit" title="Audit a AI"><i data-lucide="bot" class="h-4 w-4"></i></button>
        <button type="button" class="icon-button" data-export="json" title="Export JSON"><i data-lucide="download" class="h-4 w-4"></i></button>
      </div>
    </div>
  `;
}
