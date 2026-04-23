// node_modules/lucide/dist/esm/defaultAttributes.js
var defaultAttributes = {
  xmlns: "http://www.w3.org/2000/svg",
  width: 24,
  height: 24,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  "stroke-width": 2,
  "stroke-linecap": "round",
  "stroke-linejoin": "round"
};

// node_modules/lucide/dist/esm/createElement.js
var createSVGElement = ([tag, attrs, children]) => {
  const element = document.createElementNS("http://www.w3.org/2000/svg", tag);
  Object.keys(attrs).forEach((name) => {
    element.setAttribute(name, String(attrs[name]));
  });
  if (children?.length) {
    children.forEach((child) => {
      const childElement = createSVGElement(child);
      element.appendChild(childElement);
    });
  }
  return element;
};
var createElement = (iconNode, customAttrs = {}) => {
  const tag = "svg";
  const attrs = {
    ...defaultAttributes,
    ...customAttrs
  };
  return createSVGElement([tag, attrs, iconNode]);
};

// node_modules/lucide/dist/esm/replaceElement.js
var getAttrs = (element) => Array.from(element.attributes).reduce((attrs, attr) => {
  attrs[attr.name] = attr.value;
  return attrs;
}, {});
var getClassNames = (attrs) => {
  if (typeof attrs === "string") return attrs;
  if (!attrs || !attrs.class) return "";
  if (attrs.class && typeof attrs.class === "string") {
    return attrs.class.split(" ");
  }
  if (attrs.class && Array.isArray(attrs.class)) {
    return attrs.class;
  }
  return "";
};
var combineClassNames = (arrayOfClassnames) => {
  const classNameArray = arrayOfClassnames.flatMap(getClassNames);
  return classNameArray.map((classItem) => classItem.trim()).filter(Boolean).filter((value, index, self) => self.indexOf(value) === index).join(" ");
};
var toPascalCase = (string) => string.replace(/(\w)(\w*)(_|-|\s*)/g, (g0, g1, g2) => g1.toUpperCase() + g2.toLowerCase());
var replaceElement = (element, { nameAttr, icons, attrs }) => {
  const iconName = element.getAttribute(nameAttr);
  if (iconName == null) return;
  const ComponentName = toPascalCase(iconName);
  const iconNode = icons[ComponentName];
  if (!iconNode) {
    return console.warn(
      `${element.outerHTML} icon name was not found in the provided icons object.`
    );
  }
  const elementAttrs = getAttrs(element);
  const iconAttrs = {
    ...defaultAttributes,
    "data-lucide": iconName,
    ...attrs,
    ...elementAttrs
  };
  const classNames = combineClassNames(["lucide", `lucide-${iconName}`, elementAttrs, attrs]);
  if (classNames) {
    Object.assign(iconAttrs, {
      class: classNames
    });
  }
  const svgElement = createElement(iconNode, iconAttrs);
  return element.parentNode?.replaceChild(svgElement, element);
};

// node_modules/lucide/dist/esm/icons/activity.js
var Activity = [
  [
    "path",
    {
      d: "M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"
    }
  ]
];

// node_modules/lucide/dist/esm/icons/bot.js
var Bot = [
  ["path", { d: "M12 8V4H8" }],
  ["rect", { width: "16", height: "12", x: "4", y: "8", rx: "2" }],
  ["path", { d: "M2 14h2" }],
  ["path", { d: "M20 14h2" }],
  ["path", { d: "M15 13v2" }],
  ["path", { d: "M9 13v2" }]
];

// node_modules/lucide/dist/esm/icons/chevron-right.js
var ChevronRight = [["path", { d: "m9 18 6-6-6-6" }]];

// node_modules/lucide/dist/esm/icons/circle-dashed.js
var CircleDashed = [
  ["path", { d: "M10.1 2.182a10 10 0 0 1 3.8 0" }],
  ["path", { d: "M13.9 21.818a10 10 0 0 1-3.8 0" }],
  ["path", { d: "M17.609 3.721a10 10 0 0 1 2.69 2.7" }],
  ["path", { d: "M2.182 13.9a10 10 0 0 1 0-3.8" }],
  ["path", { d: "M20.279 17.609a10 10 0 0 1-2.7 2.69" }],
  ["path", { d: "M21.818 10.1a10 10 0 0 1 0 3.8" }],
  ["path", { d: "M3.721 6.391a10 10 0 0 1 2.7-2.69" }],
  ["path", { d: "M6.391 20.279a10 10 0 0 1-2.69-2.7" }]
];

// node_modules/lucide/dist/esm/icons/download.js
var Download = [
  ["path", { d: "M12 15V3" }],
  ["path", { d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" }],
  ["path", { d: "m7 10 5 5 5-5" }]
];

// node_modules/lucide/dist/esm/icons/gauge.js
var Gauge = [
  ["path", { d: "m12 14 4-4" }],
  ["path", { d: "M3.34 19a10 10 0 1 1 17.32 0" }]
];

// node_modules/lucide/dist/esm/icons/git-compare.js
var GitCompare = [
  ["circle", { cx: "18", cy: "18", r: "3" }],
  ["circle", { cx: "6", cy: "6", r: "3" }],
  ["path", { d: "M13 6h3a2 2 0 0 1 2 2v7" }],
  ["path", { d: "M11 18H8a2 2 0 0 1-2-2V9" }]
];

// node_modules/lucide/dist/esm/icons/layers.js
var Layers = [
  [
    "path",
    {
      d: "M12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83z"
    }
  ],
  ["path", { d: "M2 12a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 12" }],
  ["path", { d: "M2 17a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 17" }]
];

// node_modules/lucide/dist/esm/icons/maximize-2.js
var Maximize2 = [
  ["path", { d: "M15 3h6v6" }],
  ["path", { d: "m21 3-7 7" }],
  ["path", { d: "m3 21 7-7" }],
  ["path", { d: "M9 21H3v-6" }]
];

// node_modules/lucide/dist/esm/icons/minimize-2.js
var Minimize2 = [
  ["path", { d: "m14 10 7-7" }],
  ["path", { d: "M20 10h-6V4" }],
  ["path", { d: "m3 21 7-7" }],
  ["path", { d: "M4 14h6v6" }]
];

// node_modules/lucide/dist/esm/icons/network.js
var Network = [
  ["rect", { x: "16", y: "16", width: "6", height: "6", rx: "1" }],
  ["rect", { x: "2", y: "16", width: "6", height: "6", rx: "1" }],
  ["rect", { x: "9", y: "2", width: "6", height: "6", rx: "1" }],
  ["path", { d: "M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3" }],
  ["path", { d: "M12 12V8" }]
];

// node_modules/lucide/dist/esm/icons/play.js
var Play = [
  [
    "path",
    { d: "M5 5a2 2 0 0 1 3.008-1.728l11.997 6.998a2 2 0 0 1 .003 3.458l-12 7A2 2 0 0 1 5 19z" }
  ]
];

// node_modules/lucide/dist/esm/icons/radar.js
var Radar = [
  ["path", { d: "M19.07 4.93A10 10 0 0 0 6.99 3.34" }],
  ["path", { d: "M4 6h.01" }],
  ["path", { d: "M2.29 9.62A10 10 0 1 0 21.31 8.35" }],
  ["path", { d: "M16.24 7.76A6 6 0 1 0 8.23 16.67" }],
  ["path", { d: "M12 18h.01" }],
  ["path", { d: "M17.99 11.66A6 6 0 0 1 15.77 16.67" }],
  ["circle", { cx: "12", cy: "12", r: "2" }],
  ["path", { d: "m13.41 10.59 5.66-5.66" }]
];

// node_modules/lucide/dist/esm/icons/refresh-cw.js
var RefreshCw = [
  ["path", { d: "M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" }],
  ["path", { d: "M21 3v5h-5" }],
  ["path", { d: "M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" }],
  ["path", { d: "M8 16H3v5" }]
];

// node_modules/lucide/dist/esm/icons/rotate-ccw.js
var RotateCcw = [
  ["path", { d: "M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" }],
  ["path", { d: "M3 3v5h5" }]
];

// node_modules/lucide/dist/esm/icons/scan-line.js
var ScanLine = [
  ["path", { d: "M3 7V5a2 2 0 0 1 2-2h2" }],
  ["path", { d: "M17 3h2a2 2 0 0 1 2 2v2" }],
  ["path", { d: "M21 17v2a2 2 0 0 1-2 2h-2" }],
  ["path", { d: "M7 21H5a2 2 0 0 1-2-2v-2" }],
  ["path", { d: "M7 12h10" }]
];

// node_modules/lucide/dist/esm/icons/shield-alert.js
var ShieldAlert = [
  [
    "path",
    {
      d: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"
    }
  ],
  ["path", { d: "M12 8v4" }],
  ["path", { d: "M12 16h.01" }]
];

// node_modules/lucide/dist/esm/icons/shield.js
var Shield = [
  [
    "path",
    {
      d: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"
    }
  ]
];

// node_modules/lucide/dist/esm/icons/sparkles.js
var Sparkles = [
  [
    "path",
    {
      d: "M11.017 2.814a1 1 0 0 1 1.966 0l1.051 5.558a2 2 0 0 0 1.594 1.594l5.558 1.051a1 1 0 0 1 0 1.966l-5.558 1.051a2 2 0 0 0-1.594 1.594l-1.051 5.558a1 1 0 0 1-1.966 0l-1.051-5.558a2 2 0 0 0-1.594-1.594l-5.558-1.051a1 1 0 0 1 0-1.966l5.558-1.051a2 2 0 0 0 1.594-1.594z"
    }
  ],
  ["path", { d: "M20 2v4" }],
  ["path", { d: "M22 4h-4" }],
  ["circle", { cx: "4", cy: "20", r: "2" }]
];

// node_modules/lucide/dist/esm/icons/triangle-alert.js
var TriangleAlert = [
  ["path", { d: "m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3" }],
  ["path", { d: "M12 9v4" }],
  ["path", { d: "M12 17h.01" }]
];

// node_modules/lucide/dist/esm/icons/waves.js
var Waves = [
  [
    "path",
    { d: "M2 6c.6.5 1.2 1 2.5 1C7 7 7 5 9.5 5c2.6 0 2.4 2 5 2 2.5 0 2.5-2 5-2 1.3 0 1.9.5 2.5 1" }
  ],
  [
    "path",
    {
      d: "M2 12c.6.5 1.2 1 2.5 1 2.5 0 2.5-2 5-2 2.6 0 2.4 2 5 2 2.5 0 2.5-2 5-2 1.3 0 1.9.5 2.5 1"
    }
  ],
  [
    "path",
    {
      d: "M2 18c.6.5 1.2 1 2.5 1 2.5 0 2.5-2 5-2 2.6 0 2.4 2 5 2 2.5 0 2.5-2 5-2 1.3 0 1.9.5 2.5 1"
    }
  ]
];

// node_modules/lucide/dist/esm/icons/wifi.js
var Wifi = [
  ["path", { d: "M12 20h.01" }],
  ["path", { d: "M2 8.82a15 15 0 0 1 20 0" }],
  ["path", { d: "M5 12.859a10 10 0 0 1 14 0" }],
  ["path", { d: "M8.5 16.429a5 5 0 0 1 7 0" }]
];

// node_modules/lucide/dist/esm/icons/zoom-in.js
var ZoomIn = [
  ["circle", { cx: "11", cy: "11", r: "8" }],
  ["line", { x1: "21", x2: "16.65", y1: "21", y2: "16.65" }],
  ["line", { x1: "11", x2: "11", y1: "8", y2: "14" }],
  ["line", { x1: "8", x2: "14", y1: "11", y2: "11" }]
];

// node_modules/lucide/dist/esm/icons/zoom-out.js
var ZoomOut = [
  ["circle", { cx: "11", cy: "11", r: "8" }],
  ["line", { x1: "21", x2: "16.65", y1: "21", y2: "16.65" }],
  ["line", { x1: "8", x2: "14", y1: "11", y2: "11" }]
];

// node_modules/lucide/dist/esm/lucide.js
var createIcons = ({ icons = {}, nameAttr = "data-lucide", attrs = {} } = {}) => {
  if (!Object.values(icons).length) {
    throw new Error(
      "Please provide an icons object.\nIf you want to use all the icons you can import it like:\n `import { createIcons, icons } from 'lucide';\nlucide.createIcons({icons});`"
    );
  }
  if (typeof document === "undefined") {
    throw new Error("`createIcons()` only works in a browser environment.");
  }
  const elementsToReplace = document.querySelectorAll(`[${nameAttr}]`);
  Array.from(elementsToReplace).forEach(
    (element) => replaceElement(element, { nameAttr, icons, attrs })
  );
  if (nameAttr === "data-lucide") {
    const deprecatedElements = document.querySelectorAll("[icon-name]");
    if (deprecatedElements.length > 0) {
      console.warn(
        "[Lucide] Some icons were found with the now deprecated icon-name attribute. These will still be replaced for backwards compatibility, but will no longer be supported in v1.0 and you should switch to data-lucide"
      );
      Array.from(deprecatedElements).forEach(
        (element) => replaceElement(element, { nameAttr: "icon-name", icons, attrs })
      );
    }
  }
};

// ui-src/responsive.ts
var clamp = (value, min, max) => Math.max(min, Math.min(max, value));
var rem = (value) => `${(value / 16).toFixed(4).replace(/\.?0+$/, "")}rem`;
function applyResponsiveLayoutVars(target, width, height) {
  const aspect = width / Math.max(height, 1);
  const compact2 = width < 980;
  const baseScale = Math.min(width / 1600, height / 1e3);
  const aspectBias = aspect > 2.1 ? 0.96 : aspect > 1.85 ? 0.99 : aspect < 1.45 ? 0.93 : 1;
  const scale = clamp(baseScale * aspectBias, compact2 ? 0.84 : 0.82, compact2 ? 1.04 : 1.14);
  const textScale = clamp(baseScale * (compact2 ? 0.88 : 0.96), compact2 ? 0.68 : 0.74, compact2 ? 0.98 : 1.05);
  const shellPad = Math.round(clamp(height * 0.012, 10, 18) * scale);
  const layoutGap = Math.round(clamp(width * 8e-3, 8, 16) * scale);
  const panelPad = Math.round(clamp(height * 0.014, 12, 18) * scale);
  let leftCol = compact2 ? 0 : Math.round(clamp(width * 0.12, 168, 198) * scale);
  let rightCol = compact2 ? 0 : Math.round(clamp(width * 0.22, 280, 360) * scale);
  const outerShell = shellPad * 2;
  const gutter = layoutGap * 2;
  const minimumCenter = compact2 ? 360 : Math.round(680 * scale);
  let centerCol = width - outerShell - gutter - leftCol - rightCol;
  if (!compact2 && centerCol < minimumCenter) {
    const deficit = minimumCenter - centerCol;
    rightCol = Math.max(Math.round(260 * scale), rightCol - deficit);
    centerCol = width - outerShell - gutter - leftCol - rightCol;
  }
  const graphWidth = Math.round(clamp(compact2 ? width : centerCol, compact2 ? 360 : 720, compact2 ? 760 : 1800));
  const graphHeight = Math.round(clamp(compact2 ? height : height - outerShell, compact2 ? 620 : 640, compact2 ? 1180 : 1240));
  const heroHeight = Math.round(clamp(height * 0.067, 56, 78));
  const tabHeight = Math.round(clamp(height * 0.038, 32, 42));
  const detailFocusMax = Math.round(clamp(height * 0.28, 158, 290));
  target.style.setProperty("--ui-scale", scale.toFixed(4));
  target.style.setProperty("--ui-text-scale", textScale.toFixed(4));
  target.style.setProperty("--font-xs", rem(11.2 * textScale));
  target.style.setProperty("--font-sm", rem(12.9 * textScale));
  target.style.setProperty("--font-md", rem(14.6 * textScale));
  target.style.setProperty("--font-lg", rem(17.4 * textScale));
  target.style.setProperty("--font-xl", rem(20.5 * textScale));
  target.style.setProperty("--shell-pad", rem(shellPad));
  target.style.setProperty("--layout-gap", rem(layoutGap));
  target.style.setProperty("--left-col", rem(leftCol));
  target.style.setProperty("--right-col", rem(rightCol));
  target.style.setProperty("--panel-pad", rem(panelPad));
  target.style.setProperty("--hero-h", rem(heroHeight));
  target.style.setProperty("--tab-h", rem(tabHeight));
  target.style.setProperty("--graph-h", rem(graphHeight));
  target.style.setProperty("--detail-focus-max", rem(detailFocusMax));
  target.style.setProperty("--ui-aspect", aspect.toFixed(4));
  target.style.setProperty("--ui-width", rem(width));
  target.style.setProperty("--ui-height", rem(height));
  return {
    width,
    height,
    aspect,
    scale,
    textScale,
    shellPad,
    layoutGap,
    leftCol,
    rightCol,
    panelPad,
    heroHeight,
    tabHeight,
    graphWidth,
    graphHeight,
    detailFocusMax,
    compact: compact2
  };
}
function computeGraphSceneSize(metrics, expanded) {
  if (metrics.compact) {
    return {
      width: clamp(Math.round(metrics.graphWidth), 360, 760),
      height: clamp(Math.round(metrics.graphHeight), 620, 1180)
    };
  }
  const width = expanded ? clamp(Math.round(metrics.graphWidth * 1.04), 760, 1900) : clamp(Math.round(metrics.graphWidth), 720, 1800);
  const height = expanded ? clamp(Math.round(metrics.graphHeight * 1.03), 680, 1280) : clamp(Math.round(metrics.graphHeight), 640, 1240);
  return { width, height };
}
function computeGraphOrbitMetrics(width, height) {
  const minSide = Math.min(width, height);
  const padding = clamp(minSide * 0.07, minSide < 620 ? 24 : 58, 122);
  const availableRadius = Math.max(
    120,
    Math.min(width / 2 - padding, height / 2 - padding)
  );
  return {
    padding,
    availableRadius,
    ringRadii: [
      availableRadius * 0.34,
      availableRadius * 0.6,
      availableRadius * 0.81,
      availableRadius * 0.96
    ]
  };
}

// ui-src/render/left-rail.ts
function renderLeftRail(ctx) {
  return `
    ${renderStatusPanel(ctx)}
    ${renderControlPanel(ctx)}
    ${renderDataPanel(ctx)}
    ${renderDiagnosticsPanel(ctx)}
    ${renderExportPanel(ctx)}
    ${renderRunsPanel(ctx)}
  `;
}
function renderStatusPanel(ctx) {
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
        <span title="Realtime">${live ? "Live" : "Ru\u010Dn\u011B"}</span>
        <span title="Autopilot">${running ? "B\u011Bh" : "Klid"}</span>
      </div>
    </section>
  `;
}
function renderControlPanel(ctx) {
  const status = ctx.state.automationStatus;
  const running = Boolean(status?.process_running);
  const pentestLabel = ctx.state.pentestMode === "aggressive" ? "Hard" : ctx.state.pentestMode === "smart" ? "Smart" : "Vyp.";
  const pentestTitle = ctx.state.pentestMode === "aggressive" ? "Agresivn\u011Bj\u0161\xED autorizovan\xFD pentest [P]" : ctx.state.pentestMode === "smart" ? "Intern\xED smart pentest [P]" : "Pentest vypnut\xFD [P]";
  const tokenControl = ctx.state.authRequired ? ctx.state.apiTokenPresent ? actionButton(ctx, "shield", "API", "Token je ulo\u017Een\xFD. Kliknut\xEDm ho vypne\u0161 pro UI.", "data-token-clear", false, true) : actionButton(ctx, "shield", "Bez API", "Token je voliteln\xFD. Kliknut\xEDm ho m\u016F\u017Ee\u0161 doplnit pro chr\xE1n\u011Bn\xE9 akce.", "data-token-set", false, false) : "";
  return `
    <section class="rail-card rail-control-card control-panel">
      <div class="rail-section-head"><span>Ovl\xE1d\xE1n\xED</span><span>kbd</span></div>
      <div class="rail-action-grid">
        ${actionButton(ctx, "play", "Start", "Spustit autopilot", "data-automation-start", running)}
        ${actionButton(ctx, "rotate-ccw", "Reset", "Reset autopilota", "data-automation-reset", false)}
        ${actionButton(ctx, "refresh-cw", "Obnovit", "Na\u010D\xEDst znovu [R]", "data-refresh", false)}
        ${actionButton(ctx, "activity", ctx.state.liveMode ? "Live" : "Ru\u010Dn\u011B", "P\u0159epnout realtime [L]", "data-live-toggle", false, ctx.state.liveMode)}
        ${actionButton(ctx, "shield-alert", pentestLabel, pentestTitle, "data-pentest-toggle", false, ctx.state.pentestMode !== "off")}
        ${tokenControl}
      </div>
    </section>
  `;
}
function actionButton(ctx, icon, label, title, attr, disabled, active = false) {
  return `<button type="button" class="rail-action ${active ? "is-active" : ""}" ${attr} title="${ctx.escapeAttr(title)}" ${disabled ? "disabled" : ""}><i data-lucide="${icon}" class="h-3.5 w-3.5"></i><span>${ctx.escapeHtml(label)}</span></button>`;
}
function renderDataPanel(ctx) {
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
function statButton(ctx, icon, label, value, panel) {
  return `
    <button type="button" class="rail-stat" data-detail-panel="${ctx.escapeAttr(panel)}" data-detail-scope="all" data-detail-view="list" data-center-mode="reader" title="${ctx.escapeAttr(`${label}: ${value}`)}">
      <i data-lucide="${icon}" class="h-3.5 w-3.5"></i>
      <strong>${value}</strong>
      <span>${ctx.escapeHtml(label)}</span>
    </button>
  `;
}
function renderDiagnosticsPanel(ctx) {
  const status = ctx.state.automationStatus;
  const latest = ctx.state.automationLatest;
  const summary = ctx.state.report?.summary ?? {};
  const progress = clamp2(status?.progress_pct ?? Math.round((latest?.summary.tooling_coverage_ratio ?? 0) * 100), 0, 100);
  const consensus = clamp2(Math.round(Number(summary.mas_consensus_score ?? latest?.summary.mas_consensus_score ?? 0) * 100), 0, 100);
  const parallelism = clamp2(Math.round(Number(summary.mas_parallelism_ratio ?? latest?.summary.mas_parallelism_ratio ?? 0) * 100), 0, 100);
  const queue = Math.max(0, Math.round(Number(summary.mas_queue_wait_ms_avg ?? latest?.summary.mas_queue_wait_ms_avg ?? 0)));
  const readiness = ctx.state.readiness;
  const readinessPct = clamp2(Math.round(Number(readiness?.score ?? 0) * 100), 0, 100);
  const readinessGrade = readiness?.grade ?? "-";
  const blockers = readiness?.blockers?.length ?? 0;
  const aiReady = ctx.state.aiStatus?.status === "ready";
  return `
    <section class="rail-card rail-diag-card">
      <div class="rail-section-head"><span>Diagnostika</span><span>${ctx.escapeHtml(readinessGrade)}</span></div>
      ${diagLine("Pr\u016Fb\u011Bh", progress)}
      ${diagLine("Prod", readinessPct)}
      <div class="rail-mini-grid">
        <span title="Konsenzus">C ${consensus}%</span>
        <span title="Paralelismus">P ${parallelism}%</span>
        <span title="Fronta">Q ${queue}</span>
        <span title="${ctx.escapeAttr(readiness?.next_steps?.[0] ?? "Production readiness")}">B ${blockers}</span>
        <span title="Lok\xE1ln\xED AI">${aiReady ? "AI ok" : "AI lim"}</span>
      </div>
    </section>
  `;
}
function diagLine(label, value) {
  return `<div class="rail-diag-line"><span>${label}</span><div class="progress-line"><span style="width:${value}%"></span></div></div>`;
}
function renderExportPanel(ctx) {
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
function exportButton(ctx, format, label) {
  return `<button type="button" class="rail-action" data-export="${format}" ${ctx.state.report ? "" : "disabled"} title="${ctx.escapeAttr(`Export ${label}`)}"><i data-lucide="download" class="h-3.5 w-3.5"></i><span>${label}</span></button>`;
}
function renderRunsPanel(ctx) {
  const runs = ctx.state.runs.slice(0, 4);
  if (!runs.length) return "";
  return `
    <section class="rail-card rail-runs-card">
      <div class="rail-section-head"><span>B\u011Bhy</span><span>${ctx.state.runs.length}</span></div>
      <div class="rail-run-list">
        ${runs.map((run, index) => `<button type="button" class="rail-run-row ${run.run_id === ctx.state.activeRunId ? "is-active" : ""}" data-run-id="${ctx.escapeAttr(run.run_id)}" title="${ctx.escapeAttr(ctx.displayRunName(run.nazev))}"><span>${index + 1}</span><strong>${ctx.escapeHtml(ctx.trim(ctx.displayRunName(run.nazev), 18))}</strong></button>`).join("")}
      </div>
    </section>
  `;
}
var clamp2 = (value, min, max) => Math.max(min, Math.min(max, value));

// ui-src/render/graph.ts
function renderGraphSvg(ctx, nodes, edges, width, height, selectedNodeId, selectedEdgeId) {
  const centerX = width / 2;
  const centerY = height / 2;
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const visibleEdges = edges.filter(
    (edge) => nodeMap.has(edge.source) && nodeMap.has(edge.target)
  );
  const orbit = computeGraphOrbitMetrics(width, height);
  const ringRadii = orbit.ringRadii;
  const selectedEdge = selectedEdgeId ? visibleEdges.find((edge) => edge.id === selectedEdgeId) ?? null : null;
  const selectedNode = selectedNodeId ? nodeMap.get(selectedNodeId) ?? null : null;
  const edgePathDefs = visibleEdges.map((edge, index) => {
    const source = nodeMap.get(edge.source);
    const target = nodeMap.get(edge.target);
    if (!source || !target) return "";
    const control = buildEdgeControlPoint(source, target, centerX, centerY);
    return `<path id="graph-edge-${index}" d="M ${source.x} ${source.y} Q ${control.x} ${control.y} ${target.x} ${target.y}"></path>`;
  }).join("");
  const baseEdges = visibleEdges.map((edge, index) => renderEdge(ctx, edge, index, nodeMap, centerX, centerY, selectedNode, selectedEdge, false)).join("");
  const agentLayer = renderAgentLayer(ctx, visibleEdges);
  const overlayEdge = selectedEdge ? renderEdge(
    ctx,
    selectedEdge,
    visibleEdges.findIndex((edge) => edge.id === selectedEdge.id),
    nodeMap,
    centerX,
    centerY,
    selectedNode,
    selectedEdge,
    true
  ) : "";
  const sortedNodes = [...nodes].sort((left, right) => {
    const leftWeight = nodeRenderWeight(left, selectedNode, selectedEdge);
    const rightWeight = nodeRenderWeight(right, selectedNode, selectedEdge);
    return leftWeight - rightWeight;
  });
  const renderedNodes = sortedNodes.map((node) => renderGraphNode(ctx, node, selectedNode, selectedEdge)).join("");
  return `
    <svg viewBox="0 0 ${width} ${height}" class="graph-svg" preserveAspectRatio="xMidYMid meet" aria-label="Topologie s\xEDt\u011B" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
      <defs>
        <radialGradient id="nodeGlow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stop-color="rgba(56,189,248,.42)"></stop>
          <stop offset="100%" stop-color="rgba(56,189,248,0)"></stop>
        </radialGradient>
        <radialGradient id="hubGlow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stop-color="rgba(52,211,153,.40)"></stop>
          <stop offset="100%" stop-color="rgba(52,211,153,0)"></stop>
        </radialGradient>
        ${edgePathDefs}
      </defs>
      ${ringRadii.map(
    (radius, index) => `<circle cx="${centerX}" cy="${centerY}" r="${radius}" class="graph-ring graph-ring-${index + 1}"></circle>`
  ).join("")}
      <circle cx="${centerX}" cy="${centerY}" r="${Math.max(42, orbit.availableRadius * 0.2)}" class="hub-halo"></circle>
      <g class="graph-edge-layer">${baseEdges}</g>
      <g class="graph-agent-layer">${agentLayer}</g>
      <g class="graph-node-layer">${renderedNodes}</g>
      <g class="graph-overlay-layer">${overlayEdge}</g>
    </svg>
  `;
}
function renderAgentLayer(ctx, edges) {
  if (!edges.length) return "";
  const running = Boolean(ctx.state.automationStatus?.process_running);
  if (!running) return "";
  return collectAgentSignals(ctx).map((agent, index) => {
    const edgeIndex = index % edges.length;
    const duration = 6.8 + index % 5 * 0.86;
    const delay = index * 0.71 % duration;
    return `
      <g class="graph-agent-probe" data-agent-role="${ctx.escapeAttr(agent.role)}" aria-label="${ctx.escapeAttr(`${agent.label}: ${agent.summary}`)}">
        <title>${ctx.escapeHtml(agent.label)}: ${ctx.escapeHtml(agent.summary)}</title>
        <animateMotion dur="${duration}s" begin="-${delay}s" repeatCount="indefinite" rotate="auto" calcMode="spline" keyTimes="0;1" keySplines="0.35 0 0.25 1">
          <mpath href="#graph-edge-${edgeIndex}" xlink:href="#graph-edge-${edgeIndex}"></mpath>
        </animateMotion>
        <circle class="agent-probe-halo" r="8.4" fill="${agent.color}"></circle>
        <circle class="agent-probe-dot" r="3.2" fill="${agent.color}"></circle>
        <text class="agent-probe-label" x="0" y="-6.8" text-anchor="middle">${ctx.escapeHtml(agent.glyph)}</text>
      </g>
    `;
  }).join("");
}
function collectAgentSignals(ctx) {
  const statusAgents = ctx.state.automationStatus?.agents ?? [];
  const latestAgents = ctx.state.automationLatest?.agents ?? [];
  const lanes = (ctx.getLanes(ctx.state.report) ?? []).filter((lane) => lane.lane_type === "automation" || String(lane.source ?? "").includes("pentest") || String(lane.source ?? "").includes("decision")).map((lane) => ({
    role: String(lane.source ?? "lane"),
    status: String(lane.status ?? "ok"),
    summary: String(lane.summary ?? lane.title ?? "Auditn\xED agent")
  }));
  const agents = statusAgents.length ? statusAgents : latestAgents.length ? latestAgents : lanes;
  return agents.slice(0, 14).map((agent, index) => {
    const role = String(agent.role ?? agent.agent_id ?? agent.source ?? "agent");
    return {
      role,
      label: agentLabel(role),
      glyph: agentGlyph(role, index),
      color: agentColor(role, String(agent.status ?? "")),
      summary: String(agent.summary ?? agent.status ?? "b\u011B\u017E\xED nad mapou")
    };
  });
}
function agentLabel(role) {
  const text = role.toLowerCase();
  if (text.includes("pentest")) return "Pentest agent";
  if (text.includes("cve") || text.includes("intel")) return "Intel agent";
  if (text.includes("traffic") || text.includes("live") || text.includes("passive")) return "Traffic agent";
  if (text.includes("validation")) return "Validation agent";
  if (text.includes("ai") || text.includes("context")) return "AI context agent";
  if (text.includes("decision") || text.includes("risk")) return "Decision agent";
  return role.replaceAll("-", " ");
}
function agentGlyph(role, index) {
  const text = role.toLowerCase();
  if (text.includes("pentest")) return "P";
  if (text.includes("cve") || text.includes("intel")) return "I";
  if (text.includes("traffic") || text.includes("live") || text.includes("passive")) return "T";
  if (text.includes("validation")) return "V";
  if (text.includes("ai") || text.includes("context")) return "A";
  if (text.includes("decision") || text.includes("risk")) return "D";
  return String.fromCharCode(65 + index % 26);
}
function agentColor(role, status) {
  const text = `${role} ${status}`.toLowerCase();
  if (text.includes("fail") || text.includes("kill")) return "#fb7185";
  if (text.includes("pentest")) return "#f97316";
  if (text.includes("cve") || text.includes("intel")) return "#fbbf24";
  if (text.includes("traffic") || text.includes("live") || text.includes("passive")) return "#34d399";
  if (text.includes("ai") || text.includes("context")) return "#38bdf8";
  return "#a78bfa";
}
function renderEdge(ctx, edge, index, nodeMap, centerX, centerY, selectedNode, selectedEdge, overlay) {
  const source = nodeMap.get(edge.source);
  const target = nodeMap.get(edge.target);
  if (!source || !target) return "";
  const control = buildEdgeControlPoint(source, target, centerX, centerY);
  const focus = isFocusedEdge(edge, selectedNode, selectedEdge);
  const context = !focus && isContextEdge(edge, selectedNode, selectedEdge);
  const dimmed = Boolean(selectedNode || selectedEdge) && !focus && !context;
  const score = ctx.riskScoreFromIssueCounts(edge.issueCounts);
  const risk = edge.riskColor ?? ctx.riskColorForScore(score);
  const stroke = focus ? risk : context ? "rgba(56,189,248,0.42)" : "rgba(148,163,184,0.22)";
  const strokeWidth = focus ? Math.min(5.4, 2.1 + edge.packets / 20) : context ? 1.8 : 1.1;
  const opacity = overlay ? 1 : focus ? 0.98 : context ? 0.36 : dimmed ? 0.06 : 0.12;
  const pulseCount = focus && edge.active ? Math.min(4, Math.max(1, Math.round(edge.packets / 24))) : 0;
  const edgeClass = [
    "graph-edge-group",
    focus ? "is-focused" : "",
    context ? "is-context" : "",
    dimmed ? "is-dimmed" : "",
    overlay ? "is-overlay" : ""
  ].filter(Boolean).join(" ");
  return `
    <g class="${edgeClass}" data-edge-id="${ctx.escapeAttr(edge.id)}" data-edge-summary="${ctx.escapeAttr(`${edge.relation} \xB7 ${edge.packets} pkt \xB7 ${ctx.formatBytes(edge.bytes)}`)}" tabindex="0" role="button" aria-label="${ctx.escapeAttr(`${edge.relation}: ${edge.source} a\u017E ${edge.target}`)}">
      <path class="graph-edge ${edge.active ? "edge-active" : "edge-passive"}"
        style="stroke:${stroke};stroke-width:${strokeWidth};opacity:${opacity}"
        d="M ${source.x} ${source.y} Q ${control.x} ${control.y} ${target.x} ${target.y}"></path>
      ${pulseCount ? Array.from(
    { length: pulseCount },
    (_, pulse) => `<circle class="flow-pulse" r="${pulse === 0 ? 3.25 : 2.55}" fill="${risk}">
                 <animateMotion dur="${Math.max(1.8, 7.6 - Math.min(edge.packets, 180) / 26)}s" begin="${pulse * 0.52}s" repeatCount="indefinite" rotate="auto">
                   <mpath href="#graph-edge-${index}"></mpath>
                 </animateMotion>
               </circle>`
  ).join("") : ""}
    </g>
  `;
}
function renderGraphNode(ctx, node, selectedNode, selectedEdge) {
  const score = ctx.riskScoreFromIssueCounts(node.issueCounts);
  const stroke = node.riskColor ?? ctx.riskColorForScore(score);
  const radius = node.kind === "hub" ? 22 : node.kind === "core" ? 17.5 : node.kind === "external" ? 14.5 : 15.5;
  const selected = selectedNode?.id === node.id;
  const context = !selected && isContextNode(node, selectedNode, selectedEdge);
  const titleVisible = selected || selectedEdge && (selectedEdge.source === node.id || selectedEdge.target === node.id);
  const classes = [
    "graph-node-group",
    selected ? "is-selected" : "",
    context ? "is-context" : "",
    titleVisible ? "show-title" : ""
  ].filter(Boolean).join(" ");
  return `
    <g class="${classes}" data-node-id="${ctx.escapeAttr(node.id)}" tabindex="0" role="button" aria-label="${ctx.escapeAttr(`${node.title}: ${node.layerLabel}`)}">
      <circle class="node-glow" cx="${node.x}" cy="${node.y}" r="${radius + 20}" fill="${node.kind === "hub" ? "url(#hubGlow)" : "url(#nodeGlow)"}" opacity="${selected ? 1 : context ? 0.74 : 0.44}"></circle>
      <circle class="graph-node-shell" cx="${node.x}" cy="${node.y}" r="${radius}" fill="rgba(16,20,34,0.96)" stroke="${stroke}" stroke-width="${selected ? 3 : context ? 2.45 : 2.1}" style="filter:drop-shadow(0 0 ${ctx.cssLength(10 + score * 20)} ${stroke})"></circle>
      <circle class="graph-node-core" cx="${node.x}" cy="${node.y}" r="${Math.max(6.2, radius - 5.8)}" fill="rgba(255,255,255,0.04)" stroke="${stroke}" stroke-opacity="${score > 0 ? 0.34 : 0.18}" stroke-width="${1 + score * 0.92}"></circle>
      <text class="graph-node-label ${node.kind === "external" ? "is-small" : ""}" x="${node.x}" y="${node.y + 0.8}" text-anchor="middle" dominant-baseline="middle">${ctx.escapeHtml(ctx.nodeGlyph(node))}</text>
      <text class="graph-node-title ${titleVisible ? "is-visible" : ""}" x="${node.x}" y="${node.y + radius + 16}" text-anchor="middle">${ctx.escapeHtml(node.title)}</text>
    </g>
  `;
}
function buildEdgeControlPoint(source, target, centerX, centerY) {
  const midX = (source.x + target.x) / 2;
  const midY = (source.y + target.y) / 2;
  const inwardPull = source.kind === "external" || target.kind === "external" ? 0.08 : 0.16;
  return {
    x: midX + (centerX - midX) * inwardPull,
    y: midY + (centerY - midY) * inwardPull
  };
}
function isFocusedEdge(edge, selectedNode, selectedEdge) {
  if (selectedEdge) return edge.id === selectedEdge.id;
  if (selectedNode) return edge.source === selectedNode.id || edge.target === selectedNode.id;
  return false;
}
function isContextEdge(edge, selectedNode, selectedEdge) {
  if (!selectedEdge) return false;
  return edge.id !== selectedEdge.id && [edge.source, edge.target].some(
    (nodeId) => nodeId === selectedEdge.source || nodeId === selectedEdge.target
  );
}
function isContextNode(node, selectedNode, selectedEdge) {
  if (selectedEdge) {
    return node.id === selectedEdge.source || node.id === selectedEdge.target;
  }
  if (selectedNode) {
    return selectedNode.connected.includes(node.id);
  }
  return false;
}
function nodeRenderWeight(node, selectedNode, selectedEdge) {
  let weight = Math.round((node.riskScore ?? 0) * 100);
  if (selectedEdge && (node.id === selectedEdge.source || node.id === selectedEdge.target)) {
    weight += 300;
  }
  if (selectedNode?.id === node.id) {
    weight += 400;
  }
  if (node.kind === "hub") {
    weight -= 50;
  }
  return weight;
}

// ui-src/render/center-stage.ts
function renderCenterStage(ctx) {
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
    ctx.state.selectedGraphEdgeId
  );
  const status = ctx.state.automationStatus;
  const latest = ctx.state.automationLatest;
  const progress = clamp3(status?.progress_pct ?? Math.round(Number(latest?.summary?.tooling_coverage_ratio ?? 0) * 100), 0, 100);
  const phase = status?.current_phase_label ?? status?.current_phase ?? (status?.process_running ? "B\u011Bh" : "P\u0159ipraveno");
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
          <button type="button" class="icon-button" data-zoom="reset" title="Zarovnat sc\xE9nu"><i data-lucide="circle-dashed" class="h-4 w-4"></i></button>
          <button type="button" class="icon-button" data-zoom="out" title="Odd\xE1lit"><i data-lucide="zoom-out" class="h-4 w-4"></i></button>
          <button type="button" class="icon-button" data-zoom="in" title="P\u0159ibl\xED\u017Eit"><i data-lucide="zoom-in" class="h-4 w-4"></i></button>
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
        <div class="map-progress-card ${running ? "is-running" : ""}" data-progress-card aria-label="Progress b\u011Bhu">
          <div class="map-progress-head">
            <strong data-progress-phase>${ctx.escapeHtml(phase)}</strong>
            <span data-progress-value>${progress}%</span>
          </div>
          <div class="map-progress-line"><span data-progress-bar data-progress="${progress}" style="width:${progress}%"></span></div>
          <div class="map-progress-meta">
            <span class="tiny-chip"><i data-lucide="sparkles" class="h-3.5 w-3.5"></i>${agentCount}</span>
            <span class="tiny-chip"><i data-lucide="shield-alert" class="h-3.5 w-3.5"></i>${ctx.state.pentestMode === "aggressive" ? "Hard" : ctx.state.pentestMode === "smart" ? "Smart" : "Vyp."}</span>
            <span class="tiny-chip"><i data-lucide="activity" class="h-3.5 w-3.5"></i>${ctx.state.liveMode ? "Live" : "Ru\u010Dn\u011B"}</span>
          </div>
        </div>
        ${renderMobileControls(ctx)}
        <div id="graphTooltip" class="graph-tooltip"></div>
      </section>
    </div>
  `;
}
var clamp3 = (value, min, max) => Math.max(min, Math.min(max, value));
function renderReaderStage(ctx) {
  const dataset = buildReaderDataset(ctx);
  const meta = ctx.DETAIL_META[ctx.state.detailPanel] ?? { icon: "scan-line", title: "Detail" };
  const scope = ctx.state.detailScope === "all" ? "v\u0161e" : "kontext";
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
function buildReaderDataset(ctx) {
  switch (ctx.state.detailPanel) {
    case "assets":
      return buildAssetReader(ctx);
    case "lanes":
      return buildLaneReader(ctx);
    case "triage":
      return buildTriageReader(ctx);
    case "diff":
      return buildDiffReader(ctx);
    case "findings":
    default:
      return buildFindingReader(ctx);
  }
}
function buildFindingReader(ctx) {
  const items = ctx.getVisibleFindings();
  const selected = ctx.getSelectedFinding(items);
  return {
    label: ctx.state.detailScope === "all" ? "V\u0161echny n\xE1lezy" : "N\xE1lezy v kontextu",
    count: items.length,
    article: selected ? findingArticle(ctx, selected) : ctx.emptyState("Vyber n\xE1lez v prav\xE9m panelu.")
  };
}
function buildAssetReader(ctx) {
  const items = ctx.getAssets(ctx.state.report);
  const selected = ctx.getSelectedAsset();
  return {
    label: "Za\u0159\xEDzen\xED",
    count: items.length,
    article: selected ? assetArticle(ctx, selected) : ctx.emptyState("Vyber za\u0159\xEDzen\xED v prav\xE9m panelu.")
  };
}
function buildLaneReader(ctx) {
  const items = ctx.getLanes(ctx.state.report);
  const selected = items[0];
  return {
    label: "Sb\u011Br a telemetrie",
    count: items.length,
    article: selected ? laneArticle(ctx, selected) : ctx.emptyState("Bez sb\u011Brn\xFDch lane.")
  };
}
function buildTriageReader(ctx) {
  const items = ctx.getTriage(ctx.state.report);
  const selected = ctx.getSelectedAction();
  return {
    label: "Doporu\u010Den\xE9 kroky",
    count: items.length,
    article: selected ? actionArticle(ctx, selected) : ctx.emptyState("Bez doporu\u010Den\xFDch krok\u016F.")
  };
}
function buildDiffReader(ctx) {
  const items = ctx.state.report?.diff?.changed_services ?? ctx.state.report?.changes ?? [];
  return {
    label: "Zm\u011Bny",
    count: Array.isArray(items) ? items.length : 0,
    article: Array.isArray(items) && items[0] ? genericArticle(ctx, "Zm\u011Bna", items[0].service_key ?? items[0].title ?? "Zm\u011Bna", items[0].summary ?? items[0].change_type ?? "", "", Object.entries(items[0]).map(([key, value]) => `${key}=${String(value)}`)) : ctx.emptyState("Bez zm\u011Bn.")
  };
}
function findingArticle(ctx, finding) {
  const summary = finding.finding_type === "plaintext_management_protocol" ? ctx.humanizeFinding(finding) : finding.rationale ?? ctx.humanizeFinding(finding);
  const target = findingTarget(ctx, finding);
  const recommendation = ctx.localizeUiText(finding.recommendation ?? ctx.recommendedSteps(finding).join(" "));
  const steps = findingSteps(ctx, finding, recommendation);
  return readerArticle(ctx, {
    eyebrow: ctx.detailEyebrow(finding.finding_type ?? "finding"),
    title: ctx.displayFindingTitle(finding),
    lead: plainFindingLead(ctx, finding, summary),
    tone: ctx.severity(finding.severity),
    facts: [
      ["T\xFDk\xE1 se", target],
      ["Z\xE1va\u017Enost", severityLabel(ctx, finding.severity)],
      ["Jistota", ctx.confidenceLabel(finding.confidence)],
      ["Typ", ctx.detailEyebrow(finding.finding_type ?? "finding")]
    ],
    sections: [
      { title: "Co p\u0159esn\u011B se d\u011Bje", body: ctx.localizeUiText(summary) },
      { title: "Pro\u010D to vad\xED", body: findingImpact(ctx, finding) },
      { title: "Co ud\u011Blat te\u010F", steps },
      { title: "Jak pozn\xE1m, \u017Ee je hotovo", steps: findingVerification(ctx, finding) }
    ],
    evidence: [
      ...ctx.compact([finding.host_key ? `host=${finding.host_key}` : "", finding.service_key ? `slu\u017Eba=${finding.service_key}` : ""]),
      ...finding.evidence ?? []
    ],
    footnote: "V\xFDklad je slo\u017Een\xFD lok\xE1ln\u011B z reportu a pravidel programu. AI chat vpravo m\u016F\u017Ee stejn\xFD kontext je\u0161t\u011B p\u0159evypr\xE1v\u011Bt podle ot\xE1zky."
  });
}
function assetArticle(ctx, asset) {
  const related = ctx.getRelatedFindingsForNode(asset.asset_id);
  const title = asset.name ?? asset.asset_id;
  const relatedTitles = related.map((item) => ctx.displayFindingTitle(item));
  return readerArticle(ctx, {
    eyebrow: ctx.assetTypeLabel(asset.asset_type),
    title,
    lead: `${title} je za\u0159\xEDzen\xED nebo prvek, kter\xFD program na\u0161el v s\xED\u0165ov\xFDch datech. Tady je p\u0159elo\u017Een\xE9, co o n\u011Bm v\xEDme a pro\u010D se na n\u011Bj d\xEDvat.`,
    tone: related[0] ? ctx.severity(related[0].severity) : ctx.severity(asset.confidence),
    facts: [
      ["IP adresa", asset.ip ?? "neuvedeno"],
      ["Zdroj", asset.source ?? "invent\xE1\u0159"],
      ["Typ", ctx.assetTypeLabel(asset.asset_type)],
      ["Jistota", String(asset.confidence ?? "neuvedeno")]
    ],
    sections: [
      {
        title: "Co je to za prvek",
        body: ctx.compact([asset.ip, asset.vendor, asset.model, asset.location, asset.status ? `stav ${asset.status}` : ""]).join(" \xB7 ") || "Program zat\xEDm nem\xE1 v\xEDc popisn\xFDch \xFAdaj\u016F, tak\u017Ee je pot\u0159eba ov\u011B\u0159it vlastn\xEDka a \xFA\u010Del za\u0159\xEDzen\xED."
      },
      {
        title: "Pro\u010D m\u011B zaj\xEDm\xE1",
        body: related.length ? `Na za\u0159\xEDzen\xED jsou nav\xE1zan\xE1 rizika: ${relatedTitles.join(" \xB7 ")}. To neznamen\xE1 automaticky incident, ale \u0159\xEDk\xE1 to, \u017Ee se tenhle prvek m\xE1 \u0159e\u0161it p\u0159ed b\u011B\u017Enou inventurou.` : "Na za\u0159\xEDzen\xED nen\xED p\u0159\xEDmo nav\xE1zan\xFD konkr\xE9tn\xED n\xE1lez. I tak je d\u016Fle\u017Eit\xE9 v\u011Bd\u011Bt, komu pat\u0159\xED a jestli jeho viditeln\xE9 slu\u017Eby odpov\xEDdaj\xED o\u010Dek\xE1v\xE1n\xED."
      },
      {
        title: "Co ud\u011Blat te\u010F",
        steps: [
          "Ov\u011B\u0159 vlastn\xEDka za\u0159\xEDzen\xED a jeho roli v s\xEDti.",
          related[0] ? `Za\u010Dni nav\xE1zan\xFDm rizikem: ${ctx.displayFindingTitle(related[0])}.` : "Zkontroluj, zda otev\u0159en\xE9 slu\u017Eby odpov\xEDdaj\xED roli za\u0159\xEDzen\xED.",
          "Kdy\u017E jde o spr\xE1vu, server nebo s\xED\u0165ov\xFD prvek, omez p\u0159\xEDstup jen z nutn\xFDch segment\u016F."
        ]
      }
    ],
    evidence: ctx.compact([asset.source, asset.mac, asset.linked_host_key, ...asset.observations ?? []])
  });
}
function laneArticle(ctx, lane) {
  return readerArticle(ctx, {
    eyebrow: ctx.localizeUiText(lane.lane_type ?? "sb\u011Br"),
    title: ctx.localizeUiText(lane.title ?? "Sb\u011Bra\u010D"),
    lead: "Tahle \u010D\xE1st \u0159\xEDk\xE1, odkud program bere data a jestli jsou pou\u017Eiteln\xE1 pro rozhodnut\xED.",
    tone: ctx.severity(lane.status === "ok" ? "low" : lane.status),
    facts: [
      ["Zdroj", lane.source ?? "neuvedeno"],
      ["Stav", lane.status ?? "neuvedeno"],
      ["Re\u017Eim", lane.mode ?? "neuvedeno"]
    ],
    sections: [
      {
        title: "Co zdroj dodal",
        body: ctx.compact([ctx.localizeUiText(lane.summary ?? ""), lane.source ? `zdroj ${lane.source}` : "", lane.status ? `stav ${lane.status}` : ""]).join(" \xB7 ") || "Sb\u011Brn\xFD modul nem\xE1 dopl\u0148uj\xEDc\xED koment\xE1\u0159."
      },
      {
        title: "Co ud\u011Blat te\u010F",
        steps: [
          ctx.localizeUiText(lane.recommendation ?? "Ov\u011B\u0159 nav\xE1z\xE1n\xED vstupn\xEDho zdroje, dostupnost dat a konzistenci \u010Dasov\xE9ho okna."),
          "Kdy\u017E zdroj chyb\xED nebo je \u010D\xE1ste\u010Dn\xFD, neber v\xFDsledek jako kompletn\xED obraz s\xEDt\u011B."
        ]
      }
    ],
    evidence: ctx.compact([lane.source, lane.status, lane.mode, ...lane.details ?? lane.observations ?? []])
  });
}
function actionArticle(ctx, action) {
  return readerArticle(ctx, {
    eyebrow: "dal\u0161\xED krok",
    title: ctx.localizeUiText(action.title ?? "Doporu\u010Den\xFD krok"),
    lead: "Tohle je navr\u017Een\xFD praktick\xFD krok. Je psan\xFD jako \xFAkol, ne jako technick\xFD detail.",
    tone: ctx.severity(action.priority),
    facts: [
      ["Priorita", severityLabel(ctx, action.priority)],
      ["Slu\u017Eba", action.target_service_key ?? "neuvedeno"],
      ["Za\u0159\xEDzen\xED", action.target_asset_id ?? "neuvedeno"],
      ["N\xE1stroje", (action.recommended_tools ?? []).join(", ") || "neuvedeno"]
    ],
    sections: [
      { title: "Pro\u010D ten krok d\xE1v\xE1 smysl", body: ctx.localizeUiText(action.rationale ?? "Krok nem\xE1 dopl\u0148uj\xEDc\xED zd\u016Fvodn\u011Bn\xED.") },
      {
        title: "Co ud\u011Blat te\u010F",
        steps: ctx.compact([
          ctx.localizeUiText(action.next_step ?? ""),
          ...(action.recommended_tools ?? []).map((tool) => `Pou\u017Eij nebo ov\u011B\u0159 n\xE1stroj: ${tool}.`),
          "Po zm\u011Bn\u011B spus\u0165 nov\xFD b\u011Bh a porovnej, jestli n\xE1lez zmizel nebo se zm\u011Bnila priorita."
        ])
      }
    ],
    evidence: ctx.compact([action.priority, action.target_service_key, action.target_asset_id, ...action.evidence ?? []])
  });
}
function genericArticle(ctx, eyebrow, title, summary, recommendation, evidence, tone = "severity-neutral") {
  return readerArticle(ctx, {
    eyebrow,
    title,
    lead: summary || "Program na\u0161el polo\u017Eku, kterou je pot\u0159eba za\u0159adit do kontextu b\u011Bhu.",
    tone,
    sections: [
      summary ? { title: "Co se zm\u011Bnilo", body: summary } : null,
      recommendation ? { title: "Co ud\u011Blat te\u010F", body: recommendation } : null
    ].filter(Boolean),
    evidence
  });
}
function readerArticle(ctx, input) {
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
          ${evidence.length ? `<section class="reader-section reader-evidence"><strong>D\u016Fkazy a kontext</strong><p>Tohle jsou technick\xE9 stopy, ze kter\xFDch program vych\xE1z\xED. Nejsou nutn\xE9 k pochopen\xED probl\xE9mu, ale pom\xE1haj\xED dohledat p\u0159esn\xE9 m\xEDsto.</p><div class="reader-evidence-grid">${evidence.map((item) => `<code>${ctx.escapeHtml(String(item))}</code>`).join("")}</div></section>` : ""}
          ${input.footnote ? `<p class="reader-footnote">${ctx.escapeHtml(input.footnote)}</p>` : ""}
        </div>
        ${facts.length ? `<aside class="reader-fact-panel"><strong>Rychl\xE1 orientace</strong>${facts.map(([label, value]) => `<div><span>${ctx.escapeHtml(label)}</span><b>${ctx.escapeHtml(String(value || "neuvedeno"))}</b></div>`).join("")}</aside>` : ""}
      </div>
    </section>
  `;
}
function readerSection(ctx, section) {
  if (!section) return "";
  if (section.steps?.length) {
    return `<section class="reader-section reader-steps"><strong>${ctx.escapeHtml(section.title)}</strong><ol>${section.steps.map((step) => `<li>${ctx.escapeHtml(step)}</li>`).join("")}</ol></section>`;
  }
  return `<section class="reader-section"><strong>${ctx.escapeHtml(section.title)}</strong><p class="reader-summary">${ctx.escapeHtml(section.body ?? "")}</p></section>`;
}
function findingTarget(ctx, finding) {
  return ctx.compact([finding.service_key, finding.host_key]).join(" \xB7 ") || "neuvedeno";
}
function severityLabel(ctx, value) {
  const level = ctx.levelOf(value);
  if (level === "high") return "vysok\xE1";
  if (level === "medium") return "st\u0159edn\xED";
  if (level === "low") return "n\xEDzk\xE1";
  return "neur\u010Den\xE1";
}
function plainFindingLead(ctx, finding, summary) {
  const target = findingTarget(ctx, finding);
  const severity2 = severityLabel(ctx, finding.severity);
  return `Program na\u0161el probl\xE9m na ${target}. Priorita je ${severity2}. V praxi to znamen\xE1: ${ctx.localizeUiText(summary)}`;
}
function findingImpact(ctx, finding) {
  const text = `${finding.finding_type ?? ""} ${finding.title ?? ""} ${finding.rationale ?? ""}`.toLowerCase();
  if (text.includes("plaintext") || text.includes("telnet") || text.includes("ftp")) {
    return "P\u0159ihl\xE1\u0161en\xED nebo \u0159\xEDdic\xED komunikace m\u016F\u017Ee j\xEDt po s\xEDti \u010Diteln\u011B. Kdo m\xE1 mo\u017Enost provoz odposlechnout, m\u016F\u017Ee z\xEDskat \xFAdaje nebo pochopit, jak se slu\u017Eba ovl\xE1d\xE1.";
  }
  if (text.includes("cve") || text.includes("vulnerab") || text.includes("kev") || text.includes("epss")) {
    return "Slu\u017Eba vypad\xE1 jako verze, pro kterou existuj\xED zn\xE1m\xE9 bezpe\u010Dnostn\xED slabiny. Neznamen\xE1 to automaticky prolomen\xED, ale je pot\u0159eba ov\u011B\u0159it verzi, dostupnost z\xE1platy a viditelnost slu\u017Eby.";
  }
  if (text.includes("swagger") || text.includes("metrics") || text.includes("directory") || text.includes("management") || text.includes("admin")) {
    return "Slu\u017Eba zbyte\u010Dn\u011B ukazuje rozhran\xED nebo informace, kter\xE9 maj\xED b\xFDt sp\xED\u0161 intern\xED. \xDAto\u010Dn\xEDkovi to m\u016F\u017Ee pomoct naj\xEDt dal\u0161\xED cestu nebo l\xE9pe pochopit syst\xE9m.";
  }
  if (text.includes("traffic") || text.includes("packet") || text.includes("timeout") || text.includes("flow")) {
    return "S\xED\u0165ov\xFD provoz se chov\xE1 jinak, ne\u017E je pro dan\xFD c\xEDl o\u010Dek\xE1van\xE9. M\u016F\u017Ee j\xEDt o chybu konfigurace, p\u0159et\xED\u017Een\xED, skenov\xE1n\xED nebo b\u011B\u017En\xFD provoz, kter\xFD je pot\u0159eba vysv\u011Btlit.";
  }
  if (text.includes("identification") || text.includes("gap") || text.includes("uncertainty")) {
    return "Program nem\xE1 dost p\u0159esnou identitu slu\u017Eby nebo za\u0159\xEDzen\xED. Bez toho se h\u016F\u0159 rozhoduje, jestli je n\xE1lez skute\u010Dn\u011B rizikov\xFD a kdo ho m\xE1 \u0159e\u0161it.";
  }
  return "N\xE1lez je sign\xE1l ke kontrole. S\xE1m o sob\u011B nemus\xED znamenat incident, ale ukazuje m\xEDsto, kde je dobr\xE9 ov\u011B\u0159it nastaven\xED, vlastn\xEDka a re\xE1ln\xFD dopad.";
}
function findingSteps(ctx, finding, recommendation) {
  const text = `${finding.finding_type ?? ""} ${finding.title ?? ""} ${finding.rationale ?? ""}`.toLowerCase();
  const target = findingTarget(ctx, finding);
  const steps = [
    `Najdi vlastn\xEDka nebo spr\xE1vce c\xEDle ${target}.`,
    recommendation
  ];
  if (text.includes("telnet")) {
    steps.push("Vypni Telnet, pokud nen\xED nezbytn\xFD, a nahra\u010F ho SSH.");
    steps.push("Povol port 23 jen z nutn\xE9ho spr\xE1vcovsk\xE9ho segmentu, ide\xE1ln\u011B v\u016Fbec.");
  } else if (text.includes("ftp")) {
    steps.push("Ov\u011B\u0159, jestli se p\u0159es FTP pos\xEDlaj\xED p\u0159ihla\u0161ovac\xED \xFAdaje nebo citliv\xE9 soubory.");
    steps.push("Nahra\u010F FTP za SFTP nebo FTPS a omez port 21 jen na nutn\xE9 zdroje.");
  } else if (text.includes("cve") || text.includes("vulnerab") || text.includes("kev") || text.includes("epss")) {
    steps.push("Ov\u011B\u0159 skute\u010Dnou verzi slu\u017Eby na serveru, ne jen banner z Nmapu.");
    steps.push("Najdi vendor advisory nebo bal\xED\u010Dkovou aktualizaci a napl\xE1nuj patch.");
    steps.push("Do opravy omez p\u0159\xEDstup ke slu\u017Eb\u011B firewallem nebo segmentac\xED.");
  } else if (text.includes("swagger") || text.includes("metrics") || text.includes("directory") || text.includes("management") || text.includes("admin")) {
    steps.push("Zkontroluj, jestli rozhran\xED mus\xED b\xFDt dostupn\xE9 z t\xE9to s\xEDt\u011B.");
    steps.push("P\u0159idej autentizaci, reverzn\xED proxy nebo omezen\xED jen na intern\xED spr\xE1vce.");
  } else if (text.includes("traffic") || text.includes("packet") || text.includes("timeout") || text.includes("flow")) {
    steps.push("Porovnej \u010Das a c\xEDl s legitimn\xED aktivitou v s\xEDti.");
    steps.push("Kdy\u017E provoz nem\xE1 vysv\u011Btlen\xED, ov\u011B\u0159 zdrojov\xFD host a logy slu\u017Eby.");
  }
  return uniqueText(steps.filter(Boolean)).slice(0, 6);
}
function findingVerification(ctx, finding) {
  const text = `${finding.finding_type ?? ""} ${finding.title ?? ""} ${finding.rationale ?? ""}`.toLowerCase();
  const steps = ["Spus\u0165 nov\xFD b\u011Bh a ov\u011B\u0159, \u017Ee se n\xE1lez u\u017E neobjev\xED nebo klesne jeho priorita."];
  if (finding.service_key) steps.push(`Ov\u011B\u0159 slu\u017Ebu ${finding.service_key} znovu aktivn\xEDm skenem.`);
  if (text.includes("plaintext") || text.includes("telnet") || text.includes("ftp")) steps.push("V pasivn\xED \u010D\xE1sti zkontroluj, \u017Ee u\u017E nejsou vid\u011Bt ne\u0161ifrovan\xE9 p\u0159ihla\u0161ovac\xED nebo \u0159\xEDdic\xED relace.");
  if (text.includes("cve") || text.includes("vulnerab")) steps.push("Zkontroluj, \u017Ee banner/verze a CVE vazba po oprav\u011B odpov\xEDdaj\xED nov\xE9 verzi.");
  return uniqueText(steps).slice(0, 4);
}
function uniqueText(items) {
  const seen = /* @__PURE__ */ new Set();
  return items.filter((item) => {
    const key = item.trim().toLowerCase();
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
function renderMobileControls(ctx) {
  const summary = ctx.state.report?.summary ?? {};
  return `
    <div class="mobile-control-strip" aria-label="Mobiln\xED ovl\xE1d\xE1n\xED">
      <div class="mobile-stat-row">
        <span class="tiny-chip"><i data-lucide="network" class="h-3.5 w-3.5"></i>${summary.hosts_total ?? 0}</span>
        <span class="tiny-chip"><i data-lucide="shield-alert" class="h-3.5 w-3.5"></i>${summary.findings_total ?? 0}</span>
        <span class="tiny-chip"><i data-lucide="activity" class="h-3.5 w-3.5"></i>${summary.events_total ?? 0}</span>
      </div>
      <div class="mobile-action-row">
        <button type="button" class="icon-button ${ctx.state.liveMode ? "is-live" : ""}" data-live-toggle title="Realtime"><i data-lucide="activity" class="h-4 w-4"></i></button>
        <button type="button" class="icon-button" data-refresh title="Na\u010D\xEDst znovu"><i data-lucide="refresh-cw" class="h-4 w-4"></i></button>
        <button type="button" class="icon-button" data-automation-start title="Spustit autopilot"><i data-lucide="play" class="h-4 w-4"></i></button>
        <button type="button" class="icon-button" data-focus="audit" title="Audit a AI"><i data-lucide="bot" class="h-4 w-4"></i></button>
        <button type="button" class="icon-button" data-export="json" title="Export JSON"><i data-lucide="download" class="h-4 w-4"></i></button>
      </div>
    </div>
  `;
}

// ui-src/render/right-panel.ts
function renderRightStage(ctx) {
  return ctx.state.rightMode === "chat" ? `<div class="right-stack is-chat"><div id="auditHeroBlock" class="audit-hero-block">${renderAuditHero(ctx)}</div><div id="auditChatBlock" class="audit-chat-block">${renderAuditChat(ctx)}</div></div>` : `<div class="right-stack"><div id="auditHeroBlock" class="audit-hero-block">${renderAuditHero(ctx)}</div><div id="auditTabsBlock" class="audit-tabs-block">${renderAuditTabs(ctx)}</div><div id="auditDetailBlock" class="audit-detail-block">${renderAuditDetail(ctx)}</div></div>`;
}
function renderAuditHero(ctx) {
  const summary = ctx.state.report?.summary ?? {};
  const expanded = ctx.requestedFocus() === "audit";
  return `
    <div class="audit-hero-shell">
      <button type="button" class="audit-assistant-button" data-chat-toggle title="${ctx.state.rightMode === "chat" ? "Zp\u011Bt na panel" : "Otev\u0159\xEDt chat"}" aria-label="${ctx.state.rightMode === "chat" ? "Zp\u011Bt na auditn\xED panel" : "Otev\u0159\xEDt auditn\xED chat"}">
        <i data-lucide="bot" class="h-5 w-5"></i>
      </button>
      <button type="button" class="audit-focus-button ${expanded ? "is-active" : ""}" data-focus="audit" title="${expanded ? "Zmen\u0161it panel" : "Zv\u011Bt\u0161it panel"}" aria-label="${expanded ? "Zmen\u0161it auditn\xED panel" : "Zv\u011Bt\u0161it auditn\xED panel"}">
        <i data-lucide="${expanded ? "minimize-2" : "maximize-2"}" class="h-4 w-4"></i>
      </button>
      <div class="audit-hero-card">
        ${auditMetric(ctx, "shield-alert", summary.findings_total ?? 0, "N\xE1lezy")}
        ${auditMetric(ctx, "activity", summary.events_total ?? 0, "Sign\xE1ly")}
        ${auditMetric(ctx, "radar", summary.cves_total ?? 0, "CVE")}
      </div>
    </div>
  `;
}
function auditMetric(ctx, icon, value, label) {
  return `<span class="audit-metric" title="${ctx.escapeAttr(label)}" aria-label="${ctx.escapeAttr(`${label}: ${value}`)}"><i data-lucide="${icon}" class="h-3.5 w-3.5"></i><strong>${value}</strong></span>`;
}
function renderAuditTabs(ctx) {
  return `
    <div class="audit-tabs">
      <div class="audit-tab-grid">
        ${Object.keys(ctx.DETAIL_META).map((panel) => {
    const meta = ctx.DETAIL_META[panel];
    return `<button type="button" class="tab-chip ${ctx.state.detailPanel === panel ? "is-active" : ""}" data-detail-panel="${panel}" title="${ctx.escapeAttr(meta.title)}" aria-label="${ctx.escapeAttr(meta.title)}"><i data-lucide="${meta.icon}" class="h-4 w-4"></i><span>${ctx.escapeHtml(meta.title)}</span></button>`;
  }).join("")}
      </div>
      <div class="audit-mode-grid" aria-label="Re\u017Eim prav\xE9ho panelu">
        ${modeButton(ctx, "scan-line", "Detail", "detail", "detailView")}
        ${modeButton(ctx, "layers", "Seznam", "list", "detailView")}
        ${modeButton(ctx, "radar", "Kontext", "context", "detailScope")}
        ${modeButton(ctx, "network", "V\u0161e", "all", "detailScope")}
      </div>
    </div>
  `;
}
function modeButton(ctx, icon, label, value, field) {
  const active = ctx.state[field] === value;
  const dataAttr = field === "detailView" ? "data-detail-view" : "data-detail-scope";
  return `<button type="button" class="mode-chip ${active ? "is-active" : ""}" ${dataAttr}="${ctx.escapeAttr(value)}" title="${ctx.escapeAttr(label)}"><i data-lucide="${icon}" class="h-3.5 w-3.5"></i><span>${ctx.escapeHtml(label)}</span></button>`;
}
function renderAuditChat(ctx) {
  const ai = ctx.state.aiStatus;
  const aiStatus = ai?.status ?? "unknown";
  const aiReady = aiStatus === "ready";
  const aiLabel = aiReady ? "lok\xE1ln\xED AI" : aiStatus === "base-ready" ? "AI profil chyb\xED" : aiStatus === "missing-model" ? "model chyb\xED" : aiStatus === "ollama-not-running" ? "Ollama neb\u011B\u017E\xED" : "fallback";
  return `
    <div class="chat-shell classic-chat-shell">
      <div class="ai-status-strip ${aiReady ? "is-ready" : "is-limited"}" title="${ctx.escapeAttr([ai?.gpu_runtime_hint, ...ai?.next_steps ?? []].filter(Boolean).join(" "))}">
        <span><i data-lucide="bot" class="h-3.5 w-3.5"></i>${ctx.escapeHtml(aiLabel)}</span>
        <code>${ctx.escapeHtml(ai?.selected_model ?? "deterministick\xFD re\u017Eim")}</code>
      </div>
      <div class="chat-log" id="chatLog" data-scroll-key="chat">
        ${ctx.state.chatMessages.map((message, index) => `
          <div class="chat-bubble ${message.role === "assistant" ? "is-assistant" : "is-user"} ${message.streaming ? "is-streaming" : ""}" data-chat-index="${index}">
            <div data-chat-text>${ctx.escapeHtml(message.text || (message.streaming ? "P\xED\u0161u odpov\u011B\u010F\u2026" : ""))}</div>
            ${message.sources?.length ? `<div class="chat-source-row">${message.sources.slice(0, 3).map((source) => `<span class="tiny-chip">${ctx.escapeHtml(source)}</span>`).join("")}</div>` : ""}
          </div>
        `).join("")}
        ${ctx.state.chatBusy && !ctx.state.chatMessages.some((message) => message.streaming) ? `<div class="chat-bubble is-assistant is-loading">P\u0159ipravuji odpov\u011B\u010F\u2026</div>` : ""}
      </div>
      <div class="chat-compose">
        <div class="chat-quick-row compact">
          <button type="button" class="chat-quick" data-chat-prompt="Co m\xE1m \u0159e\u0161it jako prvn\xED?">Priorita</button>
          <button type="button" class="chat-quick" data-chat-prompt="Co znamen\xE1 vybran\xE9 riziko?">Riziko</button>
          <button type="button" class="chat-quick" data-chat-prompt="Co je to za za\u0159\xEDzen\xED?">Za\u0159\xEDzen\xED</button>
          <button type="button" class="chat-quick" data-chat-prompt="Jak\xFD je dal\u0161\xED krok?">Krok</button>
        </div>
        <div class="chat-input-row">
          <textarea id="chatInput" class="chat-input" rows="2" placeholder="Dotaz k vybran\xE9mu n\xE1lezu nebo za\u0159\xEDzen\xED">${ctx.escapeHtml(ctx.state.chatDraft)}</textarea>
          <button type="button" class="chat-send" data-chat-send title="Odeslat" ${ctx.state.chatBusy ? "disabled" : ""}><i data-lucide="chevron-right" class="h-4 w-4"></i></button>
        </div>
      </div>
    </div>
  `;
}
function renderAuditDetail(ctx) {
  switch (ctx.state.detailPanel) {
    case "findings":
      return renderFindingsDetail(ctx);
    case "assets":
      return renderAssetsDetail(ctx);
    case "lanes":
      return renderLanesDetail(ctx);
    case "triage":
      return renderTriageDetail(ctx);
    case "diff":
      return renderDiffDetail(ctx);
    default:
      return ctx.emptyState("Bez panelu.");
  }
}
function renderFindingsDetail(ctx) {
  const findings = ctx.getVisibleFindings();
  const total = (ctx.state.report?.findings ?? []).length;
  const selected = ctx.getSelectedFinding(findings);
  const selectedKey = selected ? ctx.findingKey(selected) : null;
  return detailPanelWrap(ctx, "Rizika", findings.length, total, selected ? renderFindingFocus(ctx, selected) : emptyFocus(ctx, "Na tomhle v\xFD\u0159ezu nejsou \u017E\xE1dn\xE1 rizika."), findings.length ? findings.map((finding, index) => findingCard(ctx, finding, index, selectedKey != null && ctx.findingKey(finding) === selectedKey)).join("") : ctx.emptyState("Bez nav\xE1zan\xFDch rizik."));
}
function renderAssetsDetail(ctx) {
  const assets = ctx.getAssets(ctx.state.report);
  const selected = ctx.getSelectedAsset();
  return detailPanelWrap(ctx, "Stanice", assets.length, assets.length, selected ? renderAssetFocus(ctx, selected) : emptyFocus(ctx, "Na\u010Dten\xFD b\u011Bh nem\xE1 invent\xE1\u0159 za\u0159\xEDzen\xED."), assets.length ? assets.map((asset) => assetCard(ctx, asset, selected && asset.asset_id === selected.asset_id)).join("") : ctx.emptyState("Bez za\u0159\xEDzen\xED."));
}
function renderLanesDetail(ctx) {
  const lanes = ctx.getLanes(ctx.state.report);
  const selected = lanes[0];
  return detailPanelWrap(ctx, "Sb\u011Br", lanes.length, lanes.length, selected ? renderLaneFocus(ctx, selected) : emptyFocus(ctx, "Na tomhle b\u011Bhu nejsou sb\u011Brn\xE9 lane."), lanes.length ? lanes.map((lane) => laneCard(ctx, lane, lane === selected)).join("") : ctx.emptyState("Bez sb\u011Brn\xFDch lane."));
}
function renderTriageDetail(ctx) {
  const actions = ctx.getTriage(ctx.state.report);
  const selected = ctx.getSelectedAction();
  const selectedKey = selected ? ctx.actionKey(selected) : null;
  return detailPanelWrap(ctx, "Kroky", actions.length, actions.length, selected ? renderActionFocus(ctx, selected) : emptyFocus(ctx, "Nad t\xEDmto b\u011Bhem nen\xED doporu\u010Den\xFD dal\u0161\xED krok."), actions.length ? actions.map((action, index) => triageCard(ctx, action, index, selectedKey != null && ctx.actionKey(action) === selectedKey)).join("") : ctx.emptyState("Bez navazuj\xEDc\xEDch krok\u016F."));
}
function renderDiffDetail(ctx) {
  const diff = ctx.state.report?.diff ?? ctx.state.report?.changes ?? [];
  const rows = Array.isArray(diff) ? diff.slice(0, 6).map((item) => ({ title: ctx.localizeUiText(item.title ?? item.kind ?? "Zm\u011Bna"), sub: ctx.localizeUiText(item.summary ?? item.value ?? "Bez detailu"), tone: ctx.levelOf(item.severity ?? item.priority ?? "medium") })) : [];
  const selected = rows[0];
  return detailPanelWrap(ctx, "Zm\u011Bny", rows.length, rows.length, selected ? renderDiffFocus(ctx, selected) : emptyFocus(ctx, "Na tomhle b\u011Bhu nen\xED diff proti p\u0159edchoz\xEDmu stavu."), rows.length ? rows.map((row, index) => `<div class="detail-card ${ctx.severity(row.tone)} ${index === 0 ? "is-active" : "is-collapsed"}" title="${ctx.escapeAttr(row.title)}"><strong>${ctx.escapeHtml(ctx.trim(row.title, 52))}</strong></div>`).join("") : ctx.emptyState("Bez zm\u011Bn."));
}
function detailPanelWrap(ctx, label, count, total, focus, content) {
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
function emptyFocus(ctx, message) {
  return `<div class="detail-focus-card severity-neutral"><div class="detail-focus-copy"><strong>Bez detailu</strong><p>${ctx.escapeHtml(message)}</p></div></div>`;
}
function renderFindingFocus(ctx, finding) {
  const evidence = (finding.evidence ?? []).slice(0, 4);
  const summary = finding.finding_type === "plaintext_management_protocol" ? ctx.humanizeFinding(finding) : finding.rationale ?? ctx.humanizeFinding(finding);
  return renderDetailFocusCard(ctx, {
    tone: ctx.levelOf(finding.severity),
    eyebrow: ctx.detailEyebrow(finding.finding_type ?? "finding"),
    title: ctx.displayFindingTitle(finding),
    summary: ctx.localizeUiText(summary),
    recommendation: ctx.localizeUiText(finding.recommendation ?? ctx.recommendedSteps(finding).join(" ")),
    chips: ctx.compact([finding.host_key, finding.service_key, ctx.confidenceLabel(finding.confidence)]),
    evidence
  });
}
function renderAssetFocus(ctx, asset) {
  const related = ctx.getRelatedFindingsForNode(asset.asset_id);
  return renderDetailFocusCard(ctx, {
    tone: related[0] ? ctx.levelOf(related[0].severity) : ctx.levelOf(asset.confidence),
    eyebrow: ctx.assetTypeLabel(asset.asset_type),
    title: asset.name ?? asset.asset_id,
    summary: ctx.compact([asset.ip, asset.vendor, asset.model, asset.location, asset.status ? `stav ${asset.status}` : ""]).join(" \xB7 ") || "Za\u0159\xEDzen\xED je v invent\xE1\u0159i bez dopl\u0148kov\xFDch \xFAdaj\u016F.",
    recommendation: related[0] ? `Nav\xE1zan\xE1 rizika: ${related.slice(0, 3).map((item) => ctx.displayFindingTitle(item)).join(" \xB7 ")}` : "Na tomhle za\u0159\xEDzen\xED te\u010F nen\xED nav\xE1zan\xFD konkr\xE9tn\xED n\xE1lez. Vyu\u017Eij p\u0159ehled vazeb a roli za\u0159\xEDzen\xED v s\xEDti.",
    chips: ctx.compact([asset.source, asset.confidence, `${related.length} rizik`]),
    evidence: (asset.observations ?? []).slice(0, 4)
  });
}
function renderLaneFocus(ctx, lane) {
  return renderDetailFocusCard(ctx, {
    tone: lane.status === "ok" ? "low" : lane.status === "partial" ? "medium" : "high",
    eyebrow: ctx.localizeUiText(lane.lane_type ?? "sb\u011Br"),
    title: ctx.localizeUiText(lane.title ?? "Sb\u011Bra\u010D"),
    summary: ctx.compact([ctx.localizeUiText(lane.summary ?? ""), lane.source ? `zdroj ${lane.source}` : "", lane.status ? `stav ${lane.status}` : ""]).join(" \xB7 ") || "Sb\u011Brn\xFD modul bez dopl\u0148uj\xEDc\xEDho koment\xE1\u0159e.",
    recommendation: ctx.localizeUiText(lane.recommendation ?? "Ov\u011B\u0159 nav\xE1z\xE1n\xED vstupn\xEDho zdroje, dostupnost dat a konzistenci \u010Dasov\xE9ho okna."),
    chips: ctx.compact([lane.source, lane.status, lane.mode]),
    evidence: (lane.details ?? lane.observations ?? []).slice(0, 4)
  });
}
function renderActionFocus(ctx, action) {
  return renderDetailFocusCard(ctx, {
    tone: ctx.levelOf(action.priority),
    eyebrow: "dal\u0161\xED krok",
    title: ctx.localizeUiText(action.title ?? "Doporu\u010Den\xFD krok"),
    summary: ctx.localizeUiText(action.rationale ?? "Krok bez dopl\u0148uj\xEDc\xEDho zd\u016Fvodn\u011Bn\xED."),
    recommendation: ctx.compact([ctx.localizeUiText(action.next_step ?? ""), (action.recommended_tools ?? []).length ? `n\xE1stroje ${(action.recommended_tools ?? []).join(", ")}` : ""]).join(" \xB7 ") || "Prove\u010F krok a znovu porovnej v\xFDsledek se zbytkem b\u011Bhu.",
    chips: ctx.compact([action.priority, action.target_service_key, action.target_asset_id]),
    evidence: (action.evidence ?? []).slice(0, 4)
  });
}
function renderDiffFocus(ctx, row) {
  return renderDetailFocusCard(ctx, {
    tone: row.tone,
    eyebrow: "zm\u011Bna",
    title: row.title,
    summary: row.sub,
    recommendation: "Pou\u017Eij zm\u011Bnu jako vstup pro ov\u011B\u0159en\xED, jestli jde o o\u010Dek\xE1van\xFD posun nebo o nov\xFD probl\xE9m v s\xEDti.",
    chips: [row.sub],
    evidence: []
  });
}
function renderDetailFocusCard(ctx, input) {
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
function findingCard(ctx, finding, index, expanded) {
  const id = ctx.findingKey(finding, index);
  const title = ctx.displayFindingTitle(finding);
  return `<button type="button" class="detail-card ${expanded ? "is-active" : "is-collapsed"} ${ctx.severity(finding.severity)}" data-select-finding="${ctx.escapeAttr(id)}" title="${ctx.escapeAttr(title)}"><strong>${ctx.escapeHtml(title)}</strong></button>`;
}
function assetCard(ctx, asset, expanded) {
  const title = String(asset.name ?? asset.asset_id);
  return `<button type="button" class="detail-card ${expanded ? "is-active" : "is-collapsed"}" data-select-asset="${ctx.escapeAttr(asset.asset_id)}" title="${ctx.escapeAttr(title)}"><strong>${ctx.escapeHtml(title)}</strong></button>`;
}
function laneCard(ctx, lane, expanded) {
  const tone = lane.status === "ok" ? "low" : lane.status === "partial" ? "medium" : "high";
  const title = ctx.localizeUiText(lane.title ?? "Senzor");
  return `<div class="detail-card ${ctx.severity(tone)} ${expanded ? "is-active" : "is-collapsed"}" title="${ctx.escapeAttr(title)}"><strong>${ctx.escapeHtml(title)}</strong></div>`;
}
function triageCard(ctx, action, index, expanded) {
  const id = ctx.actionKey(action, index);
  const title = ctx.localizeUiText(action.title ?? "Doporu\u010Den\xFD krok");
  return `<button type="button" class="detail-card ${expanded ? "is-active" : "is-collapsed"} ${ctx.severity(action.priority)}" data-select-action="${ctx.escapeAttr(id)}" title="${ctx.escapeAttr(title)}"><strong>${ctx.escapeHtml(title)}</strong></button>`;
}

// ui-src/render/compact.ts
function renderCompactHeader(ctx) {
  const summary = ctx.state.report?.summary ?? {};
  return `${renderBrandCompact(ctx)}<div class="compact-metrics">${miniMetric(ctx, "network", summary.hosts_total ?? 0, "Host\xE9")}${miniMetric(ctx, "shield-alert", summary.findings_total ?? 0, "Rizika")}${miniMetric(ctx, "wifi", summary.network_assets_total ?? 0, "Stanice")}${miniMetric(ctx, "waves", summary.monitoring_lanes_total ?? 0, "Sb\u011Br")}</div>${renderControlDockCompact(ctx)}`;
}
function renderCompactGrid(ctx) {
  const summary = ctx.state.report?.summary ?? {};
  return `${compactFocusCard(ctx, "topology", "S\xED\u0165", summary.topology_edges_total ?? 0, "network")}${compactFocusCard(ctx, "audit", "Audit", summary.findings_total ?? 0, "shield-alert")}${compactInfoCard(ctx, "Host\xE9", summary.hosts_total ?? 0, "network")}${compactInfoCard(ctx, "Kroky", summary.triage_actions_total ?? 0, "sparkles")}`;
}
function renderCompactGuide(ctx) {
  const guide = ctx.buildGuide();
  return `
    <div class="speech-card ${ctx.severity(guide.tone)}">
      <div class="speech-head"><span class="speech-mark"><i data-lucide="bot" class="h-4 w-4"></i></span><span class="speech-eyebrow">${ctx.escapeHtml(guide.eyebrow)}</span></div>
      <strong class="speech-title" data-check-wrap="true">${ctx.escapeHtml(guide.title)}</strong>
      <p class="speech-copy">${ctx.escapeHtml(guide.summary)}</p>
    </div>
  `;
}
function renderBrandCompact(ctx) {
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
function miniMetric(ctx, icon, value, label) {
  return `<div class="mini-metric"><span class="metric-icon"><i data-lucide="${icon}" class="h-4 w-4"></i></span><strong>${value}</strong><span>${ctx.escapeHtml(label)}</span></div>`;
}
function renderControlDockCompact(ctx) {
  return `
    <div class="control-row">
      <button type="button" class="icon-button" data-focus="topology" title="Zv\u011Bt\u0161it topologii"><i data-lucide="network" class="h-4 w-4"></i></button>
      <button type="button" class="icon-button" data-focus="audit" title="Zv\u011Bt\u0161it auditn\xED panel"><i data-lucide="shield-alert" class="h-4 w-4"></i></button>
      <button type="button" class="icon-button ${ctx.state.liveMode ? "is-live" : ""}" data-live-toggle title="Obnovit b\u011Bh"><i data-lucide="activity" class="h-4 w-4"></i></button>
      <button type="button" class="icon-button" data-refresh title="Na\u010D\xEDst znovu"><i data-lucide="refresh-cw" class="h-4 w-4"></i></button>
    </div>
  `;
}
function compactFocusCard(ctx, focus, label, value, icon) {
  return `<button type="button" class="panel-shell compact-card focus-card" data-focus="${focus}"><div class="panel-frame compact-card-frame"><span class="metric-icon"><i data-lucide="${icon}" class="h-4 w-4"></i></span><strong>${value}</strong><span>${ctx.escapeHtml(label)}</span></div></button>`;
}
function compactInfoCard(ctx, label, value, icon) {
  return `<div class="panel-shell compact-card"><div class="panel-frame compact-card-frame"><span class="metric-icon"><i data-lucide="${icon}" class="h-4 w-4"></i></span><strong>${value}</strong><span>${ctx.escapeHtml(label)}</span></div></div>`;
}

// ui-src/main.ts
var rootNode = document.querySelector("#app");
if (!rootNode) throw new Error("UI root #app nebyl nalezen.");
var root = rootNode;
var DETAIL_META = {
  findings: { title: "Rizika", icon: "shield-alert", accent: "#fb7185" },
  assets: { title: "Stanice", icon: "wifi", accent: "#38bdf8" },
  lanes: { title: "Sb\u011Br", icon: "waves", accent: "#22c55e" },
  triage: { title: "Kroky", icon: "sparkles", accent: "#fbbf24" },
  diff: { title: "Zm\u011Bny", icon: "git-compare", accent: "#38bdf8" }
};
var state = {
  runs: [],
  report: null,
  verification: null,
  automationLatest: null,
  automationStatus: null,
  aiStatus: null,
  readiness: null,
  authRequired: false,
  authDismissed: false,
  apiTokenPresent: false,
  pentestMode: readPentestMode(),
  activeRunId: null,
  detailPanel: "findings",
  detailScope: "context",
  detailView: "detail",
  centerMode: "map",
  loading: true,
  error: null,
  liveMode: true,
  lastUpdatedAt: null,
  graphNodes: [],
  graphEdges: [],
  selectedGraphNodeId: null,
  selectedGraphEdgeId: null,
  selectedFindingId: null,
  selectedAssetId: null,
  selectedActionId: null,
  rightMode: "detail",
  chatMessages: [],
  chatDraft: "",
  chatBusy: false,
  chatInputFocused: false,
  zoom: 1,
  panX: 0,
  panY: 0,
  shellMode: null,
  refreshHandle: null,
  renderHandle: null,
  progressAnimationHandle: null,
  visibleProgress: 0,
  scrollMemory: {
    hostRail: 0,
    runRail: 0,
    detail: 0,
    chat: 0
  },
  detailScrollLock: null,
  chatScrollLock: false,
  layout: null
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
  }, 4e3);
}
function isChatComposing() {
  const active = document.activeElement;
  return state.rightMode === "chat" && (state.chatBusy || state.chatInputFocused || active?.id === "chatInput" || state.chatDraft.trim().length > 0);
}
function setupKeyboardControls() {
  window.addEventListener("keydown", (event) => {
    const target = event.target;
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
      window.requestAnimationFrame(() => root.querySelector("#chatInput")?.focus());
      handled();
      return;
    }
    if (key === "+" || key === "=") {
      state.zoom = clamp4(state.zoom + 0.14, 0.7, 3.2);
      updateGraphZoom();
      handled();
      return;
    }
    if (key === "-" || key === "_") {
      state.zoom = clamp4(state.zoom - 0.14, 0.7, 3.2);
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
    const panels = {
      "1": "findings",
      "2": "assets",
      "3": "lanes",
      "4": "triage",
      "5": "diff"
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
    const meta = await fetchJson("/api/meta");
    state.authRequired = Boolean(meta.auth_required);
    state.authDismissed = isTokenPromptDismissed();
    state.apiTokenPresent = Boolean(getStoredToken());
    const previousRuns = state.runs;
    const followLatest = state.liveMode && (!previousActiveRunId || previousActiveRunId === previousRuns[0]?.run_id);
    const [runs, verification, automationLatest, automationStatus, aiStatus, readiness] = await Promise.all([
      fetchJson("/api/runs"),
      fetchJson("/api/verification/latest").catch(() => null),
      fetchJson("/api/automation/latest").catch(() => null),
      fetchJson("/api/automation/status").catch(() => null),
      fetchJson("/api/ai/status").catch(() => null),
      fetchJson("/api/readiness").catch(() => null)
    ]);
    state.runs = runs;
    state.verification = verification;
    state.automationLatest = automationLatest;
    state.automationStatus = automationStatus;
    state.aiStatus = aiStatus;
    state.readiness = readiness;
    const preferredLiveRunId = automationStatus?.latest_run_id && runs.some((run) => run.run_id === automationStatus.latest_run_id) ? automationStatus.latest_run_id : runs[0]?.run_id ?? null;
    state.activeRunId = followLatest ? preferredLiveRunId : (state.activeRunId && runs.some((run) => run.run_id === state.activeRunId) ? state.activeRunId : null) ?? runs[0]?.run_id ?? null;
    state.report = state.activeRunId ? await fetchJson(`/api/runs/${encodeURIComponent(state.activeRunId)}`) : null;
    fullRenderNeeded = fullRenderNeeded || previousActiveRunId !== state.activeRunId;
    state.lastUpdatedAt = (/* @__PURE__ */ new Date()).toISOString();
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
async function switchRun(runId) {
  state.loading = true;
  renderApp();
  try {
    state.report = await fetchJson(`/api/runs/${encodeURIComponent(runId)}`);
    state.activeRunId = runId;
    state.lastUpdatedAt = (/* @__PURE__ */ new Date()).toISOString();
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
async function fetchJson(url) {
  const response = await fetch(url, { headers: buildAuthHeaders() });
  if (response.status === 401 && requestToken()) {
    const retry = await fetch(url, { headers: buildAuthHeaders() });
    if (!retry.ok) throw new Error(`Na\u010Dten\xED ${url} selhalo (${retry.status}).`);
    return await retry.json();
  }
  if (!response.ok) throw new Error(`Na\u010Dten\xED ${url} selhalo (${response.status}).`);
  return await response.json();
}
function buildAuthHeaders() {
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
    fill("leftRail", renderLeftRail2());
    fill("centerStage", renderCenterStage2());
    fill("rightStage", renderRightStage2());
  } else if (mode === "compact") {
    fill("compactHeader", renderCompactHeader2());
    fill("compactGrid", renderCompactGrid2());
    fill("compactGuide", renderCompactGuide2());
  } else if (mode === "compact-topology") {
    fill("compactFocus", renderCenterStage2());
  } else if (mode === "compact-audit") {
    fill("compactFocus", renderRightStage2());
  }
  bindUi();
  restoreScrollMemory();
  createIcons({ icons: { Activity, AlertTriangle: TriangleAlert, Bot, ChevronRight, CircleDashed, Download, Gauge, GitCompare, Layers, Maximize2, Minimize2, Network, Play, Radar, RefreshCw, RotateCcw, ScanLine, Shield, ShieldAlert, Sparkles, Waves, Wifi, ZoomIn, ZoomOut } });
  syncProgressBaseline();
}
function scheduleRender() {
  if (state.renderHandle != null) window.cancelAnimationFrame(state.renderHandle);
  state.renderHandle = window.requestAnimationFrame(() => {
    state.renderHandle = null;
    renderApp();
  });
}
function syncWorkspaceClasses(mode) {
  const workspace = root.querySelector(".workspace-grid");
  if (!workspace) return;
  workspace.classList.toggle("is-focus-topology", mode === "desktop-topology");
  workspace.classList.toggle("is-focus-audit", mode === "desktop-audit");
  workspace.classList.toggle("is-reader-mode", state.centerMode === "reader");
}
function captureScrollMemory() {
  const hostRail = root.querySelector("[data-scroll-key='hostRail']");
  const runRail = root.querySelector("[data-scroll-key='runRail']");
  const detail = root.querySelector("[data-scroll-key='detail']");
  const chat = root.querySelector("[data-scroll-key='chat']");
  if (hostRail) state.scrollMemory.hostRail = hostRail.scrollTop;
  if (runRail) state.scrollMemory.runRail = runRail.scrollTop;
  if (detail && state.detailScrollLock == null) state.scrollMemory.detail = detail.scrollTop;
  if (chat && !state.chatScrollLock) state.scrollMemory.chat = chat.scrollTop;
}
function restoreScrollMemory() {
  const apply = () => {
    const hostRail = root.querySelector("[data-scroll-key='hostRail']");
    const runRail = root.querySelector("[data-scroll-key='runRail']");
    const detail = root.querySelector("[data-scroll-key='detail']");
    const chat = root.querySelector("[data-scroll-key='chat']");
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
function getLayoutMode() {
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
function ensureShell(mode) {
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
    <div class="center-mode-switch" aria-label="Hlavn\xED re\u017Eim">
      <button type="button" class="center-mode-button ${state.centerMode === "map" ? "is-active" : ""}" data-center-mode="map" title="Mapa s\xEDt\u011B"><i data-lucide="network" class="h-4 w-4"></i><span>Mapa</span></button>
      <button type="button" class="center-mode-button ${state.centerMode === "reader" ? "is-active" : ""}" data-center-mode="reader" title="Textov\xE9 \u010Dten\xED"><i data-lucide="scan-line" class="h-4 w-4"></i><span>\u010Cten\xED</span></button>
    </div>
  `;
}
function fill(id, html) {
  const element = root.querySelector(`#${id}`);
  if (element && element.innerHTML !== html) element.innerHTML = html;
}
function patchRealtimeUi() {
  state.layout = applyResponsiveLayoutVars(document.documentElement, window.innerWidth, window.innerHeight);
  syncWorkspaceClasses(getLayoutMode());
  const running = Boolean(state.automationStatus?.process_running);
  const card = root.querySelector("[data-progress-card]");
  if (card) card.classList.toggle("is-running", running);
  const phase = state.automationStatus?.current_phase_label ?? state.automationStatus?.current_phase ?? (running ? "B\u011Bh" : "P\u0159ipraveno");
  const phaseEl = root.querySelector("[data-progress-phase]");
  if (phaseEl) phaseEl.textContent = phase;
  animateProgressTo(currentProgress());
  root.querySelectorAll(".live-dot").forEach((dot) => dot.classList.toggle("is-live", state.liveMode));
}
function syncProgressBaseline() {
  const progress = currentProgress();
  state.visibleProgress = progress;
  const bar = root.querySelector("[data-progress-bar]");
  const value = root.querySelector("[data-progress-value]");
  if (bar) {
    bar.dataset.progress = String(progress);
    bar.style.width = `${progress}%`;
  }
  if (value) value.textContent = `${progress}%`;
}
function currentProgress() {
  const latestRatio = Number(state.automationLatest?.summary?.tooling_coverage_ratio ?? 0) * 100;
  return Math.round(clamp4(state.automationStatus?.progress_pct ?? latestRatio, 0, 100));
}
function animateProgressTo(target) {
  const bar = root.querySelector("[data-progress-bar]");
  const value = root.querySelector("[data-progress-value]");
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
  const ease = (t) => 1 - Math.pow(1 - t, 3);
  const tick = (now) => {
    const t = clamp4((now - started) / duration, 0, 1);
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
function renderLeftRail2() {
  return renderLeftRail(createViewContext());
}
function renderCenterStage2() {
  const report = state.report;
  if (!report) return emptyState("\u010Cek\xE1m na data.");
  const mode = getLayoutMode();
  const expanded = mode === "desktop-topology" || mode === "compact-topology";
  const dims = computeGraphSceneSize(state.layout ?? applyResponsiveLayoutVars(document.documentElement, window.innerWidth, window.innerHeight), expanded);
  const graph = buildGraph(report, dims.width, dims.height);
  state.graphNodes = graph.nodes;
  state.graphEdges = graph.edges;
  if (!state.selectedGraphNodeId && graph.nodes.length) {
    state.selectedGraphNodeId = [...graph.nodes].filter((node) => node.kind !== "hub" && node.kind !== "external").sort((left, right) => (right.riskScore ?? 0) - (left.riskScore ?? 0))[0]?.id ?? graph.nodes.find((node) => node.kind === "core")?.id ?? graph.nodes[0].id;
  }
  return renderCenterStage(createViewContext());
}
function renderRightStage2() {
  ensureChatSeed();
  return renderRightStage(createViewContext());
}
function renderCompactHeader2() {
  return renderCompactHeader(createViewContext());
}
function renderCompactGrid2() {
  return renderCompactGrid(createViewContext());
}
function renderCompactGuide2() {
  return renderCompactGuide(createViewContext());
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
    riskColorForScore
  };
}
function cssLength(value) {
  return `${(value / 16).toFixed(4).replace(/\.?0+$/, "")}rem`;
}
function ensureChatSeed() {
  if (state.chatMessages.length) return;
  const model = state.aiStatus?.selected_model ? ` Model: ${state.aiStatus.selected_model}.` : "";
  state.chatMessages = [{ role: "assistant", text: `Skoky je p\u0159ipraven\xFD nad aktu\xE1ln\xEDm b\u011Bhem. Vyber n\xE1lez nebo za\u0159\xEDzen\xED a ptej se na postup opravy, ov\u011B\u0159en\xED nebo dopad.${model}` }];
}
async function submitChatPrompt(prompt) {
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
      const current2 = state.chatMessages[streamingIndex];
      if (!current2) return;
      current2.text += chunk;
      current2.streaming = true;
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
function patchChatMessage(index) {
  const message = state.chatMessages[index];
  const textNode = root.querySelector(`[data-chat-index="${index}"] [data-chat-text]`);
  if (!message || !textNode) {
    scheduleRender();
    return;
  }
  textNode.textContent = message.text || (message.streaming ? "P\xED\u0161u odpov\u011B\u010F\u2026" : "");
}
function answerChatPrompt(prompt) {
  const normalized = prompt.toLowerCase();
  if (normalized.includes("prvn\xED") || normalized.includes("prior")) {
    const finding = getSelectedFinding() ?? getVisibleFindings()[0] ?? (state.report?.findings ?? [])[0];
    return finding ? `${displayFindingTitle(finding)}. ${humanizeFinding(finding)} ${recommendedSteps(finding)[0]}` : "Te\u010F nem\xE1m \u017E\xE1dn\xFD n\xE1lez, kter\xFD by \u0161el up\u0159ednostnit.";
  }
  if (normalized.includes("riziko")) {
    const finding = getSelectedFinding() ?? getVisibleFindings()[0] ?? (state.report?.findings ?? [])[0];
    return finding ? `${displayFindingTitle(finding)}. ${humanizeFinding(finding)} Doporu\u010Den\xFD za\u010D\xE1tek: ${recommendedSteps(finding)[0]}` : "Vyber riziko v z\xE1lo\u017Ece Rizika a vysv\u011Btl\xEDm ho.";
  }
  if (normalized.includes("za\u0159\xEDzen\xED") || normalized.includes("stanic")) {
    const asset = getSelectedAsset();
    const node = getSelectedNode();
    const related = node ? getRelatedFindingsForNode(node.id) : [];
    if (asset) return `${asset.name ?? asset.asset_id} je vid\u011Bt p\u0159es ${asset.source ?? "invent\xE1\u0159"}. ${[asset.ip, asset.vendor, asset.model].filter(Boolean).join(" \xB7 ") || "Bez p\u0159esn\u011Bj\u0161\xED identifikace."}${related.length ? ` Nav\xE1zan\xE1 rizika: ${related.slice(0, 2).map((item) => displayFindingTitle(item)).join(" \xB7 ")}.` : ""}`;
    if (node) return `${node.title} je ${node.layerLabel}. Vazeb: ${node.connected.length}. ${node.details[0] ?? ""}${related.length ? ` Nejd\u016Fle\u017Eit\u011Bj\u0161\xED nav\xE1zan\xE9 riziko: ${displayFindingTitle(related[0])}.` : ""}`;
    return "Vyber za\u0159\xEDzen\xED vlevo nebo v topologii.";
  }
  if (normalized.includes("krok") || normalized.includes("ud\u011Blat")) {
    const action = getSelectedAction() ?? getTriage(state.report)[0];
    if (action) return `${localizeUiText(action.title ?? "Doporu\u010Den\xFD krok")}. ${localizeUiText(action.rationale ?? "Bez doprovodn\xE9ho d\u016Fvodu.")}`;
    const guide2 = buildGuide();
    return guide2.actions.join(" ");
  }
  const guide = buildGuide();
  return `${guide.summary} ${guide.actions[0] ?? ""}`;
}
async function askAssistant(prompt) {
  if (!state.activeRunId) return { answer: answerChatPrompt(prompt), sources: [] };
  const response = await fetch(`/api/runs/${encodeURIComponent(state.activeRunId)}/assistant`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...buildAuthHeaders()
    },
    body: JSON.stringify({
      prompt,
      detail_panel: state.detailPanel,
      selected_node_id: state.selectedGraphNodeId,
      selected_finding_id: state.selectedFindingId,
      selected_asset_id: state.selectedAssetId,
      selected_action_id: state.selectedActionId,
      history: state.chatMessages.slice(-6).map((item) => ({ role: item.role, text: item.text }))
    })
  });
  if (!response.ok) throw new Error(`Helpdesk neodpov\u011Bd\u011Bl (${response.status}).`);
  const payload = await response.json();
  const sourceLabels = (payload.sources ?? []).map((item) => item.label || item.url || "").filter(Boolean);
  if (payload.mode) sourceLabels.unshift(`engine:${payload.mode}`);
  return {
    answer: payload.answer?.trim() || answerChatPrompt(prompt),
    sources: sourceLabels
  };
}
async function askAssistantStream(prompt, onChunk) {
  if (!state.activeRunId) return { answer: answerChatPrompt(prompt), sources: [] };
  const requestBody = {
    prompt,
    detail_panel: state.detailPanel,
    selected_node_id: state.selectedGraphNodeId,
    selected_finding_id: state.selectedFindingId,
    selected_asset_id: state.selectedAssetId,
    selected_action_id: state.selectedActionId,
    history: state.chatMessages.filter((item) => !item.streaming && item.text.trim()).slice(-8).map((item) => ({ role: item.role, text: item.text }))
  };
  const response = await fetch(`/api/runs/${encodeURIComponent(state.activeRunId)}/assistant/stream`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...buildAuthHeaders()
    },
    body: JSON.stringify(requestBody)
  });
  if (!response.ok || !response.body) {
    return askAssistant(prompt);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let answer = "";
  const sources = [];
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
      const event = JSON.parse(raw);
      if (event.type === "chunk" && event.text) {
        answer += event.text;
        onChunk(event.text);
      }
      if (event.type === "done") {
        if (event.mode) sources.unshift(`engine:${event.mode}`);
        sources.push(...event.sources ?? []);
      }
      if (event.type === "error") throw new Error(event.error || "Helpdesk stream selhal.");
    }
  }
  if (!answer.trim()) return askAssistant(prompt);
  return { answer: answer.trim(), sources };
}
function scrollChatToBottom() {
  const apply = () => {
    const log = root.querySelector("#chatLog");
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
function buildGuide() {
  const report = state.report;
  if (!report) return { eyebrow: "bez dat", title: "\u010Cek\xE1m na b\u011Bh", summary: "Jakmile bude dostupn\xFD report, p\u0159elo\u017E\xEDm ho do lidsk\xE9 \u0159e\u010Di.", actions: ["Spus\u0165 nebo na\u010Dti b\u011Bh."], tone: "neutral" };
  if (state.detailPanel === "findings") {
    const finding = getSelectedFinding() ?? (report.findings ?? [])[0];
    if (finding) return { eyebrow: levelOf(finding.severity) === "high" ? "priorita" : "kontrola", title: displayFindingTitle(finding), summary: humanizeFinding(finding), actions: recommendedSteps(finding), tone: levelOf(finding.severity) };
  }
  if (state.detailPanel === "triage") {
    const action = getSelectedAction() ?? getTriage(report)[0];
    if (action) return { eyebrow: "dal\u0161\xED krok", title: action.title ?? "Doporu\u010Den\xED", summary: action.rationale ?? "Tenhle krok m\xE1 rychle potvrdit, jestli je pot\u0159eba j\xEDt hloub\u011Bji.", actions: (action.recommended_tools ?? []).slice(0, 3).map((tool) => `Pou\u017Eij ${tool}.`), tone: levelOf(action.priority) };
  }
  if (state.detailPanel === "assets") {
    const asset = getSelectedAsset();
    const node = getSelectedNode();
    if (asset || node) return { eyebrow: "orientace", title: asset?.name ?? node?.title ?? "Za\u0159\xEDzen\xED", summary: `Tohle za\u0159\xEDzen\xED je v s\xEDti vid\u011Bt p\u0159es ${asset?.source ?? node?.subtitle ?? "invent\xE1\u0159"}. Nejd\u0159\xEDv ov\u011B\u0159 roli za\u0159\xEDzen\xED a jeho vazby.`, actions: ["Ov\u011B\u0159, \u017Ee role za\u0159\xEDzen\xED odpov\xEDd\xE1 realit\u011B.", "Porovnej napojen\xE9 objekty s o\u010Dek\xE1van\xFDm m\xEDstem v s\xEDti.", "Kdy\u017E je to spr\xE1va nebo s\xED\u0165ov\xFD prvek, ov\u011B\u0159 p\u0159\xEDstupov\xE1 pravidla."], tone: levelOf(asset?.confidence ?? node?.sev ?? "neutral") };
  }
  const risk = computeRisk(report);
  return { eyebrow: "souhrn", title: "Co z b\u011Bhu plyne", summary: risk.className === "severity-high" ? "Je tu alespo\u0148 jeden bod, kter\xFD m\xE1 smysl \u0159e\u0161it hned. Zbytek se\u0159a\u010F podle priority za n\xEDm." : "S\xED\u0165 nep\u016Fsob\xED jako akutn\xED hav\xE1rie, ale jsou tu m\xEDsta, kter\xE1 stoj\xED za ov\u011B\u0159en\xED a zpevn\u011Bn\xED.", actions: ["Za\u010Dni nejvy\u0161\u0161\xED prioritou vpravo.", "Pak si v topologii ov\u011B\u0159, \u017Ee za\u0159\xEDzen\xED sed\xED na o\u010Dek\xE1van\xE9 m\xEDsto.", "Nakonec projdi doporu\u010Den\xE9 kroky a potvr\u010F, co je skute\u010Dn\u011B pot\u0159eba \u0159e\u0161it."], tone: risk.className.replace("severity-", "") };
}
function humanizeFinding(finding) {
  const text = `${finding.title ?? ""} ${finding.rationale ?? ""}`.toLowerCase();
  if (finding.finding_type === "plaintext_management_protocol") {
    const service = String(finding.service_key ?? "");
    if (service.includes("/tcp/23") || text.includes("telnet")) return "Telnet p\u0159en\xE1\u0161\xED p\u0159ihla\u0161ovac\xED \xFAdaje i spr\xE1vcovsk\xE9 p\u0159\xEDkazy bez \u0161ifrov\xE1n\xED. V b\u011B\u017En\xE9 s\xEDti je citliv\xFD na odposlech a p\u0159evzet\xED relace.";
    if (service.includes("/tcp/21") || text.includes("ftp")) return "FTP pou\u017E\xEDv\xE1 ne\u0161ifrovan\xFD \u0159\xEDdic\xED kan\xE1l a \u010Dasto p\u0159en\xE1\u0161\xED p\u0159ihla\u0161ovac\xED \xFAdaje bez ochrany. Je pot\u0159eba ov\u011B\u0159it, jestli p\u0159es n\u011Bj nete\u010Dou citliv\xE1 data.";
    return "Slu\u017Eba pou\u017E\xEDv\xE1 ne\u0161ifrovan\xFD p\u0159\xEDstupov\xFD protokol. Bez dal\u0161\xED ochrany m\u016F\u017Ee prozrazovat citliv\xE1 data nebo \u0159\xEDdic\xED informace.";
  }
  if (text.includes("openssh") && text.includes("outdated")) return "Na hostu je vid\u011Bt zastaral\xE1 verze OpenSSH. D\xE1v\xE1 smysl ov\u011B\u0159it verzi a rozhodnout, jestli je pot\u0159eba aktualizace.";
  if (text.includes("contains vulnerabilities") || text.includes("vulnerabilities with high priority")) return "Slu\u017Eba odpov\xEDd\xE1 verzi, kter\xE1 je nav\xE1zan\xE1 na zn\xE1m\xE9 zranitelnosti. To je sign\xE1l k prioritn\xEDmu ov\u011B\u0159en\xED a p\u0159\xEDpadn\xE9mu patchi.";
  if (text.includes("swagger")) return "Na slu\u017Eb\u011B je vid\u011Bt v\xFDvoj\xE1\u0159sk\xE9 rozhran\xED. To b\xFDv\xE1 vhodn\xE9 dr\u017Eet jen intern\u011B.";
  if (text.includes("metrics")) return "Slu\u017Eba prozrazuje intern\xED technick\xE9 informace. Samy o sob\u011B nemus\xED b\xFDt \u0161kodliv\xE9, ale d\xE1vaj\xED zbyte\u010Dn\xFD kontext nav\xEDc.";
  if (text.includes("basic auth") || text.includes("basic-auth")) return "P\u0159ihl\xE1\u0161en\xED spol\xE9h\xE1 na slab\u0161\xED p\u0159enosovou ochranu. To sni\u017Euje d\u016Fv\u011Bru v bezpe\u010Dnost p\u0159\xEDstupu.";
  if (text.includes("directory")) return "Server ukazuje obsah slo\u017Eky p\u0159\xEDmo v prohl\xED\u017Ee\u010Di. To m\u016F\u017Ee odhalit soubory nebo strukturu slu\u017Eby.";
  if (text.includes("exploited") || text.includes("kev")) return "Tahle slabina nen\xED jen teoretick\xE1. Existuje sign\xE1l, \u017Ee je re\xE1ln\u011B zneu\u017E\xEDvan\xE1.";
  if (text.includes("management") || text.includes("admin")) return "Je vid\u011Bt spr\xE1vcovsk\xE9 rozhran\xED. To by m\u011Blo b\xFDt dostupn\xE9 co nejm\xE9n\u011B lidem i s\xEDt\xEDm.";
  if (text.includes("gap") || text.includes("identification")) return "Slu\u017Eba odpov\xEDd\xE1, ale jej\xED identita nen\xED dost p\u0159esn\xE1. Nen\xED to d\u016Fkaz pr\u016F\u0161vihu, sp\xED\u0161 mezera v jistot\u011B.";
  if (finding.rationale) return localizeUiText(finding.rationale);
  return "Syst\xE9m na\u0161el bod, kter\xFD stoj\xED za ov\u011B\u0159en\xED. Ne\u0159\xEDk\xE1 automaticky, \u017Ee jde o incident, ale d\xE1v\xE1 d\u016Fvod ke kontrole.";
}
function displayFindingTitle(finding) {
  const title = String(finding.title ?? "Riziko");
  const text = `${title} ${finding.rationale ?? ""}`.toLowerCase();
  const service = String(finding.service_key ?? "").replace("/tcp/", ":").replace("/udp/", ":");
  const target = service || String(finding.host_key ?? "");
  if (finding.finding_type === "plaintext_management_protocol") {
    if (service.endsWith(":23") || text.includes("telnet")) return target ? `Ne\u0161ifrovan\xFD Telnet na ${target}` : "Ne\u0161ifrovan\xFD Telnet";
    if (service.endsWith(":21") || text.includes("ftp")) return target ? `Ne\u0161ifrovan\xE9 FTP na ${target}` : "Ne\u0161ifrovan\xE9 FTP";
    return target ? `Ne\u0161ifrovan\xFD spr\xE1vcovsk\xFD protokol na ${target}` : "Ne\u0161ifrovan\xFD spr\xE1vcovsk\xFD protokol";
  }
  if (finding.finding_type === "high_risk_cve_exposure") return target ? `CVE riziko na ${target}` : "Slu\u017Eba s nav\xE1zan\xFDmi CVE";
  if (finding.finding_type === "known_exploited_vulnerability") return target ? `CISA KEV na ${target}` : "Zneu\u017E\xEDvan\xE1 zn\xE1m\xE1 zranitelnost";
  if (finding.finding_type === "probable_exploitation_interest") return target ? `Vy\u0161\u0161\xED EPSS na ${target}` : "Zv\xFD\u0161en\xFD z\xE1jem \xFAto\u010Dn\xEDk\u016F";
  if (finding.finding_type === "management_surface_exposure") return target ? `Spr\xE1vcovsk\xE1 plocha na ${target}` : "Viditeln\xE1 spr\xE1vcovsk\xE1 plocha";
  if (finding.finding_type === "identification_gap") return target ? `Ne\xFApln\xE1 identita ${target}` : "Ne\xFApln\xE1 identita slu\u017Eby";
  if (finding.finding_type === "external_flow_observed") return title.replace("Live vrstva", "\u017Div\xE1 vrstva");
  if (text.includes("openssh") && text.includes("outdated")) return target ? `Zastaral\xFD OpenSSH na ${target}` : "Zastaral\xE1 verze OpenSSH";
  if (text.includes("basic auth") || text.includes("basic-auth")) return target ? `Slab\xE9 p\u0159ihl\xE1\u0161en\xED na ${target}` : "Slab\u011B chr\xE1n\u011Bn\xE9 p\u0159ihl\xE1\u0161en\xED";
  if (text.includes("swagger")) return target ? `Swagger na ${target}` : "Vystaven\xE9 Swagger rozhran\xED";
  if (text.includes("metrics")) return target ? `Metriky na ${target}` : "Ve\u0159ejn\u011B dostupn\xE9 technick\xE9 metriky";
  if (text.includes("directory")) return target ? `V\xFDpis adres\xE1\u0159e na ${target}` : "Zapnut\xFD v\xFDpis adres\xE1\u0159e";
  if (text.includes("management") || text.includes("admin")) return target ? `Spr\xE1va na ${target}` : "Viditeln\xE9 spr\xE1vcovsk\xE9 rozhran\xED";
  if (text.includes("kev") || text.includes("known exploited")) return target ? `CISA KEV na ${target}` : "Zneu\u017E\xEDvan\xE1 zn\xE1m\xE1 zranitelnost";
  if (text.includes("identification") || text.includes("gap")) return target ? `Ne\xFApln\xE1 identita ${target}` : "Ne\xFApln\xE1 identita slu\u017Eby";
  if (text.includes("contains vulnerabilities") || text.includes("vulnerabilities")) return target ? `Zranitelnosti na ${target}` : "Slu\u017Eba s nav\xE1zan\xFDmi zranitelnostmi";
  return title;
}
function recommendedSteps(finding) {
  const text = `${finding.title ?? ""} ${finding.rationale ?? ""}`.toLowerCase();
  if (text.includes("swagger")) return ["Omez rozhran\xED jen na intern\xED s\xED\u0165.", "Zapni autentizaci nebo proxy p\u0159ed slu\u017Ebou.", "Ov\u011B\u0159, \u017Ee rozhran\xED nen\xED pot\u0159eba ve\u0159ejn\u011B."];
  if (text.includes("metrics")) return ["Ponech endpoint jen intern\u011B.", "Zkontroluj, co endpoint prozrazuje o slu\u017Eb\u011B.", "Dopl\u0148 p\u0159\xEDstupov\xE9 omezen\xED."];
  if (text.includes("basic auth") || text.includes("basic-auth")) return ["P\u0159esu\u0148 p\u0159\xEDstup na HTTPS.", "Zva\u017E siln\u011Bj\u0161\xED p\u0159ihl\xE1\u0161en\xED nebo reverzn\xED proxy.", "Ov\u011B\u0159, kdo m\xE1 m\xEDt k rozhran\xED p\u0159\xEDstup."];
  if (text.includes("directory")) return ["Vypni listing adres\xE1\u0159\u016F.", "Projdi ve\u0159ejn\xE9 cesty a citliv\xE9 soubory.", "Zkontroluj, \u017Ee se nepublikuje build nebo z\xE1loha."];
  if (text.includes("exploited") || text.includes("kev")) return ["Ov\u011B\u0159 verzi a dostupnost patche.", "Up\u0159ednostni to p\u0159ed b\u011B\u017Enou \xFAdr\u017Ebou.", "Sleduj, zda se k hostu nev\xE1\u017Ee dal\u0161\xED podez\u0159el\xE1 aktivita."];
  return ["Ov\u011B\u0159, \u017Ee slu\u017Eba je opravdu pot\u0159ebn\xE1.", "Z\xFA\u017E p\u0159\xEDstup jen na nutn\xE9 zdroje.", "Dopl\u0148 nebo zp\u0159esni identitu a nastaven\xED slu\u017Eby."];
}
function bindUi() {
  const holdPosition = (element) => {
    element.onpointerdown = (event) => event.preventDefault();
    element.onmousedown = (event) => event.preventDefault();
  };
  root.querySelectorAll("[data-run-id]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      const id = element.dataset.runId;
      if (id && id !== state.activeRunId) void switchRun(id);
    };
  });
  root.querySelectorAll("[data-select-node]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      const id = element.dataset.selectNode;
      if (!id) return;
      focusNodeContext(id, "assets");
      renderApp();
    };
  });
  root.querySelectorAll("[data-detail-panel]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      const panel = element.dataset.detailPanel;
      if (!panel) return;
      rememberDetailScroll();
      state.detailPanel = panel;
      if (element.dataset.detailScope === "context" || element.dataset.detailScope === "all") state.detailScope = element.dataset.detailScope;
      if (element.dataset.detailView === "detail" || element.dataset.detailView === "list") state.detailView = element.dataset.detailView;
      if (element.dataset.centerMode === "map" || element.dataset.centerMode === "reader") state.centerMode = element.dataset.centerMode;
      state.rightMode = "detail";
      renderApp();
    };
  });
  root.querySelectorAll("[data-center-mode]").forEach((element) => {
    if (element.dataset.detailPanel || element.dataset.detailScope || element.dataset.detailView) return;
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      const mode = element.dataset.centerMode;
      if (!mode) return;
      state.centerMode = mode;
      renderApp();
    };
  });
  root.querySelectorAll("[data-detail-scope]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      const scope = element.dataset.detailScope;
      if (!scope) return;
      rememberDetailScroll();
      state.detailScope = scope;
      if (element.dataset.centerMode === "map" || element.dataset.centerMode === "reader") state.centerMode = element.dataset.centerMode;
      state.rightMode = "detail";
      renderApp();
    };
  });
  root.querySelectorAll("[data-detail-view]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      const view = element.dataset.detailView;
      if (!view) return;
      rememberDetailScroll();
      state.detailView = view;
      if (element.dataset.centerMode === "map" || element.dataset.centerMode === "reader") state.centerMode = element.dataset.centerMode;
      state.rightMode = "detail";
      renderApp();
    };
  });
  root.querySelectorAll("[data-select-finding]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      const id = element.dataset.selectFinding;
      if (!id) return;
      rememberDetailScroll();
      state.selectedFindingId = id;
      state.detailPanel = "findings";
      if (element.closest(".right-stage")) state.centerMode = "reader";
      renderApp();
    };
  });
  root.querySelectorAll("[data-select-asset]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      const id = element.dataset.selectAsset;
      if (!id) return;
      rememberDetailScroll();
      state.selectedAssetId = id;
      state.detailPanel = "assets";
      if (element.closest(".right-stage")) state.centerMode = "reader";
      renderApp();
    };
  });
  root.querySelectorAll("[data-select-action]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      const id = element.dataset.selectAction;
      if (!id) return;
      rememberDetailScroll();
      state.selectedActionId = id;
      state.detailPanel = "triage";
      if (element.closest(".right-stage")) state.centerMode = "reader";
      renderApp();
    };
  });
  root.querySelectorAll("[data-refresh]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      void refreshData(false, false);
    };
  });
  root.querySelectorAll("[data-live-toggle]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      state.liveMode = !state.liveMode;
      renderApp();
    };
  });
  root.querySelectorAll("[data-pentest-toggle]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      cyclePentestMode();
      renderApp();
    };
  });
  root.querySelectorAll("[data-automation-start]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      void restartAutomation();
    };
  });
  root.querySelectorAll("[data-automation-reset]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      void resetAutomation();
    };
  });
  root.querySelectorAll("[data-token-set]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      window.localStorage.removeItem("bakulaApiTokenDismissed");
      state.authDismissed = false;
      requestToken();
      renderApp();
    };
  });
  root.querySelectorAll("[data-token-clear]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      clearStoredToken();
      renderApp();
    };
  });
  root.querySelectorAll("[data-focus]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      const requested = element.dataset.focus ?? null;
      const current = requestedFocus();
      setFocusQuery(requested && current === requested ? null : requested);
      renderApp();
    };
  });
  root.querySelectorAll("[data-focus-clear]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      setFocusQuery(null);
      renderApp();
    };
  });
  root.querySelectorAll("[data-export]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      const format = element.dataset.export;
      if (format) void exportCurrent(format);
    };
  });
  root.querySelectorAll("[data-zoom]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      const dir = element.dataset.zoom;
      if (dir === "reset") {
        state.zoom = 1;
        state.panX = 0;
        state.panY = 0;
      } else {
        state.zoom = clamp4(dir === "in" ? state.zoom + 0.14 : state.zoom - 0.14, 0.7, 3.2);
      }
      updateGraphZoom();
    };
  });
  root.querySelectorAll("[data-chat-toggle]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      state.rightMode = state.rightMode === "chat" ? "detail" : "chat";
      if (state.rightMode === "chat") state.chatScrollLock = true;
      renderApp();
    };
  });
  root.querySelectorAll("[data-chat-prompt]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      const prompt = element.dataset.chatPrompt;
      if (!prompt) return;
      void submitChatPrompt(prompt);
    };
  });
  const chatInput = root.querySelector("#chatInput");
  if (chatInput) {
    const sizeChatInput = () => {
      chatInput.style.height = "auto";
      const maxHeight = Math.round(clamp4(window.innerHeight * 0.22, 136, 228));
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
  root.querySelectorAll("[data-chat-send]").forEach((element) => {
    holdPosition(element);
    element.onclick = (event) => {
      event.preventDefault();
      void submitChatPrompt(state.chatDraft.trim());
    };
  });
  bindGraphInteractions();
}
function rememberDetailScroll() {
  const detail = root.querySelector("[data-scroll-key='detail']");
  if (detail) {
    state.scrollMemory.detail = detail.scrollTop;
    state.detailScrollLock = detail.scrollTop;
  }
}
function focusNodeContext(nodeId, panel = "assets", preferFindings = false) {
  state.selectedGraphNodeId = nodeId;
  state.selectedGraphEdgeId = null;
  state.detailScope = "context";
  state.detailView = "detail";
  const node = state.graphNodes.find((item) => item.id === nodeId) ?? null;
  const resolvedPanel = node?.kind === "hub" ? "findings" : panel;
  const asset = getAssets(state.report).find((item) => item.asset_id === nodeId || item.linked_host_key === nodeId || item.ip === nodeId) ?? null;
  state.selectedAssetId = asset?.asset_id ?? null;
  state.selectedActionId = null;
  const related = getRelatedFindingsForNode(nodeId);
  const fallbackFinding = state.report?.findings?.[0] ?? null;
  state.selectedFindingId = related[0] ? findingKey(related[0], 0) : fallbackFinding ? findingKey(fallbackFinding, 0) : null;
  state.detailPanel = preferFindings && related.length ? "findings" : resolvedPanel;
}
function focusEdgeContext(edgeId) {
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
async function exportCurrent(format) {
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
      headers: buildAuthHeaders()
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
function readPentestMode() {
  const value = window.localStorage.getItem("bakulaPentestMode");
  return value === "off" || value === "aggressive" ? value : "smart";
}
function cyclePentestMode() {
  state.pentestMode = state.pentestMode === "off" ? "smart" : state.pentestMode === "smart" ? "aggressive" : "off";
  window.localStorage.setItem("bakulaPentestMode", state.pentestMode);
}
async function resetAutomation() {
  try {
    const response = await fetch("/api/automation/reset", {
      method: "POST",
      headers: buildAuthHeaders()
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
  const surface = root.querySelector("[data-graph-surface='topology']");
  const tooltip = root.querySelector("#graphTooltip");
  if (!surface || !tooltip) return;
  const hideTooltip = () => tooltip.classList.remove("is-visible");
  const anchorOf = (element) => {
    const rect = element.getBoundingClientRect();
    return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
  };
  const placeTooltipAtAnchor = (anchorX, anchorY, html, widthFactor, heightFactor) => {
    const rect = surface.getBoundingClientRect();
    const margin = clamp4(Math.min(rect.width, rect.height) * 0.02, 10, 20);
    const tooltipWidth = clamp4(rect.width * widthFactor, 220, 340);
    const tooltipHeight = clamp4(rect.height * heightFactor, 132, 236);
    const horizontalOffset = anchorX >= rect.left + rect.width / 2 ? -(tooltipWidth + margin * 0.62) : margin * 0.82;
    const verticalOffset = anchorY >= rect.top + rect.height / 2 ? -(tooltipHeight * 0.72) : -(tooltipHeight * 0.28);
    const x = clamp4(
      anchorX - rect.left + horizontalOffset,
      margin,
      rect.width - tooltipWidth - margin
    );
    const y = clamp4(
      anchorY - rect.top + verticalOffset,
      margin,
      rect.height - tooltipHeight - margin
    );
    const originX = clamp4(
      (anchorX - rect.left - x) / Math.max(tooltipWidth, 1) * 100,
      0,
      100
    );
    const originY = clamp4(
      (anchorY - rect.top - y) / Math.max(tooltipHeight, 1) * 100,
      0,
      100
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
    state.zoom = clamp4(state.zoom + (event.deltaY < 0 ? 0.12 : -0.12), 0.7, 3.2);
    updateGraphZoom();
  };
  surface.onpointerdown = (event) => {
    const target = event.target;
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
    const viewport = root.querySelector("#graphTransform");
    const sceneWidth = Number(viewport?.dataset.sceneWidth ?? rect.width);
    const sceneHeight = Number(viewport?.dataset.sceneHeight ?? rect.height);
    const panLimitX = Math.max(
      (sceneWidth * state.zoom - rect.width) / 2 + rect.width * 0.08,
      rect.width * 0.12
    );
    const panLimitY = Math.max(
      (sceneHeight * state.zoom - rect.height) / 2 + rect.height * 0.08,
      rect.height * 0.12
    );
    state.panX = clamp4(basePanX + (event.clientX - startX), -panLimitX, panLimitX);
    state.panY = clamp4(basePanY + (event.clientY - startY), -panLimitY, panLimitY);
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
  surface.querySelectorAll("[data-node-id]").forEach((nodeElement) => {
    const nodeId = nodeElement.getAttribute("data-node-id") ?? "";
    const node = state.graphNodes.find((item) => item.id === nodeId);
    if (!node) return;
    const place = () => {
      const shell = nodeElement.querySelector("circle.graph-node-shell") ?? nodeElement.querySelector("circle") ?? nodeElement;
      const anchor = anchorOf(shell);
      placeTooltipAtAnchor(
        anchor.x,
        anchor.y,
        `<div class="tooltip-title">${escapeHtml(node.title)}</div><div class="tooltip-sub">${escapeHtml(node.layerLabel)} \xB7 ${escapeHtml(node.subtitle)}</div><div class="tooltip-list">${compact([
          node.issueCounts.total ? `rizika ${node.issueCounts.total}` : "",
          node.trafficPackets ? `pakety ${node.trafficPackets} \xB7 ${formatBytes(node.trafficBytes)}` : "",
          ...node.details.slice(0, 3)
        ]).map((item) => `<div>${escapeHtml(item)}</div>`).join("")}</div>`,
        0.24,
        0.24
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
  surface.querySelectorAll("[data-edge-id]").forEach((edgeElement) => {
    const edgeId = edgeElement.getAttribute("data-edge-id") ?? "";
    const edge = state.graphEdges.find((item) => item.id === edgeId);
    if (!edge) return;
    const place = () => {
      const path = edgeElement.querySelector("path.graph-edge") ?? edgeElement;
      const anchor = anchorOf(path);
      placeTooltipAtAnchor(
        anchor.x,
        anchor.y,
        `<div class="tooltip-title">${escapeHtml(edge.relation)}</div><div class="tooltip-sub">${escapeHtml(edge.source)} \u2192 ${escapeHtml(edge.target)}</div><div class="tooltip-list"><div>${edge.packets} paket\u016F \xB7 ${formatBytes(edge.bytes)}</div><div>${edge.active ? "\u017Eiv\xFD tok" : "statick\xE1 vazba"} \xB7 ${edge.issueCounts.total} nav\xE1zan\xFDch rizik</div><div>${edge.confidence} jistota</div></div>`,
        0.22,
        0.2
      );
    };
    edgeElement.onmouseenter = () => place();
    edgeElement.onfocus = () => place();
    edgeElement.onmouseleave = hideTooltip;
    edgeElement.onblur = hideTooltip;
    edgeElement.onclick = (event) => {
      event.stopPropagation();
      focusEdgeContext(edgeId);
      renderApp();
    };
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
  const viewport = root.querySelector("#graphTransform");
  if (viewport) {
    viewport.style.setProperty("--pan-x", cssLength(state.panX));
    viewport.style.setProperty("--pan-y", cssLength(state.panY));
    viewport.style.setProperty("--zoom", state.zoom.toFixed(2));
  }
}
function emptyIssueCounts() {
  return { high: 0, medium: 0, low: 0, total: 0, findingIds: [] };
}
function registerIssue(counts, finding) {
  const id = String(finding.finding_id ?? `${finding.title ?? "finding"}:${counts.total}`);
  if (counts.findingIds.includes(id)) return;
  const bucket = levelOf(finding.severity);
  if (bucket === "high" || bucket === "medium" || bucket === "low") counts[bucket] += 1;
  counts.total += 1;
  counts.findingIds.push(id);
}
function findingTouchesNode(finding, node, assets, flows) {
  if (finding.host_key === node.id || finding.service_key === node.id) return true;
  if (finding.service_key && node.id === String(finding.host_key ?? "")) return true;
  const matchedAsset = assets.find((asset) => asset.asset_id === node.id || asset.linked_host_key === node.id || asset.ip === node.id);
  if (matchedAsset) {
    if (finding.host_key === matchedAsset.ip || finding.host_key === matchedAsset.linked_host_key) return true;
    if (finding.service_key && String(finding.service_key).includes(String(matchedAsset.ip ?? ""))) return true;
  }
  const flow = flows.find(
    (item) => item.nodeId === node.id || item.sourceNodeId === node.id
  );
  if (flow) {
    if (finding.host_key === flow.sourceNodeId) return true;
    const evidenceJoined = (finding.evidence ?? []).join(" ").toLowerCase();
    if (evidenceJoined.includes(String(flow.dstIp).toLowerCase()) || evidenceJoined.includes(String(flow.sourceNodeId).toLowerCase())) return true;
  }
  const nodeNeedles = compact([node.id, node.title, node.subtitle, ...node.details ?? [], matchedAsset?.ip, matchedAsset?.mac]).map((item) => String(item).toLowerCase());
  const evidence = (finding.evidence ?? []).map((item) => String(item).toLowerCase());
  return nodeNeedles.some((needle) => evidence.some((entry) => entry.includes(needle)));
}
function buildGraph(report, width, height) {
  const hostRecords = (report.hosts ?? []).sort(
    (a, b) => String(a.ip).localeCompare(String(b.ip))
  );
  const rawAssets = getAssets(report);
  const normalizedAssets = rawAssets.length ? rawAssets : hostRecords.map((host) => ({
    asset_id: `host:${host.host_key}`,
    asset_type: "endpoint",
    name: host.hostname ?? host.ip,
    source: "host-only",
    confidence: "medium",
    ip: host.ip,
    mac: host.mac,
    vendor: host.vendor,
    linked_host_key: host.host_key,
    observations: []
  }));
  const hostByKey = new Map(hostRecords.map((host) => [host.host_key, host]));
  const hostByIp = new Map(hostRecords.map((host) => [host.ip, host]));
  const flows = getFlowFindings(report).slice(0, 8);
  const cx = width / 2;
  const cy = height / 2;
  const orbit = computeGraphOrbitMetrics(width, height);
  const nodes = [];
  const hubId = "hub:scope";
  nodes.push({
    id: hubId,
    title: report.run?.scope?.join(", ") ?? "Scope",
    subtitle: `${providerLabel(report.run?.provider ?? "provider")} \xB7 ${modeLabel(report.run?.enrichment_mode ?? "mode")}`,
    layerLabel: "\u0159\xEDdic\xED vrstva",
    kind: "hub",
    nodeType: "scope",
    x: cx,
    y: cy,
    sev: "neutral",
    tags: compact([report.run?.profile, report.run?.provider]),
    details: compact([
      `host\xE9 ${report.summary?.hosts_total ?? 0}`,
      `slu\u017Eby ${report.summary?.services_total ?? 0}`,
      `n\xE1lezy ${report.summary?.findings_total ?? 0}`
    ]),
    services: [],
    connected: [],
    trafficPackets: 0,
    trafficBytes: 0,
    issueCounts: emptyIssueCounts()
  });
  const mappedHostKeys = /* @__PURE__ */ new Set();
  const assetNodes = normalizedAssets.map((asset) => {
    const linkedHost = asset.linked_host_key && hostByKey.get(asset.linked_host_key) || asset.ip && hostByIp.get(asset.ip) || null;
    if (linkedHost?.host_key) mappedHostKeys.add(linkedHost.host_key);
    const nodeKind = resolveNodeKindForAsset(asset, linkedHost);
    const services = (linkedHost?.services ?? []).filter((service) => service.port_state === "open").slice(0, 4).map((service) => ({
      label: `${service.inventory?.service_name ?? service.port}/${service.port}`,
      severity: service.priorita ?? "neutral"
    }));
    return {
      id: asset.asset_id,
      title: asset.name ?? asset.asset_id,
      subtitle: `${assetTypeLabel(asset.asset_type)} \xB7 ${asset.ip ?? asset.source ?? "zdroj"}`,
      layerLabel: resolveLayerLabel(nodeKind, asset.asset_type),
      kind: nodeKind,
      nodeType: asset.asset_type,
      x: cx,
      y: cy,
      sev: linkedHost ? (linkedHost.services ?? []).some((service) => levelOf(service.priorita) === "high") ? "high" : (linkedHost.services ?? []).some((service) => levelOf(service.priorita) === "medium") ? "medium" : "low" : levelOf(asset.confidence),
      tags: buildAssetTags(asset, linkedHost),
      details: buildAssetDetails(asset, linkedHost),
      services,
      connected: [],
      trafficPackets: 0,
      trafficBytes: 0,
      issueCounts: emptyIssueCounts(),
      riskScore: 0,
      riskColor: "#34d399"
    };
  });
  const orphanHosts = hostRecords.filter((host) => !mappedHostKeys.has(host.host_key)).map((host) => ({
    id: host.host_key,
    title: host.hostname || host.ip,
    subtitle: host.ip,
    layerLabel: "host vrstva",
    kind: "host",
    nodeType: hostGlyphType(host),
    x: cx,
    y: cy,
    sev: (host.services ?? []).some((service) => levelOf(service.priorita) === "high") ? "high" : (host.services ?? []).some((service) => levelOf(service.priorita) === "medium") ? "medium" : "low",
    tags: compact([host.hostname, host.ip, host.vendor]),
    details: compact([
      `slu\u017Eby ${(host.services ?? []).filter((service) => service.port_state === "open").length}`,
      `vysok\xE1 priorita ${(host.services ?? []).filter((service) => levelOf(service.priorita) === "high").length}`,
      host.mac
    ]),
    services: (host.services ?? []).filter((service) => service.port_state === "open").slice(0, 4).map((service) => ({
      label: `${service.inventory?.service_name ?? service.port}/${service.port}`,
      severity: service.priorita ?? "neutral"
    })),
    connected: [],
    trafficPackets: 0,
    trafficBytes: 0,
    issueCounts: emptyIssueCounts(),
    riskScore: 0,
    riskColor: "#34d399"
  }));
  const flowNodes = flows.map((flow) => ({
    id: flow.nodeId,
    title: flow.dstIp,
    subtitle: flow.url ? trim(flow.url, 52) : "extern\xED tok",
    layerLabel: "tok / extern\xED c\xEDl",
    kind: "external",
    nodeType: "external-flow",
    x: cx,
    y: cy,
    sev: flow.severity,
    tags: compact([flow.protocol, flow.dstPort ? `:${flow.dstPort}` : "", flow.url]),
    details: compact([
      `pakety ${flow.packets}`,
      `objem ${formatBytes(flow.bytes)}`
    ]),
    services: [],
    connected: [],
    trafficPackets: flow.packets,
    trafficBytes: flow.bytes,
    issueCounts: emptyIssueCounts(),
    riskScore: 0,
    riskColor: "#38bdf8"
  }));
  const coreNodes = assetNodes.filter((node) => node.kind === "core").sort((a, b) => a.title.localeCompare(b.title));
  const hostNodes = [...assetNodes.filter((node) => node.kind === "host"), ...orphanHosts].sort((a, b) => a.title.localeCompare(b.title));
  const clientNodes = assetNodes.filter((node) => node.kind === "client").sort((a, b) => a.title.localeCompare(b.title));
  layoutRing(coreNodes, cx, cy, orbit.ringRadii[0], -90);
  layoutRing(hostNodes, cx, cy, orbit.ringRadii[1], -112);
  layoutRing(clientNodes, cx, cy, orbit.ringRadii[2], -78);
  layoutRing(flowNodes, cx, cy, orbit.ringRadii[3], -132);
  nodes.push(...coreNodes, ...hostNodes, ...clientNodes, ...flowNodes);
  const visible = new Set(nodes.map((node) => node.id));
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const edges = /* @__PURE__ */ new Map();
  const addEdge = (source, target, relation, confidence = "medium", packets = 0, bytes = 0, active = false) => {
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
        issueCounts: emptyIssueCounts()
      });
    } else {
      const current = edges.get(key);
      current.packets = Math.max(current.packets, packets);
      current.bytes = Math.max(current.bytes, bytes);
      current.active = current.active || active;
    }
    nodeMap.get(source)?.connected.push(target);
    nodeMap.get(target)?.connected.push(source);
    nodeMap.get(source).trafficPackets += packets;
    nodeMap.get(source).trafficBytes += bytes;
    nodeMap.get(target).trafficPackets += packets;
    nodeMap.get(target).trafficBytes += bytes;
  };
  coreNodes.forEach((node) => addEdge(hubId, node.id, "core", "medium"));
  getTopologyEdges(report).forEach(
    (edge) => addEdge(
      edge.source_asset_id,
      edge.target_asset_id,
      edge.relation ?? "relation",
      edge.confidence ?? "medium"
    )
  );
  hostNodes.forEach((node) => {
    const linkedAsset = coreNodes.find(
      (candidate) => candidate.details.some(
        (detail) => node.details.some(
          (nodeDetail) => detail.toLowerCase().includes(nodeDetail.toLowerCase())
        )
      )
    );
    addEdge(linkedAsset?.id ?? hubId, node.id, linkedAsset ? "inventory" : "scope", linkedAsset ? "medium" : "low");
  });
  clientNodes.forEach((node) => {
    const linked = coreNodes.find((candidate) => {
      const lowerCandidate = candidate.title.toLowerCase();
      return node.details.some((item) => item.toLowerCase().includes(lowerCandidate));
    });
    addEdge(node.id, linked?.id ?? coreNodes[0]?.id ?? hubId, "visibility", linked ? "medium" : "low");
  });
  flows.forEach((flow) => {
    const preferredSource = normalizedAssets.find(
      (asset) => asset.linked_host_key === flow.sourceNodeId || asset.ip === flow.sourceNodeId
    );
    const sourceId = preferredSource?.asset_id ?? flow.sourceNodeId;
    if (!visible.has(sourceId) || !visible.has(flow.nodeId)) return;
    addEdge(sourceId, flow.nodeId, "flow", "medium", flow.packets, flow.bytes, true);
  });
  const findings = report.findings ?? [];
  nodes.forEach((node) => {
    node.issueCounts = emptyIssueCounts();
  });
  findings.forEach((finding) => {
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
    findings.forEach((finding) => {
      if (findingTouchesNode(finding, sourceNode, normalizedAssets, flows) || findingTouchesNode(finding, targetNode, normalizedAssets, flows)) {
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
function layoutRing(nodes, cx, cy, radius, startAngleDeg) {
  if (!nodes.length) return;
  const step = Math.PI * 2 / Math.max(nodes.length, 1);
  const start = startAngleDeg * Math.PI / 180;
  nodes.forEach((node, index) => {
    const angle = start + step * index;
    node.x = cx + Math.cos(angle) * radius;
    node.y = cy + Math.sin(angle) * radius;
  });
}
function resolveNodeKindForAsset(asset, linkedHost) {
  if (["router", "switch", "firewall", "network-device", "access-point"].includes(asset.asset_type)) {
    return "core";
  }
  if (asset.asset_type === "wireless-client") {
    return "client";
  }
  const openServices = (linkedHost?.services ?? []).filter((service) => service.port_state === "open");
  return openServices.length ? "host" : "client";
}
function resolveLayerLabel(kind, assetType) {
  if (kind === "hub") return "\u0159\xEDdic\xED vrstva";
  if (kind === "core") return assetType === "access-point" ? "p\u0159\xEDstupov\xE1 vrstva" : "s\xED\u0165ov\xE1 vrstva";
  if (kind === "host") return "servisn\xED vrstva";
  if (kind === "client") return "koncov\xE1 vrstva";
  return "tok / extern\xED c\xEDl";
}
function buildAssetTags(asset, linkedHost) {
  return compact([
    asset.source,
    asset.vendor,
    asset.location,
    linkedHost?.hostname
  ]);
}
function buildAssetDetails(asset, linkedHost) {
  const openServices = (linkedHost?.services ?? []).filter((service) => service.port_state === "open").slice(0, 4).map((service) => `${service.port}/${service.proto}`);
  return compact([
    asset.ip,
    asset.mac,
    asset.vendor,
    asset.model,
    openServices.length ? `otev\u0159eno ${openServices.join(", ")}` : "",
    ...(asset.observations ?? []).slice(0, 2)
  ]);
}
function getSelectedNode() {
  if (!state.graphNodes.length) return null;
  if (!state.selectedGraphNodeId) {
    state.selectedGraphNodeId = [...state.graphNodes].filter((node) => node.kind !== "hub" && node.kind !== "external").sort((left, right) => (right.riskScore ?? 0) - (left.riskScore ?? 0))[0]?.id ?? state.graphNodes.find((node) => node.kind === "core")?.id ?? state.graphNodes[0].id;
  }
  return state.graphNodes.find((node) => node.id === state.selectedGraphNodeId) ?? state.graphNodes[0] ?? null;
}
function getSelectedFinding(pool) {
  const findings = pool ?? getVisibleFindings();
  const id = state.selectedFindingId ?? (findings[0] ? findingKey(findings[0], 0) : null);
  return findings.find((finding) => findingKey(finding) === id) ?? findings[0] ?? null;
}
function getSelectedAsset() {
  const assets = getAssets(state.report);
  if (state.selectedAssetId) return assets.find((asset) => asset.asset_id === state.selectedAssetId) ?? null;
  const nodeId = state.selectedGraphNodeId;
  if (nodeId) return assets.find((asset) => asset.asset_id === nodeId) ?? assets.find((asset) => asset.linked_host_key === nodeId || asset.ip === nodeId) ?? null;
  return assets[0] ?? null;
}
function getSelectedAction() {
  const actions = getTriage(state.report);
  if (!actions.length) return null;
  const id = state.selectedActionId ?? actionKey(actions[0], 0);
  return actions.find((action) => actionKey(action) === id) ?? actions[0] ?? null;
}
function findingKey(finding, index = 0) {
  if (!finding) return `finding:${index}`;
  return String(
    finding.finding_id ?? [
      finding.title ?? "finding",
      finding.finding_type ?? "",
      finding.host_key ?? "",
      finding.service_key ?? "",
      finding.severity ?? "",
      (finding.evidence ?? []).slice(0, 2).join("|")
    ].join("::")
  );
}
function actionKey(action, index = 0) {
  if (!action) return `action:${index}`;
  return String(
    action.action_id ?? [
      action.title ?? "action",
      action.priority ?? "",
      action.target_service_key ?? "",
      action.target_asset_id ?? "",
      action.next_step ?? ""
    ].join("::")
  );
}
function getAssets(report) {
  const explicitAssets = [...report?.networkAssets ?? report?.network_assets ?? []];
  const hosts = report?.hosts ?? [];
  if (!hosts.length) return explicitAssets;
  const covered = new Set(
    explicitAssets.flatMap(
      (asset) => compact([asset.asset_id, asset.linked_host_key, asset.host_key, asset.ip])
    )
  );
  const hostAssets = hosts.filter((host) => !covered.has(String(host.host_key ?? "")) && !covered.has(String(host.ip ?? ""))).map((host, index) => hostToAsset(host, index));
  return [...explicitAssets, ...hostAssets];
}
function hostToAsset(host, index) {
  const openServices = (host.services ?? []).filter((service) => service.port_state === "open");
  const highServices = openServices.filter((service) => levelOf(service.priorita) === "high").length;
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
      openServices.length ? `otev\u0159en\xE9 slu\u017Eby ${openServices.length}` : "",
      highServices ? `vysok\xE1 priorita ${highServices}` : "",
      host.os_name
    ])
  };
}
function getTopologyEdges(report) {
  return report?.topologyEdges ?? report?.topology_edges ?? [];
}
function getLanes(report) {
  return report?.monitoringLanes ?? report?.monitoring_lanes ?? [];
}
function getTriage(report) {
  return report?.triageActions ?? report?.triage_actions ?? [];
}
function getFlowFindings(report) {
  return (report?.findings ?? []).filter((finding) => finding.finding_type === "external_flow_observed").map((finding, index) => {
    const evidence = /* @__PURE__ */ new Map();
    (finding.evidence ?? []).forEach((item) => {
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
      severity: levelOf(finding.severity)
    };
  }).filter((item) => item.sourceNodeId.length > 0);
}
function getVisibleFindings() {
  const findings = state.report?.findings ?? [];
  if (state.detailScope === "all") return findings;
  if (state.selectedGraphEdgeId) {
    const relatedIds = new Set(getRelatedFindingsForEdge(state.selectedGraphEdgeId).map((item) => findingKey(item)));
    const filtered = findings.filter((finding) => relatedIds.has(findingKey(finding)));
    if (filtered.length) return filtered;
  }
  if (state.selectedGraphNodeId) {
    const relatedIds = new Set(getRelatedFindingsForNode(state.selectedGraphNodeId).map((item) => findingKey(item)));
    const filtered = findings.filter((finding) => relatedIds.has(findingKey(finding)));
    if (filtered.length) return filtered;
  }
  return findings;
}
function getRelatedFindingsForNode(nodeId) {
  if (!nodeId || !state.report) return [];
  const node = state.graphNodes.find((item) => item.id === nodeId) ?? null;
  const assets = getAssets(state.report);
  const flows = getFlowFindings(state.report);
  if (node) {
    return (state.report.findings ?? []).filter((finding) => findingTouchesNode(finding, node, assets, flows));
  }
  const asset = assets.find((item) => item.asset_id === nodeId || item.linked_host_key === nodeId || item.ip === nodeId) ?? null;
  const evidenceNeedles = compact([nodeId, asset?.ip, asset?.mac, asset?.name, asset?.linked_host_key]).map((item) => String(item).toLowerCase());
  return (state.report.findings ?? []).filter((finding) => {
    if (finding.host_key === nodeId || finding.service_key === nodeId) return true;
    if (asset && (finding.host_key === asset.ip || finding.host_key === asset.linked_host_key || String(finding.service_key ?? "").includes(String(asset.ip ?? "")))) return true;
    const evidence = (finding.evidence ?? []).map((item) => String(item).toLowerCase());
    return evidenceNeedles.some((needle) => evidence.some((entry) => entry.includes(needle)));
  });
}
function getRelatedFindingsForEdge(edgeId) {
  if (!edgeId) return [];
  const edge = state.graphEdges.find((item) => item.id === edgeId);
  if (!edge) return [];
  const assets = getAssets(state.report);
  const flows = getFlowFindings(state.report);
  const leftNode = state.graphNodes.find((item) => item.id === edge.source) ?? null;
  const rightNode = state.graphNodes.find((item) => item.id === edge.target) ?? null;
  const map = /* @__PURE__ */ new Map();
  (state.report?.findings ?? []).forEach((finding, index) => {
    const leftMatch = leftNode ? findingTouchesNode(finding, leftNode, assets, flows) : false;
    const rightMatch = rightNode ? findingTouchesNode(finding, rightNode, assets, flows) : false;
    if (leftMatch || rightMatch) map.set(findingKey(finding, index), finding);
  });
  return Array.from(map.values());
}
function assetCounts(assets) {
  return { accessPoints: assets.filter((item) => item.asset_type === "access-point").length, clients: assets.filter((item) => item.asset_type === "wireless-client").length, switches: assets.filter((item) => ["switch", "router", "firewall", "network-device"].includes(item.asset_type)).length };
}
function riskScoreFromIssueCounts(counts) {
  if (!counts || !counts.total) return 0;
  const weighted = counts.high * 1 + counts.medium * 0.62 + counts.low * 0.28;
  return clamp4(weighted / Math.max(1, counts.total + counts.high * 0.35), 0, 1);
}
function riskColorForScore(score) {
  if (score <= 0) return "#34d399";
  if (score >= 1) return "#fb7185";
  const clamped = clamp4(score, 0, 1);
  const hue = 148 - clamped * 138;
  const sat = 72 + clamped * 10;
  const light = 56 + (1 - clamped) * 2;
  return `hsl(${hue.toFixed(1)} ${sat.toFixed(1)}% ${light.toFixed(1)}%)`;
}
function computeRisk(report) {
  if (!report) return { className: "severity-neutral", label: "Bez dat", icon: "circle-dashed" };
  const findings = report.findings ?? [];
  if (findings.some((finding) => levelOf(finding.severity) === "high")) return { className: "severity-high", label: "Priorita", icon: "shield-alert" };
  if (findings.some((finding) => levelOf(finding.severity) === "medium")) return { className: "severity-medium", label: "Pozor", icon: "alert-triangle" };
  return { className: "severity-low", label: "Klid", icon: "shield" };
}
function pill(label, value, icon) {
  return `<span class="tiny-chip"><i data-lucide="${icon}" class="h-3.5 w-3.5"></i>${escapeHtml(label)} \xB7 ${value}</span>`;
}
function emptyState(message) {
  return `<div class="empty-state">${escapeHtml(message)}</div>`;
}
function severity(value) {
  const normalized = levelOf(value);
  if (normalized === "high") return "severity-high";
  if (normalized === "medium") return "severity-medium";
  if (normalized === "low") return "severity-low";
  return "severity-neutral";
}
function levelOf(value) {
  const normalized = String(value ?? "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
  if (normalized.includes("vysok") || normalized === "high" || normalized === "critical") return "high";
  if (normalized.includes("stred") || normalized === "medium" || normalized === "partial") return "medium";
  if (normalized.includes("niz") || normalized === "low" || normalized === "ok") return "low";
  return "neutral";
}
function detailEyebrow(type) {
  const normalized = String(type ?? "").toLowerCase();
  if (normalized.includes("greenbone")) return "audit";
  if (normalized.includes("flow")) return "\u017Eiv\xFD tok";
  if (normalized.includes("config")) return "konfigurace";
  if (normalized.includes("cve")) return "riziko";
  return "n\xE1lez";
}
function assetTypeLabel(type) {
  if (type === "access-point") return "AP";
  if (type === "wireless-client") return "Wi\u2011Fi klient";
  if (type === "switch") return "switch";
  if (type === "router") return "router";
  if (type === "endpoint") return "endpoint";
  if (type === "network-device") return "s\xED\u0165ov\xFD prvek";
  return type;
}
function confidenceLabel(value) {
  const normalized = String(value ?? "").toLowerCase();
  if (normalized.includes("high")) return "jistota vysok\xE1";
  if (normalized.includes("medium")) return "jistota st\u0159edn\xED";
  if (normalized.includes("low")) return "jistota n\xEDzk\xE1";
  return normalized ? `jistota ${normalized}` : "";
}
function hostGlyphType(host) {
  const services = (host.services ?? []).map((service) => Number(service.port));
  if (services.includes(80) || services.includes(443)) return "web";
  if (services.includes(21) || services.includes(22) || services.includes(23)) return "spr\xE1va";
  return "server";
}
function nodeGlyph(node) {
  if (node.kind === "hub") return "\u25CF";
  if (node.kind === "external") return "WAN";
  if (node.nodeType === "access-point") return "AP";
  if (node.nodeType === "switch") return "SW";
  if (node.nodeType === "router") return "RT";
  if (node.nodeType === "wireless-client") return "WF";
  if (node.nodeType === "endpoint") return "PC";
  if (node.nodeType === "web") return "WEB";
  if (node.nodeType === "spr\xE1va") return "ADM";
  return node.kind === "host" ? "SRV" : "NET";
}
function providerLabel(value) {
  return String(value).toLowerCase() === "demo" ? "demo" : value;
}
function modeLabel(value) {
  const normalized = String(value).toLowerCase();
  return normalized === "live" ? "\u017Eiv\u011B" : normalized === "audit" ? "audit" : value;
}
function displayRunName(value) {
  return String(value) === "Full visibility stack" ? "Pln\xFD p\u0159ehled s\xEDt\u011B" : value;
}
function localizeUiText(value) {
  return String(value).replace(/\bLive vrstva\b/g, "\u017Div\xE1 vrstva").replace(/\bLIVE\b/g, "\u017DIV\u011A").replace(/\blive\b/g, "\u017Eiv\u011B");
}
function relativeTime(value) {
  if (!value) return "offline";
  const diff = Date.now() - new Date(value).getTime();
  const seconds = Math.max(0, Math.round(diff / 1e3));
  if (seconds < 5) return "pr\xE1v\u011B";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${Math.round(seconds / 3600)}h`;
}
function formatBytes(value) {
  if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  if (value >= 1024) return `${Math.round(value / 1024)} kB`;
  return `${value} B`;
}
function compact(values) {
  return values.filter((value) => Boolean(value && String(value).trim())).map((value) => String(value));
}
function trim(value, max) {
  return value.length > max ? `${value.slice(0, max - 1)}\u2026` : value;
}
function clamp4(value, min, max) {
  return Math.max(min, Math.min(max, value));
}
function escapeHtml(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}
function escapeAttr(value) {
  return escapeHtml(value);
}
function requestedFocus() {
  const focus = new URL(window.location.href).searchParams.get("focus");
  if (focus === "topology" || focus === "audit") return focus;
  return null;
}
function setFocusQuery(panel) {
  const url = new URL(window.location.href);
  if (panel) url.searchParams.set("focus", panel);
  else url.searchParams.delete("focus");
  window.history.replaceState({}, "", url);
}
