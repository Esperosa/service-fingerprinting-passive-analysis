export type ResponsiveMetrics = {
  width: number;
  height: number;
  aspect: number;
  scale: number;
  textScale: number;
  shellPad: number;
  layoutGap: number;
  leftCol: number;
  rightCol: number;
  panelPad: number;
  heroHeight: number;
  tabHeight: number;
  graphWidth: number;
  graphHeight: number;
  detailFocusMax: number;
  compact: boolean;
};

export type GraphOrbitMetrics = {
  padding: number;
  availableRadius: number;
  ringRadii: [number, number, number, number];
};

const clamp = (value: number, min: number, max: number) => Math.max(min, Math.min(max, value));
const rem = (value: number) => `${(value / 16).toFixed(4).replace(/\.?0+$/, "")}rem`;

export function applyResponsiveLayoutVars(target: HTMLElement, width: number, height: number): ResponsiveMetrics {
  const aspect = width / Math.max(height, 1);
  const compact = width < 980;
  const baseScale = Math.min(width / 1600, height / 1000);
  const aspectBias = aspect > 2.1 ? 0.96 : aspect > 1.85 ? 0.99 : aspect < 1.45 ? 0.93 : 1;
  const scale = clamp(baseScale * aspectBias, compact ? 0.84 : 0.82, compact ? 1.04 : 1.14);
  const textScale = clamp(baseScale * (compact ? 0.88 : 0.96), compact ? 0.68 : 0.74, compact ? 0.98 : 1.05);
  const shellPad = Math.round(clamp(height * 0.012, 10, 18) * scale);
  const layoutGap = Math.round(clamp(width * 0.008, 8, 16) * scale);
  const panelPad = Math.round(clamp(height * 0.014, 12, 18) * scale);

  let leftCol = compact ? 0 : Math.round(clamp(width * 0.12, 168, 198) * scale);
  let rightCol = compact ? 0 : Math.round(clamp(width * 0.22, 280, 360) * scale);
  const outerShell = shellPad * 2;
  const gutter = layoutGap * 2;
  const minimumCenter = compact ? 360 : Math.round(680 * scale);
  let centerCol = width - outerShell - gutter - leftCol - rightCol;
  if (!compact && centerCol < minimumCenter) {
    const deficit = minimumCenter - centerCol;
    rightCol = Math.max(Math.round(260 * scale), rightCol - deficit);
    centerCol = width - outerShell - gutter - leftCol - rightCol;
  }

  const graphWidth = Math.round(clamp(compact ? width : centerCol, compact ? 360 : 720, compact ? 760 : 1800));
  const graphHeight = Math.round(clamp(compact ? height : height - outerShell, compact ? 620 : 640, compact ? 1180 : 1240));
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
    compact,
  };
}

export function computeGraphSceneSize(metrics: ResponsiveMetrics, expanded: boolean) {
  if (metrics.compact) {
    return {
      width: clamp(Math.round(metrics.graphWidth), 360, 760),
      height: clamp(Math.round(metrics.graphHeight), 620, 1180),
    };
  }
  const width = expanded
    ? clamp(Math.round(metrics.graphWidth * 1.04), 760, 1900)
    : clamp(Math.round(metrics.graphWidth), 720, 1800);
  const height = expanded
    ? clamp(Math.round(metrics.graphHeight * 1.03), 680, 1280)
    : clamp(Math.round(metrics.graphHeight), 640, 1240);
  return { width, height };
}

export function computeGraphOrbitMetrics(width: number, height: number): GraphOrbitMetrics {
  const minSide = Math.min(width, height);
  const padding = clamp(minSide * 0.07, minSide < 620 ? 24 : 58, 122);
  const availableRadius = Math.max(
    120,
    Math.min(width / 2 - padding, height / 2 - padding),
  );
  return {
    padding,
    availableRadius,
    ringRadii: [
      availableRadius * 0.34,
      availableRadius * 0.60,
      availableRadius * 0.81,
      availableRadius * 0.96,
    ],
  };
}
