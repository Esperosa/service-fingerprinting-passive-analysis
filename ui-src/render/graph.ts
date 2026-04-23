import type { UiRenderCtx } from "./context";
import { computeGraphOrbitMetrics } from "../responsive";

type GraphNodeLike = {
  id: string;
  title: string;
  subtitle: string;
  kind: string;
  nodeType: string;
  layerLabel: string;
  x: number;
  y: number;
  issueCounts: { high: number; medium: number; low: number; total: number };
  riskScore?: number;
  riskColor?: string;
  trafficPackets: number;
  trafficBytes: number;
  connected: string[];
  details: string[];
};

type GraphEdgeLike = {
  id: string;
  source: string;
  target: string;
  relation: string;
  packets: number;
  bytes: number;
  active: boolean;
  issueCounts: { high: number; medium: number; low: number; total: number };
  riskScore?: number;
  riskColor?: string;
};

type Point = { x: number; y: number };

export function renderGraphSvg(
  ctx: UiRenderCtx,
  nodes: GraphNodeLike[],
  edges: GraphEdgeLike[],
  width: number,
  height: number,
  selectedNodeId: string | null,
  selectedEdgeId: string | null,
) {
  const centerX = width / 2;
  const centerY = height / 2;
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const visibleEdges = edges.filter(
    (edge) => nodeMap.has(edge.source) && nodeMap.has(edge.target),
  );
  const orbit = computeGraphOrbitMetrics(width, height);
  const ringRadii = orbit.ringRadii;

  const selectedEdge = selectedEdgeId
    ? visibleEdges.find((edge) => edge.id === selectedEdgeId) ?? null
    : null;
  const selectedNode =
    selectedNodeId ? nodeMap.get(selectedNodeId) ?? null : null;

  const edgePathDefs = visibleEdges
    .map((edge, index) => {
      const source = nodeMap.get(edge.source);
      const target = nodeMap.get(edge.target);
      if (!source || !target) return "";
      const control = buildEdgeControlPoint(source, target, centerX, centerY);
      return `<path id="graph-edge-${index}" d="M ${source.x} ${source.y} Q ${control.x} ${control.y} ${target.x} ${target.y}"></path>`;
    })
    .join("");

  const baseEdges = visibleEdges
    .map((edge, index) => renderEdge(ctx, edge, index, nodeMap, centerX, centerY, selectedNode, selectedEdge, false))
    .join("");
  const agentLayer = renderAgentLayer(ctx, visibleEdges);
  const overlayEdge = selectedEdge
    ? renderEdge(
        ctx,
        selectedEdge,
        visibleEdges.findIndex((edge) => edge.id === selectedEdge.id),
        nodeMap,
        centerX,
        centerY,
        selectedNode,
        selectedEdge,
        true,
      )
    : "";

  const sortedNodes = [...nodes].sort((left, right) => {
    const leftWeight = nodeRenderWeight(left, selectedNode, selectedEdge);
    const rightWeight = nodeRenderWeight(right, selectedNode, selectedEdge);
    return leftWeight - rightWeight;
  });
  const renderedNodes = sortedNodes
    .map((node) => renderGraphNode(ctx, node, selectedNode, selectedEdge))
    .join("");

  return `
    <svg viewBox="0 0 ${width} ${height}" class="graph-svg" preserveAspectRatio="xMidYMid meet" aria-label="Topologie sítě" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
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
      ${ringRadii
        .map(
          (radius, index) =>
            `<circle cx="${centerX}" cy="${centerY}" r="${radius}" class="graph-ring graph-ring-${index + 1}"></circle>`,
        )
        .join("")}
      <circle cx="${centerX}" cy="${centerY}" r="${Math.max(42, orbit.availableRadius * 0.2)}" class="hub-halo"></circle>
      <g class="graph-edge-layer">${baseEdges}</g>
      <g class="graph-agent-layer">${agentLayer}</g>
      <g class="graph-node-layer">${renderedNodes}</g>
      <g class="graph-overlay-layer">${overlayEdge}</g>
    </svg>
  `;
}

function renderAgentLayer(ctx: UiRenderCtx, edges: GraphEdgeLike[]) {
  if (!edges.length) return "";
  const running = Boolean(ctx.state.automationStatus?.process_running);
  if (!running) return "";
  return collectAgentSignals(ctx).map((agent, index) => {
    const edgeIndex = index % edges.length;
    const duration = 6.8 + (index % 5) * 0.86;
    const delay = (index * 0.71) % duration;
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

function collectAgentSignals(ctx: UiRenderCtx) {
  const statusAgents = ctx.state.automationStatus?.agents ?? [];
  const latestAgents = ctx.state.automationLatest?.agents ?? [];
  const lanes = (ctx.getLanes(ctx.state.report) ?? [])
    .filter((lane: any) => lane.lane_type === "automation" || String(lane.source ?? "").includes("pentest") || String(lane.source ?? "").includes("decision"))
    .map((lane: any) => ({
      role: String(lane.source ?? "lane"),
      status: String(lane.status ?? "ok"),
      summary: String(lane.summary ?? lane.title ?? "Auditní agent"),
    }));
  const agents = statusAgents.length ? statusAgents : latestAgents.length ? latestAgents : lanes;
  return agents.slice(0, 14).map((agent: any, index: number) => {
    const role = String(agent.role ?? agent.agent_id ?? agent.source ?? "agent");
    return {
      role,
      label: agentLabel(role),
      glyph: agentGlyph(role, index),
      color: agentColor(role, String(agent.status ?? "")),
      summary: String(agent.summary ?? agent.status ?? "běží nad mapou"),
    };
  });
}

function agentLabel(role: string) {
  const text = role.toLowerCase();
  if (text.includes("pentest")) return "Pentest agent";
  if (text.includes("cve") || text.includes("intel")) return "Intel agent";
  if (text.includes("traffic") || text.includes("live") || text.includes("passive")) return "Traffic agent";
  if (text.includes("validation")) return "Validation agent";
  if (text.includes("ai") || text.includes("context")) return "AI context agent";
  if (text.includes("decision") || text.includes("risk")) return "Decision agent";
  return role.replaceAll("-", " ");
}

function agentGlyph(role: string, index: number) {
  const text = role.toLowerCase();
  if (text.includes("pentest")) return "P";
  if (text.includes("cve") || text.includes("intel")) return "I";
  if (text.includes("traffic") || text.includes("live") || text.includes("passive")) return "T";
  if (text.includes("validation")) return "V";
  if (text.includes("ai") || text.includes("context")) return "A";
  if (text.includes("decision") || text.includes("risk")) return "D";
  return String.fromCharCode(65 + (index % 26));
}

function agentColor(role: string, status: string) {
  const text = `${role} ${status}`.toLowerCase();
  if (text.includes("fail") || text.includes("kill")) return "#fb7185";
  if (text.includes("pentest")) return "#f97316";
  if (text.includes("cve") || text.includes("intel")) return "#fbbf24";
  if (text.includes("traffic") || text.includes("live") || text.includes("passive")) return "#34d399";
  if (text.includes("ai") || text.includes("context")) return "#38bdf8";
  return "#a78bfa";
}

function renderEdge(
  ctx: UiRenderCtx,
  edge: GraphEdgeLike,
  index: number,
  nodeMap: Map<string, GraphNodeLike>,
  centerX: number,
  centerY: number,
  selectedNode: GraphNodeLike | null,
  selectedEdge: GraphEdgeLike | null,
  overlay: boolean,
) {
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
  const strokeWidth = focus
    ? Math.min(5.4, 2.1 + edge.packets / 20)
    : context
      ? 1.8
      : 1.1;
  const opacity = overlay
    ? 1
    : focus
      ? 0.98
      : context
        ? 0.36
        : dimmed
          ? 0.06
          : 0.12;
  const pulseCount = focus && edge.active
    ? Math.min(4, Math.max(1, Math.round(edge.packets / 24)))
    : 0;
  const edgeClass = [
    "graph-edge-group",
    focus ? "is-focused" : "",
    context ? "is-context" : "",
    dimmed ? "is-dimmed" : "",
    overlay ? "is-overlay" : "",
  ]
    .filter(Boolean)
    .join(" ");

  return `
    <g class="${edgeClass}" data-edge-id="${ctx.escapeAttr(edge.id)}" data-edge-summary="${ctx.escapeAttr(`${edge.relation} · ${edge.packets} pkt · ${ctx.formatBytes(edge.bytes)}`)}" tabindex="0" role="button" aria-label="${ctx.escapeAttr(`${edge.relation}: ${edge.source} až ${edge.target}`)}">
      <path class="graph-edge ${edge.active ? "edge-active" : "edge-passive"}"
        style="stroke:${stroke};stroke-width:${strokeWidth};opacity:${opacity}"
        d="M ${source.x} ${source.y} Q ${control.x} ${control.y} ${target.x} ${target.y}"></path>
      ${
        pulseCount
          ? Array.from({ length: pulseCount }, (_, pulse) =>
              `<circle class="flow-pulse" r="${pulse === 0 ? 3.25 : 2.55}" fill="${risk}">
                 <animateMotion dur="${Math.max(1.8, 7.6 - Math.min(edge.packets, 180) / 26)}s" begin="${pulse * 0.52}s" repeatCount="indefinite" rotate="auto">
                   <mpath href="#graph-edge-${index}"></mpath>
                 </animateMotion>
               </circle>`,
            ).join("")
          : ""
      }
    </g>
  `;
}

function renderGraphNode(
  ctx: UiRenderCtx,
  node: GraphNodeLike,
  selectedNode: GraphNodeLike | null,
  selectedEdge: GraphEdgeLike | null,
) {
  const score = ctx.riskScoreFromIssueCounts(node.issueCounts);
  const stroke = node.riskColor ?? ctx.riskColorForScore(score);
  const radius = node.kind === "hub" ? 22 : node.kind === "core" ? 17.5 : node.kind === "external" ? 14.5 : 15.5;
  const selected = selectedNode?.id === node.id;
  const context = !selected && isContextNode(node, selectedNode, selectedEdge);
  const titleVisible = selected || (selectedEdge && (selectedEdge.source === node.id || selectedEdge.target === node.id));
  const classes = [
    "graph-node-group",
    selected ? "is-selected" : "",
    context ? "is-context" : "",
    titleVisible ? "show-title" : "",
  ]
    .filter(Boolean)
    .join(" ");

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

function buildEdgeControlPoint(
  source: GraphNodeLike,
  target: GraphNodeLike,
  centerX: number,
  centerY: number,
) {
  const midX = (source.x + target.x) / 2;
  const midY = (source.y + target.y) / 2;
  const inwardPull = source.kind === "external" || target.kind === "external" ? 0.08 : 0.16;
  return {
    x: midX + (centerX - midX) * inwardPull,
    y: midY + (centerY - midY) * inwardPull,
  };
}

function isFocusedEdge(
  edge: GraphEdgeLike,
  selectedNode: GraphNodeLike | null,
  selectedEdge: GraphEdgeLike | null,
) {
  if (selectedEdge) return edge.id === selectedEdge.id;
  if (selectedNode) return edge.source === selectedNode.id || edge.target === selectedNode.id;
  return false;
}

function isContextEdge(
  edge: GraphEdgeLike,
  selectedNode: GraphNodeLike | null,
  selectedEdge: GraphEdgeLike | null,
) {
  if (!selectedEdge) return false;
  return (
    edge.id !== selectedEdge.id &&
    [edge.source, edge.target].some(
      (nodeId) => nodeId === selectedEdge.source || nodeId === selectedEdge.target,
    )
  );
}

function isContextNode(
  node: GraphNodeLike,
  selectedNode: GraphNodeLike | null,
  selectedEdge: GraphEdgeLike | null,
) {
  if (selectedEdge) {
    return node.id === selectedEdge.source || node.id === selectedEdge.target;
  }
  if (selectedNode) {
    return selectedNode.connected.includes(node.id);
  }
  return false;
}

function nodeRenderWeight(
  node: GraphNodeLike,
  selectedNode: GraphNodeLike | null,
  selectedEdge: GraphEdgeLike | null,
) {
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
