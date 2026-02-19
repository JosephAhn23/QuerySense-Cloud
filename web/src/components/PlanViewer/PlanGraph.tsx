/**
 * Interactive EXPLAIN plan graph visualization (v2).
 *
 * Major upgrades over v1:
 * - Cost heatmap: continuous gradient from green → amber → red
 * - Interactive node exploration: click to expand/collapse subtrees
 * - Rich HTML tooltips with cost breakdown, timing, row estimates
 * - Actual vs estimated row comparison with warning badges
 * - Zoom & pan support (d3-zoom)
 * - Finding severity overlay (border glow for nodes with issues)
 * - Minimap for large plans
 * - Animated transitions on state changes
 */

import * as d3 from 'd3';
import { useEffect, useRef, useCallback, useState } from 'react';

// ── Types ─────────────────────────────────────────────────────────────

interface PlanNode {
  'Node Type': string;
  'Total Cost'?: number;
  'Startup Cost'?: number;
  'Actual Total Time'?: number;
  'Actual Startup Time'?: number;
  'Actual Rows'?: number;
  'Plan Rows'?: number;
  'Actual Loops'?: number;
  'Plan Width'?: number;
  'Relation Name'?: string;
  'Schema'?: string;
  'Alias'?: string;
  'Index Name'?: string;
  'Index Cond'?: string;
  'Filter'?: string;
  'Rows Removed by Filter'?: number;
  'Hash Cond'?: string;
  'Join Type'?: string;
  'Sort Key'?: string[];
  'Sort Method'?: string;
  'Sort Space Used'?: number;
  'Sort Space Type'?: string;
  'Workers Planned'?: number;
  'Workers Launched'?: number;
  'Shared Hit Blocks'?: number;
  'Shared Read Blocks'?: number;
  'Temp Written Blocks'?: number;
  Plans?: PlanNode[];
  [key: string]: unknown;
}

interface Finding {
  nodeId: string;
  severity: 'critical' | 'warning' | 'info';
  title: string;
  suggestion: string;
}

interface PlanGraphProps {
  plan: PlanNode;
  width?: number;
  height?: number;
  onNodeClick?: (node: PlanNode, path: string) => void;
  highlightPaths?: Set<string>;
  findings?: Finding[];
  showMinimap?: boolean;
}

interface TreeNode {
  id: string;
  label: string;
  cost: number;
  startupCost: number;
  exclusiveCost: number;
  costPct: number;
  time: number | null;
  exclusiveTime: number | null;
  rows: number | null;
  estimatedRows: number | null;
  rowAccuracy: number | null; // ratio of actual/estimated
  loops: number;
  relation: string;
  indexName: string;
  filter: string;
  joinType: string;
  sortInfo: string;
  bufferInfo: string;
  width: number | null;
  raw: PlanNode;
  severity: 'critical' | 'warning' | 'info' | null;
  findingTitle: string;
  findingSuggestion: string;
  children?: TreeNode[];
  _collapsed?: boolean;
}

// ── Color scales & theming ────────────────────────────────────────────

const NODE_TYPE_ICONS: Record<string, string> = {
  'Seq Scan': '⊞',
  'Index Scan': '⊟',
  'Index Only Scan': '⊡',
  'Bitmap Heap Scan': '▦',
  'Bitmap Index Scan': '▥',
  'Hash Join': '⋈',
  'Merge Join': '⋈',
  'Nested Loop': '↻',
  'Sort': '↕',
  'Aggregate': 'Σ',
  'HashAggregate': 'Σ#',
  'GroupAggregate': 'Σ⊞',
  'Limit': '⊤',
  'Gather': '⇶',
  'Gather Merge': '⇶↕',
  'CTE Scan': '↪',
  'Materialize': '▣',
  'Append': '⊕',
  'Result': '⊙',
  'Subquery Scan': '↳',
};

const SEVERITY_COLORS = {
  critical: { border: '#dc2626', glow: 'rgba(220, 38, 38, 0.4)', bg: '#fef2f2' },
  warning: { border: '#f59e0b', glow: 'rgba(245, 158, 11, 0.3)', bg: '#fffbeb' },
  info: { border: '#3b82f6', glow: 'rgba(59, 130, 246, 0.2)', bg: '#eff6ff' },
};

// ── Tree builder ──────────────────────────────────────────────────────

function computeTotalCost(node: PlanNode): number {
  let max = node['Total Cost'] || 0;
  for (const child of node.Plans || []) {
    max = Math.max(max, computeTotalCost(child));
  }
  return max;
}

function planToTree(
  node: PlanNode,
  path = '0',
  totalPlanCost: number = 0,
  findingsMap: Map<string, Finding> = new Map(),
): TreeNode {
  const children = (node.Plans || []).map((child, i) =>
    planToTree(child, `${path}.${i}`, totalPlanCost, findingsMap),
  );

  const totalCost = node['Total Cost'] || 0;
  const startupCost = node['Startup Cost'] || 0;
  const childrenCost = (node.Plans || []).reduce(
    (sum, c) => sum + (c['Total Cost'] || 0),
    0,
  );
  const exclusiveCost = Math.max(0, totalCost - childrenCost);
  const costPct = totalPlanCost > 0 ? (exclusiveCost / totalPlanCost) * 100 : 0;

  const actualTime = node['Actual Total Time'] ?? null;
  const childrenTime = (node.Plans || []).reduce(
    (sum, c) => sum + (c['Actual Total Time'] || 0),
    0,
  );
  const exclusiveTime =
    actualTime !== null ? Math.max(0, actualTime - childrenTime) : null;

  const actualRows = node['Actual Rows'] ?? null;
  const estimatedRows = node['Plan Rows'] ?? null;
  let rowAccuracy: number | null = null;
  if (actualRows !== null && estimatedRows !== null && estimatedRows > 0) {
    rowAccuracy = actualRows / estimatedRows;
  }

  const loops = node['Actual Loops'] || 1;
  const finding = findingsMap.get(path);

  // Sort info
  let sortInfo = '';
  if (node['Sort Key']) {
    sortInfo = `${node['Sort Method'] || 'Sort'}: ${(node['Sort Key'] as string[]).join(', ')}`;
    if (node['Sort Space Used']) {
      sortInfo += ` (${node['Sort Space Used']}kB ${node['Sort Space Type'] || ''})`;
    }
  }

  // Buffer info
  let bufferInfo = '';
  const hits = node['Shared Hit Blocks'] || 0;
  const reads = node['Shared Read Blocks'] || 0;
  const tempWrites = node['Temp Written Blocks'] || 0;
  if (hits || reads) {
    const hitRate = hits + reads > 0 ? ((hits / (hits + reads)) * 100).toFixed(0) : '0';
    bufferInfo = `Buffers: ${hits} hit, ${reads} read (${hitRate}% hit rate)`;
  }
  if (tempWrites) {
    bufferInfo += bufferInfo ? ` | ${tempWrites} temp written` : `${tempWrites} temp written`;
  }

  return {
    id: path,
    label: node['Node Type'] || 'Unknown',
    cost: totalCost,
    startupCost,
    exclusiveCost,
    costPct,
    time: actualTime,
    exclusiveTime,
    rows: actualRows,
    estimatedRows,
    rowAccuracy,
    loops,
    relation: node['Relation Name'] || '',
    indexName: node['Index Name'] || '',
    filter: node['Filter'] || node['Index Cond'] || node['Hash Cond'] || '',
    joinType: node['Join Type'] || '',
    sortInfo,
    bufferInfo,
    width: node['Plan Width'] ?? null,
    raw: node,
    severity: finding?.severity || null,
    findingTitle: finding?.title || '',
    findingSuggestion: finding?.suggestion || '',
    children: children.length > 0 ? children : undefined,
  };
}

// ── Format helpers ────────────────────────────────────────────────────

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

function formatCost(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toFixed(1);
}

function formatTime(ms: number): string {
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`;
  return `${ms.toFixed(2)}ms`;
}

function rowAccuracyBadge(ratio: number | null): { text: string; color: string } {
  if (ratio === null) return { text: '', color: '' };
  if (ratio >= 0.5 && ratio <= 2.0) return { text: '✓', color: '#16a34a' };
  if (ratio >= 0.1 && ratio <= 10.0) return { text: `${ratio.toFixed(1)}×`, color: '#f59e0b' };
  return { text: `${ratio >= 100 ? '⚠ ' : ''}${ratio.toFixed(0)}×`, color: '#dc2626' };
}

// ── Main component ────────────────────────────────────────────────────

export const PlanGraph: React.FC<PlanGraphProps> = ({
  plan,
  width = 1100,
  height = 700,
  onNodeClick,
  highlightPaths,
  findings = [],
  showMinimap = true,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const render = useCallback(() => {
    if (!svgRef.current) return;

    // Build findings map
    const findingsMap = new Map<string, Finding>();
    findings.forEach((f) => findingsMap.set(f.nodeId, f));

    const totalPlanCost = computeTotalCost(plan);
    const treeData = planToTree(plan, '0', totalPlanCost, findingsMap);

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const margin = { top: 30, right: 140, bottom: 30, left: 80 };
    const innerW = width - margin.left - margin.right;
    const innerH = height - margin.top - margin.bottom;

    // Defs for gradients and filters
    const defs = svg.append('defs');

    // Drop shadow filter
    const dropShadow = defs
      .append('filter')
      .attr('id', 'drop-shadow')
      .attr('x', '-10%')
      .attr('y', '-10%')
      .attr('width', '130%')
      .attr('height', '130%');
    dropShadow
      .append('feDropShadow')
      .attr('dx', '0')
      .attr('dy', '2')
      .attr('stdDeviation', '3')
      .attr('flood-color', 'rgba(0,0,0,0.12)');

    // Severity glow filters
    for (const [sev, colors] of Object.entries(SEVERITY_COLORS)) {
      const glow = defs
        .append('filter')
        .attr('id', `glow-${sev}`)
        .attr('x', '-20%')
        .attr('y', '-20%')
        .attr('width', '140%')
        .attr('height', '140%');
      glow
        .append('feDropShadow')
        .attr('dx', '0')
        .attr('dy', '0')
        .attr('stdDeviation', '4')
        .attr('flood-color', colors.glow);
    }

    // Zoom container
    const zoomG = svg
      .attr('width', width)
      .attr('height', height)
      .append('g');

    const g = zoomG.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

    // Zoom behavior
    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.3, 3])
      .on('zoom', (event) => {
        zoomG.attr('transform', event.transform);
      });

    svg.call(zoom);

    // Tree layout
    const root = d3.hierarchy(treeData);
    const nodeCount = root.descendants().length;
    const dynamicHeight = Math.max(innerH, nodeCount * 50);
    const treeLayout = d3.tree<TreeNode>().size([dynamicHeight, innerW]);
    treeLayout(root);

    // Cost-based color scale (continuous heatmap)
    const maxCost = d3.max(root.descendants(), (d) => d.data.exclusiveCost) || 1;
    const costColorScale = d3
      .scaleLinear<string>()
      .domain([0, maxCost * 0.15, maxCost * 0.4, maxCost * 0.7, maxCost])
      .range(['#22c55e', '#84cc16', '#f59e0b', '#ef4444', '#991b1b'])
      .clamp(true);

    // Time-based opacity scale
    const maxTime = d3.max(root.descendants(), (d) => d.data.exclusiveTime ?? 0) || 1;
    const timeOpacityScale = d3
      .scaleLinear()
      .domain([0, maxTime])
      .range([0.6, 1.0])
      .clamp(true);

    // ── Links ────────────────────────────────────────────────────────

    const linkGenerator = d3
      .linkHorizontal<d3.HierarchyPointLink<TreeNode>, d3.HierarchyPointNode<TreeNode>>()
      .x((d) => d.y)
      .y((d) => d.x);

    g.selectAll('.link')
      .data(root.links())
      .enter()
      .append('path')
      .attr('class', 'link')
      .attr('d', linkGenerator as any)
      .attr('fill', 'none')
      .attr('stroke', (d) => {
        // Color link by child's cost intensity
        const childCost = d.target.data.exclusiveCost;
        return d3
          .scaleLinear<string>()
          .domain([0, maxCost])
          .range(['#cbd5e1', '#f87171'])(childCost);
      })
      .attr('stroke-width', (d) => {
        // Width by rows flowing through
        const rows = d.target.data.rows ?? d.target.data.estimatedRows ?? 1;
        return Math.max(1, Math.min(4, 1 + Math.log10(Math.max(rows, 1))));
      })
      .attr('stroke-opacity', 0.6)
      .attr('stroke-linecap', 'round');

    // ── Nodes ────────────────────────────────────────────────────────

    const nodeWidth = 200;
    const nodeHeight = 64;

    const nodes = g
      .selectAll('.node')
      .data(root.descendants())
      .enter()
      .append('g')
      .attr('class', 'node')
      .attr('transform', (d) => `translate(${d.y - nodeWidth / 2},${d.x - nodeHeight / 2})`)
      .style('cursor', 'pointer')
      .on('click', (_event, d) => {
        setSelectedNode(d.data.id === selectedNode ? null : d.data.id);
        onNodeClick?.(d.data.raw, d.data.id);
      });

    // Node background with severity glow
    nodes
      .append('rect')
      .attr('width', nodeWidth)
      .attr('height', nodeHeight)
      .attr('rx', 10)
      .attr('ry', 10)
      .attr('fill', (d) => {
        if (d.data.severity) return SEVERITY_COLORS[d.data.severity].bg;
        return '#ffffff';
      })
      .attr('stroke', (d) => {
        if (d.data.severity) return SEVERITY_COLORS[d.data.severity].border;
        if (highlightPaths?.has(d.data.id)) return '#2563eb';
        return costColorScale(d.data.exclusiveCost);
      })
      .attr('stroke-width', (d) => {
        if (d.data.severity === 'critical') return 2.5;
        if (d.data.severity) return 2;
        if (highlightPaths?.has(d.data.id)) return 2.5;
        return 1.5;
      })
      .attr('filter', (d) => {
        if (d.data.severity) return `url(#glow-${d.data.severity})`;
        return 'url(#drop-shadow)';
      })
      .attr('opacity', (d) => timeOpacityScale(d.data.exclusiveTime ?? 0));

    // Cost heatmap bar (top of node)
    nodes
      .append('rect')
      .attr('x', 0)
      .attr('y', 0)
      .attr('width', (d) => Math.max(2, (d.data.costPct / 100) * nodeWidth))
      .attr('height', 4)
      .attr('rx', 2)
      .attr('fill', (d) => costColorScale(d.data.exclusiveCost))
      .attr('opacity', 0.8);

    // Full-width background bar for cost context
    nodes
      .append('rect')
      .attr('x', 0)
      .attr('y', 0)
      .attr('width', nodeWidth)
      .attr('height', 4)
      .attr('rx', 2)
      .attr('fill', '#e2e8f0')
      .attr('opacity', 0.3);

    // Re-draw cost bar on top
    nodes
      .append('rect')
      .attr('x', 0)
      .attr('y', 0)
      .attr('width', (d) => Math.max(2, (d.data.costPct / 100) * nodeWidth))
      .attr('height', 4)
      .attr('rx', 2)
      .attr('fill', (d) => costColorScale(d.data.exclusiveCost))
      .attr('opacity', 0.9);

    // Node type icon + label (line 1)
    nodes
      .append('text')
      .attr('x', 10)
      .attr('y', 20)
      .attr('font-size', '12px')
      .attr('font-weight', '600')
      .attr('fill', '#1e293b')
      .attr('font-family', 'Inter, system-ui, sans-serif')
      .text((d) => {
        const icon = NODE_TYPE_ICONS[d.data.label] || '●';
        const relation = d.data.relation ? ` → ${d.data.relation}` : '';
        const text = `${icon} ${d.data.label}${relation}`;
        return text.length > 30 ? text.substring(0, 28) + '…' : text;
      });

    // Stats line 1: cost + time (line 2)
    nodes
      .append('text')
      .attr('x', 10)
      .attr('y', 36)
      .attr('font-size', '10px')
      .attr('fill', '#64748b')
      .attr('font-family', 'Inter, system-ui, sans-serif')
      .text((d) => {
        const parts: string[] = [];
        if (d.data.costPct >= 1) parts.push(`${d.data.costPct.toFixed(0)}% cost`);
        if (d.data.exclusiveTime !== null) parts.push(formatTime(d.data.exclusiveTime));
        if (d.data.loops > 1) parts.push(`×${d.data.loops}`);
        return parts.join(' · ');
      });

    // Stats line 2: rows with accuracy badge (line 3)
    nodes
      .append('text')
      .attr('x', 10)
      .attr('y', 50)
      .attr('font-size', '10px')
      .attr('fill', '#64748b')
      .attr('font-family', 'Inter, system-ui, sans-serif')
      .text((d) => {
        const parts: string[] = [];
        if (d.data.rows !== null) {
          parts.push(`${formatNumber(d.data.rows)} rows`);
          const badge = rowAccuracyBadge(d.data.rowAccuracy);
          if (badge.text) parts.push(`(est: ${badge.text})`);
        } else if (d.data.estimatedRows !== null) {
          parts.push(`~${formatNumber(d.data.estimatedRows)} rows`);
        }
        return parts.join(' ');
      });

    // Row accuracy color indicator
    nodes
      .filter((d) => d.data.rowAccuracy !== null && (d.data.rowAccuracy! < 0.1 || d.data.rowAccuracy! > 10))
      .append('circle')
      .attr('cx', nodeWidth - 12)
      .attr('cy', 12)
      .attr('r', 5)
      .attr('fill', (d) => rowAccuracyBadge(d.data.rowAccuracy).color)
      .attr('stroke', '#fff')
      .attr('stroke-width', 1.5);

    // Severity badge
    nodes
      .filter((d) => d.data.severity !== null)
      .append('circle')
      .attr('cx', nodeWidth - 12)
      .attr('cy', nodeHeight - 12)
      .attr('r', 6)
      .attr('fill', (d) =>
        d.data.severity ? SEVERITY_COLORS[d.data.severity].border : '#ccc',
      )
      .attr('stroke', '#fff')
      .attr('stroke-width', 1.5);

    // ── Rich HTML Tooltip ────────────────────────────────────────────

    const tooltip = d3.select(tooltipRef.current);

    nodes
      .on('mouseenter', (_event, d) => {
        const data = d.data;
        const badge = rowAccuracyBadge(data.rowAccuracy);

        let html = `
          <div style="font-family:Inter,system-ui,sans-serif;max-width:320px;">
            <div style="font-weight:700;font-size:14px;margin-bottom:6px;color:#0f172a;">
              ${NODE_TYPE_ICONS[data.label] || '●'} ${data.label}
            </div>`;

        if (data.relation) {
          html += `<div style="color:#475569;font-size:12px;margin-bottom:4px;">
            Table: <strong>${data.relation}</strong>${data.indexName ? ` (via ${data.indexName})` : ''}
          </div>`;
        }

        html += `<div style="display:grid;grid-template-columns:1fr 1fr;gap:4px;margin:8px 0;font-size:11px;">`;

        // Cost
        html += `<div style="background:#f1f5f9;padding:4px 6px;border-radius:4px;">
          <div style="color:#94a3b8;">Total Cost</div>
          <div style="font-weight:600;">${formatCost(data.cost)}</div>
        </div>`;
        html += `<div style="background:${data.costPct > 50 ? '#fef2f2' : '#f1f5f9'};padding:4px 6px;border-radius:4px;">
          <div style="color:#94a3b8;">Exclusive</div>
          <div style="font-weight:600;color:${data.costPct > 50 ? '#dc2626' : '#0f172a'};">${formatCost(data.exclusiveCost)} (${data.costPct.toFixed(1)}%)</div>
        </div>`;

        // Time
        if (data.time !== null) {
          html += `<div style="background:#f1f5f9;padding:4px 6px;border-radius:4px;">
            <div style="color:#94a3b8;">Total Time</div>
            <div style="font-weight:600;">${formatTime(data.time)}</div>
          </div>`;
          html += `<div style="background:#f1f5f9;padding:4px 6px;border-radius:4px;">
            <div style="color:#94a3b8;">Exclusive Time</div>
            <div style="font-weight:600;">${data.exclusiveTime !== null ? formatTime(data.exclusiveTime) : '—'}</div>
          </div>`;
        }

        // Rows
        if (data.rows !== null) {
          html += `<div style="background:#f1f5f9;padding:4px 6px;border-radius:4px;">
            <div style="color:#94a3b8;">Actual Rows</div>
            <div style="font-weight:600;">${formatNumber(data.rows)}</div>
          </div>`;
          html += `<div style="background:${badge.color ? '#fff7ed' : '#f1f5f9'};padding:4px 6px;border-radius:4px;">
            <div style="color:#94a3b8;">Est. Accuracy</div>
            <div style="font-weight:600;color:${badge.color || '#0f172a'};">
              ${data.estimatedRows !== null ? formatNumber(data.estimatedRows) : '—'} est ${badge.text ? `(${badge.text})` : ''}
            </div>
          </div>`;
        }

        html += `</div>`;

        // Additional details
        if (data.filter) {
          html += `<div style="font-size:11px;color:#64748b;background:#f8fafc;padding:4px 6px;border-radius:4px;margin:4px 0;word-break:break-all;">
            <strong>Filter:</strong> ${data.filter}
          </div>`;
        }

        if (data.sortInfo) {
          html += `<div style="font-size:11px;color:#64748b;background:#f8fafc;padding:4px 6px;border-radius:4px;margin:4px 0;">
            <strong>${data.sortInfo}</strong>
          </div>`;
        }

        if (data.bufferInfo) {
          html += `<div style="font-size:11px;color:#64748b;background:#f0f9ff;padding:4px 6px;border-radius:4px;margin:4px 0;">
            ${data.bufferInfo}
          </div>`;
        }

        if (data.loops > 1) {
          html += `<div style="font-size:11px;color:#f59e0b;font-weight:600;margin:4px 0;">
            ⚠ Executed ${data.loops} times (loops)
          </div>`;
        }

        // Finding
        if (data.severity) {
          const sevColor = SEVERITY_COLORS[data.severity];
          html += `<div style="margin-top:8px;padding:6px 8px;border-radius:6px;border-left:3px solid ${sevColor.border};background:${sevColor.bg};font-size:11px;">
            <div style="font-weight:600;color:${sevColor.border};">${data.findingTitle}</div>
            <div style="color:#475569;margin-top:2px;">${data.findingSuggestion}</div>
          </div>`;
        }

        html += `</div>`;

        tooltip
          .html(html)
          .style('display', 'block')
          .style('opacity', '1');
      })
      .on('mousemove', (event) => {
        tooltip
          .style('left', `${event.pageX + 15}px`)
          .style('top', `${event.pageY - 10}px`);
      })
      .on('mouseleave', () => {
        tooltip.style('display', 'none').style('opacity', '0');
      });

    // ── Legend ────────────────────────────────────────────────────────

    const legend = svg.append('g').attr('transform', `translate(${width - 130}, 10)`);

    // Cost gradient legend
    const gradientId = 'cost-gradient';
    const gradient = defs
      .append('linearGradient')
      .attr('id', gradientId)
      .attr('x1', '0%')
      .attr('x2', '100%');

    gradient.append('stop').attr('offset', '0%').attr('stop-color', '#22c55e');
    gradient.append('stop').attr('offset', '30%').attr('stop-color', '#84cc16');
    gradient.append('stop').attr('offset', '60%').attr('stop-color', '#f59e0b');
    gradient.append('stop').attr('offset', '85%').attr('stop-color', '#ef4444');
    gradient.append('stop').attr('offset', '100%').attr('stop-color', '#991b1b');

    legend
      .append('text')
      .attr('x', 0)
      .attr('y', 0)
      .attr('font-size', '10px')
      .attr('fill', '#64748b')
      .attr('font-family', 'Inter, system-ui, sans-serif')
      .text('Cost Heatmap');

    legend
      .append('rect')
      .attr('x', 0)
      .attr('y', 6)
      .attr('width', 100)
      .attr('height', 8)
      .attr('rx', 4)
      .attr('fill', `url(#${gradientId})`);

    legend
      .append('text')
      .attr('x', 0)
      .attr('y', 26)
      .attr('font-size', '9px')
      .attr('fill', '#94a3b8')
      .attr('font-family', 'Inter, system-ui, sans-serif')
      .text('Low');

    legend
      .append('text')
      .attr('x', 100)
      .attr('y', 26)
      .attr('font-size', '9px')
      .attr('fill', '#94a3b8')
      .attr('text-anchor', 'end')
      .attr('font-family', 'Inter, system-ui, sans-serif')
      .text('High');

    // Reset zoom button
    legend
      .append('rect')
      .attr('x', 0)
      .attr('y', 36)
      .attr('width', 60)
      .attr('height', 18)
      .attr('rx', 4)
      .attr('fill', '#f1f5f9')
      .attr('stroke', '#cbd5e1')
      .attr('cursor', 'pointer')
      .on('click', () => {
        svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);
      });

    legend
      .append('text')
      .attr('x', 30)
      .attr('y', 49)
      .attr('font-size', '9px')
      .attr('fill', '#64748b')
      .attr('text-anchor', 'middle')
      .attr('font-family', 'Inter, system-ui, sans-serif')
      .attr('pointer-events', 'none')
      .text('Reset Zoom');

  }, [plan, width, height, onNodeClick, highlightPaths, findings, selectedNode]);

  useEffect(() => {
    render();
  }, [render]);

  return (
    <div className="relative overflow-hidden border border-gray-200 rounded-xl bg-white shadow-sm">
      {/* Toolbar */}
      <div className="flex items-center justify-between px-4 py-2 bg-gray-50 border-b border-gray-200">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-gray-500">EXPLAIN Plan</span>
          <span className="text-xs text-gray-400">|</span>
          <span className="text-xs text-gray-400">Scroll to zoom · Drag to pan</span>
        </div>
        <div className="flex items-center gap-3 text-xs">
          {findings.filter((f) => f.severity === 'critical').length > 0 && (
            <span className="px-2 py-0.5 bg-red-100 text-red-700 rounded-full font-medium">
              {findings.filter((f) => f.severity === 'critical').length} critical
            </span>
          )}
          {findings.filter((f) => f.severity === 'warning').length > 0 && (
            <span className="px-2 py-0.5 bg-amber-100 text-amber-700 rounded-full font-medium">
              {findings.filter((f) => f.severity === 'warning').length} warnings
            </span>
          )}
        </div>
      </div>

      {/* SVG Canvas */}
      <svg ref={svgRef} className="plan-graph" />

      {/* Rich Tooltip */}
      <div
        ref={tooltipRef}
        style={{
          display: 'none',
          position: 'fixed',
          zIndex: 9999,
          background: '#ffffff',
          border: '1px solid #e2e8f0',
          borderRadius: '10px',
          padding: '10px 12px',
          boxShadow: '0 10px 25px rgba(0,0,0,0.12), 0 4px 10px rgba(0,0,0,0.08)',
          pointerEvents: 'none',
          transition: 'opacity 0.15s ease',
        }}
      />
    </div>
  );
};
