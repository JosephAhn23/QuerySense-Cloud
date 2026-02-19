"""
Buffer Cache Visualizer — HTML dashboard from pg_buffercache snapshots.

Generates self-contained HTML with charts using lightweight embedded
JavaScript (no plotly dependency required). Falls back to rich tables
for CLI output.

Based on pganalyze System Memory dashboard.

Usage:
    from querysense.buffer_cache_viz import BufferCacheVisualizer
    viz = BufferCacheVisualizer(tracker)
    html = viz.generate_html_dashboard()
    Path("cache_dashboard.html").write_text(html)
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from querysense.buffer_cache_tracker import BufferCacheTracker


class BufferCacheVisualizer:
    """
    Generate visualizations for buffer cache monitoring.

    Outputs:
    - Self-contained HTML dashboard (no external dependencies)
    - Rich console tables for CLI
    - JSON data for custom integrations
    """

    def __init__(self, tracker: BufferCacheTracker) -> None:
        self.tracker = tracker

    def get_chart_data(self) -> dict[str, Any]:
        """Get structured data suitable for charting."""
        dashboard = self.tracker.get_dashboard()
        snapshots = self.tracker.snapshots

        # Hit ratio over time
        hit_ratios = [
            {"ts": s.timestamp.isoformat(), "ratio": round(s.cache_hit_ratio * 100, 2)}
            for s in snapshots[-48:]
        ]

        # Utilization over time
        utilization = [
            {"ts": s.timestamp.isoformat(), "pct": round(s.utilization_pct, 1)}
            for s in snapshots[-48:]
        ]

        # Top tables over time (heatmap data)
        all_tables: set[str] = set()
        for s in snapshots[-24:]:
            for rel in s.top_tables[:10]:
                all_tables.add(rel.full_name)

        table_names = sorted(all_tables)[:15]
        heatmap: list[dict[str, Any]] = []
        for s in snapshots[-24:]:
            table_map = {r.full_name: r.buffers for r in s.relations}
            row = {"ts": s.timestamp.isoformat()}
            for t in table_names:
                row[t] = table_map.get(t, 0)
            heatmap.append(row)

        return {
            "current": {
                "utilization_pct": dashboard.utilization_pct,
                "hit_ratio_pct": dashboard.hit_ratio_pct,
                "total_buffers": dashboard.current.total_buffers if dashboard.current else 0,
                "buffers_used": dashboard.current.buffers_used if dashboard.current else 0,
            },
            "top_tables": dashboard.top_tables,
            "top_indexes": dashboard.top_indexes,
            "outliers": dashboard.outliers,
            "recommendations": dashboard.recommendations,
            "hit_ratio_history": hit_ratios,
            "utilization_history": utilization,
            "heatmap_tables": table_names,
            "heatmap_data": heatmap,
        }

    def generate_html_dashboard(self) -> str:
        """Generate a self-contained HTML dashboard."""
        data = self.get_chart_data()
        data_json = json.dumps(data, default=str)

        return _HTML_TEMPLATE.replace("__DATA__", data_json)

    def print_cli_summary(self) -> None:
        """Print a rich CLI summary of the current cache state."""
        try:
            from rich.console import Console
            from rich.table import Table
            from rich.panel import Panel
        except ImportError:
            print("rich not installed — install with: pip install rich")
            return

        console = Console()
        dashboard = self.tracker.get_dashboard()

        console.print(Panel(
            f"[bold]Utilization:[/bold] {dashboard.utilization_pct:.1f}%\n"
            f"[bold]Hit ratio:[/bold] {dashboard.hit_ratio_pct:.2f}%\n"
            f"[bold]Snapshots:[/bold] {dashboard.snapshots_count}",
            title="Buffer Cache Status",
        ))

        if dashboard.top_tables:
            tbl = Table(title="Top Tables in Cache")
            tbl.add_column("Table", style="bold")
            tbl.add_column("Buffers", justify="right")
            tbl.add_column("Size (MB)", justify="right")
            for t in dashboard.top_tables[:10]:
                tbl.add_row(t["name"], str(t["buffers"]), f"{t['size_mb']:.1f}")
            console.print(tbl)

        if dashboard.top_indexes:
            tbl = Table(title="Top Indexes in Cache")
            tbl.add_column("Index", style="bold")
            tbl.add_column("Buffers", justify="right")
            for idx in dashboard.top_indexes[:10]:
                tbl.add_row(idx["name"], str(idx["buffers"]))
            console.print(tbl)

        if dashboard.outliers:
            console.print("\n[bold yellow]Cache Outliers:[/bold yellow]")
            for o in dashboard.outliers:
                console.print(
                    f"  {o['name']}: {o['buffers']} buffers, "
                    f"presence {o['presence_ratio']:.0%} — {o['note']}"
                )

        for rec in dashboard.recommendations:
            sev = rec["severity"]
            color = {"WARNING": "yellow", "INFO": "cyan"}.get(sev, "white")
            console.print(f"  [{color}]{sev}[/{color}] {rec['message']}")


# ── Self-contained HTML template ─────────────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>QuerySense — Buffer Cache Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:#0d1117;color:#c9d1d9;padding:1.5rem}
h1{font-size:1.5rem;margin-bottom:1rem;color:#58a6ff}
h2{font-size:1.1rem;margin:1.2rem 0 .6rem;color:#79c0ff}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem}
.metric{font-size:2rem;font-weight:700;color:#58a6ff}
.label{font-size:.85rem;color:#8b949e}
table{width:100%;border-collapse:collapse;margin-top:.5rem}
th,td{text-align:left;padding:.35rem .5rem;border-bottom:1px solid #21262d}
th{color:#8b949e;font-weight:600;font-size:.8rem;text-transform:uppercase}
td{font-size:.9rem}
.bar{height:12px;border-radius:3px;background:#238636}
.sev-WARNING{color:#d29922}.sev-INFO{color:#58a6ff}.sev-CRITICAL{color:#f85149}
canvas{width:100%!important;height:200px!important}
</style>
</head>
<body>
<h1>Buffer Cache Dashboard</h1>

<div class="grid" id="metrics"></div>
<div class="grid" style="margin-top:1rem">
  <div class="card"><h2>Top Tables</h2><div id="top-tables"></div></div>
  <div class="card"><h2>Top Indexes</h2><div id="top-indexes"></div></div>
</div>
<div class="card" style="margin-top:1rem"><h2>Cache Hit Ratio</h2><canvas id="hitChart"></canvas></div>
<div class="card" style="margin-top:1rem"><h2>Outliers</h2><div id="outliers"></div></div>
<div class="card" style="margin-top:1rem"><h2>Recommendations</h2><div id="recs"></div></div>

<script>
const D=JSON.parse('__DATA__');

// Metrics
document.getElementById('metrics').innerHTML=`
  <div class="card"><div class="metric">${D.current.utilization_pct.toFixed(1)}%</div><div class="label">Cache Utilization</div></div>
  <div class="card"><div class="metric">${D.current.hit_ratio_pct.toFixed(2)}%</div><div class="label">Hit Ratio</div></div>
  <div class="card"><div class="metric">${D.current.buffers_used.toLocaleString()}</div><div class="label">Buffers Used / ${D.current.total_buffers.toLocaleString()}</div></div>
`;

function makeTable(data,cols){
  let h='<table><tr>'+cols.map(c=>'<th>'+c.label+'</th>').join('')+'</tr>';
  const mx=Math.max(...data.map(r=>r.buffers||0),1);
  data.forEach(r=>{
    h+='<tr>'+cols.map(c=>{
      if(c.key==='bar') return '<td><div class="bar" style="width:'+((r.buffers/mx)*100)+'%"></div></td>';
      return '<td>'+(r[c.key]??'')+'</td>';
    }).join('')+'</tr>';
  });
  return h+'</table>';
}

document.getElementById('top-tables').innerHTML=makeTable(D.top_tables,[{key:'name',label:'Table'},{key:'buffers',label:'Buffers'},{key:'size_mb',label:'Size MB'},{key:'bar',label:''}]);
document.getElementById('top-indexes').innerHTML=makeTable(D.top_indexes,[{key:'name',label:'Index'},{key:'buffers',label:'Buffers'},{key:'bar',label:''}]);

// Outliers
document.getElementById('outliers').innerHTML=D.outliers.length?
  D.outliers.map(o=>'<p><strong>'+o.name+'</strong>: '+o.buffers+' buffers (presence '+Math.round(o.presence_ratio*100)+'%) &mdash; '+o.note+'</p>').join(''):
  '<p style="color:#8b949e">No outliers detected</p>';

// Recommendations
document.getElementById('recs').innerHTML=D.recommendations.length?
  D.recommendations.map(r=>'<p class="sev-'+r.severity+'"><strong>'+r.severity+'</strong> '+r.message+'</p>').join(''):
  '<p style="color:#8b949e">No recommendations</p>';

// Hit ratio chart (lightweight canvas)
const canvas=document.getElementById('hitChart');
if(canvas&&D.hit_ratio_history.length>1){
  const ctx=canvas.getContext('2d');
  const W=canvas.parentElement.clientWidth-32;
  const H=200;canvas.width=W;canvas.height=H;
  const pts=D.hit_ratio_history;
  const mn=Math.min(...pts.map(p=>p.ratio))-0.5;
  const mx=Math.max(...pts.map(p=>p.ratio))+0.5;
  const xStep=W/(pts.length-1);
  ctx.strokeStyle='#58a6ff';ctx.lineWidth=2;ctx.beginPath();
  pts.forEach((p,i)=>{
    const x=i*xStep;const y=H-(p.ratio-mn)/(mx-mn)*H;
    i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);
  });
  ctx.stroke();
  ctx.fillStyle='#8b949e';ctx.font='11px sans-serif';
  ctx.fillText(mn.toFixed(1)+'%',4,H-4);
  ctx.fillText(mx.toFixed(1)+'%',4,14);
}
</script>
</body>
</html>
"""
