"""
Planner What-If Engine -- simulate cost changes for index/knob combinations.

This is the core piece pganalyze keeps hidden: they extracted 470k LOC of the
PostgreSQL planner using libclang and run it standalone to estimate costs for
hypothetical indexes. We can't extract the planner, but we CAN build a
statistical cost model that approximates PostgreSQL's cost formulas:

  cost = (pages_read * page_cost) + (rows * cpu_cost)

Where:
  - Seq Scan cost    = relpages * seq_page_cost + reltuples * cpu_tuple_cost
  - Index Scan cost  = selectivity * relpages * random_page_cost + selectivity * reltuples * cpu_tuple_cost
  - Sort cost        = rows * log2(rows) * cpu_operator_cost + disk_spill_cost
  - Hash Join cost   = build_cost + probe_cost + hash_table_memory

This enables answering: "If I add index X and change work_mem to Y,
what would the estimated cost of query Z become?"

Usage:
    from querysense.planner_whatif import PlannerWhatIf, TableStatistics

    whatif = PlannerWhatIf()
    stats = whatif.collect_stats_from_plan(plan_json)
    result = whatif.simulate(stats, add_index=("orders", ["customer_id"]))
    print(f"Before: {result.before_cost:.0f}, After: {result.after_cost:.0f}")
    print(f"Improvement: {result.improvement_pct:.1f}%")
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any


# ---- PostgreSQL default cost constants ----

@dataclass
class CostConstants:
    """PostgreSQL planner cost constants (GUC parameters)."""
    seq_page_cost: float = 1.0
    random_page_cost: float = 4.0
    cpu_tuple_cost: float = 0.01
    cpu_index_tuple_cost: float = 0.005
    cpu_operator_cost: float = 0.0025
    parallel_tuple_cost: float = 0.1
    parallel_setup_cost: float = 1000.0
    effective_cache_size_pages: int = 524288  # 4GB default
    work_mem_kb: int = 4096  # 4MB default


@dataclass
class TableStatistics:
    """Statistics about a table, gathered from EXPLAIN or pg_class."""
    table_name: str
    relpages: int = 0          # Pages on disk
    reltuples: float = 0.0     # Estimated row count
    avg_row_width: int = 100   # Bytes per row
    indexes: list[IndexStatistics] = field(default_factory=list)
    # Column-level selectivities (estimated from plan or pg_stats)
    column_selectivities: dict[str, float] = field(default_factory=dict)
    # Pages cached in shared_buffers (estimated)
    cached_pages_ratio: float = 0.5


@dataclass
class IndexStatistics:
    """Statistics about an index."""
    index_name: str
    table_name: str
    columns: tuple[str, ...]
    index_type: str = "btree"
    index_pages: int = 0
    index_tuples: float = 0.0
    avg_selectivity: float = 0.01  # Average selectivity for leading column
    is_unique: bool = False
    is_partial: bool = False
    is_hypothetical: bool = False


@dataclass
class ScanCostEstimate:
    """Cost estimate for a single scan operation."""
    scan_type: str           # seq_scan, index_scan, index_only_scan, bitmap_scan
    table: str
    index_name: str = ""
    total_cost: float = 0.0
    startup_cost: float = 0.0
    rows_returned: float = 0.0
    pages_read: float = 0.0
    # Breakdown
    io_cost: float = 0.0
    cpu_cost: float = 0.0


@dataclass
class WhatIfResult:
    """Result of a what-if simulation."""
    description: str
    before_cost: float
    after_cost: float
    improvement_pct: float
    before_scan: ScanCostEstimate | None = None
    after_scan: ScanCostEstimate | None = None
    # Additional context
    notes: list[str] = field(default_factory=list)
    sql_to_apply: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "before_cost": round(self.before_cost, 2),
            "after_cost": round(self.after_cost, 2),
            "improvement_pct": round(self.improvement_pct, 2),
            "notes": self.notes,
            "sql_to_apply": self.sql_to_apply,
        }


@dataclass
class WhatIfBatchResult:
    """Result of simulating multiple what-if scenarios."""
    scenarios: list[WhatIfResult] = field(default_factory=list)
    best_scenario: WhatIfResult | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_count": len(self.scenarios),
            "best": self.best_scenario.to_dict() if self.best_scenario else None,
            "all_scenarios": [s.to_dict() for s in self.scenarios],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def format_text(self) -> str:
        lines: list[str] = []
        lines.append("")
        lines.append("  PLANNER WHAT-IF SIMULATION")
        lines.append("  " + "=" * 60)
        lines.append(f"  Scenarios tested: {len(self.scenarios)}")
        if self.best_scenario:
            lines.append(f"  Best: {self.best_scenario.description}")
            lines.append(
                f"    Cost: {self.best_scenario.before_cost:.0f} -> "
                f"{self.best_scenario.after_cost:.0f} "
                f"({self.best_scenario.improvement_pct:+.1f}%)"
            )
        lines.append("")

        for i, s in enumerate(self.scenarios, 1):
            direction = "BETTER" if s.improvement_pct > 0 else "WORSE" if s.improvement_pct < 0 else "SAME"
            lines.append(f"  {i}. {s.description} [{direction}]")
            lines.append(
                f"     Cost: {s.before_cost:.0f} -> {s.after_cost:.0f} "
                f"({s.improvement_pct:+.1f}%)"
            )
            if s.sql_to_apply:
                lines.append(f"     SQL: {s.sql_to_apply[:100]}")
            for n in s.notes:
                lines.append(f"     Note: {n}")
            lines.append("")

        return "\n".join(lines)


class PlannerWhatIf:
    """
    Simulate PostgreSQL planner cost changes for hypothetical configurations.

    Approximates PostgreSQL's cost model using the same formulas from
    src/backend/optimizer/path/costsize.c. Not exact (we don't have the
    full planner), but accurate enough to predict direction and magnitude
    of cost changes.
    """

    def __init__(self, costs: CostConstants | None = None):
        self.costs = costs or CostConstants()

    # ---- Cost formulas (from costsize.c) ----

    def seq_scan_cost(
        self, relpages: int, reltuples: float,
        selectivity: float = 1.0,
    ) -> ScanCostEstimate:
        """Estimate sequential scan cost."""
        io = relpages * self.costs.seq_page_cost
        cpu = reltuples * self.costs.cpu_tuple_cost
        # Filter selectivity reduces CPU cost for post-filter
        output_rows = reltuples * selectivity

        return ScanCostEstimate(
            scan_type="seq_scan",
            table="",
            total_cost=io + cpu,
            startup_cost=0.0,
            rows_returned=output_rows,
            pages_read=relpages,
            io_cost=io,
            cpu_cost=cpu,
        )

    def index_scan_cost(
        self,
        relpages: int,
        reltuples: float,
        index_pages: int,
        selectivity: float,
        index_correlation: float = 0.0,
    ) -> ScanCostEstimate:
        """
        Estimate index scan cost.

        Uses the Mackert-Lohman formula for estimating pages fetched,
        which PostgreSQL uses internally.
        """
        # Pages fetched estimate (Mackert-Lohman)
        rows_fetched = reltuples * selectivity
        if rows_fetched <= 0:
            rows_fetched = 1

        # For correlated indexes, pages fetched is much lower
        if index_correlation > 0.9:
            # Highly correlated: nearly sequential access
            pages_fetched = selectivity * relpages
        else:
            # Uncorrelated: Mackert-Lohman approximation
            pages_fetched = self._mackert_lohman(
                relpages, rows_fetched, self.costs.effective_cache_size_pages
            )

        # I/O cost: mix of random and sequential depending on correlation
        random_fraction = 1.0 - abs(index_correlation)
        io_cost = (
            pages_fetched * random_fraction * self.costs.random_page_cost +
            pages_fetched * (1 - random_fraction) * self.costs.seq_page_cost
        )

        # Index traversal cost
        index_io = math.log2(max(1, index_pages)) * self.costs.random_page_cost
        index_cpu = rows_fetched * self.costs.cpu_index_tuple_cost

        # CPU cost for filtering
        cpu_cost = rows_fetched * self.costs.cpu_tuple_cost

        total = io_cost + index_io + index_cpu + cpu_cost
        startup = index_io  # Must traverse index tree first

        return ScanCostEstimate(
            scan_type="index_scan",
            table="",
            total_cost=total,
            startup_cost=startup,
            rows_returned=rows_fetched,
            pages_read=pages_fetched,
            io_cost=io_cost + index_io,
            cpu_cost=index_cpu + cpu_cost,
        )

    def bitmap_scan_cost(
        self,
        relpages: int,
        reltuples: float,
        index_pages: int,
        selectivity: float,
    ) -> ScanCostEstimate:
        """Estimate bitmap scan cost (index scan + heap fetch in page order)."""
        rows_fetched = reltuples * selectivity
        # Bitmap sorts by page, so heap access is more sequential
        pages_fetched = min(
            relpages,
            self._mackert_lohman(relpages, rows_fetched, self.costs.effective_cache_size_pages),
        )

        # Cost is like sequential for heap pages (sorted by bitmap)
        io_cost = pages_fetched * self.costs.seq_page_cost
        # Plus index traversal
        index_io = math.log2(max(1, index_pages)) * self.costs.random_page_cost

        cpu_cost = rows_fetched * (self.costs.cpu_tuple_cost + self.costs.cpu_operator_cost)
        total = io_cost + index_io + cpu_cost

        return ScanCostEstimate(
            scan_type="bitmap_scan",
            table="",
            total_cost=total,
            startup_cost=index_io + pages_fetched * 0.01,  # Bitmap build
            rows_returned=rows_fetched,
            pages_read=pages_fetched,
            io_cost=io_cost + index_io,
            cpu_cost=cpu_cost,
        )

    def sort_cost(
        self, rows: float, width: int,
    ) -> float:
        """Estimate sort cost."""
        if rows <= 0:
            return 0.0

        comparison_cost = rows * math.log2(max(2, rows)) * self.costs.cpu_operator_cost

        # Check if sort fits in work_mem
        sort_bytes = rows * width
        work_mem_bytes = self.costs.work_mem_kb * 1024

        if sort_bytes > work_mem_bytes:
            # External sort (disk spill)
            disk_pages = sort_bytes / 8192
            disk_cost = disk_pages * self.costs.seq_page_cost * 2  # Read + write
            return comparison_cost + disk_cost
        else:
            return comparison_cost

    def hash_join_cost(
        self,
        outer_rows: float,
        inner_rows: float,
        inner_width: int,
    ) -> float:
        """Estimate hash join cost (build + probe)."""
        # Build hash table
        build_cpu = inner_rows * self.costs.cpu_operator_cost
        # Probe hash table
        probe_cpu = outer_rows * self.costs.cpu_operator_cost

        # Check if hash table fits in work_mem
        hash_bytes = inner_rows * (inner_width + 32)  # 32 bytes overhead per entry
        work_mem_bytes = self.costs.work_mem_kb * 1024

        if hash_bytes > work_mem_bytes:
            # Multi-batch hash join
            batches = math.ceil(hash_bytes / work_mem_bytes)
            disk_cost = (inner_rows + outer_rows) * 8192 / inner_width * self.costs.seq_page_cost
            return build_cpu + probe_cpu + disk_cost
        else:
            return build_cpu + probe_cpu

    # ---- What-If Simulation ----

    def simulate_add_index(
        self,
        table_stats: TableStatistics,
        index_columns: list[str],
        index_type: str = "btree",
        filter_selectivity: float = 0.01,
    ) -> WhatIfResult:
        """
        Simulate what happens when we add an index.

        Compares current seq scan cost vs hypothetical index scan cost.
        """
        # Current cost: sequential scan
        before = self.seq_scan_cost(
            table_stats.relpages,
            table_stats.reltuples,
            selectivity=filter_selectivity,
        )
        before.table = table_stats.table_name

        # Estimate index size
        # Rough: index pages ~ relpages * selectivity * column_fraction
        col_width = len(index_columns) * 8  # 8 bytes per column average
        row_width = max(table_stats.avg_row_width, 1)
        index_fraction = col_width / row_width
        index_pages = max(1, int(table_stats.relpages * index_fraction * 0.7))

        # Get selectivity from column stats if available
        sel = filter_selectivity
        for col in index_columns:
            if col in table_stats.column_selectivities:
                sel = min(sel, table_stats.column_selectivities[col])

        # After cost: index scan
        after = self.index_scan_cost(
            table_stats.relpages,
            table_stats.reltuples,
            index_pages=index_pages,
            selectivity=sel,
        )
        after.table = table_stats.table_name

        improvement = 0.0
        if before.total_cost > 0:
            improvement = (before.total_cost - after.total_cost) / before.total_cost * 100

        notes: list[str] = []
        if sel < 0.001:
            notes.append(f"Highly selective ({sel:.4%}) -- index scan very effective")
        elif sel > 0.3:
            notes.append(f"Low selectivity ({sel:.0%}) -- planner may still choose seq scan")

        if table_stats.relpages < 10:
            notes.append("Small table -- index overhead may not be worth it")

        idx_name = f"idx_{table_stats.table_name}_{'_'.join(index_columns)}"
        create_sql = (
            f"CREATE INDEX CONCURRENTLY {idx_name} "
            f"ON {table_stats.table_name} ({', '.join(index_columns)});"
        )

        return WhatIfResult(
            description=f"Add {index_type} index on {table_stats.table_name}({', '.join(index_columns)})",
            before_cost=before.total_cost,
            after_cost=after.total_cost,
            improvement_pct=improvement,
            before_scan=before,
            after_scan=after,
            notes=notes,
            sql_to_apply=create_sql,
        )

    def simulate_knob_change(
        self,
        table_stats: TableStatistics,
        knob: str,
        new_value: Any,
        current_scan_type: str = "seq_scan",
        filter_selectivity: float = 0.01,
    ) -> WhatIfResult:
        """Simulate changing a PostgreSQL GUC parameter."""
        # Save current costs
        old_costs = CostConstants(
            seq_page_cost=self.costs.seq_page_cost,
            random_page_cost=self.costs.random_page_cost,
            cpu_tuple_cost=self.costs.cpu_tuple_cost,
            work_mem_kb=self.costs.work_mem_kb,
            effective_cache_size_pages=self.costs.effective_cache_size_pages,
        )

        # Calculate before cost
        before = self._scan_cost(table_stats, current_scan_type, filter_selectivity)

        # Apply knob change
        knob_lower = knob.lower()
        sql = ""
        if knob_lower == "work_mem":
            self.costs.work_mem_kb = self._parse_memory(new_value)
            sql = f"ALTER SYSTEM SET work_mem = '{new_value}';"
        elif knob_lower == "random_page_cost":
            self.costs.random_page_cost = float(new_value)
            sql = f"ALTER SYSTEM SET random_page_cost = {new_value};"
        elif knob_lower == "seq_page_cost":
            self.costs.seq_page_cost = float(new_value)
            sql = f"ALTER SYSTEM SET seq_page_cost = {new_value};"
        elif knob_lower == "effective_cache_size":
            self.costs.effective_cache_size_pages = self._parse_memory(new_value) * 1024 // 8
            sql = f"ALTER SYSTEM SET effective_cache_size = '{new_value}';"
        elif knob_lower == "cpu_tuple_cost":
            self.costs.cpu_tuple_cost = float(new_value)
            sql = f"ALTER SYSTEM SET cpu_tuple_cost = {new_value};"

        # Calculate after cost
        after = self._scan_cost(table_stats, current_scan_type, filter_selectivity)

        # Restore original costs
        self.costs = old_costs

        improvement = 0.0
        if before.total_cost > 0:
            improvement = (before.total_cost - after.total_cost) / before.total_cost * 100

        return WhatIfResult(
            description=f"Change {knob} to {new_value}",
            before_cost=before.total_cost,
            after_cost=after.total_cost,
            improvement_pct=improvement,
            before_scan=before,
            after_scan=after,
            sql_to_apply=sql,
        )

    def simulate_batch(
        self,
        table_stats: TableStatistics,
        scenarios: list[dict[str, Any]],
    ) -> WhatIfBatchResult:
        """
        Run multiple what-if scenarios and rank by improvement.

        Each scenario is a dict with:
            {"type": "add_index", "columns": [...], "selectivity": 0.01}
            {"type": "knob", "knob": "work_mem", "value": "256MB"}
        """
        results: list[WhatIfResult] = []

        for scenario in scenarios:
            stype = scenario.get("type", "")
            if stype == "add_index":
                r = self.simulate_add_index(
                    table_stats,
                    index_columns=scenario.get("columns", []),
                    index_type=scenario.get("index_type", "btree"),
                    filter_selectivity=scenario.get("selectivity", 0.01),
                )
            elif stype == "knob":
                r = self.simulate_knob_change(
                    table_stats,
                    knob=scenario["knob"],
                    new_value=scenario["value"],
                    filter_selectivity=scenario.get("selectivity", 0.01),
                )
            else:
                continue
            results.append(r)

        results.sort(key=lambda x: -x.improvement_pct)
        best = results[0] if results else None

        return WhatIfBatchResult(scenarios=results, best_scenario=best)

    def collect_stats_from_plan(
        self, plan_data: dict[str, Any] | list,
    ) -> list[TableStatistics]:
        """Extract table statistics from an EXPLAIN plan."""
        plan = self._extract_plan(plan_data)
        if not plan:
            return []

        tables: dict[str, TableStatistics] = {}
        self._walk_plan_for_stats(plan, tables)
        return list(tables.values())

    # ---- Internal helpers ----

    def _scan_cost(
        self, stats: TableStatistics, scan_type: str, selectivity: float,
    ) -> ScanCostEstimate:
        """Calculate scan cost based on scan type."""
        if scan_type == "index_scan" and stats.indexes:
            idx = stats.indexes[0]
            return self.index_scan_cost(
                stats.relpages, stats.reltuples,
                idx.index_pages, selectivity,
            )
        return self.seq_scan_cost(stats.relpages, stats.reltuples, selectivity)

    def _mackert_lohman(
        self, relpages: int, rows_fetched: float, cache_pages: int,
    ) -> float:
        """
        Mackert-Lohman formula for estimating pages fetched.

        This is PostgreSQL's method for estimating how many disk pages
        must be fetched given T (total pages), n (rows fetched), and
        b (effective cache size).
        """
        t = max(1, relpages)
        n = max(1, rows_fetched)
        b = max(1, cache_pages)

        if n >= t:
            return float(t)

        # Simplified Mackert-Lohman
        if t <= b:
            # Table fits in cache
            return min(n, t)
        else:
            # Estimated via birthday paradox approximation
            fraction = n / t
            if fraction >= 1.0:
                return float(t)
            pages = t * (1.0 - math.exp(-n / t))
            return min(pages, t)

    def _walk_plan_for_stats(
        self, node: dict[str, Any], tables: dict[str, TableStatistics],
    ) -> None:
        """Extract table stats from plan nodes."""
        rel = node.get("Relation Name", "")
        if rel and rel not in tables:
            rows = node.get("Actual Rows") or node.get("Plan Rows", 0)
            width = node.get("Plan Width") or 100

            # Estimate relpages from rows and width
            row_bytes = rows * width
            relpages = max(1, row_bytes // 8192)

            ts = TableStatistics(
                table_name=rel,
                relpages=relpages,
                reltuples=float(rows),
                avg_row_width=width,
            )

            # Extract selectivity from filter
            filt = node.get("Filter", "")
            removed = node.get("Rows Removed by Filter") or 0
            actual = node.get("Actual Rows") or 0
            if removed > 0 and actual > 0:
                sel = actual / (actual + removed)
                # Try to extract column name
                import re
                col_match = re.search(r'\((\w+)\s*[=<>]', filt)
                if col_match:
                    ts.column_selectivities[col_match.group(1)] = sel

            # Capture existing index info
            idx_name = node.get("Index Name")
            if idx_name:
                ts.indexes.append(IndexStatistics(
                    index_name=idx_name,
                    table_name=rel,
                    columns=(),
                    index_pages=max(1, relpages // 3),
                    index_tuples=float(rows),
                ))

            tables[rel] = ts

        for child in node.get("Plans", []):
            self._walk_plan_for_stats(child, tables)

    def _parse_memory(self, value: Any) -> int:
        """Parse memory value like '128MB' to KB."""
        s = str(value).upper().strip()
        if s.endswith("GB"):
            return int(float(s[:-2]) * 1024 * 1024)
        if s.endswith("MB"):
            return int(float(s[:-2]) * 1024)
        if s.endswith("KB"):
            return int(float(s[:-2]))
        return int(float(s))

    def _extract_plan(self, data: Any) -> dict[str, Any] | None:
        if isinstance(data, list) and data:
            data = data[0]
        if isinstance(data, dict):
            return data.get("Plan", data if "Node Type" in data else None)
        return None
