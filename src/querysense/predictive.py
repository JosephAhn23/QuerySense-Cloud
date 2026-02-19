"""
Predictive Workload Optimizer -- move from reactive to predictive.

Implements DBtune-style "Workload Fingerprinting":
1. Identify the most performance-critical queries (weighted by frequency x cost)
2. Generate optimization candidates (index, knob, rewrite)
3. Estimate impact WITHOUT running against a real DB (statistical model)
4. Rank by predicted improvement / risk ratio

This is the bridge between rule-based analysis (current) and ML-powered
optimization (future). The statistical models here are interpretable
and deterministic -- no black boxes.

Usage:
    from querysense.predictive import PredictiveOptimizer, WorkloadFingerprint

    optimizer = PredictiveOptimizer()
    fingerprint = optimizer.fingerprint_workload(queries)
    plan = optimizer.optimize(fingerprint)
    for rec in plan.recommendations:
        print(f"{rec.description} -- predicted improvement: {rec.predicted_speedup:.1f}x")
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CandidateType(str, Enum):
    INDEX = "index"
    KNOB = "knob"
    REWRITE = "rewrite"
    PARTITIONING = "partitioning"
    MATERIALIZED_VIEW = "materialized_view"


@dataclass
class QueryFingerprint:
    """A single query's performance fingerprint."""
    template: str                   # Normalized SQL template
    template_hash: str              # SHA256 of template
    frequency: int = 1             # How often it runs
    avg_cost: float = 0.0          # Average plan cost
    avg_execution_ms: float = 0.0  # Average execution time
    total_cost: float = 0.0        # frequency * avg_cost
    tables: list[str] = field(default_factory=list)
    filter_columns: list[str] = field(default_factory=list)
    join_columns: list[str] = field(default_factory=list)
    sort_columns: list[str] = field(default_factory=list)
    is_seq_scan: bool = False
    estimated_rows: int = 0
    actual_rows: int = 0
    row_estimate_error: float = 0.0  # |actual - estimated| / max(actual, 1)
    has_disk_spill: bool = False
    has_nested_loop: bool = False
    node_types: list[str] = field(default_factory=list)

    @property
    def criticality_score(self) -> float:
        """How critical is this query to overall performance? (0-100)"""
        # Weight by frequency * cost, penalize for estimation errors
        base = math.log1p(self.frequency) * math.log1p(self.avg_cost)
        error_penalty = 1.0 + self.row_estimate_error
        return min(100.0, base * error_penalty)


@dataclass
class WorkloadFingerprint:
    """Fingerprint of an entire workload."""
    queries: list[QueryFingerprint] = field(default_factory=list)
    total_queries: int = 0
    total_cost: float = 0.0
    top_tables: list[tuple[str, int]] = field(default_factory=list)  # (table, access_count)
    top_filter_columns: list[tuple[str, int]] = field(default_factory=list)
    critical_query_count: int = 0  # Queries responsible for 80% of cost
    workload_type: str = "mixed"   # oltp_heavy / olap_heavy / mixed

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_queries": self.total_queries,
            "total_cost": round(self.total_cost, 2),
            "top_tables": self.top_tables[:10],
            "top_filter_columns": self.top_filter_columns[:10],
            "critical_query_count": self.critical_query_count,
            "workload_type": self.workload_type,
            "queries": [
                {
                    "template_hash": q.template_hash[:12],
                    "frequency": q.frequency,
                    "avg_cost": round(q.avg_cost, 2),
                    "criticality": round(q.criticality_score, 2),
                    "tables": q.tables,
                    "is_seq_scan": q.is_seq_scan,
                }
                for q in sorted(self.queries, key=lambda x: -x.criticality_score)[:20]
            ],
        }


@dataclass
class OptimizationCandidate:
    """A proposed optimization with predicted impact."""
    candidate_type: CandidateType
    description: str
    sql: str = ""                   # SQL to implement
    predicted_speedup: float = 1.0  # e.g., 3.0 = 3x faster
    predicted_cost_reduction: float = 0.0  # Absolute cost reduction
    confidence: float = 0.5         # 0-1 confidence in prediction
    risk: float = 0.1              # 0-1 risk of regression
    affected_queries: int = 0       # How many queries benefit
    reasoning: str = ""             # Why we predict this improvement
    side_effects: list[str] = field(default_factory=list)

    @property
    def benefit_risk_ratio(self) -> float:
        """Higher = better. Benefit weighted by confidence / risk."""
        if self.risk <= 0:
            return self.predicted_speedup * self.confidence * 100
        return (self.predicted_speedup * self.confidence) / self.risk

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.candidate_type.value,
            "description": self.description,
            "sql": self.sql,
            "predicted_speedup": round(self.predicted_speedup, 2),
            "confidence": round(self.confidence, 2),
            "risk": round(self.risk, 2),
            "benefit_risk_ratio": round(self.benefit_risk_ratio, 2),
            "affected_queries": self.affected_queries,
            "reasoning": self.reasoning,
            "side_effects": self.side_effects,
        }


@dataclass
class OptimizationPlan:
    """Ranked optimization plan from predictive analysis."""
    fingerprint: WorkloadFingerprint | None = None
    recommendations: list[OptimizationCandidate] = field(default_factory=list)
    total_predicted_improvement: float = 0.0  # % improvement
    total_affected_queries: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_predicted_improvement_pct": round(self.total_predicted_improvement, 2),
            "total_affected_queries": self.total_affected_queries,
            "recommendation_count": len(self.recommendations),
            "recommendations": [r.to_dict() for r in self.recommendations],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def format_text(self) -> str:
        lines: list[str] = []
        lines.append("")
        lines.append("  PREDICTIVE OPTIMIZATION PLAN")
        lines.append("  " + "=" * 60)
        lines.append(f"  Predicted total improvement: {self.total_predicted_improvement:.1f}%")
        lines.append(f"  Affected queries: {self.total_affected_queries}")
        lines.append(f"  Recommendations: {len(self.recommendations)}")
        lines.append("")

        for i, rec in enumerate(self.recommendations, 1):
            risk_bar = "!" * max(1, int(rec.risk * 10))
            conf_bar = "#" * max(1, int(rec.confidence * 10))
            lines.append(
                f"  {i}. [{rec.candidate_type.value.upper():>15}] {rec.description}"
            )
            lines.append(
                f"     Speedup: {rec.predicted_speedup:.1f}x | "
                f"Confidence: {rec.confidence:.0%} [{conf_bar}] | "
                f"Risk: {rec.risk:.0%} [{risk_bar}]"
            )
            if rec.sql:
                lines.append(f"     SQL: {rec.sql[:120]}")
            if rec.reasoning:
                lines.append(f"     Why: {rec.reasoning[:120]}")
            if rec.side_effects:
                for se in rec.side_effects[:2]:
                    lines.append(f"     Side effect: {se}")
            lines.append("")

        return "\n".join(lines)


class PredictiveOptimizer:
    """
    Predictive workload optimizer using statistical modeling.

    Pipeline:
    1. fingerprint_workload() -- Extract critical queries from plans
    2. generate_candidates() -- Propose optimizations
    3. estimate_impact() -- Predict impact using cost model
    4. optimize() -- Full pipeline, returns ranked OptimizationPlan
    """

    def __init__(self, seq_scan_threshold: int = 10000, cost_threshold: float = 100.0):
        self._seq_scan_threshold = seq_scan_threshold
        self._cost_threshold = cost_threshold

    # ── Step 1: Fingerprint ──────────────────────────────────────────

    def fingerprint_workload(
        self,
        plans: list[dict[str, Any]],
        sqls: list[str] | None = None,
        frequencies: list[int] | None = None,
    ) -> WorkloadFingerprint:
        """
        Extract a workload fingerprint from EXPLAIN plans.

        Args:
            plans: List of EXPLAIN JSON outputs
            sqls: Optional SQL strings corresponding to plans
            frequencies: Optional execution frequencies
        """
        queries: list[QueryFingerprint] = []
        table_counter: Counter[str] = Counter()
        column_counter: Counter[str] = Counter()

        for i, plan_data in enumerate(plans):
            sql = sqls[i] if sqls and i < len(sqls) else ""
            freq = frequencies[i] if frequencies and i < len(frequencies) else 1

            # Extract the plan tree
            plan_tree = self._extract_plan(plan_data)
            if not plan_tree:
                continue

            # Walk the tree
            tables: list[str] = []
            filters: list[str] = []
            joins: list[str] = []
            sorts: list[str] = []
            node_types: list[str] = []
            is_seq = False
            has_spill = False
            has_nested = False
            total_cost = plan_tree.get("Total Cost", 0.0)
            est_rows = plan_tree.get("Plan Rows", 0)
            act_rows = plan_tree.get("Actual Rows") or 0
            exec_time = plan_tree.get("Actual Total Time") or 0.0

            for node in self._walk_nodes(plan_tree):
                nt = node.get("Node Type", "")
                node_types.append(nt)

                rel = node.get("Relation Name")
                if rel:
                    tables.append(rel)
                    table_counter[rel] += freq

                if nt == "Seq Scan" and (node.get("Actual Rows") or node.get("Plan Rows", 0)) > self._seq_scan_threshold:
                    is_seq = True

                if nt == "Nested Loop":
                    has_nested = True

                # Extract filter columns
                for fld in ("Filter", "Index Cond", "Recheck Cond"):
                    cond = node.get(fld, "")
                    if cond:
                        cols = self._extract_columns(cond)
                        filters.extend(cols)
                        for c in cols:
                            column_counter[c] += freq

                # Join columns
                for fld in ("Hash Cond", "Merge Cond", "Join Filter"):
                    cond = node.get(fld, "")
                    if cond:
                        joins.extend(self._extract_columns(cond))

                # Sort columns
                sort_keys = node.get("Sort Key", [])
                if sort_keys:
                    sorts.extend(sort_keys)

                # Disk spill
                if node.get("Sort Space Type") == "Disk" or (node.get("Hash Batches", 0) or 0) > 1:
                    has_spill = True

            # Template
            template = self._normalize_sql(sql) if sql else f"plan_{i}"
            template_hash = hashlib.sha256(template.encode()).hexdigest()

            row_error = 0.0
            if act_rows and est_rows:
                row_error = abs(act_rows - est_rows) / max(act_rows, 1)

            qf = QueryFingerprint(
                template=template,
                template_hash=template_hash,
                frequency=freq,
                avg_cost=total_cost,
                avg_execution_ms=exec_time,
                total_cost=total_cost * freq,
                tables=list(set(tables)),
                filter_columns=list(set(filters)),
                join_columns=list(set(joins)),
                sort_columns=sorts[:5],
                is_seq_scan=is_seq,
                estimated_rows=est_rows,
                actual_rows=act_rows,
                row_estimate_error=row_error,
                has_disk_spill=has_spill,
                has_nested_loop=has_nested,
                node_types=node_types,
            )
            queries.append(qf)

        # Sort by criticality
        queries.sort(key=lambda x: -x.criticality_score)

        # Find critical queries (80% of cost)
        total_cost = sum(q.total_cost for q in queries)
        cumulative = 0.0
        critical_count = 0
        for q in queries:
            cumulative += q.total_cost
            critical_count += 1
            if cumulative >= total_cost * 0.8:
                break

        # Classify workload
        oltp_count = sum(1 for q in queries if q.avg_cost < 100 and q.frequency > 10)
        olap_count = sum(1 for q in queries if q.avg_cost > 1000)
        if oltp_count > olap_count * 3:
            wtype = "oltp_heavy"
        elif olap_count > oltp_count * 3:
            wtype = "olap_heavy"
        else:
            wtype = "mixed"

        return WorkloadFingerprint(
            queries=queries,
            total_queries=len(queries),
            total_cost=total_cost,
            top_tables=table_counter.most_common(20),
            top_filter_columns=column_counter.most_common(20),
            critical_query_count=critical_count,
            workload_type=wtype,
        )

    # ── Step 2: Generate candidates ──────────────────────────────────

    def generate_candidates(self, fp: WorkloadFingerprint) -> list[OptimizationCandidate]:
        """Generate optimization candidates from workload fingerprint."""
        candidates: list[OptimizationCandidate] = []

        candidates.extend(self._index_candidates(fp))
        candidates.extend(self._knob_candidates(fp))
        candidates.extend(self._rewrite_candidates(fp))
        candidates.extend(self._partition_candidates(fp))
        candidates.extend(self._matview_candidates(fp))

        return candidates

    # ── Step 3: Estimate impact ──────────────────────────────────────

    def estimate_impact(
        self, candidates: list[OptimizationCandidate], fp: WorkloadFingerprint,
    ) -> list[OptimizationCandidate]:
        """Estimate impact of each candidate using cost model."""
        for c in candidates:
            if c.candidate_type == CandidateType.INDEX:
                c.predicted_speedup, c.confidence = self._estimate_index_impact(c, fp)
            elif c.candidate_type == CandidateType.KNOB:
                c.predicted_speedup, c.confidence = self._estimate_knob_impact(c, fp)
            elif c.candidate_type == CandidateType.REWRITE:
                c.predicted_speedup, c.confidence = self._estimate_rewrite_impact(c, fp)
            elif c.candidate_type == CandidateType.PARTITIONING:
                c.predicted_speedup, c.confidence = self._estimate_partition_impact(c, fp)
            elif c.candidate_type == CandidateType.MATERIALIZED_VIEW:
                c.predicted_speedup, c.confidence = self._estimate_matview_impact(c, fp)

        # Sort by benefit/risk ratio
        candidates.sort(key=lambda x: -x.benefit_risk_ratio)
        return candidates

    # ── Full pipeline ────────────────────────────────────────────────

    def optimize(
        self,
        plans: list[dict[str, Any]],
        sqls: list[str] | None = None,
        frequencies: list[int] | None = None,
        top_k: int = 10,
    ) -> OptimizationPlan:
        """Full predictive optimization pipeline."""
        fp = self.fingerprint_workload(plans, sqls, frequencies)
        candidates = self.generate_candidates(fp)
        ranked = self.estimate_impact(candidates, fp)[:top_k]

        total_improvement = 0.0
        affected = set()
        for c in ranked:
            total_improvement += (c.predicted_speedup - 1.0) * c.confidence * 10
            affected.add(c.description)

        return OptimizationPlan(
            fingerprint=fp,
            recommendations=ranked,
            total_predicted_improvement=min(total_improvement, 95.0),
            total_affected_queries=len(affected),
        )

    # ── Index candidate generation ───────────────────────────────────

    def _index_candidates(self, fp: WorkloadFingerprint) -> list[OptimizationCandidate]:
        candidates: list[OptimizationCandidate] = []

        # Find seq scans on large tables with filter columns
        for q in fp.queries:
            if not q.is_seq_scan or not q.filter_columns:
                continue

            for table in q.tables:
                for col in q.filter_columns:
                    idx_name = f"idx_{table}_{col}"
                    candidates.append(OptimizationCandidate(
                        candidate_type=CandidateType.INDEX,
                        description=f"Index on {table}({col})",
                        sql=f"CREATE INDEX CONCURRENTLY {idx_name} ON {table}({col});",
                        affected_queries=q.frequency,
                        reasoning=f"Seq scan on {table} with filter on {col} ({q.frequency}x/period)",
                        risk=0.05,
                        side_effects=[
                            f"Write overhead: ~5-10% slower INSERTs on {table}",
                            f"Storage: ~{max(1, q.estimated_rows // 10000)}MB for index",
                        ],
                    ))

        # Covering indexes for high-frequency queries
        for q in fp.queries[:5]:
            if q.filter_columns and q.sort_columns:
                for table in q.tables:
                    cols = q.filter_columns[:2]
                    sort = [s.split()[0] for s in q.sort_columns[:1]]
                    all_cols = list(dict.fromkeys(cols + sort))
                    idx_name = f"idx_{table}_{'_'.join(all_cols)}"
                    candidates.append(OptimizationCandidate(
                        candidate_type=CandidateType.INDEX,
                        description=f"Covering index on {table}({', '.join(all_cols)})",
                        sql=f"CREATE INDEX CONCURRENTLY {idx_name} ON {table}({', '.join(all_cols)});",
                        affected_queries=q.frequency,
                        reasoning=f"High-frequency query ({q.frequency}x) with filter+sort: eliminates sort step",
                        risk=0.08,
                    ))

        return candidates

    def _knob_candidates(self, fp: WorkloadFingerprint) -> list[OptimizationCandidate]:
        candidates: list[OptimizationCandidate] = []

        # Disk spill -> increase work_mem
        spill_queries = [q for q in fp.queries if q.has_disk_spill]
        if spill_queries:
            candidates.append(OptimizationCandidate(
                candidate_type=CandidateType.KNOB,
                description="Increase work_mem to reduce disk spills",
                sql="ALTER SYSTEM SET work_mem = '128MB';",
                affected_queries=sum(q.frequency for q in spill_queries),
                reasoning=f"{len(spill_queries)} queries spilling to disk -- sort/hash operations use disk instead of RAM",
                risk=0.15,
                side_effects=[
                    "Each connection can use 128MB per sort/hash operation",
                    "With 100 connections, worst case = 12.8GB RAM usage",
                    "Consider SET LOCAL work_mem = '128MB' per-session instead",
                ],
            ))

        # Row estimation errors -> increase statistics target
        bad_estimate_queries = [q for q in fp.queries if q.row_estimate_error > 10]
        if bad_estimate_queries:
            tables = set()
            for q in bad_estimate_queries:
                tables.update(q.tables)
            candidates.append(OptimizationCandidate(
                candidate_type=CandidateType.KNOB,
                description="Increase default_statistics_target for better estimation",
                sql=(
                    f"-- Increase statistics granularity:\n"
                    + "\n".join(
                        f"ALTER TABLE {t} ALTER COLUMN {{col}} SET STATISTICS 1000;"
                        for t in sorted(tables)[:5]
                    )
                    + "\nANALYZE;"
                ),
                affected_queries=sum(q.frequency for q in bad_estimate_queries),
                reasoning=f"{len(bad_estimate_queries)} queries have >10x row estimation errors",
                risk=0.02,
            ))

        # OLAP workload -> enable parallel
        if fp.workload_type == "olap_heavy":
            candidates.append(OptimizationCandidate(
                candidate_type=CandidateType.KNOB,
                description="Enable aggressive parallelism for OLAP workload",
                sql=(
                    "ALTER SYSTEM SET max_parallel_workers_per_gather = 4;\n"
                    "ALTER SYSTEM SET parallel_tuple_cost = 0.001;\n"
                    "ALTER SYSTEM SET parallel_setup_cost = 100;\n"
                    "SELECT pg_reload_conf();"
                ),
                affected_queries=len([q for q in fp.queries if q.avg_cost > 1000]),
                reasoning="OLAP-heavy workload benefits from parallel query execution",
                risk=0.10,
                side_effects=["Uses more CPU cores per query -- fewer concurrent queries"],
            ))

        return candidates

    def _rewrite_candidates(self, fp: WorkloadFingerprint) -> list[OptimizationCandidate]:
        candidates: list[OptimizationCandidate] = []

        # Nested loops on large tables -> suggest hash join
        for q in fp.queries:
            if q.has_nested_loop and q.actual_rows > 10000:
                candidates.append(OptimizationCandidate(
                    candidate_type=CandidateType.REWRITE,
                    description=f"Force hash join for query on {', '.join(q.tables)}",
                    sql="SET LOCAL enable_nestloop = off; -- then run query",
                    affected_queries=q.frequency,
                    reasoning=f"Nested loop on {q.actual_rows:,} rows -- hash join typically 5-50x faster",
                    risk=0.20,
                    side_effects=["Disabling nestloop may slow other queries in the session"],
                ))

        return candidates

    def _partition_candidates(self, fp: WorkloadFingerprint) -> list[OptimizationCandidate]:
        candidates: list[OptimizationCandidate] = []

        # Large seq scans with date-like filters -> suggest partitioning
        for q in fp.queries:
            if q.is_seq_scan and q.estimated_rows > 1_000_000:
                date_cols = [c for c in q.filter_columns if any(
                    d in c.lower() for d in ("date", "time", "created", "updated", "timestamp")
                )]
                if date_cols:
                    table = q.tables[0] if q.tables else "table"
                    col = date_cols[0]
                    candidates.append(OptimizationCandidate(
                        candidate_type=CandidateType.PARTITIONING,
                        description=f"Partition {table} by {col}",
                        sql=(
                            f"-- Convert to range-partitioned table:\n"
                            f"CREATE TABLE {table}_partitioned (\n"
                            f"  LIKE {table} INCLUDING ALL\n"
                            f") PARTITION BY RANGE ({col});\n"
                            f"-- Create monthly partitions as needed"
                        ),
                        affected_queries=q.frequency,
                        reasoning=f"Seq scan on {q.estimated_rows:,} rows with date filter -- partition pruning eliminates 90%+ of data",
                        risk=0.30,
                        side_effects=[
                            "Requires application changes if table is referenced by FK",
                            "Maintenance overhead for partition management",
                        ],
                    ))

        return candidates

    def _matview_candidates(self, fp: WorkloadFingerprint) -> list[OptimizationCandidate]:
        candidates: list[OptimizationCandidate] = []

        # High-cost queries run very frequently -> materialized view
        for q in fp.queries[:5]:
            if q.avg_cost > 5000 and q.frequency > 100:
                tables = ", ".join(q.tables) if q.tables else "multiple tables"
                candidates.append(OptimizationCandidate(
                    candidate_type=CandidateType.MATERIALIZED_VIEW,
                    description=f"Materialize expensive query on {tables}",
                    sql=(
                        f"CREATE MATERIALIZED VIEW mv_{q.template_hash[:8]} AS\n"
                        f"  {q.template[:200]};\n"
                        f"CREATE UNIQUE INDEX ON mv_{q.template_hash[:8]} (id);  -- adjust PK\n"
                        f"-- Refresh: REFRESH MATERIALIZED VIEW CONCURRENTLY mv_{q.template_hash[:8]};"
                    ),
                    affected_queries=q.frequency,
                    reasoning=f"Cost {q.avg_cost:.0f} x {q.frequency}x frequency = high total impact; materialization trades freshness for speed",
                    risk=0.25,
                    side_effects=[
                        "Data staleness between refreshes",
                        "Storage overhead for materialized copy",
                        "Need REFRESH schedule (pg_cron or application)",
                    ],
                ))

        return candidates

    # ── Impact estimation models ─────────────────────────────────────

    def _estimate_index_impact(self, c: OptimizationCandidate, fp: WorkloadFingerprint) -> tuple[float, float]:
        """Estimate speedup from adding an index."""
        # Model: Index scan is O(log n) vs Seq Scan O(n)
        # Typical speedup for selective queries: 10-100x
        # For less selective: 2-5x
        affected = [q for q in fp.queries if any(t in c.description for t in q.tables)]
        if not affected:
            return 1.5, 0.3

        avg_rows = sum(q.estimated_rows for q in affected) / len(affected)
        if avg_rows > 100000:
            return min(50.0, math.log10(avg_rows) * 5), 0.8
        elif avg_rows > 10000:
            return min(20.0, math.log10(avg_rows) * 3), 0.75
        else:
            return 2.0, 0.6

    def _estimate_knob_impact(self, c: OptimizationCandidate, fp: WorkloadFingerprint) -> tuple[float, float]:
        if "work_mem" in c.sql:
            spill_count = sum(1 for q in fp.queries if q.has_disk_spill)
            return min(5.0, 1.5 + spill_count * 0.3), 0.65
        elif "statistics_target" in c.sql.lower() or "ANALYZE" in c.sql:
            return 2.0, 0.70
        elif "parallel" in c.sql.lower():
            return 3.0, 0.60
        return 1.2, 0.40

    def _estimate_rewrite_impact(self, c: OptimizationCandidate, fp: WorkloadFingerprint) -> tuple[float, float]:
        if "nestloop" in c.sql:
            return 5.0, 0.50
        return 2.0, 0.45

    def _estimate_partition_impact(self, c: OptimizationCandidate, fp: WorkloadFingerprint) -> tuple[float, float]:
        return 8.0, 0.55

    def _estimate_matview_impact(self, c: OptimizationCandidate, fp: WorkloadFingerprint) -> tuple[float, float]:
        return 20.0, 0.70

    # ── Utilities ────────────────────────────────────────────────────

    def _extract_plan(self, data: dict[str, Any]) -> dict[str, Any] | None:
        if isinstance(data, list) and data:
            data = data[0]
        if isinstance(data, dict):
            if "Plan" in data:
                return data["Plan"]
            if "Node Type" in data:
                return data
        return None

    def _walk_nodes(self, node: dict[str, Any]):
        yield node
        for child in node.get("Plans", []):
            yield from self._walk_nodes(child)

    def _extract_columns(self, condition: str) -> list[str]:
        """Extract column names from a SQL condition."""
        # Match patterns like table.column or just column
        cols = re.findall(r'(?:\w+\.)?(\w+)\s*(?:=|<|>|LIKE|IN|IS)', condition, re.IGNORECASE)
        return [c for c in cols if c.lower() not in ("null", "true", "false", "and", "or", "not")]

    def _normalize_sql(self, sql: str) -> str:
        """Normalize SQL for fingerprinting (replace literals with ?)."""
        s = re.sub(r"'[^']*'", "'?'", sql)
        s = re.sub(r"\b\d+\b", "?", s)
        s = re.sub(r"\s+", " ", s).strip().upper()
        return s
