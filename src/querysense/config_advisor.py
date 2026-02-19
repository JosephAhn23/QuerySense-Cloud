"""
Query-Aware Configuration Advisor — recommends config changes specific to a query.

The missing link between Ch. 4-5 (plan analysis) and Ch. 10 (configuration):
given a query's EXPLAIN plan and its findings, suggest the EXACT PostgreSQL
configuration changes that would improve THIS specific query.

This goes beyond static best-practice auditing (which config_auditor.py does)
by analyzing the actual plan nodes and recommending settings tuned to the
query's behavior.

pganalyze tracks configuration over time but doesn't connect plan problems
to specific configuration fixes. QuerySense does both.

Usage:
    from querysense.config_advisor import QueryConfigAdvisor, ConfigRecommendation

    advisor = QueryConfigAdvisor()
    recommendations = advisor.analyze(plan_json, findings)
    for rec in recommendations:
        print(f"SET {rec.parameter} = {rec.recommended_value};")
        print(f"  Why: {rec.reason}")
        print(f"  Expected improvement: {rec.expected_improvement}")
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ConfigRecommendation:
    """A query-specific configuration recommendation."""

    parameter: str
    current_value: str
    recommended_value: str
    scope: str  # "session" | "transaction" | "system"
    reason: str
    mechanism: str  # How this setting affects the planner
    expected_improvement: str
    risk: str  # "none" | "low" | "medium" | "high"
    apply_sql: str
    rollback_sql: str = ""
    evidence: str = ""  # What in the plan triggered this
    textbook_ref: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "parameter": self.parameter,
            "current_value": self.current_value,
            "recommended_value": self.recommended_value,
            "scope": self.scope,
            "reason": self.reason,
            "mechanism": self.mechanism,
            "expected_improvement": self.expected_improvement,
            "risk": self.risk,
            "apply_sql": self.apply_sql,
            "rollback_sql": self.rollback_sql,
            "evidence": self.evidence,
            "textbook_ref": self.textbook_ref,
        }


@dataclass
class ConfigAdvisorResult:
    """Complete result from query-aware config analysis."""

    recommendations: list[ConfigRecommendation] = field(default_factory=list)
    plan_summary: str = ""
    settings_impact_map: dict[str, list[str]] = field(default_factory=dict)

    @property
    def session_changes(self) -> list[ConfigRecommendation]:
        return [r for r in self.recommendations if r.scope in ("session", "transaction")]

    @property
    def system_changes(self) -> list[ConfigRecommendation]:
        return [r for r in self.recommendations if r.scope == "system"]

    def apply_script(self, scope: str = "session") -> str:
        """Generate a complete SQL script to apply recommendations."""
        lines = [
            f"-- QuerySense Query-Aware Configuration Recommendations",
            f"-- Scope: {scope}",
            "",
        ]
        for rec in self.recommendations:
            if scope == "all" or rec.scope == scope:
                lines.append(f"-- {rec.reason}")
                lines.append(f"{rec.apply_sql}")
                lines.append("")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "recommendations": [r.to_dict() for r in self.recommendations],
            "plan_summary": self.plan_summary,
            "session_changes_count": len(self.session_changes),
            "system_changes_count": len(self.system_changes),
        }


class QueryConfigAdvisor:
    """
    Analyze a query plan and recommend configuration changes.

    Connects plan-level problems to their configuration root causes:
    - Sort spills → work_mem
    - Bad row estimates → default_statistics_target / ANALYZE
    - No parallel → max_parallel_workers_per_gather
    - Seq Scan preference → random_page_cost (SSD mismatch)
    - Hash batch overflow → hash_mem_multiplier (PG 15+)
    """

    def analyze(
        self,
        plan_json: str | dict,
        findings: list[Any] | None = None,
        current_settings: dict[str, str] | None = None,
    ) -> ConfigAdvisorResult:
        """
        Analyze plan and findings to produce config recommendations.

        Args:
            plan_json: EXPLAIN (FORMAT JSON) output
            findings: Optional QuerySense findings from analysis
            current_settings: Optional current PostgreSQL settings

        Returns:
            ConfigAdvisorResult with specific recommendations
        """
        if isinstance(plan_json, str):
            try:
                data = json.loads(plan_json)
            except json.JSONDecodeError:
                return ConfigAdvisorResult()
        else:
            data = plan_json

        if isinstance(data, list):
            data = data[0]

        plan = data.get("Plan", data)
        settings = current_settings or {}
        result = ConfigAdvisorResult()

        # Analyze plan nodes for config-related issues
        self._check_work_mem(plan, settings, result)
        self._check_random_page_cost(plan, settings, result)
        self._check_parallel_settings(plan, settings, result)
        self._check_statistics_target(plan, settings, result, findings)
        self._check_hash_mem(plan, settings, result)
        self._check_jit(plan, settings, result)
        self._check_effective_cache_size(plan, settings, result)

        # Cross-reference with findings
        if findings:
            self._correlate_findings(findings, settings, result)

        # Build impact map
        result.settings_impact_map = self._build_impact_map(result)
        result.plan_summary = self._summarize_plan(plan)

        # Sort by expected impact
        impact_order = {"major": 0, "moderate": 1, "minor": 2}
        result.recommendations.sort(
            key=lambda r: impact_order.get(
                r.expected_improvement.split(" ")[0].lower()
                if " " in r.expected_improvement else "minor",
                3,
            )
        )

        return result

    def _check_work_mem(
        self, plan: dict, settings: dict, result: ConfigAdvisorResult,
    ) -> None:
        """Check if work_mem is causing sort/hash spills."""
        spill_nodes = self._find_nodes(plan, lambda n: (
            n.get("Sort Space Type") == "Disk"
            or n.get("Hash Batches", 1) > 1
            or "external" in (n.get("Sort Method", "")).lower()
        ))

        if not spill_nodes:
            return

        max_spill_kb = 0
        spill_details = []

        for node in spill_nodes:
            sort_space = node.get("Sort Space Used", 0)
            hash_batches = node.get("Hash Batches", 1)
            peak_memory = node.get("Peak Memory Usage", 0)

            if sort_space:
                max_spill_kb = max(max_spill_kb, sort_space)
                spill_details.append(
                    f"Sort spill: {sort_space}kB to disk ({node.get('Sort Method', 'unknown')})"
                )
            if hash_batches > 1:
                spill_details.append(f"Hash Join: {hash_batches} batches (need more memory)")

        # Recommend 2x the spill size, minimum 64MB
        recommended_mb = max(64, int(max_spill_kb * 2.5 / 1024))
        # Cap at 1GB for session-level
        recommended_mb = min(recommended_mb, 1024)

        current_wm = settings.get("work_mem", "4MB")

        result.recommendations.append(ConfigRecommendation(
            parameter="work_mem",
            current_value=current_wm,
            recommended_value=f"{recommended_mb}MB",
            scope="session",
            reason=f"Query spills {max_spill_kb}kB to disk — in-memory would be 10-100x faster",
            mechanism=(
                "work_mem controls the maximum memory for each sort/hash operation. "
                "When exceeded, PostgreSQL falls back to disk-based external sort/hash. "
                "Setting this per-session is safe and instantly reversible."
            ),
            expected_improvement=f"Major — eliminates {len(spill_nodes)} disk spill(s)",
            risk="low",
            apply_sql=f"SET work_mem = '{recommended_mb}MB';  -- session-level, reverts on disconnect",
            rollback_sql=f"SET work_mem = '{current_wm}';",
            evidence="; ".join(spill_details[:3]),
            textbook_ref="Dombrovskaya Ch. 10: Configuration Parameters",
        ))

    def _check_random_page_cost(
        self, plan: dict, settings: dict, result: ConfigAdvisorResult,
    ) -> None:
        """Check if random_page_cost is causing seq scan preference on SSDs."""
        seq_scans_with_filter = self._find_nodes(plan, lambda n: (
            n.get("Node Type") == "Seq Scan"
            and n.get("Filter")
            and n.get("Rows Removed by Filter", 0) > 0
        ))

        if not seq_scans_with_filter:
            return

        rpc = float(settings.get("random_page_cost", "4"))
        if rpc <= 1.5:
            return  # Already tuned for SSD

        high_selectivity_scans = []
        for node in seq_scans_with_filter:
            actual = node.get("Actual Rows", 0)
            removed = node.get("Rows Removed by Filter", 0)
            total = actual + removed
            if total > 0:
                selectivity = actual / total
                if selectivity < 0.15:  # <15% rows match → index should be used
                    high_selectivity_scans.append({
                        "table": node.get("Relation Name", "?"),
                        "selectivity": selectivity,
                        "rows_scanned": total,
                        "rows_returned": actual,
                    })

        if not high_selectivity_scans:
            return

        tables = ", ".join(s["table"] for s in high_selectivity_scans[:3])
        result.recommendations.append(ConfigRecommendation(
            parameter="random_page_cost",
            current_value=str(rpc),
            recommended_value="1.1",
            scope="system",
            reason=(
                f"Seq Scan on {tables} despite low selectivity — random_page_cost={rpc} "
                f"makes index scans look {rpc:.0f}x more expensive than they are on SSDs"
            ),
            mechanism=(
                f"random_page_cost={rpc} means the planner costs each random page read at "
                f"{rpc}x the cost of a sequential read. On SSDs, random and sequential I/O "
                f"are nearly equal. Setting random_page_cost=1.1 tells the planner that index "
                f"scans (random I/O) are almost as fast as seq scans (sequential I/O)."
            ),
            expected_improvement=f"Major — {len(high_selectivity_scans)} scan(s) likely to switch to Index Scan",
            risk="low",
            apply_sql="ALTER SYSTEM SET random_page_cost = 1.1;\nSELECT pg_reload_conf();",
            rollback_sql=f"ALTER SYSTEM SET random_page_cost = {rpc};\nSELECT pg_reload_conf();",
            evidence=f"Tables with inefficient Seq Scan: {tables}",
            textbook_ref="Dombrovskaya Ch. 10; PostgreSQL Internals (Rogov 2023)",
        ))

    def _check_parallel_settings(
        self, plan: dict, settings: dict, result: ConfigAdvisorResult,
    ) -> None:
        """Check if parallelism is underutilized."""
        # Look for expensive non-parallel scans
        expensive_seq_scans = self._find_nodes(plan, lambda n: (
            n.get("Node Type") == "Seq Scan"
            and n.get("Total Cost", 0) > 10000
            and not n.get("Parallel Aware", False)
        ))

        if not expensive_seq_scans:
            return

        mpwpg = int(settings.get("max_parallel_workers_per_gather", "2"))
        if mpwpg == 0:
            result.recommendations.append(ConfigRecommendation(
                parameter="max_parallel_workers_per_gather",
                current_value="0 (disabled)",
                recommended_value="4",
                scope="system",
                reason="Parallel query is DISABLED but this query has expensive sequential scans",
                mechanism=(
                    "PostgreSQL can parallelize Seq Scan, Hash Join, and aggregation across "
                    "multiple CPU cores. With max_parallel_workers_per_gather=0, this is disabled "
                    "and all scans are single-threaded."
                ),
                expected_improvement="Major — parallel scan can be 2-4x faster on multi-core",
                risk="low",
                apply_sql="ALTER SYSTEM SET max_parallel_workers_per_gather = 4;\nSELECT pg_reload_conf();",
                rollback_sql="ALTER SYSTEM SET max_parallel_workers_per_gather = 0;\nSELECT pg_reload_conf();",
                evidence=f"{len(expensive_seq_scans)} expensive Seq Scan node(s) not using parallel",
                textbook_ref="PostgreSQL Query Optimization (Dombrovskaya 2024)",
            ))

    def _check_statistics_target(
        self, plan: dict, settings: dict, result: ConfigAdvisorResult,
        findings: list[Any] | None = None,
    ) -> None:
        """Check if bad row estimates suggest stale or insufficient statistics."""
        bad_estimate_nodes = self._find_nodes(plan, lambda n: (
            n.get("Actual Rows") is not None
            and n.get("Plan Rows", 0) > 0
            and (
                n.get("Actual Rows", 0) > n.get("Plan Rows", 0) * 10
                or n.get("Actual Rows", 0) < n.get("Plan Rows", 0) / 10
            )
        ))

        if not bad_estimate_nodes:
            return

        tables = set()
        for node in bad_estimate_nodes:
            table = node.get("Relation Name")
            if table:
                tables.add(table)

        if not tables:
            return

        dst = settings.get("default_statistics_target", "100")
        table_list = ", ".join(sorted(tables)[:5])

        result.recommendations.append(ConfigRecommendation(
            parameter="default_statistics_target",
            current_value=dst,
            recommended_value="500",
            scope="system",
            reason=(
                f"{len(bad_estimate_nodes)} node(s) have >10x row estimate error on {table_list} — "
                f"planner is making decisions based on inaccurate statistics"
            ),
            mechanism=(
                "PostgreSQL samples rows to build histograms (pg_statistic). "
                f"default_statistics_target={dst} means {dst} histogram buckets. "
                "For skewed data (like status columns, geographic distributions), "
                "this is insufficient. Increasing to 500 captures more detail "
                "at the cost of slightly longer ANALYZE time."
            ),
            expected_improvement="Major — accurate estimates fix join order, scan type, and memory allocation",
            risk="none",
            apply_sql=(
                f"-- Increase statistics target for affected tables:\n"
                + "\n".join(
                    f"ALTER TABLE {t} ALTER COLUMN /* column */ SET STATISTICS 500;"
                    for t in sorted(tables)[:5]
                )
                + f"\n\n-- Or globally:\n"
                f"ALTER SYSTEM SET default_statistics_target = 500;\n"
                f"SELECT pg_reload_conf();\n"
                f"\n-- Then refresh statistics:\n"
                + "\n".join(f"ANALYZE {t};" for t in sorted(tables)[:5])
            ),
            rollback_sql=f"ALTER SYSTEM SET default_statistics_target = {dst};\nSELECT pg_reload_conf();",
            evidence=f"{len(bad_estimate_nodes)} nodes with >10x estimate error",
            textbook_ref="Peng & Peng Ch. 5.5: Cost Estimation; Dombrovskaya Ch. 16",
        ))

    def _check_hash_mem(
        self, plan: dict, settings: dict, result: ConfigAdvisorResult,
    ) -> None:
        """Check for PG15+ hash_mem_multiplier optimization."""
        hash_nodes = self._find_nodes(plan, lambda n: (
            n.get("Hash Batches", 1) > 1
        ))

        if not hash_nodes or len(hash_nodes) < 2:
            return

        # This is a PG15+ feature
        hmm = settings.get("hash_mem_multiplier", "2")

        total_batches = sum(n.get("Hash Batches", 1) for n in hash_nodes)
        result.recommendations.append(ConfigRecommendation(
            parameter="hash_mem_multiplier",
            current_value=hmm,
            recommended_value="4",
            scope="system",
            reason=f"{len(hash_nodes)} hash operations using {total_batches} total batches",
            mechanism=(
                "hash_mem_multiplier (PG 15+) multiplies work_mem specifically for hash "
                "operations. Setting to 4 allows hash tables to use 4x work_mem without "
                "affecting sort memory limits."
            ),
            expected_improvement="Moderate — reduces hash join batch count without inflating sort memory",
            risk="low",
            apply_sql=f"ALTER SYSTEM SET hash_mem_multiplier = 4;\nSELECT pg_reload_conf();",
            rollback_sql=f"ALTER SYSTEM SET hash_mem_multiplier = {hmm};\nSELECT pg_reload_conf();",
            evidence=f"{len(hash_nodes)} hash operations with multi-batch execution",
            textbook_ref="PostgreSQL 15 Release Notes",
        ))

    def _check_jit(
        self, plan: dict, settings: dict, result: ConfigAdvisorResult,
    ) -> None:
        """Check JIT compilation settings."""
        jit_info = plan.get("JIT", {})
        if not jit_info:
            return

        jit_time_ms = jit_info.get("Timing", {})
        generation_ms = jit_time_ms.get("Generation", 0)
        inlining_ms = jit_time_ms.get("Inlining", 0)
        optimization_ms = jit_time_ms.get("Optimization", 0)
        emission_ms = jit_time_ms.get("Emission", 0)
        total_jit_ms = generation_ms + inlining_ms + optimization_ms + emission_ms

        exec_time_ms = plan.get("Actual Total Time", 0)

        if exec_time_ms > 0 and total_jit_ms > exec_time_ms * 0.3:
            result.recommendations.append(ConfigRecommendation(
                parameter="jit",
                current_value="on",
                recommended_value="off (for this query)",
                scope="session",
                reason=(
                    f"JIT compilation took {total_jit_ms:.0f}ms "
                    f"({total_jit_ms / exec_time_ms * 100:.0f}% of execution time) — "
                    f"hurting rather than helping"
                ),
                mechanism=(
                    "JIT compiles query expressions to native code via LLVM. "
                    "For short/medium queries, the compilation overhead exceeds the "
                    "execution savings. Disabling JIT for this session avoids the overhead."
                ),
                expected_improvement=f"Moderate — saves ~{total_jit_ms:.0f}ms JIT overhead",
                risk="none",
                apply_sql="SET jit = off;  -- session-level, reverts on disconnect",
                rollback_sql="SET jit = on;",
                evidence=f"JIT: {generation_ms:.0f}ms gen + {optimization_ms:.0f}ms opt + {emission_ms:.0f}ms emit",
                textbook_ref="PostgreSQL 11+ JIT documentation",
            ))

    def _check_effective_cache_size(
        self, plan: dict, settings: dict, result: ConfigAdvisorResult,
    ) -> None:
        """Check if effective_cache_size mismatch causes wrong scan choices."""
        # Look for plans where buffer reads >> hits (cold cache)
        cold_nodes = self._find_nodes(plan, lambda n: (
            n.get("Shared Read Blocks", 0) > n.get("Shared Hit Blocks", 0) * 2
            and n.get("Shared Read Blocks", 0) > 1000
        ))

        if not cold_nodes:
            return

        total_reads = sum(n.get("Shared Read Blocks", 0) for n in cold_nodes)
        total_hits = sum(n.get("Shared Hit Blocks", 0) for n in cold_nodes)

        if total_hits + total_reads == 0:
            return

        hit_rate = total_hits / (total_hits + total_reads)

        if hit_rate < 0.5:
            ecs = settings.get("effective_cache_size", "4GB")
            result.recommendations.append(ConfigRecommendation(
                parameter="effective_cache_size",
                current_value=ecs,
                recommended_value="Increase to match actual cache + OS cache",
                scope="system",
                reason=(
                    f"Buffer hit rate is only {hit_rate:.0%} — {total_reads:,} reads vs "
                    f"{total_hits:,} hits. effective_cache_size may be underestimating available cache."
                ),
                mechanism=(
                    "effective_cache_size tells the planner how much data is likely cached in "
                    "shared_buffers + OS page cache. If set too low, the planner avoids index "
                    "scans (assuming random reads are expensive). If too high, it overestimates "
                    "cache availability."
                ),
                expected_improvement="Moderate — more accurate cache estimation improves scan type selection",
                risk="none",
                apply_sql=(
                    "-- Set to ~75% of total system RAM:\n"
                    "ALTER SYSTEM SET effective_cache_size = '12GB';  -- adjust to your RAM\n"
                    "SELECT pg_reload_conf();"
                ),
                rollback_sql=f"ALTER SYSTEM SET effective_cache_size = '{ecs}';\nSELECT pg_reload_conf();",
                evidence=f"Buffer hit rate: {hit_rate:.0%} ({total_reads:,} reads, {total_hits:,} hits)",
                textbook_ref="Mastering PostgreSQL (Schönig 2020); Dombrovskaya Ch. 10",
            ))

    def _correlate_findings(
        self, findings: list[Any], settings: dict, result: ConfigAdvisorResult,
    ) -> None:
        """Cross-reference findings with config recommendations."""
        seen_params: set[str] = {r.parameter for r in result.recommendations}

        for finding in findings:
            rule_id = getattr(finding, "rule_id", "")

            if rule_id == "WORK_MEM_TUNING" and "work_mem" not in seen_params:
                metrics = getattr(finding, "metrics", {}) or {}
                result.recommendations.append(ConfigRecommendation(
                    parameter="work_mem",
                    current_value=settings.get("work_mem", "4MB"),
                    recommended_value=f"{max(64, metrics.get('recommended_mb', 64))}MB",
                    scope="session",
                    reason="WorkMem rule detected operations that would benefit from more memory",
                    mechanism="Increasing work_mem keeps sort/hash in RAM",
                    expected_improvement="Moderate — eliminates disk spill",
                    risk="low",
                    apply_sql=f"SET work_mem = '{max(64, metrics.get('recommended_mb', 64))}MB';",
                    textbook_ref="Dombrovskaya Ch. 10",
                ))
                seen_params.add("work_mem")

    def _build_impact_map(self, result: ConfigAdvisorResult) -> dict[str, list[str]]:
        """Build a map of which settings affect which plan nodes."""
        impact: dict[str, list[str]] = {}
        for rec in result.recommendations:
            param = rec.parameter
            if param not in impact:
                impact[param] = []
            impact[param].append(rec.reason)
        return impact

    def _summarize_plan(self, plan: dict) -> str:
        """Generate one-line plan summary."""
        node_type = plan.get("Node Type", "?")
        total_cost = plan.get("Total Cost", 0)
        rows = plan.get("Plan Rows", 0)
        return f"{node_type} (cost={total_cost:,.1f}, rows={rows:,})"

    @staticmethod
    def _find_nodes(plan: dict, predicate: Any) -> list[dict]:
        """Find all plan nodes matching a predicate."""
        results: list[dict] = []
        if predicate(plan):
            results.append(plan)
        for child in plan.get("Plans", []):
            results.extend(QueryConfigAdvisor._find_nodes(child, predicate))
        return results
