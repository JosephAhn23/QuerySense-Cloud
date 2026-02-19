"""
Query Classifier — distinguish OLTP from OLAP and adjust recommendations.

Addresses "Short vs. Long Query Distinction" gap identified in
Dombrovskaya et al. 2024: "Your 35 rules treat all queries the same."

Classification signals:
- OLTP: Point lookups, low row count, LIMIT, simple JOINs, index scans
- OLAP: Aggregations, GROUP BY, window functions, full scans, high row count
- HYBRID: Mix of OLTP and OLAP characteristics

Each class gets different recommendations:
- OLTP → emphasize index-only scans, connection pooling, latency
- OLAP → emphasize parallelization, work_mem, partitioning, materialized views

Usage:
    from querysense.query_classifier import QueryClassifier, QueryClass

    classifier = QueryClassifier()
    result = classifier.classify(explain_output, sql_text)
    print(result.query_class)   # QueryClass.OLTP
    print(result.confidence)    # 0.92
    print(result.adjustments)   # {"parallel_recommendation": "skip", ...}
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class QueryClass(str, Enum):
    """Classification of query workload type."""

    OLTP = "OLTP"       # Transactional: fast point lookups, low latency
    OLAP = "OLAP"       # Analytical: aggregations, large scans, throughput
    HYBRID = "HYBRID"   # Mixed characteristics
    DDL = "DDL"         # Schema changes (CREATE, ALTER, DROP)
    DML = "DML"         # Data manipulation (INSERT, UPDATE, DELETE)


@dataclass(frozen=True)
class ClassificationResult:
    """Result of query classification."""

    query_class: QueryClass
    confidence: float  # 0.0 to 1.0
    signals: dict[str, Any] = field(default_factory=dict)
    recommendation_adjustments: dict[str, str] = field(default_factory=dict)

    @property
    def is_oltp(self) -> bool:
        return self.query_class == QueryClass.OLTP

    @property
    def is_olap(self) -> bool:
        return self.query_class == QueryClass.OLAP

    def adjust_finding_severity(self, rule_id: str, original_severity: str) -> str:
        """Adjust a finding's severity based on query class.

        For example: SEQ_SCAN on an OLAP query is less severe (expected),
        but on an OLTP query it's critical (latency killer).
        """
        adjustments = _SEVERITY_ADJUSTMENTS.get(self.query_class, {})
        return adjustments.get(rule_id, original_severity)

    def should_skip_rule(self, rule_id: str) -> bool:
        """Check if a rule should be skipped for this query class."""
        return rule_id in _SKIP_RULES.get(self.query_class, set())


# Rules that are less relevant for certain query classes
_SKIP_RULES: dict[QueryClass, set[str]] = {
    QueryClass.OLTP: {
        "PARALLEL_QUERY_NOT_USED",  # OLTP queries are too small for parallelism
    },
    QueryClass.OLAP: {
        "LIMIT_WITHOUT_INDEX",  # OLAP typically doesn't use LIMIT
    },
}

# Severity adjustments by query class
_SEVERITY_ADJUSTMENTS: dict[QueryClass, dict[str, str]] = {
    QueryClass.OLTP: {
        "SEQ_SCAN_LARGE_TABLE": "critical",   # Fatal for OLTP latency
        "SORT_AVOIDABLE_WITH_INDEX": "critical",  # Every ms counts
        "SPILLING_TO_DISK": "critical",  # Unacceptable for OLTP
    },
    QueryClass.OLAP: {
        "SEQ_SCAN_LARGE_TABLE": "info",    # Expected for analytics
        "PARALLEL_QUERY_NOT_USED": "critical",  # OLAP needs parallelism
        "WORK_MEM_TUNING": "critical",  # Hash joins need memory
        "SPILLING_TO_DISK": "warning",  # Less critical, but still bad
    },
}


class QueryClassifier:
    """Classify queries as OLTP, OLAP, HYBRID, DDL, or DML."""

    def classify(
        self,
        explain: "ExplainOutput | None" = None,
        sql: str | None = None,
    ) -> ClassificationResult:
        """Classify a query based on EXPLAIN output and/or SQL text.

        Args:
            explain: Parsed EXPLAIN output (optional)
            sql: Original SQL text (optional)

        Returns:
            ClassificationResult with query class and confidence
        """
        signals: dict[str, Any] = {}
        oltp_score = 0.0
        olap_score = 0.0

        # ── SQL-based signals ─────────────────────────────────────────
        if sql:
            sql_upper = sql.upper().strip()

            # DDL detection
            if re.match(r"^\s*(CREATE|ALTER|DROP|TRUNCATE)\b", sql_upper):
                return ClassificationResult(
                    query_class=QueryClass.DDL,
                    confidence=0.99,
                    signals={"sql_starts_with_ddl": True},
                    recommendation_adjustments={
                        "focus": "migration_safety",
                        "skip_plan_analysis": "true",
                    },
                )

            # DML detection (non-SELECT)
            if re.match(r"^\s*(INSERT|UPDATE|DELETE|MERGE)\b", sql_upper):
                signals["is_dml"] = True
                oltp_score += 2.0  # DML is typically OLTP

            # OLAP signals from SQL
            olap_keywords = {
                "GROUP BY": 2.0,
                "HAVING": 1.5,
                "WINDOW": 2.0,
                "OVER (": 2.0,
                "PARTITION BY": 2.0,
                "CUBE": 2.5,
                "ROLLUP": 2.5,
                "GROUPING SETS": 2.5,
                "WITH RECURSIVE": 1.5,
                "UNION ALL": 1.5,
                "UNION": 1.0,
                "INTERSECT": 1.0,
                "EXCEPT": 1.0,
                "DISTINCT ON": 1.0,
            }
            for kw, weight in olap_keywords.items():
                if kw in sql_upper:
                    olap_score += weight
                    signals[f"sql_has_{kw.lower().replace(' ', '_')}"] = True

            # OLTP signals from SQL
            oltp_keywords = {
                "LIMIT": 1.5,
                "WHERE": 1.0,
                "= $": 1.5,  # Parameterized point lookup
                "= ?": 1.5,  # Parameterized point lookup
                "BY PRIMARY KEY": 2.0,
            }
            for kw, weight in oltp_keywords.items():
                if kw in sql_upper:
                    oltp_score += weight
                    signals[f"sql_has_{kw.lower().replace(' ', '_')}"] = True

            # Count joins — many joins suggest OLAP
            join_count = sql_upper.count(" JOIN ")
            signals["join_count"] = join_count
            if join_count > 3:
                olap_score += 1.5
            elif join_count <= 1:
                oltp_score += 0.5

            # Subquery count
            subquery_count = sql_upper.count("SELECT") - 1
            if subquery_count > 2:
                olap_score += 1.5
                signals["subquery_count"] = subquery_count

        # ── Plan-based signals ────────────────────────────────────────
        if explain:
            root = explain.plan
            if root:
                total_rows = root.raw.get("Actual Rows", root.raw.get("Plan Rows", 0))
                total_cost = root.raw.get("Total Cost", 0)
                actual_time = root.raw.get("Actual Total Time", 0)

                signals["total_rows"] = total_rows
                signals["total_cost"] = total_cost
                signals["actual_time_ms"] = actual_time

                # Row count signals
                if total_rows > 10000:
                    olap_score += 2.0
                    signals["large_result_set"] = True
                elif total_rows <= 100:
                    oltp_score += 2.0
                    signals["small_result_set"] = True

                # Execution time signals
                if actual_time and actual_time > 1000:  # >1 second
                    olap_score += 1.5
                elif actual_time and actual_time < 10:  # <10ms
                    oltp_score += 2.0

                # Walk plan tree for node type signals
                agg_count = 0
                sort_count = 0
                seq_scan_count = 0
                index_scan_count = 0
                parallel_count = 0
                has_limit = False

                for _, node_info, _ in self._iter_nodes(root):
                    nt = node_info.get("Node Type", "")
                    if "Aggregate" in nt:
                        agg_count += 1
                    if nt == "Sort":
                        sort_count += 1
                    if nt == "Seq Scan":
                        seq_scan_count += 1
                    if nt in ("Index Scan", "Index Only Scan"):
                        index_scan_count += 1
                    if "Parallel" in nt or "Gather" in nt:
                        parallel_count += 1
                    if nt == "Limit":
                        has_limit = True

                signals["aggregate_nodes"] = agg_count
                signals["index_scan_nodes"] = index_scan_count
                signals["seq_scan_nodes"] = seq_scan_count
                signals["parallel_nodes"] = parallel_count

                if agg_count > 0:
                    olap_score += agg_count * 1.5
                if parallel_count > 0:
                    olap_score += 2.0
                if index_scan_count > 0 and seq_scan_count == 0:
                    oltp_score += 2.0
                if has_limit:
                    oltp_score += 1.0

        # ── Compute classification ────────────────────────────────────
        total = oltp_score + olap_score
        if total == 0:
            return ClassificationResult(
                query_class=QueryClass.HYBRID,
                confidence=0.5,
                signals=signals,
            )

        oltp_ratio = oltp_score / total
        olap_ratio = olap_score / total

        if oltp_ratio > 0.65:
            qclass = QueryClass.OLTP
            confidence = min(0.99, 0.6 + oltp_ratio * 0.4)
        elif olap_ratio > 0.65:
            qclass = QueryClass.OLAP
            confidence = min(0.99, 0.6 + olap_ratio * 0.4)
        else:
            qclass = QueryClass.HYBRID
            confidence = 0.5 + abs(oltp_ratio - olap_ratio) * 0.3

        # Build recommendation adjustments
        adjustments = self._build_adjustments(qclass)

        return ClassificationResult(
            query_class=qclass,
            confidence=round(confidence, 2),
            signals=signals,
            recommendation_adjustments=adjustments,
        )

    def _build_adjustments(self, qclass: QueryClass) -> dict[str, str]:
        """Build recommendation adjustments based on query class."""
        if qclass == QueryClass.OLTP:
            return {
                "index_strategy": "Prioritize index-only scans to minimize I/O",
                "memory_strategy": "Keep work_mem moderate — many concurrent queries share RAM",
                "parallelism": "Skip parallel recommendations — overhead exceeds benefit for small queries",
                "focus": "Latency reduction: every millisecond counts for OLTP",
                "connection_pooling": "Recommend PgBouncer if not already in use",
            }
        elif qclass == QueryClass.OLAP:
            return {
                "index_strategy": "Consider partial indexes and covering indexes for filtered aggregations",
                "memory_strategy": "Increase work_mem aggressively — fewer concurrent queries need more RAM each",
                "parallelism": "Maximize parallel workers — OLAP benefits most from multi-core",
                "focus": "Throughput optimization: scan speed and parallelism over latency",
                "materialized_views": "Consider materialized views for repeated expensive aggregations",
                "partitioning": "Partition large tables by time for efficient range scans",
            }
        elif qclass == QueryClass.DDL:
            return {
                "focus": "Migration safety: lock analysis, rollback generation",
            }
        else:
            return {
                "focus": "Balanced optimization: consider both latency and throughput",
            }

    @staticmethod
    def _iter_nodes(root: Any, path: str = "0") -> list[tuple[str, dict, dict | None]]:
        """Walk the plan tree and yield (path, raw_dict, parent_raw_dict)."""
        results = []
        raw = root.raw if hasattr(root, "raw") else root

        def _walk(node_raw: dict, current_path: str, parent: dict | None) -> None:
            results.append((current_path, node_raw, parent))
            for i, child in enumerate(node_raw.get("Plans", [])):
                _walk(child, f"{current_path}.{i}", node_raw)

        _walk(raw, path, None)
        return results
