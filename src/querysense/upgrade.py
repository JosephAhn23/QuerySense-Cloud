"""
Post-upgrade plan validation for QuerySense.

Compares query plans across PostgreSQL version upgrades to detect
regressions introduced by planner changes. Fills the $50K consulting gap.

Usage:
    from querysense.upgrade import UpgradeValidator, UpgradeConfig

    validator = UpgradeValidator(UpgradeConfig(
        source_dsn="postgresql://localhost:5432/mydb",
        target_dsn="postgresql://localhost:5433/mydb",
    ))
    report = validator.validate()

CLI:
    querysense upgrade compare \\
        --source postgresql://localhost:5432/mydb \\
        --target postgresql://localhost:5433/mydb \\
        --top-queries 100
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ── Version-Specific Knowledge Base ────────────────────────────────────


@dataclass(frozen=True)
class VersionChange:
    """A known optimizer change between PostgreSQL versions."""

    from_version: int  # e.g. 15
    to_version: int  # e.g. 16
    title: str
    description: str
    risk_level: str  # "improvement", "neutral", "risk"
    affected_node_types: tuple[str, ...] = ()
    detection_hint: str = ""


VERSION_KNOWLEDGE_BASE: list[VersionChange] = [
    # PG 14 → 15
    VersionChange(
        from_version=14, to_version=15,
        title="Sort performance improvements",
        description="3-44% faster sorts with Datum-only storage for single-column sorts",
        risk_level="improvement",
        affected_node_types=("Sort",),
        detection_hint="Sort operations may show different memory profiles",
    ),
    # PG 15 → 16
    VersionChange(
        from_version=15, to_version=16,
        title="Incremental Sort for DISTINCT",
        description="63% faster DISTINCT queries using Incremental Sort",
        risk_level="improvement",
        affected_node_types=("Incremental Sort", "Sort", "Unique"),
        detection_hint="Hash Aggregate → Incremental Sort transition",
    ),
    VersionChange(
        from_version=15, to_version=16,
        title="Memoize for UNION ALL",
        description="6x faster UNION ALL with Memoize nodes",
        risk_level="improvement",
        affected_node_types=("Memoize", "Append"),
        detection_hint="New Memoize nodes in UNION ALL queries",
    ),
    VersionChange(
        from_version=15, to_version=16,
        title="Right Anti Join for NOT EXISTS",
        description="Execution time nearly halved for NOT EXISTS patterns",
        risk_level="improvement",
        affected_node_types=("Nested Loop", "Hash Join"),
        detection_hint="Anti join strategy changes in NOT EXISTS subqueries",
    ),
    VersionChange(
        from_version=15, to_version=16,
        title="Pre-sorted aggregation optimization",
        description="ORDER BY/DISTINCT aggregates >2x faster when pre-sorted",
        risk_level="neutral",
        affected_node_types=("Aggregate", "GroupAggregate", "HashAggregate"),
        detection_hint="Hash Aggregate may become Group Aggregate with pre-sorted input",
    ),
    # PG 16 → 17
    VersionChange(
        from_version=16, to_version=17,
        title="CTE statistics propagation",
        description="Materialized CTEs share pathkeys with outer query, enabling merge joins",
        risk_level="risk",
        affected_node_types=("CTE Scan", "Hash Join", "Merge Join"),
        detection_hint="Hash Join → Merge Join in queries with CTEs",
    ),
    VersionChange(
        from_version=16, to_version=17,
        title="B-tree IN list optimization",
        description="Multi-value IN lookups use single scan instead of bitmap",
        risk_level="improvement",
        affected_node_types=("Index Scan", "Bitmap Index Scan", "Bitmap Heap Scan"),
        detection_hint="Bitmap scans replaced by Index Scans for IN clauses",
    ),
    VersionChange(
        from_version=16, to_version=17,
        title="IS NULL/NOT NULL optimization",
        description="Redundant checks eliminated on NOT NULL columns",
        risk_level="improvement",
        affected_node_types=("Filter",),
        detection_hint="Simplified filter conditions",
    ),
    # PG 17 → 18
    VersionChange(
        from_version=17, to_version=18,
        title="Statistics preservation during pg_upgrade",
        description="pg_dump --statistics-only preserves stats across upgrades",
        risk_level="improvement",
        affected_node_types=(),
        detection_hint="Post-upgrade plans should match pre-upgrade without ANALYZE",
    ),
]


def get_version_changes(from_ver: int, to_ver: int) -> list[VersionChange]:
    """Get known optimizer changes between two PostgreSQL major versions."""
    changes: list[VersionChange] = []
    for change in VERSION_KNOWLEDGE_BASE:
        if change.from_version >= from_ver and change.to_version <= to_ver:
            changes.append(change)
    return changes


# ── Plan Comparison ────────────────────────────────────────────────────


@dataclass(frozen=True)
class PlanDiff:
    """Diff between two query plans."""

    queryid: str
    query_text: str
    severity: str  # "critical", "high", "medium", "low", "info"
    severity_score: int  # 0-100

    # Structural changes
    node_type_changes: list[dict[str, str]] = field(default_factory=list)
    nodes_added: list[str] = field(default_factory=list)
    nodes_removed: list[str] = field(default_factory=list)

    # Cost changes
    source_cost: float = 0.0
    target_cost: float = 0.0
    cost_change_percent: float = 0.0

    # Version-specific context
    known_changes: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @property
    def is_regression(self) -> bool:
        return self.severity in ("critical", "high", "medium")

    @property
    def is_improvement(self) -> bool:
        return self.cost_change_percent < -10 and not self.node_type_changes

    def to_dict(self) -> dict[str, Any]:
        return {
            "queryid": self.queryid,
            "query_text": self.query_text[:200],
            "severity": self.severity,
            "severity_score": self.severity_score,
            "node_type_changes": self.node_type_changes,
            "nodes_added": self.nodes_added,
            "nodes_removed": self.nodes_removed,
            "source_cost": round(self.source_cost, 2),
            "target_cost": round(self.target_cost, 2),
            "cost_change_percent": round(self.cost_change_percent, 1),
            "known_changes": self.known_changes,
            "recommendations": self.recommendations,
            "is_regression": self.is_regression,
            "is_improvement": self.is_improvement,
        }


@dataclass(frozen=True)
class UpgradeReport:
    """Complete upgrade validation report."""

    source_version: str
    target_version: str
    total_queries: int
    regressions: int
    improvements: int
    unchanged: int
    critical_regressions: int
    diffs: tuple[PlanDiff, ...] = ()
    known_changes: tuple[VersionChange, ...] = ()
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def safe_to_upgrade(self) -> bool:
        return self.critical_regressions == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_version": self.source_version,
            "target_version": self.target_version,
            "total_queries": self.total_queries,
            "regressions": self.regressions,
            "improvements": self.improvements,
            "unchanged": self.unchanged,
            "critical_regressions": self.critical_regressions,
            "safe_to_upgrade": self.safe_to_upgrade,
            "timestamp": self.timestamp,
            "diffs": [d.to_dict() for d in self.diffs],
            "known_changes": [
                {"title": c.title, "description": c.description, "risk_level": c.risk_level}
                for c in self.known_changes
            ],
        }

    def render_summary(self) -> str:
        """Render a human-readable summary."""
        lines = [
            f"PostgreSQL Upgrade Validation: {self.source_version} -> {self.target_version}",
            "=" * 70,
            f"Total queries compared: {self.total_queries}",
            f"Regressions: {self.regressions} ({self.critical_regressions} critical)",
            f"Improvements: {self.improvements}",
            f"Unchanged: {self.unchanged}",
            "",
            f"Safe to upgrade: {'YES' if self.safe_to_upgrade else 'NO'}",
            "",
        ]

        if self.diffs:
            regressions = [d for d in self.diffs if d.is_regression]
            if regressions:
                lines.append("REGRESSIONS:")
                lines.append("-" * 40)
                for d in sorted(regressions, key=lambda x: -x.severity_score):
                    lines.append(
                        f"  [{d.severity.upper()}] {d.queryid}: "
                        f"cost {d.source_cost:.0f} -> {d.target_cost:.0f} "
                        f"({d.cost_change_percent:+.1f}%)"
                    )
                    for change in d.node_type_changes:
                        lines.append(
                            f"    {change['path']}: {change['before']} -> {change['after']}"
                        )
                    for rec in d.recommendations:
                        lines.append(f"    -> {rec}")
                    lines.append("")

        if self.known_changes:
            lines.append("KNOWN OPTIMIZER CHANGES:")
            lines.append("-" * 40)
            for c in self.known_changes:
                risk_icon = {"improvement": "+", "neutral": "~", "risk": "!"}
                lines.append(f"  [{risk_icon.get(c.risk_level, '?')}] {c.title}")
                lines.append(f"      {c.description}")
            lines.append("")

        return "\n".join(lines)


# ── Upgrade Configuration ──────────────────────────────────────────────


@dataclass
class UpgradeConfig:
    """Configuration for upgrade validation."""

    source_dsn: str = ""
    target_dsn: str = ""
    top_queries: int = 100
    include_queryids: list[str] = field(default_factory=list)
    use_generic_plans: bool = True
    output_format: str = "text"  # "text", "json", "markdown"


# ── Upgrade Validator ──────────────────────────────────────────────────


class UpgradeValidator:
    """
    Validates query plans across PostgreSQL version upgrades.

    Connects to source and target instances, fetches top-N queries
    from pg_stat_statements, runs EXPLAIN on both, and produces a
    detailed regression report with version-specific context.
    """

    def __init__(self, config: UpgradeConfig) -> None:
        self.config = config

    def validate(self) -> UpgradeReport:
        """
        Run the full upgrade validation.

        Returns an UpgradeReport with all plan diffs and recommendations.
        """
        try:
            import psycopg
        except ImportError:
            logger.error(
                "psycopg not installed. Install with: pip install 'querysense[db]'"
            )
            raise SystemExit(1)

        source_version = ""
        target_version = ""
        diffs: list[PlanDiff] = []

        with psycopg.connect(self.config.source_dsn) as source_conn, \
             psycopg.connect(self.config.target_dsn) as target_conn:

            source_version = self._get_pg_version(source_conn)
            target_version = self._get_pg_version(target_conn)

            logger.info(
                "Upgrade validation: %s -> %s", source_version, target_version
            )

            # Get top queries from source
            queries = self._get_top_queries(source_conn)
            logger.info("Comparing %d queries", len(queries))

            for queryid, query_text in queries:
                try:
                    diff = self._compare_query(
                        source_conn, target_conn,
                        queryid, query_text,
                        source_version, target_version,
                    )
                    if diff is not None:
                        diffs.append(diff)
                except Exception as e:
                    logger.warning("Failed to compare query %s: %s", queryid, e)

        # Get known version changes
        source_major = _parse_major_version(source_version)
        target_major = _parse_major_version(target_version)
        known_changes = tuple(get_version_changes(source_major, target_major))

        regressions = sum(1 for d in diffs if d.is_regression)
        improvements = sum(1 for d in diffs if d.is_improvement)
        critical = sum(1 for d in diffs if d.severity in ("critical", "high"))

        return UpgradeReport(
            source_version=source_version,
            target_version=target_version,
            total_queries=len(diffs),
            regressions=regressions,
            improvements=improvements,
            unchanged=len(diffs) - regressions - improvements,
            critical_regressions=critical,
            diffs=tuple(sorted(diffs, key=lambda d: -d.severity_score)),
            known_changes=known_changes,
        )

    def _get_pg_version(self, conn: Any) -> str:
        """Get PostgreSQL version string."""
        with conn.cursor() as cur:
            cur.execute("SHOW server_version")
            return str(cur.fetchone()[0])

    def _get_top_queries(self, conn: Any) -> list[tuple[str, str]]:
        """Fetch top-N queries from pg_stat_statements."""
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT queryid::text, query
                FROM pg_stat_statements
                WHERE query NOT LIKE '%pg_stat%'
                  AND query NOT LIKE '%pg_catalog%'
                ORDER BY total_exec_time DESC
                LIMIT %s
                """,
                [self.config.top_queries],
            )
            return [(str(row[0]), row[1]) for row in cur.fetchall()]

    def _compare_query(
        self,
        source_conn: Any,
        target_conn: Any,
        queryid: str,
        query_text: str,
        source_version: str,
        target_version: str,
    ) -> PlanDiff | None:
        """Compare a single query's plan between source and target."""
        source_plan = self._get_explain(source_conn, query_text)
        target_plan = self._get_explain(target_conn, query_text)

        if source_plan is None or target_plan is None:
            return None

        # Compare plans
        source_nodes = self._extract_nodes(source_plan)
        target_nodes = self._extract_nodes(target_plan)

        node_changes, added, removed = self._diff_nodes(source_nodes, target_nodes)

        source_cost = source_plan.get("Total Cost", 0)
        target_cost = target_plan.get("Total Cost", 0)
        cost_pct = 0.0
        if source_cost > 0:
            cost_pct = ((target_cost - source_cost) / source_cost) * 100

        # Score severity
        score = self._score_diff(node_changes, added, removed, cost_pct)
        sev = _severity_from_score(score)

        # Match against known version changes
        source_major = _parse_major_version(source_version)
        target_major = _parse_major_version(target_version)
        known = get_version_changes(source_major, target_major)
        matched_changes = self._match_known_changes(node_changes, added, known)

        # Generate recommendations
        recs = self._generate_recommendations(node_changes, cost_pct, sev)

        return PlanDiff(
            queryid=queryid,
            query_text=query_text[:500],
            severity=sev,
            severity_score=score,
            node_type_changes=node_changes,
            nodes_added=added,
            nodes_removed=removed,
            source_cost=source_cost,
            target_cost=target_cost,
            cost_change_percent=cost_pct,
            known_changes=matched_changes,
            recommendations=recs,
        )

    def _get_explain(self, conn: Any, query_text: str) -> dict[str, Any] | None:
        """Run EXPLAIN on a query and return the plan JSON."""
        try:
            explain_sql = f"EXPLAIN (FORMAT JSON, COSTS) {query_text}"
            with conn.cursor() as cur:
                cur.execute(explain_sql)
                result = cur.fetchone()
                if result and result[0]:
                    plans = result[0]
                    if isinstance(plans, str):
                        plans = json.loads(plans)
                    if isinstance(plans, list) and plans:
                        return plans[0].get("Plan", {})
        except Exception as e:
            logger.debug("EXPLAIN failed for query %s: %s", query_text[:50], e)
            conn.rollback()
        return None

    def _extract_nodes(
        self, plan: dict[str, Any], path: str = "0"
    ) -> dict[str, dict[str, Any]]:
        """Extract nodes indexed by path."""
        nodes: dict[str, dict[str, Any]] = {}
        nodes[path] = {
            "node_type": plan.get("Node Type", "Unknown"),
            "relation_name": plan.get("Relation Name"),
            "index_name": plan.get("Index Name"),
            "join_type": plan.get("Join Type"),
            "total_cost": plan.get("Total Cost", 0),
        }
        for i, child in enumerate(plan.get("Plans", [])):
            child_path = f"{path}.{i}"
            nodes.update(self._extract_nodes(child, child_path))
        return nodes

    def _diff_nodes(
        self,
        source: dict[str, dict[str, Any]],
        target: dict[str, dict[str, Any]],
    ) -> tuple[list[dict[str, str]], list[str], list[str]]:
        """Diff two node sets. Delegates to shared plan_diff utility."""
        from querysense.plan_diff import diff_plan_nodes

        return diff_plan_nodes(source, target)

    def _score_diff(
        self,
        changes: list[dict[str, str]],
        added: list[str],
        removed: list[str],
        cost_pct: float,
    ) -> int:
        """Score the severity of a plan diff."""
        score = 0

        # Node type downgrades
        for change in changes:
            before = change["before"]
            after = change["after"]

            # Scan downgrades
            if before in ("Index Scan", "Index Only Scan") and after == "Seq Scan":
                score = max(score, 85)
            elif before == "Bitmap Heap Scan" and after == "Seq Scan":
                score = max(score, 70)
            elif before == "Index Only Scan" and after == "Index Scan":
                score = max(score, 30)

            # Join changes
            elif before == "Hash Join" and after == "Nested Loop":
                score = max(score, 60)
            elif before == "Merge Join" and after == "Nested Loop":
                score = max(score, 65)

            # Parallel loss
            elif "Parallel" in before and "Parallel" not in after:
                score = max(score, 50)

            # Any other change
            else:
                score = max(score, 20)

        # Nodes added/removed
        score += min(len(added) * 5, 20)
        score += min(len(removed) * 5, 20)

        # Cost increase
        if cost_pct > 500:
            score = max(score, 70)
        elif cost_pct > 100:
            score = max(score, 50)
        elif cost_pct > 50:
            score = max(score, 30)
        elif cost_pct > 10:
            score = max(score, 15)

        return min(score, 100)

    def _match_known_changes(
        self,
        node_changes: list[dict[str, str]],
        nodes_added: list[str],
        known: list[VersionChange],
    ) -> list[str]:
        """Match plan diffs against known version changes."""
        matches: list[str] = []
        all_types = set()
        for c in node_changes:
            all_types.add(c["before"])
            all_types.add(c["after"])
        for n in nodes_added:
            parts = n.split(": ", 1)
            if len(parts) == 2:
                all_types.add(parts[1])

        for change in known:
            if any(t in all_types for t in change.affected_node_types):
                matches.append(f"{change.title}: {change.description}")

        return matches

    def _generate_recommendations(
        self,
        changes: list[dict[str, str]],
        cost_pct: float,
        severity: str,
    ) -> list[str]:
        """Generate recommendations based on plan diffs."""
        recs: list[str] = []

        for change in changes:
            before = change["before"]
            after = change["after"]
            relation = change.get("relation", "")

            if after == "Seq Scan" and before in ("Index Scan", "Index Only Scan"):
                recs.append(
                    f"Run ANALYZE on {relation or 'affected table'} to refresh statistics"
                )
                recs.append(
                    "Check if indexes exist and match the query pattern on the target instance"
                )
            elif "Nested Loop" in after and before in ("Hash Join", "Merge Join"):
                recs.append("Verify work_mem is sufficient on the target instance")
                recs.append("Run ANALYZE on both sides of the join")

        if cost_pct > 100 and not recs:
            recs.append("Run ANALYZE on all tables after upgrade")
            recs.append("Review optimizer parameter changes between versions")

        if severity in ("critical", "high"):
            recs.append(
                "Consider using pg_hint_plan to force the original plan while investigating"
            )

        return recs


# ── Helpers ────────────────────────────────────────────────────────────


def _parse_major_version(version_str: str) -> int:
    """Parse major version from version string (e.g., '16.2' -> 16)."""
    try:
        return int(version_str.split(".")[0])
    except (ValueError, IndexError):
        return 0


def _severity_from_score(score: int) -> str:
    """Convert severity score to label."""
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 30:
        return "medium"
    if score >= 10:
        return "low"
    return "info"
