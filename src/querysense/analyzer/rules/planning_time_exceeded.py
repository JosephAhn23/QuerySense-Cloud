"""
Rule: Planning Time Exceeded (AGGREGATE)

Detects queries where planning time is a significant fraction of total
execution, indicating planning overhead that warrants attention.

Why it matters:
- For some workloads, planning time is a first-class latency component
- Partitioned tables with many partitions can have planning times that
  dominate execution time
- Complex queries with many joins can have exponential planning costs
- Prepared statements help but interact badly with connection pooling
  and can themselves cause generic-plan regressions

Detection:
- Checks ExplainOutput.planning_time against configurable thresholds
- Checks ratio of planning time to execution time
- Both absolute and relative thresholds are supported

Requires EXPLAIN ANALYZE (planning_time is only available with ANALYZE).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import (
    Finding,
    ImpactBand,
    NodeContext,
    RulePhase,
    Severity,
)
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class PlanningTimeConfig(RuleConfig):
    """
    Configuration for planning time detection.

    Attributes:
        warning_ms: Planning time in ms to trigger WARNING (default 100ms).
        critical_ms: Planning time in ms to trigger CRITICAL (default 1000ms).
        ratio_warning: Planning/execution ratio to trigger WARNING (default 0.5).
        ratio_critical: Planning/execution ratio to trigger CRITICAL (default 2.0).
    """

    warning_ms: float = Field(
        default=100.0,
        ge=0.0,
        description="Planning time threshold for WARNING (ms)",
    )
    critical_ms: float = Field(
        default=1000.0,
        ge=0.0,
        description="Planning time threshold for CRITICAL (ms)",
    )
    ratio_warning: float = Field(
        default=0.5,
        ge=0.0,
        description="Planning/execution time ratio for WARNING",
    )
    ratio_critical: float = Field(
        default=2.0,
        ge=0.0,
        description="Planning/execution time ratio for CRITICAL",
    )


@register_rule
class PlanningTimeExceeded(Rule):
    """
    Detect queries with excessive planning time.

    This AGGREGATE rule checks the top-level planning time from EXPLAIN
    ANALYZE against configurable absolute and relative thresholds.
    """

    rule_id = "PLANNING_TIME_EXCEEDED"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Detects queries with excessive planning time"
    config_schema = PlanningTimeConfig
    phase = RulePhase.AGGREGATE

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Check planning time against thresholds."""
        config: PlanningTimeConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        planning_time = explain.planning_time
        execution_time = explain.execution_time

        # Need planning time data
        if planning_time is None:
            return []

        # Absolute threshold check
        abs_finding = self._check_absolute(planning_time, execution_time, config)
        if abs_finding:
            findings.append(abs_finding)

        # Ratio threshold check (only if we also have execution time)
        if execution_time is not None and execution_time > 0:
            ratio_finding = self._check_ratio(
                planning_time, execution_time, config
            )
            if ratio_finding:
                findings.append(ratio_finding)

        return findings

    def _check_absolute(
        self,
        planning_time: float,
        execution_time: float | None,
        config: PlanningTimeConfig,
    ) -> Finding | None:
        """Check absolute planning time threshold."""
        if planning_time < config.warning_ms:
            return None

        severity = (
            Severity.CRITICAL if planning_time >= config.critical_ms
            else Severity.WARNING
        )

        exec_info = ""
        if execution_time is not None:
            exec_info = f", execution: {execution_time:.1f}ms"

        return Finding(
            rule_id=self.rule_id,
            severity=severity,
            context=NodeContext.root("Query"),
            title=(
                f"Planning time {planning_time:.1f}ms exceeds "
                f"threshold ({config.warning_ms:.0f}ms)"
            ),
            description=(
                f"Query planning took {planning_time:.1f}ms{exec_info}. "
                f"High planning time can dominate total query latency, "
                f"especially for frequently-executed queries.\n\n"
                f"Common causes:\n"
                f"- Partitioned tables with many partitions\n"
                f"- Complex queries with many joins (exponential planning cost)\n"
                f"- Many candidate indexes to evaluate\n"
                f"- Generated SQL with excessive joins or unions"
            ),
            suggestion=self._build_suggestion(planning_time),
            metrics={
                "planning_time_ms": planning_time,
                "execution_time_ms": execution_time or 0.0,
                "total_time_ms": planning_time + (execution_time or 0.0),
            },
            impact_band=(
                ImpactBand.HIGH if planning_time > 1000
                else ImpactBand.MEDIUM
            ),
            assumptions=(
                "Planning time is consistent across executions",
                "Planning overhead is per-execution (not amortized with PREPARE)",
            ),
            verification_steps=(
                "Run EXPLAIN ANALYZE multiple times to confirm planning time is stable",
                "Test with PREPARE/EXECUTE to amortize planning cost",
                "Check if partitioned tables can be consolidated",
                "Review query for unnecessary join complexity",
            ),
        )

    def _check_ratio(
        self,
        planning_time: float,
        execution_time: float,
        config: PlanningTimeConfig,
    ) -> Finding | None:
        """Check planning-to-execution time ratio."""
        ratio = planning_time / execution_time

        if ratio < config.ratio_warning:
            return None

        severity = (
            Severity.CRITICAL if ratio >= config.ratio_critical
            else Severity.WARNING
        )

        planning_pct = (planning_time / (planning_time + execution_time)) * 100

        return Finding(
            rule_id=self.rule_id,
            severity=severity,
            context=NodeContext.root("Query"),
            title=(
                f"Planning time ({planning_time:.1f}ms) is "
                f"{ratio:.1f}x the execution time ({execution_time:.1f}ms)"
            ),
            description=(
                f"Planning takes {planning_pct:.0f}% of total query time "
                f"({planning_time:.1f}ms planning + {execution_time:.1f}ms execution). "
                f"When planning dominates execution, the query is 'plan-bound' — "
                f"using PREPARE/EXECUTE or a connection pooler that caches plans "
                f"can dramatically reduce per-query latency."
            ),
            suggestion=(
                "-- Use prepared statements to amortize planning cost:\n"
                "PREPARE my_query (type1, type2) AS\n"
                "    SELECT ... WHERE col1 = $1 AND col2 = $2;\n"
                "EXECUTE my_query('value1', 'value2');\n"
                "\n"
                "-- Caution: prepared statements may use generic plans.\n"
                "-- Monitor for plan quality regression after switching.\n"
                "\n"
                "-- If using partitioned tables, consider:\n"
                "-- 1. Reducing partition count\n"
                "-- 2. Using partition-aware prepared statements\n"
                "-- 3. Upgrading PostgreSQL (planning overhead improves per release)\n"
                "\n"
                "-- Docs: https://www.postgresql.org/docs/current/sql-prepare.html"
            ),
            metrics={
                "planning_time_ms": planning_time,
                "execution_time_ms": execution_time,
                "planning_ratio": round(ratio, 2),
                "planning_pct": round(planning_pct, 1),
            },
            impact_band=(
                ImpactBand.HIGH if ratio > 5
                else ImpactBand.MEDIUM
            ),
            assumptions=(
                "Query is executed frequently enough that planning cost matters",
                "Prepared statements are feasible for this workload",
            ),
            verification_steps=(
                "Test with PREPARE/EXECUTE and measure total latency",
                "Check if connection pooling supports plan caching",
                "Verify generic plan quality after switching to PREPARE",
            ),
        )

    def _build_suggestion(self, planning_time: float) -> str:
        """Build actionable suggestion for high planning time."""
        lines = [
            "-- Reduce planning overhead with prepared statements:",
            "PREPARE my_query (type1, type2) AS <your query>;",
            "EXECUTE my_query('value1', 'value2');",
            "",
            "-- For connection-pooled environments:",
            "-- Use DEALLOCATE ALL when returning connections to the pool",
            "",
        ]

        if planning_time > 500:
            lines.extend([
                "-- For very high planning times (>500ms), investigate:",
                "-- 1. Partitioned tables with excessive partition counts",
                "-- 2. Queries with 10+ joins (combinatorial explosion)",
                "-- 3. join_collapse_limit / from_collapse_limit settings",
                "SET join_collapse_limit = 8;  -- Reduce from default 8 if higher",
                "",
            ])

        lines.append(
            "-- Docs: https://www.postgresql.org/docs/current/runtime-config-query.html"
        )

        return "\n".join(lines)
