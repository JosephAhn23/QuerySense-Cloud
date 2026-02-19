"""Rule: Gather Worker Shortage — planned workers not launched."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import Finding, ImpactBand, NodeContext, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class GatherWorkerConfig(RuleConfig):
    min_planned_workers: int = Field(default=1, ge=1, description="Minimum planned workers to check")


@register_rule
class GatherWorkerShortage(Rule):
    """Detect Gather/Gather Merge with fewer workers than planned."""

    rule_id = "GATHER_WORKER_SHORTAGE"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Parallel query launched fewer workers than planned"
    config_schema = GatherWorkerConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: GatherWorkerConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type not in ("Gather", "Gather Merge"):
                continue

            raw = node.raw
            planned = raw.get("Workers Planned", 0)
            launched = raw.get("Workers Launched", 0)

            if planned < config.min_planned_workers:
                continue

            if launched >= planned:
                continue

            shortage = planned - launched
            context = NodeContext.from_node(node, path, parent)

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                context=context,
                title=f"{node.node_type}: {launched}/{planned} workers launched",
                description=(
                    f"PostgreSQL planned {planned} parallel workers but only launched "
                    f"{launched}. The missing {shortage} worker(s) mean the query runs "
                    f"slower than the planner expected. This usually means "
                    f"max_parallel_workers or max_parallel_workers_per_gather is set "
                    f"too low, or other queries are consuming the worker pool."
                ),
                suggestion=(
                    f"-- Check parallel worker settings\n"
                    f"SHOW max_parallel_workers;\n"
                    f"SHOW max_parallel_workers_per_gather;\n"
                    f"-- Consider increasing:\n"
                    f"ALTER SYSTEM SET max_parallel_workers = {planned * 2};\n"
                    f"ALTER SYSTEM SET max_parallel_workers_per_gather = {planned};\n"
                    f"SELECT pg_reload_conf();"
                ),
                impact_band=ImpactBand.MEDIUM,
                metrics={
                    "workers_planned": planned,
                    "workers_launched": launched,
                    "workers_missing": shortage,
                },
            ))

        return findings
