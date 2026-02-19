"""Rule: Memoize Cache Miss Rate — detects inefficient Memoize nodes (PG14+)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import Finding, ImpactBand, NodeContext, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class MemoizeMissConfig(RuleConfig):
    miss_rate_warning: float = Field(default=0.5, ge=0.0, le=1.0, description="Miss rate to trigger warning")
    miss_rate_critical: float = Field(default=0.9, ge=0.0, le=1.0, description="Miss rate for critical")
    min_calls: int = Field(default=100, ge=1, description="Minimum calls to evaluate")


@register_rule
class MemoizeMissRate(Rule):
    """Detect Memoize nodes with high cache miss rate (PG14+)."""

    rule_id = "MEMOIZE_MISS_RATE"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Memoize node with high cache miss rate adds overhead without benefit"
    config_schema = MemoizeMissConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: MemoizeMissConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type != "Memoize":
                continue

            raw = node.raw
            cache_hits = raw.get("Cache Hits", 0)
            cache_misses = raw.get("Cache Misses", 0)
            cache_evictions = raw.get("Cache Evictions", 0)
            total_calls = cache_hits + cache_misses

            if total_calls < config.min_calls:
                continue

            miss_rate = cache_misses / total_calls if total_calls > 0 else 0

            if miss_rate < config.miss_rate_warning:
                continue

            severity = (
                Severity.CRITICAL if miss_rate >= config.miss_rate_critical
                else self.severity
            )
            context = NodeContext.from_node(node, path, parent)

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=f"Memoize cache miss rate: {miss_rate:.0%} ({cache_misses:,}/{total_calls:,})",
                description=(
                    f"The Memoize node has a {miss_rate:.0%} cache miss rate "
                    f"({cache_hits:,} hits, {cache_misses:,} misses, "
                    f"{cache_evictions:,} evictions). High miss rates mean the "
                    f"cache adds overhead without reducing repeated computations. "
                    f"This typically happens when the parameterized values have "
                    f"high cardinality."
                ),
                suggestion=(
                    f"-- Disable memoize for this query if miss rate is consistently high\n"
                    f"SET enable_memoize = off;\n"
                    f"-- Or increase work_mem to reduce evictions"
                ),
                impact_band=ImpactBand.LOW if miss_rate < 0.8 else ImpactBand.MEDIUM,
                metrics={
                    "cache_hits": cache_hits,
                    "cache_misses": cache_misses,
                    "cache_evictions": cache_evictions,
                    "miss_rate": round(miss_rate, 4),
                },
            ))

        return findings
