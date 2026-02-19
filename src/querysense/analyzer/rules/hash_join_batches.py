"""Rule: Hash Join Batches — detects hash joins spilling to multiple batches."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import Finding, ImpactBand, NodeContext, Severity
from querysense.analyzer.registry import register_rule
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class HashJoinBatchesConfig(RuleConfig):
    min_batches: int = Field(default=2, ge=1, description="Minimum batches to trigger warning")
    critical_batches: int = Field(default=16, ge=2, description="Batches to escalate to critical")


@register_rule
class HashJoinBatches(Rule):
    """Detect hash joins using multiple batches (memory pressure)."""

    rule_id = "HASH_JOIN_BATCHES"
    version = "1.0.0"
    severity = Severity.WARNING
    description = "Hash join using multiple batches indicates work_mem is too low"
    config_schema = HashJoinBatchesConfig

    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        config: HashJoinBatchesConfig = self.config  # type: ignore[assignment]
        findings: list[Finding] = []

        for path, node, parent in self.iter_nodes_with_parent(explain):
            if node.node_type not in ("Hash Join", "Hash"):
                continue

            raw = node.raw
            hash_batches = raw.get("Hash Batches", 1)
            original_batches = raw.get("Original Hash Batches", 1)
            peak_memory = raw.get("Peak Memory Usage", 0)

            if hash_batches < config.min_batches:
                continue

            severity = (
                Severity.CRITICAL if hash_batches >= config.critical_batches
                else self.severity
            )

            table = node.relation_name or "hash table"
            context = NodeContext.from_node(node, path, parent)

            work_mem_suggestion = max(peak_memory * 2, 64) if peak_memory else "higher"

            findings.append(Finding(
                rule_id=self.rule_id,
                severity=severity,
                context=context,
                title=f"Hash join using {hash_batches} batches on {table}",
                description=(
                    f"Hash join required {hash_batches} batches (originally planned: "
                    f"{original_batches}). Multiple batches mean the hash table doesn't "
                    f"fit in work_mem and must be written to disk, dramatically slowing "
                    f"the join operation."
                ),
                suggestion=(
                    f"-- Increase work_mem for this query\n"
                    f"SET work_mem = '{work_mem_suggestion}MB';\n"
                    f"-- Or globally: ALTER SYSTEM SET work_mem = '{work_mem_suggestion}MB';\n"
                    f"-- Then: SELECT pg_reload_conf();"
                ),
                impact_band=ImpactBand.MEDIUM if hash_batches < 8 else ImpactBand.HIGH,
                metrics={
                    "hash_batches": hash_batches,
                    "original_batches": original_batches,
                    "peak_memory_kb": peak_memory,
                },
            ))

        return findings
