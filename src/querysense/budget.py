"""
Performance Budgets as Code — declarative query performance constraints.

Defines budgets in a `query-performance.yml` file committed to the repo.
Each budget specifies latency, cost, or structural constraints for named
queries or query patterns. CI pipelines enforce these automatically.

This moves performance from "afterthought" to "contract" — every query
that matters has a budget, and regressions are caught before merge.

File format (query-performance.yml):
    version: "1.0"

    defaults:
      max_cost: 50000
      max_time_ms: 200
      deny_seq_scan_above: 10000
      require_index_scan: false

    budgets:
      get_user_by_id:
        sql_pattern: "SELECT.*FROM users WHERE id ="
        max_cost: 100
        max_time_ms: 5
        require_index_scan: true
        alert: critical

      search_orders:
        sql_pattern: "SELECT.*FROM orders WHERE.*status"
        max_cost: 5000
        max_time_ms: 50
        deny_seq_scan_above: 1000
        alert: warning

      dashboard_query:
        plan_file: plans/dashboard.json
        max_cost: 20000
        max_time_ms: 200
        max_findings: 2
        max_critical_findings: 0

    labels:
      hot_path:
        max_time_ms: 10
        require_index_scan: true

Usage:
    from querysense.budget import BudgetEngine, load_budgets

    engine = load_budgets("query-performance.yml")
    violations = engine.check(analysis_result, query_name="get_user_by_id")
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

BUDGET_SCHEMA_VERSION = "1.0"


class AlertLevel(str, Enum):
    """How urgently a budget violation should be treated."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    BLOCKING = "blocking"  # Fails CI


@dataclass(frozen=True)
class BudgetDefaults:
    """Default constraints applied to all queries unless overridden."""
    max_cost: float = 100000
    max_time_ms: float = 1000
    deny_seq_scan_above: int = 10000
    require_index_scan: bool = False
    max_findings: int | None = None
    max_critical_findings: int | None = None


@dataclass(frozen=True)
class QueryBudget:
    """Performance budget for a specific query or pattern."""
    name: str
    sql_pattern: str | None = None
    plan_file: str | None = None
    max_cost: float | None = None
    max_time_ms: float | None = None
    deny_seq_scan_above: int | None = None
    require_index_scan: bool | None = None
    max_findings: int | None = None
    max_critical_findings: int | None = None
    alert: AlertLevel = AlertLevel.WARNING
    labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class BudgetLabel:
    """Reusable label that applies constraints to tagged queries."""
    name: str
    max_cost: float | None = None
    max_time_ms: float | None = None
    deny_seq_scan_above: int | None = None
    require_index_scan: bool | None = None
    max_findings: int | None = None
    max_critical_findings: int | None = None


@dataclass
class BudgetViolation:
    """A specific budget constraint that was violated."""
    budget_name: str
    constraint: str  # e.g., "max_cost", "max_time_ms"
    actual_value: float
    budget_value: float
    alert: AlertLevel
    message: str

    @property
    def is_blocking(self) -> bool:
        return self.alert == AlertLevel.BLOCKING

    def __str__(self) -> str:
        return (
            f"[{self.alert.value.upper()}] {self.budget_name}: {self.message} "
            f"(actual: {self.actual_value:.1f}, budget: {self.budget_value:.1f})"
        )


class BudgetEngine:
    """
    Evaluate query performance against declared budgets.

    Loads budgets from query-performance.yml and checks analysis results
    against them. Returns violations for CI gating.
    """

    def __init__(
        self,
        defaults: BudgetDefaults | None = None,
        budgets: dict[str, QueryBudget] | None = None,
        labels: dict[str, BudgetLabel] | None = None,
    ) -> None:
        self.defaults = defaults or BudgetDefaults()
        self.budgets = budgets or {}
        self.labels = labels or {}

    def check(
        self,
        *,
        query_name: str | None = None,
        sql: str | None = None,
        total_cost: float = 0,
        execution_time_ms: float = 0,
        findings_count: int = 0,
        critical_findings_count: int = 0,
        has_seq_scan: bool = False,
        seq_scan_rows: int = 0,
        has_index_scan: bool = False,
    ) -> list[BudgetViolation]:
        """
        Check a query against its budget.

        Matches by query_name first, then by sql_pattern, then falls back
        to defaults.
        """
        violations: list[BudgetViolation] = []

        # Find matching budget
        budget = self._match_budget(query_name, sql)
        if budget:
            violations.extend(
                self._check_budget(budget, total_cost, execution_time_ms,
                                   findings_count, critical_findings_count,
                                   has_seq_scan, seq_scan_rows, has_index_scan)
            )
        else:
            # Check against defaults
            violations.extend(
                self._check_defaults(total_cost, execution_time_ms,
                                     findings_count, critical_findings_count,
                                     has_seq_scan, seq_scan_rows)
            )

        return violations

    def check_all(
        self,
        results: list[dict[str, Any]],
    ) -> dict[str, list[BudgetViolation]]:
        """Check multiple query results against their budgets."""
        all_violations: dict[str, list[BudgetViolation]] = {}
        for r in results:
            name = r.get("query_name", "unknown")
            violations = self.check(
                query_name=name,
                sql=r.get("sql"),
                total_cost=r.get("total_cost", 0),
                execution_time_ms=r.get("execution_time_ms", 0),
                findings_count=r.get("findings_count", 0),
                critical_findings_count=r.get("critical_findings_count", 0),
                has_seq_scan=r.get("has_seq_scan", False),
                seq_scan_rows=r.get("seq_scan_rows", 0),
                has_index_scan=r.get("has_index_scan", False),
            )
            if violations:
                all_violations[name] = violations
        return all_violations

    def _match_budget(
        self, query_name: str | None, sql: str | None,
    ) -> QueryBudget | None:
        """Find the budget that matches this query."""
        # Exact name match
        if query_name and query_name in self.budgets:
            return self.budgets[query_name]

        # Pattern match
        if sql:
            for budget in self.budgets.values():
                if budget.sql_pattern:
                    try:
                        if re.search(budget.sql_pattern, sql, re.IGNORECASE):
                            return budget
                    except re.error:
                        logger.warning(
                            "Invalid regex in budget %s: %s",
                            budget.name, budget.sql_pattern,
                        )

        return None

    def _check_budget(
        self,
        budget: QueryBudget,
        total_cost: float,
        execution_time_ms: float,
        findings_count: int,
        critical_findings_count: int,
        has_seq_scan: bool,
        seq_scan_rows: int,
        has_index_scan: bool,
    ) -> list[BudgetViolation]:
        """Check a query against a specific budget."""
        violations: list[BudgetViolation] = []

        # Resolve label constraints
        effective_budget = self._resolve_labels(budget)

        if effective_budget.max_cost is not None and total_cost > effective_budget.max_cost:
            violations.append(BudgetViolation(
                budget_name=budget.name,
                constraint="max_cost",
                actual_value=total_cost,
                budget_value=effective_budget.max_cost,
                alert=budget.alert,
                message=f"Query cost {total_cost:,.0f} exceeds budget {effective_budget.max_cost:,.0f}",
            ))

        if effective_budget.max_time_ms is not None and execution_time_ms > effective_budget.max_time_ms:
            violations.append(BudgetViolation(
                budget_name=budget.name,
                constraint="max_time_ms",
                actual_value=execution_time_ms,
                budget_value=effective_budget.max_time_ms,
                alert=budget.alert,
                message=f"Execution time {execution_time_ms:.0f}ms exceeds budget {effective_budget.max_time_ms:.0f}ms",
            ))

        if effective_budget.max_findings is not None and findings_count > effective_budget.max_findings:
            violations.append(BudgetViolation(
                budget_name=budget.name,
                constraint="max_findings",
                actual_value=float(findings_count),
                budget_value=float(effective_budget.max_findings),
                alert=budget.alert,
                message=f"{findings_count} findings exceeds budget of {effective_budget.max_findings}",
            ))

        if effective_budget.max_critical_findings is not None and critical_findings_count > effective_budget.max_critical_findings:
            violations.append(BudgetViolation(
                budget_name=budget.name,
                constraint="max_critical_findings",
                actual_value=float(critical_findings_count),
                budget_value=float(effective_budget.max_critical_findings),
                alert=AlertLevel.BLOCKING,
                message=f"{critical_findings_count} critical findings exceeds budget of {effective_budget.max_critical_findings}",
            ))

        if effective_budget.require_index_scan and not has_index_scan:
            violations.append(BudgetViolation(
                budget_name=budget.name,
                constraint="require_index_scan",
                actual_value=0,
                budget_value=1,
                alert=budget.alert,
                message="Budget requires index scan but none found",
            ))

        if effective_budget.deny_seq_scan_above is not None and has_seq_scan and seq_scan_rows > effective_budget.deny_seq_scan_above:
            violations.append(BudgetViolation(
                budget_name=budget.name,
                constraint="deny_seq_scan_above",
                actual_value=float(seq_scan_rows),
                budget_value=float(effective_budget.deny_seq_scan_above),
                alert=budget.alert,
                message=f"Sequential scan on {seq_scan_rows:,} rows exceeds limit of {effective_budget.deny_seq_scan_above:,}",
            ))

        return violations

    def _check_defaults(
        self,
        total_cost: float,
        execution_time_ms: float,
        findings_count: int,
        critical_findings_count: int,
        has_seq_scan: bool,
        seq_scan_rows: int,
    ) -> list[BudgetViolation]:
        """Check against default constraints."""
        violations: list[BudgetViolation] = []
        d = self.defaults

        if total_cost > d.max_cost:
            violations.append(BudgetViolation(
                budget_name="(default)",
                constraint="max_cost",
                actual_value=total_cost,
                budget_value=d.max_cost,
                alert=AlertLevel.WARNING,
                message=f"Query cost {total_cost:,.0f} exceeds default budget {d.max_cost:,.0f}",
            ))

        if execution_time_ms > d.max_time_ms:
            violations.append(BudgetViolation(
                budget_name="(default)",
                constraint="max_time_ms",
                actual_value=execution_time_ms,
                budget_value=d.max_time_ms,
                alert=AlertLevel.WARNING,
                message=f"Execution time {execution_time_ms:.0f}ms exceeds default budget {d.max_time_ms:.0f}ms",
            ))

        if has_seq_scan and seq_scan_rows > d.deny_seq_scan_above:
            violations.append(BudgetViolation(
                budget_name="(default)",
                constraint="deny_seq_scan_above",
                actual_value=float(seq_scan_rows),
                budget_value=float(d.deny_seq_scan_above),
                alert=AlertLevel.WARNING,
                message=f"Sequential scan on {seq_scan_rows:,} rows exceeds default limit",
            ))

        return violations

    def _resolve_labels(self, budget: QueryBudget) -> QueryBudget:
        """Apply label constraints to a budget (budget values take precedence)."""
        if not budget.labels:
            return budget

        # Collect label constraints
        label_cost: float | None = None
        label_time: float | None = None
        label_seq: int | None = None
        label_idx: bool | None = None
        label_findings: int | None = None
        label_crit: int | None = None

        for label_name in budget.labels:
            label = self.labels.get(label_name)
            if not label:
                continue
            if label.max_cost is not None:
                label_cost = min(label_cost, label.max_cost) if label_cost is not None else label.max_cost
            if label.max_time_ms is not None:
                label_time = min(label_time, label.max_time_ms) if label_time is not None else label.max_time_ms
            if label.deny_seq_scan_above is not None:
                label_seq = min(label_seq, label.deny_seq_scan_above) if label_seq is not None else label.deny_seq_scan_above
            if label.require_index_scan:
                label_idx = True
            if label.max_findings is not None:
                label_findings = min(label_findings, label.max_findings) if label_findings is not None else label.max_findings
            if label.max_critical_findings is not None:
                label_crit = min(label_crit, label.max_critical_findings) if label_crit is not None else label.max_critical_findings

        # Budget values override label values
        return QueryBudget(
            name=budget.name,
            sql_pattern=budget.sql_pattern,
            plan_file=budget.plan_file,
            max_cost=budget.max_cost if budget.max_cost is not None else label_cost,
            max_time_ms=budget.max_time_ms if budget.max_time_ms is not None else label_time,
            deny_seq_scan_above=budget.deny_seq_scan_above if budget.deny_seq_scan_above is not None else label_seq,
            require_index_scan=budget.require_index_scan if budget.require_index_scan is not None else label_idx,
            max_findings=budget.max_findings if budget.max_findings is not None else label_findings,
            max_critical_findings=budget.max_critical_findings if budget.max_critical_findings is not None else label_crit,
            alert=budget.alert,
            labels=budget.labels,
        )


def load_budgets(path: str | Path = "query-performance.yml") -> BudgetEngine:
    """
    Load performance budgets from a YAML file.

    Args:
        path: Path to query-performance.yml

    Returns:
        BudgetEngine configured with the declared budgets

    Raises:
        FileNotFoundError: If budget file doesn't exist
        ValueError: If budget file has invalid format
    """
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(f"Budget file not found: {filepath}")

    try:
        import yaml
    except ImportError:
        raise ImportError(
            "PyYAML required for budget files: pip install pyyaml"
        )

    data = yaml.safe_load(filepath.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Invalid budget file format: expected YAML mapping")

    # Parse defaults
    defaults_data = data.get("defaults", {})
    defaults = BudgetDefaults(
        max_cost=defaults_data.get("max_cost", 100000),
        max_time_ms=defaults_data.get("max_time_ms", 1000),
        deny_seq_scan_above=defaults_data.get("deny_seq_scan_above", 10000),
        require_index_scan=defaults_data.get("require_index_scan", False),
        max_findings=defaults_data.get("max_findings"),
        max_critical_findings=defaults_data.get("max_critical_findings"),
    )

    # Parse labels
    labels: dict[str, BudgetLabel] = {}
    for name, label_data in data.get("labels", {}).items():
        labels[name] = BudgetLabel(
            name=name,
            max_cost=label_data.get("max_cost"),
            max_time_ms=label_data.get("max_time_ms"),
            deny_seq_scan_above=label_data.get("deny_seq_scan_above"),
            require_index_scan=label_data.get("require_index_scan"),
            max_findings=label_data.get("max_findings"),
            max_critical_findings=label_data.get("max_critical_findings"),
        )

    # Parse budgets
    budgets: dict[str, QueryBudget] = {}
    for name, budget_data in data.get("budgets", {}).items():
        budget_labels = budget_data.get("labels", [])
        if isinstance(budget_labels, str):
            budget_labels = [budget_labels]

        budgets[name] = QueryBudget(
            name=name,
            sql_pattern=budget_data.get("sql_pattern"),
            plan_file=budget_data.get("plan_file"),
            max_cost=budget_data.get("max_cost"),
            max_time_ms=budget_data.get("max_time_ms"),
            deny_seq_scan_above=budget_data.get("deny_seq_scan_above"),
            require_index_scan=budget_data.get("require_index_scan"),
            max_findings=budget_data.get("max_findings"),
            max_critical_findings=budget_data.get("max_critical_findings"),
            alert=AlertLevel(budget_data.get("alert", "warning")),
            labels=tuple(budget_labels),
        )

    return BudgetEngine(defaults=defaults, budgets=budgets, labels=labels)
