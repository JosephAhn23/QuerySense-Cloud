"""
Performance budgets as code.

Define performance budgets in YAML and enforce them in CI.
The "Harness killer" — same safety guarantees, zero enterprise complexity.

Budget file (.querysense.yml):
    performance_budgets:
      - query: "SELECT * FROM orders WHERE status = 'pending'"
        max_execution_time: 50ms
        max_rows_scanned: 10000
      - table: "users"
        max_seq_scan_rows: 5000

    migration_policies:
      - block_drop_index_without_review: true
      - require_rollback_for_all: true
      - auto_approve_if_impact_low: true

CLI:
    querysense budget check --config .querysense.yml plan.json
    querysense budget init  # generates starter .querysense.yml

.. deprecated:: 2.0.0
    For new projects, prefer ``querysense.budget.BudgetEngine`` with
    ``query-performance.yml``.  This module will be maintained for
    backwards compatibility but new features land in ``budget.py``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ── Models ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class QueryBudget:
    """Performance budget for a specific query or table."""
    name: str = ""                         # Optional label
    query: str = ""                        # SQL pattern to match (regex-ok)
    table: str = ""                        # Table name to match
    max_execution_time_ms: float | None = None
    max_cost: float | None = None
    max_rows_scanned: int | None = None
    max_seq_scan_rows: int | None = None
    max_findings: int | None = None        # Max number of findings allowed
    max_severity: str | None = None        # Highest allowed severity (info/warning)
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class MigrationPolicy:
    """Policy for migration safety."""
    block_drop_index_without_review: bool = False
    block_drop_table_without_review: bool = True
    require_rollback_for_all: bool = False
    auto_approve_if_impact_low: bool = False
    block_column_type_change: bool = False
    require_concurrent_index: bool = True
    max_risk_level: str = "high"  # low/medium/high/critical


@dataclass
class BudgetConfig:
    """Full performance budget configuration."""
    performance_budgets: list[QueryBudget] = field(default_factory=list)
    migration_policy: MigrationPolicy = field(default_factory=MigrationPolicy)
    global_max_findings: int | None = None
    global_max_severity: str | None = None  # "info" or "warning" (block critical)


@dataclass(frozen=True)
class BudgetViolation:
    """A single budget violation."""
    budget_name: str
    metric: str          # what was violated (e.g., "execution_time")
    budget_value: str     # what the budget says
    actual_value: str     # what we measured
    severity: str        # critical / warning / info


@dataclass
class BudgetCheckResult:
    """Result of checking a plan against budgets."""
    passed: bool
    violations: list[BudgetViolation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    budgets_checked: int = 0
    budgets_passed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "budgets_checked": self.budgets_checked,
            "budgets_passed": self.budgets_passed,
            "violations": [
                {
                    "budget": v.budget_name,
                    "metric": v.metric,
                    "budget_value": v.budget_value,
                    "actual_value": v.actual_value,
                    "severity": v.severity,
                }
                for v in self.violations
            ],
            "warnings": self.warnings,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ── Parsing ──────────────────────────────────────────────────────────

def _parse_duration(value: str) -> float:
    """Parse a duration string like '50ms' or '2s' to milliseconds."""
    value = value.strip().lower()
    if value.endswith("ms"):
        return float(value[:-2])
    if value.endswith("s"):
        return float(value[:-1]) * 1000
    if value.endswith("m"):
        return float(value[:-1]) * 60_000
    return float(value)  # assume ms


def load_budget_config(path: str | Path) -> BudgetConfig:
    """
    Load budget configuration from a YAML or JSON file.

    Args:
        path: Path to .querysense.yml or .querysense.json

    Returns:
        Parsed BudgetConfig
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")

    if path.suffix in (".yml", ".yaml"):
        if not HAS_YAML:
            raise ImportError("PyYAML required for YAML budget files: pip install pyyaml")
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)

    if not isinstance(data, dict):
        raise ValueError(f"Budget config must be a YAML/JSON object, got {type(data).__name__}")

    # Parse performance budgets
    budgets: list[QueryBudget] = []
    for item in data.get("performance_budgets", []):
        max_time = item.get("max_execution_time")
        if isinstance(max_time, str):
            max_time = _parse_duration(max_time)

        budgets.append(QueryBudget(
            name=item.get("name", item.get("query", item.get("table", "unnamed"))[:40]),
            query=item.get("query", ""),
            table=item.get("table", ""),
            max_execution_time_ms=max_time,
            max_cost=item.get("max_cost"),
            max_rows_scanned=item.get("max_rows_scanned"),
            max_seq_scan_rows=item.get("max_seq_scan_rows"),
            max_findings=item.get("max_findings"),
            max_severity=item.get("max_severity"),
            tags=tuple(item.get("tags", [])),
        ))

    # Parse migration policy
    mp_data = data.get("migration_policies", data.get("migration_policy", {}))
    if isinstance(mp_data, list):
        # Handle list format by merging all dicts
        merged: dict[str, Any] = {}
        for item in mp_data:
            if isinstance(item, dict):
                merged.update(item)
        mp_data = merged

    migration_policy = MigrationPolicy(
        block_drop_index_without_review=mp_data.get("block_drop_index_without_review", False),
        block_drop_table_without_review=mp_data.get("block_drop_table_without_review", True),
        require_rollback_for_all=mp_data.get("require_rollback_for_all", False),
        auto_approve_if_impact_low=mp_data.get("auto_approve_if_impact_low", False),
        block_column_type_change=mp_data.get("block_column_type_change", False),
        require_concurrent_index=mp_data.get("require_concurrent_index", True),
        max_risk_level=mp_data.get("max_risk_level", "high"),
    )

    return BudgetConfig(
        performance_budgets=budgets,
        migration_policy=migration_policy,
        global_max_findings=data.get("global_max_findings"),
        global_max_severity=data.get("global_max_severity"),
    )


# ── Checking ─────────────────────────────────────────────────────────

def _collect_scanned_rows(plan: dict[str, Any]) -> int:
    """Recursively sum all actual rows from plan nodes."""
    total = plan.get("Actual Rows", 0) * max(plan.get("Actual Loops", 1), 1)
    for child in plan.get("Plans", []):
        total += _collect_scanned_rows(child)
    return total


def _collect_seq_scan_rows(plan: dict[str, Any], table: str = "") -> int:
    """Sum actual rows from Seq Scan nodes, optionally filtered by table."""
    total = 0
    if plan.get("Node Type") == "Seq Scan":
        relation = plan.get("Relation Name", "")
        if not table or relation == table:
            total += plan.get("Actual Rows", 0) * max(plan.get("Actual Loops", 1), 1)
    for child in plan.get("Plans", []):
        total += _collect_seq_scan_rows(child, table)
    return total


def _get_relation_names(plan: dict[str, Any]) -> set[str]:
    """Collect all relation names from a plan."""
    names: set[str] = set()
    rel = plan.get("Relation Name")
    if rel:
        names.add(rel)
    for child in plan.get("Plans", []):
        names |= _get_relation_names(child)
    return names


def check_budget(
    config: BudgetConfig,
    plan: dict[str, Any],
    findings: list[Any] | None = None,
    sql: str | None = None,
) -> BudgetCheckResult:
    """
    Check an EXPLAIN plan against performance budgets.

    Args:
        config: Budget configuration
        plan: Raw EXPLAIN plan dict (the Plan node)
        findings: Optional list of Finding objects from analysis
        sql: Optional SQL text of the query

    Returns:
        BudgetCheckResult
    """
    violations: list[BudgetViolation] = []
    warnings: list[str] = []
    budgets_checked = 0
    budgets_passed = 0

    execution_time = plan.get("Actual Total Time")
    total_cost = plan.get("Total Cost", 0)
    total_scanned = _collect_scanned_rows(plan)
    relations = _get_relation_names(plan)

    for budget in config.performance_budgets:
        # Check if budget applies to this query
        applies = False

        if budget.query and sql:
            # Match query pattern
            try:
                if re.search(budget.query, sql, re.IGNORECASE):
                    applies = True
            except re.error:
                if budget.query.lower() in sql.lower():
                    applies = True

        if budget.table and budget.table in relations:
            applies = True

        if not budget.query and not budget.table:
            # Global budget applies to all queries
            applies = True

        if not applies:
            continue

        budgets_checked += 1
        budget_passed = True

        budget_label = budget.name or budget.query[:30] or budget.table or "global"

        # Check execution time
        if budget.max_execution_time_ms is not None and execution_time is not None:
            if execution_time > budget.max_execution_time_ms:
                pct_over = ((execution_time / budget.max_execution_time_ms) - 1) * 100
                violations.append(BudgetViolation(
                    budget_name=budget_label,
                    metric="execution_time",
                    budget_value=f"{budget.max_execution_time_ms:.0f}ms",
                    actual_value=f"{execution_time:.1f}ms ({pct_over:.0f}% over budget)",
                    severity="critical" if pct_over > 200 else "warning",
                ))
                budget_passed = False

        # Check cost
        if budget.max_cost is not None:
            if total_cost > budget.max_cost:
                violations.append(BudgetViolation(
                    budget_name=budget_label,
                    metric="plan_cost",
                    budget_value=f"{budget.max_cost:.0f}",
                    actual_value=f"{total_cost:.0f}",
                    severity="warning",
                ))
                budget_passed = False

        # Check rows scanned
        if budget.max_rows_scanned is not None:
            if total_scanned > budget.max_rows_scanned:
                violations.append(BudgetViolation(
                    budget_name=budget_label,
                    metric="rows_scanned",
                    budget_value=f"{budget.max_rows_scanned:,}",
                    actual_value=f"{total_scanned:,}",
                    severity="warning",
                ))
                budget_passed = False

        # Check seq scan rows
        if budget.max_seq_scan_rows is not None:
            seq_rows = _collect_seq_scan_rows(plan, budget.table)
            if seq_rows > budget.max_seq_scan_rows:
                violations.append(BudgetViolation(
                    budget_name=budget_label,
                    metric="seq_scan_rows",
                    budget_value=f"{budget.max_seq_scan_rows:,}",
                    actual_value=f"{seq_rows:,}",
                    severity="critical",
                ))
                budget_passed = False

        # Check findings count
        if budget.max_findings is not None and findings is not None:
            if len(findings) > budget.max_findings:
                violations.append(BudgetViolation(
                    budget_name=budget_label,
                    metric="findings_count",
                    budget_value=str(budget.max_findings),
                    actual_value=str(len(findings)),
                    severity="warning",
                ))
                budget_passed = False

        # Check max severity
        if budget.max_severity is not None and findings is not None:
            severity_order = {"info": 0, "warning": 1, "critical": 2}
            max_allowed = severity_order.get(budget.max_severity, 1)
            for f in findings:
                sev_val = f.severity.value if hasattr(f.severity, "value") else f.severity
                if severity_order.get(sev_val, 0) > max_allowed:
                    violations.append(BudgetViolation(
                        budget_name=budget_label,
                        metric="severity",
                        budget_value=f"max {budget.max_severity}",
                        actual_value=f"found {sev_val}: {getattr(f, 'title', str(f))}",
                        severity="critical",
                    ))
                    budget_passed = False
                    break

        if budget_passed:
            budgets_passed += 1

    # Check global budgets
    if config.global_max_findings is not None and findings is not None:
        budgets_checked += 1
        if len(findings) > config.global_max_findings:
            violations.append(BudgetViolation(
                budget_name="global",
                metric="total_findings",
                budget_value=str(config.global_max_findings),
                actual_value=str(len(findings)),
                severity="warning",
            ))
        else:
            budgets_passed += 1

    if config.global_max_severity is not None and findings is not None:
        budgets_checked += 1
        severity_order = {"info": 0, "warning": 1, "critical": 2}
        max_allowed = severity_order.get(config.global_max_severity, 1)
        breach = False
        for f in findings:
            sev_val = f.severity.value if hasattr(f.severity, "value") else f.severity
            if severity_order.get(sev_val, 0) > max_allowed:
                violations.append(BudgetViolation(
                    budget_name="global",
                    metric="max_severity",
                    budget_value=f"max {config.global_max_severity}",
                    actual_value=f"found {sev_val}",
                    severity="critical",
                ))
                breach = True
                break
        if not breach:
            budgets_passed += 1

    return BudgetCheckResult(
        passed=len(violations) == 0,
        violations=violations,
        warnings=warnings,
        budgets_checked=budgets_checked,
        budgets_passed=budgets_passed,
    )


# ── Generator ────────────────────────────────────────────────────────

def generate_starter_config() -> str:
    """Generate a starter .querysense.yml file."""
    return """\
# QuerySense Performance Budget Configuration
# Docs: https://querysense.dev/budgets
#
# Put this file in your repo root as .querysense.yml
# Then run: querysense budget check --config .querysense.yml plan.json

performance_budgets:
  # Budget for specific queries (regex matching)
  - name: "Order lookup"
    query: "SELECT.*FROM orders WHERE"
    max_execution_time: 50ms
    max_rows_scanned: 10000

  # Budget for a specific table
  - name: "Users table policy"
    table: "users"
    max_seq_scan_rows: 5000

  # Global budget for all queries
  - name: "Default budget"
    max_execution_time: 500ms
    max_severity: "warning"  # Block any critical findings
    max_findings: 5

migration_policies:
  block_drop_index_without_review: true
  block_drop_table_without_review: true
  require_rollback_for_all: true
  require_concurrent_index: true
  auto_approve_if_impact_low: true
  max_risk_level: "high"

# Global limits
global_max_severity: "warning"  # Block PRs with critical findings
"""


def format_check_result(result: BudgetCheckResult) -> str:
    """Format budget check result for terminal display."""
    lines: list[str] = []

    if result.passed:
        lines.append("")
        lines.append("  BUDGET CHECK PASSED")
        lines.append("  " + "=" * 40)
        lines.append(f"  {result.budgets_passed}/{result.budgets_checked} budgets passed")
        lines.append("")
        return "\n".join(lines)

    lines.append("")
    lines.append("  BUDGET CHECK FAILED")
    lines.append("  " + "=" * 40)
    lines.append("")

    for v in result.violations:
        indicator = "[!!!]" if v.severity == "critical" else "[!!]"
        lines.append(f"  {indicator} Budget: {v.budget_name}")
        lines.append(f"       Metric: {v.metric}")
        lines.append(f"       Budget: {v.budget_value}")
        lines.append(f"       Actual: {v.actual_value}")
        lines.append("")

    lines.append(f"  {result.budgets_passed}/{result.budgets_checked} budgets passed")
    lines.append(f"  {len(result.violations)} violation(s)")
    lines.append("")

    return "\n".join(lines)
