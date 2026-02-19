"""
Policy-as-code engine for QuerySense.

Defines declarative, version-controlled policies that enforce query performance
standards in CI/CD pipelines. Policies are the mechanism that converts QuerySense
from "advice" into "enforceable infrastructure."

Policy files live at `.querysense/policy.yml` and are committed to the repository.
This means policies are reviewed in PRs, versioned, and auditable.

Usage:
    from querysense.policy import Policy, load_policy

    # Load from file
    policy = load_policy(".querysense/policy.yml")

    # Evaluate against analysis results
    violations = policy.evaluate(analysis_result, baseline_diff)

    # Check if CI should fail
    if violations:
        for v in violations:
            print(f"POLICY VIOLATION: {v.message}")

Policy file format (.querysense/policy.yml):
    version: "1.0"

    # Table classifications for differentiated enforcement
    tables:
      users:
        classification: pii
        max_seq_scan_rows: 1000
      transactions:
        classification: financial
        max_seq_scan_rows: 0      # Never allow seq scans
      audit_log:
        classification: compliance
        max_cost: 10000

    # Global deny rules
    deny:
      - rule: no_seq_scan
        tables: [transactions, payments]
        reason: "Financial tables must use index scans"

      - rule: max_cost
        threshold: 100000
        reason: "Queries exceeding cost 100K require DBA review"

      - rule: no_regression
        severity: high
        reason: "High-severity regressions block deployment"

    # Baseline enforcement
    baselines:
      require_locked: [get_user_by_id, process_payment]
      max_unlocked_regressions: 2
      fail_on_any_locked_violation: true
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Policy schema version
POLICY_SCHEMA_VERSION = "1.0"


class TableClassification(str, Enum):
    """Table data sensitivity classification."""

    PUBLIC = "public"
    INTERNAL = "internal"
    PII = "pii"
    FINANCIAL = "financial"
    COMPLIANCE = "compliance"


@dataclass(frozen=True)
class TablePolicy:
    """Policy for a specific table."""

    name: str
    classification: TableClassification = TableClassification.INTERNAL
    max_seq_scan_rows: int | None = None  # None = use global default
    max_cost: float | None = None
    deny_seq_scan: bool = False
    skip_rules: tuple[str, ...] = ()


@dataclass(frozen=True)
class DenyRule:
    """A declarative deny rule that blocks CI if matched."""

    rule: str  # "no_seq_scan", "max_cost", "no_regression", "require_index"
    tables: tuple[str, ...] = ()  # Empty = all tables
    threshold: float | None = None
    severity: str | None = None  # For no_regression: "low", "medium", "high", "critical"
    reason: str = ""


@dataclass(frozen=True)
class BaselinePolicy:
    """Policy for baseline enforcement."""

    require_locked: tuple[str, ...] = ()
    max_unlocked_regressions: int = -1  # -1 = no limit
    fail_on_any_locked_violation: bool = True


@dataclass(frozen=True)
class PolicyViolation:
    """A policy violation detected during evaluation."""

    rule: str
    message: str
    severity: str  # "critical", "warning"
    table: str | None = None
    query_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


class Policy:
    """
    Declarative policy engine for CI/CD query gating.

    Evaluates analysis results and baseline diffs against a set of
    declarative rules to produce pass/fail decisions.
    """

    def __init__(
        self,
        *,
        tables: dict[str, TablePolicy] | None = None,
        deny_rules: list[DenyRule] | None = None,
        baseline_policy: BaselinePolicy | None = None,
        version: str = POLICY_SCHEMA_VERSION,
    ) -> None:
        self.tables = tables or {}
        self.deny_rules = deny_rules or []
        self.baseline_policy = baseline_policy or BaselinePolicy()
        self.version = version

    def evaluate(
        self,
        analysis_result: Any,
        baseline_diffs: list[Any] | None = None,
    ) -> list[PolicyViolation]:
        """
        Evaluate analysis results against all policy rules.

        Args:
            analysis_result: AnalysisResult from the analyzer
            baseline_diffs: Optional list of BaselineDiff objects

        Returns:
            List of PolicyViolation objects (empty = pass)
        """
        violations: list[PolicyViolation] = []

        # Evaluate deny rules against findings
        violations.extend(self._evaluate_deny_rules(analysis_result))

        # Evaluate table policies against findings
        violations.extend(self._evaluate_table_policies(analysis_result))

        # Evaluate baseline policies
        if baseline_diffs:
            violations.extend(self._evaluate_baseline_policy(baseline_diffs))

        return violations

    def _evaluate_deny_rules(self, result: Any) -> list[PolicyViolation]:
        """Evaluate deny rules against analysis findings."""
        violations: list[PolicyViolation] = []

        for deny in self.deny_rules:
            if deny.rule == "no_seq_scan":
                violations.extend(self._check_no_seq_scan(deny, result))
            elif deny.rule == "max_cost":
                violations.extend(self._check_max_cost(deny, result))
            elif deny.rule == "no_regression":
                # Handled in baseline policy evaluation
                pass
            elif deny.rule == "require_index":
                violations.extend(self._check_require_index(deny, result))

        return violations

    def _check_no_seq_scan(
        self, deny: DenyRule, result: Any
    ) -> list[PolicyViolation]:
        """Check for sequential scans on denied tables."""
        violations: list[PolicyViolation] = []

        for finding in result.findings:
            if finding.rule_id != "SEQ_SCAN_LARGE_TABLE":
                continue

            table = finding.context.relation_name
            if not table:
                continue

            # Check if this table is in the deny list
            if deny.tables and table not in deny.tables:
                continue

            violations.append(PolicyViolation(
                rule="no_seq_scan",
                message=(
                    f"Sequential scan on '{table}' violates policy"
                    f"{': ' + deny.reason if deny.reason else ''}"
                ),
                severity="critical",
                table=table,
                details={
                    "rule_id": finding.rule_id,
                    "rows": finding.context.actual_rows,
                    "reason": deny.reason,
                },
            ))

        return violations

    def _check_max_cost(
        self, deny: DenyRule, result: Any
    ) -> list[PolicyViolation]:
        """Check if any finding exceeds max cost threshold."""
        violations: list[PolicyViolation] = []

        if deny.threshold is None:
            return violations

        for finding in result.findings:
            cost = finding.context.total_cost
            if cost > deny.threshold:
                violations.append(PolicyViolation(
                    rule="max_cost",
                    message=(
                        f"Query cost {cost:.0f} exceeds policy limit "
                        f"{deny.threshold:.0f}"
                        f"{': ' + deny.reason if deny.reason else ''}"
                    ),
                    severity="critical",
                    table=finding.context.relation_name,
                    details={
                        "cost": cost,
                        "threshold": deny.threshold,
                        "reason": deny.reason,
                    },
                ))
                break  # One violation per cost rule is enough

        return violations

    def _check_require_index(
        self, deny: DenyRule, result: Any
    ) -> list[PolicyViolation]:
        """Check that specified tables are always accessed via index."""
        violations: list[PolicyViolation] = []

        for finding in result.findings:
            if finding.rule_id not in (
                "SEQ_SCAN_LARGE_TABLE",
                "FOREIGN_KEY_INDEX",
            ):
                continue

            table = finding.context.relation_name
            if not table:
                continue

            if deny.tables and table not in deny.tables:
                continue

            violations.append(PolicyViolation(
                rule="require_index",
                message=(
                    f"Table '{table}' requires index access per policy"
                    f"{': ' + deny.reason if deny.reason else ''}"
                ),
                severity="critical",
                table=table,
                details={
                    "rule_id": finding.rule_id,
                    "reason": deny.reason,
                },
            ))

        return violations

    def _evaluate_table_policies(self, result: Any) -> list[PolicyViolation]:
        """Evaluate per-table policies against findings."""
        violations: list[PolicyViolation] = []

        for finding in result.findings:
            table = finding.context.relation_name
            if not table or table not in self.tables:
                continue

            table_policy = self.tables[table]

            # Check deny_seq_scan
            if (
                table_policy.deny_seq_scan
                and finding.rule_id == "SEQ_SCAN_LARGE_TABLE"
            ):
                violations.append(PolicyViolation(
                    rule="table_deny_seq_scan",
                    message=(
                        f"Sequential scan on '{table}' "
                        f"(classification: {table_policy.classification.value}) "
                        f"violates table policy"
                    ),
                    severity="critical",
                    table=table,
                    details={
                        "classification": table_policy.classification.value,
                    },
                ))

            # Check max_seq_scan_rows
            if (
                table_policy.max_seq_scan_rows is not None
                and finding.rule_id == "SEQ_SCAN_LARGE_TABLE"
                and finding.context.actual_rows is not None
                and finding.context.actual_rows > table_policy.max_seq_scan_rows
            ):
                violations.append(PolicyViolation(
                    rule="table_max_seq_scan_rows",
                    message=(
                        f"Seq scan on '{table}' returned {finding.context.actual_rows} rows "
                        f"(policy limit: {table_policy.max_seq_scan_rows})"
                    ),
                    severity="critical",
                    table=table,
                    details={
                        "actual_rows": finding.context.actual_rows,
                        "max_rows": table_policy.max_seq_scan_rows,
                    },
                ))

            # Check max_cost
            if (
                table_policy.max_cost is not None
                and finding.context.total_cost > table_policy.max_cost
            ):
                violations.append(PolicyViolation(
                    rule="table_max_cost",
                    message=(
                        f"Query on '{table}' has cost {finding.context.total_cost:.0f} "
                        f"(policy limit: {table_policy.max_cost:.0f})"
                    ),
                    severity="warning",
                    table=table,
                    details={
                        "cost": finding.context.total_cost,
                        "max_cost": table_policy.max_cost,
                    },
                ))

        return violations

    def _evaluate_baseline_policy(
        self, baseline_diffs: list[Any]
    ) -> list[PolicyViolation]:
        """Evaluate baseline policy against diffs."""
        from querysense.baseline import RegressionSeverity

        violations: list[PolicyViolation] = []

        # Check locked plan violations
        for diff in baseline_diffs:
            if (
                self.baseline_policy.fail_on_any_locked_violation
                and getattr(diff, "is_locked", False)
                and diff.status == "CHANGED"
            ):
                violations.append(PolicyViolation(
                    rule="locked_plan_violation",
                    message=(
                        f"Locked plan '{diff.query_id}' was modified"
                        f"{': ' + diff.lock_reason if diff.lock_reason else ''}"
                    ),
                    severity="critical",
                    query_id=diff.query_id,
                    details={
                        "lock_reason": getattr(diff, "lock_reason", ""),
                        "danger_score": getattr(diff, "danger_score", 0),
                    },
                ))

        # Check regression severity deny rules
        for deny in self.deny_rules:
            if deny.rule != "no_regression":
                continue

            min_severity = deny.severity or "high"
            severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            min_level = severity_order.get(min_severity, 2)

            for diff in baseline_diffs:
                if diff.status != "CHANGED":
                    continue

                diff_severity = getattr(diff, "regression_severity", None)
                if diff_severity is None:
                    continue

                diff_level = severity_order.get(diff_severity.value, 0)
                if diff_level >= min_level:
                    violations.append(PolicyViolation(
                        rule="no_regression",
                        message=(
                            f"Plan regression on '{diff.query_id}' "
                            f"(severity: {diff_severity.value})"
                            f"{': ' + deny.reason if deny.reason else ''}"
                        ),
                        severity="critical" if diff_level >= 2 else "warning",
                        query_id=diff.query_id,
                        details={
                            "regression_severity": diff_severity.value,
                            "danger_score": getattr(diff, "danger_score", 0),
                            "reason": deny.reason,
                        },
                    ))

        # Check max unlocked regressions
        if self.baseline_policy.max_unlocked_regressions >= 0:
            unlocked_regressions = sum(
                1
                for diff in baseline_diffs
                if diff.status == "CHANGED"
                and not getattr(diff, "is_locked", False)
                and getattr(diff, "is_regression", False)
            )
            if unlocked_regressions > self.baseline_policy.max_unlocked_regressions:
                violations.append(PolicyViolation(
                    rule="max_unlocked_regressions",
                    message=(
                        f"{unlocked_regressions} unlocked regressions exceed "
                        f"policy limit of {self.baseline_policy.max_unlocked_regressions}"
                    ),
                    severity="critical",
                    details={
                        "count": unlocked_regressions,
                        "limit": self.baseline_policy.max_unlocked_regressions,
                    },
                ))

        # Check require_locked enforcement
        for required_qid in self.baseline_policy.require_locked:
            found = False
            for diff in baseline_diffs:
                if diff.query_id == required_qid:
                    found = True
                    if not getattr(diff, "is_locked", False):
                        violations.append(PolicyViolation(
                            rule="require_locked",
                            message=(
                                f"Query '{required_qid}' is required to be locked "
                                f"by policy but is not locked"
                            ),
                            severity="warning",
                            query_id=required_qid,
                        ))
                    break
            # If the query wasn't in the diffs at all, that's not a violation
            # (it might not have been analyzed in this batch)

        return violations


def load_policy(path: str | Path = ".querysense/policy.yml") -> Policy:
    """
    Load a policy from a YAML or JSON file.

    Args:
        path: Path to the policy file

    Returns:
        Policy instance (returns empty/permissive policy if file not found)
    """
    policy_path = Path(path)

    if not policy_path.exists():
        logger.debug("No policy file at %s, using permissive defaults", path)
        return Policy()

    try:
        raw = policy_path.read_text(encoding="utf-8")

        if policy_path.suffix in (".yaml", ".yml"):
            try:
                import yaml

                data = yaml.safe_load(raw)
            except ImportError:
                logger.warning(
                    "PyYAML not installed, cannot load YAML policy. "
                    "Install with: pip install pyyaml"
                )
                return Policy()
        else:
            import json

            data = json.loads(raw)

        if not isinstance(data, dict):
            logger.warning("Policy file is not a dictionary: %s", path)
            return Policy()

        return _parse_policy(data)

    except Exception as e:
        logger.error("Failed to load policy from %s: %s", path, e)
        return Policy()


def _parse_policy(data: dict[str, Any]) -> Policy:
    """Parse a policy from a dictionary."""
    # Parse tables
    tables: dict[str, TablePolicy] = {}
    for table_name, table_data in data.get("tables", {}).items():
        classification_str = table_data.get("classification", "internal")
        try:
            classification = TableClassification(classification_str)
        except ValueError:
            classification = TableClassification.INTERNAL

        tables[table_name] = TablePolicy(
            name=table_name,
            classification=classification,
            max_seq_scan_rows=table_data.get("max_seq_scan_rows"),
            max_cost=table_data.get("max_cost"),
            deny_seq_scan=table_data.get("deny_seq_scan", False),
            skip_rules=tuple(table_data.get("skip_rules", [])),
        )

    # Parse deny rules
    deny_rules: list[DenyRule] = []
    for deny_data in data.get("deny", []):
        deny_rules.append(DenyRule(
            rule=deny_data.get("rule", ""),
            tables=tuple(deny_data.get("tables", [])),
            threshold=deny_data.get("threshold"),
            severity=deny_data.get("severity"),
            reason=deny_data.get("reason", ""),
        ))

    # Parse baseline policy
    baseline_data = data.get("baselines", {})
    baseline_policy = BaselinePolicy(
        require_locked=tuple(baseline_data.get("require_locked", [])),
        max_unlocked_regressions=baseline_data.get("max_unlocked_regressions", -1),
        fail_on_any_locked_violation=baseline_data.get(
            "fail_on_any_locked_violation", True
        ),
    )

    return Policy(
        tables=tables,
        deny_rules=deny_rules,
        baseline_policy=baseline_policy,
        version=data.get("version", POLICY_SCHEMA_VERSION),
    )


def generate_default_policy() -> str:
    """
    Generate a default policy YAML file with documentation.

    Returns:
        YAML string suitable for writing to .querysense/policy.yml
    """
    return """\
# QuerySense Policy Configuration
# ================================
# This file defines enforceable query performance policies for CI/CD.
# Commit this to your repository - policies travel with the code.
#
# Documentation: https://github.com/JosephAhn23/Query-Sense
version: "1.0"

# Table classifications
# =====================
# Classify tables by data sensitivity to apply differentiated enforcement.
# Classifications: public, internal, pii, financial, compliance
tables:
  # Example: Deny seq scans on financial tables
  # transactions:
  #   classification: financial
  #   deny_seq_scan: true
  #   max_cost: 50000
  #
  # Example: Strict limits on PII tables
  # users:
  #   classification: pii
  #   max_seq_scan_rows: 1000

# Deny rules
# ==========
# Declarative rules that block CI when violated.
deny:
  # Block deployments on high-severity regressions
  - rule: no_regression
    severity: high
    reason: "High-severity plan regressions require DBA review"

  # Example: Block seq scans on specific tables
  # - rule: no_seq_scan
  #   tables: [transactions, payments]
  #   reason: "Financial tables must use index scans"

  # Example: Block expensive queries
  # - rule: max_cost
  #   threshold: 100000
  #   reason: "Queries exceeding cost 100K require DBA review"

# Baseline enforcement
# ====================
# Controls how plan regressions are handled.
baselines:
  # Queries that MUST be locked (CI warns if unlocked)
  require_locked: []

  # Maximum number of unlocked regressions before CI fails (-1 = no limit)
  max_unlocked_regressions: -1

  # Always fail if a locked plan changes
  fail_on_any_locked_violation: true
"""
