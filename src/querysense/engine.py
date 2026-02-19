"""
AnalysisService - first-class orchestration layer for QuerySense.

This is the single entry point for running analyses with baseline comparison.
CLI, CI, GitHub Action, and API server should all use this service rather
than orchestrating analysis + baselines themselves.

Design principle: Ports & Adapters
- This is the "application layer" that coordinates domain operations
- It depends only on core abstractions (Analyzer, BaselineStore)
- Delivery mechanisms (CLI, API, Action) are thin adapters around this

Usage:
    from querysense.engine import AnalysisService

    service = AnalysisService()

    # Simple analysis
    result = service.analyze(explain)

    # Analysis with SQL enhancement
    result = service.analyze(explain, sql=query)

    # Analysis with baseline comparison
    report = service.analyze_with_baseline(
        explain, query_id="users_by_email",
        baseline_path=".querysense/baselines.json",
    )

    # CI pipeline: analyze multiple plans
    ci_report = service.analyze_batch(
        plans=[("query1", explain1), ("query2", explain2)],
        baseline_path=".querysense/baselines.json",
        fail_on="warning",
    )
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from querysense.analyzer.analyzer import Analyzer
from querysense.analyzer.models import AnalysisResult, Severity

if TYPE_CHECKING:
    from querysense.baseline import BaselineDiff, BaselineStore, RegressionVerdict
    from querysense.config import Config
    from querysense.db.probe import DBProbe, TopQueryEntry
    from querysense.parser.models import ExplainOutput
    from querysense.policy import PolicyViolation

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AnalysisReport:
    """
    Complete analysis report with optional baseline comparison.

    Combines analysis results with baseline diff information.
    This is the primary output type for the orchestration layer.
    """

    result: AnalysisResult
    query_id: str | None = None
    baseline_diff: "BaselineDiff | None" = None
    file_path: str | None = None
    verdict: "RegressionVerdict | None" = None
    policy_violations: tuple["PolicyViolation", ...] = ()

    @property
    def has_regression(self) -> bool:
        """Whether a plan regression was detected."""
        if self.baseline_diff is None:
            return False
        return self.baseline_diff.is_regression

    @property
    def has_critical(self) -> bool:
        """Whether critical findings were detected."""
        return self.result.has_critical

    @property
    def has_warnings(self) -> bool:
        """Whether warnings were detected."""
        return self.result.has_warnings

    @property
    def has_policy_violations(self) -> bool:
        """Whether any policy violations were detected."""
        return len(self.policy_violations) > 0


@dataclass(frozen=True)
class BatchReport:
    """
    Report for a batch of analyses (CI/CD use case).

    Aggregates multiple AnalysisReports and determines pass/fail.
    """

    reports: tuple[AnalysisReport, ...] = ()
    fail_on: str = "warning"  # "critical", "warning", "info", "none"

    @property
    def total_plans(self) -> int:
        return len(self.reports)

    @property
    def critical_count(self) -> int:
        return sum(
            len(r.result.findings_by_severity(Severity.CRITICAL))
            for r in self.reports
        )

    @property
    def warning_count(self) -> int:
        return sum(
            len(r.result.findings_by_severity(Severity.WARNING))
            for r in self.reports
        )

    @property
    def info_count(self) -> int:
        return sum(
            len(r.result.findings_by_severity(Severity.INFO))
            for r in self.reports
        )

    @property
    def regression_count(self) -> int:
        return sum(1 for r in self.reports if r.has_regression)

    @property
    def has_failures(self) -> bool:
        """Check if any report exceeds the fail_on threshold."""
        if self.fail_on == "none":
            return False
        if self.fail_on == "critical":
            return self.critical_count > 0 or self.regression_count > 0
        if self.fail_on == "warning":
            return (
                self.critical_count > 0
                or self.warning_count > 0
                or self.regression_count > 0
            )
        if self.fail_on == "info":
            return (
                self.critical_count > 0
                or self.warning_count > 0
                or self.info_count > 0
                or self.regression_count > 0
            )
        return False

    def to_summary_dict(self) -> dict[str, Any]:
        """Export summary as dictionary for JSON output."""
        return {
            "total_plans": self.total_plans,
            "critical_count": self.critical_count,
            "warning_count": self.warning_count,
            "info_count": self.info_count,
            "regression_count": self.regression_count,
            "fail_on": self.fail_on,
            "has_failures": self.has_failures,
        }


@dataclass(frozen=True)
class UpgradeReport:
    """
    Report from a post-upgrade plan validation run.

    Compares query plans before and after a PostgreSQL version upgrade
    to identify regressions introduced by planner changes. This is an
    episodic but high-stakes workflow that concentrates risk.
    """

    before_version: str
    after_version: str
    reports: tuple[AnalysisReport, ...] = ()
    verdicts: tuple["RegressionVerdict", ...] = ()
    timestamp: str = ""

    @property
    def total_queries(self) -> int:
        return len(self.reports)

    @property
    def regression_count(self) -> int:
        return sum(1 for r in self.reports if r.has_regression)

    @property
    def critical_regression_count(self) -> int:
        from querysense.baseline import RegressionSeverity
        return sum(
            1 for v in self.verdicts
            if v.severity in (RegressionSeverity.CRITICAL, RegressionSeverity.HIGH)
        )

    @property
    def safe_to_upgrade(self) -> bool:
        """Conservative safety check: no high or critical regressions."""
        return self.critical_regression_count == 0

    def to_summary_dict(self) -> dict[str, Any]:
        """Export summary as dictionary for JSON output."""
        return {
            "before_version": self.before_version,
            "after_version": self.after_version,
            "total_queries": self.total_queries,
            "regression_count": self.regression_count,
            "critical_regression_count": self.critical_regression_count,
            "safe_to_upgrade": self.safe_to_upgrade,
            "timestamp": self.timestamp,
            "verdicts": [v.to_dict() for v in self.verdicts],
        }


class AnalysisService:
    """
    First-class orchestration service for QuerySense.

    Coordinates analysis, SQL enhancement, baseline comparison,
    policy enforcement, and reporting into a single coherent workflow.

    All entry points (CLI, CI, API) should use this service.
    """

    def __init__(
        self,
        config: "Config | None" = None,
        db_probe: "DBProbe | None" = None,
        prefer_pglast: bool = True,
        cache_enabled: bool = False,
    ) -> None:
        """
        Initialize the service.

        Args:
            config: Configuration instance (if None, uses get_config())
            db_probe: Database probe for Level 3 analysis
            prefer_pglast: Prefer pglast SQL parser
            cache_enabled: Enable analysis result caching
        """
        self._analyzer = Analyzer(
            config=config,
            db_probe=db_probe,
            prefer_pglast=prefer_pglast,
            cache_enabled=cache_enabled,
        )
        self._config = config

    @property
    def analyzer(self) -> Analyzer:
        """Access the underlying Analyzer (for backward compatibility)."""
        return self._analyzer

    def analyze(
        self,
        explain: "ExplainOutput",
        sql: str | None = None,
    ) -> AnalysisResult:
        """
        Analyze a single EXPLAIN output.

        Args:
            explain: Parsed EXPLAIN output
            sql: Optional SQL query for enhanced analysis

        Returns:
            AnalysisResult with findings and metadata
        """
        return self._analyzer.analyze(explain, sql)

    def analyze_with_baseline(
        self,
        explain: "ExplainOutput",
        query_id: str,
        baseline_path: str | Path = ".querysense/baselines.json",
        sql: str | None = None,
        policy_path: str | Path | None = None,
    ) -> AnalysisReport:
        """
        Analyze with baseline comparison, verdict generation, and policy evaluation.

        Args:
            explain: Parsed EXPLAIN output
            query_id: Identifier for baseline lookup
            baseline_path: Path to baseline file
            sql: Optional SQL query for enhanced analysis
            policy_path: Optional path to policy file

        Returns:
            AnalysisReport with result, baseline diff, verdict, and policy violations
        """
        from querysense.baseline import BaselineStore

        result = self._analyzer.analyze(explain, sql)

        # Load and compare baseline
        store = BaselineStore(baseline_path)
        baseline_diff = None
        verdict = None
        if store.path.exists():
            baseline_diff = store.compare(query_id, explain)
            if baseline_diff and baseline_diff.status == "CHANGED":
                verdict = baseline_diff.verdict()

        # Evaluate policy
        policy_violations: tuple[PolicyViolation, ...] = ()
        if policy_path:
            from querysense.policy import load_policy
            policy = load_policy(policy_path)
            diffs = [baseline_diff] if baseline_diff else []
            violations = policy.evaluate(result, diffs)
            policy_violations = tuple(violations)

        return AnalysisReport(
            result=result,
            query_id=query_id,
            baseline_diff=baseline_diff,
            verdict=verdict,
            policy_violations=policy_violations,
        )

    def analyze_batch(
        self,
        plans: list[tuple[str, "ExplainOutput", str | None]],
        baseline_path: str | Path = ".querysense/baselines.json",
        fail_on: str = "warning",
        policy_path: str | Path | None = None,
    ) -> BatchReport:
        """
        Analyze a batch of EXPLAIN plans (CI/CD use case).

        Produces analysis results, baseline comparisons, regression verdicts,
        and policy evaluations for each plan. This is the primary CI workflow.

        Args:
            plans: List of (query_id, explain, file_path) tuples
            baseline_path: Path to baseline file
            fail_on: Severity threshold for failure ("critical", "warning", "info", "none")
            policy_path: Optional path to policy file for enforcement

        Returns:
            BatchReport with aggregated results
        """
        from querysense.baseline import BaselineStore

        store = BaselineStore(baseline_path)
        has_baselines = store.path.exists()

        # Load policy if available
        policy = None
        if policy_path:
            from querysense.policy import load_policy
            policy = load_policy(policy_path)

        reports: list[AnalysisReport] = []
        all_diffs: list[Any] = []
        failed_plans: list[tuple[str, str]] = []  # (query_id, error_message)

        for query_id, explain, file_path in plans:
            try:
                result = self._analyzer.analyze(explain)

                baseline_diff = None
                verdict = None
                if has_baselines:
                    baseline_diff = store.compare(query_id, explain)
                    if baseline_diff and baseline_diff.status == "CHANGED":
                        verdict = baseline_diff.verdict()
                    if baseline_diff:
                        all_diffs.append(baseline_diff)

                # Per-plan policy evaluation
                plan_violations: tuple[PolicyViolation, ...] = ()
                if policy:
                    diffs = [baseline_diff] if baseline_diff else []
                    violations = policy.evaluate(result, diffs)
                    plan_violations = tuple(violations)

                reports.append(AnalysisReport(
                    result=result,
                    query_id=query_id,
                    baseline_diff=baseline_diff,
                    file_path=file_path,
                    verdict=verdict,
                    policy_violations=plan_violations,
                ))
            except Exception as e:
                error_msg = f"{type(e).__name__}: {e}"
                failed_plans.append((query_id, error_msg))
                logger.warning("Failed to analyze %s: %s", query_id, error_msg)

        if failed_plans:
            logger.warning(
                "Batch analysis: %d/%d plans failed: %s",
                len(failed_plans),
                len(plans),
                ", ".join(qid for qid, _ in failed_plans),
            )

        return BatchReport(
            reports=tuple(reports),
            fail_on=fail_on,
        )

    def update_baselines(
        self,
        plans: list[tuple[str, "ExplainOutput"]],
        baseline_path: str | Path = ".querysense/baselines.json",
    ) -> dict[str, str]:
        """
        Update baselines from current EXPLAIN outputs.

        Args:
            plans: List of (query_id, explain) tuples
            baseline_path: Path to baseline file

        Returns:
            Dict mapping query_id to structure hash
        """
        from querysense.baseline import BaselineStore

        store = BaselineStore(baseline_path)
        results: dict[str, str] = {}

        for query_id, explain in plans:
            structure_hash = store.record(query_id, explain)
            results[query_id] = structure_hash

        if results:
            store.save()

        return results

    def validate_upgrade(
        self,
        plans: list[tuple[str, "ExplainOutput", str | None]],
        baseline_path: str | Path = ".querysense/baselines.json",
        before_version: str = "",
        after_version: str = "",
    ) -> UpgradeReport:
        """
        Validate query plans after a PostgreSQL version upgrade.

        Compares all plans against pre-upgrade baselines and generates
        structured verdicts highlighting regressions introduced by
        planner changes in the new version.

        This is an episodic but high-stakes workflow: organizations
        schedule upgrades, fear regressions, and need evidence that
        top queries won't regress.

        Args:
            plans: List of (query_id, explain, file_path) tuples (post-upgrade plans)
            baseline_path: Path to pre-upgrade baselines
            before_version: PostgreSQL version before upgrade
            after_version: PostgreSQL version after upgrade

        Returns:
            UpgradeReport with per-query verdicts and safety assessment
        """
        from datetime import datetime, timezone

        from querysense.baseline import BaselineStore

        store = BaselineStore(baseline_path)

        reports: list[AnalysisReport] = []
        verdicts: list[RegressionVerdict] = []

        for query_id, explain, file_path in plans:
            try:
                result = self._analyzer.analyze(explain)
                baseline_diff = store.compare(query_id, explain)

                verdict = None
                if baseline_diff and baseline_diff.status == "CHANGED":
                    verdict = baseline_diff.verdict()
                    verdicts.append(verdict)

                reports.append(AnalysisReport(
                    result=result,
                    query_id=query_id,
                    baseline_diff=baseline_diff,
                    file_path=file_path,
                    verdict=verdict,
                ))
            except Exception as e:
                logger.warning("Failed to analyze %s during upgrade check: %s", query_id, e)

        return UpgradeReport(
            before_version=before_version,
            after_version=after_version,
            reports=tuple(reports),
            verdicts=tuple(verdicts),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def tune(
        self,
        explain: "ExplainOutput",
        sql: str | None = None,
    ) -> "WorkbookResult":
        """
        Run the automated Query Tuning Workbook (Ch. 16).

        Implements the full "Ultimate Optimization Algorithm" from
        Dombrovskaya et al. (2024): Baseline → Diagnose → Hypothesize →
        Plan → Predict → Recommend.

        This is what pganalyze does manually via Workbooks, but automated.

        Args:
            explain: Parsed EXPLAIN output
            sql: Optional SQL query (enables rewrite variants)

        Returns:
            WorkbookResult with hypotheses, variants, and recommendations
        """
        from querysense.workbook import TuningWorkbook

        wb = TuningWorkbook()
        # Convert ExplainOutput back to raw JSON for the workbook
        plan_json = explain.to_dict() if hasattr(explain, "to_dict") else {}
        return wb.run(plan_json, sql=sql or "")

    async def tune_with_db(
        self,
        explain: "ExplainOutput",
        sql: str,
        dsn: str,
    ) -> "WorkbookResult":
        """
        Run the Tuning Workbook with live database testing.

        Executes all 8 phases including EXPLAIN ANALYZE of variant
        queries against a live database, within a ROLLBACK transaction.

        Args:
            explain: Parsed EXPLAIN output
            sql: The SQL query to optimize
            dsn: PostgreSQL connection string

        Returns:
            WorkbookResult with measured (not just predicted) improvements
        """
        from querysense.workbook import TuningWorkbook

        wb = TuningWorkbook()
        plan_json = explain.to_dict() if hasattr(explain, "to_dict") else {}
        return await wb.run_with_db(plan_json, sql=sql, dsn=dsn)

    def explain_planner(
        self,
        explain: "ExplainOutput",
        settings: dict[str, Any] | None = None,
    ) -> list["PlannerInsight"]:
        """
        Explain why PostgreSQL chose each plan decision.

        Codifies planner behavior from Peng & Peng Ch. 5 and
        Dombrovskaya Ch. 4-5 to provide transparent reasoning
        for every node in the execution plan.

        Args:
            explain: Parsed EXPLAIN output
            settings: Optional dict of current PostgreSQL settings

        Returns:
            List of PlannerInsight objects explaining each node
        """
        from querysense.planner_insight import explain_plan_choices

        plan_json = explain.to_dict() if hasattr(explain, "to_dict") else {}
        return explain_plan_choices(plan_json, settings=settings)

    def advise_config(
        self,
        explain: "ExplainOutput",
        findings: list[Any] | None = None,
        current_settings: dict[str, str] | None = None,
    ) -> "ConfigAdvisorResult":
        """
        Get query-specific configuration recommendations.

        Analyzes the plan and findings to recommend the exact
        PostgreSQL settings that would improve this specific query.

        Args:
            explain: Parsed EXPLAIN output
            findings: Optional findings from analysis
            current_settings: Optional current PostgreSQL settings

        Returns:
            ConfigAdvisorResult with specific setting recommendations
        """
        from querysense.config_advisor import QueryConfigAdvisor

        advisor = QueryConfigAdvisor()
        plan_json = explain.to_dict() if hasattr(explain, "to_dict") else {}
        return advisor.analyze(plan_json, findings=findings, current_settings=current_settings)
