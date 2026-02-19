"""
GitHub PR comment generator for QuerySense CI integration.

Generates actionable, non-overwhelming Markdown comments for pull requests.
Designed for the "EXPLAIN plan linter" CI workflow:

- Status badge (pass/fail at a glance)
- Findings grouped by severity with collapsible details
- Baseline diffs showing plan structure changes
- Rule execution summary in a collapsible section

Design principles:
- Actionable: Every finding has a clear next step
- Not overwhelming: Collapsible details, severity grouping
- Copy-paste friendly: SQL suggestions in code blocks
- Machine-parseable: Consistent structure for automation

Usage:
    from querysense.output.pr_comment import render_pr_comment

    comment = render_pr_comment(results, baseline_diffs)
    # Post to GitHub PR via API
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult, Finding, RuleRunStatus, Severity
    from querysense.baseline import BaselineDiff, RegressionVerdict
    from querysense.policy import PolicyViolation


@dataclass
class CIResult:
    """Aggregated result from analyzing multiple plan files."""

    file_path: str
    result: "AnalysisResult"
    baseline_diff: "BaselineDiff | None" = None
    verdict: "RegressionVerdict | None" = None
    policy_violations: list["PolicyViolation"] | None = None


def _severity_icon(severity: Any) -> str:
    """Map severity to GitHub-friendly emoji."""
    severity_str = severity.value if hasattr(severity, "value") else str(severity)
    return {
        "critical": "🔴",
        "warning": "🟡",
        "info": "🔵",
    }.get(severity_str, "⚪")


def _severity_label(severity: Any) -> str:
    """Map severity to display label."""
    severity_str = severity.value if hasattr(severity, "value") else str(severity)
    return severity_str.upper()


def render_pr_comment(
    ci_results: list[CIResult],
    *,
    fail_on: str = "warning",
    show_passed: bool = True,
) -> str:
    """
    Generate a GitHub PR comment from CI analysis results.

    Args:
        ci_results: List of per-file analysis results with optional baseline diffs
        fail_on: Minimum severity to consider a failure ("critical", "warning", "info")
        show_passed: Whether to include passing checks in the output

    Returns:
        Markdown string suitable for posting as a GitHub PR comment
    """
    # Aggregate counts
    total_plans = len(ci_results)
    all_findings: list[tuple[str, "Finding"]] = []
    all_baseline_diffs: list[tuple[str, "BaselineDiff"]] = []

    critical_count = 0
    warning_count = 0
    info_count = 0
    regression_count = 0

    for cr in ci_results:
        for finding in cr.result.findings:
            all_findings.append((cr.file_path, finding))
            sev = finding.severity.value
            if sev == "critical":
                critical_count += 1
            elif sev == "warning":
                warning_count += 1
            elif sev == "info":
                info_count += 1

        if cr.baseline_diff and cr.baseline_diff.status == "CHANGED":
            all_baseline_diffs.append((cr.file_path, cr.baseline_diff))
            if cr.baseline_diff.is_regression:
                regression_count += 1

    # Determine pass/fail
    has_failures = _check_failure(
        critical_count, warning_count, info_count, regression_count, fail_on
    )

    lines: list[str] = []

    # Header
    if has_failures:
        lines.append("## 🔴 QuerySense found performance issues")
    elif regression_count > 0:
        lines.append("## 🟡 QuerySense detected plan changes")
    else:
        lines.append("## ✅ QuerySense: all checks passed")

    lines.append("")

    # Summary line
    summary_parts = [f"**{total_plans} plans analyzed**"]
    if critical_count:
        summary_parts.append(f"🔴 {critical_count} critical")
    if warning_count:
        summary_parts.append(f"🟡 {warning_count} warnings")
    if info_count:
        summary_parts.append(f"🔵 {info_count} info")
    if regression_count:
        summary_parts.append(f"📉 {regression_count} regressions")

    lines.append(" | ".join(summary_parts))
    lines.append("")

    # Regression verdicts (primary product surface, shown first)
    all_verdicts: list[tuple[str, Any]] = []
    for cr in ci_results:
        if cr.verdict and cr.verdict.severity.value != "none":
            all_verdicts.append((cr.file_path, cr.verdict))

    if all_verdicts:
        lines.append("### 📉 Plan Regression Verdicts")
        lines.append("")

        for file_path, verdict in all_verdicts:
            sev = verdict.severity.value.upper()
            lines.append(
                f"**`{file_path}`** — {sev} "
                f"(danger: {verdict.danger_score}/100)"
            )
            lines.append("")

            # Rationale
            if verdict.rationale:
                lines.append(f"> {verdict.rationale}")
                lines.append("")

            # Structural changes
            if verdict.structural_changes:
                lines.append("<details>")
                lines.append("<summary>Structural changes</summary>")
                lines.append("")
                lines.append("```diff")
                for change in verdict.structural_changes:
                    if change.startswith("+"):
                        lines.append(change)
                    elif change.startswith("-"):
                        lines.append(change)
                    else:
                        lines.append(f"! {change}")
                lines.append("```")
                lines.append("")
                lines.append("</details>")
                lines.append("")

            # Plausible causes
            if verdict.plausible_causes:
                lines.append("<details>")
                lines.append("<summary>Plausible causes</summary>")
                lines.append("")
                for cause in verdict.plausible_causes:
                    lines.append(f"- {cause}")
                lines.append("")
                lines.append("</details>")
                lines.append("")

            # Recommended actions (always visible, actionable)
            if verdict.recommended_actions:
                lines.append("**Recommended actions:**")
                for action in verdict.recommended_actions:
                    lines.append(f"- [ ] {action}")
                lines.append("")

            # Plan control hints
            if verdict.plan_control_hints:
                lines.append("<details>")
                lines.append("<summary>Plan control options</summary>")
                lines.append("")
                for hint in verdict.plan_control_hints:
                    lines.append(f"- {hint}")
                lines.append("")
                lines.append("</details>")
                lines.append("")

    # Fall back to basic baseline diffs if no verdicts available
    elif all_baseline_diffs:
        lines.append("### 📉 Plan Regressions")
        lines.append("")

        for file_path, diff in all_baseline_diffs:
            lines.append(f"**`{file_path}`** — plan structure changed")
            lines.append("")

            if diff.node_type_changes:
                lines.append("<details>")
                lines.append("<summary>Node type changes</summary>")
                lines.append("")
                lines.append("```diff")
                for change in diff.node_type_changes:
                    relation = f" on {change['relation']}" if change.get("relation") else ""
                    lines.append(f"- {change['path']}: {change['before']}{relation}")
                    lines.append(f"+ {change['path']}: {change['after']}{relation}")
                lines.append("```")
                lines.append("")
                lines.append("</details>")
                lines.append("")

            if diff.nodes_added:
                lines.append("<details>")
                lines.append("<summary>Nodes added</summary>")
                lines.append("")
                lines.append("```diff")
                for node in diff.nodes_added:
                    lines.append(f"+ {node}")
                lines.append("```")
                lines.append("")
                lines.append("</details>")
                lines.append("")

            if diff.nodes_removed:
                lines.append("<details>")
                lines.append("<summary>Nodes removed</summary>")
                lines.append("")
                lines.append("```diff")
                for node in diff.nodes_removed:
                    lines.append(f"- {node}")
                lines.append("```")
                lines.append("")
                lines.append("</details>")
                lines.append("")

            if diff.has_cost_regression:
                lines.append(
                    f"> Cost: {diff.cost_before:.0f} → {diff.cost_after:.0f} "
                    f"({diff.cost_change_percent:+.1f}%)"
                )
                lines.append("")

    # Policy violations section
    all_policy_violations: list[tuple[str, Any]] = []
    for cr in ci_results:
        if cr.policy_violations:
            for pv in cr.policy_violations:
                all_policy_violations.append((cr.file_path, pv))

    if all_policy_violations:
        lines.append("### 🛡️ Policy Violations")
        lines.append("")

        for file_path, pv in all_policy_violations:
            sev_icon = {"critical": "🔴", "warning": "🟡"}.get(pv.severity, "⚪")
            lines.append(f"{sev_icon} **{pv.rule}** — `{file_path}`")
            lines.append(f"> {pv.message}")
            lines.append("")

    # Findings grouped by severity
    for severity_value in ("critical", "warning", "info"):
        severity_findings = [
            (fp, f) for fp, f in all_findings if f.severity.value == severity_value
        ]

        if not severity_findings:
            continue

        icon = _severity_icon_str(severity_value)
        label = severity_value.upper()
        lines.append(f"### {icon} {label} ({len(severity_findings)})")
        lines.append("")

        for file_path, finding in severity_findings:
            lines.append(f"**{finding.title}**")
            lines.append(f"  `{file_path}` | Rule: `{finding.rule_id}`")
            lines.append("")
            lines.append(f"> {finding.description[:200]}")
            lines.append("")

            if finding.suggestion:
                lines.append("<details>")
                lines.append("<summary>Suggestion</summary>")
                lines.append("")
                lines.append("```sql")
                lines.append(finding.suggestion)
                lines.append("```")
                lines.append("")
                lines.append("</details>")
                lines.append("")

            if finding.verification_steps:
                lines.append("<details>")
                lines.append("<summary>Verification steps</summary>")
                lines.append("")
                for step in finding.verification_steps:
                    lines.append(f"- [ ] {step}")
                lines.append("")
                lines.append("</details>")
                lines.append("")

    # Rule execution details (collapsible)
    all_rule_runs = []
    for cr in ci_results:
        for run in cr.result.rule_runs:
            all_rule_runs.append(run)

    if all_rule_runs:
        lines.append("<details>")
        lines.append("<summary>Rule execution details</summary>")
        lines.append("")
        lines.append("| Rule | Status | Runtime |")
        lines.append("|------|--------|---------|")

        # Deduplicate by rule_id (show worst status)
        rule_summary: dict[str, dict[str, Any]] = {}
        for run in all_rule_runs:
            existing = rule_summary.get(run.rule_id)
            if existing is None:
                rule_summary[run.rule_id] = {
                    "status": run.status,
                    "runtime_ms": run.runtime_ms,
                    "findings_count": run.findings_count,
                }
            else:
                existing["runtime_ms"] += run.runtime_ms
                existing["findings_count"] += run.findings_count

        for rule_id, info in sorted(rule_summary.items()):
            status = info["status"]
            status_str = status.value if hasattr(status, "value") else str(status)
            if status_str == "pass":
                status_icon = "✅"
            elif status_str == "skip":
                status_icon = "⏭️"
            else:
                status_icon = "❌"
            lines.append(
                f"| `{rule_id}` | {status_icon} {status_str} | {info['runtime_ms']:.1f}ms |"
            )

        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append(
        "*Powered by [QuerySense](https://github.com/JosephAhn23/Query-Sense) "
        "— EXPLAIN plan linter for CI/CD*"
    )

    return "\n".join(lines)


def _severity_icon_str(severity_value: str) -> str:
    """Map severity string to emoji."""
    return {
        "critical": "🔴",
        "warning": "🟡",
        "info": "🔵",
    }.get(severity_value, "⚪")


def _check_failure(
    critical: int,
    warning: int,
    info: int,
    regressions: int,
    fail_on: str,
) -> bool:
    """Determine if CI should fail based on fail_on threshold."""
    if fail_on == "critical":
        return critical > 0 or regressions > 0
    elif fail_on == "warning":
        return critical > 0 or warning > 0 or regressions > 0
    elif fail_on == "info":
        return critical > 0 or warning > 0 or info > 0 or regressions > 0
    else:
        # "none" or unknown - only fail on regressions
        return regressions > 0


def render_ci_summary_json(
    ci_results: list[CIResult],
    *,
    fail_on: str = "warning",
) -> dict[str, Any]:
    """
    Generate machine-readable CI summary.

    Returns a dict suitable for JSON output and GitHub Action outputs.
    """
    total_plans = len(ci_results)
    critical_count = 0
    warning_count = 0
    info_count = 0
    regression_count = 0
    all_findings: list[dict[str, Any]] = []

    for cr in ci_results:
        for finding in cr.result.findings:
            sev = finding.severity.value
            if sev == "critical":
                critical_count += 1
            elif sev == "warning":
                warning_count += 1
            elif sev == "info":
                info_count += 1

            all_findings.append({
                "file": cr.file_path,
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "title": finding.title,
                "description": finding.description,
                "suggestion": finding.suggestion,
                "table": finding.context.relation_name,
                "rows": finding.context.actual_rows,
            })

        if cr.baseline_diff and cr.baseline_diff.is_regression:
            regression_count += 1

    has_failures = _check_failure(
        critical_count, warning_count, info_count, regression_count, fail_on
    )

    # Collect verdicts and policy violations
    verdicts: list[dict[str, Any]] = []
    policy_violations: list[dict[str, Any]] = []
    for cr in ci_results:
        if cr.verdict:
            verdicts.append(cr.verdict.to_dict())
        if cr.policy_violations:
            for pv in cr.policy_violations:
                policy_violations.append({
                    "file": cr.file_path,
                    "rule": pv.rule,
                    "severity": pv.severity,
                    "message": pv.message,
                    "table": pv.table,
                    "query_id": pv.query_id,
                })

    return {
        "version": "1.1",
        "summary": {
            "total_plans": total_plans,
            "critical_count": critical_count,
            "warning_count": warning_count,
            "info_count": info_count,
            "regression_count": regression_count,
            "has_failures": has_failures,
            "policy_violation_count": len(policy_violations),
        },
        "findings": all_findings,
        "verdicts": verdicts,
        "policy_violations": policy_violations,
    }
