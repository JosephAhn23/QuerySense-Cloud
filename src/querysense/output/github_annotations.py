"""
GitHub Actions annotation formatter for QuerySense CI integration.

Emits GitHub Actions workflow commands that create inline annotations
on pull requests. These appear directly on the changed files in the PR diff.

Supported annotation types:
- ::error file={name},line={line}::{message}
- ::warning file={name},line={line}::{message}
- ::notice file={name},line={line}::{message}

Also supports:
- GITHUB_STEP_SUMMARY: Rich Markdown summary in the Actions tab
- GITHUB_OUTPUT: Machine-readable outputs for downstream steps

Reference: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions

Usage:
    from querysense.output.github_annotations import render_annotations, render_step_summary

    # Emit annotations to stdout (GitHub Actions picks them up)
    print(render_annotations(ci_results))

    # Write step summary
    write_step_summary(ci_results, fail_on="warning")

    # Set output variables
    write_github_outputs(ci_results, fail_on="warning")
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from querysense.output.pr_comment import CIResult


def _escape_annotation(text: str) -> str:
    """Escape special characters for GitHub Actions annotations.

    GitHub Actions uses specific escape sequences:
    - %25 for %
    - %0A for newline
    - %0D for carriage return
    """
    return (
        text.replace("%", "%25")
        .replace("\n", "%0A")
        .replace("\r", "%0D")
    )


def _severity_to_annotation_level(severity_value: str) -> str:
    """Map QuerySense severity to GitHub annotation level."""
    return {
        "critical": "error",
        "warning": "warning",
        "info": "notice",
    }.get(severity_value, "notice")


def render_annotations(ci_results: list[CIResult]) -> str:
    """
    Generate GitHub Actions annotation commands from CI results.

    Each finding becomes an inline annotation on the PR. Critical findings
    become errors, warnings become warnings, info becomes notices.

    Args:
        ci_results: List of per-file CI analysis results

    Returns:
        String of ::error/::warning/::notice commands, one per line
    """
    lines: list[str] = []

    for cr in ci_results:
        file_path = cr.file_path or "unknown"

        for finding in cr.result.findings:
            level = _severity_to_annotation_level(finding.severity.value)
            title = _escape_annotation(finding.title)
            description = _escape_annotation(finding.description[:200])
            rule_id = finding.rule_id

            # Build the annotation message
            message = f"[{rule_id}] {title}"
            if finding.suggestion:
                suggestion_preview = finding.suggestion.split("\n")[0][:100]
                message += f" -- Fix: {suggestion_preview}"

            message = _escape_annotation(message)

            # GitHub annotation format
            lines.append(
                f"::{level} file={file_path},title=QuerySense: {rule_id}::{message}"
            )

        # Baseline regressions get their own annotations
        if cr.baseline_diff and cr.baseline_diff.is_regression:
            message = _escape_annotation(
                f"Plan regression detected: query plan structure changed. "
                f"Cost: {cr.baseline_diff.cost_before:.0f} -> {cr.baseline_diff.cost_after:.0f}"
            )
            lines.append(
                f"::error file={file_path},title=QuerySense: Plan Regression::{message}"
            )

        # Verdict annotations (highest signal)
        if cr.verdict and cr.verdict.severity.value != "none":
            sev = cr.verdict.severity.value
            level = "error" if sev in ("critical", "high") else "warning"
            message = _escape_annotation(
                f"Regression verdict: {sev.upper()} "
                f"(danger score: {cr.verdict.danger_score}/100). "
                f"{cr.verdict.rationale or ''}"
            )
            lines.append(
                f"::{level} file={file_path},title=QuerySense: Regression Verdict::{message}"
            )

        # Policy violations
        if cr.policy_violations:
            for pv in cr.policy_violations:
                level = "error" if pv.severity == "critical" else "warning"
                message = _escape_annotation(f"[Policy: {pv.rule}] {pv.message}")
                lines.append(
                    f"::{level} file={file_path},title=QuerySense: Policy Violation::{message}"
                )

    return "\n".join(lines)


def render_step_summary(
    ci_results: list[CIResult],
    *,
    fail_on: str = "warning",
) -> str:
    """
    Generate Markdown content for GITHUB_STEP_SUMMARY.

    This appears as a rich summary in the GitHub Actions run page.
    Designed to be scannable: status badge, counts, then expandable details.

    Args:
        ci_results: List of per-file CI analysis results
        fail_on: Severity threshold for pass/fail

    Returns:
        Markdown string for the step summary
    """
    from querysense.output.pr_comment import render_ci_summary_json

    summary = render_ci_summary_json(ci_results, fail_on=fail_on)
    s = summary["summary"]

    lines: list[str] = []

    # Header with pass/fail badge
    if s["has_failures"]:
        lines.append("## :x: QuerySense — Performance issues detected")
    else:
        lines.append("## :white_check_mark: QuerySense — All checks passed")

    lines.append("")

    # Counts table
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Plans analyzed | {s['total_plans']} |")
    lines.append(f"| :red_circle: Critical | {s['critical_count']} |")
    lines.append(f"| :yellow_circle: Warnings | {s['warning_count']} |")
    lines.append(f"| :blue_circle: Info | {s['info_count']} |")
    lines.append(f"| :chart_with_downwards_trend: Regressions | {s['regression_count']} |")
    if s.get("policy_violation_count"):
        lines.append(f"| :shield: Policy violations | {s['policy_violation_count']} |")
    lines.append(f"| Fail threshold | `{fail_on}` |")
    lines.append("")

    # Findings detail (collapsible per severity)
    findings = summary.get("findings", [])

    for sev_value, sev_label, sev_icon in [
        ("critical", "Critical", ":red_circle:"),
        ("warning", "Warnings", ":yellow_circle:"),
        ("info", "Info", ":blue_circle:"),
    ]:
        sev_findings = [f for f in findings if f["severity"] == sev_value]
        if not sev_findings:
            continue

        lines.append(f"<details>")
        lines.append(f"<summary>{sev_icon} {sev_label} ({len(sev_findings)})</summary>")
        lines.append("")
        lines.append("| File | Rule | Issue | Table |")
        lines.append("|------|------|-------|-------|")

        for f in sev_findings:
            file_name = f.get("file", "")
            rule = f.get("rule_id", "")
            title = f.get("title", "")[:60]
            table = f.get("table", "") or "-"
            lines.append(f"| `{file_name}` | `{rule}` | {title} | `{table}` |")

        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Top suggestions (always visible for critical/warning)
    actionable = [f for f in findings if f.get("suggestion") and f["severity"] in ("critical", "warning")]
    if actionable:
        lines.append("### Suggested fixes")
        lines.append("")
        for f in actionable[:5]:  # Top 5
            lines.append(f"**{f['title']}** (`{f['file']}`)")
            lines.append("")
            lines.append("```sql")
            lines.append(f["suggestion"])
            lines.append("```")
            lines.append("")

    # Footer
    lines.append("---")
    lines.append(
        "*Powered by [QuerySense](https://github.com/JosephAhn23/Query-Sense) "
        "— lint your SQL performance in CI*"
    )

    return "\n".join(lines)


def write_step_summary(
    ci_results: list[CIResult],
    *,
    fail_on: str = "warning",
) -> bool:
    """
    Write the step summary to GITHUB_STEP_SUMMARY if available.

    Args:
        ci_results: List of per-file CI analysis results
        fail_on: Severity threshold for pass/fail

    Returns:
        True if summary was written, False if not in GitHub Actions
    """
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return False

    content = render_step_summary(ci_results, fail_on=fail_on)

    with open(summary_path, "a", encoding="utf-8") as f:
        f.write(content)
        f.write("\n")

    return True


def write_github_outputs(
    ci_results: list[CIResult],
    *,
    fail_on: str = "warning",
) -> bool:
    """
    Set GitHub Actions output variables for downstream steps.

    Outputs:
        - result: "pass" or "fail"
        - critical_count: Number of critical findings
        - warning_count: Number of warning findings
        - info_count: Number of info findings
        - regression_count: Number of plan regressions
        - total_plans: Number of plans analyzed
        - findings_json: JSON array of findings (for programmatic use)

    Usage in workflow:
        steps:
          - id: querysense
            run: querysense ci gate "plans/*.json"
          - if: steps.querysense.outputs.result == 'fail'
            run: echo "QuerySense found issues"

    Returns:
        True if outputs were written, False if not in GitHub Actions
    """
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return False

    from querysense.output.pr_comment import render_ci_summary_json
    import json

    summary = render_ci_summary_json(ci_results, fail_on=fail_on)
    s = summary["summary"]

    outputs = {
        "result": "fail" if s["has_failures"] else "pass",
        "critical_count": str(s["critical_count"]),
        "warning_count": str(s["warning_count"]),
        "info_count": str(s["info_count"]),
        "regression_count": str(s["regression_count"]),
        "total_plans": str(s["total_plans"]),
    }

    with open(output_path, "a", encoding="utf-8") as f:
        for key, value in outputs.items():
            f.write(f"{key}={value}\n")

        # Multi-line output for findings JSON
        findings_json = json.dumps(summary["findings"], separators=(",", ":"))
        f.write(f"findings_json<<EOF\n{findings_json}\nEOF\n")

    return True
