"""
Output renderers for different formats.

Separates presentation logic from analysis logic.
Uses schema.py Pydantic models as the single source of truth
for JSON serialization — no manual dict construction.
"""

from __future__ import annotations

import json
from enum import Enum
from typing import TYPE_CHECKING, Any

from querysense.output.schema import (
    AnalysisResultSchema,
    FindingSchema,
    MetadataSchema,
    NodeContextSchema,
    ReproducibilitySchema,
    RuleRunSchema,
    SummarySchema,
)

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult, Finding
    from querysense.engine import UpgradeReport


class OutputFormat(str, Enum):
    """Supported output formats."""

    TEXT = "text"
    JSON = "json"
    MARKDOWN = "markdown"
    ASCII = "ascii"


def render(result: "AnalysisResult", format: OutputFormat = OutputFormat.TEXT) -> str:
    """
    Render analysis result in the specified format.

    Args:
        result: Analysis result to render
        format: Output format (text, json, markdown)

    Returns:
        Formatted string
    """
    if format == OutputFormat.TEXT:
        return render_text(result)
    elif format == OutputFormat.JSON:
        return render_json(result)
    elif format == OutputFormat.MARKDOWN:
        return render_markdown(result)
    elif format == OutputFormat.ASCII:
        from querysense.output.ascii import render_ascii
        return render_ascii(result)
    else:
        raise ValueError(f"Unknown output format: {format}")


# =============================================================================
# Schema-based serialization (single source of truth)
# =============================================================================


def _result_to_schema(result: "AnalysisResult") -> AnalysisResultSchema:
    """Convert AnalysisResult to the Pydantic schema model."""
    summary_dict = result.summary()

    return AnalysisResultSchema(
        version="1.0",
        evidence_level=result.evidence_level.value,
        sql_confidence=result.sql_confidence.value,
        degraded=result.degraded,
        degraded_reasons=list(result.degraded_reasons),
        summary=SummarySchema(
            total=summary_dict["total"],
            critical=summary_dict["critical"],
            warning=summary_dict["warning"],
            info=summary_dict["info"],
            rules_passed=summary_dict.get("rules_passed", 0),
            rules_skipped=summary_dict.get("rules_skipped", 0),
            rules_failed=summary_dict.get("rules_failed", 0),
            evidence_level=result.evidence_level.value,
            sql_confidence=result.sql_confidence.value,
            degraded=result.degraded,
            success_rate=summary_dict.get("success_rate", 1.0),
        ),
        findings=[_finding_to_schema(f) for f in result.findings],
        rule_runs=[_rule_run_to_schema(r) for r in result.rule_runs],
        metadata=MetadataSchema(
            node_count=result.metadata.node_count,
            execution_time_ms=result.metadata.execution_time_ms,
            analysis_duration_ms=result.metadata.analysis_duration_ms,
            cache_hit=result.metadata.cache_hit,
            rules_run=result.metadata.rules_run,
            rules_failed=result.metadata.rules_failed,
            rules_skipped=result.metadata.rules_skipped,
        ),
        reproducibility=(
            ReproducibilitySchema(
                analysis_id=result.reproducibility.analysis_id,
                plan_hash=result.reproducibility.plan_hash,
                sql_hash=result.reproducibility.sql_hash,
                config_hash=result.reproducibility.config_hash,
                rules_hash=result.reproducibility.rules_hash,
                querysense_version=result.reproducibility.querysense_version,
            )
            if result.reproducibility
            else None
        ),
    )


def _finding_to_schema(finding: "Finding") -> FindingSchema:
    """Convert Finding to the Pydantic schema model."""
    return FindingSchema(
        rule_id=finding.rule_id,
        severity=finding.severity.value,
        title=finding.title,
        description=finding.description,
        suggestion=finding.suggestion,
        impact_band=finding.impact_band.value,
        impact_score=finding.impact_score,
        assumptions=list(finding.assumptions),
        verification_steps=list(finding.verification_steps),
        metrics=finding.metrics,
        context=NodeContextSchema(
            path=str(finding.context.path),
            node_type=finding.context.node_type,
            relation_name=finding.context.relation_name,
            actual_rows=finding.context.actual_rows,
            plan_rows=finding.context.plan_rows,
            total_cost=finding.context.total_cost,
            filter=finding.context.filter,
        ),
    )


def _rule_run_to_schema(run: Any) -> RuleRunSchema:
    """Convert RuleRun to the Pydantic schema model."""
    return RuleRunSchema(
        rule_id=run.rule_id,
        version=run.version,
        status=run.status.value,
        runtime_ms=run.runtime_ms,
        findings_count=run.findings_count,
        error_summary=run.error_summary,
        skip_reason=run.skip_reason,
    )


def _result_to_dict(result: "AnalysisResult") -> dict[str, Any]:
    """Convert AnalysisResult to dictionary via the schema model."""
    schema = _result_to_schema(result)
    return schema.model_dump(mode="json")


# =============================================================================
# Text renderer (terminal)
# =============================================================================


def render_text(result: "AnalysisResult") -> str:
    """
    Render analysis result as rich terminal text.

    Uses ANSI colors and formatting for terminal display.
    """
    lines: list[str] = []

    # Header
    summary = result.summary()
    lines.append("=" * 60)
    lines.append("QuerySense Analysis Report")
    lines.append("=" * 60)
    lines.append("")

    # Evidence level
    lines.append(f"Evidence Level: {result.evidence_level.value}")
    if result.sql_confidence.value != "none":
        lines.append(f"SQL Confidence: {result.sql_confidence.value}")
    if result.degraded:
        lines.append(f"⚠ Degraded Mode: {', '.join(result.degraded_reasons)}")
    lines.append("")

    # Summary
    lines.append("Summary:")
    lines.append(f"  Total Findings: {summary['total']}")
    if summary["critical"]:
        lines.append(f"  🔴 Critical: {summary['critical']}")
    if summary["warning"]:
        lines.append(f"  🟡 Warnings: {summary['warning']}")
    if summary["info"]:
        lines.append(f"  🔵 Info: {summary['info']}")
    lines.append("")

    # Rule execution status
    if result.rule_runs:
        passed = len(
            result.rule_runs_by_status(result.rule_runs[0].status.__class__.PASS)
        )
        skipped = len(
            result.rule_runs_by_status(result.rule_runs[0].status.__class__.SKIP)
        )
        failed = len(
            result.rule_runs_by_status(result.rule_runs[0].status.__class__.FAIL)
        )
        lines.append(f"Rules: {passed} passed, {skipped} skipped, {failed} failed")
        lines.append("")

    # Findings
    if result.findings:
        lines.append("-" * 60)
        lines.append("FINDINGS")
        lines.append("-" * 60)

        for i, finding in enumerate(result.findings, 1):
            lines.append("")
            lines.append(
                f"[{i}] {_severity_icon(finding.severity)} {finding.title}"
            )
            lines.append(f"    Rule: {finding.rule_id}")
            lines.append(f"    Location: {finding.context.path}")
            impact_parts: list[str] = []
            if finding.impact_band.value != "UNKNOWN":
                impact_parts.append(finding.impact_band.value)
            if finding.impact_score > 0:
                impact_parts.append(f"Score: {finding.impact_score:.1f}/10")
            if impact_parts:
                lines.append(f"    Impact: {' | '.join(impact_parts)}")
            lines.append("")
            lines.append(f"    {finding.description}")

            if finding.suggestion:
                lines.append("")
                lines.append("    Suggestion:")
                for line in finding.suggestion.split("\n"):
                    lines.append(f"      {line}")

            if finding.assumptions:
                lines.append("")
                lines.append("    Assumptions:")
                for assumption in finding.assumptions:
                    lines.append(f"      • {assumption}")

            if finding.verification_steps:
                lines.append("")
                lines.append("    Verification:")
                for step in finding.verification_steps:
                    lines.append(f"      □ {step}")
    else:
        lines.append("✓ No issues found")

    lines.append("")
    lines.append("=" * 60)

    return "\n".join(lines)


# =============================================================================
# JSON renderer (uses schema models)
# =============================================================================


def render_json(result: "AnalysisResult", indent: int = 2) -> str:
    """
    Render analysis result as stable JSON schema.

    Uses Pydantic schema models for guaranteed consistency.
    Suitable for API responses, CI/CD integration, log aggregation.
    """
    return json.dumps(_result_to_dict(result), indent=indent, default=str)


# =============================================================================
# Markdown renderer
# =============================================================================


def render_markdown(result: "AnalysisResult") -> str:
    """
    Render analysis result as Markdown.

    Suitable for GitHub comments/issues, Slack messages, documentation.
    """
    lines: list[str] = []

    # Header
    summary = result.summary()
    lines.append("# QuerySense Analysis Report")
    lines.append("")

    # Status badge
    if summary["critical"]:
        lines.append("🔴 **Critical issues found**")
    elif summary["warning"]:
        lines.append("🟡 **Warnings found**")
    elif result.degraded:
        lines.append("⚠️ **Analysis ran in degraded mode**")
    else:
        lines.append("✅ **No issues found**")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Evidence Level | `{result.evidence_level.value}` |")
    lines.append(f"| SQL Confidence | `{result.sql_confidence.value}` |")
    lines.append(f"| Total Findings | {summary['total']} |")
    lines.append(f"| Critical | {summary['critical']} |")
    lines.append(f"| Warnings | {summary['warning']} |")
    lines.append(f"| Info | {summary['info']} |")
    lines.append("")

    # Findings
    if result.findings:
        lines.append("## Findings")
        lines.append("")

        for i, finding in enumerate(result.findings, 1):
            severity_emoji = _severity_icon(finding.severity)
            lines.append(f"### {i}. {severity_emoji} {finding.title}")
            lines.append("")
            lines.append(f"**Rule:** `{finding.rule_id}`  ")
            lines.append(f"**Location:** `{finding.context.path}`  ")
            impact_md: list[str] = []
            if finding.impact_band.value != "UNKNOWN":
                impact_md.append(finding.impact_band.value)
            if finding.impact_score > 0:
                impact_md.append(f"**{finding.impact_score:.1f}**/10")
            if impact_md:
                lines.append(f"**Impact:** {' — '.join(impact_md)}")
            lines.append("")
            lines.append(finding.description)
            lines.append("")

            if finding.suggestion:
                lines.append("**Suggestion:**")
                lines.append("")
                lines.append("```sql")
                lines.append(finding.suggestion)
                lines.append("```")
                lines.append("")

            if finding.assumptions:
                lines.append("**Assumptions:**")
                lines.append("")
                for assumption in finding.assumptions:
                    lines.append(f"- {assumption}")
                lines.append("")

            if finding.verification_steps:
                lines.append("**Verification:**")
                lines.append("")
                for step in finding.verification_steps:
                    lines.append(f"- [ ] {step}")
                lines.append("")

    # Rule execution (collapsible)
    if result.rule_runs:
        lines.append("<details>")
        lines.append("<summary>Rule Execution Details</summary>")
        lines.append("")
        lines.append("| Rule | Status | Runtime |")
        lines.append("|------|--------|---------|")
        for run in result.rule_runs:
            status_icon = (
                "✅"
                if run.status.value == "pass"
                else ("⏭️" if run.status.value == "skip" else "❌")
            )
            lines.append(
                f"| `{run.rule_id}` | {status_icon} {run.status.value} | "
                f"{run.runtime_ms:.1f}ms |"
            )
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Reproducibility info
    if result.reproducibility:
        lines.append("<details>")
        lines.append("<summary>Reproducibility Info</summary>")
        lines.append("")
        lines.append("```")
        lines.append(f"analysis_id: {result.reproducibility.analysis_id}")
        lines.append(f"plan_hash: {result.reproducibility.plan_hash}")
        if result.reproducibility.sql_hash:
            lines.append(f"sql_hash: {result.reproducibility.sql_hash}")
        lines.append(f"config_hash: {result.reproducibility.config_hash}")
        lines.append(f"rules_hash: {result.reproducibility.rules_hash}")
        lines.append(
            f"querysense_version: {result.reproducibility.querysense_version}"
        )
        lines.append("```")
        lines.append("")
        lines.append("</details>")

    return "\n".join(lines)


# =============================================================================
# Upgrade report renderers (consolidated from cli/main.py)
# =============================================================================


def render_upgrade_text(report: "UpgradeReport") -> str:
    """Render an upgrade report as text."""
    lines: list[str] = []

    header = (
        f"PostgreSQL Upgrade Validation: "
        f"{report.before_version or '?'} -> {report.after_version or '?'}"
    )
    lines.append(header)
    lines.append("=" * len(header))
    lines.append("")

    safety = "SAFE" if report.safe_to_upgrade else "RISK DETECTED"
    lines.append(f"Assessment: {safety}")
    lines.append(f"Total queries: {report.total_queries}")
    lines.append(f"Regressions: {report.regression_count}")
    lines.append(f"Critical/High: {report.critical_regression_count}")
    lines.append("")

    if report.verdicts:
        lines.append("Regression Details:")
        lines.append("-" * 40)
        for verdict in report.verdicts:
            lines.append(verdict.format_summary())
            lines.append("")

    return "\n".join(lines)


def render_upgrade_markdown(report: "UpgradeReport") -> str:
    """Render an upgrade report as Markdown."""
    lines: list[str] = []

    safe = report.safe_to_upgrade
    icon = "✅" if safe else "🔴"
    status = "Safe to proceed" if safe else "Regressions detected"

    lines.append(f"## {icon} PostgreSQL Upgrade Validation — {status}")
    lines.append("")
    lines.append(
        f"**{report.before_version or '?'}** → **{report.after_version or '?'}** | "
        f"{report.total_queries} queries checked"
    )
    lines.append("")

    # Summary table
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total queries | {report.total_queries} |")
    lines.append(f"| Regressions | {report.regression_count} |")
    lines.append(f"| Critical/High | {report.critical_regression_count} |")
    lines.append(f"| Assessment | {'Safe' if safe else '**RISK**'} |")
    lines.append("")

    # Verdict details
    if report.verdicts:
        lines.append("### Regression Details")
        lines.append("")

        for verdict in report.verdicts:
            sev = verdict.severity.value.upper()
            lines.append(
                f"#### `{verdict.query_id}` — {sev} "
                f"(danger: {verdict.danger_score}/100)"
            )
            lines.append("")

            if verdict.rationale:
                lines.append(f"> {verdict.rationale}")
                lines.append("")

            if verdict.structural_changes:
                lines.append("<details>")
                lines.append("<summary>Structural changes</summary>")
                lines.append("")
                for change in verdict.structural_changes:
                    lines.append(f"- {change}")
                lines.append("")
                lines.append("</details>")
                lines.append("")

            if verdict.plausible_causes:
                lines.append("<details>")
                lines.append("<summary>Plausible causes</summary>")
                lines.append("")
                for cause in verdict.plausible_causes:
                    lines.append(f"- {cause}")
                lines.append("")
                lines.append("</details>")
                lines.append("")

            if verdict.recommended_actions:
                lines.append("**Recommended actions:**")
                for action in verdict.recommended_actions:
                    lines.append(f"- [ ] {action}")
                lines.append("")

    # Footer
    lines.append("---")
    lines.append(
        "*Powered by [QuerySense](https://github.com/JosephAhn23/Query-Sense) "
        "— EXPLAIN plan linter for CI/CD*"
    )

    return "\n".join(lines)


# =============================================================================
# Helpers
# =============================================================================


def _severity_icon(severity: Any) -> str:
    """Get icon for severity level."""
    severity_str = severity.value if hasattr(severity, "value") else str(severity)
    return {
        "critical": "🔴",
        "warning": "🟡",
        "info": "🔵",
    }.get(severity_str, "⚪")
