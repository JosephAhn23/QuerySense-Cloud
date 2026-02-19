"""
Audit trail generator for QuerySense.

Produces timestamped, hash-signed analysis reports suitable for
compliance requirements (SOC2, PCI, HIPAA audit evidence).

Every analysis produces a deterministic, reproducible report that includes:
- Analysis timestamp (UTC)
- Input hashes (plan, SQL, config)
- All findings with severity
- Policy evaluation results
- Baseline comparison results
- QuerySense version and rule versions

The audit trail is designed to answer: "What did QuerySense say about
this query at this point in time, and can we reproduce it?"

Usage:
    from querysense.audit_trail import AuditTrail, render_audit_report

    trail = AuditTrail.from_analysis(
        result=analysis_result,
        baseline_diff=baseline_diff,
        policy_violations=violations,
    )

    # JSON for storage
    report_json = trail.to_json()

    # Markdown for human review
    report_md = render_audit_report(trail)
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult
    from querysense.baseline import BaselineDiff
    from querysense.policy import PolicyViolation

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuditTrail:
    """
    Immutable, timestamped record of an analysis run.

    Designed for compliance audit evidence. Every field is
    deterministic given the same inputs.
    """

    # Identification
    audit_id: str
    timestamp: str  # ISO 8601 UTC
    querysense_version: str

    # Input hashes
    plan_hash: str
    sql_hash: str | None
    config_hash: str
    rules_hash: str

    # Results summary
    findings_count: int
    critical_count: int
    warning_count: int
    info_count: int

    # Findings detail
    findings: tuple[dict[str, Any], ...] = ()

    # Baseline
    baseline_status: str = "not_checked"  # "not_checked", "unchanged", "changed", "no_baseline"
    regression_severity: str = "none"
    danger_score: int = 0
    is_locked: bool = False

    # Policy
    policy_violations: tuple[dict[str, Any], ...] = ()
    policy_pass: bool = True

    # Rule execution
    rules_run: int = 0
    rules_passed: int = 0
    rules_skipped: int = 0
    rules_failed: int = 0

    # Evidence level
    evidence_level: str = "PLAN"

    # Integrity
    report_hash: str = ""  # SHA-256 of all other fields

    @classmethod
    def from_analysis(
        cls,
        result: "AnalysisResult",
        baseline_diff: "BaselineDiff | None" = None,
        policy_violations: list["PolicyViolation"] | None = None,
    ) -> "AuditTrail":
        """
        Create an audit trail from analysis results.

        Args:
            result: The analysis result
            baseline_diff: Optional baseline comparison
            policy_violations: Optional policy evaluation results

        Returns:
            Immutable AuditTrail record
        """
        from querysense.analyzer.models import RuleRunStatus, Severity

        now = datetime.now(timezone.utc)

        # Build findings detail
        findings_detail = tuple(
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "title": f.title,
                "table": f.context.relation_name,
                "node_type": f.context.node_type,
                "impact_band": f.impact_band.value if hasattr(f.impact_band, "value") else str(f.impact_band),
            }
            for f in result.findings
        )

        # Baseline info
        baseline_status = "not_checked"
        regression_severity = "none"
        danger_score = 0
        is_locked = False
        if baseline_diff is not None:
            baseline_status = baseline_diff.status.lower()
            if hasattr(baseline_diff, "regression_severity"):
                regression_severity = baseline_diff.regression_severity.value
            if hasattr(baseline_diff, "danger_score"):
                danger_score = baseline_diff.danger_score
            is_locked = getattr(baseline_diff, "is_locked", False)

        # Policy info
        policy_detail = tuple(
            {
                "rule": v.rule,
                "message": v.message,
                "severity": v.severity,
                "table": v.table,
                "query_id": v.query_id,
            }
            for v in (policy_violations or [])
        )

        # Rule execution stats
        rules_passed = len(result.rule_runs_by_status(RuleRunStatus.PASS))
        rules_skipped = len(result.rule_runs_by_status(RuleRunStatus.SKIP))
        rules_failed = len(result.rule_runs_by_status(RuleRunStatus.FAIL))

        # Build the trail without report_hash first
        trail_data = {
            "audit_id": result.reproducibility.analysis_id,
            "timestamp": now.isoformat(),
            "querysense_version": result.reproducibility.querysense_version,
            "plan_hash": result.reproducibility.plan_hash,
            "sql_hash": result.reproducibility.sql_hash,
            "config_hash": result.reproducibility.config_hash,
            "rules_hash": result.reproducibility.rules_hash,
            "findings_count": len(result.findings),
            "critical_count": len(result.findings_by_severity(Severity.CRITICAL)),
            "warning_count": len(result.findings_by_severity(Severity.WARNING)),
            "info_count": len(result.findings_by_severity(Severity.INFO)),
            "findings": findings_detail,
            "baseline_status": baseline_status,
            "regression_severity": regression_severity,
            "danger_score": danger_score,
            "is_locked": is_locked,
            "policy_violations": policy_detail,
            "policy_pass": len(policy_detail) == 0,
            "rules_run": result.metadata.rules_run,
            "rules_passed": rules_passed,
            "rules_skipped": rules_skipped,
            "rules_failed": rules_failed,
            "evidence_level": result.evidence_level.value,
        }

        # Compute integrity hash over all fields
        hash_content = json.dumps(trail_data, sort_keys=True, default=str)
        report_hash = hashlib.sha256(hash_content.encode()).hexdigest()

        return cls(**trail_data, report_hash=report_hash)

    def to_json(self) -> str:
        """Serialize to JSON for storage."""
        data = {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp,
            "querysense_version": self.querysense_version,
            "plan_hash": self.plan_hash,
            "sql_hash": self.sql_hash,
            "config_hash": self.config_hash,
            "rules_hash": self.rules_hash,
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
            "warning_count": self.warning_count,
            "info_count": self.info_count,
            "findings": list(self.findings),
            "baseline_status": self.baseline_status,
            "regression_severity": self.regression_severity,
            "danger_score": self.danger_score,
            "is_locked": self.is_locked,
            "policy_violations": list(self.policy_violations),
            "policy_pass": self.policy_pass,
            "rules_run": self.rules_run,
            "rules_passed": self.rules_passed,
            "rules_skipped": self.rules_skipped,
            "rules_failed": self.rules_failed,
            "evidence_level": self.evidence_level,
            "report_hash": self.report_hash,
        }
        return json.dumps(data, indent=2, sort_keys=True)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return json.loads(self.to_json())


def render_audit_report(trail: AuditTrail) -> str:
    """
    Render an audit trail as a Markdown report.

    Suitable for attaching to compliance documentation,
    PR comments, or archival storage.

    Args:
        trail: The audit trail to render

    Returns:
        Markdown string
    """
    lines: list[str] = []

    # Header
    status = "PASS" if trail.policy_pass and trail.findings_count == 0 else "FINDINGS"
    if not trail.policy_pass:
        status = "POLICY VIOLATION"

    lines.append(f"# QuerySense Audit Report — {status}")
    lines.append("")

    # Metadata table
    lines.append("## Analysis Metadata")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Audit ID | `{trail.audit_id}` |")
    lines.append(f"| Timestamp | {trail.timestamp} |")
    lines.append(f"| QuerySense Version | {trail.querysense_version} |")
    lines.append(f"| Evidence Level | {trail.evidence_level} |")
    lines.append(f"| Plan Hash | `{trail.plan_hash}` |")
    if trail.sql_hash:
        lines.append(f"| SQL Hash | `{trail.sql_hash}` |")
    lines.append(f"| Config Hash | `{trail.config_hash}` |")
    lines.append(f"| Rules Hash | `{trail.rules_hash}` |")
    lines.append(f"| Report Integrity | `{trail.report_hash[:16]}...` |")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append(
        f"| Metric | Count |"
    )
    lines.append("|--------|-------|")
    lines.append(f"| Total Findings | {trail.findings_count} |")
    lines.append(f"| Critical | {trail.critical_count} |")
    lines.append(f"| Warning | {trail.warning_count} |")
    lines.append(f"| Info | {trail.info_count} |")
    lines.append(f"| Rules Run | {trail.rules_run} |")
    lines.append(f"| Rules Passed | {trail.rules_passed} |")
    lines.append(f"| Rules Skipped | {trail.rules_skipped} |")
    lines.append(f"| Rules Failed | {trail.rules_failed} |")
    lines.append("")

    # Baseline status
    if trail.baseline_status != "not_checked":
        lines.append("## Baseline Comparison")
        lines.append("")
        lines.append(f"- **Status:** {trail.baseline_status.upper()}")
        if trail.baseline_status == "changed":
            lines.append(f"- **Regression Severity:** {trail.regression_severity.upper()}")
            lines.append(f"- **Danger Score:** {trail.danger_score}/100")
        if trail.is_locked:
            lines.append("- **Locked Plan:** YES (violation detected)")
        lines.append("")

    # Policy evaluation
    if trail.policy_violations:
        lines.append("## Policy Violations")
        lines.append("")
        for pv in trail.policy_violations:
            sev_icon = {"critical": "🔴", "warning": "🟡"}.get(
                pv.get("severity", ""), "⚪"
            )
            lines.append(f"- {sev_icon} **{pv.get('rule', 'unknown')}**: {pv.get('message', '')}")
        lines.append("")
    elif trail.policy_pass:
        lines.append("## Policy Evaluation")
        lines.append("")
        lines.append("All policies passed.")
        lines.append("")

    # Findings detail
    if trail.findings:
        lines.append("## Findings Detail")
        lines.append("")
        lines.append("| # | Severity | Rule | Table | Title |")
        lines.append("|---|----------|------|-------|-------|")
        for i, f in enumerate(trail.findings, 1):
            sev = f.get("severity", "?").upper()
            lines.append(
                f"| {i} | {sev} | `{f.get('rule_id', '')}` | "
                f"{f.get('table', '-')} | {f.get('title', '')} |"
            )
        lines.append("")

    # Footer
    lines.append("---")
    lines.append(
        f"*Generated by QuerySense {trail.querysense_version} "
        f"at {trail.timestamp}. "
        f"Report hash: `{trail.report_hash[:16]}`*"
    )

    return "\n".join(lines)
