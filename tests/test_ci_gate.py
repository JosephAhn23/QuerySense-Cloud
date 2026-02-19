"""
Tests for the CI gate command and supporting modules.

Tests cover:
- CI config loading and parsing
- GitHub Actions annotation formatting
- Step summary generation
- Gate command exit codes
- Config file auto-discovery
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from querysense.analyzer.models import (
    AnalysisResult,
    EvidenceLevel,
    ExecutionMetadata,
    Finding,
    ImpactBand,
    NodeContext,
    ReproducibilityInfo,
    RuleRun,
    RuleRunStatus,
    Severity,
    SQLConfidence,
)
from querysense.analyzer.path import NodePath
from querysense.ci_config import CIConfig, GitHubSettings, FileOverride, load_ci_config, _simple_yaml_parse
from querysense.output.github_annotations import (
    render_annotations,
    render_step_summary,
)
from querysense.output.pr_comment import CIResult


# =============================================================================
# Fixtures
# =============================================================================

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _make_finding(
    rule_id: str = "SEQ_SCAN_LARGE_TABLE",
    severity: Severity = Severity.WARNING,
    title: str = "Sequential scan on orders (500,000 rows)",
    description: str = "Full table scan on a large table",
    suggestion: str | None = "CREATE INDEX idx_orders_status ON orders(status);",
    relation_name: str = "orders",
    actual_rows: int = 500000,
) -> Finding:
    """Create a test finding."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        context=NodeContext(
            path=NodePath.root(),
            node_type="Seq Scan",
            relation_name=relation_name,
            actual_rows=actual_rows,
            plan_rows=500000,
            total_cost=18334.0,
        ),
        title=title,
        description=description,
        suggestion=suggestion,
        impact_band=ImpactBand.MEDIUM,
    )


def _make_result(
    findings: list[Finding] | None = None,
) -> AnalysisResult:
    """Create a test AnalysisResult."""
    if findings is None:
        findings = [_make_finding()]

    return AnalysisResult.create(
        findings=findings,
        rule_runs=[
            RuleRun(
                rule_id="SEQ_SCAN_LARGE_TABLE",
                version="1.0",
                status=RuleRunStatus.PASS,
                runtime_ms=1.5,
                findings_count=len(findings),
            ),
        ],
        evidence_level=EvidenceLevel.PLAN,
        sql_confidence=SQLConfidence.NONE,
        reproducibility=ReproducibilityInfo(
            analysis_id="test-ci",
            plan_hash="abc123",
            sql_hash=None,
            config_hash="def456",
            rules_hash="ghi789",
            querysense_version="0.5.2",
        ),
        metadata=ExecutionMetadata(
            node_count=1,
            execution_time_ms=547.234,
            rules_run=1,
        ),
    )


def _make_ci_result(
    file_path: str = "plans/slow_query.json",
    findings: list[Finding] | None = None,
) -> CIResult:
    """Create a test CIResult."""
    return CIResult(
        file_path=file_path,
        result=_make_result(findings),
    )


# =============================================================================
# CI Config Tests
# =============================================================================


class TestCIConfig:
    """Tests for CI configuration loading."""

    def test_default_config(self) -> None:
        """Default config has sensible values."""
        cfg = CIConfig.default()
        assert cfg.plans == ("plans/**/*.json",)
        assert cfg.fail_on == "warning"
        assert cfg.require_analyze is True
        assert cfg.github.annotations is True
        assert cfg.github.step_summary is True

    def test_load_nonexistent_explicit_path_raises(self) -> None:
        """Explicit path that doesn't exist raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_ci_config("/nonexistent/path.yml")

    def test_load_auto_discovery_returns_defaults(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """When no config files exist, returns defaults."""
        monkeypatch.chdir(tmp_path)
        cfg = load_ci_config()
        assert cfg.fail_on == "warning"

    def test_load_from_yml_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Config loads from .querysense-ci.yml."""
        monkeypatch.chdir(tmp_path)
        config_content = """\
plans:
  - "sql/**/*.json"
fail_on: critical
require_analyze: false
github:
  annotations: false
  step_summary: true
"""
        (tmp_path / ".querysense-ci.yml").write_text(config_content)
        cfg = load_ci_config()
        assert cfg.plans == ("sql/**/*.json",)
        assert cfg.fail_on == "critical"
        assert cfg.require_analyze is False
        assert cfg.github.annotations is False
        assert cfg.github.step_summary is True

    def test_effective_fail_on_with_override(self) -> None:
        """File-specific override changes fail_on for matching files."""
        cfg = CIConfig(
            fail_on="warning",
            overrides=(
                FileOverride(pattern="migrations/*.json", fail_on="critical"),
            ),
        )
        assert cfg.effective_fail_on("plans/query.json") == "warning"
        assert cfg.effective_fail_on("migrations/001.json") == "critical"

    def test_effective_ignore_rules_combines(self) -> None:
        """Ignored rules combine global + per-file overrides."""
        cfg = CIConfig(
            ignore_rules=("MISSING_BUFFERS",),
            overrides=(
                FileOverride(
                    pattern="migrations/*.json",
                    ignore_rules=("PARALLEL_QUERY_NOT_USED",),
                ),
            ),
        )
        # Non-matching file: only global ignores
        assert cfg.effective_ignore_rules("plans/query.json") == {"MISSING_BUFFERS"}
        # Matching file: global + override
        assert cfg.effective_ignore_rules("migrations/001.json") == {
            "MISSING_BUFFERS",
            "PARALLEL_QUERY_NOT_USED",
        }


class TestSimpleYamlParser:
    """Tests for the fallback YAML parser."""

    def test_parses_basic_key_value(self) -> None:
        """Parses simple key: value pairs."""
        result = _simple_yaml_parse("fail_on: critical\nrequire_analyze: true")
        assert result["fail_on"] == "critical"
        assert result["require_analyze"] is True

    def test_parses_list(self) -> None:
        """Parses YAML list syntax."""
        result = _simple_yaml_parse("plans:\n  - one.json\n  - two.json")
        assert result["plans"] == ["one.json", "two.json"]

    def test_ignores_comments(self) -> None:
        """Comments are ignored."""
        result = _simple_yaml_parse("# comment\nfail_on: warning\n# another comment")
        assert result["fail_on"] == "warning"
        assert len(result) == 1

    def test_parses_boolean_values(self) -> None:
        """true/false strings become Python booleans."""
        result = _simple_yaml_parse("enabled: true\ndisabled: false")
        assert result["enabled"] is True
        assert result["disabled"] is False


# =============================================================================
# GitHub Annotations Tests
# =============================================================================


class TestGitHubAnnotations:
    """Tests for GitHub Actions annotation formatting."""

    def test_render_warning_annotation(self) -> None:
        """Warning findings produce ::warning annotations."""
        ci_results = [_make_ci_result()]
        output = render_annotations(ci_results)

        assert "::warning " in output
        assert "SEQ_SCAN_LARGE_TABLE" in output
        assert "plans/slow_query.json" in output

    def test_render_critical_annotation(self) -> None:
        """Critical findings produce ::error annotations."""
        finding = _make_finding(
            rule_id="EXCESSIVE_SEQ_SCANS",
            severity=Severity.CRITICAL,
            title="Multiple sequential scans detected",
            description="Too many seq scans in one query",
        )
        ci_results = [_make_ci_result(findings=[finding])]
        output = render_annotations(ci_results)

        assert "::error " in output
        assert "EXCESSIVE_SEQ_SCANS" in output

    def test_render_info_annotation(self) -> None:
        """Info findings produce ::notice annotations."""
        finding = _make_finding(
            rule_id="MISSING_BUFFERS",
            severity=Severity.INFO,
            title="Missing buffer statistics",
            description="Buffer stats not available",
            suggestion=None,
        )
        ci_results = [_make_ci_result(findings=[finding])]
        output = render_annotations(ci_results)

        assert "::notice " in output

    def test_render_multiple_files(self) -> None:
        """Multiple CI results produce annotations for each file."""
        ci_results = [
            _make_ci_result(file_path="plans/query_a.json"),
            _make_ci_result(file_path="plans/query_b.json"),
        ]
        output = render_annotations(ci_results)

        assert "query_a.json" in output
        assert "query_b.json" in output

    def test_render_empty_results(self) -> None:
        """No findings produces empty annotation output."""
        ci_results = [_make_ci_result(findings=[])]
        output = render_annotations(ci_results)
        assert output == ""

    def test_suggestion_included_in_annotation(self) -> None:
        """Fix suggestion appears in the annotation message."""
        ci_results = [_make_ci_result()]
        output = render_annotations(ci_results)
        assert "Fix:" in output
        assert "CREATE INDEX" in output

    def test_newlines_escaped(self) -> None:
        """Newlines in messages are escaped for GitHub Actions."""
        finding = _make_finding(
            description="Line 1\nLine 2\nLine 3",
        )
        ci_results = [_make_ci_result(findings=[finding])]
        output = render_annotations(ci_results)

        # Raw newlines should be escaped
        assert "\n" not in output.split("::")[1] or "%0A" in output


# =============================================================================
# Step Summary Tests
# =============================================================================


class TestStepSummary:
    """Tests for GITHUB_STEP_SUMMARY generation."""

    def test_failing_summary_has_x_icon(self) -> None:
        """Failed checks show :x: in the header."""
        ci_results = [_make_ci_result()]
        output = render_step_summary(ci_results, fail_on="warning")

        assert ":x:" in output
        assert "Performance issues detected" in output

    def test_passing_summary_has_check_icon(self) -> None:
        """Passed checks show :white_check_mark: in the header."""
        ci_results = [_make_ci_result(findings=[])]
        output = render_step_summary(ci_results, fail_on="warning")

        assert ":white_check_mark:" in output
        assert "All checks passed" in output

    def test_summary_contains_counts_table(self) -> None:
        """Summary includes a counts table with all severity levels."""
        ci_results = [_make_ci_result()]
        output = render_step_summary(ci_results, fail_on="warning")

        assert "Plans analyzed" in output
        assert "Critical" in output
        assert "Warnings" in output

    def test_summary_contains_suggestions(self) -> None:
        """Summary includes SQL fix suggestions for actionable findings."""
        ci_results = [_make_ci_result()]
        output = render_step_summary(ci_results, fail_on="warning")

        assert "Suggested fixes" in output
        assert "CREATE INDEX" in output

    def test_summary_contains_footer(self) -> None:
        """Summary has QuerySense branding footer."""
        ci_results = [_make_ci_result(findings=[])]
        output = render_step_summary(ci_results, fail_on="warning")

        assert "QuerySense" in output
        assert "lint your SQL performance" in output


# =============================================================================
# GitHub Output Tests
# =============================================================================


class TestGitHubOutputs:
    """Tests for GITHUB_OUTPUT variable writing."""

    def test_writes_outputs_to_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Output variables are written to GITHUB_OUTPUT file."""
        from querysense.output.github_annotations import write_github_outputs

        output_file = tmp_path / "output.txt"
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

        ci_results = [_make_ci_result()]
        result = write_github_outputs(ci_results, fail_on="warning")

        assert result is True
        content = output_file.read_text()
        assert "result=fail" in content
        assert "warning_count=1" in content
        assert "total_plans=1" in content

    def test_writes_pass_when_no_issues(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Output is 'pass' when no issues found."""
        from querysense.output.github_annotations import write_github_outputs

        output_file = tmp_path / "output.txt"
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

        ci_results = [_make_ci_result(findings=[])]
        write_github_outputs(ci_results, fail_on="warning")

        content = output_file.read_text()
        assert "result=pass" in content

    def test_returns_false_outside_github(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns False when not in GitHub Actions."""
        from querysense.output.github_annotations import write_github_outputs

        monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
        result = write_github_outputs([_make_ci_result()], fail_on="warning")
        assert result is False

    def test_findings_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Findings JSON is written as multi-line output."""
        from querysense.output.github_annotations import write_github_outputs

        output_file = tmp_path / "output.txt"
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

        ci_results = [_make_ci_result()]
        write_github_outputs(ci_results, fail_on="warning")

        content = output_file.read_text()
        assert "findings_json<<EOF" in content
        # Verify the JSON is valid
        json_start = content.index("findings_json<<EOF\n") + len("findings_json<<EOF\n")
        json_end = content.index("\nEOF", json_start)
        findings = json.loads(content[json_start:json_end])
        assert isinstance(findings, list)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SEQ_SCAN_LARGE_TABLE"


# =============================================================================
# Step Summary File Tests
# =============================================================================


class TestStepSummaryFile:
    """Tests for writing to GITHUB_STEP_SUMMARY."""

    def test_writes_to_summary_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Summary is written to GITHUB_STEP_SUMMARY path."""
        from querysense.output.github_annotations import write_step_summary

        summary_file = tmp_path / "summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

        ci_results = [_make_ci_result()]
        result = write_step_summary(ci_results, fail_on="warning")

        assert result is True
        content = summary_file.read_text()
        assert "QuerySense" in content

    def test_returns_false_outside_github(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns False when GITHUB_STEP_SUMMARY is not set."""
        from querysense.output.github_annotations import write_step_summary

        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
        result = write_step_summary([_make_ci_result()], fail_on="warning")
        assert result is False


# =============================================================================
# Integration: Gate command (via CLI runner)
# =============================================================================


class TestCIGateIntegration:
    """Integration tests for `querysense ci gate` using Typer test runner."""

    def test_gate_passes_clean_plan(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Gate exits 0 for a clean plan with no issues."""
        from typer.testing import CliRunner
        from querysense.cli.main import app

        monkeypatch.chdir(tmp_path)

        # Multi-node plan with balanced timing + buffer data — no rules should fire.
        # Both nodes must stay under 60% exclusive time (TIME_SKEW threshold).
        plans_dir = tmp_path / "plans"
        plans_dir.mkdir()

        clean_plan = [
            {
                "Plan": {
                    "Node Type": "Limit",
                    "Startup Cost": 0.29,
                    "Total Cost": 8.30,
                    "Plan Rows": 1,
                    "Plan Width": 40,
                    "Actual Startup Time": 0.01,
                    "Actual Total Time": 0.10,
                    "Actual Rows": 1,
                    "Actual Loops": 1,
                    "Shared Hit Blocks": 4,
                    "Shared Read Blocks": 0,
                    "Plans": [
                        {
                            "Node Type": "Index Scan",
                            "Parent Relationship": "Outer",
                            "Relation Name": "users",
                            "Schema": "public",
                            "Index Name": "users_pkey",
                            "Index Cond": "(id = 42)",
                            "Startup Cost": 0.29,
                            "Total Cost": 8.30,
                            "Plan Rows": 1,
                            "Plan Width": 40,
                            "Actual Startup Time": 0.01,
                            "Actual Total Time": 0.05,
                            "Actual Rows": 1,
                            "Actual Loops": 1,
                            "Shared Hit Blocks": 4,
                            "Shared Read Blocks": 0,
                        }
                    ],
                },
                "Planning Time": 0.1,
                "Execution Time": 0.12,
            }
        ]
        (plans_dir / "clean.json").write_text(json.dumps(clean_plan))

        runner = CliRunner()
        result = runner.invoke(app, ["ci", "gate", "plans/*.json"])
        assert result.exit_code == 0

    def test_gate_fails_on_slow_query(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Gate exits 1 when findings exceed fail_on threshold."""
        from typer.testing import CliRunner
        from querysense.cli.main import app

        monkeypatch.chdir(tmp_path)

        plans_dir = tmp_path / "plans"
        plans_dir.mkdir()

        # Copy the fixture that triggers SEQ_SCAN_LARGE_TABLE
        slow_plan = [
            {
                "Plan": {
                    "Node Type": "Seq Scan",
                    "Relation Name": "orders",
                    "Startup Cost": 0.00,
                    "Total Cost": 18334.00,
                    "Plan Rows": 500000,
                    "Plan Width": 68,
                    "Actual Startup Time": 0.015,
                    "Actual Total Time": 523.456,
                    "Actual Rows": 487293,
                    "Actual Loops": 1,
                    "Filter": "(status = 'pending'::text)",
                    "Rows Removed by Filter": 12707,
                },
                "Planning Time": 0.089,
                "Execution Time": 547.234,
            }
        ]
        (plans_dir / "slow.json").write_text(json.dumps(slow_plan))

        runner = CliRunner()
        result = runner.invoke(app, ["ci", "gate", "plans/*.json"])
        assert result.exit_code == 1

    def test_gate_respects_fail_on_critical(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Gate passes when findings are only warnings but fail_on is critical."""
        from typer.testing import CliRunner
        from querysense.cli.main import app

        monkeypatch.chdir(tmp_path)

        plans_dir = tmp_path / "plans"
        plans_dir.mkdir()

        # Multi-node plan that triggers only WARNING findings, not CRITICAL.
        # - Balanced time distribution (each node < 80% → no CRITICAL TIME_SKEW)
        # - Good cache hit ratio (>50% hits → no CRITICAL BUFFER_ANALYSIS)
        # - Distributed cost (no single node at 100% → no CRITICAL COST_HOTSPOT)
        # - Still has a seq scan to produce a WARNING
        slow_plan = [
            {
                "Plan": {
                    "Node Type": "Hash Join",
                    "Join Type": "Inner",
                    "Hash Cond": "(o.user_id = u.id)",
                    "Startup Cost": 3000.00,
                    "Total Cost": 21000.00,
                    "Plan Rows": 400000,
                    "Plan Width": 76,
                    "Actual Startup Time": 200.0,
                    "Actual Total Time": 500.0,
                    "Actual Rows": 400000,
                    "Actual Loops": 1,
                    "Shared Hit Blocks": 20000,
                    "Shared Read Blocks": 2000,
                    "Plans": [
                        {
                            "Node Type": "Seq Scan",
                            "Parent Relationship": "Outer",
                            "Relation Name": "orders",
                            "Schema": "public",
                            "Startup Cost": 0.00,
                            "Total Cost": 15000.00,
                            "Plan Rows": 500000,
                            "Plan Width": 68,
                            "Actual Startup Time": 0.015,
                            "Actual Total Time": 200.0,
                            "Actual Rows": 487293,
                            "Actual Loops": 1,
                            "Filter": "(status = 'pending'::text)",
                            "Rows Removed by Filter": 12707,
                            "Shared Hit Blocks": 10000,
                            "Shared Read Blocks": 1000,
                        },
                        {
                            "Node Type": "Hash",
                            "Parent Relationship": "Inner",
                            "Startup Cost": 2000.00,
                            "Total Cost": 2000.00,
                            "Plan Rows": 50000,
                            "Plan Width": 8,
                            "Actual Startup Time": 150.0,
                            "Actual Total Time": 150.0,
                            "Actual Rows": 50000,
                            "Actual Loops": 1,
                            "Hash Buckets": 65536,
                            "Hash Batches": 1,
                            "Peak Memory Usage": 2048,
                            "Shared Hit Blocks": 8000,
                            "Shared Read Blocks": 1000,
                            "Plans": [
                                {
                                    "Node Type": "Seq Scan",
                                    "Parent Relationship": "Outer",
                                    "Relation Name": "users",
                                    "Schema": "public",
                                    "Startup Cost": 0.00,
                                    "Total Cost": 2000.00,
                                    "Plan Rows": 50000,
                                    "Plan Width": 8,
                                    "Actual Startup Time": 0.01,
                                    "Actual Total Time": 100.0,
                                    "Actual Rows": 50000,
                                    "Actual Loops": 1,
                                    "Shared Hit Blocks": 8000,
                                    "Shared Read Blocks": 1000,
                                }
                            ],
                        }
                    ],
                },
                "Planning Time": 0.5,
                "Execution Time": 510.0,
            }
        ]
        (plans_dir / "slow.json").write_text(json.dumps(slow_plan))

        runner = CliRunner()
        result = runner.invoke(app, ["ci", "gate", "plans/*.json", "--fail-on", "critical"])
        # Should pass because findings are warnings, not critical
        assert result.exit_code == 0

    def test_gate_no_plans_exits_zero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Gate exits 0 when no plan files match (not an error)."""
        from typer.testing import CliRunner
        from querysense.cli.main import app

        monkeypatch.chdir(tmp_path)

        runner = CliRunner()
        result = runner.invoke(app, ["ci", "gate", "nonexistent/*.json"])
        assert result.exit_code == 0

    def test_gate_reads_config_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Gate reads patterns from .querysense-ci.yml."""
        from typer.testing import CliRunner
        from querysense.cli.main import app

        monkeypatch.chdir(tmp_path)

        # Create config pointing to custom directory
        config = "plans:\n  - 'sql_plans/*.json'\nfail_on: critical\n"
        (tmp_path / ".querysense-ci.yml").write_text(config)

        # Create plan file in custom directory
        (tmp_path / "sql_plans").mkdir()
        clean_plan = [
            {
                "Plan": {
                    "Node Type": "Limit",
                    "Startup Cost": 0.29,
                    "Total Cost": 8.30,
                    "Plan Rows": 1,
                    "Plan Width": 40,
                    "Actual Startup Time": 0.01,
                    "Actual Total Time": 0.10,
                    "Actual Rows": 1,
                    "Actual Loops": 1,
                    "Shared Hit Blocks": 4,
                    "Shared Read Blocks": 0,
                    "Plans": [
                        {
                            "Node Type": "Index Scan",
                            "Parent Relationship": "Outer",
                            "Relation Name": "users",
                            "Schema": "public",
                            "Index Name": "users_pkey",
                            "Index Cond": "(id = 42)",
                            "Startup Cost": 0.29,
                            "Total Cost": 8.30,
                            "Plan Rows": 1,
                            "Plan Width": 40,
                            "Actual Startup Time": 0.01,
                            "Actual Total Time": 0.05,
                            "Actual Rows": 1,
                            "Actual Loops": 1,
                            "Shared Hit Blocks": 4,
                            "Shared Read Blocks": 0,
                        }
                    ],
                },
                "Planning Time": 0.1,
                "Execution Time": 0.12,
            }
        ]
        (tmp_path / "sql_plans" / "query.json").write_text(json.dumps(clean_plan))

        runner = CliRunner()
        result = runner.invoke(app, ["ci", "gate"])
        assert result.exit_code == 0

    def test_gate_writes_json_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Gate writes JSON results to file when --json is specified."""
        from typer.testing import CliRunner
        from querysense.cli.main import app

        monkeypatch.chdir(tmp_path)

        plans_dir = tmp_path / "plans"
        plans_dir.mkdir()

        clean_plan = [
            {
                "Plan": {
                    "Node Type": "Limit",
                    "Startup Cost": 0.29,
                    "Total Cost": 8.30,
                    "Plan Rows": 1,
                    "Plan Width": 40,
                    "Actual Startup Time": 0.01,
                    "Actual Total Time": 0.10,
                    "Actual Rows": 1,
                    "Actual Loops": 1,
                    "Shared Hit Blocks": 4,
                    "Shared Read Blocks": 0,
                    "Plans": [
                        {
                            "Node Type": "Index Scan",
                            "Parent Relationship": "Outer",
                            "Relation Name": "users",
                            "Schema": "public",
                            "Index Name": "users_pkey",
                            "Index Cond": "(id = 42)",
                            "Startup Cost": 0.29,
                            "Total Cost": 8.30,
                            "Plan Rows": 1,
                            "Plan Width": 40,
                            "Actual Startup Time": 0.01,
                            "Actual Total Time": 0.05,
                            "Actual Rows": 1,
                            "Actual Loops": 1,
                            "Shared Hit Blocks": 4,
                            "Shared Read Blocks": 0,
                        }
                    ],
                },
                "Planning Time": 0.1,
                "Execution Time": 0.12,
            }
        ]
        (plans_dir / "clean.json").write_text(json.dumps(clean_plan))

        json_path = tmp_path / "results.json"
        runner = CliRunner()
        result = runner.invoke(app, ["ci", "gate", "plans/*.json", "--json", str(json_path)])
        assert result.exit_code == 0
        assert json_path.exists()

        data = json.loads(json_path.read_text())
        assert "summary" in data
        assert "findings" in data
