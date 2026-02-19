"""
Package-level exception hierarchy for QuerySense.

All exceptions inherit from QuerySenseError, enabling:
- Catching all QuerySense errors with a single except clause
- Rich context fields for debugging (rule_id, node_path, config_key, etc.)
- Structured serialization via to_dict() for JSON error responses
- Actionable fix suggestions for every error (unlike AWS DMS silent failures)
- Error codes for programmatic handling

Hierarchy:
    QuerySenseError
    ├── AnalyzerError          – Errors during analysis orchestration
    │   ├── RuleError          – A specific rule failed during execution
    │   └── ConfigurationError – Invalid analyzer configuration
    ├── ParseError             – Failed to parse EXPLAIN JSON input
    ├── IRConversionError      – Failed to convert plan to IR representation
    ├── BaselineError          – Errors in baseline storage / comparison
    ├── PolicyError            – Policy evaluation failures
    └── CloudError             – Errors in the cloud / API layer
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from querysense.analyzer.path import NodePath


class QuerySenseError(Exception):
    """
    Base exception for all QuerySense errors.

    All QuerySense-specific exceptions inherit from this class,
    enabling callers to catch all library errors with a single handler.

    Design principle: every error tells you WHAT happened, WHY it happened,
    and HOW to fix it. No silent failures, no cryptic stack traces.
    This is what AWS DMS and Percona PMM get wrong.

    Attributes:
        message: Human-readable error description.
        fix_suggestion: Actionable fix the user can apply immediately.
        docs_url: Link to relevant documentation (if available).
        error_code: Machine-readable error code (e.g., "QS-E001").
    """

    def __init__(
        self,
        message: str,
        *,
        fix_suggestion: str | None = None,
        docs_url: str | None = None,
        error_code: str | None = None,
    ) -> None:
        self.message = message
        self.fix_suggestion = fix_suggestion
        self.docs_url = docs_url
        self.error_code = error_code
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON error responses."""
        result: dict[str, Any] = {
            "error_type": type(self).__name__,
            "message": self.message,
        }
        if self.fix_suggestion:
            result["fix"] = self.fix_suggestion
        if self.docs_url:
            result["docs"] = self.docs_url
        if self.error_code:
            result["code"] = self.error_code
        return result

    def format_rich(self) -> str:
        """Format for Rich console output with fix guidance."""
        parts = [f"[red bold]{self.error_code or 'ERROR'}:[/red bold] {self.message}"]
        if self.fix_suggestion:
            parts.append(f"\n[yellow bold]Fix:[/yellow bold] {self.fix_suggestion}")
        if self.docs_url:
            parts.append(f"[dim]Docs: {self.docs_url}[/dim]")
        return "\n".join(parts)


# ── Analysis Errors ──────────────────────────────────────────────────────


class AnalyzerError(QuerySenseError):
    """Errors during analysis orchestration."""
    pass


class RuleError(AnalyzerError):
    """
    Error during rule execution.

    Captures which rule failed and optionally which node it was processing.
    This context is essential for debugging rule issues — unlike tools
    that silently skip failed rules, we tell you exactly what broke.

    Attributes:
        rule_id: The ID of the rule that failed.
        rule_version: Version of the rule.
        node_path: Path to the node being processed (if known).
        original_error: The underlying exception.
    """

    def __init__(
        self,
        rule_id: str,
        rule_version: str,
        original_error: Exception,
        node_path: "NodePath | None" = None,
    ) -> None:
        self.rule_id = rule_id
        self.rule_version = rule_version
        self.node_path = node_path
        self.original_error = original_error

        context = f"Rule '{rule_id}' v{rule_version}"
        if node_path:
            context += f" at {node_path}"

        message = (
            f"{context} failed: "
            f"{original_error.__class__.__name__}: {original_error}"
        )
        super().__init__(
            message,
            fix_suggestion=(
                f"This is a bug in the '{rule_id}' rule. The analysis will "
                f"continue without it. Please report this at "
                f"https://github.com/JosephAhn23/Query-Sense/issues "
                f"with the EXPLAIN JSON that triggered it."
            ),
            error_code="QS-R001",
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output / logging."""
        result = super().to_dict()
        result.update({
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "node_path": list(self.node_path.segments) if self.node_path else None,
            "original_error_type": self.original_error.__class__.__name__,
            "original_error_message": str(self.original_error),
        })
        return result


class ConfigurationError(AnalyzerError):
    """
    Error in analyzer configuration.

    Attributes:
        config_key: The configuration key that caused the error (if known).
    """

    def __init__(self, message: str, config_key: str | None = None) -> None:
        self.config_key = config_key
        fix = None
        if config_key:
            fix = f"Check the '{config_key}' value in your configuration file."
        super().__init__(
            message,
            fix_suggestion=fix,
            error_code="QS-C001",
        )

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result["config_key"] = self.config_key
        return result


# ── Parse Errors ─────────────────────────────────────────────────────────


class ParseError(QuerySenseError):
    """
    Failed to parse EXPLAIN JSON input.

    Raised when the input is not valid EXPLAIN JSON, is too large,
    too deeply nested, or otherwise cannot be interpreted.

    Unlike AWS DMS (which logs nothing when tasks fail), every parse
    error tells you exactly what's wrong and how to generate valid input.

    Attributes:
        source: Description of the input source (file path, "stdin", etc.).
    """

    def __init__(self, message: str, source: str | None = None) -> None:
        self.source = source

        # Auto-detect fix suggestions based on common failure patterns
        fix = None
        if "not valid json" in message.lower() or "json" in message.lower():
            fix = (
                "Ensure you're using FORMAT JSON: "
                "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT ..."
            )
        elif "empty" in message.lower():
            fix = (
                "The file appears empty. Generate a plan with:\n"
                "  psql -c 'EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) your_query' > plan.json"
            )
        elif "too large" in message.lower() or "too deep" in message.lower():
            fix = (
                "The plan is unusually large. Try simplifying the query or "
                "setting max_depth in your QuerySense config."
            )

        super().__init__(
            message,
            fix_suggestion=fix,
            error_code="QS-P001",
        )

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result["source"] = self.source
        return result


# ── IR Errors ────────────────────────────────────────────────────────────


class IRConversionError(QuerySenseError):
    """
    Failed to convert a plan to the IR (Intermediate Representation).

    Raised when the engine-specific adapter cannot translate a plan
    node into the universal IR format.

    Attributes:
        engine: The source engine (e.g., "postgresql", "mysql").
        node_type: The plan node type that failed conversion.
    """

    def __init__(
        self,
        message: str,
        engine: str | None = None,
        node_type: str | None = None,
    ) -> None:
        self.engine = engine
        self.node_type = node_type
        super().__init__(
            message,
            fix_suggestion=(
                f"The '{node_type or 'unknown'}' node type from {engine or 'unknown'} "
                f"engine could not be converted. This may be an unsupported feature. "
                f"Please report at https://github.com/JosephAhn23/Query-Sense/issues"
            ),
            error_code="QS-I001",
        )

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result["engine"] = self.engine
        result["node_type"] = self.node_type
        return result


# ── Baseline Errors ──────────────────────────────────────────────────────


class BaselineError(QuerySenseError):
    """
    Errors in baseline storage or comparison.

    Raised when baseline files are corrupt, schema versions are
    incompatible, or comparison fails.
    """

    def __init__(self, message: str) -> None:
        fix = None
        if "corrupt" in message.lower() or "invalid" in message.lower():
            fix = (
                "The baseline file may be corrupt. Regenerate it with:\n"
                "  querysense baseline update 'plans/**/*.json'"
            )
        elif "not found" in message.lower():
            fix = (
                "No baseline file found. Create one with:\n"
                "  querysense baseline update 'plans/**/*.json'"
            )
        super().__init__(message, fix_suggestion=fix, error_code="QS-B001")


# ── Policy Errors ────────────────────────────────────────────────────────


class PolicyError(QuerySenseError):
    """
    Policy evaluation failure.

    Raised when a policy file cannot be loaded, parsed, or evaluated.
    NOT raised for policy violations (those return PolicyViolation objects).
    """

    def __init__(self, message: str) -> None:
        fix = None
        if "not found" in message.lower():
            fix = (
                "Create a policy file with:\n"
                "  querysense policy init"
            )
        elif "syntax" in message.lower() or "parse" in message.lower():
            fix = "Check the YAML syntax in your policy file."
        super().__init__(message, fix_suggestion=fix, error_code="QS-Y001")


# ── Cloud Errors ─────────────────────────────────────────────────────────


class CloudError(QuerySenseError):
    """
    Errors in the cloud / API layer.

    Covers authentication failures, rate limiting, and service errors.
    """

    def __init__(self, message: str) -> None:
        fix = None
        if "auth" in message.lower() or "401" in message:
            fix = (
                "Check your API key. Generate one at Settings > API Keys, "
                "then set: Authorization: Bearer qs_..."
            )
        elif "rate" in message.lower() or "429" in message:
            fix = "You've hit the rate limit. Wait a moment and retry, or upgrade your plan."
        elif "limit" in message.lower():
            fix = "You've reached your plan limit. Check your usage at Settings > Billing."
        super().__init__(message, fix_suggestion=fix, error_code="QS-W001")
