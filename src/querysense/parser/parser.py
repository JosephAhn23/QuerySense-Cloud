"""
Parser for PostgreSQL EXPLAIN (FORMAT JSON) output.

This module handles:
- Loading EXPLAIN JSON from files or strings
- Validating the structure matches expected format
- Converting to typed Pydantic models
- Detecting whether ANALYZE data is present
- Enforcing resource limits to prevent OOM crashes

Error handling philosophy: Fail fast with clear messages. If we can't parse
the input, tell the user exactly what's wrong rather than returning garbage.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from querysense.exceptions import ParseError as _BaseParseError
from querysense.parser.config import DEFAULT_CONFIG, ParserConfig
from querysense.parser.models import ExplainOutput

if TYPE_CHECKING:
    from typing import Any


class ParseError(_BaseParseError):
    """
    Raised when EXPLAIN JSON cannot be parsed.

    Extends the base ParseError from querysense.exceptions with additional
    detail for debugging parser-specific failures.

    Attributes:
        message: Human-readable error description
        detail: Technical details for debugging (optional)
        source: Where the error occurred (e.g., "validation", "json_decode")
    """

    def __init__(
        self,
        message: str,
        *,
        detail: str | None = None,
        source: str = "unknown",
    ) -> None:
        self.detail = detail
        super().__init__(message, source=source)

    def __str__(self) -> str:
        if self.detail:
            return f"{self.message}\n\nDetails: {self.detail}"
        return self.message


def parse_explain(
    source: str | Path | dict[str, Any] | list[Any],
    config: ParserConfig | None = None,
) -> ExplainOutput:
    """
    Parse PostgreSQL EXPLAIN (FORMAT JSON) output into typed models.
    
    Accepts multiple input formats for convenience:
    - File path (str or Path): Reads and parses the file
    - JSON string: Parses the string
    - Dict: Validates as the inner EXPLAIN object
    - List: Expects single-element array from EXPLAIN output
    
    Args:
        source: EXPLAIN JSON in any of the supported formats
        config: Parser configuration with resource limits. If None,
            uses DEFAULT_CONFIG (100MB, 50K nodes, depth 100).
        
    Returns:
        ExplainOutput: Validated and typed representation of the plan
        
    Raises:
        ParseError: If input cannot be parsed, validated, or exceeds limits
        
    Example:
        >>> output = parse_explain("explain.json")
        >>> output = parse_explain('{"Plan": {...}}')
        >>> output = parse_explain({"Plan": {...}})
        >>> for node in output.plan.iter_nodes():
        ...     print(node.node_type)
        
        # With custom limits
        >>> from querysense.parser.config import ParserConfig
        >>> config = ParserConfig(max_nodes=1000)
        >>> output = parse_explain("explain.json", config=config)
    """
    config = config or DEFAULT_CONFIG
    
    # Check file size before loading (if source is a file path)
    _check_file_size(source, config)
    
    data = _load_source(source)
    data = _unwrap_array(data)
    
    # Check depth before full validation (prevents stack overflow)
    _check_tree_depth(data, config)
    
    output = _validate_explain(data)
    
    # Check node count after parsing
    _check_node_count(output, config)
    
    return output


def parse_explain_file(path: str | Path) -> ExplainOutput:
    """
    Parse EXPLAIN JSON from a file.
    
    Convenience wrapper around parse_explain() for file inputs.
    Provides better error messages for file-specific issues.
    
    Args:
        path: Path to the JSON file
        
    Returns:
        ExplainOutput: Validated plan
        
    Raises:
        ParseError: If file cannot be read or parsed
    """
    filepath = Path(path)
    
    if not filepath.exists():
        raise ParseError(
            f"File not found: {filepath}",
            source="file_read",
        )
    
    if not filepath.is_file():
        raise ParseError(
            f"Path is not a file: {filepath}",
            source="file_read",
        )
    
    try:
        content = filepath.read_text(encoding="utf-8")
    except OSError as e:
        raise ParseError(
            f"Cannot read file: {filepath}",
            detail=str(e),
            source="file_read",
        ) from e
    
    if not content.strip():
        raise ParseError(
            f"File is empty: {filepath}",
            source="file_read",
        )
    
    return parse_explain(content)


def _load_source(source: str | Path | dict[str, Any] | list[Any]) -> dict[str, Any] | list[Any]:
    """
    Load source into a Python dict/list.
    
    Handles file paths, JSON strings, and already-parsed data.
    """
    # Already parsed
    if isinstance(source, (dict, list)):
        return source
    
    # File path
    if isinstance(source, Path):
        return _load_json_file(source)
    
    # String - could be file path or JSON
    if isinstance(source, str):
        # Check if it looks like JSON (starts with { or [)
        stripped = source.strip()
        if stripped.startswith(("{", "[")):
            return _parse_json_string(stripped)
        
        # Treat as file path
        return _load_json_file(Path(source))
    
    raise ParseError(
        f"Unsupported source type: {type(source).__name__}",
        detail="Expected file path, JSON string, dict, or list",
        source="type_check",
    )


def _load_json_file(path: Path) -> dict[str, Any] | list[Any]:
    """Load and parse a JSON file."""
    if not path.exists():
        raise ParseError(
            f"File not found: {path}",
            source="file_read",
        )
    
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ParseError(
            f"Cannot read file: {path}",
            detail=str(e),
            source="file_read",
        ) from e
    
    return _parse_json_string(content)


def _parse_json_string(content: str) -> dict[str, Any] | list[Any]:
    """Parse a JSON string."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ParseError(
            "Invalid JSON format",
            detail=f"Line {e.lineno}, column {e.colno}: {e.msg}",
            source="json_decode",
        ) from e
    
    if not isinstance(data, (dict, list)):
        raise ParseError(
            f"Expected JSON object or array, got {type(data).__name__}",
            source="json_decode",
        )
    
    return data


def _unwrap_array(data: dict[str, Any] | list[Any]) -> dict[str, Any]:
    """
    Unwrap the single-element array that PostgreSQL EXPLAIN returns.
    
    EXPLAIN (FORMAT JSON) returns: [{"Plan": {...}}]
    We want just: {"Plan": {...}}
    """
    if isinstance(data, dict):
        return data
    
    if not isinstance(data, list):
        raise ParseError(
            f"Expected array or object, got {type(data).__name__}",
            source="structure",
        )
    
    if len(data) == 0:
        raise ParseError(
            "Empty array - no EXPLAIN output found",
            detail="PostgreSQL EXPLAIN (FORMAT JSON) returns a single-element array",
            source="structure",
        )
    
    if len(data) > 1:
        raise ParseError(
            f"Expected single EXPLAIN output, got {len(data)} elements",
            detail="Did you concatenate multiple EXPLAIN outputs? Analyze one at a time.",
            source="structure",
        )
    
    inner = data[0]
    if not isinstance(inner, dict):
        raise ParseError(
            f"Expected object inside array, got {type(inner).__name__}",
            source="structure",
        )
    
    return inner


def _validate_explain(data: dict[str, Any]) -> ExplainOutput:
    """
    Validate the data against our Pydantic models.
    
    Converts Pydantic validation errors into user-friendly ParseErrors.
    """
    # Quick sanity check before full validation
    if "Plan" not in data:
        raise ParseError(
            "Missing 'Plan' field - this doesn't look like EXPLAIN output",
            detail="EXPLAIN (FORMAT JSON) output must contain a 'Plan' object",
            source="validation",
        )
    
    try:
        return ExplainOutput.model_validate(data)
    except ValidationError as e:
        # Convert Pydantic errors to readable format
        errors = []
        for error in e.errors():
            loc = " -> ".join(str(x) for x in error["loc"])
            msg = error["msg"]
            errors.append(f"  {loc}: {msg}")
        
        raise ParseError(
            "EXPLAIN output validation failed",
            detail="\n".join(errors),
            source="validation",
        ) from e


def _check_file_size(source: str | Path | dict[str, Any] | list[Any], config: ParserConfig) -> None:
    """Check file size before loading into memory."""
    path: Path | None = None
    
    if isinstance(source, Path):
        path = source
    elif isinstance(source, str) and not source.strip().startswith(("{", "[")):
        # Looks like a file path, not JSON
        path = Path(source)
    
    if path is not None and path.exists() and path.is_file():
        size_mb = path.stat().st_size / (1024 * 1024)
        if size_mb > config.max_file_size_mb:
            raise ParseError(
                f"File too large: {size_mb:.1f}MB (max {config.max_file_size_mb}MB)",
                detail="Use a smaller EXPLAIN output or increase max_file_size_mb in config",
                source="resource_limit",
            )


def _check_tree_depth(data: dict[str, Any], config: ParserConfig) -> None:
    """
    Check tree depth before full Pydantic validation.
    
    This prevents stack overflow during recursive model validation.
    """
    def measure_depth(node: dict[str, Any], current_depth: int) -> int:
        if current_depth > config.max_depth:
            return current_depth
        
        max_child_depth = current_depth
        plans = node.get("Plans", [])
        if isinstance(plans, list):
            for child in plans:
                if isinstance(child, dict):
                    child_depth = measure_depth(child, current_depth + 1)
                    max_child_depth = max(max_child_depth, child_depth)
        
        return max_child_depth
    
    plan = data.get("Plan", {})
    if isinstance(plan, dict):
        depth = measure_depth(plan, 1)
        if depth > config.max_depth:
            raise ParseError(
                f"Plan too deeply nested: depth {depth} (max {config.max_depth})",
                detail="This may indicate a pathological query or corrupted EXPLAIN output",
                source="resource_limit",
            )


def _check_node_count(output: ExplainOutput, config: ParserConfig) -> None:
    """Check total node count after parsing."""
    node_count = len(output.all_nodes)
    if node_count > config.max_nodes:
        raise ParseError(
            f"Plan too large: {node_count:,} nodes (max {config.max_nodes:,})",
            detail="Consider analyzing a simpler query or increasing max_nodes in config",
            source="resource_limit",
        )


def validate_has_analyze(output: ExplainOutput) -> None:
    """
    Verify that EXPLAIN ANALYZE data is present.
    
    Raises ParseError if only EXPLAIN (not ANALYZE) was run.
    Call this when your analysis requires actual execution data.
    
    Args:
        output: Parsed EXPLAIN output
        
    Raises:
        ParseError: If ANALYZE data is missing
    """
    if not output.has_analyze_data:
        raise ParseError(
            "Missing EXPLAIN ANALYZE data",
            detail=(
                "This looks like plain EXPLAIN output without ANALYZE.\n"
                "For accurate analysis, run: EXPLAIN (ANALYZE, FORMAT JSON) <your query>\n"
                "Note: ANALYZE actually executes the query, so be careful with mutations."
            ),
            source="validation",
        )

