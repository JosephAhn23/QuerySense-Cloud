"""
Query Parameter Extraction & Named Parameter Sets.

Based on pganalyze Query Tuning Workbooks: automatic parameter extraction
from query samples, conversion of positional ($1, $2) to named parameters,
and safe parameterized testing.

This extends QuerySense's existing TuningWorkbook (workbook.py) with the
parameter management that pganalyze added in their latest release.

Usage:
    from querysense.tuning.parameters import ParameterExtractor

    extractor = ParameterExtractor()
    params = extractor.extract_named("SELECT * FROM orders WHERE id = $1 AND status = $2")
    param_set = extractor.from_sample(
        query="SELECT * FROM orders WHERE id = 42 AND status = 'pending'",
        template="SELECT * FROM orders WHERE id = $1 AND status = $2",
    )
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class QueryParameter:
    """A single query parameter with type and source metadata."""

    name: str
    position: int          # Original $N position (1-based)
    value: Any = None
    pg_type: str = "text"
    source: str = "manual"  # manual, sample, inline

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "position": self.position,
            "value": self.value,
            "pg_type": self.pg_type,
            "source": self.source,
        }


@dataclass
class ParameterSet:
    """A named set of parameter values for a query."""

    id: str
    name: str
    parameters: list[QueryParameter] = field(default_factory=list)
    description: str = ""
    tags: list[str] = field(default_factory=list)

    def values_dict(self) -> dict[str, Any]:
        return {p.name: p.value for p in self.parameters}

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "parameters": [p.to_dict() for p in self.parameters],
            "description": self.description,
            "tags": self.tags,
        }


# Regex for positional placeholders ($1, $2, ...)
_POS_PARAM = re.compile(r"\$(\d+)")

# Patterns for extracting column context around a placeholder
_COL_CONTEXT = re.compile(
    r"(\w+)\s*(?:=|>=|<=|<>|!=|>|<|~~|LIKE|ILIKE|IN)\s*\$(\d+)",
    re.IGNORECASE,
)

# Patterns for inline literal values
_STRING_LITERAL = re.compile(r"(\w+)\s*=\s*'([^']*)'", re.IGNORECASE)
_INT_LITERAL = re.compile(r"(\w+)\s*=\s*(\d+)(?!\.\d)", re.IGNORECASE)
_FLOAT_LITERAL = re.compile(r"(\w+)\s*=\s*(\d+\.\d+)", re.IGNORECASE)
_BOOL_LITERAL = re.compile(r"(\w+)\s*=\s*(true|false)\b", re.IGNORECASE)


class ParameterExtractor:
    """
    Extract and name query parameters from SQL templates and samples.

    Converts positional parameters ($1, $2) to named parameters by
    analyzing surrounding column context in the query.
    """

    def extract_named(self, query: str) -> list[QueryParameter]:
        """
        Extract named parameters from a parameterized query.

        Analyzes the SQL context around each $N placeholder to infer
        a meaningful name from the column it's compared against.

        Returns a list of QueryParameter with names derived from context.
        """
        # Find all positional params
        positions = sorted(set(int(m.group(1)) for m in _POS_PARAM.finditer(query)))
        if not positions:
            return []

        # Map position -> column name from context
        col_map: dict[int, str] = {}
        for match in _COL_CONTEXT.finditer(query):
            col_name, pos_str = match.group(1), int(match.group(2))
            if pos_str not in col_map:
                col_map[pos_str] = col_name

        params: list[QueryParameter] = []
        for pos in positions:
            name = col_map.get(pos, f"param_{pos}")
            params.append(QueryParameter(name=name, position=pos))

        return params

    def normalize_query(self, query: str) -> tuple[str, list[QueryParameter]]:
        """
        Convert positional parameters to named parameters.

        Returns (normalized_query, parameters).
        E.g., "WHERE id = $1" -> "WHERE id = $id", [QueryParameter(name="id", ...)]
        """
        params = self.extract_named(query)
        normalized = query

        # Replace in reverse order to avoid position shifts
        for param in sorted(params, key=lambda p: -p.position):
            normalized = normalized.replace(f"${param.position}", f"${param.name}")

        return normalized, params

    def from_sample(
        self,
        query: str,
        template: str | None = None,
    ) -> ParameterSet:
        """
        Extract a ParameterSet from a concrete query sample.

        If a template is provided (with $N placeholders), matches literal
        values in the sample to template positions. Otherwise, extracts
        inline literals directly.
        """
        if template:
            return self._match_template(query, template)
        return self._extract_inline(query)

    def from_samples(
        self,
        samples: list[dict[str, Any]],
        template: str | None = None,
    ) -> list[ParameterSet]:
        """
        Extract parameter sets from multiple query samples.

        Each sample dict should have at least a 'query' key,
        and optionally 'parameters' (pre-extracted) or 'timestamp'.
        """
        results: list[ParameterSet] = []
        for i, sample in enumerate(samples):
            if "parameters" in sample and isinstance(sample["parameters"], dict):
                # Pre-extracted parameters
                ps = self._build_param_set(
                    name=f"Sample {i + 1}",
                    values=sample["parameters"],
                    source="sample",
                    description=f"From sample at {sample.get('timestamp', 'unknown')}",
                )
                results.append(ps)
            elif "query" in sample:
                ps = self.from_sample(sample["query"], template=template)
                ps.name = f"Sample {i + 1}"
                results.append(ps)
        return results

    def build_query(
        self,
        template: str,
        param_set: ParameterSet,
    ) -> str:
        """
        Build a concrete query from a template and parameter values.

        Replaces $name or $N with properly typed and quoted values.
        """
        query = template
        for param in param_set.parameters:
            placeholder_name = f"${param.name}"
            placeholder_pos = f"${param.position}"
            formatted = self._format_value(param.value, param.pg_type)

            if placeholder_name in query:
                query = query.replace(placeholder_name, formatted)
            elif placeholder_pos in query:
                query = query.replace(placeholder_pos, formatted)

        return query

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _match_template(self, sample: str, template: str) -> ParameterSet:
        """Match a concrete query against a template to extract values."""
        params = self.extract_named(template)
        values = self._extract_inline_values(sample)

        for param in params:
            if param.name in values:
                param.value = values[param.name]
                param.pg_type = self._infer_pg_type(param.value)
                param.source = "sample"

        param_id = hashlib.sha256(sample.encode()).hexdigest()[:8]
        return ParameterSet(
            id=param_id,
            name="Extracted",
            parameters=params,
            description=f"Matched from: {sample[:80]}",
        )

    def _extract_inline(self, query: str) -> ParameterSet:
        """Extract inline literal values from a concrete query."""
        values = self._extract_inline_values(query)
        params = [
            QueryParameter(
                name=name,
                position=i + 1,
                value=val,
                pg_type=self._infer_pg_type(val),
                source="inline",
            )
            for i, (name, val) in enumerate(values.items())
        ]
        param_id = hashlib.sha256(query.encode()).hexdigest()[:8]
        return ParameterSet(
            id=param_id,
            name="Inline",
            parameters=params,
            description=f"Extracted from: {query[:80]}",
        )

    @staticmethod
    def _extract_inline_values(query: str) -> dict[str, Any]:
        """Extract literal values from WHERE clauses."""
        values: dict[str, Any] = {}
        for match in _BOOL_LITERAL.finditer(query):
            values[match.group(1)] = match.group(2).lower() == "true"
        for match in _FLOAT_LITERAL.finditer(query):
            values[match.group(1)] = float(match.group(2))
        for match in _INT_LITERAL.finditer(query):
            if match.group(1) not in values:
                values[match.group(1)] = int(match.group(2))
        for match in _STRING_LITERAL.finditer(query):
            values[match.group(1)] = match.group(2)
        return values

    def _build_param_set(
        self,
        name: str,
        values: dict[str, Any],
        source: str = "manual",
        description: str = "",
    ) -> ParameterSet:
        params = [
            QueryParameter(
                name=k,
                position=i + 1,
                value=v,
                pg_type=self._infer_pg_type(v),
                source=source,
            )
            for i, (k, v) in enumerate(values.items())
        ]
        param_id = hashlib.sha256(
            json.dumps(values, default=str, sort_keys=True).encode()
        ).hexdigest()[:8]
        return ParameterSet(id=param_id, name=name, parameters=params, description=description)

    @staticmethod
    def _infer_pg_type(value: Any) -> str:
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int):
            return "integer"
        if isinstance(value, float):
            return "numeric"
        if isinstance(value, (list, dict)):
            return "jsonb"
        return "text"

    @staticmethod
    def _format_value(value: Any, pg_type: str) -> str:
        if value is None:
            return "NULL"
        if pg_type in ("text", "varchar", "date", "timestamp", "timestamptz"):
            escaped = str(value).replace("'", "''")
            return f"'{escaped}'"
        if pg_type == "boolean":
            return "TRUE" if value else "FALSE"
        if pg_type == "jsonb":
            return f"'{json.dumps(value)}'::jsonb"
        return str(value)
