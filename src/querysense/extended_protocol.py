"""
Extended Query Protocol Parser — handle parameterized queries ($1, $2, ...).

PostgreSQL's extended query protocol sends parameter values separately from
the query text. pg_stat_statements only shows the template with $1/$2.
This module:
1. Normalizes parameterized queries for fingerprinting
2. Generates safe sample values based on pg_type for EXPLAIN
3. Detects parameter types from pg_prepared_statements
4. Provides parameter-aware EXPLAIN execution

Matches pganalyze's "Supports query parameters sent separately".

Usage:
    from querysense.extended_protocol import ExtendedProtocolParser

    parser = ExtendedProtocolParser()
    pq = parser.normalize("SELECT * FROM users WHERE id = $1 AND name = $2")
    explain_sql = await parser.prepare_for_explain(sql, conn)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_PARAM_RE = re.compile(r"\$(\d+)")

_TYPE_SAMPLES: dict[str, str] = {
    "int2": "1",
    "int4": "1",
    "int8": "1",
    "float4": "1.0",
    "float8": "1.0",
    "numeric": "1.0",
    "text": "'sample_text'",
    "varchar": "'sample_text'",
    "char": "'x'",
    "bpchar": "'x'",
    "bool": "true",
    "boolean": "true",
    "date": "'2024-01-01'",
    "timestamp": "'2024-01-01 00:00:00'",
    "timestamptz": "'2024-01-01 00:00:00+00'",
    "time": "'12:00:00'",
    "timetz": "'12:00:00+00'",
    "interval": "'1 hour'",
    "uuid": "'12345678-1234-1234-1234-123456789012'",
    "jsonb": "'{}'::jsonb",
    "json": "'{}'::json",
    "inet": "'127.0.0.1'",
    "cidr": "'10.0.0.0/8'",
    "macaddr": "'00:00:00:00:00:00'",
    "bytea": "'\\x00'::bytea",
    "oid": "1",
    "regclass": "'pg_class'::regclass",
    "name": "'sample'",
    "int4range": "'[1,10)'::int4range",
    "tstzrange": "'[2024-01-01,2024-01-02)'::tstzrange",
    "point": "'(0,0)'",
    "array": "ARRAY[1]",
    "int4[]": "ARRAY[1]",
    "text[]": "ARRAY['a']",
}


@dataclass
class ParameterizedQuery:
    """A query with its parameter metadata."""

    original: str
    normalized: str
    param_positions: list[int] = field(default_factory=list)
    param_types: dict[int, str] = field(default_factory=dict)
    param_samples: dict[int, str] = field(default_factory=dict)

    @property
    def param_count(self) -> int:
        return len(self.param_positions)

    @property
    def has_params(self) -> bool:
        return self.param_count > 0

    @property
    def explain_ready_sql(self) -> str:
        """SQL with sample values substituted for $N placeholders."""
        result = self.original
        for pos in sorted(self.param_positions, reverse=True):
            sample = self.param_samples.get(pos, "NULL")
            result = result.replace(f"${pos}", sample)
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "original": self.original,
            "normalized": self.normalized,
            "param_count": self.param_count,
            "param_positions": self.param_positions,
            "param_types": {str(k): v for k, v in self.param_types.items()},
            "param_samples": {str(k): v for k, v in self.param_samples.items()},
            "explain_ready_sql": self.explain_ready_sql,
        }


class ExtendedProtocolParser:
    """
    Parse and normalize queries using PostgreSQL's extended query protocol.

    Handles $1/$2 positional parameters, type detection, and sample value
    generation for EXPLAIN execution.
    """

    def normalize(self, query: str) -> ParameterizedQuery:
        """
        Normalize a parameterized query.

        Extracts parameter positions and replaces $N with ? for fingerprinting.
        """
        positions = sorted({int(m) for m in _PARAM_RE.findall(query)})
        normalized = _PARAM_RE.sub("?", query)

        pq = ParameterizedQuery(
            original=query,
            normalized=normalized,
            param_positions=positions,
        )

        for pos in positions:
            pq.param_samples[pos] = "NULL"

        return pq

    async def detect_types(
        self,
        query: str,
        conn: Any,
    ) -> ParameterizedQuery:
        """
        Detect parameter types by preparing the statement on the server.

        Uses pg_prepared_statements to discover $N types.
        """
        pq = self.normalize(query)
        if not pq.has_params:
            return pq

        stmt_name = f"_qs_typecheck_{hash(query) % 99999}"

        try:
            await conn.execute(f"PREPARE {stmt_name} AS {query}")

            rows = await conn.fetch(
                "SELECT parameter_types FROM pg_prepared_statements "
                "WHERE name = $1",
                stmt_name,
            )

            if rows and rows[0]["parameter_types"]:
                types = rows[0]["parameter_types"]
                if isinstance(types, str):
                    type_list = [t.strip() for t in types.strip("{}").split(",")]
                elif isinstance(types, (list, tuple)):
                    type_list = list(types)
                else:
                    type_list = []

                for i, pg_type in enumerate(type_list):
                    pos = i + 1
                    if pos in pq.param_positions:
                        pq.param_types[pos] = pg_type
                        pq.param_samples[pos] = self._sample_for_type(pg_type)

        except Exception:
            pass
        finally:
            try:
                await conn.execute(f"DEALLOCATE {stmt_name}")
            except Exception:
                pass

        return pq

    async def prepare_for_explain(
        self,
        query: str,
        conn: Any,
    ) -> str:
        """
        Prepare a parameterized query for EXPLAIN by substituting sample values.

        Detects types live from the database when possible, falls back to
        type-agnostic samples.
        """
        pq = await self.detect_types(query, conn)
        return pq.explain_ready_sql

    def substitute_samples(
        self,
        query: str,
        type_hints: dict[int, str] | None = None,
    ) -> str:
        """
        Offline substitution when no database connection is available.

        Provide type_hints as {1: "int4", 2: "text"} or let it use NULL.
        """
        pq = self.normalize(query)

        if type_hints:
            for pos, pg_type in type_hints.items():
                if pos in pq.param_positions:
                    pq.param_types[pos] = pg_type
                    pq.param_samples[pos] = self._sample_for_type(pg_type)

        return pq.explain_ready_sql

    @staticmethod
    def _sample_for_type(pg_type: str) -> str:
        """Generate a safe sample value for a PostgreSQL type."""
        pg_type = pg_type.lower().strip()

        if pg_type in _TYPE_SAMPLES:
            return _TYPE_SAMPLES[pg_type]

        if pg_type.endswith("[]"):
            base = pg_type[:-2]
            inner = _TYPE_SAMPLES.get(base, "NULL")
            return f"ARRAY[{inner}]"

        for prefix in ("int", "float", "numeric", "decimal"):
            if pg_type.startswith(prefix):
                return "1"

        for prefix in ("varchar", "char", "text", "name"):
            if pg_type.startswith(prefix):
                return "'sample'"

        if "time" in pg_type or "date" in pg_type:
            return "'2024-01-01 00:00:00'"

        return "NULL"
