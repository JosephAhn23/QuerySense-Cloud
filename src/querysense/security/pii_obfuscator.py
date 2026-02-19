"""
PII Obfuscation Engine — configurable masking for EXPLAIN plans and logs.

Matches pganalyze's "PII obfuscation for sensitive log data" but goes further:
- Configurable patterns (email, SSN, credit card, phone, IP, custom)
- Deterministic hashing (same input → same hash) for correlation
- Context-aware masking (protects column names from false positives)
- Plan-level recursive obfuscation (handles nested EXPLAIN JSON)
- Query-level obfuscation (masks string literals, not structure)

Usage:
    from querysense.security.pii_obfuscator import PIIObfuscator

    obfuscator = PIIObfuscator()
    safe_plan = obfuscator.obfuscate_plan(plan_dict)
    safe_query = obfuscator.obfuscate_query("SELECT * FROM users WHERE email = 'john@example.com'")
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Pattern


@dataclass
class PIIPattern:
    """A named PII detection pattern with its obfuscation rule."""

    name: str
    pattern: Pattern[str]
    replacement: str = ""
    enabled: bool = True

    def obfuscate(self, text: str, salt: str = "", deterministic: bool = True) -> str:
        if not self.enabled:
            return text

        if deterministic and salt:

            def _hash_match(match: re.Match[str]) -> str:
                value = match.group(0)
                hashed = hashlib.sha256(
                    (value + salt).encode()
                ).hexdigest()[:8]
                return f"[{self.name}:{hashed}]"

            return self.pattern.sub(_hash_match, text)

        repl = self.replacement or f"[{self.name.upper()}]"
        return self.pattern.sub(repl, text)


@dataclass
class ObfuscationReport:
    """Summary of what was obfuscated."""

    total_matches: int = 0
    matches_by_type: dict[str, int] = field(default_factory=dict)
    fields_processed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_matches": self.total_matches,
            "matches_by_type": self.matches_by_type,
            "fields_processed": self.fields_processed,
        }


_BUILTIN_PATTERNS: list[PIIPattern] = [
    PIIPattern(
        name="email",
        pattern=re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        replacement="[EMAIL]",
    ),
    PIIPattern(
        name="credit_card",
        pattern=re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
        replacement="[CREDIT_CARD]",
    ),
    PIIPattern(
        name="ssn",
        pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        replacement="[SSN]",
    ),
    PIIPattern(
        name="phone_us",
        pattern=re.compile(r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        replacement="[PHONE]",
    ),
    PIIPattern(
        name="ipv4",
        pattern=re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        replacement="[IP]",
    ),
    PIIPattern(
        name="ipv6",
        pattern=re.compile(
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        ),
        replacement="[IPv6]",
    ),
    PIIPattern(
        name="uuid",
        pattern=re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        replacement="[UUID]",
    ),
]


class PIIObfuscator:
    """
    Configurable PII masking for EXPLAIN plans, queries, and logs.

    Supports:
    - Built-in patterns (email, SSN, credit card, phone, IP, UUID)
    - Custom regex patterns via config
    - Deterministic hashing for cross-reference without exposing raw data
    - Context-aware masking that preserves SQL structure
    """

    def __init__(
        self,
        salt: str = "",
        deterministic: bool = True,
        custom_patterns: list[dict[str, str]] | None = None,
        disabled_patterns: set[str] | None = None,
        protect_column_names: bool = True,
    ) -> None:
        self.salt = salt
        self.deterministic = deterministic
        self.protect_column_names = protect_column_names
        self._known_columns: set[str] = set()
        self._known_tables: set[str] = set()

        self.patterns: list[PIIPattern] = []
        disabled = disabled_patterns or set()

        for p in _BUILTIN_PATTERNS:
            cp = PIIPattern(
                name=p.name,
                pattern=p.pattern,
                replacement=p.replacement,
                enabled=p.name not in disabled,
            )
            self.patterns.append(cp)

        if custom_patterns:
            for cp_dict in custom_patterns:
                self.patterns.append(PIIPattern(
                    name=cp_dict["name"],
                    pattern=re.compile(cp_dict["pattern"]),
                    replacement=cp_dict.get("replacement", f"[{cp_dict['name'].upper()}]"),
                    enabled=True,
                ))

    async def load_schema_info(self, conn: Any) -> None:
        """Load table/column names for context-aware obfuscation."""
        try:
            rows = await conn.fetch(
                "SELECT table_name, column_name "
                "FROM information_schema.columns "
                "WHERE table_schema NOT IN ('pg_catalog', 'information_schema')"
            )
            for row in rows:
                self._known_tables.add(row["table_name"])
                self._known_columns.add(row["column_name"])
        except Exception:
            pass

    # ── Plan obfuscation ─────────────────────────────────────────────

    def obfuscate_plan(self, plan: Any) -> Any:
        """Recursively obfuscate PII in an EXPLAIN plan (dict/list/str)."""
        if isinstance(plan, dict):
            return {k: self.obfuscate_plan(v) for k, v in plan.items()}
        if isinstance(plan, list):
            return [self.obfuscate_plan(item) for item in plan]
        if isinstance(plan, str):
            return self._obfuscate_text(plan)
        return plan

    def obfuscate_plan_with_report(self, plan: Any) -> tuple[Any, ObfuscationReport]:
        """Obfuscate plan and return a report of what was masked."""
        report = ObfuscationReport()
        result = self._obfuscate_plan_tracked(plan, report)
        return result, report

    # ── Query obfuscation ────────────────────────────────────────────

    def obfuscate_query(self, query: str) -> str:
        """
        Obfuscate PII in a SQL query while preserving SQL structure.

        Column names and table names from the schema are protected from
        false-positive matches.
        """
        protected: dict[str, str] = {}

        if self.protect_column_names:
            counter = 0
            for name in self._known_columns | self._known_tables:
                if name in query:
                    placeholder = f"__QS_PROTECT_{counter}__"
                    protected[placeholder] = name
                    query = query.replace(name, placeholder)
                    counter += 1

        query = self._obfuscate_text(query)

        for placeholder, name in protected.items():
            query = query.replace(placeholder, name)

        return query

    def obfuscate_log_line(self, line: str) -> str:
        """Obfuscate PII in a log line."""
        return self._obfuscate_text(line)

    # ── Batch operations ─────────────────────────────────────────────

    def obfuscate_queries(self, queries: list[str]) -> list[str]:
        """Obfuscate a batch of queries."""
        return [self.obfuscate_query(q) for q in queries]

    def obfuscate_log_lines(self, lines: list[str]) -> list[str]:
        """Obfuscate a batch of log lines."""
        return [self.obfuscate_log_line(line) for line in lines]

    # ── Internal ─────────────────────────────────────────────────────

    def _obfuscate_text(self, text: str) -> str:
        result = text
        for p in self.patterns:
            result = p.obfuscate(result, salt=self.salt, deterministic=self.deterministic)
        return result

    def _obfuscate_plan_tracked(self, plan: Any, report: ObfuscationReport) -> Any:
        if isinstance(plan, dict):
            return {k: self._obfuscate_plan_tracked(v, report) for k, v in plan.items()}
        if isinstance(plan, list):
            return [self._obfuscate_plan_tracked(item, report) for item in plan]
        if isinstance(plan, str):
            report.fields_processed += 1
            original = plan
            result = self._obfuscate_text(plan)
            if result != original:
                for p in self.patterns:
                    matches = p.pattern.findall(original)
                    if matches:
                        report.total_matches += len(matches)
                        report.matches_by_type[p.name] = (
                            report.matches_by_type.get(p.name, 0) + len(matches)
                        )
            return result
        return plan
