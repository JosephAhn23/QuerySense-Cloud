"""
Oracle-to-PostgreSQL Hint Translator.

Translates Oracle optimizer hints to pg_hint_plan equivalents with
confidence scores and migration guidance.  Based on the comprehensive
hint mapping from pganalyze's Oracle migration blog posts.

Usage:
    from querysense.migration.hint_translator import OracleHintTranslator

    translator = OracleHintTranslator()
    result = translator.translate_query(
        "SELECT /*+ FULL(t) USE_HASH(t u) */ * FROM orders t JOIN users u ..."
    )
    print(result["translated_query"])
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class HintType(str, Enum):
    ACCESS_PATH = "access_path"
    JOIN_OPERATION = "join_operation"
    JOIN_ORDER = "join_order"
    PARALLEL = "parallel"
    QUERY_TRANSFORM = "query_transform"
    OTHER = "other"


class Confidence(str, Enum):
    HIGH = "high"      # Direct semantic equivalent exists
    MEDIUM = "medium"  # Approximate equivalent, may behave differently
    LOW = "low"        # Workaround only, manual review needed
    NONE = "none"      # No PostgreSQL equivalent


@dataclass
class HintTranslation:
    """Result of translating a single Oracle hint."""

    original: str
    pg_hint: str | None
    hint_type: HintType = HintType.OTHER
    confidence: Confidence = Confidence.NONE
    notes: str = ""
    alternatives: list[str] = field(default_factory=list)
    status: str = "translated"  # translated | unsupported | unknown | error

    def to_dict(self) -> dict[str, Any]:
        return {
            "original": self.original,
            "pg_hint": self.pg_hint,
            "hint_type": self.hint_type.value,
            "confidence": self.confidence.value,
            "notes": self.notes,
            "alternatives": self.alternatives,
            "status": self.status,
        }


@dataclass
class QueryTranslation:
    """Result of translating all hints in a query."""

    original_query: str
    translated_query: str
    hints: list[HintTranslation] = field(default_factory=list)
    total: int = 0
    high_confidence: int = 0
    medium_confidence: int = 0
    low_confidence: int = 0
    unsupported: int = 0
    coverage_pct: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_query": self.original_query,
            "translated_query": self.translated_query,
            "hints": [h.to_dict() for h in self.hints],
            "summary": {
                "total": self.total,
                "high_confidence": self.high_confidence,
                "medium_confidence": self.medium_confidence,
                "low_confidence": self.low_confidence,
                "unsupported": self.unsupported,
                "coverage_pct": self.coverage_pct,
            },
        }


# Hints that have no PostgreSQL equivalent at all
_UNSUPPORTED_HINTS = frozenset({
    "UNNEST", "NO_UNNEST",
    "MERGE", "NO_MERGE",
    "PUSH_SUBQ", "NO_PUSH_SUBQ",
    "STAR_TRANSFORMATION", "NO_STAR_TRANSFORMATION",
    "FACT", "NO_FACT",
    "RESULT_CACHE", "NO_RESULT_CACHE",
    "DYNAMIC_SAMPLING",
    "QB_NAME",
    "PUSH_PRED", "NO_PUSH_PRED",
    "USE_CONCAT",
    "NO_QUERY_TRANSFORMATION",
})

# Alternatives to suggest for unsupported hints
_ALTERNATIVES: dict[str, list[str]] = {
    "USE_CONCAT": [
        "Manually rewrite query using UNION ALL",
        "See: https://pganalyze.com/blog/or-to-any-postgresql",
    ],
    "RESULT_CACHE": [
        "Implement application-level caching (Redis, memcached)",
        "Use materialized views for stable datasets",
    ],
    "NO_RESULT_CACHE": [
        "PostgreSQL has no result cache to disable",
    ],
    "DYNAMIC_SAMPLING": [
        "Ensure regular ANALYZE runs",
        "Increase default_statistics_target for columns",
    ],
    "UNNEST": [
        "Use NOT MATERIALIZED CTE: WITH cte AS NOT MATERIALIZED (...)",
    ],
    "NO_UNNEST": [
        "Use MATERIALIZED CTE: WITH cte AS MATERIALIZED (...)",
    ],
}

# Regex to extract the Oracle hint block: /*+ ... */
_HINT_BLOCK_RE = re.compile(r"/\*\+\s*(.*?)\s*\*/", re.DOTALL)


class OracleHintTranslator:
    """
    Translate Oracle optimizer hints to pg_hint_plan syntax.

    Covers access-path, join-operation, join-order, and parallel hints
    with high/medium/low/none confidence scoring.
    """

    # ── Individual hint translators ───────────────────────────────────

    def translate_hint(self, oracle_hint: str) -> HintTranslation:
        """Translate a single Oracle hint string."""
        name, args = self._parse_hint(oracle_hint)

        if name in _UNSUPPORTED_HINTS:
            return HintTranslation(
                original=oracle_hint,
                pg_hint=None,
                status="unsupported",
                notes=f"No PostgreSQL equivalent for {name}",
                alternatives=_ALTERNATIVES.get(name, ["Consider query restructuring"]),
            )

        handler = self._HANDLERS.get(name)
        if handler is None:
            return HintTranslation(
                original=oracle_hint,
                pg_hint=None,
                status="unknown",
                notes=f"Unknown Oracle hint: {name}",
            )

        try:
            return handler(self, args, oracle_hint)
        except Exception as exc:  # noqa: BLE001
            return HintTranslation(
                original=oracle_hint,
                pg_hint=None,
                status="error",
                notes=str(exc),
            )

    # ── Full-query translation ────────────────────────────────────────

    def translate_query(self, oracle_query: str) -> QueryTranslation:
        """Translate all hints in an Oracle query to pg_hint_plan."""
        match = _HINT_BLOCK_RE.search(oracle_query)
        if not match:
            return QueryTranslation(
                original_query=oracle_query,
                translated_query=oracle_query,
            )

        block = match.group(0)
        content = match.group(1)
        individual = self._split_hints(content)

        translations: list[HintTranslation] = []
        pg_parts: list[str] = []

        for hint_str in individual:
            tr = self.translate_hint(hint_str)
            translations.append(tr)
            if tr.pg_hint:
                pg_parts.append(tr.pg_hint)

        if pg_parts:
            pg_block = f"/*+ {' '.join(pg_parts)} */"
            translated = oracle_query.replace(block, pg_block)
        else:
            translated = oracle_query.replace(block, "").strip()
            translated = re.sub(r"\s{2,}", " ", translated)

        total = len(translations)
        high = sum(1 for t in translations if t.confidence == Confidence.HIGH)
        med = sum(1 for t in translations if t.confidence == Confidence.MEDIUM)
        low = sum(1 for t in translations if t.confidence == Confidence.LOW)
        unsup = sum(1 for t in translations if t.status == "unsupported")

        return QueryTranslation(
            original_query=oracle_query,
            translated_query=translated,
            hints=translations,
            total=total,
            high_confidence=high,
            medium_confidence=med,
            low_confidence=low,
            unsupported=unsup,
            coverage_pct=round((total - unsup) / total * 100, 1) if total else 0.0,
        )

    # ── Hint parsing helpers ──────────────────────────────────────────

    @staticmethod
    def _parse_hint(hint: str) -> tuple[str, list[str]]:
        hint = hint.strip()
        paren = hint.find("(")
        if paren == -1:
            return hint.upper(), []
        name = hint[:paren].strip().upper()
        args_str = hint[paren + 1 : hint.rfind(")")]
        args = [a.strip() for a in OracleHintTranslator._split_args(args_str) if a.strip()]
        return name, args

    @staticmethod
    def _split_args(args_str: str) -> list[str]:
        args: list[str] = []
        cur: list[str] = []
        depth = 0
        for ch in args_str:
            if ch == "(":
                depth += 1
                cur.append(ch)
            elif ch == ")":
                depth -= 1
                cur.append(ch)
            elif ch in (",", " ") and depth == 0:
                token = "".join(cur).strip()
                if token:
                    args.append(token)
                cur = []
            else:
                cur.append(ch)
        token = "".join(cur).strip()
        if token:
            args.append(token)
        return args

    @staticmethod
    def _split_hints(content: str) -> list[str]:
        """Split the inner content of a hint block into individual hints.

        Handles both parenthesized hints like ``FULL(t)`` and bare keywords
        like ``ORDERED``.  Two bare keywords separated by spaces are distinct
        hints; a space *inside* parentheses is part of the argument list.
        """
        hints: list[str] = []
        cur: list[str] = []
        depth = 0
        for ch in content:
            if ch == "(":
                depth += 1
                cur.append(ch)
            elif ch == ")":
                depth -= 1
                cur.append(ch)
                if depth == 0:
                    hints.append("".join(cur).strip())
                    cur = []
            elif ch.isspace() and depth == 0:
                token = "".join(cur).strip()
                if token:
                    hints.append(token)
                cur = []
            else:
                cur.append(ch)
        token = "".join(cur).strip()
        if token:
            hints.append(token)
        return hints

    # ── Per-hint handler methods (keyed by uppercase Oracle hint name) ─

    def _handle_full(self, args: list[str], raw: str) -> HintTranslation:
        tbl = args[0] if args else "?"
        return HintTranslation(
            original=raw,
            pg_hint=f"SeqScan({tbl})",
            hint_type=HintType.ACCESS_PATH,
            confidence=Confidence.HIGH,
            notes="Sequential scan (full table scan)",
        )

    def _handle_index(self, args: list[str], raw: str) -> HintTranslation:
        pg = f"IndexScan({' '.join(args)})" if args else "IndexScan(?)"
        return HintTranslation(
            original=raw,
            pg_hint=pg,
            hint_type=HintType.ACCESS_PATH,
            confidence=Confidence.HIGH,
            notes="Index scan; use IndexOnlyScan or BitmapScan if more specific",
        )

    def _handle_index_ffs(self, args: list[str], raw: str) -> HintTranslation:
        pg = f"IndexOnlyScan({' '.join(args)})" if args else "IndexOnlyScan(?)"
        return HintTranslation(
            original=raw,
            pg_hint=pg,
            hint_type=HintType.ACCESS_PATH,
            confidence=Confidence.MEDIUM,
            notes="Approximate: IndexOnlyScan may still access heap for visibility",
        )

    def _handle_index_desc(self, args: list[str], raw: str) -> HintTranslation:
        tbl = args[0] if args else "?"
        return HintTranslation(
            original=raw,
            pg_hint=None,
            hint_type=HintType.ACCESS_PATH,
            confidence=Confidence.LOW,
            notes="No direct equivalent; add ORDER BY ... DESC to the query",
            alternatives=[
                f"Add ORDER BY ... DESC and IndexScan({tbl}) hint",
            ],
            status="unsupported",
        )

    def _handle_no_index(self, args: list[str], raw: str) -> HintTranslation:
        return HintTranslation(
            original=raw,
            pg_hint=None,
            hint_type=HintType.ACCESS_PATH,
            confidence=Confidence.NONE,
            notes="Cannot disallow individual indexes in pg_hint_plan",
            status="unsupported",
        )

    def _handle_use_nl(self, args: list[str], raw: str) -> HintTranslation:
        return HintTranslation(
            original=raw,
            pg_hint=f"NestLoop({' '.join(args)})" if args else "NestLoop(?)",
            hint_type=HintType.JOIN_OPERATION,
            confidence=Confidence.HIGH,
            notes="Nested loop join",
        )

    def _handle_use_hash(self, args: list[str], raw: str) -> HintTranslation:
        return HintTranslation(
            original=raw,
            pg_hint=f"HashJoin({' '.join(args)})" if args else "HashJoin(?)",
            hint_type=HintType.JOIN_OPERATION,
            confidence=Confidence.HIGH,
            notes="Hash join",
        )

    def _handle_use_merge(self, args: list[str], raw: str) -> HintTranslation:
        return HintTranslation(
            original=raw,
            pg_hint=f"MergeJoin({' '.join(args)})" if args else "MergeJoin(?)",
            hint_type=HintType.JOIN_OPERATION,
            confidence=Confidence.HIGH,
            notes="Merge join",
        )

    def _handle_no_use_nl(self, args: list[str], raw: str) -> HintTranslation:
        return HintTranslation(
            original=raw,
            pg_hint=f"NoNestLoop({' '.join(args)})" if args else "NoNestLoop(?)",
            hint_type=HintType.JOIN_OPERATION,
            confidence=Confidence.HIGH,
            notes="Prevents nested loop join",
        )

    def _handle_no_use_hash(self, args: list[str], raw: str) -> HintTranslation:
        return HintTranslation(
            original=raw,
            pg_hint=f"NoHashJoin({' '.join(args)})" if args else "NoHashJoin(?)",
            hint_type=HintType.JOIN_OPERATION,
            confidence=Confidence.HIGH,
            notes="Prevents hash join",
        )

    def _handle_no_use_merge(self, args: list[str], raw: str) -> HintTranslation:
        return HintTranslation(
            original=raw,
            pg_hint=f"NoMergeJoin({' '.join(args)})" if args else "NoMergeJoin(?)",
            hint_type=HintType.JOIN_OPERATION,
            confidence=Confidence.HIGH,
            notes="Prevents merge join",
        )

    def _handle_ordered(self, args: list[str], raw: str) -> HintTranslation:
        return HintTranslation(
            original=raw,
            pg_hint="Set(join_collapse_limit 1)",
            hint_type=HintType.JOIN_ORDER,
            confidence=Confidence.HIGH,
            notes="Forces join in FROM clause order",
        )

    def _handle_leading(self, args: list[str], raw: str) -> HintTranslation:
        return HintTranslation(
            original=raw,
            pg_hint=f"Leading({' '.join(args)})" if args else "Leading(?)",
            hint_type=HintType.JOIN_ORDER,
            confidence=Confidence.HIGH,
            notes="Specifies join order",
        )

    def _handle_parallel(self, args: list[str], raw: str) -> HintTranslation:
        if len(args) >= 2:
            try:
                degree = int(args[1])
                pg = f"Parallel({args[0]} {degree} hard)"
            except ValueError:
                pg = f"Parallel({args[0]} {args[1]})"
        elif args:
            pg = f"Parallel({args[0]})"
        else:
            pg = "Parallel(?)"

        return HintTranslation(
            original=raw,
            pg_hint=pg,
            hint_type=HintType.PARALLEL,
            confidence=Confidence.HIGH,
            notes="Parallel execution; 'hard' forces the degree",
        )

    def _handle_no_parallel(self, args: list[str], raw: str) -> HintTranslation:
        tbl = args[0] if args else "?"
        return HintTranslation(
            original=raw,
            pg_hint=f"Parallel({tbl} 0)",
            hint_type=HintType.PARALLEL,
            confidence=Confidence.HIGH,
            notes="Disables parallel execution",
        )

    def _handle_opt_param(self, args: list[str], raw: str) -> HintTranslation:
        if len(args) >= 2:
            pg = f"Set({args[0]} {args[1]})"
        else:
            pg = None
        return HintTranslation(
            original=raw,
            pg_hint=pg,
            hint_type=HintType.OTHER,
            confidence=Confidence.HIGH if pg else Confidence.NONE,
            notes="Sets PostgreSQL GUC parameter" if pg else "Missing arguments",
            status="translated" if pg else "error",
        )

    def _handle_use_nl_with_index(self, args: list[str], raw: str) -> HintTranslation:
        if len(args) >= 2:
            pg = (
                f"NestLoop({args[0]} ?) "
                f"IndexScan({args[0]} {args[1]})"
            )
        else:
            pg = None
        return HintTranslation(
            original=raw,
            pg_hint=pg,
            hint_type=HintType.JOIN_OPERATION,
            confidence=Confidence.MEDIUM,
            notes="Combination of NestLoop + IndexScan; may need Leading hint too",
            status="translated" if pg else "error",
        )

    def _handle_index_join(self, _args: list[str], raw: str) -> HintTranslation:
        return HintTranslation(
            original=raw,
            pg_hint=None,
            hint_type=HintType.ACCESS_PATH,
            confidence=Confidence.NONE,
            notes="PostgreSQL has no direct 'index join' concept",
            status="unsupported",
        )

    # Registry: Oracle hint name → handler method
    _HANDLERS: dict[str, Any] = {
        "FULL": _handle_full,
        "INDEX": _handle_index,
        "INDEX_FFS": _handle_index_ffs,
        "INDEX_DESC": _handle_index_desc,
        "NO_INDEX": _handle_no_index,
        "INDEX_JOIN": _handle_index_join,
        "USE_NL": _handle_use_nl,
        "USE_HASH": _handle_use_hash,
        "USE_MERGE": _handle_use_merge,
        "USE_NL_WITH_INDEX": _handle_use_nl_with_index,
        "NO_USE_NL": _handle_no_use_nl,
        "NO_USE_HASH": _handle_no_use_hash,
        "NO_USE_MERGE": _handle_no_use_merge,
        "ORDERED": _handle_ordered,
        "LEADING": _handle_leading,
        "PARALLEL": _handle_parallel,
        "NO_PARALLEL": _handle_no_parallel,
        "OPT_PARAM": _handle_opt_param,
    }
