"""
Natural Language Query Explainer — "Why is this query slow?" in plain English.

Combines deterministic analysis with optional LLM explanations.
Works offline with just rule-based analysis, or enhanced with any LLM:
  - Local Ollama (privacy-first)
  - OpenAI GPT-4o
  - Claude (Anthropic)

Usage:
    from querysense.explainer.nlq import NLQueryExplainer

    explainer = NLQueryExplainer()

    # Pure deterministic (no LLM needed):
    result = explainer.explain_query(sql, explain_plan)

    # With local LLM enhancement:
    explainer = NLQueryExplainer(llm="ollama", model="llama3")
    result = await explainer.explain_query_async(sql, explain_plan)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class QueryExplanation:
    """Human-readable explanation of a query's performance."""

    sql: str
    summary: str  # One-line summary
    bottlenecks: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    index_suggestions: list[str] = field(default_factory=list)
    llm_explanation: str = ""  # Extra detail from LLM if available
    estimated_improvement: str = ""
    query_type: str = ""  # OLTP, OLAP, DDL, etc.
    complexity_score: int = 0  # 1-10

    def to_plain_english(self) -> str:
        """Format as a human-readable explanation."""
        lines = [self.summary, ""]

        if self.bottlenecks:
            lines.append("Bottlenecks:")
            for b in self.bottlenecks:
                lines.append(f"  - {b}")
            lines.append("")

        if self.recommendations:
            lines.append("Recommendations:")
            for i, r in enumerate(self.recommendations, 1):
                lines.append(f"  {i}. {r}")
            lines.append("")

        if self.index_suggestions:
            lines.append("Index suggestions:")
            for s in self.index_suggestions:
                lines.append(f"  {s}")
            lines.append("")

        if self.llm_explanation:
            lines.append("Detailed explanation:")
            lines.append(f"  {self.llm_explanation}")

        return "\n".join(lines)


class NLQueryExplainer:
    """
    Schema-aware natural language query explainer.

    Reads a SQL query and its EXPLAIN plan, then produces human-readable
    explanations of what's slow and how to fix it.

    Works in two modes:
    1. Deterministic only (default) — fast, offline, rule-based
    2. LLM-enhanced — adds natural language depth from local or cloud LLM
    """

    def __init__(
        self,
        llm: str = "",  # "", "ollama", "openai", "claude"
        model: str = "",
        api_key: str = "",
        base_url: str = "",
    ) -> None:
        self.llm = llm
        self.model = model
        self.api_key = api_key
        self.base_url = base_url

    def explain_query(
        self,
        sql: str,
        explain_plan: dict[str, Any] | str | None = None,
        schema_context: dict[str, Any] | None = None,
    ) -> QueryExplanation:
        """
        Explain a query's performance using deterministic analysis only.

        This works entirely offline — no LLM or network needed.
        """
        plan_data = self._normalize_plan(explain_plan) if explain_plan else {}

        query_type = self._classify_query(sql)
        complexity = self._estimate_complexity(sql)
        bottlenecks = self._find_bottlenecks(sql, plan_data)
        recommendations = self._generate_recommendations(sql, plan_data, bottlenecks)
        index_suggestions = self._suggest_indexes(sql, plan_data)
        summary = self._build_summary(sql, plan_data, bottlenecks, query_type)

        return QueryExplanation(
            sql=sql,
            summary=summary,
            bottlenecks=bottlenecks,
            recommendations=recommendations,
            index_suggestions=index_suggestions,
            query_type=query_type,
            complexity_score=complexity,
        )

    async def explain_query_async(
        self,
        sql: str,
        explain_plan: dict[str, Any] | str | None = None,
        schema_context: dict[str, Any] | None = None,
    ) -> QueryExplanation:
        """
        Explain with optional LLM enhancement.

        Falls back to deterministic-only if LLM is unavailable.
        """
        # Start with deterministic analysis
        result = self.explain_query(sql, explain_plan, schema_context)

        # Enhance with LLM if configured
        if self.llm:
            try:
                llm_text = await self._get_llm_explanation(sql, result)
                result.llm_explanation = llm_text
            except Exception as e:
                logger.debug("LLM enhancement failed: %s", e)

        return result

    # ── Deterministic analysis ───────────────────────────────────────

    def _classify_query(self, sql: str) -> str:
        """Classify query as OLTP, OLAP, DDL, DML."""
        sql_upper = sql.strip().upper()
        if sql_upper.startswith(("ALTER", "CREATE", "DROP", "TRUNCATE")):
            return "DDL"
        if sql_upper.startswith(("INSERT", "UPDATE", "DELETE")):
            return "DML"
        # Check for OLAP patterns
        olap_markers = ["GROUP BY", "HAVING", "WINDOW", "OVER(", "OVER ("]
        if any(m in sql_upper for m in olap_markers):
            # Count aggregate functions
            agg_funcs = len(re.findall(r'\b(SUM|AVG|COUNT|MIN|MAX|STDDEV|VARIANCE)\s*\(', sql_upper))
            if agg_funcs >= 2 or "GROUP BY" in sql_upper:
                return "OLAP"
        # Check for sub-selects
        sub_selects = sql_upper.count("SELECT") - 1
        if sub_selects >= 2:
            return "OLAP"
        return "OLTP"

    def _estimate_complexity(self, sql: str) -> int:
        """Estimate query complexity on a 1-10 scale."""
        sql_upper = sql.upper()
        score = 1

        # Joins
        joins = len(re.findall(r'\bJOIN\b', sql_upper))
        score += min(joins, 4)

        # Subqueries
        sub_selects = sql_upper.count("SELECT") - 1
        score += min(sub_selects * 2, 3)

        # Aggregations and window functions
        if re.search(r'\b(GROUP BY|HAVING)\b', sql_upper):
            score += 1
        if re.search(r'\bOVER\s*\(', sql_upper):
            score += 1

        # CTEs
        ctes = len(re.findall(r'\bWITH\b', sql_upper))
        if ctes:
            score += 1

        return min(score, 10)

    def _normalize_plan(self, plan: dict | str) -> dict:
        """Normalize plan to a dict."""
        if isinstance(plan, str):
            try:
                return json.loads(plan)
            except json.JSONDecodeError:
                return {}
        return plan

    def _find_bottlenecks(
        self, sql: str, plan: dict,
    ) -> list[str]:
        """Identify bottlenecks from plan and SQL."""
        bottlenecks: list[str] = []

        # Walk the plan tree for PostgreSQL EXPLAIN
        self._walk_plan_bottlenecks(plan, bottlenecks)

        # SQL-level heuristic checks
        sql_upper = sql.upper()

        if "SELECT *" in sql_upper:
            bottlenecks.append(
                "SELECT * fetches all columns — only request columns you need"
            )

        if re.search(r'WHERE\s+\w+\s+(NOT\s+)?LIKE\s+[\'"]%', sql_upper):
            bottlenecks.append(
                "Leading wildcard LIKE '%...' prevents index usage"
            )

        if re.search(r'WHERE\s+\w+\s+IS\s+NOT\s+NULL', sql_upper):
            # Not always bad, but common with ORMs
            pass

        if "ORDER BY" in sql_upper and "LIMIT" not in sql_upper:
            bottlenecks.append(
                "ORDER BY without LIMIT sorts the entire result set"
            )

        if re.search(r'\bOR\b', sql_upper) and "WHERE" in sql_upper:
            # OR in WHERE can prevent index usage
            or_count = len(re.findall(r'\bOR\b', sql_upper))
            if or_count >= 2:
                bottlenecks.append(
                    f"Multiple OR conditions ({or_count}) can prevent index usage — "
                    "consider UNION ALL or IN()"
                )

        if "OFFSET" in sql_upper:
            offset_match = re.search(r'OFFSET\s+(\d+)', sql_upper)
            if offset_match and int(offset_match.group(1)) > 1000:
                bottlenecks.append(
                    f"Large OFFSET ({offset_match.group(1)}) scans and discards rows — "
                    "use keyset pagination instead"
                )

        # Function calls in WHERE
        func_in_where = re.findall(r'WHERE\s+(\w+)\s*\(', sql_upper)
        if func_in_where:
            bottlenecks.append(
                f"Function call in WHERE clause ({', '.join(func_in_where[:3])}) — "
                "may prevent index usage, consider a functional index"
            )

        return bottlenecks

    def _walk_plan_bottlenecks(
        self, node: dict, bottlenecks: list[str],
    ) -> None:
        """Walk EXPLAIN plan tree to find bottlenecks."""
        if not isinstance(node, dict):
            return

        # PostgreSQL EXPLAIN format
        plan = node.get("Plan", node)
        node_type = plan.get("Node Type", "")
        total_cost = plan.get("Total Cost", 0)
        actual_rows = plan.get("Actual Rows", 0)
        plan_rows = plan.get("Plan Rows", 0)

        if node_type == "Seq Scan":
            relation = plan.get("Relation Name", "?")
            rows = plan.get("Actual Rows", plan.get("Plan Rows", 0))
            if rows > 10000:
                bottlenecks.append(
                    f"Sequential scan on '{relation}' ({rows:,} rows) — "
                    f"add an index on the filter columns"
                )

        if node_type == "Sort" and plan.get("Sort Method") == "external merge":
            bottlenecks.append(
                "Sort spilled to disk (external merge) — increase work_mem"
            )

        if node_type == "Hash Join" and plan.get("Peak Memory Usage", 0) > 0:
            mem = plan.get("Peak Memory Usage", 0)
            if mem > 100000:  # > 100MB
                bottlenecks.append(
                    f"Hash join using {mem // 1024}MB — consider increasing work_mem"
                )

        if node_type == "Nested Loop" and actual_rows > 10000:
            bottlenecks.append(
                f"Nested loop with {actual_rows:,} rows — "
                f"may benefit from a hash or merge join (check join condition indexes)"
            )

        # Cardinality misestimate
        if plan_rows > 0 and actual_rows > 0:
            ratio = actual_rows / plan_rows
            if ratio > 10 or ratio < 0.1:
                bottlenecks.append(
                    f"Cardinality misestimate in {node_type}: "
                    f"planned {plan_rows:,} rows, got {actual_rows:,} — "
                    f"run ANALYZE on the table"
                )

        # Recurse
        for child in plan.get("Plans", []):
            self._walk_plan_bottlenecks(child, bottlenecks)

    def _generate_recommendations(
        self, sql: str, plan: dict, bottlenecks: list[str],
    ) -> list[str]:
        """Generate actionable recommendations."""
        recs: list[str] = []

        query_type = self._classify_query(sql)

        if any("sequential scan" in b.lower() or "seq scan" in b.lower() for b in bottlenecks):
            recs.append("Add targeted indexes on the WHERE clause columns")

        if any("sort" in b.lower() and "disk" in b.lower() for b in bottlenecks):
            recs.append("Increase work_mem: SET work_mem = '256MB';")

        if any("cardinality" in b.lower() for b in bottlenecks):
            recs.append("Update statistics: ANALYZE <table>;")

        if query_type == "OLAP":
            recs.append("Consider materialized views for frequently-run analytics")
            recs.append("Enable parallel query: SET max_parallel_workers_per_gather = 4;")

        if "SELECT *" in sql.upper():
            recs.append("List only the columns you need to enable index-only scans")

        if any("offset" in b.lower() for b in bottlenecks):
            recs.append(
                "Use keyset pagination: WHERE id > :last_id ORDER BY id LIMIT N"
            )

        if any("wildcard" in b.lower() or "like '%'" in b.lower() for b in bottlenecks):
            recs.append(
                "For full-text search, use GIN indexes with pg_trgm or tsvector"
            )

        return recs

    def _suggest_indexes(
        self, sql: str, plan: dict,
    ) -> list[str]:
        """Suggest specific CREATE INDEX statements."""
        suggestions: list[str] = []

        # Extract table and WHERE columns from SQL
        tables = re.findall(r'\bFROM\s+(\w+)', sql, re.IGNORECASE)
        where_cols = re.findall(r'WHERE\s+(\w+)\s*[=<>!]', sql, re.IGNORECASE)
        order_cols = re.findall(r'ORDER\s+BY\s+(\w+)', sql, re.IGNORECASE)
        join_cols = re.findall(r'ON\s+\w+\.(\w+)\s*=', sql, re.IGNORECASE)

        if tables and where_cols:
            table = tables[0]
            cols = ", ".join(dict.fromkeys(where_cols))  # Dedupe preserving order
            suggestions.append(
                f"CREATE INDEX CONCURRENTLY idx_{table}_{'_'.join(where_cols[:3])} "
                f"ON {table} ({cols});"
            )

        if tables and order_cols and not where_cols:
            table = tables[0]
            suggestions.append(
                f"CREATE INDEX CONCURRENTLY idx_{table}_{'_'.join(order_cols[:2])} "
                f"ON {table} ({', '.join(order_cols[:2])});"
            )

        return suggestions

    def _build_summary(
        self,
        sql: str,
        plan: dict,
        bottlenecks: list[str],
        query_type: str,
    ) -> str:
        """Build a one-line summary."""
        if not bottlenecks:
            return f"This {query_type} query looks efficient — no obvious bottlenecks found."

        top_issue = bottlenecks[0].split("—")[0].strip() if bottlenecks else "unknown issue"
        count = len(bottlenecks)
        plural = "issue" if count == 1 else "issues"

        return (
            f"This {query_type} query has {count} performance {plural}. "
            f"Primary: {top_issue}."
        )

    # ── LLM integration ─────────────────────────────────────────────

    async def _get_llm_explanation(
        self, sql: str, analysis: QueryExplanation,
    ) -> str:
        """Get additional explanation from configured LLM."""
        prompt = (
            f"A {analysis.query_type} query has these performance issues:\n"
            + "\n".join(f"- {b}" for b in analysis.bottlenecks)
            + f"\n\nSQL:\n{sql[:500]}\n\n"
            + "Explain in 2-3 sentences why this query is slow and the single "
            + "most impactful fix."
        )

        if self.llm == "ollama":
            from querysense.explainer.ollama_explainer import OllamaExplainer
            explainer = OllamaExplainer(
                model=self.model or "llama3",
                base_url=self.base_url or "http://localhost:11434",
            )
            # Create a minimal finding-like object for the protocol
            result = await self._call_with_prompt(explainer, prompt)
            return result

        elif self.llm == "openai":
            from querysense.explainer.openai_explainer import OpenAIExplainer
            explainer = OpenAIExplainer(
                api_key=self.api_key,
                model=self.model or "gpt-4o-mini",
                base_url=self.base_url or None,
            )
            result = await self._call_with_prompt(explainer, prompt)
            return result

        elif self.llm == "claude":
            from querysense.explainer.claude import ClaudeExplainer
            explainer = ClaudeExplainer(
                api_key=self.api_key,
                model=self.model or "claude-sonnet-4-20250514",
            )
            result = await self._call_with_prompt(explainer, prompt)
            return result

        return ""

    async def _call_with_prompt(self, explainer: Any, prompt: str) -> str:
        """Call an explainer with a raw text prompt (wrapping in a Finding-like object)."""
        # Create a minimal namespace that looks like a Finding
        class _PseudoFinding:
            id = "nlq"
            title = prompt[:200]
            description = prompt
            sql = ""
            severity = ""

        result = await explainer.explain_one(_PseudoFinding())
        return result.explanation or ""
