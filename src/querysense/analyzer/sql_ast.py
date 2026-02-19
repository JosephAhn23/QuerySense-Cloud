"""
SQL parsing port -- the single public entry point for SQL analysis.

This module is the authoritative SQL parsing interface for QuerySense.
All consumers should import SQL parsing types and functions from here,
not from the internal ``sql_parser`` adapter.

Provides accurate SQL parsing for:
- CTEs (WITH clauses)
- Window functions
- Complex JOINs with parenthetical grouping
- Lateral joins
- PostgreSQL-specific syntax

Prefers pglast (PostgreSQL's actual C parser) when installed, and falls
back to sqlparse (heuristic tokenizer) transparently.  Confidence level
is captured in ``SQLParseResult`` so callers can gate advice.

Usage:
    from querysense.analyzer.sql_ast import SQLASTParser, SQLParseResult
    
    parser = SQLASTParser()
    result = parser.parse("SELECT * FROM orders WHERE status = 'pending'")
    
    if result.confidence == SQLConfidence.HIGH:
        # Reliable AST available
        for col in result.query_info.filter_columns:
            print(col.qualified_name)
    else:
        # Heuristic or failed - disable index advice or mark as heuristic
        ...

Re-exported from internal adapter (sql_parser.py):
    ColumnInfo, ColumnUsage, QueryInfo, SQLQueryAnalyzer
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from querysense.analyzer.models import SQLConfidence

# Re-export shared data models from the internal sqlparse adapter so that
# consumers only need ``from querysense.analyzer.sql_ast import ...``.
from querysense.analyzer.sql_parser import (  # noqa: F401
    ColumnInfo,
    ColumnUsage,
    QueryInfo,
    SQLQueryAnalyzer,
)

__all__ = [
    # Core parser facade
    "SQLASTParser",
    "SQLParseResult",
    "PglastParser",
    # Factory / introspection
    "get_sql_parser",
    "is_pglast_available",
    # Re-exported data models (canonical import location)
    "ColumnInfo",
    "ColumnUsage",
    "QueryInfo",
    "SQLQueryAnalyzer",
]

logger = logging.getLogger(__name__)

# Try to import pglast (optional dependency)
_PGLAST_AVAILABLE = False
try:
    import pglast
    from pglast import Node, parse_sql
    from pglast.enums import A_Expr_Kind, JoinType, SortByDir
    _PGLAST_AVAILABLE = True
except ImportError:
    pglast = None  # type: ignore[assignment]
    parse_sql = None  # type: ignore[assignment]
    Node = None  # type: ignore[assignment]


@dataclass
class SQLParseResult:
    """
    Result of SQL parsing with confidence level.
    
    Attributes:
        query_info: Extracted query information
        confidence: Confidence level (HIGH=pglast, MEDIUM=sqlparse, LOW=failed)
        ast: Raw AST if available (pglast only)
        normalized_sql: Normalized SQL for fingerprinting
        parse_error: Error message if parsing failed
    """
    
    query_info: QueryInfo
    confidence: SQLConfidence
    ast: Any | None = None
    normalized_sql: str | None = None
    parse_error: str | None = None
    
    @property
    def sql_hash(self) -> str | None:
        """Hash of normalized SQL for cache keys."""
        if self.normalized_sql:
            return hashlib.sha256(self.normalized_sql.encode()).hexdigest()[:16]
        return None
    
    @property
    def is_reliable(self) -> bool:
        """Whether the parse result is reliable enough for index advice."""
        return self.confidence in (SQLConfidence.HIGH, SQLConfidence.MEDIUM)


class PglastParser:
    """
    SQL parser using pglast (libpg_query - actual PostgreSQL parser).
    
    Provides accurate AST for:
    - CTEs
    - Window functions
    - Complex JOINs
    - Subqueries
    - PostgreSQL-specific syntax
    """
    
    def __init__(self) -> None:
        if not _PGLAST_AVAILABLE:
            raise RuntimeError("pglast is not installed. Install with: pip install pglast")
    
    def parse(self, sql: str) -> SQLParseResult:
        """
        Parse SQL using pglast and extract query information.
        
        Returns SQLParseResult with HIGH confidence on success.
        """
        try:
            # Parse SQL into AST
            tree = parse_sql(sql)
            
            if not tree:
                return SQLParseResult(
                    query_info=QueryInfo(),
                    confidence=SQLConfidence.LOW,
                    parse_error="Empty parse result",
                )
            
            # Extract query info from AST
            query_info = self._extract_query_info(tree)
            
            # Normalize SQL for fingerprinting
            normalized = self._normalize_sql(tree)
            
            return SQLParseResult(
                query_info=query_info,
                confidence=SQLConfidence.HIGH,
                ast=tree,
                normalized_sql=normalized,
            )
            
        except Exception as e:
            logger.warning("pglast parse failed: %s", e)
            return SQLParseResult(
                query_info=QueryInfo(),
                confidence=SQLConfidence.LOW,
                parse_error=str(e),
            )
    
    def _extract_query_info(self, tree: list[Node]) -> QueryInfo:  # type: ignore[name-defined]
        """Extract query information from pglast AST."""
        tables: list[str] = []
        filter_columns: list[ColumnInfo] = []
        join_columns: list[ColumnInfo] = []
        order_by_columns: list[ColumnInfo] = []
        group_by_columns: list[ColumnInfo] = []
        
        # Table aliases for resolution
        aliases: dict[str, str] = {}
        
        for stmt in tree:
            if hasattr(stmt, 'stmt'):
                self._visit_node(
                    stmt.stmt,
                    tables=tables,
                    aliases=aliases,
                    filter_columns=filter_columns,
                    join_columns=join_columns,
                    order_by_columns=order_by_columns,
                    group_by_columns=group_by_columns,
                )
        
        # Resolve aliases to table names
        def resolve_table(col: ColumnInfo) -> ColumnInfo:
            if col.table and col.table in aliases:
                return ColumnInfo(
                    table=aliases[col.table],
                    column=col.column,
                    usage=col.usage,
                    operator=col.operator,
                    is_equality=col.is_equality,
                    is_range=col.is_range,
                    sort_direction=col.sort_direction,
                )
            return col
        
        return QueryInfo(
            tables=tables,
            filter_columns=[resolve_table(c) for c in filter_columns],
            join_columns=[resolve_table(c) for c in join_columns],
            order_by_columns=[resolve_table(c) for c in order_by_columns],
            group_by_columns=[resolve_table(c) for c in group_by_columns],
        )
    
    def _visit_node(
        self,
        node: Any,
        tables: list[str],
        aliases: dict[str, str],
        filter_columns: list[ColumnInfo],
        join_columns: list[ColumnInfo],
        order_by_columns: list[ColumnInfo],
        group_by_columns: list[ColumnInfo],
    ) -> None:
        """Recursively visit AST nodes to extract information."""
        if node is None:
            return
        
        node_tag = getattr(node, 'node_tag', None)
        
        # Handle SELECT statement
        if node_tag == 'SelectStmt':
            # FROM clause
            if hasattr(node, 'fromClause') and node.fromClause:
                for item in node.fromClause:
                    self._extract_from_item(item, tables, aliases, join_columns)
            
            # WHERE clause
            if hasattr(node, 'whereClause') and node.whereClause:
                self._extract_where(node.whereClause, filter_columns)
            
            # ORDER BY
            if hasattr(node, 'sortClause') and node.sortClause:
                for sort_item in node.sortClause:
                    self._extract_sort_by(sort_item, order_by_columns)
            
            # GROUP BY
            if hasattr(node, 'groupClause') and node.groupClause:
                for group_item in node.groupClause:
                    self._extract_group_by(group_item, group_by_columns)
            
            # CTEs
            if hasattr(node, 'withClause') and node.withClause:
                if hasattr(node.withClause, 'ctes'):
                    for cte in node.withClause.ctes:
                        if hasattr(cte, 'ctequery'):
                            self._visit_node(
                                cte.ctequery,
                                tables, aliases, filter_columns,
                                join_columns, order_by_columns, group_by_columns,
                            )
    
    def _extract_from_item(
        self,
        item: Any,
        tables: list[str],
        aliases: dict[str, str],
        join_columns: list[ColumnInfo],
    ) -> None:
        """Extract tables and joins from FROM clause."""
        if item is None:
            return
        
        node_tag = getattr(item, 'node_tag', None)
        
        if node_tag == 'RangeVar':
            # Simple table reference
            table_name = getattr(item, 'relname', None)
            alias = None
            if hasattr(item, 'alias') and item.alias:
                alias = getattr(item.alias, 'aliasname', None)
            
            if table_name:
                tables.append(table_name)
                if alias:
                    aliases[alias] = table_name
        
        elif node_tag == 'JoinExpr':
            # JOIN expression
            if hasattr(item, 'larg'):
                self._extract_from_item(item.larg, tables, aliases, join_columns)
            if hasattr(item, 'rarg'):
                self._extract_from_item(item.rarg, tables, aliases, join_columns)
            
            # Extract JOIN condition
            if hasattr(item, 'quals') and item.quals:
                self._extract_join_condition(item.quals, join_columns)
        
        elif node_tag == 'RangeSubselect':
            # Subquery in FROM
            if hasattr(item, 'subquery'):
                # Could recurse into subquery here
                pass
    
    def _extract_where(self, node: Any, filter_columns: list[ColumnInfo]) -> None:
        """Extract columns from WHERE clause."""
        if node is None:
            return
        
        node_tag = getattr(node, 'node_tag', None)
        
        if node_tag == 'A_Expr':
            # Comparison or boolean expression
            kind = getattr(node, 'kind', None)
            
            # Get operator
            operator = None
            if hasattr(node, 'name') and node.name:
                for op_node in node.name:
                    if hasattr(op_node, 'sval'):
                        operator = op_node.sval.upper()
                        break
            
            is_equality = operator in ('=', 'IS')
            is_range = operator in ('>', '<', '>=', '<=', '!=', '<>')
            
            # Extract column from left side
            if hasattr(node, 'lexpr'):
                col_info = self._extract_column_ref(node.lexpr, ColumnUsage.FILTER)
                if col_info:
                    filter_columns.append(ColumnInfo(
                        table=col_info[0],
                        column=col_info[1],
                        usage=ColumnUsage.FILTER,
                        operator=operator,
                        is_equality=is_equality,
                        is_range=is_range,
                    ))
            
            # Recurse into right side (for nested expressions)
            if hasattr(node, 'rexpr'):
                self._extract_where(node.rexpr, filter_columns)
        
        elif node_tag == 'BoolExpr':
            # AND/OR expression
            if hasattr(node, 'args'):
                for arg in node.args:
                    self._extract_where(arg, filter_columns)
        
        elif node_tag == 'SubLink':
            # Subquery (IN, EXISTS, etc.)
            if hasattr(node, 'testexpr'):
                col_info = self._extract_column_ref(node.testexpr, ColumnUsage.FILTER)
                if col_info:
                    filter_columns.append(ColumnInfo(
                        table=col_info[0],
                        column=col_info[1],
                        usage=ColumnUsage.FILTER,
                        operator='IN',
                        is_equality=True,
                    ))
    
    def _extract_join_condition(self, node: Any, join_columns: list[ColumnInfo]) -> None:
        """Extract columns from JOIN condition."""
        if node is None:
            return
        
        node_tag = getattr(node, 'node_tag', None)
        
        if node_tag == 'A_Expr':
            # Get operator
            operator = None
            if hasattr(node, 'name') and node.name:
                for op_node in node.name:
                    if hasattr(op_node, 'sval'):
                        operator = op_node.sval.upper()
                        break
            
            is_equality = operator == '='
            
            # Extract both sides
            for side in ('lexpr', 'rexpr'):
                if hasattr(node, side):
                    col_info = self._extract_column_ref(getattr(node, side), ColumnUsage.JOIN)
                    if col_info:
                        join_columns.append(ColumnInfo(
                            table=col_info[0],
                            column=col_info[1],
                            usage=ColumnUsage.JOIN,
                            operator=operator,
                            is_equality=is_equality,
                        ))
        
        elif node_tag == 'BoolExpr':
            if hasattr(node, 'args'):
                for arg in node.args:
                    self._extract_join_condition(arg, join_columns)
    
    def _extract_column_ref(
        self,
        node: Any,
        usage: ColumnUsage,
    ) -> tuple[str | None, str] | None:
        """Extract table and column name from a column reference."""
        if node is None:
            return None
        
        node_tag = getattr(node, 'node_tag', None)
        
        if node_tag == 'ColumnRef':
            fields = getattr(node, 'fields', [])
            if len(fields) >= 2:
                # table.column
                table = getattr(fields[0], 'sval', None)
                column = getattr(fields[1], 'sval', None)
                if column:
                    return (table, column)
            elif len(fields) == 1:
                # Just column name
                column = getattr(fields[0], 'sval', None)
                if column:
                    return (None, column)
        
        return None
    
    def _extract_sort_by(self, node: Any, order_by_columns: list[ColumnInfo]) -> None:
        """Extract columns from ORDER BY clause."""
        if node is None:
            return
        
        node_tag = getattr(node, 'node_tag', None)
        
        if node_tag == 'SortBy':
            # Get sort direction
            direction = "ASC"
            if hasattr(node, 'sortby_dir'):
                if node.sortby_dir == SortByDir.SORTBY_DESC:
                    direction = "DESC"
            
            # Get column
            if hasattr(node, 'node'):
                col_info = self._extract_column_ref(node.node, ColumnUsage.ORDER_BY)
                if col_info:
                    order_by_columns.append(ColumnInfo(
                        table=col_info[0],
                        column=col_info[1],
                        usage=ColumnUsage.ORDER_BY,
                        sort_direction=direction,
                    ))
    
    def _extract_group_by(self, node: Any, group_by_columns: list[ColumnInfo]) -> None:
        """Extract columns from GROUP BY clause."""
        col_info = self._extract_column_ref(node, ColumnUsage.GROUP_BY)
        if col_info:
            group_by_columns.append(ColumnInfo(
                table=col_info[0],
                column=col_info[1],
                usage=ColumnUsage.GROUP_BY,
            ))
    
    def _normalize_sql(self, tree: list[Any]) -> str:
        """Normalize SQL for fingerprinting (removes literals, normalizes whitespace)."""
        try:
            # pglast can pretty-print the AST back to SQL
            from pglast import prettify
            normalized = prettify(tree)
            # Replace string literals with placeholders
            normalized = re.sub(r"'[^']*'", "'?'", normalized)
            # Replace numeric literals with placeholders
            normalized = re.sub(r'\b\d+\b', '?', normalized)
            return normalized
        except Exception:
            return ""


class SQLASTParser:
    """
    Main SQL parser that prefers pglast but falls back to sqlparse.
    
    Design principle: Use the source of truth when available.
    When pglast is not available, fall back to heuristic parsing
    but mark confidence as MEDIUM.
    
    Hard rule: If AST parse fails, set sql_confidence=LOW and
    disable index advice (or mark as "heuristic").
    """
    
    def __init__(self, prefer_pglast: bool = True) -> None:
        """
        Initialize the parser.
        
        Args:
            prefer_pglast: If True and pglast is available, use it.
                          If False, always use sqlparse.
        """
        self.prefer_pglast = prefer_pglast
        self._pglast_parser: PglastParser | None = None
        self._sqlparse_parser = SQLQueryAnalyzer()
        
        if prefer_pglast and _PGLAST_AVAILABLE:
            try:
                self._pglast_parser = PglastParser()
            except Exception as e:
                logger.warning("Could not initialize pglast: %s", e)
    
    @property
    def uses_pglast(self) -> bool:
        """Whether pglast is being used."""
        return self._pglast_parser is not None
    
    def parse(self, sql: str) -> SQLParseResult:
        """
        Parse SQL and extract query information.
        
        Tries pglast first (if available), falls back to sqlparse.
        """
        if not sql or not sql.strip():
            return SQLParseResult(
                query_info=QueryInfo(),
                confidence=SQLConfidence.NONE,
            )
        
        # Try pglast first
        if self._pglast_parser is not None:
            result = self._pglast_parser.parse(sql)
            if result.confidence == SQLConfidence.HIGH:
                return result
            # pglast failed, fall back to sqlparse
            logger.debug("pglast parse failed, falling back to sqlparse")
        
        # Use sqlparse as fallback
        try:
            query_info = self._sqlparse_parser.analyze(sql)
            
            # Normalize SQL (simple approach for sqlparse)
            normalized = self._normalize_sql_simple(sql)
            
            return SQLParseResult(
                query_info=query_info,
                confidence=SQLConfidence.MEDIUM,
                normalized_sql=normalized,
            )
        except Exception as e:
            logger.warning("sqlparse failed: %s", e)
            return SQLParseResult(
                query_info=QueryInfo(),
                confidence=SQLConfidence.LOW,
                parse_error=str(e),
            )
    
    def _normalize_sql_simple(self, sql: str) -> str:
        """Simple SQL normalization for fingerprinting."""
        # Normalize whitespace
        normalized = " ".join(sql.split())
        # Replace string literals
        normalized = re.sub(r"'[^']*'", "'?'", normalized)
        # Replace numeric literals
        normalized = re.sub(r'\b\d+\b', '?', normalized)
        # Lowercase keywords (rough)
        normalized = normalized.upper()
        return normalized


def get_sql_parser(prefer_pglast: bool = True) -> SQLASTParser:
    """
    Get a configured SQL parser instance.
    
    Args:
        prefer_pglast: Whether to prefer pglast over sqlparse
        
    Returns:
        Configured SQLASTParser instance
    """
    return SQLASTParser(prefer_pglast=prefer_pglast)


def is_pglast_available() -> bool:
    """Check if pglast is available."""
    return _PGLAST_AVAILABLE
