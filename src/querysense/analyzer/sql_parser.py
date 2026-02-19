"""
Internal sqlparse-based SQL parser adapter.

This is the heuristic fallback backend for SQL analysis.  It is used
automatically by :class:`~querysense.analyzer.sql_ast.SQLASTParser`
when *pglast* is not installed.

**External consumers should import from** ``querysense.analyzer.sql_ast``
rather than directly from this module.  The data models
(``ColumnInfo``, ``ColumnUsage``, ``QueryInfo``) defined here are
re-exported through the public ``sql_ast`` port.

Parses SQL queries to extract:
- Filter columns from WHERE clauses
- Join columns from JOIN conditions
- Sort columns from ORDER BY
- Group columns from GROUP BY
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import sqlparse
from sqlparse import tokens as T
from sqlparse.sql import (
    Comparison,
    Function,
    Identifier,
    IdentifierList,
    Parenthesis,
    Token,
    Where,
)


class ColumnUsage(str, Enum):
    """How a column is used in a query."""
    FILTER = "filter"        # WHERE clause
    JOIN = "join"            # JOIN condition
    ORDER_BY = "order_by"    # ORDER BY clause
    GROUP_BY = "group_by"    # GROUP BY clause
    SELECT = "select"        # SELECT list


@dataclass(frozen=True)
class ColumnInfo:
    """
    Information about a column reference in a SQL query.
    
    Attributes:
        table: Table name or alias (None if not qualified)
        column: Column name
        usage: How the column is used (filter, join, order_by, etc.)
        operator: Operator used (=, >, <, LIKE, etc.) if applicable
        is_equality: True if this is an equality check
        is_range: True if this is a range check
    """
    table: str | None
    column: str
    usage: ColumnUsage
    operator: str | None = None
    is_equality: bool = False
    is_range: bool = False
    sort_direction: str | None = None  # ASC or DESC for ORDER BY
    
    @property
    def qualified_name(self) -> str:
        """Return table.column if table is known, else just column."""
        if self.table:
            return f"{self.table}.{self.column}"
        return self.column


@dataclass
class QueryInfo:
    """
    Complete analysis of a SQL query.
    
    Attributes:
        tables: List of tables referenced in the query
        filter_columns: Columns used in WHERE clause
        join_columns: Columns used in JOIN conditions
        order_by_columns: Columns used in ORDER BY
        group_by_columns: Columns used in GROUP BY
        select_columns: Columns in SELECT list
    """
    tables: list[str] = field(default_factory=list)
    filter_columns: list[ColumnInfo] = field(default_factory=list)
    join_columns: list[ColumnInfo] = field(default_factory=list)
    order_by_columns: list[ColumnInfo] = field(default_factory=list)
    group_by_columns: list[ColumnInfo] = field(default_factory=list)
    select_columns: list[ColumnInfo] = field(default_factory=list)
    
    @property
    def all_indexed_columns(self) -> list[ColumnInfo]:
        """All columns that might benefit from an index."""
        return self.filter_columns + self.join_columns + self.order_by_columns
    
    def get_columns_for_table(self, table: str) -> list[ColumnInfo]:
        """Get all index-relevant columns for a specific table."""
        return [
            c for c in self.all_indexed_columns
            if c.table == table or c.table is None
        ]
    
    def suggest_composite_index(self, table: str) -> list[str]:
        """
        Suggest optimal column order for a composite index.
        
        Order: equality filters first, then range filters, then sort columns.
        """
        columns = self.get_columns_for_table(table)
        
        # Separate by type
        equality = [c.column for c in columns if c.is_equality]
        ranges = [c.column for c in columns if c.is_range and c.column not in equality]
        sorts = [c.column for c in self.order_by_columns 
                 if (c.table == table or c.table is None) and c.column not in equality + ranges]
        
        # Remove duplicates while preserving order
        seen: set[str] = set()
        result: list[str] = []
        for col in equality + ranges + sorts:
            if col not in seen:
                seen.add(col)
                result.append(col)
        
        return result


class SQLQueryAnalyzer:
    """
    Analyzes SQL queries to extract column usage information.
    
    Uses sqlparse for parsing and custom logic for extracting
    meaningful column information.
    """
    
    # Operators that indicate equality
    EQUALITY_OPS = {"=", "==", "IS", "IN"}
    
    # Operators that indicate range
    RANGE_OPS = {">", "<", ">=", "<=", "BETWEEN", "!=", "<>"}
    
    def analyze(self, sql: str) -> QueryInfo:
        """
        Analyze a SQL query and extract column information.
        
        Args:
            sql: The SQL query string
            
        Returns:
            QueryInfo with extracted column information
        """
        # Initialize
        self._table_aliases: dict[str, str] = {}
        
        # Parse the SQL
        parsed = sqlparse.parse(sql)
        if not parsed:
            return QueryInfo()
        
        stmt = parsed[0]
        
        query_info = QueryInfo()
        
        # Extract tables from FROM clause (also populates _table_aliases)
        query_info.tables = self._extract_tables(stmt)
        
        # Process each part of the query
        for token in stmt.tokens:
            if isinstance(token, Where):
                query_info.filter_columns.extend(self._extract_where_columns(token))
            elif token.ttype is T.Keyword:
                keyword = token.value.upper()
                if keyword == "ORDER":
                    # Find ORDER BY columns
                    order_cols = self._extract_order_by(stmt)
                    query_info.order_by_columns.extend(order_cols)
                elif keyword == "GROUP":
                    # Find GROUP BY columns
                    group_cols = self._extract_group_by(stmt)
                    query_info.group_by_columns.extend(group_cols)
        
        # Extract JOIN columns
        query_info.join_columns.extend(self._extract_join_columns(stmt))
        
        # Resolve aliases to table names
        query_info = self._resolve_aliases(query_info)
        
        return query_info
    
    def _resolve_aliases(self, query_info: QueryInfo) -> QueryInfo:
        """Resolve table aliases to actual table names."""
        def resolve_column(col: ColumnInfo) -> ColumnInfo:
            if col.table and col.table in self._table_aliases:
                return ColumnInfo(
                    table=self._table_aliases[col.table],
                    column=col.column,
                    usage=col.usage,
                    operator=col.operator,
                    is_equality=col.is_equality,
                    is_range=col.is_range,
                    sort_direction=col.sort_direction,
                )
            return col
        
        return QueryInfo(
            tables=query_info.tables,
            filter_columns=[resolve_column(c) for c in query_info.filter_columns],
            join_columns=[resolve_column(c) for c in query_info.join_columns],
            order_by_columns=[resolve_column(c) for c in query_info.order_by_columns],
            group_by_columns=[resolve_column(c) for c in query_info.group_by_columns],
            select_columns=[resolve_column(c) for c in query_info.select_columns],
        )
    
    def _extract_tables(self, stmt: Any) -> list[str]:
        """Extract table names from FROM clause."""
        tables: list[str] = []
        aliases: dict[str, str] = {}  # alias -> table name
        
        from_seen = False
        for token in stmt.tokens:
            if token.ttype is T.Keyword and token.value.upper() == "FROM":
                from_seen = True
                continue
            
            if from_seen:
                if token.ttype is T.Keyword:
                    # Hit another keyword, stop (but allow JOIN)
                    if token.value.upper() in ("WHERE", "ORDER", "GROUP", "HAVING", "LIMIT"):
                        break
                    # Skip JOIN keywords but continue parsing
                    if "JOIN" in token.value.upper():
                        continue
                
                if isinstance(token, Identifier):
                    table_name = self._get_table_name(token)
                    alias = self._get_alias(token)
                    tables.append(table_name)
                    if alias and alias != table_name:
                        aliases[alias] = table_name
                elif isinstance(token, IdentifierList):
                    for item in token.get_identifiers():
                        if isinstance(item, Identifier):
                            table_name = self._get_table_name(item)
                            alias = self._get_alias(item)
                            tables.append(table_name)
                            if alias and alias != table_name:
                                aliases[alias] = table_name
        
        # Store aliases for later use
        self._table_aliases = aliases
        return tables
    
    def _get_alias(self, identifier: Identifier) -> str | None:
        """Get the alias from an identifier if present."""
        alias = identifier.get_alias()
        return alias
    
    def _get_table_name(self, identifier: Identifier) -> str:
        """Extract table name from identifier (handles aliases)."""
        # Get the real name (first part before alias)
        name = identifier.get_real_name()
        return name or str(identifier)
    
    def _extract_where_columns(self, where: Where) -> list[ColumnInfo]:
        """Extract columns from WHERE clause."""
        columns: list[ColumnInfo] = []
        
        for token in where.tokens:
            if isinstance(token, Comparison):
                col_info = self._parse_comparison(token, ColumnUsage.FILTER)
                if col_info:
                    columns.append(col_info)
            elif isinstance(token, Parenthesis):
                # Recurse into parentheses
                columns.extend(self._extract_from_parenthesis(token, ColumnUsage.FILTER))
            elif isinstance(token, Identifier):
                # Simple column reference (e.g., in EXISTS)
                table, column = self._parse_identifier(token)
                columns.append(ColumnInfo(
                    table=table,
                    column=column,
                    usage=ColumnUsage.FILTER,
                ))
        
        return columns
    
    def _extract_from_parenthesis(self, paren: Parenthesis, usage: ColumnUsage) -> list[ColumnInfo]:
        """Extract columns from parenthesized expression."""
        columns: list[ColumnInfo] = []
        
        for token in paren.tokens:
            if isinstance(token, Comparison):
                col_info = self._parse_comparison(token, usage)
                if col_info:
                    columns.append(col_info)
            elif isinstance(token, Parenthesis):
                columns.extend(self._extract_from_parenthesis(token, usage))
        
        return columns
    
    def _parse_comparison(self, comp: Comparison, usage: ColumnUsage) -> ColumnInfo | None:
        """Parse a comparison to extract column info."""
        left = None
        operator = None
        
        for token in comp.tokens:
            if token.ttype in (T.Name, T.Literal.String.Symbol):
                if left is None:
                    left = str(token)
            elif isinstance(token, Identifier):
                if left is None:
                    table, column = self._parse_identifier(token)
                    left = column
                    left_table = table
            elif token.ttype in (T.Comparison, T.Operator.Comparison):
                operator = str(token).strip().upper()
        
        if left:
            is_equality = operator in self.EQUALITY_OPS if operator else False
            is_range = operator in self.RANGE_OPS if operator else False
            
            return ColumnInfo(
                table=left_table if 'left_table' in dir() else None,
                column=left,
                usage=usage,
                operator=operator,
                is_equality=is_equality,
                is_range=is_range,
            )
        
        return None
    
    def _parse_identifier(self, identifier: Identifier) -> tuple[str | None, str]:
        """Parse identifier to get table and column."""
        parts = str(identifier).split(".")
        if len(parts) == 2:
            return parts[0].strip(), parts[1].strip()
        return None, parts[0].strip()
    
    def _extract_order_by(self, stmt: Any) -> list[ColumnInfo]:
        """Extract columns from ORDER BY clause."""
        columns: list[ColumnInfo] = []
        
        # Normalize SQL string (remove extra whitespace)
        sql_str = " ".join(str(stmt).split())
        
        # Use regex to find ORDER BY clause
        order_match = re.search(
            r"ORDER\s+BY\s+(.+?)(?:\s+LIMIT\b|\s+OFFSET\b|\s+FOR\b|;|$)",
            sql_str,
            re.IGNORECASE
        )
        
        if order_match:
            order_clause = order_match.group(1).strip()
            # Parse individual columns
            for col_str in order_clause.split(","):
                col_str = col_str.strip()
                if not col_str:
                    continue
                
                # Determine direction
                direction = "ASC"
                if re.search(r"\bDESC\b", col_str, re.IGNORECASE):
                    direction = "DESC"
                
                # Remove direction keywords
                col_str = re.sub(r"\s*(DESC|ASC)\s*$", "", col_str, flags=re.I)
                col_str = col_str.strip()
                
                # Parse table.column
                if "." in col_str:
                    parts = col_str.split(".")
                    table, column = parts[0].strip(), parts[1].strip()
                else:
                    table, column = None, col_str
                
                if column:
                    columns.append(ColumnInfo(
                        table=table,
                        column=column,
                        usage=ColumnUsage.ORDER_BY,
                        sort_direction=direction,
                    ))
        
        return columns
    
    def _get_sort_direction(self, identifier: Identifier) -> str:
        """Get sort direction (ASC/DESC) from identifier."""
        # Check if identifier has ASC or DESC suffix
        for token in identifier.tokens:
            if token.ttype is T.Keyword:
                if token.value.upper() in ("ASC", "DESC"):
                    return token.value.upper()
        return "ASC"  # Default
    
    def _extract_group_by(self, stmt: Any) -> list[ColumnInfo]:
        """Extract columns from GROUP BY clause."""
        columns: list[ColumnInfo] = []
        
        group_by_seen = False
        for token in stmt.tokens:
            if token.ttype is T.Keyword:
                if token.value.upper() == "BY" and group_by_seen:
                    continue
                elif token.value.upper() == "GROUP":
                    group_by_seen = True
                    continue
                elif token.value.upper() in ("HAVING", "ORDER", "LIMIT"):
                    break
            
            if group_by_seen:
                if isinstance(token, Identifier):
                    table, column = self._parse_identifier(token)
                    columns.append(ColumnInfo(
                        table=table,
                        column=column,
                        usage=ColumnUsage.GROUP_BY,
                    ))
                elif isinstance(token, IdentifierList):
                    for item in token.get_identifiers():
                        if isinstance(item, Identifier):
                            table, column = self._parse_identifier(item)
                            columns.append(ColumnInfo(
                                table=table,
                                column=column,
                                usage=ColumnUsage.GROUP_BY,
                            ))
        
        return columns
    
    def _extract_join_columns(self, stmt: Any) -> list[ColumnInfo]:
        """Extract columns from JOIN conditions."""
        columns: list[ColumnInfo] = []
        
        # Look for JOIN ... ON patterns
        sql_str = str(stmt)
        
        # Simple regex for JOIN ON conditions
        # Matches: JOIN table ON table1.col1 = table2.col2
        join_pattern = re.compile(
            r"JOIN\s+\w+\s+(?:\w+\s+)?ON\s+"
            r"(\w+)\.(\w+)\s*=\s*(\w+)\.(\w+)",
            re.IGNORECASE
        )
        
        for match in join_pattern.finditer(sql_str):
            table1, col1, table2, col2 = match.groups()
            
            columns.append(ColumnInfo(
                table=table1,
                column=col1,
                usage=ColumnUsage.JOIN,
                operator="=",
                is_equality=True,
            ))
            columns.append(ColumnInfo(
                table=table2,
                column=col2,
                usage=ColumnUsage.JOIN,
                operator="=",
                is_equality=True,
            ))
        
        return columns


def analyze_sql(sql: str) -> QueryInfo:
    """
    Convenience function to analyze a SQL query.
    
    Args:
        sql: The SQL query string
        
    Returns:
        QueryInfo with extracted column information
    """
    analyzer = SQLQueryAnalyzer()
    return analyzer.analyze(sql)


def suggest_indexes_for_query(sql: str) -> dict[str, list[str]]:
    """
    Analyze SQL and suggest indexes for each table.
    
    Args:
        sql: The SQL query string
        
    Returns:
        Dict mapping table names to recommended index columns
    """
    query_info = analyze_sql(sql)
    
    suggestions: dict[str, list[str]] = {}
    for table in query_info.tables:
        columns = query_info.suggest_composite_index(table)
        if columns:
            suggestions[table] = columns
    
    return suggestions
