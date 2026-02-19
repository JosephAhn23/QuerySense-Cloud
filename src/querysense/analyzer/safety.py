"""
Query safety checking for EXPLAIN ANALYZE.

EXPLAIN ANALYZE actually executes the query, which means:
- INSERT/UPDATE/DELETE will modify data
- Expensive queries will consume resources

This module provides safety checks to prevent accidents.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Pattern


class QueryType(str, Enum):
    """Classification of query types."""
    
    SELECT = "select"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    DDL = "ddl"  # CREATE, ALTER, DROP
    DCL = "dcl"  # GRANT, REVOKE
    UNKNOWN = "unknown"


@dataclass
class SafetyCheckResult:
    """Result of a safety check."""
    
    safe: bool
    query_type: QueryType
    reason: str
    warnings: list[str] = field(default_factory=list)


class QuerySafetyChecker:
    """
    Checks if a query is safe for EXPLAIN ANALYZE.
    
    EXPLAIN ANALYZE executes the query, so we must prevent:
    - Data modification (INSERT, UPDATE, DELETE)
    - Schema changes (CREATE, ALTER, DROP)
    - Permission changes (GRANT, REVOKE)
    
    Example:
        checker = QuerySafetyChecker()
        
        result = checker.check("SELECT * FROM users")
        assert result.safe  # OK
        
        result = checker.check("DELETE FROM users")
        assert not result.safe  # Blocked
    """
    
    # Patterns that indicate unsafe queries (case-insensitive)
    UNSAFE_PATTERNS: list[tuple[Pattern[str], QueryType, str]] = [
        # DML - modifies data
        (re.compile(r"\bINSERT\s+INTO\b", re.IGNORECASE), 
         QueryType.INSERT, "Query inserts data"),
        (re.compile(r"\bUPDATE\s+\w+\s+SET\b", re.IGNORECASE), 
         QueryType.UPDATE, "Query updates data"),
        (re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE), 
         QueryType.DELETE, "Query deletes data"),
        (re.compile(r"\bTRUNCATE\b", re.IGNORECASE), 
         QueryType.DELETE, "Query truncates table"),
        
        # DDL - modifies schema
        (re.compile(r"\bCREATE\s+(TABLE|INDEX|VIEW|FUNCTION|PROCEDURE|TRIGGER)\b", re.IGNORECASE),
         QueryType.DDL, "Query creates schema object"),
        (re.compile(r"\bALTER\s+(TABLE|INDEX|VIEW|FUNCTION|PROCEDURE)\b", re.IGNORECASE),
         QueryType.DDL, "Query alters schema object"),
        (re.compile(r"\bDROP\s+(TABLE|INDEX|VIEW|FUNCTION|PROCEDURE|TRIGGER|DATABASE)\b", re.IGNORECASE),
         QueryType.DDL, "Query drops schema object"),
        
        # DCL - modifies permissions
        (re.compile(r"\bGRANT\b", re.IGNORECASE),
         QueryType.DCL, "Query grants permissions"),
        (re.compile(r"\bREVOKE\b", re.IGNORECASE),
         QueryType.DCL, "Query revokes permissions"),
    ]
    
    def __init__(
        self,
        allow_dml: bool = False,
        allow_ddl: bool = False,
    ):
        """
        Initialize the safety checker.
        
        Args:
            allow_dml: Allow INSERT/UPDATE/DELETE (dangerous!)
            allow_ddl: Allow CREATE/ALTER/DROP (dangerous!)
        """
        self.allow_dml = allow_dml
        self.allow_ddl = allow_ddl
    
    def check(self, query: str) -> SafetyCheckResult:
        """
        Check if a query is safe for EXPLAIN ANALYZE.
        
        Args:
            query: SQL query text
            
        Returns:
            SafetyCheckResult with safe flag, query type, and reason
        """
        if not query or not query.strip():
            return SafetyCheckResult(
                safe=False,
                query_type=QueryType.UNKNOWN,
                reason="Empty query",
            )
        
        query = query.strip()
        warnings: list[str] = []
        
        # Check for unsafe patterns
        for pattern, query_type, reason in self.UNSAFE_PATTERNS:
            if pattern.search(query):
                # Check if this type is explicitly allowed
                if query_type in (QueryType.INSERT, QueryType.UPDATE, QueryType.DELETE):
                    if not self.allow_dml:
                        return SafetyCheckResult(
                            safe=False,
                            query_type=query_type,
                            reason=f"{reason}. Use --allow-dml to override.",
                        )
                    else:
                        warnings.append(f"DML allowed: {reason}")
                
                elif query_type == QueryType.DDL:
                    if not self.allow_ddl:
                        return SafetyCheckResult(
                            safe=False,
                            query_type=query_type,
                            reason=f"{reason}. Use --allow-ddl to override.",
                        )
                    else:
                        warnings.append(f"DDL allowed: {reason}")
                
                elif query_type == QueryType.DCL:
                    # Never allow permission changes
                    return SafetyCheckResult(
                        safe=False,
                        query_type=query_type,
                        reason=f"{reason}. Permission changes are never allowed.",
                    )
        
        return SafetyCheckResult(
            safe=True,
            query_type=QueryType.SELECT,
            reason="Query is safe for EXPLAIN ANALYZE",
            warnings=warnings,
        )
    
    def check_or_raise(self, query: str) -> SafetyCheckResult:
        """
        Check query safety, raising exception if unsafe.
        
        Raises:
            UnsafeQueryError: If query is not safe
        """
        result = self.check(query)
        if not result.safe:
            raise UnsafeQueryError(result.reason, result.query_type)
        return result


class UnsafeQueryError(Exception):
    """Raised when attempting to ANALYZE an unsafe query."""
    
    def __init__(self, message: str, query_type: QueryType):
        super().__init__(message)
        self.query_type = query_type
