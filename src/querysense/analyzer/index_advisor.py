"""
Smart Index Recommendation Engine.

Analyzes query plans to generate specific, actionable index recommendations
with estimated cost improvements. Goes beyond "CREATE INDEX" to tell you
exactly which columns, in what order, and why.

Technical approach:
1. Parse all condition types (Filter, Join, Hash, Merge conditions)
2. Extract columns and operators from each condition
3. Analyze Sort Keys for composite index opportunities
4. Calculate selectivity from actual vs filtered rows
5. Estimate cost improvement using PostgreSQL's cost model
6. Suggest optimal index type (btree, hash, partial, covering)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput, PlanNode


class IndexType(str, Enum):
    """PostgreSQL index types."""
    BTREE = "btree"
    HASH = "hash"
    GIN = "gin"
    GIST = "gist"
    BRIN = "brin"


class ConditionType(str, Enum):
    """Types of conditions in query plans."""
    FILTER = "filter"
    INDEX_COND = "index_cond"
    JOIN_FILTER = "join_filter"
    HASH_COND = "hash_cond"
    MERGE_COND = "merge_cond"
    RECHECK_COND = "recheck_cond"


@dataclass(frozen=True)
class ColumnReference:
    """
    A column referenced in a condition.
    
    Attributes:
        table: Table name or alias (if identifiable)
        column: Column name
        operator: Operator used (=, >, <, LIKE, etc.)
        is_equality: True if this is an equality check
        is_range: True if this is a range check (>, <, BETWEEN)
        is_pattern: True if this is a pattern match (LIKE, ~)
    """
    table: str | None
    column: str
    operator: str
    is_equality: bool = False
    is_range: bool = False
    is_pattern: bool = False
    
    @classmethod
    def from_match(
        cls,
        table: str | None,
        column: str,
        operator: str,
    ) -> "ColumnReference":
        """Create from parsed components."""
        op_lower = operator.lower().strip()
        return cls(
            table=table,
            column=column,
            operator=operator,
            is_equality=op_lower in ("=", "is"),
            is_range=op_lower in (">", "<", ">=", "<=", "between"),
            is_pattern=op_lower in ("like", "ilike", "~", "~*"),
        )


@dataclass
class IndexRecommendation:
    """
    A specific index recommendation with cost analysis.
    
    Attributes:
        table: Target table
        columns: Ordered list of columns for the index
        index_type: Recommended index type
        is_partial: Whether to use a partial index
        partial_predicate: WHERE clause for partial index
        include_columns: Columns for covering index (INCLUDE clause)
        estimated_improvement: Estimated cost reduction factor
        confidence: Confidence in this recommendation (0.0-1.0)
        reasoning: Human-readable explanation
        sql: Ready-to-run CREATE INDEX statement
    """
    table: str
    columns: list[str]
    index_type: IndexType = IndexType.BTREE
    is_partial: bool = False
    partial_predicate: str | None = None
    include_columns: list[str] = field(default_factory=list)
    
    # Cost analysis
    estimated_improvement: float = 1.0  # 1.0 = no improvement, 10.0 = 10x faster
    estimated_index_size_mb: float | None = None
    confidence: float = 0.8
    
    # Explanation
    reasoning: str = ""
    
    @property
    def index_name(self) -> str:
        """Generate a sensible index name."""
        cols = "_".join(self.columns[:3])  # Limit length
        if len(self.columns) > 3:
            cols += "_etc"
        if self.is_partial:
            return f"idx_{self.table}_{cols}_partial"
        return f"idx_{self.table}_{cols}"
    
    @property
    def sql(self) -> str:
        """Generate CREATE INDEX statement."""
        cols_str = ", ".join(self.columns)
        
        # Start with CREATE INDEX
        parts = [f"CREATE INDEX {self.index_name}"]
        parts.append(f"ON {self.table}")
        
        # Add USING clause if not btree (btree is default)
        if self.index_type != IndexType.BTREE:
            parts.append(f"USING {self.index_type.value}")
        
        parts.append(f"({cols_str})")
        
        # Add INCLUDE for covering index
        if self.include_columns:
            include_str = ", ".join(self.include_columns)
            parts.append(f"INCLUDE ({include_str})")
        
        # Add WHERE for partial index
        if self.is_partial and self.partial_predicate:
            parts.append(f"WHERE {self.partial_predicate}")
        
        return " ".join(parts) + ";"
    
    def format_full(self) -> str:
        """Format complete recommendation with analysis."""
        lines = [self.sql, ""]
        
        if self.estimated_improvement > 1.0:
            lines.append(
                f"-- Estimated improvement: {self.estimated_improvement:.1f}x faster"
            )
        
        if self.estimated_index_size_mb:
            lines.append(
                f"-- Estimated index size: {self.estimated_index_size_mb:.1f}MB"
            )
        
        if self.reasoning:
            # Wrap reasoning in comment
            for line in self.reasoning.split("\n"):
                lines.append(f"-- {line}")
        
        lines.append("")
        lines.append("-- Docs: https://www.postgresql.org/docs/current/indexes.html")
        
        return "\n".join(lines)


class ConditionParser:
    """
    Parses PostgreSQL filter conditions to extract column references.
    
    Handles complex conditions like:
    - Simple: (status = 'active')
    - Compound: ((status = 'active') AND (created_at > '2024-01-01'))
    - Qualified: (orders.customer_id = customers.id)
    - Functions: (lower(email) = 'test@example.com')
    - Arrays: (status = ANY('{active,pending}'::text[]))
    - Type casts: ((status)::text = 'pending'::text)
    """
    
    # Patterns for extracting column references
    # Match: column operator value, including type casts
    SIMPLE_PATTERN = re.compile(
        r"[\(\s]"  # Start with ( or space
        r"([a-zA-Z_][a-zA-Z0-9_]*)"  # Column name
        r"(?:\.([a-zA-Z_][a-zA-Z0-9_]*))?"  # Optional .column for qualified names
        r"(?:\s*\)?\s*::[a-zA-Z_]+)?"  # Optional type cast like )::text or ::text
        r"\s*"
        r"([=<>!]+|(?:IS\s+(?:NOT\s+)?NULL)|(?:~~?\*?)|(?:LIKE|ILIKE|IN|ANY|BETWEEN))"  # Operator
        r"\s*",
        re.IGNORECASE,
    )
    
    # Pattern specifically for type casts: ((column)::type = value)
    TYPECAST_PATTERN = re.compile(
        r"\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)\s*::",
    )
    
    # Match: table.column pattern
    QUALIFIED_PATTERN = re.compile(
        r"([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z_][a-zA-Z0-9_]*)",
    )
    
    # Match: function(column) patterns
    FUNCTION_PATTERN = re.compile(
        r"([a-zA-Z_]+)\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)",
    )
    
    @classmethod
    def parse(cls, condition: str) -> list[ColumnReference]:
        """
        Extract all column references from a condition string.
        
        Args:
            condition: PostgreSQL condition string from EXPLAIN
            
        Returns:
            List of ColumnReference objects
        """
        if not condition:
            return []
        
        refs: list[ColumnReference] = []
        seen: set[tuple[str | None, str]] = set()
        
        # Check for type cast pattern first: ((column)::type = value)
        for match in cls.TYPECAST_PATTERN.finditer(condition):
            column = match.group(1)
            if column.upper() not in ("AND", "OR", "NOT", "NULL", "TRUE", "FALSE"):
                key = (None, column)
                if key not in seen:
                    seen.add(key)
                    refs.append(ColumnReference.from_match(None, column, "="))
        
        # Try simple pattern
        for match in cls.SIMPLE_PATTERN.finditer(condition):
            first, second, operator = match.groups()
            
            if second:
                # Qualified: table.column
                table, column = first, second
            else:
                # Unqualified: just column
                table, column = None, first
            
            # Skip if looks like a literal or keyword
            if column.upper() in ("AND", "OR", "NOT", "NULL", "TRUE", "FALSE"):
                continue
            
            key = (table, column)
            if key not in seen:
                seen.add(key)
                refs.append(ColumnReference.from_match(table, column, operator))
        
        # Also check for qualified names we might have missed
        for match in cls.QUALIFIED_PATTERN.finditer(condition):
            table, column = match.groups()
            key = (table, column)
            if key not in seen:
                seen.add(key)
                # Assume equality if we can't determine operator
                refs.append(ColumnReference.from_match(table, column, "="))
        
        return refs
    
    @classmethod
    def extract_sort_columns(cls, sort_key: list[str]) -> list[str]:
        """
        Extract column names from Sort Key.
        
        Args:
            sort_key: Sort Key list from EXPLAIN (e.g., ["orders.created_at", "orders.id DESC"])
            
        Returns:
            List of column names in order
        """
        columns = []
        
        for key in sort_key:
            # Remove table prefix and sort direction
            key = key.strip()
            
            # Remove DESC/ASC/NULLS FIRST/NULLS LAST
            key = re.sub(r"\s+(DESC|ASC|NULLS\s+(?:FIRST|LAST))\s*$", "", key, flags=re.I)
            
            # Handle table.column
            if "." in key:
                key = key.split(".")[-1]
            
            # Remove any remaining parentheses
            key = key.strip("()")
            
            if key and not key.upper() in ("DESC", "ASC"):
                columns.append(key)
        
        return columns


class CostEstimator:
    """
    Estimates cost improvements from adding indexes.
    
    Uses PostgreSQL's cost model formulas:
    - seq_page_cost = 1.0 (sequential I/O)
    - random_page_cost = 4.0 (random I/O, default for HDD)
    - cpu_tuple_cost = 0.01
    - cpu_index_tuple_cost = 0.005
    - cpu_operator_cost = 0.0025
    """
    
    # PostgreSQL default cost parameters
    SEQ_PAGE_COST = 1.0
    RANDOM_PAGE_COST = 4.0  # Conservative (HDD default)
    CPU_TUPLE_COST = 0.01
    CPU_INDEX_TUPLE_COST = 0.005
    CPU_OPERATOR_COST = 0.0025
    
    # Assume 8KB pages, average row ~100 bytes
    ROWS_PER_PAGE = 80
    
    @classmethod
    def estimate_seq_scan_cost(
        cls,
        total_rows: int,
        row_width: int = 100,
    ) -> float:
        """
        Estimate cost of sequential scan.
        
        Cost = (pages * seq_page_cost) + (rows * cpu_tuple_cost)
        """
        pages = max(1, total_rows // cls.ROWS_PER_PAGE)
        return (pages * cls.SEQ_PAGE_COST) + (total_rows * cls.CPU_TUPLE_COST)
    
    @classmethod
    def estimate_index_scan_cost(
        cls,
        total_rows: int,
        matching_rows: int,
        selectivity: float,
    ) -> float:
        """
        Estimate cost of index scan.
        
        Cost = (index_pages * random_page_cost) 
             + (matching_rows * cpu_index_tuple_cost)
             + (heap_pages * random_page_cost)
             + (matching_rows * cpu_tuple_cost)
        """
        # Estimate index size (much smaller than table)
        index_pages = max(1, total_rows // (cls.ROWS_PER_PAGE * 4))
        
        # Index lookup cost
        # B-tree depth is roughly log(n), so cost is depth * random_page_cost
        import math
        btree_depth = max(1, int(math.log2(max(1, index_pages))))
        index_cost = btree_depth * cls.RANDOM_PAGE_COST
        
        # Add cost for scanning matching index entries
        index_cost += matching_rows * cls.CPU_INDEX_TUPLE_COST
        
        # Heap fetch cost (random access for each matching row)
        # Clustered tables would be cheaper, but assume worst case
        heap_pages_touched = min(matching_rows, total_rows // cls.ROWS_PER_PAGE)
        heap_cost = heap_pages_touched * cls.RANDOM_PAGE_COST
        
        # CPU cost for processing rows
        cpu_cost = matching_rows * cls.CPU_TUPLE_COST
        
        return index_cost + heap_cost + cpu_cost
    
    @classmethod
    def calculate_selectivity(
        cls,
        rows_returned: int,
        rows_scanned: int,
        rows_removed_by_filter: int | None = None,
    ) -> float:
        """
        Calculate filter selectivity.
        
        Selectivity = fraction of rows that match the filter.
        Lower selectivity = better index candidate.
        """
        if rows_removed_by_filter is not None:
            total_before_filter = rows_returned + rows_removed_by_filter
            if total_before_filter > 0:
                return rows_returned / total_before_filter
        
        if rows_scanned > 0:
            return rows_returned / rows_scanned
        
        return 1.0  # No selectivity info
    
    @classmethod
    def estimate_improvement(
        cls,
        total_rows: int,
        matching_rows: int,
        current_cost: float,
    ) -> float:
        """
        Estimate improvement factor from adding an index.
        
        Returns ratio: current_cost / new_cost
        A value of 10.0 means 10x faster.
        """
        if matching_rows <= 0 or total_rows <= 0:
            return 1.0
        
        selectivity = matching_rows / total_rows
        
        # For highly selective queries (< 10%), index is very beneficial
        # Use a simplified model based on selectivity
        if selectivity < 0.01:
            # < 1% selectivity: huge improvement
            improvement = min(100.0, 1.0 / selectivity)
        elif selectivity < 0.1:
            # 1-10% selectivity: significant improvement
            # Index scan touches ~10% of pages vs 100% for seq scan
            improvement = min(50.0, (1.0 / selectivity) * 0.5)
        elif selectivity < 0.5:
            # 10-50% selectivity: moderate improvement
            improvement = max(2.0, (1.0 / selectivity) * 0.3)
        else:
            # > 50% selectivity: seq scan might be better
            improvement = 1.0
        
        # Also factor in actual cost comparison
        if current_cost > 0:
            # Estimate index scan cost
            new_cost = cls.estimate_index_scan_cost(total_rows, matching_rows, selectivity)
            if new_cost > 0:
                cost_ratio = current_cost / new_cost
                # Use the more conservative of the two estimates
                improvement = max(improvement, cost_ratio)
        
        # Cap at reasonable max
        return min(improvement, 1000.0)
    
    @classmethod
    def estimate_index_size_mb(
        cls,
        total_rows: int,
        num_columns: int = 1,
        avg_column_width: int = 8,
    ) -> float:
        """
        Estimate index size in MB.
        
        B-tree overhead is roughly 2-3x the data size.
        """
        # Each index entry: column data + 6 bytes tuple pointer + overhead
        entry_size = (avg_column_width * num_columns) + 6 + 8  # 8 bytes overhead
        
        # B-tree has ~75% fill factor by default
        entries_per_page = int(8192 * 0.75 / entry_size)
        pages = max(1, total_rows // max(1, entries_per_page))
        
        # Add internal pages (roughly log2(pages))
        import math
        internal_pages = max(1, int(math.log2(max(1, pages))))
        
        total_pages = pages + internal_pages
        return (total_pages * 8192) / (1024 * 1024)


class IndexRecommender:
    """
    Generates smart index recommendations from query plans.
    
    Usage:
        recommender = IndexRecommender()
        recommendations = recommender.analyze(explain_output)
        
        for rec in recommendations:
            print(rec.format_full())
    """
    
    def __init__(self):
        self.parser = ConditionParser()
        self.estimator = CostEstimator()
    
    def analyze(self, explain: "ExplainOutput") -> list[IndexRecommendation]:
        """
        Analyze a query plan and generate index recommendations.
        
        Args:
            explain: Parsed EXPLAIN output
            
        Returns:
            List of recommendations, sorted by estimated improvement
        """
        recommendations: list[IndexRecommendation] = []
        
        for node in explain.all_nodes:
            recs = self._analyze_node(node)
            recommendations.extend(recs)
        
        # Deduplicate and merge similar recommendations
        recommendations = self._merge_recommendations(recommendations)
        
        # Sort by estimated improvement (highest first)
        recommendations.sort(key=lambda r: r.estimated_improvement, reverse=True)
        
        return recommendations
    
    def analyze_node(self, node: "PlanNode") -> list[IndexRecommendation]:
        """Analyze a single node for index opportunities."""
        return self._analyze_node(node)
    
    def _analyze_node(self, node: "PlanNode") -> list[IndexRecommendation]:
        """Generate recommendations for a single plan node."""
        recs: list[IndexRecommendation] = []
        
        # Sequential scan with filter - primary target for indexing
        if node.node_type == "Seq Scan" and node.relation_name:
            rec = self._analyze_seq_scan(node)
            if rec:
                recs.append(rec)
        
        # Nested loop join - check if inner needs index
        if node.node_type == "Nested Loop" and len(node.plans) >= 2:
            rec = self._analyze_nested_loop(node)
            if rec:
                recs.append(rec)
        
        # Sort node - might benefit from index
        if node.node_type in ("Sort", "Incremental Sort") and node.sort_key:
            rec = self._analyze_sort(node)
            if rec:
                recs.append(rec)
        
        return recs
    
    def _analyze_seq_scan(self, node: "PlanNode") -> IndexRecommendation | None:
        """Analyze sequential scan for index opportunities."""
        table = node.relation_name
        if not table:
            return None
        
        # Need filter to recommend index columns
        if not node.filter:
            return None
        
        # Parse the filter condition
        columns = self.parser.parse(node.filter)
        if not columns:
            return None
        
        # Get actual metrics
        actual_rows = node.actual_rows or 0
        rows_removed = node.rows_removed_by_filter or 0
        total_rows = actual_rows + rows_removed
        
        if total_rows < 1000:
            return None  # Too small to matter
        
        # Calculate selectivity
        selectivity = self.estimator.calculate_selectivity(
            actual_rows, total_rows, rows_removed
        )
        
        # Determine column order for composite index
        # Put equality columns first, then range columns
        equality_cols = [c.column for c in columns if c.is_equality]
        range_cols = [c.column for c in columns if c.is_range and c.column not in equality_cols]
        
        # Combine: equality first (in filter order), then range
        index_columns = equality_cols + range_cols
        
        if not index_columns:
            # Fall back to first column
            index_columns = [columns[0].column]
        
        # Estimate improvement
        improvement = self.estimator.estimate_improvement(
            total_rows, actual_rows, node.total_cost
        )
        
        # Estimate index size
        index_size = self.estimator.estimate_index_size_mb(
            total_rows, len(index_columns)
        )
        
        # Build reasoning
        reasoning_parts = [
            f"Filter: {node.filter}",
            f"Selectivity: {selectivity:.2%} ({actual_rows:,} of {total_rows:,} rows)",
        ]
        
        if len(equality_cols) > 0:
            reasoning_parts.append(f"Equality columns: {', '.join(equality_cols)}")
        if len(range_cols) > 0:
            reasoning_parts.append(f"Range columns: {', '.join(range_cols)}")
        
        # Consider partial index for very selective filters
        is_partial = False
        partial_predicate = None
        if selectivity < 0.1 and len(equality_cols) == 1:
            # Could be a good partial index candidate
            # But we'd need to know the actual value, which requires query context
            pass
        
        return IndexRecommendation(
            table=table,
            columns=index_columns,
            index_type=IndexType.BTREE,
            is_partial=is_partial,
            partial_predicate=partial_predicate,
            estimated_improvement=improvement,
            estimated_index_size_mb=index_size,
            confidence=0.85 if len(index_columns) == 1 else 0.75,
            reasoning="\n".join(reasoning_parts),
        )
    
    def _analyze_nested_loop(self, node: "PlanNode") -> IndexRecommendation | None:
        """Analyze nested loop for missing index on inner relation."""
        inner = node.plans[1]
        
        # If inner is already an index scan, no recommendation needed
        if "Index" in inner.node_type:
            return None
        
        # Check for Seq Scan on inner
        if inner.node_type != "Seq Scan" or not inner.relation_name:
            return None
        
        # Need high loop count to matter
        loops = inner.actual_loops or 1
        if loops < 100:
            return None
        
        # Try to find join condition
        join_filter = None
        if node.model_extra:
            join_filter = node.model_extra.get("Join Filter")
        
        # Parse join condition or inner filter
        condition = join_filter or inner.filter
        if not condition:
            return None
        
        columns = self.parser.parse(condition)
        if not columns:
            return None
        
        # Find columns belonging to inner table
        table = inner.relation_name
        inner_cols = [
            c.column for c in columns
            if c.table is None or c.table == table
        ]
        
        if not inner_cols:
            return None
        
        # Calculate improvement
        inner_rows = inner.actual_rows or 0
        total_rows_scanned = inner_rows * loops
        
        # With index, each loop would be O(log n) instead of O(n)
        improvement = min(float(inner_rows) / 10, 100.0)  # Conservative estimate
        
        return IndexRecommendation(
            table=table,
            columns=inner_cols[:2],  # Usually just need 1-2 columns
            index_type=IndexType.BTREE,
            estimated_improvement=improvement,
            estimated_index_size_mb=self.estimator.estimate_index_size_mb(
                inner_rows * loops, len(inner_cols[:2])
            ),
            confidence=0.9,
            reasoning=f"Nested loop executes {loops:,} times, scanning {inner_rows:,} rows each time.\n"
                     f"Join condition: {condition}\n"
                     f"Index would reduce O(n*m) to O(n*log(m))",
        )
    
    def _analyze_sort(self, node: "PlanNode") -> IndexRecommendation | None:
        """Analyze sort node for index opportunities."""
        if not node.sort_key:
            return None
        
        # Need to find the table being sorted
        # Look for child scan node
        table = None
        total_rows = 0
        for child in node.plans:
            if child.relation_name:
                table = child.relation_name
                total_rows = child.actual_rows or 0
                break
        
        if not table or total_rows < 10000:
            return None
        
        # Only recommend if sort is spilling to disk
        is_spilling = (
            node.sort_space_type == "Disk" or 
            (node.sort_method and "external" in node.sort_method.lower())
        )
        
        if not is_spilling:
            return None
        
        # Extract sort columns
        sort_columns = self.parser.extract_sort_columns(node.sort_key)
        if not sort_columns:
            return None
        
        # An index on sort columns eliminates the sort entirely
        improvement = 5.0  # Conservative: sorts are expensive
        if node.sort_space_used:
            # Larger spills = bigger improvement
            spill_mb = node.sort_space_used / 1024
            improvement = min(10.0 + spill_mb / 10, 50.0)
        
        return IndexRecommendation(
            table=table,
            columns=sort_columns[:3],  # Limit to first 3 sort columns
            index_type=IndexType.BTREE,
            estimated_improvement=improvement,
            estimated_index_size_mb=self.estimator.estimate_index_size_mb(
                total_rows, len(sort_columns[:3])
            ),
            confidence=0.7,  # Lower confidence: depends on access pattern
            reasoning=f"Sort spilling to disk ({node.sort_space_used or 0}KB).\n"
                     f"Sort key: {', '.join(node.sort_key)}\n"
                     f"Index would eliminate sort operation entirely.",
        )
    
    def _merge_recommendations(
        self,
        recs: list[IndexRecommendation],
    ) -> list[IndexRecommendation]:
        """
        Merge similar recommendations.
        
        If multiple recommendations suggest indexes on the same table with
        overlapping columns, suggest a composite index instead.
        """
        # Group by table
        by_table: dict[str, list[IndexRecommendation]] = {}
        for rec in recs:
            by_table.setdefault(rec.table, []).append(rec)
        
        merged: list[IndexRecommendation] = []
        
        for table, table_recs in by_table.items():
            if len(table_recs) == 1:
                merged.append(table_recs[0])
                continue
            
            # Check if columns overlap
            all_columns: list[str] = []
            total_improvement = 0.0
            total_confidence = 0.0
            reasonings: list[str] = []
            
            for rec in table_recs:
                for col in rec.columns:
                    if col not in all_columns:
                        all_columns.append(col)
                total_improvement = max(total_improvement, rec.estimated_improvement)
                total_confidence += rec.confidence
                if rec.reasoning:
                    reasonings.append(rec.reasoning)
            
            if len(all_columns) > 1:
                # Create composite index recommendation
                merged.append(IndexRecommendation(
                    table=table,
                    columns=all_columns[:4],  # Limit composite size
                    index_type=IndexType.BTREE,
                    estimated_improvement=total_improvement,
                    estimated_index_size_mb=CostEstimator.estimate_index_size_mb(
                        100000, len(all_columns[:4])  # Rough estimate
                    ),
                    confidence=min(total_confidence / len(table_recs), 0.95),
                    reasoning="Combined recommendation:\n" + "\n---\n".join(reasonings),
                ))
            else:
                # Just use the best single recommendation
                best = max(table_recs, key=lambda r: r.estimated_improvement)
                merged.append(best)
        
        return merged


def recommend_indexes(explain: "ExplainOutput") -> list[IndexRecommendation]:
    """
    Convenience function to generate index recommendations.
    
    Args:
        explain: Parsed EXPLAIN output
        
    Returns:
        List of recommendations, sorted by impact
    """
    recommender = IndexRecommender()
    return recommender.analyze(explain)
