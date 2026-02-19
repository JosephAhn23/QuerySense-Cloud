"""
Plan fingerprinting for caching.

Simple, stable identifiers for query plans to enable:
- Caching analysis results across runs
- Detecting if a plan has changed
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult
    from querysense.ir.plan import IRNode, IRPlan
    from querysense.parser.models import ExplainOutput

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PlanFingerprint:
    """
    Stable identifier for a query plan.
    
    Used for caching - if fingerprint matches, plan is the same.
    """
    
    query_hash: str       # Hash of query text
    structure_hash: str   # Hash of plan structure (node types)
    data_hash: str        # Hash of row counts and costs
    node_count: int = 0
    
    @classmethod
    def from_explain(cls, explain: "ExplainOutput") -> "PlanFingerprint":
        """Create fingerprint from EXPLAIN output."""
        # Hash query text
        query_text = explain.query_text or ""
        query_hash = hashlib.sha256(query_text.encode()).hexdigest()[:16]
        
        # Get all nodes (iter_nodes is on PlanNode, not ExplainOutput)
        all_nodes = explain.all_nodes
        
        # Hash structure (node types and relations)
        structure_parts = []
        for node in all_nodes:
            structure_parts.append(f"{node.node_type}:{node.relation_name or ''}")
        structure_hash = hashlib.sha256(
            "|".join(structure_parts).encode()
        ).hexdigest()[:16]
        
        # Hash data (row counts, costs)
        data_parts = []
        for node in all_nodes:
            data_parts.append(f"{node.actual_rows}:{node.total_cost:.2f}")
        data_hash = hashlib.sha256(
            "|".join(data_parts).encode()
        ).hexdigest()[:16]
        
        return cls(
            query_hash=query_hash,
            structure_hash=structure_hash,
            data_hash=data_hash,
            node_count=len(all_nodes),
        )
    
    @property
    def full_hash(self) -> str:
        """Full hash combining all components."""
        combined = f"{self.query_hash}:{self.structure_hash}:{self.data_hash}"
        return hashlib.sha256(combined.encode()).hexdigest()[:32]
    
    def diff(self, other: "PlanFingerprint") -> "PlanDiff":
        """Compare with another fingerprint."""
        return PlanDiff(
            query_changed=(self.query_hash != other.query_hash),
            structure_changed=(self.structure_hash != other.structure_hash),
            data_changed=(self.data_hash != other.data_hash),
        )


@dataclass(frozen=True)
class IRPlanFingerprint:
    """
    Cross-engine plan fingerprint based on the universal IR.

    Unlike PlanFingerprint (which works on engine-specific PlanNodes),
    this fingerprint operates on the normalized IR representation,
    enabling cross-engine plan comparison.

    Three hash components (mirroring SQL Server's query_plan_hash approach):
    - operator_hash: Hash of the operator tree shape (categories + strategies)
    - topology_hash: Hash of tree structure (branching factor, depth)
    - cardinality_hash: Hash of estimated row counts (engine-comparable)

    Plans from different engines that perform equivalent operations
    (e.g., Hash Join → Filter → Index Scan on table X) will produce
    the same operator_hash and topology_hash.
    """

    operator_hash: str      # Hash of operator categories + strategies
    topology_hash: str       # Hash of tree shape (children counts, depth)
    cardinality_hash: str    # Hash of estimated row counts
    engine: str              # Source engine (for provenance)
    node_count: int = 0

    @classmethod
    def from_ir_plan(cls, ir_plan: "IRPlan") -> "IRPlanFingerprint":
        """Create a cross-engine fingerprint from an IR plan."""
        op_parts: list[str] = []
        topo_parts: list[str] = []
        card_parts: list[str] = []
        node_count = 0

        def _walk(node: "IRNode", depth: int) -> None:
            nonlocal node_count
            node_count += 1

            # Operator hash: operator enum + algorithm (engine-agnostic)
            op_parts.append(f"{node.operator.value}:{node.algorithm}")

            # Topology hash: depth + children count
            topo_parts.append(f"{depth}:{len(node.children)}")

            # Cardinality hash: estimated rows (cross-engine comparable)
            card = node.properties.cardinality
            est = card.estimated_rows if card.estimated_rows is not None else -1
            card_parts.append(str(est))

            for child in node.children:
                _walk(child, depth + 1)

        _walk(ir_plan.root, 0)

        operator_hash = hashlib.sha256(
            "|".join(op_parts).encode()
        ).hexdigest()[:16]
        topology_hash = hashlib.sha256(
            "|".join(topo_parts).encode()
        ).hexdigest()[:16]
        cardinality_hash = hashlib.sha256(
            "|".join(card_parts).encode()
        ).hexdigest()[:16]

        return cls(
            operator_hash=operator_hash,
            topology_hash=topology_hash,
            cardinality_hash=cardinality_hash,
            engine=ir_plan.engine,
            node_count=node_count,
        )

    @property
    def structure_hash(self) -> str:
        """Combined operator + topology hash (plan shape, no data)."""
        combined = f"{self.operator_hash}:{self.topology_hash}"
        return hashlib.sha256(combined.encode()).hexdigest()[:24]

    @property
    def full_hash(self) -> str:
        """Full hash including cardinality data."""
        combined = (
            f"{self.operator_hash}:{self.topology_hash}:{self.cardinality_hash}"
        )
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    def is_same_shape(self, other: "IRPlanFingerprint") -> bool:
        """
        Check if two plans have the same logical shape.

        Plans from different engines that perform equivalent operations
        will match on shape even if cardinalities differ.
        """
        return (
            self.operator_hash == other.operator_hash
            and self.topology_hash == other.topology_hash
        )

    def diff(self, other: "IRPlanFingerprint") -> "IRPlanDiff":
        """Compare with another IR fingerprint."""
        return IRPlanDiff(
            operator_changed=self.operator_hash != other.operator_hash,
            topology_changed=self.topology_hash != other.topology_hash,
            cardinality_changed=self.cardinality_hash != other.cardinality_hash,
            engine_changed=self.engine != other.engine,
        )


@dataclass(frozen=True)
class IRPlanDiff:
    """Difference between two IR plan fingerprints."""

    operator_changed: bool
    topology_changed: bool
    cardinality_changed: bool
    engine_changed: bool

    @property
    def is_identical(self) -> bool:
        return not (
            self.operator_changed
            or self.topology_changed
            or self.cardinality_changed
        )

    @property
    def shape_changed(self) -> bool:
        """True if the plan's logical shape changed."""
        return self.operator_changed or self.topology_changed

    @property
    def needs_reanalysis(self) -> bool:
        return self.operator_changed or self.topology_changed


@dataclass
class PlanDiff:
    """Difference between two plan fingerprints."""
    
    query_changed: bool
    structure_changed: bool
    data_changed: bool
    
    @property
    def is_identical(self) -> bool:
        """True if plans are exactly the same."""
        return not (self.query_changed or self.structure_changed or self.data_changed)
    
    @property
    def needs_reanalysis(self) -> bool:
        """True if we need to re-run analysis."""
        return self.query_changed or self.structure_changed


@dataclass
class CachedAnalysis:
    """Cached analysis result."""
    
    fingerprint: PlanFingerprint
    result: "AnalysisResult"
    cached_at: float = field(default_factory=time.time)
    
    def is_expired(self, ttl_seconds: float) -> bool:
        """Check if cache entry has expired."""
        return (time.time() - self.cached_at) > ttl_seconds


class AnalysisCache:
    """
    Simple in-memory LRU cache for analysis results.
    
    Supports two cache key strategies:
    1. Simple: fingerprint.full_hash (plan structure only)
    2. Extended: reproducibility.cache_key (plan + SQL + config + rules)
    
    Use get_extended/set_extended for full cache correctness.
    
    Example:
        cache = AnalysisCache(max_size=100, ttl_seconds=300)
        
        fingerprint = PlanFingerprint.from_explain(explain)
        cached = cache.get(fingerprint)
        
        if cached:
            return cached.result
        
        result = analyzer.analyze(explain)
        cache.set(fingerprint, result)
    """
    
    def __init__(
        self,
        max_size: int = 100,
        ttl_seconds: float = 300.0,  # 5 minutes
    ) -> None:
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, CachedAnalysis] = OrderedDict()
        self._hits = 0
        self._misses = 0
    
    def get(self, fingerprint: PlanFingerprint) -> CachedAnalysis | None:
        """Get cached result if available and not expired (simple key)."""
        key = fingerprint.full_hash
        
        if key in self._cache:
            cached = self._cache[key]
            
            if cached.is_expired(self.ttl_seconds):
                del self._cache[key]
                self._misses += 1
                return None
            
            # Move to end (LRU)
            self._cache.move_to_end(key)
            self._hits += 1
            return cached
        
        self._misses += 1
        return None
    
    def get_extended(self, cache_key: str) -> CachedAnalysis | None:
        """
        Get cached result using extended cache key.
        
        The extended key includes: plan_hash + sql_hash + config_hash + rules_hash
        This is the correct way to cache results.
        
        Args:
            cache_key: The reproducibility.cache_key value
            
        Returns:
            CachedAnalysis if found and not expired, None otherwise
        """
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            
            if cached.is_expired(self.ttl_seconds):
                del self._cache[cache_key]
                self._misses += 1
                return None
            
            # Move to end (LRU)
            self._cache.move_to_end(cache_key)
            self._hits += 1
            return cached
        
        self._misses += 1
        return None
    
    def set(self, fingerprint: PlanFingerprint, result: "AnalysisResult") -> None:
        """Cache an analysis result (simple key)."""
        key = fingerprint.full_hash
        self._set_internal(key, fingerprint, result)
    
    def set_extended(
        self,
        cache_key: str,
        fingerprint: PlanFingerprint,
        result: "AnalysisResult",
    ) -> None:
        """
        Cache an analysis result using extended cache key.
        
        Args:
            cache_key: The reproducibility.cache_key value
            fingerprint: The plan fingerprint
            result: The analysis result
        """
        self._set_internal(cache_key, fingerprint, result)
    
    def _set_internal(
        self,
        key: str,
        fingerprint: PlanFingerprint,
        result: "AnalysisResult",
    ) -> None:
        """Internal set method."""
        # Evict oldest if at capacity
        while len(self._cache) >= self.max_size:
            self._cache.popitem(last=False)
        
        self._cache[key] = CachedAnalysis(
            fingerprint=fingerprint,
            result=result,
        )
    
    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()
        self._hits = 0
        self._misses = 0
    
    @property
    def hit_rate(self) -> float:
        """Cache hit rate (0.0 to 1.0)."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0
    
    @property
    def size(self) -> int:
        """Current number of cached entries."""
        return len(self._cache)
    
    def stats(self) -> dict[str, Any]:
        """Get cache statistics for observability."""
        return {
            "size": self.size,
            "max_size": self.max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self.hit_rate,
            "ttl_seconds": self.ttl_seconds,
        }