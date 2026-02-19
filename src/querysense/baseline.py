"""
Plan baseline storage and comparison for CI/CD regression detection.

Stores normalized plan shapes per query and compares against them on
subsequent runs. This is the persistence layer that enables:
- Plan shape regression detection (S-tier use case)
- Post-upgrade plan comparison
- Baseline management ("lock" a known-good plan)
- Regression severity scoring (not just "changed" but "how bad")

Storage format: JSON file committed to the repository (`.querysense/baselines.json`).
This ensures baselines travel with the code and are version-controlled.

Usage:
    from querysense.baseline import BaselineStore

    store = BaselineStore(".querysense/baselines.json")

    # Record a baseline
    store.record("get_user_by_id", explain_output)
    store.save()

    # Lock a plan (CI will hard-fail if it changes)
    store.lock("get_user_by_id", reason="Production critical path")
    store.save()

    # Compare against baseline
    diff = store.compare("get_user_by_id", current_explain)
    if diff.is_regression:
        print(f"Regression! Severity: {diff.regression_severity}")
        print(f"Danger score: {diff.danger_score}/100")
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput, PlanNode

logger = logging.getLogger(__name__)

# Schema version for baseline file format migration
BASELINE_SCHEMA_VERSION = "1.1"


class RegressionSeverity(str, Enum):
    """
    Severity of a plan regression, computed from structural and cost signals.

    Used by CI gating to decide whether to block a merge. Higher severity
    means higher risk of production incident.
    """

    NONE = "none"            # No regression detected
    LOW = "low"              # Minor cost increase, no structural change
    MEDIUM = "medium"        # Moderate cost increase or minor structural change
    HIGH = "high"            # Large cost increase or dangerous structural change
    CRITICAL = "critical"    # Scan type downgrade or locked plan violated


# Node type transitions ranked by danger (higher = worse)
# These represent transitions from efficient to inefficient access patterns.
_DANGEROUS_TRANSITIONS: dict[tuple[str, str], int] = {
    # Index -> Seq Scan: almost always a regression
    ("Index Scan", "Seq Scan"): 90,
    ("Index Only Scan", "Seq Scan"): 95,
    ("Bitmap Index Scan", "Seq Scan"): 80,
    ("Bitmap Heap Scan", "Seq Scan"): 70,
    # Index downgrade
    ("Index Only Scan", "Index Scan"): 30,
    ("Index Only Scan", "Bitmap Heap Scan"): 40,
    # Join type regressions
    ("Hash Join", "Nested Loop"): 60,
    ("Merge Join", "Nested Loop"): 65,
    ("Hash Join", "Merge Join"): 15,  # Merge join isn't always worse
    # Parallel -> serial
    ("Parallel Seq Scan", "Seq Scan"): 50,
    ("Gather Merge", "Sort"): 45,
    ("Gather", "Result"): 40,
    # Aggregation regressions
    ("HashAggregate", "GroupAggregate"): 25,
}


def _compute_transition_danger(before: str, after: str) -> int:
    """
    Score the danger of a node type transition (0-100).

    Known dangerous transitions get pre-assigned scores.
    Unknown transitions get a base score of 20 (structural change always has some risk).
    """
    return _DANGEROUS_TRANSITIONS.get((before, after), 20)


# Plausible cause mapping: what typically causes each class of regression
_PLAUSIBLE_CAUSES: dict[str, list[str]] = {
    "index_to_seq": [
        "Index was dropped or invalidated by a schema migration",
        "Statistics drift after bulk INSERT/UPDATE (run ANALYZE)",
        "Planner selectivity estimate changed due to data distribution shift",
        "New column or expression in WHERE clause not covered by existing index",
    ],
    "join_type_change": [
        "Row estimate change caused planner to pick a different join strategy",
        "Statistics on join columns are stale (run ANALYZE on both tables)",
        "work_mem change affected hash join feasibility",
        "Table size crossed a threshold that changed join cost estimates",
    ],
    "parallel_to_serial": [
        "max_parallel_workers_per_gather was reduced or set to 0",
        "Table fell below min_parallel_table_scan_size threshold",
        "Parallel-restricted function in query prevents parallel execution",
    ],
    "cost_increase": [
        "Table grew significantly since baseline was recorded",
        "Statistics are stale — run ANALYZE to refresh row estimates",
        "Index bloat is inflating random I/O cost estimates",
        "PostgreSQL version upgrade changed planner cost model",
    ],
    "plan_shape_change": [
        "PostgreSQL version upgrade changed planner heuristics",
        "Configuration change (e.g., random_page_cost, effective_cache_size)",
        "New extension or operator class affected plan selection",
        "Prepared statement switched from custom to generic plan",
    ],
    "locked_violation": [
        "Schema migration changed table structure or indexes",
        "Statistics refresh changed planner estimates",
        "PostgreSQL version upgrade changed planner behavior",
    ],
}


def _classify_transition(before: str, after: str) -> str:
    """Classify a node type transition into a cause category."""
    scan_types = {"Seq Scan", "Index Scan", "Index Only Scan", "Bitmap Heap Scan", "Bitmap Index Scan"}
    join_types = {"Hash Join", "Merge Join", "Nested Loop"}

    if before in scan_types and after == "Seq Scan" and before != "Seq Scan":
        return "index_to_seq"
    if before in join_types and after in join_types:
        return "join_type_change"
    if "Parallel" in before and "Parallel" not in after:
        return "parallel_to_serial"
    return "plan_shape_change"


@dataclass(frozen=True)
class RegressionVerdict:
    """
    Structured, explainable verdict for a plan regression.

    Answers four operational questions:
    1. What changed — structural diff summary
    2. Why it matters — severity with danger score rationale
    3. Who should care — affected tables/queries
    4. What to do next — plausible causes and recommended actions

    This is the primary product surface for plan regression prevention:
    a stable, explainable output that CI gates and PR comments consume.
    """

    query_id: str
    severity: RegressionSeverity
    danger_score: int

    # What changed
    structural_changes: tuple[str, ...] = ()
    cost_change_summary: str = ""
    critical_transitions: tuple[str, ...] = ()

    # Why it matters
    rationale: str = ""

    # Plausible causes (domain-grounded explanations)
    plausible_causes: tuple[str, ...] = ()

    # Recommended next actions
    recommended_actions: tuple[str, ...] = ()

    # Plan control suggestions (pg_hint_plan, Aurora QPM, etc.)
    plan_control_hints: tuple[str, ...] = ()

    # Whether this is a locked plan violation
    locked_violation: bool = False
    lock_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON output."""
        return {
            "query_id": self.query_id,
            "severity": self.severity.value,
            "danger_score": self.danger_score,
            "structural_changes": list(self.structural_changes),
            "cost_change_summary": self.cost_change_summary,
            "critical_transitions": list(self.critical_transitions),
            "rationale": self.rationale,
            "plausible_causes": list(self.plausible_causes),
            "recommended_actions": list(self.recommended_actions),
            "plan_control_hints": list(self.plan_control_hints),
            "locked_violation": self.locked_violation,
            "lock_reason": self.lock_reason,
        }

    def format_summary(self) -> str:
        """Human-readable multi-line summary suitable for terminal or PR comment."""
        lines: list[str] = []

        # Header with severity badge
        sev = self.severity.value.upper()
        lines.append(f"Regression Verdict: {sev} (danger: {self.danger_score}/100)")

        if self.locked_violation:
            lines.append(f"  LOCKED PLAN VIOLATED — {self.lock_reason or 'no reason specified'}")

        # What changed
        if self.structural_changes:
            lines.append("  What changed:")
            for change in self.structural_changes:
                lines.append(f"    - {change}")
        if self.cost_change_summary:
            lines.append(f"  Cost: {self.cost_change_summary}")

        # Why it matters
        if self.rationale:
            lines.append(f"  Why it matters: {self.rationale}")

        # Plausible causes
        if self.plausible_causes:
            lines.append("  Plausible causes:")
            for cause in self.plausible_causes:
                lines.append(f"    - {cause}")

        # Recommended actions
        if self.recommended_actions:
            lines.append("  Recommended actions:")
            for action in self.recommended_actions:
                lines.append(f"    - {action}")

        # Plan control hints
        if self.plan_control_hints:
            lines.append("  Plan control options:")
            for hint in self.plan_control_hints:
                lines.append(f"    - {hint}")

        return "\n".join(lines)


@dataclass(frozen=True)
class BaselineDiff:
    """
    Result of comparing a plan against its baseline.

    Provides detailed structural and metric changes between the
    baseline plan and the current plan, plus severity scoring.
    """

    query_id: str
    status: str  # "NO_BASELINE", "UNCHANGED", "CHANGED"

    # Structural changes
    node_type_changes: list[dict[str, str]] = field(default_factory=list)
    nodes_added: list[str] = field(default_factory=list)
    nodes_removed: list[str] = field(default_factory=list)

    # Metric changes
    cost_before: float = 0.0
    cost_after: float = 0.0
    row_estimate_before: int = 0
    row_estimate_after: int = 0

    # Fingerprints
    baseline_structure_hash: str = ""
    current_structure_hash: str = ""

    # Lock state
    is_locked: bool = False
    lock_reason: str = ""

    @property
    def has_structural_changes(self) -> bool:
        """True if the plan structure changed (node types, joins, scans)."""
        return bool(self.node_type_changes or self.nodes_added or self.nodes_removed)

    @property
    def has_cost_regression(self) -> bool:
        """True if total cost increased."""
        return self.cost_after > self.cost_before and self.cost_before > 0

    @property
    def cost_change_percent(self) -> float:
        """Percent change in total cost. Positive = regression."""
        if self.cost_before == 0:
            return 0.0
        return ((self.cost_after - self.cost_before) / self.cost_before) * 100

    @property
    def is_regression(self) -> bool:
        """True if this represents a plan regression."""
        return self.has_structural_changes or self.has_cost_regression

    @property
    def danger_score(self) -> int:
        """
        Composite danger score (0-100) combining structural and cost signals.

        Scoring:
        - Node type transitions: max danger of all transitions (0-95)
        - Cost regression: scaled by magnitude (0-40)
        - Nodes added/removed: 10 points each
        - Locked plan violated: automatically 100

        The score is capped at 100.
        """
        if self.status != "CHANGED":
            return 0

        if self.is_locked:
            return 100

        score = 0

        # Structural danger: worst transition wins
        if self.node_type_changes:
            transition_scores = [
                _compute_transition_danger(change["before"], change["after"])
                for change in self.node_type_changes
            ]
            score = max(score, max(transition_scores))

        # Nodes added/removed contribute
        score += min(len(self.nodes_added) * 10, 30)
        score += min(len(self.nodes_removed) * 10, 30)

        # Cost regression contribution (0-40 points)
        pct = self.cost_change_percent
        if pct > 0:
            if pct > 500:
                score += 40
            elif pct > 100:
                score += 30
            elif pct > 50:
                score += 20
            elif pct > 10:
                score += 10
            else:
                score += 5

        return min(score, 100)

    @property
    def regression_severity(self) -> RegressionSeverity:
        """
        Compute regression severity from danger score.

        Thresholds:
        - CRITICAL: danger >= 80 or locked plan violated
        - HIGH: danger >= 50
        - MEDIUM: danger >= 20
        - LOW: danger > 0
        - NONE: no changes
        """
        ds = self.danger_score
        if ds == 0:
            return RegressionSeverity.NONE
        if ds >= 80 or self.is_locked:
            return RegressionSeverity.CRITICAL
        if ds >= 50:
            return RegressionSeverity.HIGH
        if ds >= 20:
            return RegressionSeverity.MEDIUM
        return RegressionSeverity.LOW

    def summary(self) -> str:
        """Human-readable summary of changes."""
        if self.status == "NO_BASELINE":
            return "No baseline recorded (new query)"
        if self.status == "UNCHANGED":
            return "Plan unchanged from baseline"

        parts: list[str] = []

        # Show lock violation prominently
        if self.is_locked:
            parts.append(f"  LOCKED PLAN VIOLATED (reason: {self.lock_reason or 'not specified'})")

        # Show severity and danger score
        parts.append(
            f"  Regression severity: {self.regression_severity.value.upper()} "
            f"(danger score: {self.danger_score}/100)"
        )

        if self.node_type_changes:
            for change in self.node_type_changes:
                danger = _compute_transition_danger(change["before"], change["after"])
                parts.append(
                    f"  {change['path']}: {change['before']} -> {change['after']} "
                    f"(danger: {danger})"
                )
        if self.nodes_added:
            for node in self.nodes_added:
                parts.append(f"  + {node}")
        if self.nodes_removed:
            for node in self.nodes_removed:
                parts.append(f"  - {node}")
        if self.has_cost_regression:
            parts.append(f"  Cost: {self.cost_before:.0f} -> {self.cost_after:.0f} ({self.cost_change_percent:+.1f}%)")

        header = "Plan CHANGED from baseline:"
        return "\n".join([header, *parts]) if parts else header

    def verdict(self) -> RegressionVerdict:
        """
        Build a structured, explainable regression verdict.

        Produces a RegressionVerdict that answers: what changed, why it matters,
        plausible causes, and recommended next actions. This is the primary
        product surface for plan regression prevention.

        Returns:
            RegressionVerdict if status is CHANGED, or a no-regression verdict otherwise
        """
        if self.status != "CHANGED":
            return RegressionVerdict(
                query_id=self.query_id,
                severity=RegressionSeverity.NONE,
                danger_score=0,
                rationale="No regression detected" if self.status == "UNCHANGED"
                else "No baseline recorded for this query",
            )

        # --- What changed ---
        structural_changes: list[str] = []
        critical_transitions: list[str] = []
        cause_categories: set[str] = set()

        for change in self.node_type_changes:
            danger = _compute_transition_danger(change["before"], change["after"])
            relation = f" on {change.get('relation', '')}" if change.get("relation") else ""
            desc = f"{change['before']} -> {change['after']}{relation} (danger: {danger})"
            structural_changes.append(desc)

            if danger >= 60:
                critical_transitions.append(desc)

            category = _classify_transition(change["before"], change["after"])
            cause_categories.add(category)

        for node in self.nodes_added:
            structural_changes.append(f"+ {node}")
        for node in self.nodes_removed:
            structural_changes.append(f"- {node}")

        # Cost summary
        cost_summary = ""
        if self.has_cost_regression:
            cost_summary = (
                f"{self.cost_before:.0f} -> {self.cost_after:.0f} "
                f"({self.cost_change_percent:+.1f}%)"
            )
            if not cause_categories:
                cause_categories.add("cost_increase")

        # --- Why it matters ---
        severity = self.regression_severity
        rationale_parts: list[str] = []

        if self.is_locked:
            rationale_parts.append(
                "This query's plan is LOCKED, meaning any structural change "
                "is treated as critical. Locked plans are typically production "
                "critical paths that have been explicitly validated."
            )
            cause_categories.add("locked_violation")
        elif critical_transitions:
            rationale_parts.append(
                "High-danger transitions detected: efficient access methods "
                "(index scans, hash joins) replaced by less efficient ones "
                "(sequential scans, nested loops). This pattern frequently "
                "causes production incidents."
            )
        elif self.has_cost_regression and self.cost_change_percent > 100:
            rationale_parts.append(
                f"Cost increased by {self.cost_change_percent:.0f}%, which "
                "suggests the planner found a significantly worse execution path. "
                "Large cost regressions often indicate missing indexes or stale statistics."
            )
        elif structural_changes:
            rationale_parts.append(
                "Plan structure changed from baseline. While not all structural "
                "changes cause performance regressions, they indicate the planner "
                "chose a different execution strategy."
            )

        rationale = " ".join(rationale_parts)

        # --- Plausible causes ---
        plausible_causes: list[str] = []
        seen_causes: set[str] = set()
        for category in sorted(cause_categories):
            for cause in _PLAUSIBLE_CAUSES.get(category, []):
                if cause not in seen_causes:
                    plausible_causes.append(cause)
                    seen_causes.add(cause)

        # --- Recommended actions ---
        actions: list[str] = []
        if any(cat in cause_categories for cat in ("index_to_seq", "cost_increase")):
            actions.append("Run ANALYZE on affected tables to refresh planner statistics")
            actions.append("Check for recent schema migrations that dropped or changed indexes")
        if "join_type_change" in cause_categories:
            actions.append("Run ANALYZE on both sides of the join to refresh selectivity estimates")
            actions.append("Check if work_mem is sufficient for hash join on the current data volume")
        if "parallel_to_serial" in cause_categories:
            actions.append("Verify max_parallel_workers_per_gather setting")
        if self.is_locked:
            actions.append("Review the schema migration that caused this change")
            actions.append("If the new plan is correct, unlock and re-lock with the new baseline")

        # Always suggest baseline review
        actions.append(
            "Compare plans side-by-side: "
            "querysense baseline diff <plan_file>"
        )

        # --- Plan control hints ---
        plan_hints: list[str] = []
        if critical_transitions or self.is_locked:
            plan_hints.append(
                "pg_hint_plan: Use /*+ SeqScan(t) */ or /*+ IndexScan(t idx) */ "
                "to force a specific access method"
            )
            plan_hints.append(
                "Aurora PostgreSQL: Use apg_plan_mgmt.evolve_plan_baselines() "
                "to approve/reject new plans"
            )
            plan_hints.append(
                "Query Store (SQL Server): Use sp_query_store_force_plan to "
                "pin the known-good plan"
            )

        return RegressionVerdict(
            query_id=self.query_id,
            severity=severity,
            danger_score=self.danger_score,
            structural_changes=tuple(structural_changes),
            cost_change_summary=cost_summary,
            critical_transitions=tuple(critical_transitions),
            rationale=rationale,
            plausible_causes=tuple(plausible_causes[:5]),  # Cap at 5 most relevant
            recommended_actions=tuple(actions),
            plan_control_hints=tuple(plan_hints),
            locked_violation=self.is_locked,
            lock_reason=self.lock_reason,
        )


def _normalize_plan_tree(node: PlanNode, path: str = "0") -> list[dict[str, Any]]:
    """
    Extract structural skeleton from a plan tree.

    Strips timing, costs, and buffer data — keeps only the shape:
    node types, relation names, index names, join types.
    This produces a stable representation for structural comparison.
    """
    entry: dict[str, Any] = {
        "path": path,
        "node_type": node.node_type,
    }

    if node.relation_name:
        entry["relation_name"] = node.relation_name
    if node.index_name:
        entry["index_name"] = node.index_name
    if node.join_type:
        entry["join_type"] = node.join_type

    result = [entry]

    for i, child in enumerate(node.plans):
        child_path = f"{path}.{i}"
        result.extend(_normalize_plan_tree(child, child_path))

    return result


def _compute_structure_hash(normalized: list[dict[str, Any]]) -> str:
    """Compute a stable hash of the normalized plan structure."""
    content = json.dumps(normalized, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


class BaselineStore:
    """
    Manages plan baseline storage and comparison.

    Baselines are stored as a JSON file containing normalized plan trees
    keyed by query identifier. The file is designed to be committed to
    version control alongside the code.

    Supports plan locking: locked baselines cause CI to hard-fail if the
    plan changes at all, regardless of severity thresholds.

    Example:
        store = BaselineStore(".querysense/baselines.json")

        # Record baselines from current EXPLAIN output
        store.record("users_by_email", explain_output)
        store.save()

        # Lock a critical query
        store.lock("users_by_email", reason="Production critical path")
        store.save()

        # Later, compare against baseline
        diff = store.compare("users_by_email", new_explain)
        if diff.is_locked and diff.has_structural_changes:
            print("LOCKED plan violated!")
    """

    def __init__(self, baseline_path: str | Path = ".querysense/baselines.json") -> None:
        self.path = Path(baseline_path)
        self.baselines: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        """Load existing baselines or return empty structure."""
        if not self.path.exists():
            return {"schema_version": BASELINE_SCHEMA_VERSION, "queries": {}}

        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            # Migrate from 1.0 to 1.1 (add locked field to existing entries)
            stored_version = data.get("schema_version", "1.0")
            if stored_version == "1.0":
                logger.info("Migrating baselines from schema 1.0 to 1.1")
                for _qid, entry in data.get("queries", {}).items():
                    entry.setdefault("locked", False)
                    entry.setdefault("lock_reason", "")
                data["schema_version"] = BASELINE_SCHEMA_VERSION
            return data
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load baselines from %s: %s", self.path, e)
            return {"schema_version": BASELINE_SCHEMA_VERSION, "queries": {}}

    def save(self) -> None:
        """Persist baselines to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self.baselines, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        logger.info("Baselines saved to %s (%d queries)", self.path, len(self.queries))

    @property
    def queries(self) -> dict[str, Any]:
        """Get the queries dict from the baselines."""
        return self.baselines.get("queries", {})

    def record(self, query_id: str, explain: ExplainOutput) -> str:
        """
        Store normalized plan as baseline.

        Args:
            query_id: Unique identifier for the query (e.g., filename, hash, label)
            explain: Parsed EXPLAIN output to record as baseline

        Returns:
            Structure hash of the recorded baseline
        """
        normalized = _normalize_plan_tree(explain.plan)
        structure_hash = _compute_structure_hash(normalized)

        # Preserve lock state if already locked
        existing = self.baselines.get("queries", {}).get(query_id, {})
        is_locked = existing.get("locked", False)
        lock_reason = existing.get("lock_reason", "")

        self.baselines.setdefault("queries", {})[query_id] = {
            "normalized_plan": normalized,
            "structure_hash": structure_hash,
            "total_cost": explain.plan.total_cost,
            "plan_rows": explain.plan.plan_rows,
            "node_count": len(explain.all_nodes),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "locked": is_locked,
            "lock_reason": lock_reason,
        }

        logger.debug(
            "Recorded baseline for %s (hash=%s, nodes=%d, locked=%s)",
            query_id,
            structure_hash,
            len(explain.all_nodes),
            is_locked,
        )

        return structure_hash

    def has_baseline(self, query_id: str) -> bool:
        """Check if a baseline exists for a query."""
        return query_id in self.queries

    def is_query_locked(self, query_id: str) -> bool:
        """Check if a query's baseline is locked."""
        entry = self.queries.get(query_id, {})
        return bool(entry.get("locked", False))

    def lock(self, query_id: str, reason: str = "") -> bool:
        """
        Lock a baseline - CI will hard-fail if this plan changes.

        A locked baseline means "this query plan must not change under any
        circumstances." Use for production critical paths, compliance-sensitive
        queries, or recently-validated plans.

        Args:
            query_id: The query to lock
            reason: Human-readable reason for locking (shows in reports)

        Returns:
            True if locked, False if query_id not found
        """
        queries = self.baselines.get("queries", {})
        if query_id not in queries:
            return False

        queries[query_id]["locked"] = True
        queries[query_id]["lock_reason"] = reason
        queries[query_id]["locked_at"] = datetime.now(timezone.utc).isoformat()
        logger.info("Locked baseline for %s (reason: %s)", query_id, reason or "none")
        return True

    def unlock(self, query_id: str) -> bool:
        """
        Unlock a baseline - plan changes will be subject to normal severity scoring.

        Args:
            query_id: The query to unlock

        Returns:
            True if unlocked, False if query_id not found
        """
        queries = self.baselines.get("queries", {})
        if query_id not in queries:
            return False

        queries[query_id]["locked"] = False
        queries[query_id]["lock_reason"] = ""
        queries[query_id].pop("locked_at", None)
        logger.info("Unlocked baseline for %s", query_id)
        return True

    def compare(self, query_id: str, current_explain: ExplainOutput) -> BaselineDiff:
        """
        Compare current plan against stored baseline.

        Args:
            query_id: The query identifier to compare against
            current_explain: Current EXPLAIN output

        Returns:
            BaselineDiff with structural/metric changes and severity scoring
        """
        if query_id not in self.queries:
            return BaselineDiff(
                query_id=query_id,
                status="NO_BASELINE",
            )

        baseline = self.queries[query_id]
        baseline_normalized = baseline["normalized_plan"]
        baseline_hash = baseline["structure_hash"]
        is_locked = baseline.get("locked", False)
        lock_reason = baseline.get("lock_reason", "")

        current_normalized = _normalize_plan_tree(current_explain.plan)
        current_hash = _compute_structure_hash(current_normalized)

        # Fast path: structural hash match means no changes
        if baseline_hash == current_hash:
            return BaselineDiff(
                query_id=query_id,
                status="UNCHANGED",
                cost_before=baseline.get("total_cost", 0),
                cost_after=current_explain.plan.total_cost,
                row_estimate_before=baseline.get("plan_rows", 0),
                row_estimate_after=current_explain.plan.plan_rows,
                baseline_structure_hash=baseline_hash,
                current_structure_hash=current_hash,
                is_locked=is_locked,
                lock_reason=lock_reason,
            )

        # Detailed diff
        node_type_changes, nodes_added, nodes_removed = _diff_normalized_plans(
            baseline_normalized, current_normalized
        )

        return BaselineDiff(
            query_id=query_id,
            status="CHANGED",
            node_type_changes=node_type_changes,
            nodes_added=nodes_added,
            nodes_removed=nodes_removed,
            cost_before=baseline.get("total_cost", 0),
            cost_after=current_explain.plan.total_cost,
            row_estimate_before=baseline.get("plan_rows", 0),
            row_estimate_after=current_explain.plan.plan_rows,
            baseline_structure_hash=baseline_hash,
            current_structure_hash=current_hash,
            is_locked=is_locked,
            lock_reason=lock_reason,
        )

    def remove(self, query_id: str) -> bool:
        """Remove a baseline entry."""
        queries = self.baselines.get("queries", {})
        if query_id in queries:
            del queries[query_id]
            return True
        return False

    def list_queries(self) -> list[str]:
        """List all query IDs with baselines."""
        return list(self.queries.keys())

    def locked_queries(self) -> list[str]:
        """List all locked query IDs."""
        return [
            qid for qid, entry in self.queries.items()
            if entry.get("locked", False)
        ]

    def stats(self) -> dict[str, Any]:
        """Get baseline store statistics."""
        queries = self.queries
        locked_count = sum(1 for q in queries.values() if q.get("locked", False))
        return {
            "total_queries": len(queries),
            "locked_queries": locked_count,
            "schema_version": self.baselines.get("schema_version", "unknown"),
            "path": str(self.path),
            "exists": self.path.exists(),
        }


def _diff_normalized_plans(
    baseline: list[dict[str, Any]],
    current: list[dict[str, Any]],
) -> tuple[list[dict[str, str]], list[str], list[str]]:
    """
    Diff two normalized plan trees.

    Delegates to the shared plan_diff utility for the actual comparison.

    Returns:
        Tuple of (node_type_changes, nodes_added, nodes_removed)
    """
    from querysense.plan_diff import diff_plan_nodes

    baseline_by_path = {n["path"]: n for n in baseline}
    current_by_path = {n["path"]: n for n in current}

    return diff_plan_nodes(baseline_by_path, current_by_path)
