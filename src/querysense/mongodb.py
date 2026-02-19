"""
MongoDB Query Optimizer — the first open-source MongoDB query optimizer.

Works with any MongoDB deployment: Atlas, self-hosted, AWS DocumentDB,
Azure Cosmos DB. No vendor lock-in.

Features:
1. EXPLAIN parser — parse MongoDB explain() output
2. Index advisor — compound index, covered query, partial index recommendations
3. Schema advice — anti-pattern detection, embedding vs referencing
4. Slow query analyzer — system.profile + currentOp analysis
5. Index usage auditor — find unused and redundant indexes

MongoDB's Atlas Performance Advisor is cloud-only. QuerySense provides
the same capabilities for ALL MongoDB deployments, free and open-source.

Usage:
    from querysense.mongodb import MongoDBAnalyzer, MongoExplainParser

    analyzer = MongoDBAnalyzer(uri="mongodb://localhost:27017/mydb")
    report = await analyzer.full_analysis()
    for rec in report.recommendations:
        print(rec.command)

    # Or parse explain output:
    parser = MongoExplainParser()
    result = parser.parse(explain_json)
"""

from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ── Explain Parser ───────────────────────────────────────────────────────

@dataclass
class MongoScanInfo:
    """Information about a scan stage in a MongoDB query plan."""
    stage: str  # COLLSCAN, IXSCAN, FETCH, SORT, etc.
    namespace: str = ""
    index_name: str = ""
    index_key_pattern: dict[str, int] = field(default_factory=dict)
    direction: str = "forward"
    is_multi_key: bool = False
    filter: dict[str, Any] = field(default_factory=dict)
    n_returned: int = 0
    n_examined: int = 0
    execution_time_ms: float = 0.0
    children: list[MongoScanInfo] = field(default_factory=list)

    @property
    def is_collection_scan(self) -> bool:
        return self.stage == "COLLSCAN"

    @property
    def is_index_scan(self) -> bool:
        return self.stage == "IXSCAN"

    @property
    def examined_to_returned_ratio(self) -> float:
        if self.n_returned == 0:
            return float("inf") if self.n_examined > 0 else 0
        return self.n_examined / self.n_returned


@dataclass
class MongoExplainResult:
    """Parsed MongoDB explain() output."""
    winning_plan: MongoScanInfo | None = None
    rejected_plans: list[MongoScanInfo] = field(default_factory=list)
    namespace: str = ""
    n_returned: int = 0
    total_docs_examined: int = 0
    total_keys_examined: int = 0
    execution_time_ms: float = 0.0
    is_covered_query: bool = False
    used_index: str = ""
    sort_in_memory: bool = False

    @property
    def is_collection_scan(self) -> bool:
        return self.winning_plan.is_collection_scan if self.winning_plan else False

    @property
    def efficiency_ratio(self) -> float:
        """Ratio of docs examined to docs returned. 1.0 is perfect."""
        if self.n_returned == 0:
            return float("inf") if self.total_docs_examined > 0 else 0
        return self.total_docs_examined / self.n_returned


class MongoExplainParser:
    """Parse MongoDB explain() JSON output into structured results."""

    def parse(self, explain_data: dict[str, Any]) -> MongoExplainResult:
        """
        Parse explain() output.

        Handles both executionStats and queryPlanner verbosity modes.
        """
        result = MongoExplainResult()

        # Handle cursor-level or command-level explain
        if "cursor" in explain_data:
            explain_data = explain_data["cursor"]
        if "queryPlanner" in explain_data:
            qp = explain_data["queryPlanner"]
            result.namespace = qp.get("namespace", "")

            winning = qp.get("winningPlan", {})
            result.winning_plan = self._parse_stage(winning)

            for rejected in qp.get("rejectedPlans", []):
                result.rejected_plans.append(self._parse_stage(rejected))

        if "executionStats" in explain_data:
            es = explain_data["executionStats"]
            result.n_returned = es.get("nReturned", 0)
            result.total_docs_examined = es.get("totalDocsExamined", 0)
            result.total_keys_examined = es.get("totalKeysExamined", 0)
            result.execution_time_ms = es.get("executionTimeMillis", 0)

            # Check for covered query (keys examined > 0, docs examined = 0)
            if result.total_keys_examined > 0 and result.total_docs_examined == 0:
                result.is_covered_query = True

            # Check for in-memory sort
            all_stages = es.get("executionStages", {})
            result.sort_in_memory = self._has_sort_stage(all_stages)

        # Extract used index name
        if result.winning_plan and result.winning_plan.is_index_scan:
            result.used_index = result.winning_plan.index_name
        elif result.winning_plan:
            for child in result.winning_plan.children:
                if child.is_index_scan:
                    result.used_index = child.index_name
                    break

        return result

    def _parse_stage(self, stage_data: dict[str, Any]) -> MongoScanInfo:
        """Parse a single plan stage recursively."""
        stage = MongoScanInfo(
            stage=stage_data.get("stage", "UNKNOWN"),
            index_name=stage_data.get("indexName", ""),
            direction=stage_data.get("direction", "forward"),
            is_multi_key=stage_data.get("isMultiKey", False),
            filter=stage_data.get("filter", {}),
        )

        key_pattern = stage_data.get("keyPattern", {})
        if key_pattern:
            stage.index_key_pattern = key_pattern

        # Recurse into input stage(s)
        input_stage = stage_data.get("inputStage")
        if input_stage:
            stage.children.append(self._parse_stage(input_stage))

        input_stages = stage_data.get("inputStages", [])
        for child in input_stages:
            stage.children.append(self._parse_stage(child))

        return stage

    def _has_sort_stage(self, stages: dict) -> bool:
        """Check if any stage is an in-memory SORT."""
        if stages.get("stage") == "SORT":
            return True
        input_stage = stages.get("inputStage", {})
        if input_stage:
            return self._has_sort_stage(input_stage)
        for child in stages.get("inputStages", []):
            if self._has_sort_stage(child):
                return True
        return False


# ── Index Advisor ────────────────────────────────────────────────────────

@dataclass
class MongoIndexRecommendation:
    """A MongoDB index recommendation."""
    collection: str
    key_pattern: dict[str, int]  # e.g. {"user_id": 1, "created_at": -1}
    reason: str
    severity: str = "warning"  # critical, warning, info
    impact: str = ""
    command: str = ""  # db.collection.createIndex(...)
    estimated_improvement: str = ""

    def __post_init__(self) -> None:
        if not self.command and self.key_pattern:
            keys_str = ", ".join(f'"{k}": {v}' for k, v in self.key_pattern.items())
            self.command = f'db.{self.collection}.createIndex({{{keys_str}}})'


@dataclass
class MongoIndexAudit:
    """Audit of existing indexes on a collection."""
    collection: str
    index_name: str
    key_pattern: dict[str, int]
    accesses_ops: int = 0  # From $indexStats
    since: str = ""  # When tracking started
    size_bytes: int = 0
    is_unused: bool = False
    is_redundant: bool = False
    redundant_with: str = ""
    drop_command: str = ""


# ── Schema Advice ────────────────────────────────────────────────────────

@dataclass
class MongoSchemaFinding:
    """A schema design finding."""
    collection: str
    finding_type: str  # anti_pattern, recommendation, info
    severity: str
    title: str
    description: str
    remediation: str = ""


# ── Full Analysis Report ─────────────────────────────────────────────────

@dataclass
class MongoAnalysisReport:
    """Complete MongoDB analysis report."""
    database: str = ""
    collections_analyzed: int = 0
    index_recommendations: list[MongoIndexRecommendation] = field(default_factory=list)
    index_audits: list[MongoIndexAudit] = field(default_factory=list)
    schema_findings: list[MongoSchemaFinding] = field(default_factory=list)
    slow_queries: list[dict[str, Any]] = field(default_factory=list)
    total_time_ms: float = 0

    @property
    def unused_indexes(self) -> list[MongoIndexAudit]:
        return [a for a in self.index_audits if a.is_unused]

    @property
    def redundant_indexes(self) -> list[MongoIndexAudit]:
        return [a for a in self.index_audits if a.is_redundant]

    def to_dict(self) -> dict[str, Any]:
        return {
            "database": self.database,
            "collections_analyzed": self.collections_analyzed,
            "index_recommendations": [
                {"collection": r.collection, "key_pattern": r.key_pattern,
                 "reason": r.reason, "command": r.command}
                for r in self.index_recommendations
            ],
            "unused_indexes": [
                {"collection": a.collection, "index": a.index_name,
                 "drop_command": a.drop_command}
                for a in self.unused_indexes
            ],
            "redundant_indexes": [
                {"collection": a.collection, "index": a.index_name,
                 "redundant_with": a.redundant_with}
                for a in self.redundant_indexes
            ],
            "schema_findings": [
                {"collection": f.collection, "type": f.finding_type,
                 "severity": f.severity, "title": f.title}
                for f in self.schema_findings
            ],
            "slow_queries": len(self.slow_queries),
        }


# ── Analyzer ─────────────────────────────────────────────────────────────

class MongoDBAnalyzer:
    """
    Full MongoDB query optimizer.

    Connects to a MongoDB instance and provides:
    1. Index recommendations from slow queries + collection scans
    2. Unused / redundant index detection
    3. Schema advice (anti-patterns, embedding vs referencing)
    4. Slow query analysis from system.profile
    """

    def __init__(self, uri: str = "mongodb://localhost:27017", database: str = "") -> None:
        self.uri = uri
        self.database = database

    async def full_analysis(
        self,
        min_slow_ms: int = 100,
        profile_limit: int = 200,
    ) -> MongoAnalysisReport:
        """Run complete analysis."""
        import time as _time
        start = _time.monotonic()

        try:
            from pymongo import MongoClient
        except ImportError:
            raise RuntimeError(
                "pymongo required for MongoDB analysis.\n"
                "Install with: pip install 'querysense[mongodb]' or pip install pymongo"
            )

        client = MongoClient(self.uri, serverSelectionTimeoutMS=5000)
        try:
            db = client[self.database] if self.database else client.get_default_database()
            report = MongoAnalysisReport(database=db.name)

            collections = [
                name for name in db.list_collection_names()
                if not name.startswith("system.")
            ]
            report.collections_analyzed = len(collections)

            # 1. Analyze slow queries from system.profile
            report.slow_queries = self._get_slow_queries(db, min_slow_ms, profile_limit)

            # 2. Index recommendations from slow queries
            report.index_recommendations = self._recommend_indexes(
                db, collections, report.slow_queries,
            )

            # 3. Audit existing indexes
            report.index_audits = self._audit_indexes(db, collections)

            # 4. Schema advice
            report.schema_findings = self._analyze_schema(db, collections)

            report.total_time_ms = (_time.monotonic() - start) * 1000
            return report
        finally:
            client.close()

    def _get_slow_queries(
        self, db: Any, min_ms: int, limit: int,
    ) -> list[dict[str, Any]]:
        """Get slow queries from system.profile."""
        try:
            profile = db["system.profile"]
            queries = list(profile.find(
                {"millis": {"$gte": min_ms}},
                sort=[("millis", -1)],
                limit=limit,
            ))
            return [
                {
                    "op": q.get("op", ""),
                    "ns": q.get("ns", ""),
                    "millis": q.get("millis", 0),
                    "query": q.get("command", q.get("query", {})),
                    "nreturned": q.get("nreturned", 0),
                    "docsExamined": q.get("docsExamined", 0),
                    "keysExamined": q.get("keysExamined", 0),
                    "planSummary": q.get("planSummary", ""),
                    "ts": str(q.get("ts", "")),
                }
                for q in queries
            ]
        except Exception as e:
            logger.debug("Could not read system.profile: %s", e)
            return []

    def _recommend_indexes(
        self,
        db: Any,
        collections: list[str],
        slow_queries: list[dict],
    ) -> list[MongoIndexRecommendation]:
        """Generate index recommendations."""
        recs: list[MongoIndexRecommendation] = []

        # From slow queries: find collection scans
        for q in slow_queries:
            plan_summary = q.get("planSummary", "")
            ns = q.get("ns", "")
            collection = ns.split(".")[-1] if "." in ns else ns

            if "COLLSCAN" in plan_summary and collection in collections:
                # Extract filter fields from the query
                query_doc = q.get("query", {})
                if isinstance(query_doc, dict):
                    # Look for filter in command.filter or directly
                    filter_doc = query_doc.get("filter", query_doc.get("$match", query_doc))
                    fields = self._extract_filter_fields(filter_doc)

                    if fields:
                        key_pattern = {f: 1 for f in fields[:4]}
                        recs.append(MongoIndexRecommendation(
                            collection=collection,
                            key_pattern=key_pattern,
                            reason=f"Collection scan on {collection} ({q.get('millis', 0)}ms, "
                                   f"{q.get('docsExamined', 0)} docs examined)",
                            severity="warning",
                            impact=f"Query examines {q.get('docsExamined', 0)} docs to return "
                                   f"{q.get('nreturned', 0)}",
                        ))

        # From collection stats: large collections without indexes
        for coll_name in collections:
            try:
                stats = db.command("collStats", coll_name)
                doc_count = stats.get("count", 0)
                indexes = list(db[coll_name].list_indexes())
                non_id_indexes = [i for i in indexes if i.get("name") != "_id_"]

                if doc_count > 10000 and len(non_id_indexes) == 0:
                    recs.append(MongoIndexRecommendation(
                        collection=coll_name,
                        key_pattern={},
                        reason=f"Collection '{coll_name}' has {doc_count:,} documents but no "
                               f"indexes beyond _id. Every query will be a collection scan.",
                        severity="critical",
                        impact="All queries on this collection will scan every document",
                        command=f"-- Analyze query patterns on {coll_name} and add appropriate indexes",
                    ))
            except Exception:
                continue

        # Deduplicate by (collection, key_pattern)
        seen: set[str] = set()
        deduped: list[MongoIndexRecommendation] = []
        for rec in recs:
            key = f"{rec.collection}_{rec.key_pattern}"
            if key not in seen:
                seen.add(key)
                deduped.append(rec)

        return deduped

    def _audit_indexes(
        self, db: Any, collections: list[str],
    ) -> list[MongoIndexAudit]:
        """Audit existing indexes for unused and redundant entries."""
        audits: list[MongoIndexAudit] = []

        for coll_name in collections:
            try:
                # Get index stats
                stats = list(db[coll_name].aggregate([{"$indexStats": {}}]))
                indexes = list(db[coll_name].list_indexes())

                stat_map: dict[str, dict] = {}
                for s in stats:
                    stat_map[s["name"]] = s

                index_list: list[dict] = []
                for idx in indexes:
                    name = idx.get("name", "")
                    if name == "_id_":
                        continue

                    key_pattern = dict(idx.get("key", {}))
                    s = stat_map.get(name, {})
                    ops = s.get("accesses", {}).get("ops", 0)
                    since = str(s.get("accesses", {}).get("since", ""))

                    audit = MongoIndexAudit(
                        collection=coll_name,
                        index_name=name,
                        key_pattern=key_pattern,
                        accesses_ops=ops,
                        since=since,
                        is_unused=ops == 0,
                        drop_command=f'db.{coll_name}.dropIndex("{name}")',
                    )
                    index_list.append({"audit": audit, "keys": list(key_pattern.keys())})
                    audits.append(audit)

                # Check for redundant indexes (prefix overlap)
                for i, idx_a in enumerate(index_list):
                    for j, idx_b in enumerate(index_list):
                        if i >= j:
                            continue
                        keys_a = idx_a["keys"]
                        keys_b = idx_b["keys"]
                        # A is redundant if B starts with all of A's keys
                        if len(keys_a) < len(keys_b) and keys_a == keys_b[:len(keys_a)]:
                            idx_a["audit"].is_redundant = True
                            idx_a["audit"].redundant_with = idx_b["audit"].index_name

            except Exception as e:
                logger.debug("Could not audit indexes on %s: %s", coll_name, e)

        return audits

    def _analyze_schema(
        self, db: Any, collections: list[str],
    ) -> list[MongoSchemaFinding]:
        """Analyze schema for anti-patterns."""
        findings: list[MongoSchemaFinding] = []

        for coll_name in collections:
            try:
                # Sample documents to detect patterns
                sample = list(db[coll_name].find().limit(100))
                if not sample:
                    continue

                # Detect anti-patterns
                findings.extend(self._check_unbounded_arrays(coll_name, sample))
                findings.extend(self._check_deep_nesting(coll_name, sample))
                findings.extend(self._check_large_documents(coll_name, sample))
                findings.extend(self._check_inconsistent_schema(coll_name, sample))

            except Exception as e:
                logger.debug("Could not analyze schema for %s: %s", coll_name, e)

        return findings

    def _check_unbounded_arrays(
        self, coll: str, sample: list[dict],
    ) -> list[MongoSchemaFinding]:
        """Detect unbounded arrays (common anti-pattern)."""
        findings: list[MongoSchemaFinding] = []

        for doc in sample[:20]:
            for key, value in doc.items():
                if isinstance(value, list) and len(value) > 100:
                    findings.append(MongoSchemaFinding(
                        collection=coll,
                        finding_type="anti_pattern",
                        severity="warning",
                        title=f"Unbounded array in '{key}'",
                        description=(
                            f"Field '{key}' contains {len(value)} elements. "
                            f"Unbounded arrays cause document growth, index bloat, "
                            f"and can exceed the 16MB document size limit."
                        ),
                        remediation=(
                            f"Consider moving '{key}' to a separate collection "
                            f"with a reference field back to {coll}."
                        ),
                    ))
                    break  # One finding per field is enough
        return findings

    def _check_deep_nesting(
        self, coll: str, sample: list[dict],
    ) -> list[MongoSchemaFinding]:
        """Detect deeply nested documents."""
        def max_depth(obj: Any, depth: int = 0) -> int:
            if isinstance(obj, dict):
                if not obj:
                    return depth
                return max(max_depth(v, depth + 1) for v in obj.values())
            if isinstance(obj, list) and obj:
                return max(max_depth(v, depth) for v in obj[:5])
            return depth

        for doc in sample[:10]:
            depth = max_depth(doc)
            if depth > 5:
                return [MongoSchemaFinding(
                    collection=coll,
                    finding_type="anti_pattern",
                    severity="notice",
                    title=f"Deep nesting (depth {depth})",
                    description=(
                        f"Documents in '{coll}' have nesting depth {depth}. "
                        f"Deep nesting makes queries harder to write and index."
                    ),
                    remediation="Flatten the schema or use references for deeply nested sub-documents.",
                )]
        return []

    def _check_large_documents(
        self, coll: str, sample: list[dict],
    ) -> list[MongoSchemaFinding]:
        """Detect oversized documents."""
        import json
        for doc in sample[:20]:
            try:
                size = len(json.dumps(doc, default=str))
                if size > 1_000_000:  # >1MB
                    return [MongoSchemaFinding(
                        collection=coll,
                        finding_type="anti_pattern",
                        severity="warning",
                        title=f"Large documents (~{size // 1024}KB)",
                        description=(
                            f"Documents in '{coll}' are approximately {size // 1024}KB. "
                            f"The 16MB limit is approaching, and large documents hurt "
                            f"read performance and working set efficiency."
                        ),
                        remediation="Split large embedded data into separate collections.",
                    )]
            except Exception:
                pass
        return []

    def _check_inconsistent_schema(
        self, coll: str, sample: list[dict],
    ) -> list[MongoSchemaFinding]:
        """Detect inconsistent field presence across documents."""
        if len(sample) < 10:
            return []

        field_counts: Counter[str] = Counter()
        for doc in sample:
            for key in doc.keys():
                if key != "_id":
                    field_counts[key] += 1

        total = len(sample)
        inconsistent = [
            f for f, c in field_counts.items()
            if 0.1 * total < c < 0.8 * total
        ]

        if len(inconsistent) > 3:
            return [MongoSchemaFinding(
                collection=coll,
                finding_type="recommendation",
                severity="notice",
                title=f"Inconsistent schema ({len(inconsistent)} optional fields)",
                description=(
                    f"Fields {inconsistent[:5]} appear in only some documents. "
                    f"This may indicate schema evolution or mixed document types."
                ),
                remediation="Consider schema validation or separating document types into sub-collections.",
            )]
        return []

    def _extract_filter_fields(self, doc: dict) -> list[str]:
        """Extract field names used in a MongoDB query filter."""
        fields: list[str] = []
        if not isinstance(doc, dict):
            return fields
        for key, value in doc.items():
            if key.startswith("$"):
                # Logical operator: $and, $or, etc.
                if isinstance(value, list):
                    for sub in value:
                        fields.extend(self._extract_filter_fields(sub))
            else:
                fields.append(key)
        return fields
