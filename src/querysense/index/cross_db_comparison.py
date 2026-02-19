"""
Cross-Database Index Comparison Engine.

Compares index behavior across PostgreSQL, SQL Server, MySQL, and Oracle.
Based on Postgres vs SQL Server B-Tree analysis from pganalyze blog.

Features:
1. Index capability matrix — what each engine supports
2. Migration advisor — recommend equivalent indexes when switching engines
3. Deduplication impact analysis — PG13+ vs SQL Server
4. Storage efficiency comparison
5. Vector/GIN/BRIN/Columnstore cross-platform guidance

Usage:
    from querysense.index.cross_db_comparison import CrossDBIndexAdvisor, DatabaseEngine
    advisor = CrossDBIndexAdvisor()
    result = advisor.get_index_recommendation(
        query_pattern="SELECT * FROM orders WHERE status = 'pending'",
        source_db=DatabaseEngine.SQL_SERVER,
        target_db=DatabaseEngine.POSTGRESQL,
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DatabaseEngine(Enum):
    POSTGRESQL = "postgresql"
    SQL_SERVER = "sql_server"
    MYSQL = "mysql"
    ORACLE = "oracle"


class IndexType(Enum):
    BTREE = "btree"
    CLUSTERED = "clustered"
    NONCLUSTERED = "nonclustered"
    HASH = "hash"
    GIN = "gin"
    GIST = "gist"
    BRIN = "brin"
    COLUMNSTORE = "columnstore"
    FILTERED = "filtered"
    SPATIAL = "spatial"
    XML = "xml"
    VECTOR = "vector"
    FULLTEXT = "fulltext"
    BITMAP = "bitmap"
    COVERING = "covering"


@dataclass
class IndexCapability:
    """Capabilities of an index type on a specific database engine."""
    index_type: IndexType
    database: DatabaseEngine
    supported: bool
    description: str
    use_cases: list[str]
    limitations: list[str]
    syntax_example: str
    deduplication_support: bool
    storage_efficiency: float  # 0-10
    write_overhead: float  # 0-10


@dataclass
class MigrationRecommendation:
    """Recommendation for index migration between databases."""
    source_database: str
    target_database: str
    query_pattern: str
    source_index_type: str
    source_syntax: str
    target_index_type: str
    target_syntax: str
    target_limitations: list[str]
    migration_notes: list[str]
    storage_efficiency_source: float
    storage_efficiency_target: float
    size_delta_multiplier: float


class CrossDBIndexAdvisor:
    """
    Compare index behavior across PostgreSQL, SQL Server, MySQL, Oracle.

    Helps with:
    - Cross-platform migrations (PG -> SQL Server, MySQL -> PG, etc.)
    - Index type selection for multi-database environments
    - Understanding deduplication impact across engines
    """

    INDEX_CAPABILITIES: dict[tuple[IndexType, DatabaseEngine], IndexCapability] = {
        # B-Tree
        (IndexType.BTREE, DatabaseEngine.POSTGRESQL): IndexCapability(
            index_type=IndexType.BTREE,
            database=DatabaseEngine.POSTGRESQL,
            supported=True,
            description="Default B-Tree with deduplication (PG13+), INCLUDE columns (PG11+)",
            use_cases=["Equality", "Range queries", "Sorting", "Prefix matching"],
            limitations=["No index-only scans for wide rows without INCLUDE"],
            syntax_example="CREATE INDEX ON table(col) WITH (deduplicate_items=on);",
            deduplication_support=True,
            storage_efficiency=9,
            write_overhead=3,
        ),
        (IndexType.BTREE, DatabaseEngine.SQL_SERVER): IndexCapability(
            index_type=IndexType.BTREE,
            database=DatabaseEngine.SQL_SERVER,
            supported=True,
            description="Clustered/Nonclustered B-Tree with INCLUDE columns",
            use_cases=["Equality", "Range queries", "Covering indexes"],
            limitations=["No deduplication", "One clustered index per table"],
            syntax_example="CREATE NONCLUSTERED INDEX idx ON table(col) INCLUDE (col2);",
            deduplication_support=False,
            storage_efficiency=7,
            write_overhead=4,
        ),
        (IndexType.BTREE, DatabaseEngine.MYSQL): IndexCapability(
            index_type=IndexType.BTREE,
            database=DatabaseEngine.MYSQL,
            supported=True,
            description="InnoDB B-Tree (clustered by PK)",
            use_cases=["Equality", "Range queries", "Prefix matching"],
            limitations=["Always clustered on PK", "No INCLUDE columns", "No partial indexes"],
            syntax_example="CREATE INDEX idx ON table(col);",
            deduplication_support=False,
            storage_efficiency=7,
            write_overhead=4,
        ),
        (IndexType.BTREE, DatabaseEngine.ORACLE): IndexCapability(
            index_type=IndexType.BTREE,
            database=DatabaseEngine.ORACLE,
            supported=True,
            description="B-Tree with index-organized tables (IOT)",
            use_cases=["Equality", "Range queries", "Unique constraints"],
            limitations=["No deduplication", "No INCLUDE columns natively"],
            syntax_example="CREATE INDEX idx ON table(col);",
            deduplication_support=False,
            storage_efficiency=7,
            write_overhead=4,
        ),
        # GIN (PostgreSQL-specific)
        (IndexType.GIN, DatabaseEngine.POSTGRESQL): IndexCapability(
            index_type=IndexType.GIN,
            database=DatabaseEngine.POSTGRESQL,
            supported=True,
            description="Generalized Inverted Index for multi-valued columns",
            use_cases=["Full-text search", "JSONB queries", "Array containment", "pg_trgm"],
            limitations=["Slower writes than B-Tree", "No range queries"],
            syntax_example="CREATE INDEX ON table USING GIN (col);",
            deduplication_support=False,
            storage_efficiency=8,
            write_overhead=6,
        ),
        (IndexType.GIN, DatabaseEngine.SQL_SERVER): IndexCapability(
            index_type=IndexType.GIN,
            database=DatabaseEngine.SQL_SERVER,
            supported=False,
            description="No equivalent; use Full-Text Index or JSON path indexes",
            use_cases=["Full-text via CONTAINS", "JSON via computed columns"],
            limitations=["No native GIN", "Full-text is separate service"],
            syntax_example="CREATE FULLTEXT INDEX ON table(col) KEY INDEX pk;",
            deduplication_support=False,
            storage_efficiency=5,
            write_overhead=5,
        ),
        # BRIN (PostgreSQL)
        (IndexType.BRIN, DatabaseEngine.POSTGRESQL): IndexCapability(
            index_type=IndexType.BRIN,
            database=DatabaseEngine.POSTGRESQL,
            supported=True,
            description="Block Range INdex — tiny index for naturally ordered data",
            use_cases=["Time-series", "Append-only tables", "Range queries on sorted data"],
            limitations=["Only for physically ordered data", "Less selective than B-Tree"],
            syntax_example="CREATE INDEX ON events USING BRIN (created_at);",
            deduplication_support=False,
            storage_efficiency=10,
            write_overhead=1,
        ),
        # Columnstore (SQL Server)
        (IndexType.COLUMNSTORE, DatabaseEngine.SQL_SERVER): IndexCapability(
            index_type=IndexType.COLUMNSTORE,
            database=DatabaseEngine.SQL_SERVER,
            supported=True,
            description="Columnar storage with batch mode execution for analytics",
            use_cases=["Data warehousing", "Aggregations", "Large scans"],
            limitations=["Update-heavy workloads suffer", "No unique constraints"],
            syntax_example="CREATE CLUSTERED COLUMNSTORE INDEX idx ON table;",
            deduplication_support=True,
            storage_efficiency=10,
            write_overhead=8,
        ),
        (IndexType.COLUMNSTORE, DatabaseEngine.POSTGRESQL): IndexCapability(
            index_type=IndexType.COLUMNSTORE,
            database=DatabaseEngine.POSTGRESQL,
            supported=False,
            description="Via extensions: TimescaleDB compression, Citus columnar",
            use_cases=["Analytics via extensions"],
            limitations=["Not native", "Extension dependent"],
            syntax_example="-- Use TimescaleDB: ALTER TABLE t SET (timescaledb.compress);",
            deduplication_support=False,
            storage_efficiency=5,
            write_overhead=6,
        ),
        # Vector (PostgreSQL pgvector)
        (IndexType.VECTOR, DatabaseEngine.POSTGRESQL): IndexCapability(
            index_type=IndexType.VECTOR,
            database=DatabaseEngine.POSTGRESQL,
            supported=True,
            description="pgvector: HNSW and IVFFlat for similarity search",
            use_cases=["AI/ML embeddings", "Similarity search", "RAG applications"],
            limitations=["Extension required", "Approximate results with IVFFlat"],
            syntax_example="CREATE INDEX ON items USING hnsw (embedding vector_cosine_ops);",
            deduplication_support=False,
            storage_efficiency=8,
            write_overhead=5,
        ),
        (IndexType.VECTOR, DatabaseEngine.SQL_SERVER): IndexCapability(
            index_type=IndexType.VECTOR,
            database=DatabaseEngine.SQL_SERVER,
            supported=False,
            description="No native vector support — use Azure AI Search",
            use_cases=["Vector search via external service only"],
            limitations=["No native vector indexing", "Requires external service"],
            syntax_example="-- Use Azure AI Search or Azure Cosmos DB for MongoDB vCore",
            deduplication_support=False,
            storage_efficiency=0,
            write_overhead=0,
        ),
        # Filtered / Partial
        (IndexType.FILTERED, DatabaseEngine.POSTGRESQL): IndexCapability(
            index_type=IndexType.FILTERED,
            database=DatabaseEngine.POSTGRESQL,
            supported=True,
            description="Partial index — index only rows matching a WHERE predicate",
            use_cases=["Hot/cold data", "Status columns", "Soft deletes"],
            limitations=["Must match query WHERE exactly"],
            syntax_example="CREATE INDEX ON orders(id) WHERE status = 'active';",
            deduplication_support=True,
            storage_efficiency=10,
            write_overhead=1,
        ),
        (IndexType.FILTERED, DatabaseEngine.SQL_SERVER): IndexCapability(
            index_type=IndexType.FILTERED,
            database=DatabaseEngine.SQL_SERVER,
            supported=True,
            description="Filtered index — similar to PG partial index",
            use_cases=["Sparse columns", "Status flags"],
            limitations=["Limited predicate syntax", "Can't use OR, IN, BETWEEN"],
            syntax_example="CREATE INDEX idx ON orders(id) WHERE status = 'active';",
            deduplication_support=False,
            storage_efficiency=9,
            write_overhead=2,
        ),
        (IndexType.FILTERED, DatabaseEngine.MYSQL): IndexCapability(
            index_type=IndexType.FILTERED,
            database=DatabaseEngine.MYSQL,
            supported=False,
            description="Not supported — use prefix indexes or generated columns",
            use_cases=[],
            limitations=["No partial/filtered indexes in MySQL"],
            syntax_example="-- Workaround: generated column + index",
            deduplication_support=False,
            storage_efficiency=0,
            write_overhead=0,
        ),
        # Bitmap (Oracle)
        (IndexType.BITMAP, DatabaseEngine.ORACLE): IndexCapability(
            index_type=IndexType.BITMAP,
            database=DatabaseEngine.ORACLE,
            supported=True,
            description="Bitmap index for low-cardinality columns (DW)",
            use_cases=["Data warehouse queries", "Low-cardinality columns", "Complex AND/OR"],
            limitations=["Terrible for OLTP", "Lock contention on updates"],
            syntax_example="CREATE BITMAP INDEX idx ON table(status);",
            deduplication_support=True,
            storage_efficiency=10,
            write_overhead=9,
        ),
    }

    def get_capabilities_for_engine(
        self, engine: DatabaseEngine,
    ) -> list[IndexCapability]:
        """Get all index capabilities for a specific database engine."""
        return [
            cap for (_, db), cap in self.INDEX_CAPABILITIES.items()
            if db == engine
        ]

    def compare_engines(
        self,
        engine_a: DatabaseEngine,
        engine_b: DatabaseEngine,
    ) -> list[dict[str, Any]]:
        """Compare index capabilities between two engines."""
        all_types = set()
        for (idx_type, _) in self.INDEX_CAPABILITIES:
            all_types.add(idx_type)

        comparison: list[dict[str, Any]] = []
        for idx_type in sorted(all_types, key=lambda t: t.value):
            cap_a = self.INDEX_CAPABILITIES.get((idx_type, engine_a))
            cap_b = self.INDEX_CAPABILITIES.get((idx_type, engine_b))

            comparison.append({
                "index_type": idx_type.value,
                engine_a.value: {
                    "supported": cap_a.supported if cap_a else False,
                    "description": cap_a.description if cap_a else "Not available",
                    "dedup": cap_a.deduplication_support if cap_a else False,
                    "efficiency": cap_a.storage_efficiency if cap_a else 0,
                } if cap_a else {"supported": False},
                engine_b.value: {
                    "supported": cap_b.supported if cap_b else False,
                    "description": cap_b.description if cap_b else "Not available",
                    "dedup": cap_b.deduplication_support if cap_b else False,
                    "efficiency": cap_b.storage_efficiency if cap_b else 0,
                } if cap_b else {"supported": False},
            })

        return comparison

    def get_index_recommendation(
        self,
        query_pattern: str,
        source_db: DatabaseEngine,
        target_db: DatabaseEngine,
    ) -> MigrationRecommendation:
        """Recommend index when migrating between databases."""
        pattern_type = self._classify_query_pattern(query_pattern)
        source_cap = self._recommend_for_pattern(pattern_type, source_db)
        target_cap = self._recommend_for_pattern(pattern_type, target_db)

        notes = self._generate_migration_notes(source_cap, target_cap)

        return MigrationRecommendation(
            source_database=source_db.value,
            target_database=target_db.value,
            query_pattern=pattern_type,
            source_index_type=source_cap.index_type.value,
            source_syntax=source_cap.syntax_example,
            target_index_type=target_cap.index_type.value,
            target_syntax=target_cap.syntax_example,
            target_limitations=target_cap.limitations,
            migration_notes=notes,
            storage_efficiency_source=source_cap.storage_efficiency,
            storage_efficiency_target=target_cap.storage_efficiency,
            size_delta_multiplier=self._estimate_size_delta(source_cap, target_cap),
        )

    def _classify_query_pattern(self, query: str) -> str:
        q = query.upper()
        if "VECTOR" in q or "<->" in query or "cosine" in query.lower():
            return "similarity_search"
        if "JSON" in q or "->" in query or "JSONB" in q:
            return "json_access"
        if "LIKE" in q and "%" in query:
            return "pattern_match"
        if "GROUP BY" in q:
            return "aggregation"
        if "ORDER BY" in q and "LIMIT" in q:
            return "sorted_retrieval"
        if "BETWEEN" in q or ("<" in q and ">" in q):
            return "range_scan"
        if "=" in q:
            return "equality_lookup"
        return "general_purpose"

    def _recommend_for_pattern(
        self, pattern: str, db: DatabaseEngine,
    ) -> IndexCapability:
        pattern_map: dict[str, dict[DatabaseEngine, IndexType]] = {
            "equality_lookup": {
                DatabaseEngine.POSTGRESQL: IndexType.BTREE,
                DatabaseEngine.SQL_SERVER: IndexType.BTREE,
                DatabaseEngine.MYSQL: IndexType.BTREE,
                DatabaseEngine.ORACLE: IndexType.BTREE,
            },
            "range_scan": {
                DatabaseEngine.POSTGRESQL: IndexType.BTREE,
                DatabaseEngine.SQL_SERVER: IndexType.BTREE,
                DatabaseEngine.MYSQL: IndexType.BTREE,
                DatabaseEngine.ORACLE: IndexType.BTREE,
            },
            "sorted_retrieval": {
                DatabaseEngine.POSTGRESQL: IndexType.BTREE,
                DatabaseEngine.SQL_SERVER: IndexType.CLUSTERED,
                DatabaseEngine.MYSQL: IndexType.BTREE,
                DatabaseEngine.ORACLE: IndexType.BTREE,
            },
            "aggregation": {
                DatabaseEngine.POSTGRESQL: IndexType.BTREE,
                DatabaseEngine.SQL_SERVER: IndexType.COLUMNSTORE,
                DatabaseEngine.MYSQL: IndexType.BTREE,
                DatabaseEngine.ORACLE: IndexType.BITMAP,
            },
            "pattern_match": {
                DatabaseEngine.POSTGRESQL: IndexType.GIN,
                DatabaseEngine.SQL_SERVER: IndexType.BTREE,
                DatabaseEngine.MYSQL: IndexType.BTREE,
                DatabaseEngine.ORACLE: IndexType.BTREE,
            },
            "json_access": {
                DatabaseEngine.POSTGRESQL: IndexType.GIN,
                DatabaseEngine.SQL_SERVER: IndexType.BTREE,
                DatabaseEngine.MYSQL: IndexType.BTREE,
                DatabaseEngine.ORACLE: IndexType.BTREE,
            },
            "similarity_search": {
                DatabaseEngine.POSTGRESQL: IndexType.VECTOR,
                DatabaseEngine.SQL_SERVER: IndexType.BTREE,
                DatabaseEngine.MYSQL: IndexType.BTREE,
                DatabaseEngine.ORACLE: IndexType.BTREE,
            },
            "general_purpose": {
                DatabaseEngine.POSTGRESQL: IndexType.BTREE,
                DatabaseEngine.SQL_SERVER: IndexType.BTREE,
                DatabaseEngine.MYSQL: IndexType.BTREE,
                DatabaseEngine.ORACLE: IndexType.BTREE,
            },
        }

        idx_type = pattern_map.get(pattern, {}).get(db, IndexType.BTREE)
        cap = self.INDEX_CAPABILITIES.get((idx_type, db))

        if cap:
            return cap

        # Fallback to B-Tree
        return self.INDEX_CAPABILITIES.get(
            (IndexType.BTREE, db),
            IndexCapability(
                index_type=IndexType.BTREE, database=db,
                supported=True, description="B-Tree (default)",
                use_cases=["General purpose"], limitations=[],
                syntax_example="CREATE INDEX ON table(col);",
                deduplication_support=False,
                storage_efficiency=7, write_overhead=3,
            ),
        )

    def _generate_migration_notes(
        self, source: IndexCapability, target: IndexCapability,
    ) -> list[str]:
        notes: list[str] = []

        if source.deduplication_support and not target.deduplication_support:
            notes.append(
                "Target lacks deduplication — index may be up to 3x larger "
                "for columns with high duplication."
            )

        if not target.supported:
            notes.append(
                f"Index type {target.index_type.value} not natively supported "
                f"on {target.database.value}. Using alternative."
            )

        if source.index_type != target.index_type:
            notes.append(
                f"Index type changes: {source.index_type.value} -> {target.index_type.value}"
            )

        if source.storage_efficiency - target.storage_efficiency > 2:
            notes.append("Storage efficiency decreases significantly in target.")
        elif target.storage_efficiency - source.storage_efficiency > 2:
            notes.append("Storage efficiency improves in target.")

        if target.write_overhead - source.write_overhead > 2:
            notes.append("Write overhead increases in target — monitor insert/update latency.")

        return notes or ["No major migration concerns."]

    def _estimate_size_delta(
        self, source: IndexCapability, target: IndexCapability,
    ) -> float:
        if source.deduplication_support and not target.deduplication_support:
            return 3.0
        if not source.deduplication_support and target.deduplication_support:
            return 0.33
        return 1.0
