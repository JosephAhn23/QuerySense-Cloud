"""
Semantic Translation Layer -- cross-database optimization patterns.

Translates PostgreSQL-specific optimization recommendations to equivalent
patterns for MySQL, SQL Server, Oracle, and other databases. This enables
QuerySense findings to be actionable regardless of target database.

Mapping examples:
- PostgreSQL GIN index -> MySQL FULLTEXT index
- PostgreSQL partial index -> MySQL: not supported (suggest filtered view)
- PostgreSQL BRIN index -> MySQL: partition pruning
- PostgreSQL ANALYZE -> MySQL ANALYZE TABLE
- PostgreSQL work_mem -> MySQL sort_buffer_size
- PostgreSQL shared_buffers -> MySQL innodb_buffer_pool_size

Usage:
    from querysense.semantic_translator import SemanticTranslator

    translator = SemanticTranslator()
    pg_finding = "CREATE INDEX CONCURRENTLY idx_users_email ON users USING GIN (email gin_trgm_ops)"
    translated = translator.translate(pg_finding, target="mysql")
    print(translated.sql)  # "ALTER TABLE users ADD FULLTEXT INDEX idx_users_email (email);"
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TranslatedRecommendation:
    """A recommendation translated to a target database."""
    source_db: str = "postgresql"
    target_db: str = ""
    original_sql: str = ""
    translated_sql: str = ""
    confidence: float = 0.0       # 0-1 translation accuracy
    notes: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    equivalent: bool = True       # True if semantically equivalent

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_db": self.source_db,
            "target_db": self.target_db,
            "original_sql": self.original_sql,
            "translated_sql": self.translated_sql,
            "confidence": round(self.confidence, 2),
            "equivalent": self.equivalent,
            "notes": self.notes,
            "limitations": self.limitations,
        }


@dataclass
class TranslationResult:
    """Result of translating multiple recommendations."""
    target_db: str
    translations: list[TranslatedRecommendation] = field(default_factory=list)
    untranslatable: list[str] = field(default_factory=list)
    coverage: float = 0.0  # % of recommendations successfully translated

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_db": self.target_db,
            "translation_count": len(self.translations),
            "untranslatable_count": len(self.untranslatable),
            "coverage": round(self.coverage, 2),
            "translations": [t.to_dict() for t in self.translations],
            "untranslatable": self.untranslatable,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def format_text(self) -> str:
        lines: list[str] = []
        lines.append("")
        lines.append(f"  SEMANTIC TRANSLATION: PostgreSQL -> {self.target_db.upper()}")
        lines.append("  " + "=" * 60)
        lines.append(f"  Coverage: {self.coverage:.0%} ({len(self.translations)}/{len(self.translations) + len(self.untranslatable)})")
        lines.append("")

        for t in self.translations:
            conf_bar = "#" * int(t.confidence * 10)
            equiv = "EXACT" if t.equivalent else "APPROX"
            lines.append(f"  [{equiv}] {t.confidence:.0%} [{conf_bar}]")
            lines.append(f"    PG:     {t.original_sql[:100]}")
            lines.append(f"    {self.target_db.upper()}: {t.translated_sql[:100]}")
            for note in t.notes:
                lines.append(f"    Note: {note}")
            for lim in t.limitations:
                lines.append(f"    Limitation: {lim}")
            lines.append("")

        if self.untranslatable:
            lines.append("  Untranslatable:")
            for u in self.untranslatable:
                lines.append(f"    - {u[:80]}")
            lines.append("")

        return "\n".join(lines)


# ── Knob mappings ────────────────────────────────────────────────────

_KNOB_MAP: dict[str, dict[str, dict[str, Any]]] = {
    "work_mem": {
        "mysql": {"name": "sort_buffer_size", "factor": 1.0, "note": "MySQL equivalent for sort operations"},
        "sqlserver": {"name": "max server memory (MB)", "note": "SQL Server manages memory differently"},
        "oracle": {"name": "SORT_AREA_SIZE", "factor": 1.0},
    },
    "shared_buffers": {
        "mysql": {"name": "innodb_buffer_pool_size", "factor": 1.0, "note": "Set to 70-80% of available RAM"},
        "sqlserver": {"name": "max server memory", "note": "SQL Server auto-manages buffer pool"},
        "oracle": {"name": "DB_CACHE_SIZE", "factor": 1.0},
    },
    "effective_cache_size": {
        "mysql": {"name": "innodb_buffer_pool_size", "note": "MySQL uses buffer pool for similar purpose"},
        "sqlserver": {"name": "N/A", "note": "SQL Server auto-detects available memory"},
    },
    "random_page_cost": {
        "mysql": {"name": "N/A", "note": "MySQL optimizer uses different cost model; ensure InnoDB buffer pool is large enough"},
        "sqlserver": {"name": "N/A", "note": "SQL Server cost model auto-calibrates"},
    },
    "max_parallel_workers_per_gather": {
        "mysql": {"name": "innodb_parallel_read_threads", "note": "MySQL 8.0+ parallel read"},
        "sqlserver": {"name": "max degree of parallelism", "factor": 1.0},
        "oracle": {"name": "PARALLEL_DEGREE_POLICY", "note": "Oracle uses resource manager for parallelism"},
    },
    "default_statistics_target": {
        "mysql": {"name": "innodb_stats_persistent_sample_pages", "note": "Controls histogram sampling"},
        "sqlserver": {"name": "N/A", "note": "Use UPDATE STATISTICS with FULLSCAN"},
        "oracle": {"name": "DBMS_STATS.SET_TABLE_PREFS", "note": "Oracle has fine-grained stats control"},
    },
}

# ── Index type mappings ──────────────────────────────────────────────

_INDEX_MAP: dict[str, dict[str, dict[str, str]]] = {
    "btree": {
        "mysql": {"type": "BTREE", "note": "Default index type in both"},
        "sqlserver": {"type": "NONCLUSTERED", "note": "B-tree is default"},
        "oracle": {"type": "INDEX", "note": "B-tree is default"},
    },
    "gin": {
        "mysql": {"type": "FULLTEXT", "note": "For text search; for JSONB use generated columns + index"},
        "sqlserver": {"type": "FULLTEXT", "note": "Use Full-Text Search catalog"},
        "oracle": {"type": "CONTEXT", "note": "Oracle Text CONTEXT index"},
    },
    "gist": {
        "mysql": {"type": "SPATIAL", "note": "For spatial data only"},
        "sqlserver": {"type": "SPATIAL", "note": "SQL Server spatial index"},
        "oracle": {"type": "SPATIAL", "note": "Oracle Spatial SDO_INDEX"},
    },
    "brin": {
        "mysql": {"type": "N/A", "note": "Use table partitioning for similar partition pruning benefits"},
        "sqlserver": {"type": "COLUMNSTORE", "note": "Columnstore provides similar benefits for large scans"},
        "oracle": {"type": "N/A", "note": "Use partition pruning instead"},
    },
    "hash": {
        "mysql": {"type": "HASH", "note": "Supported in NDB Cluster; InnoDB uses adaptive hash internally"},
        "sqlserver": {"type": "N/A", "note": "SQL Server uses hash internally for hash joins"},
        "oracle": {"type": "N/A", "note": "Oracle uses hash cluster for similar purpose"},
    },
}


class SemanticTranslator:
    """Translate PostgreSQL optimizations to other databases."""

    def translate(
        self,
        sql: str,
        target: str = "mysql",
    ) -> TranslatedRecommendation:
        """Translate a single SQL recommendation."""
        target = target.lower()

        # Try each translator in order
        translators = [
            self._translate_create_index,
            self._translate_alter_system,
            self._translate_analyze,
            self._translate_explain,
            self._translate_set,
        ]

        for translator in translators:
            result = translator(sql, target)
            if result:
                return result

        # Fallback
        return TranslatedRecommendation(
            target_db=target,
            original_sql=sql,
            translated_sql=f"-- No direct translation for: {sql[:80]}",
            confidence=0.0,
            equivalent=False,
            notes=[f"Manual translation required for {target}"],
        )

    def translate_batch(
        self,
        sqls: list[str],
        target: str = "mysql",
    ) -> TranslationResult:
        """Translate multiple SQL recommendations."""
        translations: list[TranslatedRecommendation] = []
        untranslatable: list[str] = []

        for sql in sqls:
            result = self.translate(sql, target)
            if result.confidence > 0:
                translations.append(result)
            else:
                untranslatable.append(sql)

        total = len(translations) + len(untranslatable)
        coverage = len(translations) / total if total > 0 else 0.0

        return TranslationResult(
            target_db=target,
            translations=translations,
            untranslatable=untranslatable,
            coverage=coverage,
        )

    def _translate_create_index(self, sql: str, target: str) -> TranslatedRecommendation | None:
        """Translate CREATE INDEX statements."""
        m = re.match(
            r"CREATE\s+INDEX\s+(?:CONCURRENTLY\s+)?(\w+)\s+ON\s+(\w+)"
            r"(?:\s+USING\s+(\w+))?\s*\(([^)]+)\)",
            sql,
            re.IGNORECASE,
        )
        if not m:
            return None

        idx_name = m.group(1)
        table = m.group(2)
        idx_type = (m.group(3) or "btree").lower()
        columns = m.group(4)

        # Look up index type mapping
        type_map = _INDEX_MAP.get(idx_type, {}).get(target)
        if not type_map:
            return TranslatedRecommendation(
                target_db=target,
                original_sql=sql,
                translated_sql=f"-- {idx_type.upper()} index not directly supported in {target}",
                confidence=0.2,
                equivalent=False,
                notes=[f"No direct {idx_type} equivalent in {target}"],
            )

        mapped_type = type_map["type"]
        note = type_map.get("note", "")

        if mapped_type == "N/A":
            return TranslatedRecommendation(
                target_db=target,
                original_sql=sql,
                translated_sql=f"-- Not available in {target}: {note}",
                confidence=0.3,
                equivalent=False,
                notes=[note],
                limitations=[f"{idx_type} index type not supported in {target}"],
            )

        if target == "mysql":
            if mapped_type == "FULLTEXT":
                trans = f"ALTER TABLE {table} ADD FULLTEXT INDEX {idx_name} ({columns});"
            else:
                trans = f"CREATE INDEX {idx_name} ON {table} ({columns});"
            # MySQL doesn't support CONCURRENTLY
            notes = ["MySQL doesn't support CONCURRENTLY -- index creation locks table"]
            if "gin_trgm_ops" in sql:
                notes.append("gin_trgm_ops not available -- using FULLTEXT for text search")
        elif target == "sqlserver":
            trans = f"CREATE {mapped_type} INDEX {idx_name} ON {table} ({columns});"
            notes = ["SQL Server supports ONLINE = ON for minimal locking"]
        elif target == "oracle":
            trans = f"CREATE INDEX {idx_name} ON {table} ({columns}) ONLINE;"
            notes = ["Oracle supports ONLINE index creation"]
        else:
            trans = f"CREATE INDEX {idx_name} ON {table} ({columns});"
            notes = []

        return TranslatedRecommendation(
            target_db=target,
            original_sql=sql,
            translated_sql=trans,
            confidence=0.85 if mapped_type != "FULLTEXT" else 0.65,
            equivalent=mapped_type not in ("FULLTEXT", "N/A"),
            notes=notes + ([note] if note else []),
        )

    def _translate_alter_system(self, sql: str, target: str) -> TranslatedRecommendation | None:
        """Translate ALTER SYSTEM SET statements."""
        m = re.match(
            r"ALTER\s+SYSTEM\s+SET\s+(\w+)\s*=\s*(.+?)(?:;|$)",
            sql,
            re.IGNORECASE,
        )
        if not m:
            return None

        param = m.group(1)
        value = m.group(2).strip().strip("'\"")

        mapping = _KNOB_MAP.get(param, {}).get(target)
        if not mapping:
            return TranslatedRecommendation(
                target_db=target,
                original_sql=sql,
                translated_sql=f"-- No direct mapping for {param} in {target}",
                confidence=0.2,
                equivalent=False,
            )

        target_param = mapping["name"]
        note = mapping.get("note", "")
        factor = mapping.get("factor", 1.0)

        if target_param == "N/A":
            return TranslatedRecommendation(
                target_db=target,
                original_sql=sql,
                translated_sql=f"-- {param}: {note}",
                confidence=0.3,
                equivalent=False,
                notes=[note],
            )

        if target == "mysql":
            trans = f"SET GLOBAL {target_param} = {value};"
        elif target == "sqlserver":
            trans = f"EXEC sp_configure '{target_param}', {value};\nRECONFIGURE;"
        elif target == "oracle":
            trans = f"ALTER SYSTEM SET {target_param} = {value} SCOPE=BOTH;"
        else:
            trans = f"SET {target_param} = {value};"

        return TranslatedRecommendation(
            target_db=target,
            original_sql=sql,
            translated_sql=trans,
            confidence=0.70,
            equivalent=True,
            notes=[note] if note else [],
        )

    def _translate_analyze(self, sql: str, target: str) -> TranslatedRecommendation | None:
        """Translate ANALYZE statements."""
        m = re.match(r"ANALYZE\s+(\w+)", sql, re.IGNORECASE)
        if not m:
            if sql.strip().upper() == "ANALYZE;":
                m_all = True
                table = None
            else:
                return None
        else:
            table = m.group(1)

        if target == "mysql":
            trans = f"ANALYZE TABLE {table};" if table else "-- ANALYZE all tables: mysqlcheck --analyze --all-databases"
        elif target == "sqlserver":
            trans = f"UPDATE STATISTICS {table};" if table else "EXEC sp_updatestats;"
        elif target == "oracle":
            trans = f"EXEC DBMS_STATS.GATHER_TABLE_STATS(NULL, '{table}');" if table else "EXEC DBMS_STATS.GATHER_SCHEMA_STATS(NULL);"
        else:
            return None

        return TranslatedRecommendation(
            target_db=target,
            original_sql=sql,
            translated_sql=trans,
            confidence=0.90,
            equivalent=True,
        )

    def _translate_explain(self, sql: str, target: str) -> TranslatedRecommendation | None:
        """Translate EXPLAIN statements."""
        if not sql.strip().upper().startswith("EXPLAIN"):
            return None

        if target == "mysql":
            trans = sql.replace("EXPLAIN (ANALYZE, FORMAT JSON)", "EXPLAIN ANALYZE FORMAT=JSON")
            trans = trans.replace("EXPLAIN (ANALYZE)", "EXPLAIN ANALYZE")
        elif target == "sqlserver":
            trans = "SET STATISTICS PROFILE ON;\n" + re.sub(r"EXPLAIN\s*\([^)]*\)\s*", "", sql)
        elif target == "oracle":
            trans = f"EXPLAIN PLAN FOR {re.sub(r'EXPLAIN[^)]*\\)', '', sql)};\nSELECT * FROM TABLE(DBMS_XPLAN.DISPLAY);"
        else:
            return None

        return TranslatedRecommendation(
            target_db=target,
            original_sql=sql,
            translated_sql=trans,
            confidence=0.75,
            equivalent=True,
            notes=[f"EXPLAIN syntax differs significantly in {target}"],
        )

    def _translate_set(self, sql: str, target: str) -> TranslatedRecommendation | None:
        """Translate SET/SET LOCAL statements."""
        m = re.match(r"SET\s+(?:LOCAL\s+)?(\w+)\s*=\s*(.+?)(?:;|$)", sql, re.IGNORECASE)
        if not m:
            return None

        param = m.group(1)
        value = m.group(2).strip().strip("'\"")

        mapping = _KNOB_MAP.get(param, {}).get(target)
        if not mapping:
            return TranslatedRecommendation(
                target_db=target,
                original_sql=sql,
                translated_sql=f"-- No mapping for SET {param} in {target}",
                confidence=0.2,
                equivalent=False,
            )

        target_param = mapping["name"]
        if target_param == "N/A":
            return TranslatedRecommendation(
                target_db=target,
                original_sql=sql,
                translated_sql=f"-- {mapping.get('note', 'Not available')}",
                confidence=0.3,
                equivalent=False,
            )

        if target == "mysql":
            trans = f"SET SESSION {target_param} = {value};"
        else:
            trans = f"SET {target_param} = {value};"

        return TranslatedRecommendation(
            target_db=target,
            original_sql=sql,
            translated_sql=trans,
            confidence=0.70,
            equivalent=True,
            notes=[mapping.get("note", "")] if mapping.get("note") else [],
        )
