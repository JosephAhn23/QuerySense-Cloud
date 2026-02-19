"""
Competitor migration toolkit — import from any tool, switch in minutes.

Supports importing from:
- pganalyze: JSON exports (query plans, indexes, statistics)
- EverSQL: SQL exports and query optimization results
- Datadog: Dashboard JSON exports
- Liquibase: changelog.xml / changelog.yml
- pgMustard: plan JSON exports

Lock-in is real. Make switching to QuerySense trivial.

Usage:
    from querysense.competitor_import import import_from, detect_format

    result = import_from("export.json", source="pganalyze")

CLI:
    querysense import --from=pganalyze export.json
    querysense import --from=eversql queries.sql
    querysense import --from=datadog dashboard.json
    querysense import --from=liquibase changelog.xml
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ── Models ───────────────────────────────────────────────────────────

@dataclass
class ImportedQuery:
    """A query imported from a competitor tool."""
    sql: str
    plan_json: dict[str, Any] | None = None
    source_tool: str = ""
    original_id: str = ""
    execution_time_ms: float | None = None
    recommendations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ImportedIndex:
    """An index recommendation imported from a competitor."""
    table: str
    columns: list[str]
    index_type: str = "btree"
    source_tool: str = ""
    create_sql: str = ""


@dataclass
class ImportedMigration:
    """A migration imported from Liquibase/Flyway."""
    id: str
    sql: str
    author: str = ""
    description: str = ""
    rollback_sql: str = ""
    applied: bool = False
    source_tool: str = ""


@dataclass
class ImportResult:
    """Result of importing from a competitor tool."""
    source: str
    source_file: str
    queries: list[ImportedQuery] = field(default_factory=list)
    indexes: list[ImportedIndex] = field(default_factory=list)
    migrations: list[ImportedMigration] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "source_file": self.source_file,
            "stats": self.stats,
            "queries_imported": len(self.queries),
            "indexes_imported": len(self.indexes),
            "migrations_imported": len(self.migrations),
            "warnings": self.warnings,
            "queries": [
                {
                    "sql": q.sql[:200],
                    "execution_time_ms": q.execution_time_ms,
                    "has_plan": q.plan_json is not None,
                    "recommendations": q.recommendations,
                }
                for q in self.queries
            ],
            "indexes": [
                {
                    "table": idx.table,
                    "columns": idx.columns,
                    "create_sql": idx.create_sql,
                }
                for idx in self.indexes
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ── Format detection ─────────────────────────────────────────────────

def detect_format(path: str | Path) -> str:
    """
    Auto-detect the source tool from an export file.

    Returns one of: pganalyze, eversql, datadog, liquibase, flyway,
                     pgmustard, unknown
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")[:5000]

    # Liquibase XML
    if path.suffix == ".xml" and ("databaseChangeLog" in text or "<changeSet" in text):
        return "liquibase"

    # Liquibase YAML
    if path.suffix in (".yml", ".yaml") and "databaseChangeLog" in text:
        return "liquibase"

    # Flyway SQL
    if path.suffix == ".sql" and re.match(r"^V\d+", path.stem):
        return "flyway"

    # Try JSON
    if path.suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return "unknown"

        if isinstance(data, dict):
            # Datadog dashboard
            if "widgets" in data or "template_variables" in data or "dashboard" in data:
                return "datadog"

            # pganalyze
            if "queries" in data and any(
                "query_text" in q or "plan" in q for q in data.get("queries", [])
            ):
                return "pganalyze"

            # pgMustard
            if "Plan" in data or (isinstance(data, list) and data and "Plan" in data[0]):
                return "pgmustard"

            # EverSQL
            if "optimizations" in data or "optimized_queries" in data:
                return "eversql"

        # Raw EXPLAIN JSON (list format)
        if isinstance(data, list) and data and "Plan" in data[0]:
            return "pgmustard"

    # EverSQL SQL export
    if path.suffix == ".sql" and ("-- EverSQL" in text or "-- Optimized" in text):
        return "eversql"

    return "unknown"


# ── Importers ────────────────────────────────────────────────────────

def _import_pganalyze(path: Path, data: dict) -> ImportResult:
    """Import from pganalyze JSON export."""
    result = ImportResult(source="pganalyze", source_file=str(path))

    queries = data.get("queries", [])
    for q in queries:
        sql = q.get("query_text", q.get("normalized_query", q.get("query", "")))
        plan = q.get("plan", q.get("explain_plan"))

        if isinstance(plan, str):
            try:
                plan = json.loads(plan)
            except json.JSONDecodeError:
                plan = None

        imp = ImportedQuery(
            sql=sql,
            plan_json=plan,
            source_tool="pganalyze",
            original_id=str(q.get("query_id", q.get("id", ""))),
            execution_time_ms=q.get("avg_time_ms", q.get("mean_time")),
            metadata={
                k: v for k, v in q.items()
                if k not in ("query_text", "plan", "explain_plan", "normalized_query")
            },
        )
        result.queries.append(imp)

    # Index recommendations
    for idx in data.get("index_recommendations", data.get("indexes", [])):
        result.indexes.append(ImportedIndex(
            table=idx.get("table", idx.get("relation", "")),
            columns=idx.get("columns", []),
            index_type=idx.get("type", "btree"),
            source_tool="pganalyze",
            create_sql=idx.get("create_statement", ""),
        ))

    result.stats = {
        "queries_found": len(result.queries),
        "plans_found": sum(1 for q in result.queries if q.plan_json),
        "indexes_found": len(result.indexes),
    }

    return result


def _import_eversql(path: Path, data: dict | None, text: str) -> ImportResult:
    """Import from EverSQL JSON or SQL export."""
    result = ImportResult(source="eversql", source_file=str(path))

    if data:
        # JSON format
        optimizations = data.get("optimizations", data.get("optimized_queries", []))
        for opt in optimizations:
            sql = opt.get("original_query", opt.get("query", ""))
            result.queries.append(ImportedQuery(
                sql=sql,
                source_tool="eversql",
                execution_time_ms=opt.get("execution_time_ms"),
                recommendations=opt.get("recommendations", []),
                metadata=opt,
            ))

            # Extract index suggestions
            for idx_sql in opt.get("index_suggestions", []):
                # Parse CREATE INDEX statement
                m = re.search(
                    r"CREATE\s+INDEX.*?ON\s+(\w+)\s*\(([^)]+)\)",
                    idx_sql,
                    re.IGNORECASE,
                )
                if m:
                    result.indexes.append(ImportedIndex(
                        table=m.group(1),
                        columns=[c.strip() for c in m.group(2).split(",")],
                        source_tool="eversql",
                        create_sql=idx_sql,
                    ))
    else:
        # SQL text format
        # Split by comment blocks or semicolons
        queries = re.split(r";\s*\n", text)
        for q in queries:
            q = q.strip()
            if q and not q.startswith("--"):
                # Remove comments
                clean = re.sub(r"--.*$", "", q, flags=re.MULTILINE).strip()
                if clean:
                    result.queries.append(ImportedQuery(
                        sql=clean,
                        source_tool="eversql",
                    ))

    result.stats = {
        "queries_found": len(result.queries),
        "indexes_found": len(result.indexes),
    }

    return result


def _import_datadog(path: Path, data: dict) -> ImportResult:
    """Import from Datadog dashboard/DBM export."""
    result = ImportResult(source="datadog", source_file=str(path))

    # Extract queries from dashboard widgets
    widgets = data.get("widgets", [])
    dashboard = data.get("dashboard", {})
    if not widgets and isinstance(dashboard, dict):
        widgets = dashboard.get("widgets", [])

    for widget in widgets:
        definition = widget.get("definition", widget)
        requests = definition.get("requests", [])

        for req in requests:
            query = req.get("q", req.get("query", ""))
            # Datadog queries might be metric queries, skip those
            if query and ("SELECT" in query.upper() or "FROM" in query.upper()):
                result.queries.append(ImportedQuery(
                    sql=query,
                    source_tool="datadog",
                    metadata={"widget_title": definition.get("title", "")},
                ))

    # Also check for DBM exports (top queries)
    for q in data.get("top_queries", data.get("database_queries", [])):
        sql = q.get("query", q.get("raw_query", q.get("statement", "")))
        if sql:
            result.queries.append(ImportedQuery(
                sql=sql,
                source_tool="datadog",
                execution_time_ms=q.get("avg_latency_ms", q.get("avg_time")),
                metadata=q,
            ))

    result.stats = {
        "queries_found": len(result.queries),
        "widgets_scanned": len(widgets),
    }

    if not result.queries:
        result.warnings.append(
            "No SQL queries found in Datadog export. "
            "Datadog exports are mostly metric-based. "
            "Consider exporting from Database Monitoring > Top Queries."
        )

    return result


def _import_liquibase(path: Path) -> ImportResult:
    """Import from Liquibase changelog (XML or YAML)."""
    result = ImportResult(source="liquibase", source_file=str(path))

    if path.suffix in (".yml", ".yaml"):
        return _import_liquibase_yaml(path, result)

    # XML format
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError as e:
        result.warnings.append(f"XML parse error: {e}")
        return result

    # Handle namespace
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    for cs in root.iter(f"{ns}changeSet"):
        cs_id = cs.get("id", "unknown")
        author = cs.get("author", "")

        # Extract SQL from various Liquibase elements
        sqls: list[str] = []
        rollback_sqls: list[str] = []

        for sql_el in cs.iter(f"{ns}sql"):
            if sql_el.text:
                sqls.append(sql_el.text.strip())

        for sql_el in cs.iter(f"{ns}sqlFile"):
            sqls.append(f"-- SQL file: {sql_el.get('path', 'unknown')}")

        # Common DDL elements
        for create_table in cs.iter(f"{ns}createTable"):
            table_name = create_table.get("tableName", "unknown")
            sqls.append(f"CREATE TABLE {table_name}")

        for add_col in cs.iter(f"{ns}addColumn"):
            table_name = add_col.get("tableName", "unknown")
            sqls.append(f"ALTER TABLE {table_name} ADD COLUMN")

        for create_idx in cs.iter(f"{ns}createIndex"):
            table_name = create_idx.get("tableName", "unknown")
            idx_name = create_idx.get("indexName", "unknown")
            sqls.append(f"CREATE INDEX {idx_name} ON {table_name}")

        for drop_table in cs.iter(f"{ns}dropTable"):
            table_name = drop_table.get("tableName", "unknown")
            sqls.append(f"DROP TABLE {table_name}")

        # Rollback
        for rb in cs.iter(f"{ns}rollback"):
            if rb.text:
                rollback_sqls.append(rb.text.strip())

        combined_sql = ";\n".join(sqls) if sqls else ""
        combined_rollback = ";\n".join(rollback_sqls) if rollback_sqls else ""

        if combined_sql:
            result.migrations.append(ImportedMigration(
                id=cs_id,
                sql=combined_sql,
                author=author,
                rollback_sql=combined_rollback,
                source_tool="liquibase",
            ))

    result.stats = {
        "changesets_found": len(result.migrations),
        "with_rollback": sum(1 for m in result.migrations if m.rollback_sql),
        "without_rollback": sum(1 for m in result.migrations if not m.rollback_sql),
    }

    if any(not m.rollback_sql for m in result.migrations):
        result.warnings.append(
            f"{result.stats['without_rollback']} changeset(s) missing rollback. "
            "Run: querysense migrate-check <sql> to generate rollback SQL."
        )

    return result


def _import_liquibase_yaml(path: Path, result: ImportResult) -> ImportResult:
    """Import from Liquibase YAML changelog."""
    if not HAS_YAML:
        result.warnings.append("PyYAML required for YAML changelogs")
        return result

    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)

    if not isinstance(data, dict):
        result.warnings.append("Invalid Liquibase YAML format")
        return result

    for item in data.get("databaseChangeLog", []):
        cs = item.get("changeSet")
        if not cs:
            continue

        cs_id = str(cs.get("id", "unknown"))
        author = cs.get("author", "")
        changes = cs.get("changes", [])

        sqls: list[str] = []
        for change in changes:
            if isinstance(change, dict):
                for key, val in change.items():
                    if key == "sql" and isinstance(val, dict):
                        sqls.append(val.get("sql", ""))
                    elif key == "createTable":
                        sqls.append(f"CREATE TABLE {val.get('tableName', '')}")
                    elif key == "addColumn":
                        sqls.append(f"ALTER TABLE {val.get('tableName', '')} ADD COLUMN")
                    elif key == "createIndex":
                        sqls.append(f"CREATE INDEX {val.get('indexName', '')} ON {val.get('tableName', '')}")

        rollback = cs.get("rollback", "")
        if isinstance(rollback, list):
            rollback = ";\n".join(str(r) for r in rollback)

        if sqls:
            result.migrations.append(ImportedMigration(
                id=cs_id,
                sql=";\n".join(sqls),
                author=author,
                rollback_sql=str(rollback) if rollback else "",
                source_tool="liquibase",
            ))

    result.stats = {
        "changesets_found": len(result.migrations),
        "with_rollback": sum(1 for m in result.migrations if m.rollback_sql),
    }

    return result


def _import_pgmustard(path: Path, data: Any) -> ImportResult:
    """Import from pgMustard / raw EXPLAIN JSON."""
    result = ImportResult(source="pgmustard", source_file=str(path))

    # pgMustard uses standard EXPLAIN (FORMAT JSON) output
    plan_data = data
    if isinstance(data, list) and data:
        plan_data = data[0]

    if isinstance(plan_data, dict) and "Plan" in plan_data:
        result.queries.append(ImportedQuery(
            sql=plan_data.get("Query Text", plan_data.get("query", "")),
            plan_json=plan_data,
            source_tool="pgmustard",
            execution_time_ms=plan_data.get("Execution Time"),
        ))

    result.stats = {
        "plans_found": len(result.queries),
    }

    return result


def _import_flyway(path: Path) -> ImportResult:
    """Import from Flyway SQL migration file."""
    result = ImportResult(source="flyway", source_file=str(path))

    text = path.read_text(encoding="utf-8")
    # Flyway files are named V{version}__{description}.sql
    match = re.match(r"^V(\d+(?:\.\d+)*(?:__|\s)(.*))?", path.stem)
    description = match.group(2).replace("_", " ") if match and match.group(2) else path.stem

    result.migrations.append(ImportedMigration(
        id=path.stem,
        sql=text,
        description=description,
        source_tool="flyway",
    ))

    result.stats = {"migrations_found": 1}

    return result


# ── Public API ───────────────────────────────────────────────────────

def import_from(
    path: str | Path,
    source: str | None = None,
) -> ImportResult:
    """
    Import queries/plans/migrations from a competitor tool's export.

    Args:
        path: Path to the export file
        source: Source tool name (auto-detected if None)

    Returns:
        ImportResult with all imported data
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Import file not found: {path}")

    if source is None:
        source = detect_format(path)

    source = source.lower().strip()

    # Read file
    text = path.read_text(encoding="utf-8", errors="replace")
    data: dict | list | None = None
    if path.suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            pass

    # Dispatch to importer
    if source == "pganalyze":
        if not isinstance(data, dict):
            return ImportResult(
                source=source,
                source_file=str(path),
                warnings=["Expected JSON object for pganalyze export"],
            )
        return _import_pganalyze(path, data)

    elif source == "eversql":
        return _import_eversql(path, data if isinstance(data, dict) else None, text)

    elif source == "datadog":
        if not isinstance(data, dict):
            return ImportResult(
                source=source,
                source_file=str(path),
                warnings=["Expected JSON object for Datadog export"],
            )
        return _import_datadog(path, data)

    elif source == "liquibase":
        return _import_liquibase(path)

    elif source == "flyway":
        return _import_flyway(path)

    elif source in ("pgmustard", "explain"):
        return _import_pgmustard(path, data)

    else:
        # Try auto-detection on the data
        if isinstance(data, dict):
            if "queries" in data:
                return _import_pganalyze(path, data)
            if "widgets" in data:
                return _import_datadog(path, data)
            if "Plan" in data:
                return _import_pgmustard(path, data)

        return ImportResult(
            source="unknown",
            source_file=str(path),
            warnings=[
                f"Could not detect source format for {path.name}. "
                "Use --from to specify: pganalyze, eversql, datadog, liquibase, pgmustard"
            ],
        )


@dataclass
class SwitchReport:
    """
    Side-by-side comparison report generated after importing from a competitor.

    Shows exactly what QuerySense found that the competitor missed,
    creating an immediate "wow" moment that drives adoption.
    """
    source_tool: str
    queries_imported: int
    plans_analyzed: int
    competitor_recommendations: int
    querysense_findings: int
    new_findings: int  # findings QS found that competitor didn't surface
    finding_details: list[dict[str, Any]] = field(default_factory=list)
    performance_insights: list[str] = field(default_factory=list)
    competitor_pricing: str = ""
    time_to_analyze_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_tool": self.source_tool,
            "queries_imported": self.queries_imported,
            "plans_analyzed": self.plans_analyzed,
            "competitor_recommendations": self.competitor_recommendations,
            "querysense_findings": self.querysense_findings,
            "new_findings_vs_competitor": self.new_findings,
            "time_to_analyze_ms": round(self.time_to_analyze_ms, 1),
            "finding_details": self.finding_details,
            "performance_insights": self.performance_insights,
            "competitor_pricing": self.competitor_pricing,
            "verdict": self._verdict(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def _verdict(self) -> str:
        if self.new_findings > 0:
            return (
                f"QuerySense found {self.new_findings} issue(s) that "
                f"{self.source_tool} missed -- for free."
            )
        return f"QuerySense matched {self.source_tool}'s coverage -- for free."

    def format_text(self) -> str:
        lines: list[str] = []
        lines.append("")
        lines.append("  QUERYSENSE vs " + self.source_tool.upper() + " -- SWITCH REPORT")
        lines.append("  " + "=" * 60)
        lines.append("")

        # Import summary
        lines.append(f"  Imported: {self.queries_imported} queries from {self.source_tool}")
        lines.append(f"  Analyzed: {self.plans_analyzed} EXPLAIN plans")
        lines.append(f"  Analysis time: {self.time_to_analyze_ms:.0f}ms")
        lines.append("")

        # Head-to-head
        lines.append("  HEAD-TO-HEAD COMPARISON")
        lines.append("  " + "-" * 50)
        lines.append(f"  {self.source_tool:>20s}: {self.competitor_recommendations} recommendation(s)")
        lines.append(f"  {'QuerySense':>20s}: {self.querysense_findings} finding(s)")
        if self.new_findings > 0:
            lines.append(
                f"  {'':>20s}  --> +{self.new_findings} NEW issues found by QuerySense"
            )
        lines.append("")

        # Finding details
        if self.finding_details:
            lines.append("  WHAT QUERYSENSE FOUND")
            lines.append("  " + "-" * 50)
            for i, detail in enumerate(self.finding_details[:15], 1):
                severity = detail.get("severity", "info").upper()
                title = detail.get("title", "Unknown")
                suggestion = detail.get("suggestion", "")
                lines.append(f"  {i:2d}. [{severity}] {title}")
                if suggestion:
                    # Truncate long suggestions
                    if len(suggestion) > 120:
                        suggestion = suggestion[:117] + "..."
                    lines.append(f"      Fix: {suggestion}")
            if len(self.finding_details) > 15:
                lines.append(f"      ... and {len(self.finding_details) - 15} more")
            lines.append("")

        # Performance insights
        if self.performance_insights:
            lines.append("  PERFORMANCE INSIGHTS")
            lines.append("  " + "-" * 50)
            for insight in self.performance_insights:
                lines.append(f"  - {insight}")
            lines.append("")

        # Pricing comparison
        if self.competitor_pricing:
            lines.append("  COST COMPARISON")
            lines.append("  " + "-" * 50)
            lines.append(f"  {self.source_tool}: {self.competitor_pricing}")
            lines.append(f"  QuerySense: Free forever (MIT license)")
            lines.append("")

        # Verdict
        lines.append("  " + "=" * 60)
        lines.append(f"  {self._verdict()}")
        lines.append("  " + "=" * 60)
        lines.append("")

        return "\n".join(lines)


COMPETITOR_PRICING: dict[str, str] = {
    "pganalyze": "$149+/mo (Scale plan)",
    "eversql": "$29+/mo",
    "datadog": "$70/host/mo (DBM)",
    "pgmustard": "EUR 95+/yr",
    "liquibase": "$175+/mo (Pro)",
    "flyway": "$65+/mo (Teams)",
}


def import_and_compare(
    path: str | Path,
    source: str | None = None,
) -> tuple[ImportResult, SwitchReport]:
    """
    Import from a competitor tool AND immediately run QuerySense analysis.

    Returns both the import result and a side-by-side comparison report
    showing what QuerySense found that the competitor missed.

    This is the "nuclear weapon" for driving competitor switching:
    one command, immediate proof of value.

    Usage:
        result, report = import_and_compare("pganalyze-export.json")
        print(report.format_text())
    """
    import time as _time

    # Step 1: Import
    result = import_from(path, source=source)

    # Step 2: Analyze all plans
    plans_with_data = [q for q in result.queries if q.plan_json]
    competitor_recs = len(result.indexes) + sum(
        len(q.recommendations) for q in result.queries
    )

    start = _time.perf_counter()
    all_findings: list[dict[str, Any]] = []
    performance_insights: list[str] = []

    if plans_with_data:
        try:
            from querysense.engine import AnalysisService
            from querysense.parser import parse_explain

            service = AnalysisService()

            total_time_ms = 0.0
            total_cost = 0.0

            for q in plans_with_data:
                try:
                    plan_data = q.plan_json
                    if isinstance(plan_data, dict) and "Plan" in plan_data:
                        plan_data = [plan_data]
                    elif isinstance(plan_data, dict):
                        plan_data = [{"Plan": plan_data}]

                    explain = parse_explain(plan_data)
                    analysis = service.analyze(explain, sql=q.sql or None)

                    if analysis.findings:
                        for f in analysis.findings:
                            all_findings.append({
                                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                                "title": f.title,
                                "rule_id": f.rule_id,
                                "suggestion": getattr(f, "suggestion", "") or "",
                                "impact_score": getattr(f, "impact_score", 0),
                            })

                    # Gather performance insights
                    if explain.root and hasattr(explain.root, "actual_total_time"):
                        actual_time = getattr(explain.root, "actual_total_time", 0) or 0
                        total_time_ms += actual_time
                        est_cost = getattr(explain.root, "total_cost", 0) or 0
                        total_cost += est_cost

                except Exception:
                    pass

            # Generate performance insights
            if total_time_ms > 1000:
                performance_insights.append(
                    f"Total execution time across plans: {total_time_ms:,.0f}ms "
                    f"-- potential for significant optimization"
                )

            critical = sum(1 for f in all_findings if f["severity"] == "critical")
            if critical > 0:
                performance_insights.append(
                    f"{critical} CRITICAL issue(s) found -- address these first for maximum impact"
                )

            seq_scans = sum(1 for f in all_findings if "SEQ_SCAN" in f.get("rule_id", ""))
            if seq_scans > 0:
                performance_insights.append(
                    f"{seq_scans} sequential scan(s) detected on large tables -- "
                    "indexes would dramatically improve performance"
                )

        except ImportError:
            pass

    elapsed_ms = (_time.perf_counter() - start) * 1000

    # Build switch report
    report = SwitchReport(
        source_tool=result.source,
        queries_imported=len(result.queries),
        plans_analyzed=len(plans_with_data),
        competitor_recommendations=competitor_recs,
        querysense_findings=len(all_findings),
        new_findings=max(0, len(all_findings) - competitor_recs),
        finding_details=all_findings,
        performance_insights=performance_insights,
        competitor_pricing=COMPETITOR_PRICING.get(result.source, ""),
        time_to_analyze_ms=elapsed_ms,
    )

    return result, report


def format_import_result(result: ImportResult) -> str:
    """Format import result for terminal display."""
    lines: list[str] = []

    lines.append("")
    lines.append(f"  IMPORTED FROM {result.source.upper()}")
    lines.append("  " + "=" * 50)
    lines.append(f"  Source file: {result.source_file}")
    lines.append("")

    if result.queries:
        lines.append(f"  Queries imported: {len(result.queries)}")
        plans = sum(1 for q in result.queries if q.plan_json)
        if plans:
            lines.append(f"  With EXPLAIN plans: {plans}")

    if result.indexes:
        lines.append(f"  Index recommendations: {len(result.indexes)}")

    if result.migrations:
        lines.append(f"  Migrations imported: {len(result.migrations)}")
        with_rb = sum(1 for m in result.migrations if m.rollback_sql)
        lines.append(f"  With rollback SQL: {with_rb}")

    if result.stats:
        lines.append("")
        for k, v in result.stats.items():
            lines.append(f"  {k}: {v}")

    if result.warnings:
        lines.append("")
        for w in result.warnings:
            lines.append(f"  [!] {w}")

    lines.append("")

    # Next steps
    lines.append("  NEXT STEPS:")
    lines.append("  " + "-" * 40)

    if result.queries:
        plans = [q for q in result.queries if q.plan_json]
        if plans:
            lines.append(
                "  Run analysis on imported plans:"
            )
            lines.append(
                "    querysense analyze <plan_file>"
            )

    if result.migrations:
        lines.append(
            "  Check migration safety:"
        )
        lines.append(
            "    querysense migrate-check <migration.sql>"
        )

    if result.indexes:
        lines.append(
            "  Validate index recommendations:"
        )
        lines.append(
            "    querysense simulate test --dsn $DSN"
        )

    lines.append("")

    return "\n".join(lines)
