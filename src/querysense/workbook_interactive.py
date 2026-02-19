"""
Interactive Query Tuning Workbook — persistent, multi-step optimization.

Builds on TuningWorkbook (one-shot automated) with a persistent, interactive
workflow where users explicitly manage parameter sets, variants, and comparisons.

pganalyze charges $500/mo for their beta Workbooks feature (web-only).
This is free, CLI-first, and scriptable.

Workflow:
    1. init     — Create a workbook with a SQL query
    2. add-params — Add parameter sets to test
    3. baseline  — Run baseline with all params against live DB
    4. variant   — Add SQL/index variants
    5. test      — Test all variants against all param sets
    6. compare   — Show winner matrix
    7. apply     — Generate migration for winning variant

Storage: SQLite at ~/.querysense/workbooks.db

Usage:
    from querysense.workbook_interactive import WorkbookManager

    mgr = WorkbookManager()
    wb_id = mgr.init("SELECT * FROM orders WHERE user_id = $1", "orders_opt")
    mgr.add_params(wb_id, {"user_id": 1, "status": "shipped"})
    mgr.add_params(wb_id, {"user_id": 50000, "status": "pending"})
    await mgr.run_baseline(wb_id, dsn)
    mgr.add_variant(wb_id, "composite_idx", index_sql="CREATE INDEX ...")
    await mgr.run_variants(wb_id, dsn)
    report = mgr.compare(wb_id)
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DB_PATH = Path.home() / ".querysense" / "workbooks.db"


# ── Data structures ──────────────────────────────────────────────────────


@dataclass
class ParamSet:
    """A set of parameter values to test a query with."""

    id: int = 0
    workbook_id: int = 0
    label: str = ""
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "params": self.params,
        }


@dataclass
class WorkbookVariant:
    """A query variant to test."""

    id: int = 0
    workbook_id: int = 0
    name: str = ""
    sql: str = ""
    index_sql: str = ""
    config_sql: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "sql": self.sql,
            "index_sql": self.index_sql,
            "config_sql": self.config_sql,
            "description": self.description,
        }


@dataclass
class RunResult:
    """Result of running a query variant with a parameter set."""

    id: int = 0
    workbook_id: int = 0
    variant_name: str = ""
    param_label: str = ""
    execution_time_ms: float = 0.0
    planning_time_ms: float = 0.0
    total_cost: float = 0.0
    rows_returned: int = 0
    shared_hit: int = 0
    shared_read: int = 0
    node_type: str = ""
    plan_json: str = ""
    error: str = ""
    run_at: str = ""

    @property
    def cache_hit_pct(self) -> float:
        total = self.shared_hit + self.shared_read
        return (self.shared_hit / total * 100) if total > 0 else 100.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "variant_name": self.variant_name,
            "param_label": self.param_label,
            "execution_time_ms": round(self.execution_time_ms, 2),
            "planning_time_ms": round(self.planning_time_ms, 2),
            "total_cost": round(self.total_cost, 2),
            "rows_returned": self.rows_returned,
            "shared_hit": self.shared_hit,
            "shared_read": self.shared_read,
            "cache_hit_pct": round(self.cache_hit_pct, 1),
            "node_type": self.node_type,
            "error": self.error,
        }


@dataclass
class ComparisonCell:
    """One cell in the comparison matrix: variant x param_set."""

    variant_name: str = ""
    param_label: str = ""
    time_ms: float = 0.0
    baseline_time_ms: float = 0.0
    speedup: float = 0.0
    is_winner: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "variant_name": self.variant_name,
            "param_label": self.param_label,
            "time_ms": round(self.time_ms, 2),
            "baseline_time_ms": round(self.baseline_time_ms, 2),
            "speedup": round(self.speedup, 1),
            "is_winner": self.is_winner,
            "error": self.error,
        }


@dataclass
class ComparisonReport:
    """Full comparison across all variants and parameter sets."""

    workbook_name: str = ""
    sql: str = ""
    cells: list[ComparisonCell] = field(default_factory=list)
    overall_winner: str = ""
    param_labels: list[str] = field(default_factory=list)
    variant_names: list[str] = field(default_factory=list)

    def get_cell(self, variant: str, param: str) -> ComparisonCell | None:
        for c in self.cells:
            if c.variant_name == variant and c.param_label == param:
                return c
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "workbook_name": self.workbook_name,
            "sql": self.sql,
            "param_labels": self.param_labels,
            "variant_names": self.variant_names,
            "cells": [c.to_dict() for c in self.cells],
            "overall_winner": self.overall_winner,
        }


@dataclass
class WorkbookInfo:
    """Summary of a workbook."""

    id: int = 0
    name: str = ""
    sql: str = ""
    created_at: str = ""
    param_count: int = 0
    variant_count: int = 0
    run_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "sql": self.sql[:100],
            "created_at": self.created_at,
            "param_count": self.param_count,
            "variant_count": self.variant_count,
            "run_count": self.run_count,
        }


# ── Workbook Manager ─────────────────────────────────────────────────────


class WorkbookManager:
    """
    Persistent workbook manager backed by SQLite.

    All workbook state (SQL, params, variants, results) is stored locally
    at ~/.querysense/workbooks.db.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS workbooks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    sql TEXT NOT NULL,
                    query_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS param_sets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workbook_id INTEGER NOT NULL REFERENCES workbooks(id),
                    label TEXT NOT NULL,
                    params_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS variants (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workbook_id INTEGER NOT NULL REFERENCES workbooks(id),
                    name TEXT NOT NULL,
                    sql TEXT NOT NULL DEFAULT '',
                    index_sql TEXT NOT NULL DEFAULT '',
                    config_sql TEXT NOT NULL DEFAULT '',
                    description TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS run_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workbook_id INTEGER NOT NULL REFERENCES workbooks(id),
                    variant_name TEXT NOT NULL,
                    param_label TEXT NOT NULL,
                    execution_time_ms REAL NOT NULL DEFAULT 0,
                    planning_time_ms REAL NOT NULL DEFAULT 0,
                    total_cost REAL NOT NULL DEFAULT 0,
                    rows_returned INTEGER NOT NULL DEFAULT 0,
                    shared_hit INTEGER NOT NULL DEFAULT 0,
                    shared_read INTEGER NOT NULL DEFAULT 0,
                    node_type TEXT NOT NULL DEFAULT '',
                    plan_json TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    run_at TEXT NOT NULL
                );
            """)

    # ── Init ─────────────────────────────────────────────────────────

    def init(self, sql: str, name: str = "") -> int:
        """Create a new workbook. Returns workbook ID."""
        if not name:
            name = f"workbook_{hashlib.md5(sql.encode()).hexdigest()[:8]}"

        query_hash = hashlib.md5(sql.encode()).hexdigest()
        now = datetime.now(timezone.utc).isoformat()

        with sqlite3.connect(str(self.db_path)) as conn:
            cur = conn.execute(
                "INSERT INTO workbooks (name, sql, query_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, sql, query_hash, now),
            )
            return cur.lastrowid  # type: ignore[return-value]

    # ── Parameter Sets ───────────────────────────────────────────────

    def add_params(self, workbook_id: int, params: dict[str, Any], label: str = "") -> int:
        """Add a parameter set. Returns param set ID."""
        if not label:
            label = ",".join(f"{k}={v}" for k, v in params.items())

        with sqlite3.connect(str(self.db_path)) as conn:
            cur = conn.execute(
                "INSERT INTO param_sets (workbook_id, label, params_json) VALUES (?, ?, ?)",
                (workbook_id, label, json.dumps(params)),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def get_params(self, workbook_id: int) -> list[ParamSet]:
        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT id, workbook_id, label, params_json FROM param_sets WHERE workbook_id = ?",
                (workbook_id,),
            ).fetchall()
            return [
                ParamSet(id=r[0], workbook_id=r[1], label=r[2], params=json.loads(r[3]))
                for r in rows
            ]

    # ── Variants ─────────────────────────────────────────────────────

    def add_variant(
        self,
        workbook_id: int,
        name: str,
        sql: str = "",
        index_sql: str = "",
        config_sql: str = "",
        description: str = "",
    ) -> int:
        """Add a query variant. Returns variant ID."""
        with sqlite3.connect(str(self.db_path)) as conn:
            cur = conn.execute(
                "INSERT INTO variants (workbook_id, name, sql, index_sql, config_sql, description) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (workbook_id, name, sql, index_sql, config_sql, description),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def get_variants(self, workbook_id: int) -> list[WorkbookVariant]:
        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT id, workbook_id, name, sql, index_sql, config_sql, description "
                "FROM variants WHERE workbook_id = ?",
                (workbook_id,),
            ).fetchall()
            return [
                WorkbookVariant(id=r[0], workbook_id=r[1], name=r[2], sql=r[3],
                                index_sql=r[4], config_sql=r[5], description=r[6])
                for r in rows
            ]

    # ── Run Baseline ─────────────────────────────────────────────────

    async def run_baseline(self, workbook_id: int, dsn: str) -> list[RunResult]:
        """Run the original query with each parameter set."""
        wb = self._get_workbook(workbook_id)
        params = self.get_params(workbook_id)

        if not params:
            raise ValueError("No parameter sets defined. Use add_params() first.")

        results: list[RunResult] = []
        import asyncpg

        conn = await asyncpg.connect(dsn)
        try:
            for ps in params:
                result = await self._execute_explain(
                    conn, wb["sql"], ps.params, "baseline", ps.label, workbook_id,
                )
                results.append(result)
        finally:
            await conn.close()

        return results

    # ── Run Variants ─────────────────────────────────────────────────

    async def run_variants(self, workbook_id: int, dsn: str) -> list[RunResult]:
        """Run all variants with all parameter sets."""
        wb = self._get_workbook(workbook_id)
        params = self.get_params(workbook_id)
        variants = self.get_variants(workbook_id)

        if not params:
            raise ValueError("No parameter sets. Use add_params() first.")
        if not variants:
            raise ValueError("No variants. Use add_variant() first.")

        results: list[RunResult] = []
        import asyncpg

        conn = await asyncpg.connect(dsn)
        try:
            for variant in variants:
                for ps in params:
                    # Apply index if specified
                    if variant.index_sql:
                        try:
                            await conn.execute(variant.index_sql)
                        except Exception as e:
                            logger.warning("Index creation failed: %s", e)

                    # Apply config if specified
                    if variant.config_sql:
                        for cmd in variant.config_sql.split(";"):
                            cmd = cmd.strip()
                            if cmd:
                                try:
                                    await conn.execute(cmd)
                                except Exception:
                                    pass

                    sql = variant.sql or wb["sql"]
                    result = await self._execute_explain(
                        conn, sql, ps.params, variant.name, ps.label, workbook_id,
                    )
                    results.append(result)

                    # Clean up temp indexes (best effort)
                    if variant.index_sql and "CREATE INDEX" in variant.index_sql.upper():
                        idx_name = self._extract_index_name(variant.index_sql)
                        if idx_name:
                            try:
                                await conn.execute(f"DROP INDEX IF EXISTS {idx_name}")
                            except Exception:
                                pass

                    # Reset config
                    if variant.config_sql:
                        try:
                            await conn.execute("RESET ALL")
                        except Exception:
                            pass
        finally:
            await conn.close()

        return results

    # ── Compare ──────────────────────────────────────────────────────

    def compare(self, workbook_id: int) -> ComparisonReport:
        """Build comparison matrix from all run results."""
        wb = self._get_workbook(workbook_id)
        results = self._get_results(workbook_id)

        param_labels = sorted({r.param_label for r in results})
        variant_names = sorted({r.variant_name for r in results})

        # Build lookup: (variant, param) -> best time
        best: dict[tuple[str, str], RunResult] = {}
        for r in results:
            key = (r.variant_name, r.param_label)
            if key not in best or r.execution_time_ms < best[key].execution_time_ms:
                best[key] = r

        cells: list[ComparisonCell] = []
        variant_total_speedup: dict[str, float] = {}

        for param in param_labels:
            baseline_result = best.get(("baseline", param))
            baseline_ms = baseline_result.execution_time_ms if baseline_result else 0.0

            param_winner = ""
            param_best_ms = float("inf")

            for variant in variant_names:
                result = best.get((variant, param))
                if not result:
                    cells.append(ComparisonCell(
                        variant_name=variant, param_label=param, error="no data",
                    ))
                    continue

                speedup = (
                    baseline_ms / result.execution_time_ms
                    if result.execution_time_ms > 0 and baseline_ms > 0
                    else 0.0
                )

                cell = ComparisonCell(
                    variant_name=variant,
                    param_label=param,
                    time_ms=result.execution_time_ms,
                    baseline_time_ms=baseline_ms,
                    speedup=speedup,
                    error=result.error,
                )
                cells.append(cell)

                if variant != "baseline" and result.execution_time_ms < param_best_ms:
                    param_best_ms = result.execution_time_ms
                    param_winner = variant

                variant_total_speedup[variant] = (
                    variant_total_speedup.get(variant, 0) + speedup
                )

            # Mark winner for this param set
            for c in cells:
                if c.param_label == param and c.variant_name == param_winner:
                    c.is_winner = True

        # Overall winner: highest total speedup across all param sets
        non_baseline = {k: v for k, v in variant_total_speedup.items() if k != "baseline"}
        overall = max(non_baseline, key=non_baseline.get) if non_baseline else "baseline"

        return ComparisonReport(
            workbook_name=wb["name"],
            sql=wb["sql"],
            cells=cells,
            overall_winner=overall,
            param_labels=param_labels,
            variant_names=variant_names,
        )

    # ── Apply ────────────────────────────────────────────────────────

    def generate_migration(self, workbook_id: int, variant_name: str) -> str:
        """Generate migration SQL for the winning variant."""
        variants = self.get_variants(workbook_id)
        target = next((v for v in variants if v.name == variant_name), None)
        if not target:
            return f"-- Variant '{variant_name}' not found"

        wb = self._get_workbook(workbook_id)
        lines: list[str] = [
            f"-- Migration generated by QuerySense Workbook: {wb['name']}",
            f"-- Winner: {variant_name}",
            f"-- Generated: {datetime.now(timezone.utc).isoformat()}",
            "",
        ]

        if target.index_sql:
            lines.append("-- Index creation")
            lines.append(target.index_sql.rstrip(";") + ";")
            lines.append("")

        if target.config_sql:
            lines.append("-- Configuration changes")
            for cmd in target.config_sql.split(";"):
                cmd = cmd.strip()
                if cmd:
                    lines.append(cmd + ";")
            lines.append("")

        if target.sql and target.sql != wb["sql"]:
            lines.append("-- Query rewrite")
            lines.append(f"-- Original: {wb['sql'][:200]}")
            lines.append(f"-- Rewritten: {target.sql[:200]}")

        return "\n".join(lines)

    # ── List / Get ───────────────────────────────────────────────────

    def list_workbooks(self) -> list[WorkbookInfo]:
        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute("""
                SELECT w.id, w.name, w.sql, w.created_at,
                    (SELECT COUNT(*) FROM param_sets WHERE workbook_id = w.id),
                    (SELECT COUNT(*) FROM variants WHERE workbook_id = w.id),
                    (SELECT COUNT(*) FROM run_results WHERE workbook_id = w.id)
                FROM workbooks w ORDER BY w.created_at DESC
            """).fetchall()
            return [
                WorkbookInfo(id=r[0], name=r[1], sql=r[2], created_at=r[3],
                             param_count=r[4], variant_count=r[5], run_count=r[6])
                for r in rows
            ]

    def get_workbook_by_name(self, name: str) -> dict[str, Any] | None:
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute(
                "SELECT id, name, sql, query_hash, created_at FROM workbooks WHERE name = ?",
                (name,),
            ).fetchone()
            if not row:
                return None
            return {"id": row[0], "name": row[1], "sql": row[2], "query_hash": row[3], "created_at": row[4]}

    def delete_workbook(self, workbook_id: int) -> None:
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("DELETE FROM run_results WHERE workbook_id = ?", (workbook_id,))
            conn.execute("DELETE FROM variants WHERE workbook_id = ?", (workbook_id,))
            conn.execute("DELETE FROM param_sets WHERE workbook_id = ?", (workbook_id,))
            conn.execute("DELETE FROM workbooks WHERE id = ?", (workbook_id,))

    # ── Internal ─────────────────────────────────────────────────────

    def _get_workbook(self, workbook_id: int) -> dict[str, Any]:
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute(
                "SELECT id, name, sql, query_hash, created_at FROM workbooks WHERE id = ?",
                (workbook_id,),
            ).fetchone()
            if not row:
                raise ValueError(f"Workbook {workbook_id} not found")
            return {"id": row[0], "name": row[1], "sql": row[2], "query_hash": row[3], "created_at": row[4]}

    def _get_results(self, workbook_id: int) -> list[RunResult]:
        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT id, workbook_id, variant_name, param_label, "
                "execution_time_ms, planning_time_ms, total_cost, rows_returned, "
                "shared_hit, shared_read, node_type, plan_json, error, run_at "
                "FROM run_results WHERE workbook_id = ? ORDER BY run_at DESC",
                (workbook_id,),
            ).fetchall()
            return [
                RunResult(
                    id=r[0], workbook_id=r[1], variant_name=r[2], param_label=r[3],
                    execution_time_ms=r[4], planning_time_ms=r[5], total_cost=r[6],
                    rows_returned=r[7], shared_hit=r[8], shared_read=r[9],
                    node_type=r[10], plan_json=r[11], error=r[12], run_at=r[13],
                )
                for r in rows
            ]

    async def _execute_explain(
        self,
        conn: Any,
        sql: str,
        params: dict[str, Any],
        variant_name: str,
        param_label: str,
        workbook_id: int,
    ) -> RunResult:
        """Execute EXPLAIN ANALYZE for a query with parameters."""
        now = datetime.now(timezone.utc).isoformat()
        result = RunResult(
            workbook_id=workbook_id,
            variant_name=variant_name,
            param_label=param_label,
            run_at=now,
        )

        try:
            # Build parameterized query
            param_values = list(params.values())
            explain_sql = f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {sql}"

            row = await conn.fetchval(explain_sql, *param_values)
            plan_data = json.loads(row) if isinstance(row, str) else row

            if isinstance(plan_data, list) and plan_data:
                plan = plan_data[0]
            elif isinstance(plan_data, dict):
                plan = plan_data
            else:
                plan = {}

            result.execution_time_ms = plan.get("Execution Time", 0.0)
            result.planning_time_ms = plan.get("Planning Time", 0.0)

            root = plan.get("Plan", {})
            result.total_cost = root.get("Total Cost", 0.0)
            result.rows_returned = root.get("Actual Rows", 0)
            result.shared_hit = root.get("Shared Hit Blocks", 0)
            result.shared_read = root.get("Shared Read Blocks", 0)
            result.node_type = root.get("Node Type", "")
            result.plan_json = json.dumps(plan_data)

        except Exception as e:
            result.error = str(e)
            logger.warning("Execution failed for %s/%s: %s", variant_name, param_label, e)

        # Store result
        self._store_result(result)
        return result

    def _store_result(self, r: RunResult) -> None:
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                "INSERT INTO run_results "
                "(workbook_id, variant_name, param_label, execution_time_ms, "
                "planning_time_ms, total_cost, rows_returned, shared_hit, shared_read, "
                "node_type, plan_json, error, run_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (r.workbook_id, r.variant_name, r.param_label, r.execution_time_ms,
                 r.planning_time_ms, r.total_cost, r.rows_returned, r.shared_hit,
                 r.shared_read, r.node_type, r.plan_json, r.error, r.run_at),
            )

    @staticmethod
    def _extract_index_name(sql: str) -> str:
        """Extract index name from CREATE INDEX statement."""
        import re
        m = re.search(r"CREATE\s+INDEX\s+(?:CONCURRENTLY\s+)?(\w+)", sql, re.IGNORECASE)
        return m.group(1) if m else ""
