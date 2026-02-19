# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.5.0] - 2026-02-13

### Added - Complete VACUUM Advisor (pganalyze's Crown Jewel, Free)

#### VACUUM Advisor CLI (`querysense vacuum`)
- `querysense vacuum --full` -- unified 4-category health report
- `querysense vacuum --bloat` -- table and index bloat analysis
- `querysense vacuum --freezing` -- XID wraparound risk monitoring
- `querysense vacuum --workers` -- autovacuum worker saturation and queue depth
- `querysense vacuum --throttling` -- cost-based throttling tuner (SSD auto-detection)
- `querysense vacuum --tune --table <name>` -- per-table autovacuum parameter generator
- `querysense vacuum --fix-script` -- generates complete SQL fix script
- `querysense vacuum --json` -- machine-readable JSON output

#### Xmin Horizon Blocker Detector (`querysense txns`)
- `querysense txns blocking-vacuum` -- finds idle-in-transaction, long queries, replication slots blocking vacuum
- Impact summary: dead tuples stuck, estimated bloat, wraparound risk

#### HOT Update Monitor (`querysense hot`)
- `querysense hot` -- per-table HOT ratio analysis
- Identifies indexes blocking HOT updates with fix commands
- Fillfactor recommendations for write-heavy tables
- Fix script generation

#### VacuumAdvisor Enhancements
- TOAST table bloat detection and large column identification
- Cost throttling analysis with SSD auto-detection (random_page_cost heuristic)
- Never-vacuumed table detection
- Multixact ID (MXID) wraparound tracking alongside XID
- Anti-wraparound vacuum detection
- Freeze map coverage analysis

#### Exports
- `HOTDetector`, `HOTAnalysis`, `HOTFinding` added to `querysense.__init__`
- `XminHorizonTracker`, `XminHorizonReport`, `XminBlocker` added
- `TOASTBloat`, `CostThrottlingInfo` added

## [1.4.0] - 2026-02-13

### Added - Universal Multi-Database Plan Analysis

#### Multi-DB Parser (`querysense.parser.multidb`)
- `parse_any()` -- universal plan parser that auto-detects engine and translates to common format
- `detect_engine()` -- heuristic engine detection from plan format (XML, JSON, text)
- `DatabaseEngine` enum -- postgresql, mysql, mariadb, sqlserver, oracle, duckdb, sqlite, clickhouse
- SQL Server XML SHOWPLAN -> ExplainOutput translator (full operator mapping)
- Oracle DBMS_XPLAN text -> ExplainOutput translator (80% operator coverage)
- DuckDB JSON EXPLAIN -> ExplainOutput translator
- SQLite EXPLAIN QUERY PLAN -> ExplainOutput translator
- ClickHouse JSON EXPLAIN -> ExplainOutput translator
- MariaDB support (MySQL-compatible, shares MySQL parser)

#### CLI Enhancement
- `querysense analyze --engine <name>` -- explicit engine selection
- Auto-detection: `.sqlplan` -> SQL Server, Oracle markers -> Oracle, etc.
- All 37+ analysis rules now apply to translated plans from any engine

#### Exports
- `parse_any`, `detect_engine`, `DatabaseEngine` added to `querysense.__init__`

## [1.3.0] - 2026-02-13

### Added - Validation Hub, Polish & Competitive Proof

#### Validation Hub
- `querysense validate` command -- reproducible benchmark harness
- Benchmark comparison suite: QuerySense vs pganalyze vs EverSQL vs pgMustard
- Publishable benchmark report with throughput proof (plans/sec)
- Automated regression detection between runs

#### Competitor Import Enhancements
- `querysense import --compare` -- instant side-by-side comparison report after import
- `SwitchReport` class with visual comparison of competitor vs QuerySense findings
- One-liner import-and-compare for pganalyze, EverSQL, Datadog, Liquibase, Flyway, pgMustard

#### Documentation & Quality
- Fixed all broken links, 404s, and stale references across README.md and docs/
- Aligned version references (removed stale 0.x references)
- Updated rule count badge to 37+ (actual count from rules/ directory)
- Removed dead image reference (query.png)
- Updated MySQL status from "Experimental" to "GA"
- Added CHANGELOG entries for all versions from 0.6.0 through 1.3.0

## [1.2.0] - 2026-02-12

### Added - pganalyze Deep Parity

#### Planner What-If Engine
- `PlannerWhatIf` class -- simulate PostgreSQL's cost model offline
- Sequential scan, index scan (Mackert-Lohman), bitmap scan, sort, hash join cost estimation
- `simulate_add_index()`, `simulate_knob_change()`, `simulate_batch()`
- CLI: `querysense whatif plan.json --add-index orders.customer_id`

#### Xmin Horizon Tracker
- `XminHorizonTracker` class -- identify transactions blocking VACUUM
- Analyzes `pg_stat_activity`, `pg_replication_slots`, `pg_prepared_xacts`
- Generates actionable fix SQL for each blocker
- CLI: `querysense xmin-horizon --dsn postgresql://...`

#### Ideal-Size Bloat Estimator
- `IdealSizeBloatEstimator` class -- calculates ideal table size from pg_stats
- PostgreSQL page layout constants for accurate estimation
- Compares actual vs ideal size to derive bloat percentage
- CLI: `querysense bloat --dsn postgresql://...`

#### Index Interaction Analyzer
- `IndexInteractionAnalyzer` class -- detect redundancy, overlap, conflict, synergy
- Prefix redundancy detection (e.g., idx(a) redundant with idx(a,b))
- Write overhead conflict analysis
- Bitmap AND synergy detection
- CLI: `querysense index-interactions --dsn postgresql://...`

#### Autovacuum Worker Utilization
- `AutovacuumAnalyzer` class -- monitor worker saturation, queue depth, I/O budget
- Per-table tuning recommendations
- CLI: `querysense autovacuum-status --dsn postgresql://...`

## [1.1.0] - 2026-02-11

### Added - pganalyze Parity Features

#### Cluster-Aware Index Advisor
- `querysense cluster detect/advise/unused` commands
- CP-SAT optimization across primary + replicas

#### Advisor Framework
- YAML-based configurable advisor checks (Percona PMM parity)
- `querysense advisor` subcommands

#### Collector & Monitoring
- `querysense collect`, `querysense monitor`, `querysense vacuum-history`
- Continuous stats collection with SQLite storage

#### pganalyze-Parity Audit Extras
- `querysense audit hot/iwo/deps/vacuum-full` checks
- HOT update detection, IWO calculation, functional dependency detection

## [1.0.0] - 2026-02-10

### Added - Next-Level Analysis (Predictive + Holistic)

#### Predictive Workload Optimization
- `PredictiveOptimizer` class with workload fingerprinting (frequency x cost)
- Candidate generation: indexes, knobs, rewrites, partitioning, materialized views
- Statistical impact estimation
- CLI: `querysense predict`

#### Holistic Tuner
- `HolisticTuner` class -- coordinated index + knob + hint optimization
- Interaction detection between tuning dimensions
- CLI: `querysense holistic`

#### GEQO Analyzer
- `GEQOAnalyzer` class -- genetic optimizer analysis for 12+ table joins
- Plan instability detection, suboptimal join order identification
- CLI: `querysense geqo`

#### t-Digest Statistics Engine
- `PerformanceTracker` with streaming t-digest percentile estimation (P50-P99.9)
- Anomaly detection and trend analysis
- Minimal memory footprint

#### Node-Level Profiler
- `NodeProfiler` class -- per-node bottleneck identification
- Exclusive vs inclusive time, I/O patterns, estimation error analysis
- CLI: `querysense profile-nodes`

#### Cost Model Calibrator
- `CostCalibrator` class -- compare estimated vs actual costs
- GUC parameter accuracy assessment
- CLI: `querysense calibrate`

#### Plan Stability Analyzer
- `PlanStabilityAnalyzer` class -- parameter sniffing detection
- Plan signature diffing, cost variance analysis
- CLI: `querysense stability`

#### Semantic Translation Layer
- `SemanticTranslator` class -- cross-DB recommendation translation
- PostgreSQL to MySQL, SQL Server, Oracle
- CLI: `querysense translate`

## [0.9.0] - 2026-02-09

### Added - Enterprise Readiness

#### SOC2 Audit Logging
- `AuditLogger` class with structured logging via structlog
- Audit trail for all analysis, migration, and configuration operations

#### RBAC System
- `RBACChecker` class with workspace-scoped permissions
- 4 roles: ANALYZE, MIGRATE, MANAGE_USERS, ADMIN

#### Concurrency Benchmark
- `ConcurrencyTester` class with async workload testing
- Progressive concurrency levels, breaking point detection
- CLI: `querysense bench`

#### Zero-Downtime Migration Planner
- `ZeroDowntimePlanner` class with 3-phase migrations (expand/migrate/contract)
- Batched backfill with pg_sleep throttling
- CLI: `querysense zero-downtime`

#### Rewrite Pattern Library
- 20+ rewrite patterns with safety validation
- NOT IN to NOT EXISTS, OR to IN, UNION to UNION ALL, and more
- CLI: `querysense rewrite`

#### Learning Paths
- `LearningPathGenerator` with personalized lessons
- Progressive: statistics -> indexing -> rewrites -> configuration
- CLI: `querysense learn`

## [0.8.0] - 2026-02-08

### Added - Database Intelligence

#### Config Auditor
- `querysense audit config/schema/indexes/vacuum/txn/repl` commands
- 20+ checks across 6 audit categories

#### Autovacuum Monitor
- Proactive vacuum health monitoring
- Dead tuple tracking and bloat prediction

#### ORM Anti-Pattern Detection
- 7 ORM anti-patterns: N+1 queries, SELECT *, unbounded queries, etc.
- CLI: `querysense orm-detect`

#### Query Classification
- `QueryClassifier` class: OLTP/OLAP/DYNAMIC/BATCH/MAINTENANCE
- CLI: `querysense classify`

#### Optimization Coach
- 10-step guided optimization wizard
- CLI: `querysense coach`

#### Dynamic Workload Advisor
- Query family analysis for parameterized queries
- CLI: `querysense workload-advisor`

#### Safe Migration Planner
- Replication-aware migration planning
- CLI: `querysense migration-plan`

## [0.7.0] - 2026-02-07

### Added - Platform Features

#### Competitor Import Toolkit
- Import from pganalyze, EverSQL, Datadog, Liquibase, Flyway, pgMustard
- Auto-format detection
- CLI: `querysense import`

#### Performance Budgets as Code
- YAML-based performance budget definitions
- CI/CD gating with `querysense budget check`

#### GitHub App Integration
- Auto-comment on PRs with migration analysis
- CLI: `querysense comment-pr`

#### Schema Drift Detection
- `querysense schema snapshot/compare/sync` commands

#### Kubernetes / Helm
- Helm chart for Kubernetes deployment
- OpenTelemetry integration

#### Web Dashboard
- `querysense web` for browser-based analysis

## [0.6.0] - 2026-02-07

### Added - Query Rewrite & Migration

#### SQL Rewrite Engine
- 8 initial rewrite patterns with sandbox testing
- CLI: `querysense rewrite`

#### Migration Generation
- 5 formats: Flyway, Liquibase, Alembic, Django, raw SQL
- CLI: `querysense migrate`

#### MySQL Support (GA)
- Full MySQL EXPLAIN JSON analysis with MySQL-specific rules
- CLI: `querysense mysql analyze`

#### Plan History
- SQLite-based plan tracking with regression detection
- CLI: `querysense history`

## [0.5.2] - 2026-02-06

### Added - Overkill Rigour System Design (Phase 1)

#### Typed Capability System
- `Capability` enum with typed capability tokens (not freeform strings)
- Categories: SQL_*, DB_*, EXPLAIN_*, PRIOR_*, rule-provided
- `check_requirements()` validates rule dependencies against available capabilities
- `build_rule_dag()` sorts rules by topological order, detects cycles

#### FactStore with Provenance
- `FactKey` enum for typed fact keys
- `FactStore` class tracks facts with provenance (source, evidence level, timestamp)
- `FactProvenance` dataclass for debugging and auditing
- Capabilities derive from facts + environment

#### AnalysisResult "Must-Populate" Fields
- All fields on `AnalysisResult` are now required (non-optional)
- `AnalysisResult.create()` factory enforces invariants
- `AnalysisResult.empty()` for testing backward compat
- Compile-time guarantee: if design says it exists, runtime emits it or fails

#### DAG Rule Execution
- Rules sorted by topological order based on requires/provides
- Cycle detection at startup with `CycleDetectedError`
- Missing capability → `RuleRunStatus.SKIP` with explicit skip_reason
- `RuleRun` always exists, even for skipped rules

### Changed
- `AnalysisContext` now wraps `FactStore` with typed access
- Analyzer uses `build_rule_dag()` instead of phase-only ordering
- Tests updated to use `AnalysisResult.empty()` factory

## [0.5.1] - 2026-02-06

### Fixed - Integration Wiring

#### Analyzer Now Uses New Infrastructure
- Analyzer properly populates `rule_runs`, `evidence_level`, `reproducibility` fields
- Uses new `SQLASTParser` instead of legacy `SQLQueryAnalyzer`
- Implements rule dependency checking via `requires`/`provides` capabilities
- Integrates `Config` for rule thresholds and enable/disable
- Cache key now includes `sql_hash` + `config_hash` for correctness

#### Rule Execution Status Tracking
- Every rule now reports PASS/SKIP/FAIL status with runtime_ms
- Rules can be skipped if capabilities (sql_ast, db_probe) unavailable
- `degraded` flag set when analysis runs with skipped/failed rules
- `degraded_reasons` tuple explains what went wrong

#### Reproducibility Info
- Each analysis generates `ReproducibilityInfo` with:
  - `analysis_id`: Unique ID for this run
  - `plan_hash`: Hash of the plan structure
  - `sql_hash`: Hash of SQL (if provided)
  - `config_hash`: Hash of configuration
  - `rules_hash`: Hash of ruleset versions

#### Backward Compatibility
- `summary()` method includes `errors` key for backward compat
- All 113 tests pass

## [0.5.0] - 2026-02-06

### Added - Design Upgrade (Overkill Rigour)

#### Evidence Level System (Principle: Deterministic Core, Progressive Enhancement)
- `EvidenceLevel` enum: `PLAN`, `PLAN+SQL`, `PLAN+SQL+DB`
- Explicit tracking of what data sources inform findings
- `evidence_level` field on `AnalysisResult`

#### SQL AST Parser with pglast (Principle: Use the Source of Truth)
- New `sql_ast.py` module using pglast (PostgreSQL's actual parser)
- `SQLConfidence` enum: `HIGH` (pglast), `MEDIUM` (sqlparse), `LOW` (failed)
- Falls back to sqlparse when pglast unavailable
- Hard rule: If AST parse fails, disable index advice or mark as heuristic

#### Rule Run Status (Principle: Observable Failure, Not Silent)
- `RuleRunStatus` enum: `PASS`, `SKIP`, `FAIL`
- `RuleRun` model with rule_id, version, status, runtime_ms, error_summary
- `rule_runs` tuple on `AnalysisResult` for explicit observability
- `degraded` flag when analysis ran with some rules skipped/failed

#### Configuration System (Principle: Config is Not Code)
- New `config.py` module following 12-factor principles
- `Config` class with environment variable loading
- Per-rule thresholds via `QUERYSENSE_RULE_<RULE_ID>_<SETTING>`
- Per-table overrides via `QUERYSENSE_TABLE_<TABLE>_<SETTING>`
- Environment profiles: development/staging/production

#### Impact Bands (Principle: Never Overclaim)
- `ImpactBand` enum: `LOW`, `MEDIUM`, `HIGH`, `UNKNOWN`
- `assumptions` field on `Finding` for explicit assumptions
- `verification_steps` field for actionable verification
- Replaces specific multiplier claims ("57x faster")

#### Database Probe for Level 3 Analysis
- New `db/` module with `DBProbe` protocol
- `AsyncpgProbe` implementation for PostgreSQL
- `list_indexes(table)`: Check if suggested indexes exist
- `table_stats(table)`: Get statistics freshness, row counts
- `settings()`: Get relevant PostgreSQL settings
- `query_stats(queryid)`: Query pg_stat_statements (optional)

#### Rule Dependency DAG
- `requires` and `provides` fields on `Rule` class
- Topological sort of rules based on dependencies
- Rules SKIP if prerequisites not met
- Built-in capabilities: `sql_ast`, `sql_ast_high`, `db_probe`

#### Output Module (Principle: Presentation ≠ Domain Logic)
- New `output/` module separating rendering from analysis
- `render_text()`: Rich terminal output for CLI
- `render_json()`: Stable JSON schema for API
- `render_markdown()`: GitHub/Slack-friendly format
- `AnalysisResultSchema` for OpenAPI integration

#### Plan Compare Mode (Principle: Track Change)
- Enhanced `comparator.py` with node-level diffs
- `NodeDiff` class tracking scan type changes, row/loop/buffer changes
- `PlanComparison` class with cost_reduction_percent, time_reduction_percent
- `compare_plans()` function for before/after plan comparison

#### Reproducibility Info
- `ReproducibilityInfo` model with hashes for bug reports
- `analysis_id`, `plan_hash`, `sql_hash`, `config_hash`, `rules_hash`
- Enables reproducible bug reports and cache validation

### Changed
- Version bump to 0.5.0
- `Finding` model now includes `impact_band`, `assumptions`, `verification_steps`
- `AnalysisResult` now includes `evidence_level`, `sql_confidence`, `rule_runs`, `reproducibility`
- `ExecutionMetadata` now includes `rules_skipped`, `analysis_duration_ms`, `cache_hit`
- `Rule` base class now supports `requires` and `provides` for dependency DAG
- `RuleContext` class added for advanced rule execution

### Dependencies
- Added optional `pglast>=6.0` for accurate SQL parsing
- Added optional `psycopg[binary]>=3.1.0` for DB probe

---

## [0.4.0] - 2026-02-06

### Added
- Thread-safe analyzer using `contextvars` (fixes race condition in concurrent usage)
- Async support via `analyze_async()` method for web servers and async applications
- Built-in LRU caching with `cache_enabled=True` option
- Structured observability with `AnalyzerMetrics` and `Tracer` classes
- `SQLEnhanceable` protocol for rules to provide SQL-enhanced recommendations
- `get_current_query_info()` function for thread-safe access to query context
- `SECURITY.md` with vulnerability reporting process
- `STABILITY.md` with stability guarantees
- `CHANGELOG.md` following Keep a Changelog format
- `py.typed` marker for PEP 561 compliance
- Backwards compatibility tests

### Changed
- `Analyzer` now uses `contextvars` instead of instance variables for thread safety
- SQL enhancement logic moved from hardcoded rule IDs to `SQLEnhanceable` protocol
- `SeqScanLargeTable` rule now implements `SQLEnhanceable` protocol (version 2.1.0)
- Updated dependency version bounds for stability

### Fixed
- **CRITICAL**: Thread-safety bug where `_current_query_info` was stored on instance
- Race condition when using same `Analyzer` instance across multiple threads

### Security
- Added `SECURITY.md` with vulnerability reporting process
- Thread-safety fix prevents potential data leakage in concurrent environments

---

## [0.3.1] - 2026-02-06

### Fixed
- Documentation improvements
- Minor bug fixes

---

## [0.3.0] - 2026-01-15

### Added
- Initial PyPI release
- PostgreSQL EXPLAIN JSON parser with resource limits
- Rule-based analyzer with 11 built-in detection rules
- CLI with `analyze`, `fix`, and `rules` commands
- Optional Claude AI explainer integration
- Index recommendation engine with cost estimation
- SQL query parsing for enhanced recommendations
- Plan fingerprinting for caching support
- Before/after comparison utilities

### Rules Included
- `SEQ_SCAN_LARGE_TABLE` - Sequential scans on large tables
- `BAD_ROW_ESTIMATE` - Severe planner estimation errors
- `NESTED_LOOP_LARGE_TABLE` - O(n*m) nested loop problems
- `SPILLING_TO_DISK` - Hash/sort operations spilling to disk
- `MISSING_BUFFERS` - Missing BUFFERS option in EXPLAIN
- `FOREIGN_KEY_INDEX` - Foreign keys without indexes
- `STALE_STATISTICS` - Outdated table statistics
- `TABLE_BLOAT` - Table bloat issues
- `CORRELATED_SUBQUERY` - Correlated subqueries
- `EXCESSIVE_SEQ_SCANS` - Multiple sequential scans
- `PARALLEL_QUERY_NOT_USED` - Parallel query opportunities

---

## Migration Guide

### Upgrading to 0.4.0

#### Thread Safety Changes

The analyzer is now thread-safe. If you were using workarounds for the thread-safety issue, you can remove them:

```python
# Before (workaround)
def analyze_query(query):
    analyzer = Analyzer()  # Create new instance per call
    return analyzer.analyze(query)

# After (0.4.0+)
analyzer = Analyzer()  # Safe to share across threads
def analyze_query(query):
    return analyzer.analyze(query)  # Thread-safe
```

#### New Caching Feature

Enable caching for repeated analysis:

```python
# New in 0.4.0
analyzer = Analyzer(
    cache_enabled=True,
    cache_size=100,
    cache_ttl=300.0,
)
```

#### Async Support

For async applications:

```python
# New in 0.4.0
result = await analyzer.analyze_async(explain, sql)
```

#### Custom Rules with SQL Enhancement

If you have custom rules that need SQL-based enhancement:

```python
from querysense.analyzer.rules.base import Rule, SQLEnhanceable

class MyRule(Rule, SQLEnhanceable):
    def enhance_with_sql(self, finding, query_info):
        # Provide better suggestions when SQL is available
        return finding.model_copy(update={"suggestion": "..."})
```

---

## Version History

| Version | Release Date | Python | Status |
|---------|--------------|--------|--------|
| 1.3.0   | 2026-02-13   | 3.11+  | Current |
| 1.2.0   | 2026-02-12   | 3.11+  | Supported |
| 1.1.0   | 2026-02-11   | 3.11+  | Supported |
| 1.0.0   | 2026-02-10   | 3.11+  | Supported |
| 0.9.0   | 2026-02-09   | 3.11+  | Supported |
| 0.8.0   | 2026-02-08   | 3.11+  | Supported |
| 0.7.0   | 2026-02-07   | 3.11+  | Supported |
| 0.6.0   | 2026-02-07   | 3.11+  | Supported |
| 0.5.2   | 2026-02-06   | 3.11+  | Supported |
| 0.5.0   | 2026-02-06   | 3.11+  | Supported |
| 0.4.0   | 2026-02-06   | 3.11+  | Supported |
| 0.3.0   | 2026-01-15   | 3.11+  | Initial release |

[Unreleased]: https://github.com/JosephAhn23/Query-Sense/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/JosephAhn23/Query-Sense/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/JosephAhn23/Query-Sense/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/JosephAhn23/Query-Sense/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/JosephAhn23/Query-Sense/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/JosephAhn23/Query-Sense/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/JosephAhn23/Query-Sense/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/JosephAhn23/Query-Sense/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/JosephAhn23/Query-Sense/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/JosephAhn23/Query-Sense/compare/v0.5.0...v0.5.2
[0.5.0]: https://github.com/JosephAhn23/Query-Sense/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/JosephAhn23/Query-Sense/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/JosephAhn23/Query-Sense/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/JosephAhn23/Query-Sense/releases/tag/v0.3.0
