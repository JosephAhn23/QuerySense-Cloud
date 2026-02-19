"""
Analyzer - rule engine for EXPLAIN plans with progressive enhancement.

Runs rules against an EXPLAIN output and returns findings.
Designed to work without any external dependencies (no LLM required).

Evidence Levels (progressive enhancement):
- Level 1 (PLAN): EXPLAIN JSON only -> findings are plan-evidenced
- Level 2 (PLAN+SQL): EXPLAIN JSON + SQL -> findings include SQL-derived hypotheses
- Level 3 (PLAN+SQL+DB): EXPLAIN + SQL + DB facts -> validated recommendations

Design Principles:
- Deterministic core: Works offline without LLM
- Observable failure: PASS/SKIP/FAIL status for every rule
- Never overclaim: Impact bands instead of specific multipliers
- Config is not code: Thresholds from environment, not hardcoded
- One concept, one module: Uses consolidated capabilities, dag, and observability
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any

from querysense.analyzer.capabilities import (
    Capability,
    FactKey,
    FactStore,
    check_requirements,
)
from querysense.analyzer.context import AnalysisContext
from querysense.analyzer.dag import CycleDetectedError, build_rule_dag
from querysense.analyzer.errors import RuleError
from querysense.analyzer.fingerprint import AnalysisCache, PlanFingerprint
from querysense.analyzer.models import (
    AnalysisResult,
    EvidenceLevel,
    ExecutionMetadata,
    Finding,
    ReproducibilityInfo,
    RulePhase,
    RuleRun,
    RuleRunStatus,
    Severity,
    SQLConfidence,
    compute_evidence_level,
)
from querysense.analyzer.observability import AnalyzerMetrics, Tracer
from querysense.analyzer.registry import get_registry
from querysense.analyzer.rules.base import Rule, RuleContext, SQLEnhanceable
from querysense.analyzer.sql_ast import (
    QueryInfo,
    SQLASTParser,
    SQLParseResult,
    is_pglast_available,
)

if TYPE_CHECKING:
    from querysense.config import Config
    from querysense.db.probe import DBProbe
    from querysense.ir.node import IRPlan
    from querysense.parser.models import ExplainOutput

logger = logging.getLogger(__name__)

# Package version for reproducibility
__version__ = "0.5.2"

# Thread-safe context variable for query info (fixes race condition)
_current_query_info: ContextVar[QueryInfo | None] = ContextVar(
    "current_query_info", default=None
)


def get_current_query_info() -> QueryInfo | None:
    """Get the current query info from context (thread-safe)."""
    return _current_query_info.get()


# Global metrics instance (can be replaced with custom instance)
_global_metrics = AnalyzerMetrics()


class Analyzer:
    """
    Rule-based query plan analyzer with progressive enhancement.

    Runs rules in two phases:
    1. PER_NODE rules: Analyze individual plan nodes
    2. AGGREGATE rules: Analyze patterns across findings

    Features:
    - Thread-safe: Uses contextvars for request-scoped state
    - Caching: Optional LRU cache with SQL/config-aware keys
    - Async: Supports both sync and async analysis
    - Observable: PASS/SKIP/FAIL status for every rule
    - Configurable: Thresholds from environment via Config
    - Progressive: Level 1 (PLAN) -> Level 2 (PLAN+SQL) -> Level 3 (PLAN+SQL+DB)

    Example:
        from querysense import parse_explain, Analyzer

        explain = parse_explain("plan.json")
        analyzer = Analyzer()
        result = analyzer.analyze(explain)

        for finding in result.findings:
            print(f"{finding.severity}: {finding.title}")
    """

    # Configuration constants (documented with rationale)
    DEFAULT_MAX_FINDINGS_PER_RULE: int = 100  # Prevent memory explosion from noisy rules
    DEFAULT_MAX_WORKERS: int = 4  # Balance parallelism vs thread overhead
    DEFAULT_CACHE_SIZE: int = 100  # Reasonable for typical usage patterns
    DEFAULT_CACHE_TTL: float = 300.0  # 5 minutes - plans may change

    def __init__(
        self,
        rules: list[Rule] | None = None,
        include_rules: set[str] | None = None,
        exclude_rules: set[str] | None = None,
        fail_fast: bool = False,
        max_findings_per_rule: int = DEFAULT_MAX_FINDINGS_PER_RULE,
        parallel: bool = True,
        max_workers: int = DEFAULT_MAX_WORKERS,
        # Caching options
        cache_enabled: bool = False,
        cache_size: int = DEFAULT_CACHE_SIZE,
        cache_ttl: float = DEFAULT_CACHE_TTL,
        # Observability options
        metrics: AnalyzerMetrics | None = None,
        tracing_enabled: bool = False,
        # Config integration
        config: "Config | None" = None,
        # Level 3: Database probe
        db_probe: "DBProbe | None" = None,
        # SQL parsing options
        prefer_pglast: bool = True,
    ) -> None:
        """
        Initialize the analyzer.

        Args:
            rules: Custom rules to use (if None, uses registry)
            include_rules: Only run these rule IDs
            exclude_rules: Skip these rule IDs
            fail_fast: Raise on first rule error
            max_findings_per_rule: Limit findings per rule (default: 100)
            parallel: Run rules in parallel
            max_workers: Thread pool size for parallel execution (default: 4)
            cache_enabled: Enable LRU caching of analysis results
            cache_size: Maximum number of cached results (default: 100)
            cache_ttl: Cache TTL in seconds (default: 300)
            metrics: Custom metrics instance (default: global metrics)
            tracing_enabled: Enable detailed tracing for debugging
            config: Configuration instance (if None, uses get_config())
            db_probe: Database probe for Level 3 analysis (validated recommendations)
            prefer_pglast: Prefer pglast (accurate) over sqlparse (heuristic)
        """
        # Load config
        self.config = config
        if self.config is None:
            try:
                from querysense.config import get_config
                self.config = get_config()
            except Exception as e:
                logger.warning(
                    "Failed to load config, falling back to defaults: %s", e
                )
                self.config = None

        # Initialize rules
        if rules is not None:
            self.rules = rules
        else:
            registry = get_registry()
            rule_classes = registry.filter(include=include_rules, exclude=exclude_rules)
            self.rules = [cls() for cls in rule_classes]

        # Filter rules based on config
        if self.config is not None:
            self.rules = [
                r for r in self.rules
                if self.config.is_rule_enabled(r.rule_id)
            ]

        self.fail_fast = fail_fast
        self.max_findings_per_rule = max_findings_per_rule
        self.parallel = parallel
        self.max_workers = max_workers

        # Caching
        self.cache_enabled = cache_enabled
        self._cache: AnalysisCache | None = None
        if cache_enabled:
            self._cache = AnalysisCache(max_size=cache_size, ttl_seconds=cache_ttl)

        # Observability (from consolidated observability module)
        self.metrics = metrics if metrics is not None else _global_metrics
        self.tracing_enabled = tracing_enabled

        # Level 3: Database probe
        self.db_probe = db_probe

        # SQL parsing
        self.prefer_pglast = prefer_pglast
        self._sql_parser = SQLASTParser(prefer_pglast=prefer_pglast)

        # Compute rules hash for reproducibility
        self._rules_hash = self._compute_rules_hash()

        # Validate and sort rules by DAG (topological order)
        # Uses the consolidated dag module
        try:
            self.rules = build_rule_dag(self.rules)
            self._dag_validated = True
        except CycleDetectedError as e:
            logger.error("Rule dependency cycle detected: %s", e)
            self._dag_validated = False
        except Exception as e:
            logger.warning("Could not build rule DAG: %s. Using legacy execution.", e)
            self._dag_validated = False

    def _compute_rules_hash(self) -> str:
        """Compute hash of ruleset versions for cache key."""
        rules_info = sorted(f"{r.rule_id}:{r.version}" for r in self.rules)
        return hashlib.sha256("|".join(rules_info).encode()).hexdigest()[:16]

    def analyze(
        self,
        explain: "ExplainOutput",
        sql: str | None = None,
    ) -> AnalysisResult:
        """
        Analyze an EXPLAIN output for performance issues.

        This method is thread-safe - multiple threads can call analyze()
        on the same Analyzer instance concurrently.

        Args:
            explain: Parsed EXPLAIN output
            sql: Optional SQL query for enhanced analysis

        Returns:
            AnalysisResult with findings, rule_runs, evidence_level, and metadata
        """
        start_time = time.perf_counter()
        tracer = Tracer(enabled=self.tracing_enabled)
        tracer.start_span("analyze", sql_provided=sql is not None)
        analysis_id = str(uuid.uuid4())[:8]
        degraded_reasons: list[str] = []

        try:
            # Step 1: Fingerprint the plan
            tracer.start_span("fingerprint")
            fingerprint = PlanFingerprint.from_explain(explain)
            tracer.end_span()

            # Step 2: Parse SQL (if provided)
            sql_parse_result, query_info, sql_confidence, sql_hash = (
                self._parse_sql(sql, tracer, degraded_reasons)
            )

            # Step 3: Determine evidence level
            evidence_level = self._determine_evidence_level(query_info, sql_confidence)

            # Step 4: Build reproducibility info
            reproducibility = self._build_reproducibility(
                analysis_id, fingerprint, sql_hash,
            )

            # Step 5: Check cache
            if self.cache_enabled and self._cache is not None:
                cached_result = self._check_cache(
                    reproducibility, start_time, tracer,
                )
                if cached_result is not None:
                    return cached_result

            # Step 6: Build analysis context and populate facts
            fact_store = self._build_context(
                explain, fingerprint, sql_parse_result,
                query_info, sql_confidence, sql_hash,
                evidence_level, tracer, degraded_reasons,
            )

            # Step 7: Execute rules in two phases
            rule_runs: list[RuleRun] = []
            token = _current_query_info.set(query_info)
            try:
                all_findings = self._execute_rule_phases(
                    explain, fact_store, query_info, sql_confidence,
                    rule_runs, tracer,
                )
            finally:
                _current_query_info.reset(token)

            # Step 8: Build and return result
            return self._build_result(
                all_findings, rule_runs, evidence_level, sql_confidence,
                reproducibility, degraded_reasons, explain,
                fingerprint, start_time, tracer,
            )

        finally:
            tracer.end_span()
            if self.tracing_enabled:
                trace = tracer.get_trace()
                if trace:
                    logger.debug("Analysis trace: %s", trace)

    # ── Private orchestration methods ─────────────────────────────────

    def _parse_sql(
        self,
        sql: str | None,
        tracer: Tracer,
        degraded_reasons: list[str],
    ) -> tuple[
        "SQLParseResult | None",
        "QueryInfo | None",
        SQLConfidence,
        "str | None",
    ]:
        """Parse SQL query if provided. Returns (parse_result, query_info, confidence, hash)."""
        if not sql:
            return None, None, SQLConfidence.NONE, None

        tracer.start_span("sql_parse")
        try:
            sql_parse_result = self._sql_parser.parse(sql)
            query_info = sql_parse_result.query_info
            sql_confidence = sql_parse_result.confidence
            sql_hash = sql_parse_result.sql_hash

            logger.debug(
                "SQL parsed: confidence=%s, %d tables, %d filter cols",
                sql_confidence.value,
                len(query_info.tables),
                len(query_info.filter_columns),
            )

            if sql_confidence == SQLConfidence.LOW:
                degraded_reasons.append(
                    f"SQL parse failed: {sql_parse_result.parse_error}"
                )

            return sql_parse_result, query_info, sql_confidence, sql_hash

        except Exception as e:
            logger.warning("Failed to parse SQL query: %s", e)
            degraded_reasons.append(f"SQL parse exception: {e}")
            return None, None, SQLConfidence.NONE, None
        finally:
            tracer.end_span()

    def _determine_evidence_level(
        self,
        query_info: "QueryInfo | None",
        sql_confidence: SQLConfidence,
    ) -> EvidenceLevel:
        """Determine the evidence level from available data sources."""
        if self.db_probe is not None and query_info is not None:
            return EvidenceLevel.PLAN_SQL_DB
        if query_info is not None and sql_confidence != SQLConfidence.LOW:
            return EvidenceLevel.PLAN_SQL
        return EvidenceLevel.PLAN

    def _build_reproducibility(
        self,
        analysis_id: str,
        fingerprint: PlanFingerprint,
        sql_hash: str | None,
    ) -> ReproducibilityInfo:
        """Build reproducibility info for cache keys and bug reports."""
        config_hash = "no-config"
        if self.config is not None:
            try:
                config_hash = self.config.config_hash()
            except Exception:
                config_hash = "config-hash-error"
        return ReproducibilityInfo(
            analysis_id=analysis_id,
            plan_hash=fingerprint.full_hash,
            sql_hash=sql_hash,
            config_hash=config_hash,
            rules_hash=self._rules_hash,
            querysense_version=__version__,
        )

    def _check_cache(
        self,
        reproducibility: ReproducibilityInfo,
        start_time: float,
        tracer: Tracer,
    ) -> AnalysisResult | None:
        """Check cache for existing result. Returns cached result or None."""
        assert self._cache is not None
        tracer.start_span("cache_lookup")
        extended_key = reproducibility.cache_key
        cached = self._cache.get_extended(extended_key)
        tracer.end_span()

        if cached is not None:
            duration_ms = (time.perf_counter() - start_time) * 1000
            self.metrics.record_analysis(
                duration_ms=duration_ms,
                findings_count=len(cached.result.findings),
                errors_count=len(cached.result.errors),
                cache_hit=True,
            )
            logger.debug("Cache hit for key %s", extended_key[:8])
            return cached.result

        return None

    def _build_context(
        self,
        explain: "ExplainOutput",
        fingerprint: PlanFingerprint,
        sql_parse_result: "SQLParseResult | None",
        query_info: "QueryInfo | None",
        sql_confidence: SQLConfidence,
        sql_hash: str | None,
        evidence_level: EvidenceLevel,
        tracer: Tracer,
        degraded_reasons: list[str],
    ) -> FactStore:
        """Build analysis context and populate the FactStore."""
        tracer.start_span("context_setup")
        analysis_ctx = AnalysisContext(
            explain=explain,
            db_probe=self.db_probe,
        )
        fact_store = analysis_ctx.fact_store

        # Add plan-derived facts
        fact_store.set(FactKey.PLAN_FINGERPRINT, fingerprint, source_rule="analyzer")
        fact_store.set(FactKey.PLAN_NODE_COUNT, len(explain.all_nodes), source_rule="analyzer")

        # Build IR plan for engine-agnostic analysis
        tracer.start_span("ir_build")
        try:
            ir_plan = self._build_ir_plan(explain)
            if ir_plan is not None:
                fact_store.set(FactKey.IR_PLAN, ir_plan, source_rule="analyzer")
                fact_store.set(FactKey.IR_ENGINE, ir_plan.engine.value, source_rule="analyzer")
                from querysense.ir.node import EngineType
                if ir_plan.engine == EngineType.POSTGRESQL:
                    fact_store.add_capability(Capability.ENGINE_POSTGRESQL)
                elif ir_plan.engine == EngineType.MYSQL:
                    fact_store.add_capability(Capability.ENGINE_MYSQL)
        except Exception as e:
            logger.debug("IR plan construction skipped: %s", e)
            degraded_reasons.append(f"IR construction skipped: {e}")
        tracer.end_span()

        # Store SQL parse results as facts
        if sql_parse_result:
            fact_store.set(
                FactKey.SQL_HASH, sql_hash,
                source_rule="sql_parser",
                evidence_level=evidence_level.value,
            )
            fact_store.set(
                FactKey.SQL_CONFIDENCE, sql_confidence.value,
                source_rule="sql_parser",
            )
            if sql_parse_result.ast:
                fact_store.set(FactKey.SQL_AST, sql_parse_result.ast, source_rule="sql_parser")
            if query_info:
                fact_store.set(FactKey.SQL_TABLES, query_info.tables, source_rule="sql_parser")

            # Add SQL-derived capabilities based on confidence
            if sql_confidence == SQLConfidence.HIGH:
                fact_store.add_capability(Capability.SQL_AST)
                fact_store.add_capability(Capability.SQL_AST_HIGH)
                fact_store.add_capability(Capability.SQL_TABLES)
            elif sql_confidence == SQLConfidence.MEDIUM:
                fact_store.add_capability(Capability.SQL_AST)
                fact_store.add_capability(Capability.SQL_TABLES)

        tracer.end_span()
        return fact_store

    def _execute_rule_phases(
        self,
        explain: "ExplainOutput",
        fact_store: FactStore,
        query_info: "QueryInfo | None",
        sql_confidence: SQLConfidence,
        rule_runs: list[RuleRun],
        tracer: Tracer,
    ) -> list[Finding]:
        """Execute rules in two phases (PER_NODE then AGGREGATE)."""
        capabilities = fact_store.capabilities

        # Split rules by phase
        per_node_rules = [r for r in self.rules if r.phase == RulePhase.PER_NODE]
        aggregate_rules = [r for r in self.rules if r.phase == RulePhase.AGGREGATE]

        # Phase 1: PER_NODE rules (DAG-sorted)
        tracer.start_span("phase1_per_node", rule_count=len(per_node_rules))
        phase1_findings, phase1_runs = self._run_rules_with_status(
            per_node_rules, explain, prior_findings=[],
            capabilities=capabilities, query_info=query_info,
        )
        rule_runs.extend(phase1_runs)
        tracer.end_span()

        # Update capabilities with what Phase 1 rules provide
        for rule in per_node_rules:
            for cap in rule.provides:
                if isinstance(cap, Capability):
                    fact_store.add_capability(cap)
                elif isinstance(cap, str):
                    try:
                        fact_store.add_capability(Capability(cap))
                    except ValueError:
                        pass  # Unknown capability string
        fact_store.add_capability(Capability.PRIOR_FINDINGS)

        # Phase 2: AGGREGATE rules (see phase 1 findings)
        capabilities = fact_store.capabilities
        tracer.start_span("phase2_aggregate", rule_count=len(aggregate_rules))
        phase2_findings, phase2_runs = self._run_rules_with_status(
            aggregate_rules, explain, prior_findings=phase1_findings,
            capabilities=capabilities, query_info=query_info,
        )
        rule_runs.extend(phase2_runs)
        tracer.end_span()

        # Combine results
        all_findings = phase1_findings + phase2_findings

        # Enhance findings with SQL-based recommendations if available
        if query_info and sql_confidence != SQLConfidence.LOW:
            tracer.start_span("enhance_with_sql")
            all_findings = self._enhance_findings_with_sql(all_findings, query_info)
            tracer.end_span()

        return all_findings

    def _build_result(
        self,
        all_findings: list[Finding],
        rule_runs: list[RuleRun],
        evidence_level: EvidenceLevel,
        sql_confidence: SQLConfidence,
        reproducibility: ReproducibilityInfo,
        degraded_reasons: list[str],
        explain: "ExplainOutput",
        fingerprint: PlanFingerprint,
        start_time: float,
        tracer: Tracer,
    ) -> AnalysisResult:
        """Build the final AnalysisResult, cache it, and record metrics."""
        duration_ms = (time.perf_counter() - start_time) * 1000

        passed = len([r for r in rule_runs if r.status == RuleRunStatus.PASS])
        skipped = len([r for r in rule_runs if r.status == RuleRunStatus.SKIP])
        failed = len([r for r in rule_runs if r.status == RuleRunStatus.FAIL])

        metadata = ExecutionMetadata(
            node_count=len(explain.all_nodes),
            rules_run=passed + failed,
            rules_failed=failed,
            rules_skipped=skipped,
            analysis_duration_ms=duration_ms,
            cache_hit=False,
        )

        result = AnalysisResult.create(
            findings=all_findings,
            rule_runs=rule_runs,
            evidence_level=evidence_level,
            sql_confidence=sql_confidence,
            reproducibility=reproducibility,
            metadata=metadata,
            degraded_reasons=degraded_reasons,
        )

        # Cache the result
        if self.cache_enabled and self._cache is not None:
            tracer.start_span("cache_store")
            self._cache.set_extended(reproducibility.cache_key, fingerprint, result)
            tracer.end_span()

        # Record metrics
        self.metrics.record_analysis(
            duration_ms=duration_ms,
            findings_count=len(result.findings),
            errors_count=failed,
            cache_hit=False,
        )

        return result

    def _compute_cache_key(
        self,
        fingerprint: PlanFingerprint,
        sql_hash: str | None,
    ) -> str:
        """Compute cache key including plan, SQL, config, and ruleset."""
        parts = [fingerprint.full_hash]

        if sql_hash:
            parts.append(sql_hash)

        if self.config:
            parts.append(self.config.config_hash())

        parts.append(self._rules_hash)

        return hashlib.sha256(":".join(parts).encode()).hexdigest()[:32]

    async def analyze_async(
        self,
        explain: "ExplainOutput",
        sql: str | None = None,
    ) -> AnalysisResult:
        """
        Async version of analyze() for use in async applications.

        Runs the analysis in a thread pool to avoid blocking the event loop.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.analyze(explain, sql),
        )

    def _enhance_findings_with_sql(
        self,
        findings: list[Finding],
        query_info: QueryInfo,
    ) -> list[Finding]:
        """
        Enhance findings with SQL-based index recommendations.

        Uses the SQLEnhanceable protocol to delegate enhancement to rules
        that opt-in to SQL-based enhancement.
        """
        rule_by_id: dict[str, Rule] = {rule.rule_id: rule for rule in self.rules}
        enhanced: list[Finding] = []

        for finding in findings:
            rule = rule_by_id.get(finding.rule_id)

            if rule is not None and isinstance(rule, SQLEnhanceable):
                try:
                    enhanced_finding = rule.enhance_with_sql(finding, query_info)
                    enhanced.append(enhanced_finding)
                except Exception as e:
                    logger.warning(
                        "Rule %s failed to enhance finding with SQL: %s",
                        finding.rule_id, e,
                    )
                    enhanced.append(finding)
            else:
                enhanced_finding = self._default_sql_enhancement(finding, query_info)
                enhanced.append(enhanced_finding)

        return enhanced

    def _default_sql_enhancement(
        self,
        finding: Finding,
        query_info: QueryInfo,
    ) -> Finding:
        """Default SQL enhancement for rules that don't implement SQLEnhanceable."""
        from querysense.analyzer.index_advisor import IndexRecommendation, IndexType

        if "SCAN" not in finding.rule_id:
            return finding

        table = finding.context.relation_name
        if not table:
            return finding

        columns = query_info.suggest_composite_index(table)
        if not columns:
            return finding

        rec = IndexRecommendation(
            table=table,
            columns=columns,
            index_type=IndexType.BTREE,
            estimated_improvement=finding.metrics.get("estimated_improvement", 1.0),
            reasoning=self._build_sql_reasoning(query_info, table, columns),
        )

        return finding.model_copy(update={
            "suggestion": rec.format_full(),
        })

    def _build_sql_reasoning(
        self,
        query_info: QueryInfo,
        table: str,
        columns: list[str],
    ) -> str:
        """Build reasoning based on SQL analysis."""
        parts: list[str] = ["Based on SQL query analysis:"]

        filter_cols = [
            c for c in query_info.filter_columns
            if c.table == table or c.table is None
        ]
        join_cols = [
            c for c in query_info.join_columns
            if c.table == table or c.table is None
        ]
        order_cols = [
            c for c in query_info.order_by_columns
            if c.table == table or c.table is None
        ]

        if filter_cols:
            equality = [c.column for c in filter_cols if c.is_equality]
            ranges = [c.column for c in filter_cols if c.is_range]
            if equality:
                parts.append(f"- Equality filters on: {', '.join(equality)}")
            if ranges:
                parts.append(f"- Range filters on: {', '.join(ranges)}")

        if join_cols:
            parts.append(f"- Join columns: {', '.join(c.column for c in join_cols)}")

        if order_cols:
            parts.append(f"- Sort columns: {', '.join(c.column for c in order_cols)}")

        parts.append("")
        parts.append(f"Recommended column order: {', '.join(columns)}")
        parts.append("(Equality columns first, then range, then sort)")

        return "\n".join(parts)

    def _build_ir_plan(
        self,
        explain: "ExplainOutput",
    ) -> "IRPlan | None":
        """
        Build IR plan from ExplainOutput for engine-agnostic analysis.

        Converts the PostgreSQL-specific PlanNode tree into the universal
        IR representation. This enables rules to work across database engines.

        Returns None if conversion fails (analysis continues without IR).
        """
        try:
            from querysense.ir.adapters.postgresql import PostgreSQLAdapter
            adapter = PostgreSQLAdapter()
            ir_node = adapter.convert_plan_node(explain.plan)

            from querysense.ir.node import EngineType, IRPlan
            return IRPlan(
                root=ir_node,
                engine=EngineType.POSTGRESQL,
                planning_time_ms=explain.planning_time,
                execution_time_ms=explain.execution_time,
            )
        except Exception as e:
            logger.debug("Failed to build IR plan: %s", e)
            return None

    def _run_rules_with_status(
        self,
        rules: list[Rule],
        explain: "ExplainOutput",
        prior_findings: list[Finding],
        capabilities: frozenset[Capability],
        query_info: QueryInfo | None,
    ) -> tuple[list[Finding], list[RuleRun]]:
        """
        Run rules and track execution status (PASS/SKIP/FAIL).

        Uses typed Capability enum for dependency checking.
        Rules are executed in DAG order (if DAG validation passed).
        """
        findings: list[Finding] = []
        rule_runs: list[RuleRun] = []

        # Convert capabilities to string set for legacy compatibility
        cap_strings = {cap.value for cap in capabilities}

        for rule in rules:
            # Check requirements using typed capabilities
            can_run, missing = check_requirements(rule, capabilities)

            if not can_run:
                skip_reason = f"Missing capabilities: {', '.join(missing)}"
                rule_runs.append(RuleRun(
                    rule_id=rule.rule_id,
                    version=rule.version,
                    status=RuleRunStatus.SKIP,
                    runtime_ms=0.0,
                    findings_count=0,
                    skip_reason=skip_reason,
                ))
                logger.debug("Rule %s skipped: %s", rule.rule_id, skip_reason)
                continue

            # Run the rule
            rule_start = time.perf_counter()
            try:
                if rule.uses_context:
                    ctx = RuleContext(
                        explain=explain,
                        prior_findings=prior_findings,
                        query_info=query_info,
                        db_probe=self.db_probe,
                        capabilities=cap_strings,
                    )
                    rule_findings = rule.analyze_with_context(ctx)
                else:
                    rule_findings = rule.analyze(explain, prior_findings)

                rule_findings = rule_findings[:self.max_findings_per_rule]
                findings.extend(rule_findings)

                runtime_ms = (time.perf_counter() - rule_start) * 1000
                rule_runs.append(RuleRun(
                    rule_id=rule.rule_id,
                    version=rule.version,
                    status=RuleRunStatus.PASS,
                    runtime_ms=runtime_ms,
                    findings_count=len(rule_findings),
                ))

            except Exception as e:
                runtime_ms = (time.perf_counter() - rule_start) * 1000

                if self.fail_fast:
                    raise RuleError(rule.rule_id, rule.version, e) from e

                rule_runs.append(RuleRun(
                    rule_id=rule.rule_id,
                    version=rule.version,
                    status=RuleRunStatus.FAIL,
                    runtime_ms=runtime_ms,
                    findings_count=0,
                    error_summary=str(e),
                ))
                logger.warning("Rule %s failed: %s", rule.rule_id, e)

        return findings, rule_runs
