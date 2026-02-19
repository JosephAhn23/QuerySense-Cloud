"""
End-to-end test for the Universal Query Plan IR and Causal Analysis system.

Tests:
1. IR operator taxonomy and properties
2. PostgreSQL adapter (EXPLAIN JSON -> IR)
3. MySQL adapter (EXPLAIN JSON -> IR)
4. SQL Server adapter (Showplan XML -> IR)
5. Causal analysis engine
6. Temporal intelligence (change-point detection)
7. Fix verification (IR plan comparison)
8. Bridge (legacy IR -> universal IR)
9. Unified analyzer
"""

import json
import sys
from datetime import datetime, timezone, timedelta

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS: {name}")
    else:
        FAIL += 1
        print(f"  FAIL: {name} {detail}")


def test_operators():
    print("\n=== 1. IR Operators ===")
    from querysense.ir.operators import (
        IROperator, ScanMethod, JoinAlgorithm, AggregateStrategy,
        SortVariant, SetOpKind, Operator,
        is_scan, is_join, is_aggregate, is_sort, scan_danger_rank,
    )

    check("IROperator.SCAN_SEQ exists", IROperator.SCAN_SEQ.value == "scan_seq")
    check("IROperator.JOIN_HASH exists", IROperator.JOIN_HASH.value == "join_hash")
    check("is_scan works", is_scan(IROperator.SCAN_SEQ))
    check("is_scan false for join", not is_scan(IROperator.JOIN_HASH))
    check("is_join works", is_join(IROperator.JOIN_NESTED_LOOP))
    check("is_aggregate works", is_aggregate(IROperator.AGGREGATE_HASH))
    check("is_sort works", is_sort(IROperator.SORT))
    check("scan_danger_rank seq > index", scan_danger_rank(IROperator.SCAN_SEQ) > scan_danger_rank(IROperator.SCAN_INDEX))

    # Backward-compatible Operator
    op = Operator(category="scan", scan=ScanMethod.SEQUENTIAL, original="Seq Scan", engine="postgresql")
    check("Operator.is_scan", op.is_scan)
    check("Operator.is_full_table_scan", op.is_full_table_scan)
    check("Operator not is_join", not op.is_join)
    check("Operator.to_dict works", "category" in op.to_dict())


def test_properties():
    print("\n=== 2. IR Properties ===")
    from querysense.ir.properties import (
        CardinalitySignals, CostSignals, TimeSignals, MemorySignals,
        ParallelismSignals, Predicates, IRProperties,
    )

    c = CardinalitySignals(estimated_rows=100, actual_rows=500, actual_loops=1)
    check("estimate_ratio = 5.0", c.estimate_ratio == 5.0)
    check("estimate_error_factor = 5.0", c.estimate_error_factor == 5.0)
    check("has_actuals", c.has_actuals)
    check("total_rows = 500", c.total_rows == 500)

    mem = MemorySignals(sort_space_type="Disk", sort_space_used_kb=1024)
    check("is_spilling (disk sort)", mem.is_spilling)

    mem2 = MemorySignals(hash_batches=4)
    check("is_spilling (hash batches)", mem2.is_spilling)

    mem3 = MemorySignals(shared_hit_blocks=90, shared_read_blocks=10)
    check("buffer_hit_ratio = 0.9", mem3.buffer_hit_ratio == 0.9)


def test_annotations():
    print("\n=== 3. IR Annotations ===")
    from querysense.ir.annotations import (
        IRAnnotations, IRCapability, PostgresAnnotations,
        MySQLAnnotations, SQLServerAnnotations, OracleAnnotations,
    )

    ann = IRAnnotations(postgres=PostgresAnnotations(heap_fetches=42))
    check("engine = postgres", ann.engine == "postgres")

    ann2 = IRAnnotations(mysql=MySQLAnnotations(access_type="range"))
    check("engine = mysql", ann2.engine == "mysql")

    ann3 = IRAnnotations(oracle=OracleAnnotations(operation="TABLE ACCESS FULL"))
    check("engine = oracle", ann3.engine == "oracle")

    check("IRCapability.HAS_ACTUAL_ROWS exists", IRCapability.HAS_ACTUAL_ROWS.value == "has_actual_rows")
    check("IRCapability.ENGINE_POSTGRES exists", IRCapability.ENGINE_POSTGRES.value == "engine_postgres")


def test_postgres_adapter():
    print("\n=== 4. PostgreSQL Adapter ===")
    from querysense.ir.adapters.postgres import PostgresAdapter

    adapter = PostgresAdapter()

    plan = [{
        "Plan": {
            "Node Type": "Hash Join",
            "Join Type": "Inner",
            "Hash Cond": "(o.customer_id = c.id)",
            "Plan Rows": 12000,
            "Plan Width": 200,
            "Startup Cost": 0.0,
            "Total Cost": 350.2,
            "Actual Rows": 11880,
            "Actual Total Time": 42.1,
            "Actual Loops": 1,
            "Plans": [
                {
                    "Node Type": "Seq Scan",
                    "Relation Name": "orders",
                    "Plan Rows": 50000,
                    "Plan Width": 120,
                    "Total Cost": 150.0,
                    "Actual Rows": 48500,
                    "Actual Loops": 1,
                    "Filter": "(status = 'active')",
                    "Rows Removed by Filter": 1500,
                },
                {
                    "Node Type": "Hash",
                    "Plan Rows": 1000,
                    "Total Cost": 20.0,
                    "Hash Buckets": 2048,
                    "Hash Batches": 1,
                    "Plans": [
                        {
                            "Node Type": "Index Only Scan",
                            "Relation Name": "customers",
                            "Index Name": "customers_pkey",
                            "Plan Rows": 1000,
                            "Total Cost": 15.0,
                            "Actual Rows": 1000,
                            "Actual Loops": 1,
                            "Heap Fetches": 5,
                        }
                    ],
                },
            ],
        },
        "Planning Time": 0.5,
        "Execution Time": 43.0,
    }]

    check("can_handle", adapter.can_handle(plan))

    ir = adapter.translate(plan)
    check("engine = postgres", ir.engine == "postgres")
    check("planning_time = 0.5", ir.planning_time_ms == 0.5)
    check("execution_time = 43.0", ir.execution_time_ms == 43.0)
    check("root is JOIN_HASH", ir.root.operator.value == "join_hash")
    check("node_count >= 4", ir.node_count >= 4)

    # Check capabilities
    from querysense.ir.annotations import IRCapability
    check("HAS_ACTUAL_ROWS", ir.has_capability(IRCapability.HAS_ACTUAL_ROWS))
    check("HAS_COST", ir.has_capability(IRCapability.HAS_COST))
    check("ENGINE_POSTGRES", ir.has_capability(IRCapability.ENGINE_POSTGRES))
    check("HAS_PREDICATES", ir.has_capability(IRCapability.HAS_PREDICATES))

    # Check structure hash
    h = ir.structure_hash()
    check("structure hash is 16 chars", len(h) == 16)

    # Check fingerprint
    fp = ir.full_fingerprint()
    check("fingerprint has structure", "structure" in fp)
    check("fingerprint has engine", fp["engine"] == "postgres")

    # Check cost shares
    root_share = ir.root.properties.cost.cost_share
    check("root cost_share = 1.0", root_share is not None and abs(root_share - 1.0) < 0.01)

    # Check self times
    root_self = ir.root.properties.time.self_time_ms
    check("root has self_time", root_self is not None)

    # Check JSON serialization
    j = ir.to_json()
    parsed = json.loads(j)
    check("to_json roundtrip", "root" in parsed and "capabilities" in parsed)

    # Check seq scan child
    seq_scan = ir.root.children[0]
    check("child 0 is SCAN_SEQ", seq_scan.operator.value == "scan_seq")
    check("seq scan relation = orders", seq_scan.properties.relation_name == "orders")
    check("seq scan has filter", seq_scan.properties.predicates.filter_condition is not None)


def test_mysql_adapter():
    print("\n=== 5. MySQL Adapter ===")
    from querysense.ir.adapters.mysql import MySQLAdapter

    adapter = MySQLAdapter()

    plan = {
        "query_block": {
            "select_id": 1,
            "cost_info": {"query_cost": "100.50"},
            "nested_loop": [
                {
                    "table": {
                        "table_name": "orders",
                        "access_type": "ALL",
                        "rows_examined_per_scan": 50000,
                        "rows_produced_per_join": 50000,
                        "cost_info": {"read_cost": "80.00"},
                        "attached_condition": "orders.status = 'active'",
                    }
                },
                {
                    "table": {
                        "table_name": "customers",
                        "access_type": "eq_ref",
                        "key": "PRIMARY",
                        "key_length": "4",
                        "rows_examined_per_scan": 1,
                        "rows_produced_per_join": 1,
                        "cost_info": {"read_cost": "0.25"},
                    }
                },
            ],
        }
    }

    check("can_handle", adapter.can_handle(plan))
    check("not can_handle list", not adapter.can_handle([{"Plan": {}}]))

    ir = adapter.translate(plan)
    check("engine = mysql", ir.engine == "mysql")
    check("has nodes", ir.node_count >= 2)
    check("has capabilities", len(ir.capabilities) > 0)

    # Check MySQL annotations
    found_mysql_ann = False
    for node in ir.all_nodes():
        if node.annotations.mysql:
            found_mysql_ann = True
            break
    check("has MySQL annotations", found_mysql_ann)


def test_sqlserver_adapter():
    print("\n=== 6. SQL Server Adapter ===")
    from querysense.ir.adapters.sqlserver import SQLServerAdapter

    adapter = SQLServerAdapter()

    xml = '''<?xml version="1.0" encoding="utf-16"?>
    <ShowPlanXML xmlns="http://schemas.microsoft.com/sqlserver/2004/07/showplan" Version="1.0">
      <BatchSequence>
        <Batch>
          <Statements>
            <StmtSimple StatementText="SELECT * FROM orders WHERE id = 1">
              <QueryPlan>
                <RelOp PhysicalOp="Clustered Index Seek" LogicalOp="Clustered Index Seek"
                  EstimateRows="1" EstimatedTotalSubtreeCost="0.003">
                </RelOp>
              </QueryPlan>
            </StmtSimple>
          </Statements>
        </Batch>
      </BatchSequence>
    </ShowPlanXML>'''

    check("can_handle XML", adapter.can_handle(xml))
    check("not can_handle dict", not adapter.can_handle({"Plan": {}}))

    ir = adapter.translate(xml)
    check("engine = sqlserver", ir.engine == "sqlserver")
    check("root operator mapped", ir.root.operator.value == "scan_index")
    check("has SS annotations", ir.root.annotations.sqlserver is not None)
    check("physical_op preserved", ir.root.annotations.sqlserver.physical_op == "Clustered Index Seek")


def test_causal_engine():
    print("\n=== 7. Causal Analysis Engine ===")
    from querysense.causal.engine import CausalEngine
    from querysense.ir.adapters.postgres import PostgresAdapter

    # Create a plan with bad cardinality estimates
    plan = [{
        "Plan": {
            "Node Type": "Nested Loop",
            "Plan Rows": 10,
            "Total Cost": 5000.0,
            "Actual Rows": 50000,
            "Actual Loops": 1,
            "Plans": [
                {
                    "Node Type": "Seq Scan",
                    "Relation Name": "orders",
                    "Plan Rows": 10,
                    "Total Cost": 3000.0,
                    "Actual Rows": 50000,
                    "Actual Loops": 1,
                    "Filter": "(status = 'pending')",
                    "Rows Removed by Filter": 5000,
                },
                {
                    "Node Type": "Seq Scan",
                    "Relation Name": "items",
                    "Plan Rows": 1,
                    "Total Cost": 500.0,
                    "Actual Rows": 100,
                    "Actual Loops": 50000,
                },
            ],
        },
    }]

    adapter = PostgresAdapter()
    ir = adapter.translate(plan)

    engine = CausalEngine()
    report = engine.analyze(ir)

    check("has findings", report.has_findings)
    check("engine = postgres", report.engine == "postgres")

    # Should detect bad cardinality (H2)
    h2_found = any(
        rh.hypothesis.id.value == "H2_bad_cardinality_estimate"
        for rh in report.ranked
    )
    check("H2 bad cardinality detected", h2_found)

    # Should detect missing access path (H1)
    h1_found = any(
        rh.hypothesis.id.value == "H1_missing_access_path"
        for rh in report.ranked
    )
    check("H1 missing access path detected", h1_found)

    # Should detect join mismatch (H7)
    h7_found = any(
        rh.hypothesis.id.value == "H7_join_strategy_mismatch"
        for rh in report.ranked
    )
    check("H7 join mismatch detected", h7_found)

    # Top cause should have high confidence
    top = report.top_cause
    check("top cause exists", top is not None)
    if top:
        check(f"top cause confidence > 0.5 (got {top.confidence:.2f})", top.confidence > 0.5)
        check("top cause has explanation", bool(top.explanation))

    # Summary should be non-empty
    summary = report.summary()
    check("summary is non-empty", len(summary) > 0)

    # High confidence list
    high = report.high_confidence
    check("high confidence hypotheses exist", len(high) > 0)


def test_temporal():
    print("\n=== 8. Temporal Intelligence ===")
    from querysense.temporal.store import InMemoryTemporalStore, PlanSnapshot
    from querysense.temporal.changepoint import detect_changepoints, pelt_changepoints
    from querysense.temporal.drift import DriftAnalyzer, DriftType

    # Test change-point detection
    # Stable at 10, then jumps to 50
    series = [10, 11, 9, 10, 12, 10, 50, 48, 52, 49, 51, 50]
    cps = detect_changepoints(series, threshold_pct=0.3, min_segment=3)
    check("detect_changepoints finds change", len(cps) > 0)
    if cps:
        check("changepoint near index 6", abs(cps[0].index - 6) <= 2)
        check("direction = increase", cps[0].direction == "increase")

    # PELT
    pelt_cps = pelt_changepoints(series)
    check("pelt finds change", len(pelt_cps) > 0)

    # Test temporal store
    store = InMemoryTemporalStore()
    now = datetime.now(timezone.utc)

    for i in range(12):
        latency = 10.0 if i < 6 else 50.0
        store.store(PlanSnapshot(
            query_id="q_order_lookup",
            timestamp=now + timedelta(hours=i),
            structure_hash="abc123" if i < 6 else "def456",
            latency_p50_ms=latency,
            cost_total=latency * 10,
        ))

    check("store has snapshots", len(store.query("q_order_lookup")) == 12)
    check("latest is correct", store.latest("q_order_lookup").latency_p50_ms == 50.0)

    # Test drift analyzer
    analyzer = DriftAnalyzer(store, min_snapshots=5)
    events = analyzer.analyze_query("q_order_lookup")
    check("drift events detected", len(events) > 0)

    if events:
        # Should detect plan regression (structure changed + latency increased)
        regression = [e for e in events if e.drift_type == DriftType.PLAN_REGRESSION]
        check("plan regression detected", len(regression) > 0)

    # Export/import
    exported = store.export_json()
    store2 = InMemoryTemporalStore()
    store2.import_json(exported)
    check("export/import roundtrip", len(store2.query("q_order_lookup")) == 12)


def test_comparator():
    print("\n=== 9. Fix Verification (IR Comparison) ===")
    from querysense.ir.adapters.postgres import PostgresAdapter
    from querysense.verification.comparator import compare_ir_plans

    adapter = PostgresAdapter()

    before = [{
        "Plan": {
            "Node Type": "Seq Scan",
            "Relation Name": "orders",
            "Plan Rows": 50000,
            "Total Cost": 3000.0,
            "Filter": "(customer_id = 42)",
        },
    }]

    after = [{
        "Plan": {
            "Node Type": "Index Scan",
            "Relation Name": "orders",
            "Index Name": "idx_orders_customer_id",
            "Plan Rows": 50,
            "Total Cost": 5.0,
            "Index Cond": "(customer_id = 42)",
        },
    }]

    before_ir = adapter.translate(before)
    after_ir = adapter.translate(after)

    comparison = compare_ir_plans(before_ir, after_ir)

    check("structure changed", comparison.structure_changed)
    check("cost improved", comparison.cost_delta < 0)
    check("has improvements", comparison.has_improvements)
    check("scan improvement detected", comparison.scan_improvements > 0)
    check("cost improvement > 99%", comparison.cost_improvement_pct > 99)


def test_unified():
    print("\n=== 10. Unified Analyzer ===")
    from querysense.ir.unified import UnifiedAnalyzer

    plan = [{
        "Plan": {
            "Node Type": "Sort",
            "Plan Rows": 100000,
            "Total Cost": 25000.0,
            "Sort Key": ["created_at"],
            "Sort Space Used": 51200,
            "Sort Space Type": "Disk",
            "Plans": [
                {
                    "Node Type": "Seq Scan",
                    "Relation Name": "events",
                    "Plan Rows": 100000,
                    "Total Cost": 15000.0,
                    "Actual Rows": 95000,
                    "Actual Loops": 1,
                    "Filter": "(type = 'click')",
                },
            ],
        },
    }]

    analyzer = UnifiedAnalyzer()
    report = analyzer.analyze_raw(plan, engine="postgres", query_id="q_events_sort")

    check("report has ir_plan", report.ir_plan is not None)
    check("report has causal_report", report.causal_report is not None)
    check("report has capabilities", len(report.capabilities) > 0)
    check("report has fingerprint", len(report.plan_fingerprint) > 0)
    check("snapshot stored", report.snapshots_stored)

    # Should detect memory pressure (sort spilling to disk)
    h6_found = any(
        rh.hypothesis.id.value == "H6_memory_pressure_spill"
        for rh in report.causal_report.ranked
    )
    check("H6 memory pressure detected", h6_found)

    # Check summary
    summary = report.summary()
    check("summary is non-empty", len(summary) > 50)


def test_bridge():
    print("\n=== 11. Legacy-to-Universal Bridge ===")
    try:
        from querysense.ir.node import IRNode, IRPlan, EngineType
        from querysense.ir.operators import Operator, ScanMethod
        from querysense.ir.node import ScanStrategy, OperatorCategory
        from querysense.ir.bridge import legacy_to_universal

        # Build a simple legacy IR plan
        legacy_node = IRNode(
            operator=Operator(
                category="scan",
                scan=ScanStrategy.FULL_TABLE,
                original="Seq Scan",
                engine="postgresql",
            ),
            estimated_rows=50000,
            estimated_cost=3000.0,
            relation="orders",
            source_node_type="Seq Scan",
            engine=EngineType.POSTGRESQL,
        )

        legacy_plan = IRPlan(
            root=legacy_node,
            engine=EngineType.POSTGRESQL,
            planning_time_ms=0.5,
            execution_time_ms=42.0,
        )

        universal = legacy_to_universal(legacy_plan)
        check("bridge produces universal plan", universal is not None)
        check("bridge engine = postgres", universal.engine == "postgres")
        check("bridge preserves planning_time", universal.planning_time_ms == 0.5)
        check("bridge root is SCAN_SEQ", universal.root.operator.value == "scan_seq")
        check("bridge preserves relation", universal.root.properties.relation_name == "orders")

    except Exception as exc:
        check(f"bridge test (error: {exc})", False)


# ── Run all tests ─────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("Universal Query Plan IR & Causal Analysis - End-to-End Tests")
    print("=" * 60)

    test_operators()
    test_properties()
    test_annotations()
    test_postgres_adapter()
    test_mysql_adapter()
    test_sqlserver_adapter()
    test_causal_engine()
    test_temporal()
    test_comparator()
    test_unified()
    test_bridge()

    print("\n" + "=" * 60)
    print(f"Results: {PASS} passed, {FAIL} failed out of {PASS + FAIL} total")
    print("=" * 60)

    if FAIL > 0:
        sys.exit(1)
    print("\nAll tests passed!")
