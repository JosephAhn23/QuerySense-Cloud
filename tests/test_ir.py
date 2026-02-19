"""
Comprehensive tests for the Plan IR (Intermediate Representation) layer.

Tests cover:
1. Operator taxonomy: Classification, predicates, serialization
2. IRNode: Construction, traversal, fingerprinting, properties
3. PostgreSQL adapter: PG EXPLAIN JSON → IRNode mapping
4. MySQL adapter: MySQL EXPLAIN JSON → IRNode mapping (both formats)
5. Engine detection: Automatic format recognition
6. Cost normalization: Cross-engine cost comparison
7. Round-trip fidelity: Engine-specific data preservation
"""

from __future__ import annotations

import json
import pytest

from querysense.ir import (
    IRNode,
    IRPlan,
    EngineType,
    Operator,
    OperatorCategory,
    ScanStrategy,
    JoinStrategy,
    JoinType,
    SortStrategy,
    AggregateStrategy,
    auto_convert,
    detect_engine,
)
from querysense.ir.node import (
    BufferStats,
    Condition,
    ConditionKind,
    HashInfo,
    ParallelInfo,
    SortInfo,
)
from querysense.ir.cost import CostBand, CostNormalizer, NormalizedCost
from querysense.ir.node import (
    ControlStrategy,
    MaterializeStrategy,
    ScanDirection,
)
from querysense.ir.adapters.postgresql import PostgreSQLAdapter
from querysense.ir.adapters.mysql import MySQLAdapter
from querysense.ir import detect_engine as detect_engine_func


# =============================================================================
# Fixtures: PostgreSQL EXPLAIN JSON
# =============================================================================

PG_SEQ_SCAN_PLAN = {
    "Plan": {
        "Node Type": "Seq Scan",
        "Relation Name": "orders",
        "Schema": "public",
        "Alias": "orders",
        "Startup Cost": 0.0,
        "Total Cost": 45000.50,
        "Plan Rows": 250000,
        "Plan Width": 120,
        "Actual Startup Time": 0.015,
        "Actual Total Time": 320.5,
        "Actual Rows": 248000,
        "Actual Loops": 1,
        "Filter": "(status = 'pending')",
        "Rows Removed by Filter": 752000,
    },
    "Planning Time": 0.25,
    "Execution Time": 325.0,
}

PG_INDEX_SCAN_PLAN = {
    "Plan": {
        "Node Type": "Index Scan",
        "Relation Name": "users",
        "Index Name": "idx_users_email",
        "Scan Direction": "Forward",
        "Startup Cost": 0.42,
        "Total Cost": 8.44,
        "Plan Rows": 1,
        "Plan Width": 50,
        "Actual Rows": 1,
        "Actual Loops": 1,
        "Index Cond": "(email = 'test@example.com')",
        "Filter": "(active = true)",
        "Rows Removed by Filter": 0,
    },
}

PG_HASH_JOIN_PLAN = {
    "Plan": {
        "Node Type": "Hash Join",
        "Join Type": "Inner",
        "Hash Cond": "(o.user_id = u.id)",
        "Startup Cost": 100.0,
        "Total Cost": 5000.0,
        "Plan Rows": 10000,
        "Plan Width": 200,
        "Actual Rows": 9500,
        "Actual Loops": 1,
        "Plans": [
            {
                "Node Type": "Seq Scan",
                "Relation Name": "orders",
                "Alias": "o",
                "Startup Cost": 0.0,
                "Total Cost": 3000.0,
                "Plan Rows": 50000,
                "Plan Width": 100,
                "Actual Rows": 48000,
                "Actual Loops": 1,
            },
            {
                "Node Type": "Hash",
                "Startup Cost": 50.0,
                "Total Cost": 50.0,
                "Plan Rows": 1000,
                "Plan Width": 50,
                "Actual Rows": 1000,
                "Actual Loops": 1,
                "Hash Buckets": 2048,
                "Hash Batches": 1,
                "Peak Memory Usage": 128,
                "Plans": [
                    {
                        "Node Type": "Seq Scan",
                        "Relation Name": "users",
                        "Alias": "u",
                        "Startup Cost": 0.0,
                        "Total Cost": 50.0,
                        "Plan Rows": 1000,
                        "Plan Width": 50,
                        "Actual Rows": 1000,
                        "Actual Loops": 1,
                    }
                ],
            },
        ],
    },
    "Planning Time": 1.5,
    "Execution Time": 450.0,
}

PG_SORT_SPILL_PLAN = {
    "Plan": {
        "Node Type": "Sort",
        "Sort Key": ["created_at DESC"],
        "Sort Method": "external merge",
        "Sort Space Used": 51200,
        "Sort Space Type": "Disk",
        "Startup Cost": 50000.0,
        "Total Cost": 55000.0,
        "Plan Rows": 250000,
        "Plan Width": 120,
        "Plans": [
            {
                "Node Type": "Seq Scan",
                "Relation Name": "events",
                "Startup Cost": 0.0,
                "Total Cost": 30000.0,
                "Plan Rows": 250000,
                "Plan Width": 120,
            }
        ],
    },
}

PG_PARALLEL_PLAN = {
    "Plan": {
        "Node Type": "Gather",
        "Workers Planned": 4,
        "Workers Launched": 3,
        "Startup Cost": 100.0,
        "Total Cost": 10000.0,
        "Plan Rows": 1000000,
        "Plan Width": 50,
        "Plans": [
            {
                "Node Type": "Seq Scan",
                "Relation Name": "big_table",
                "Parallel Aware": True,
                "Startup Cost": 0.0,
                "Total Cost": 5000.0,
                "Plan Rows": 250000,
                "Plan Width": 50,
            }
        ],
    },
}

PG_BUFFERS_PLAN = {
    "Plan": {
        "Node Type": "Index Scan",
        "Relation Name": "accounts",
        "Index Name": "idx_accounts_pk",
        "Startup Cost": 0.42,
        "Total Cost": 4.44,
        "Plan Rows": 1,
        "Plan Width": 30,
        "Shared Hit Blocks": 3,
        "Shared Read Blocks": 1,
        "Shared Dirtied Blocks": 0,
        "Shared Written Blocks": 0,
        "I/O Read Time": 0.05,
        "I/O Write Time": 0.0,
    },
}


# =============================================================================
# Fixtures: MySQL EXPLAIN JSON
# =============================================================================

MYSQL_FULL_TABLE_SCAN = {
    "query_block": {
        "select_id": 1,
        "cost_info": {
            "query_cost": "25843.00"
        },
        "table": {
            "table_name": "orders",
            "access_type": "ALL",
            "possible_keys": None,
            "key": None,
            "rows_examined_per_scan": 250000,
            "rows_produced_per_join": 25000,
            "filtered": "10.00",
            "cost_info": {
                "read_cost": "23343.00",
                "eval_cost": "2500.00",
                "prefix_cost": "25843.00"
            },
            "used_columns": ["id", "customer_id", "status"],
            "attached_condition": "(`testdb`.`orders`.`status` = 'pending')"
        }
    }
}

MYSQL_GOOD_QUERY = {
    "query_block": {
        "select_id": 1,
        "cost_info": {
            "query_cost": "0.35"
        },
        "table": {
            "table_name": "users",
            "access_type": "const",
            "possible_keys": ["PRIMARY", "idx_email"],
            "key": "idx_email",
            "key_length": "767",
            "ref": ["const"],
            "rows_examined_per_scan": 1,
            "filtered": "100.00",
            "using_index": True
        }
    }
}

MYSQL_NESTED_LOOP_JOIN = {
    "query_block": {
        "select_id": 1,
        "cost_info": {
            "query_cost": "125000.00"
        },
        "nested_loop": [
            {
                "table": {
                    "table_name": "orders",
                    "access_type": "ALL",
                    "possible_keys": None,
                    "key": None,
                    "rows_examined_per_scan": 50000,
                    "filtered": "100.00",
                    "attached_condition": "(`testdb`.`orders`.`status` = 'pending')"
                }
            },
            {
                "table": {
                    "table_name": "order_items",
                    "access_type": "ref",
                    "possible_keys": ["idx_order_id"],
                    "key": "idx_order_id",
                    "key_length": "4",
                    "ref": ["testdb.orders.id"],
                    "rows_examined_per_scan": 5,
                    "filtered": "100.00"
                }
            }
        ]
    }
}

MYSQL_FILESORT_PLAN = {
    "query_block": {
        "select_id": 1,
        "cost_info": {
            "query_cost": "25843.00"
        },
        "ordering_operation": {
            "using_filesort": True,
            "table": {
                "table_name": "orders",
                "access_type": "ALL",
                "possible_keys": None,
                "key": None,
                "rows_examined_per_scan": 250000,
                "rows_produced_per_join": 250000,
                "filtered": "100.00"
            }
        }
    }
}

MYSQL_GROUPING_PLAN = {
    "query_block": {
        "select_id": 1,
        "cost_info": {
            "query_cost": "50000.00"
        },
        "grouping_operation": {
            "using_temporary_table": True,
            "using_filesort": True,
            "table": {
                "table_name": "orders",
                "access_type": "ALL",
                "possible_keys": None,
                "key": None,
                "rows_examined_per_scan": 250000,
                "filtered": "100.00"
            }
        }
    }
}

MYSQL_TABULAR_FORMAT = [
    {
        "id": 1,
        "select_type": "SIMPLE",
        "table": "orders",
        "partitions": None,
        "type": "ALL",
        "possible_keys": None,
        "key": None,
        "key_len": None,
        "ref": None,
        "rows": 250000,
        "filtered": 10.0,
        "Extra": "Using where"
    }
]

MYSQL_TABULAR_JOIN = [
    {
        "id": 1,
        "select_type": "SIMPLE",
        "table": "orders",
        "type": "ALL",
        "possible_keys": None,
        "key": None,
        "rows": 50000,
        "filtered": 100.0,
        "Extra": "Using where"
    },
    {
        "id": 1,
        "select_type": "SIMPLE",
        "table": "order_items",
        "type": "ref",
        "possible_keys": "idx_order_id",
        "key": "idx_order_id",
        "key_len": "4",
        "ref": "testdb.orders.id",
        "rows": 5,
        "filtered": 100.0,
        "Extra": "Using index condition"
    }
]


# =============================================================================
# Test: Operator Taxonomy
# =============================================================================


class TestOperatorTaxonomy:
    """Test the operator type system."""

    def test_scan_operator_creation(self):
        op = Operator(
            category=OperatorCategory.SCAN,
            scan=ScanStrategy.FULL_TABLE,
            original="Seq Scan",
            engine="postgresql",
        )
        assert op.category == OperatorCategory.SCAN
        assert op.scan == ScanStrategy.FULL_TABLE
        assert op.is_scan
        assert op.is_full_table_scan
        assert not op.is_index_scan
        assert not op.is_join
        assert op.original == "Seq Scan"

    def test_join_operator_creation(self):
        op = Operator(
            category=OperatorCategory.JOIN,
            join=JoinStrategy.HASH_JOIN,
            original="Hash Join",
            engine="postgresql",
        )
        assert op.is_join
        assert op.is_hash_join
        assert not op.is_nested_loop
        assert not op.is_scan

    def test_sort_operator_creation(self):
        op = Operator(
            category=OperatorCategory.SORT,
            sort=SortStrategy.EXTERNAL_MERGE,
            original="Sort",
            engine="postgresql",
        )
        assert op.is_sort
        assert not op.is_scan
        assert not op.is_join

    def test_operator_equality(self):
        op1 = Operator(
            category=OperatorCategory.SCAN,
            scan=ScanStrategy.FULL_TABLE,
            original="Seq Scan",
            engine="postgresql",
        )
        op2 = Operator(
            category=OperatorCategory.SCAN,
            scan=ScanStrategy.FULL_TABLE,
            original="MySQL ALL",
            engine="mysql",
        )
        # Same semantic operation despite different engines
        assert op1 == op2

    def test_operator_inequality(self):
        op1 = Operator(
            category=OperatorCategory.SCAN,
            scan=ScanStrategy.FULL_TABLE,
        )
        op2 = Operator(
            category=OperatorCategory.SCAN,
            scan=ScanStrategy.INDEX_SCAN,
        )
        assert op1 != op2

    def test_operator_hash(self):
        op1 = Operator(
            category=OperatorCategory.SCAN,
            scan=ScanStrategy.FULL_TABLE,
        )
        op2 = Operator(
            category=OperatorCategory.SCAN,
            scan=ScanStrategy.FULL_TABLE,
        )
        assert hash(op1) == hash(op2)
        assert {op1, op2} == {op1}

    def test_operator_serialization(self):
        op = Operator(
            category=OperatorCategory.JOIN,
            join=JoinStrategy.NESTED_LOOP,
            original="Nested Loop",
            engine="postgresql",
        )
        d = op.to_dict()
        assert d["category"] == "join"
        assert d["strategy"] == "nested_loop"
        assert d["original"] == "Nested Loop"
        assert d["engine"] == "postgresql"

    def test_operator_repr(self):
        op = Operator(
            category=OperatorCategory.SCAN,
            scan=ScanStrategy.INDEX_ONLY,
            original="Index Only Scan",
            engine="postgresql",
        )
        repr_str = repr(op)
        assert "SCAN" in repr_str or "scan" in repr_str
        assert "index_only" in repr_str


# =============================================================================
# Test: IRNode
# =============================================================================


class TestIRNode:
    """Test the IR node data structure."""

    def test_basic_construction(self):
        node = IRNode(
            operator=Operator(
                category=OperatorCategory.SCAN,
                scan=ScanStrategy.FULL_TABLE,
            ),
            estimated_rows=10000,
            estimated_cost=500.0,
            relation="orders",
        )
        assert node.relation == "orders"
        assert node.estimated_rows == 10000
        assert node.is_full_table_scan
        assert not node.has_analyze_data

    def test_analyze_data(self):
        node = IRNode(
            operator=Operator(
                category=OperatorCategory.SCAN,
                scan=ScanStrategy.INDEX_SCAN,
            ),
            estimated_rows=100,
            actual_rows=95,
            actual_time_ms=1.5,
            actual_loops=1,
        )
        assert node.has_analyze_data
        assert node.row_estimate_ratio == pytest.approx(0.95)
        assert node.total_actual_time_ms == pytest.approx(1.5)

    def test_tree_traversal(self):
        child1 = IRNode(
            operator=Operator(category=OperatorCategory.SCAN, scan=ScanStrategy.FULL_TABLE),
            relation="orders",
        )
        child2 = IRNode(
            operator=Operator(category=OperatorCategory.SCAN, scan=ScanStrategy.INDEX_SCAN),
            relation="users",
        )
        root = IRNode(
            operator=Operator(category=OperatorCategory.JOIN, join=JoinStrategy.HASH_JOIN),
            children=(child1, child2),
        )

        all_nodes = list(root.iter_all())
        assert len(all_nodes) == 3
        assert all_nodes[0] is root
        assert all_nodes[1] is child1
        assert all_nodes[2] is child2

    def test_node_count(self):
        grandchild = IRNode(
            operator=Operator(category=OperatorCategory.SCAN, scan=ScanStrategy.FULL_TABLE),
        )
        child = IRNode(
            operator=Operator(category=OperatorCategory.MATERIALIZE, materialize=MaterializeStrategy.HASH_TABLE),
            children=(grandchild,),
        )
        root = IRNode(
            operator=Operator(category=OperatorCategory.JOIN, join=JoinStrategy.HASH_JOIN),
            children=(child,),
        )
        assert root.node_count == 3
        assert root.depth == 2

    def test_find_full_table_scans(self):
        scan1 = IRNode(
            operator=Operator(category=OperatorCategory.SCAN, scan=ScanStrategy.FULL_TABLE),
            relation="orders",
        )
        scan2 = IRNode(
            operator=Operator(category=OperatorCategory.SCAN, scan=ScanStrategy.INDEX_SCAN),
            relation="users",
        )
        root = IRNode(
            operator=Operator(category=OperatorCategory.JOIN, join=JoinStrategy.NESTED_LOOP),
            children=(scan1, scan2),
        )
        fts = root.find_full_table_scans()
        assert len(fts) == 1
        assert fts[0].relation == "orders"

    def test_conditions(self):
        node = IRNode(
            operator=Operator(category=OperatorCategory.SCAN, scan=ScanStrategy.FULL_TABLE),
            conditions=(
                Condition("(status = 'active')", ConditionKind.FILTER),
                Condition("(id = 42)", ConditionKind.INDEX_CONDITION),
            ),
        )
        assert len(node.filter_conditions) == 1
        assert len(node.index_conditions) == 1
        assert node.filter_conditions[0].expression == "(status = 'active')"

    def test_spilling_detection(self):
        node = IRNode(
            operator=Operator(category=OperatorCategory.SORT, sort=SortStrategy.EXTERNAL),
            sort_info=SortInfo(
                strategy=SortStrategy.EXTERNAL,
                space_type="Disk",
                space_used_kb=50000,
            ),
        )
        assert node.is_spilling

    def test_hash_spilling(self):
        node = IRNode(
            operator=Operator(category=OperatorCategory.MATERIALIZE, materialize=MaterializeStrategy.HASH_TABLE),
            hash_info=HashInfo(batches=4, peak_memory_kb=1024),
        )
        assert node.is_spilling

    def test_structure_hash_deterministic(self):
        node1 = IRNode(
            operator=Operator(category=OperatorCategory.SCAN, scan=ScanStrategy.FULL_TABLE),
            relation="orders",
            estimated_rows=100,
        )
        node2 = IRNode(
            operator=Operator(category=OperatorCategory.SCAN, scan=ScanStrategy.FULL_TABLE),
            relation="orders",
            estimated_rows=999,  # Different rows, same structure
        )
        assert node1.structure_hash() == node2.structure_hash()

    def test_structure_hash_different(self):
        node1 = IRNode(
            operator=Operator(category=OperatorCategory.SCAN, scan=ScanStrategy.FULL_TABLE),
            relation="orders",
        )
        node2 = IRNode(
            operator=Operator(category=OperatorCategory.SCAN, scan=ScanStrategy.INDEX_SCAN),
            relation="orders",
        )
        assert node1.structure_hash() != node2.structure_hash()

    def test_serialization(self):
        node = IRNode(
            operator=Operator(
                category=OperatorCategory.SCAN,
                scan=ScanStrategy.FULL_TABLE,
                original="Seq Scan",
                engine="postgresql",
            ),
            estimated_rows=10000,
            estimated_cost=500.0,
            relation="orders",
            actual_rows=9500,
            engine=EngineType.POSTGRESQL,
        )
        d = node.to_dict()
        assert d["operator"]["category"] == "scan"
        assert d["relation"] == "orders"
        assert d["actual_rows"] == 9500
        assert d["engine"] == "postgresql"

    def test_iter_with_parent(self):
        child = IRNode(
            operator=Operator(category=OperatorCategory.SCAN, scan=ScanStrategy.FULL_TABLE),
            relation="t1",
        )
        root = IRNode(
            operator=Operator(category=OperatorCategory.SORT, sort=SortStrategy.IN_MEMORY),
            children=(child,),
        )

        pairs = list(root.iter_with_parent())
        assert len(pairs) == 2
        assert pairs[0] == (root, None)
        assert pairs[1] == (child, root)

    def test_buffer_stats(self):
        buffers = BufferStats(
            shared_hit_blocks=100,
            shared_read_blocks=10,
        )
        assert buffers.total_blocks == 110
        assert buffers.cache_hit_ratio == pytest.approx(100 / 110)
        assert buffers.has_data


# =============================================================================
# Test: IRPlan
# =============================================================================


class TestIRPlan:
    """Test the top-level plan wrapper."""

    def test_basic_plan(self):
        root = IRNode(
            operator=Operator(category=OperatorCategory.SCAN, scan=ScanStrategy.FULL_TABLE),
            relation="orders",
        )
        plan = IRPlan(root=root, engine=EngineType.POSTGRESQL)
        assert plan.engine == EngineType.POSTGRESQL
        assert plan.node_count == 1
        assert not plan.has_analyze_data

    def test_plan_with_timing(self):
        root = IRNode(
            operator=Operator(category=OperatorCategory.SCAN, scan=ScanStrategy.FULL_TABLE),
            actual_rows=100,
        )
        plan = IRPlan(
            root=root,
            engine=EngineType.POSTGRESQL,
            planning_time_ms=0.5,
            execution_time_ms=10.0,
        )
        assert plan.has_analyze_data
        assert plan.execution_time_ms == 10.0


# =============================================================================
# Test: Engine Detection
# =============================================================================


class TestEngineDetection:
    """Test automatic engine detection from plan format."""

    def test_detect_postgresql(self):
        assert detect_engine(PG_SEQ_SCAN_PLAN) == EngineType.POSTGRESQL

    def test_detect_postgresql_array(self):
        assert detect_engine([PG_SEQ_SCAN_PLAN]) == EngineType.POSTGRESQL

    def test_detect_mysql_json(self):
        assert detect_engine(MYSQL_FULL_TABLE_SCAN) == EngineType.MYSQL

    def test_detect_mysql_tabular(self):
        assert detect_engine(MYSQL_TABULAR_FORMAT) == EngineType.MYSQL

    def test_detect_unknown(self):
        assert detect_engine({"random": "data"}) == EngineType.UNKNOWN

    def test_detect_empty(self):
        assert detect_engine({}) == EngineType.UNKNOWN


# =============================================================================
# Test: PostgreSQL Adapter
# =============================================================================


class TestPostgreSQLAdapter:
    """Test PostgreSQL EXPLAIN → IR conversion."""

    def setup_method(self):
        self.adapter = PostgreSQLAdapter()

    def test_can_handle(self):
        assert self.adapter.can_handle(PG_SEQ_SCAN_PLAN)
        assert not self.adapter.can_handle(MYSQL_FULL_TABLE_SCAN)

    def test_seq_scan_conversion(self):
        ir = self.adapter.convert(PG_SEQ_SCAN_PLAN)
        root = ir.root
        assert root.is_full_table_scan
        assert root.relation == "orders"
        assert root.estimated_rows == 250000
        assert root.actual_rows == 248000
        assert root.estimated_cost == 45000.50
        assert root.schema == "public"
        assert root.engine == EngineType.POSTGRESQL
        assert root.source_node_type == "Seq Scan"
        assert ir.planning_time_ms == 0.25
        assert ir.execution_time_ms == 325.0

    def test_seq_scan_conditions(self):
        ir = self.adapter.convert(PG_SEQ_SCAN_PLAN)
        root = ir.root
        assert len(root.conditions) == 1
        assert root.conditions[0].kind == ConditionKind.FILTER
        assert "status" in root.conditions[0].expression

    def test_index_scan_conversion(self):
        ir = self.adapter.convert(PG_INDEX_SCAN_PLAN)
        root = ir.root
        assert root.is_index_scan
        assert not root.is_full_table_scan
        assert root.index_name == "idx_users_email"
        assert root.relation == "users"
        # Should have both filter and index condition
        assert len(root.conditions) == 2
        kinds = {c.kind for c in root.conditions}
        assert ConditionKind.FILTER in kinds
        assert ConditionKind.INDEX_CONDITION in kinds

    def test_hash_join_conversion(self):
        ir = self.adapter.convert(PG_HASH_JOIN_PLAN)
        root = ir.root
        assert root.is_join
        assert root.operator.is_hash_join
        assert root.join_type == JoinType.INNER
        assert len(root.children) == 2
        # First child: Seq Scan on orders
        assert root.children[0].is_full_table_scan
        assert root.children[0].relation == "orders"
        # Second child: Hash → Seq Scan on users
        assert root.children[1].operator.category == OperatorCategory.MATERIALIZE
        assert root.children[1].hash_info is not None
        assert root.children[1].hash_info.batches == 1

    def test_sort_spill_conversion(self):
        ir = self.adapter.convert(PG_SORT_SPILL_PLAN)
        root = ir.root
        assert root.is_sort
        assert root.sort_info is not None
        assert root.sort_info.is_spilling
        assert root.sort_info.strategy == SortStrategy.EXTERNAL_MERGE
        assert root.sort_info.space_used_kb == 51200
        assert root.sort_info.space_type == "Disk"
        assert root.is_spilling

    def test_parallel_plan_conversion(self):
        ir = self.adapter.convert(PG_PARALLEL_PLAN)
        root = ir.root
        assert root.operator.category == OperatorCategory.CONTROL
        assert root.parallel_info is not None
        assert root.parallel_info.workers_planned == 4
        assert root.parallel_info.workers_launched == 3
        assert root.parallel_info.underutilized
        # Child should be parallel-aware
        child = root.children[0]
        assert child.parallel_info is not None
        assert child.parallel_info.aware is True

    def test_buffer_stats_conversion(self):
        ir = self.adapter.convert(PG_BUFFERS_PLAN)
        root = ir.root
        assert root.buffers is not None
        assert root.buffers.shared_hit_blocks == 3
        assert root.buffers.shared_read_blocks == 1
        assert root.buffers.cache_hit_ratio == pytest.approx(0.75)
        assert root.buffers.io_read_time_ms == 0.05

    def test_tree_structure_preserved(self):
        ir = self.adapter.convert(PG_HASH_JOIN_PLAN)
        assert ir.node_count == 4  # join + 2 scans + hash
        all_nodes = ir.all_nodes
        scan_nodes = [n for n in all_nodes if n.is_scan]
        join_nodes = [n for n in all_nodes if n.is_join]
        assert len(scan_nodes) == 2
        assert len(join_nodes) == 1

    def test_engine_specific_preserved(self):
        """Engine-specific data not in IR should be preserved."""
        ir = self.adapter.convert(PG_SEQ_SCAN_PLAN)
        root = ir.root
        # "Rows Removed by Filter" is in engine_specific
        assert "Rows Removed by Filter" in root.engine_specific

    def test_plan_node_conversion(self):
        """Test conversion from existing PlanNode objects."""
        from querysense.parser.models import PlanNode

        node = PlanNode.model_validate({
            "Node Type": "Seq Scan",
            "Relation Name": "test_table",
            "Startup Cost": 0.0,
            "Total Cost": 100.0,
            "Plan Rows": 1000,
            "Plan Width": 50,
            "Actual Rows": 950,
            "Actual Loops": 1,
            "Filter": "(active = true)",
        })

        ir_node = self.adapter.convert_plan_node(node)
        assert ir_node.is_full_table_scan
        assert ir_node.relation == "test_table"
        assert ir_node.actual_rows == 950
        assert len(ir_node.filter_conditions) == 1


# =============================================================================
# Test: MySQL Adapter
# =============================================================================


class TestMySQLAdapter:
    """Test MySQL EXPLAIN → IR conversion."""

    def setup_method(self):
        self.adapter = MySQLAdapter()

    def test_can_handle_json(self):
        assert self.adapter.can_handle(MYSQL_FULL_TABLE_SCAN)
        assert not self.adapter.can_handle(PG_SEQ_SCAN_PLAN)

    def test_full_table_scan_json(self):
        ir = self.adapter.convert(MYSQL_FULL_TABLE_SCAN)
        root = ir.root
        assert root.is_full_table_scan
        assert root.relation == "orders"
        assert root.estimated_rows == 250000
        assert root.engine == EngineType.MYSQL
        assert "access_type" in root.engine_specific
        assert root.engine_specific["access_type"] == "ALL"

    def test_full_table_scan_condition(self):
        ir = self.adapter.convert(MYSQL_FULL_TABLE_SCAN)
        root = ir.root
        assert len(root.conditions) == 1
        assert root.conditions[0].kind == ConditionKind.ATTACHED
        assert "status" in root.conditions[0].expression

    def test_good_query_json(self):
        ir = self.adapter.convert(MYSQL_GOOD_QUERY)
        root = ir.root
        # const access = ROWID_SCAN (single row lookup)
        assert root.operator.scan == ScanStrategy.INDEX_ONLY
        assert root.relation == "users"
        assert root.index_name == "idx_email"

    def test_nested_loop_join_json(self):
        ir = self.adapter.convert(MYSQL_NESTED_LOOP_JOIN)
        root = ir.root
        assert root.is_join
        assert root.operator.is_nested_loop
        # Should have 2 children
        assert len(root.children) == 2
        assert root.children[0].relation == "orders"
        assert root.children[1].relation == "order_items"
        # First child: full scan
        assert root.children[0].is_full_table_scan
        # Second child: index scan (ref)
        assert root.children[1].is_index_scan

    def test_filesort_json(self):
        ir = self.adapter.convert(MYSQL_FILESORT_PLAN)
        root = ir.root
        assert root.is_sort
        assert root.sort_info is not None
        assert root.sort_info.strategy == SortStrategy.EXTERNAL
        # Child should be the table scan
        assert len(root.children) == 1
        assert root.children[0].is_full_table_scan

    def test_grouping_with_temporary(self):
        ir = self.adapter.convert(MYSQL_GROUPING_PLAN)
        root = ir.root
        assert root.is_aggregate
        assert root.operator.aggregate == AggregateStrategy.HASH
        assert root.engine_specific.get("using_temporary_table") is True

    def test_tabular_format_single(self):
        """Test MySQL tabular format (single table)."""
        ir = self.adapter.convert({"rows": MYSQL_TABULAR_FORMAT})
        root = ir.root
        assert root.is_full_table_scan
        assert root.relation == "orders"
        assert root.estimated_rows == 250000

    def test_tabular_format_join(self):
        """Test MySQL tabular format (join)."""
        ir = self.adapter.convert({"rows": MYSQL_TABULAR_JOIN})
        root = ir.root
        assert root.is_join
        assert root.operator.is_nested_loop
        assert len(root.children) == 2


# =============================================================================
# Test: Cross-Engine Comparison (IR Enables This)
# =============================================================================


class TestCrossEngineComparison:
    """
    Demonstrate that the IR enables cross-engine comparison.

    The same semantic operation (full table scan on 'orders') produces
    comparable IR nodes regardless of the source engine.
    """

    def test_same_semantic_operation(self):
        """PG Seq Scan and MySQL ALL produce equivalent IR operators."""
        pg_adapter = PostgreSQLAdapter()
        mysql_adapter = MySQLAdapter()

        pg_ir = pg_adapter.convert(PG_SEQ_SCAN_PLAN)
        mysql_ir = mysql_adapter.convert(MYSQL_FULL_TABLE_SCAN)

        # Same operator semantics
        assert pg_ir.root.operator == mysql_ir.root.operator
        assert pg_ir.root.is_full_table_scan
        assert mysql_ir.root.is_full_table_scan

        # Same table
        assert pg_ir.root.relation == mysql_ir.root.relation == "orders"

        # Different engines
        assert pg_ir.engine == EngineType.POSTGRESQL
        assert mysql_ir.engine == EngineType.MYSQL

    def test_find_full_table_scans_works_for_both(self):
        """find_full_table_scans works identically for both engines."""
        pg_adapter = PostgreSQLAdapter()
        mysql_adapter = MySQLAdapter()

        pg_ir = pg_adapter.convert(PG_HASH_JOIN_PLAN)
        mysql_ir = mysql_adapter.convert(MYSQL_NESTED_LOOP_JOIN)

        pg_fts = pg_ir.find_full_table_scans()
        mysql_fts = mysql_ir.find_full_table_scans()

        # Both find full table scans on 'orders'
        assert any(n.relation == "orders" for n in pg_fts)
        assert any(n.relation == "orders" for n in mysql_fts)


# =============================================================================
# Test: Cost Normalization
# =============================================================================


class TestCostNormalization:
    """Test cross-engine cost normalization."""

    def setup_method(self):
        self.normalizer = CostNormalizer()

    def test_pg_passthrough(self):
        """PostgreSQL costs pass through unchanged."""
        result = self.normalizer.normalize(500.0, EngineType.POSTGRESQL)
        assert result.raw_cost == 500.0
        assert result.normalized_cost == 500.0
        assert result.band == CostBand.LOW

    def test_mysql_scaling(self):
        """MySQL costs are scaled up."""
        result = self.normalizer.normalize(500.0, EngineType.MYSQL)
        assert result.raw_cost == 500.0
        assert result.normalized_cost == 2000.0  # 4x factor
        assert result.band == CostBand.MEDIUM

    def test_band_classification(self):
        """Cost band boundaries work correctly."""
        assert self.normalizer.normalize(5.0, EngineType.POSTGRESQL).band == CostBand.TRIVIAL
        assert self.normalizer.normalize(500.0, EngineType.POSTGRESQL).band == CostBand.LOW
        assert self.normalizer.normalize(25000.0, EngineType.POSTGRESQL).band == CostBand.MEDIUM
        assert self.normalizer.normalize(100000.0, EngineType.POSTGRESQL).band == CostBand.HIGH
        assert self.normalizer.normalize(1000000.0, EngineType.POSTGRESQL).band == CostBand.EXTREME

    def test_cost_comparison_regression(self):
        before = self.normalizer.normalize(1000.0, EngineType.POSTGRESQL)
        after = self.normalizer.normalize(5000.0, EngineType.POSTGRESQL)
        delta = self.normalizer.compare_costs(before, after)
        assert delta.is_regression
        assert not delta.is_improvement
        assert delta.ratio == pytest.approx(5.0)
        assert delta.percentage_change == pytest.approx(400.0)

    def test_cost_comparison_improvement(self):
        before = self.normalizer.normalize(5000.0, EngineType.POSTGRESQL)
        after = self.normalizer.normalize(500.0, EngineType.POSTGRESQL)
        delta = self.normalizer.compare_costs(before, after)
        assert delta.is_improvement
        assert not delta.is_regression

    def test_cost_comparison_stable(self):
        before = self.normalizer.normalize(1000.0, EngineType.POSTGRESQL)
        after = self.normalizer.normalize(1050.0, EngineType.POSTGRESQL)
        delta = self.normalizer.compare_costs(before, after)
        assert not delta.is_regression  # Within 10% threshold
        assert not delta.is_improvement


# =============================================================================
# Test: Auto-Conversion
# =============================================================================


class TestAutoConvert:
    """Test the auto_convert convenience function."""

    def test_auto_convert_pg(self):
        ir = auto_convert(PG_SEQ_SCAN_PLAN)
        assert ir.engine == EngineType.POSTGRESQL
        assert ir.root.is_full_table_scan

    def test_auto_convert_pg_array(self):
        ir = auto_convert([PG_SEQ_SCAN_PLAN])
        assert ir.engine == EngineType.POSTGRESQL

    def test_auto_convert_mysql(self):
        ir = auto_convert(MYSQL_FULL_TABLE_SCAN)
        assert ir.engine == EngineType.MYSQL
        assert ir.root.is_full_table_scan

    def test_auto_convert_unknown_raises(self):
        with pytest.raises(ValueError, match="Cannot detect"):
            auto_convert({"not": "a plan"})


# =============================================================================
# Test: Integration with Existing Parser
# =============================================================================


class TestParserIntegration:
    """Test that IR works with existing QuerySense parser pipeline."""

    def test_parse_then_convert(self):
        """Parse with existing parser, then convert to IR."""
        from querysense.parser.parser import parse_explain

        explain = parse_explain(PG_SEQ_SCAN_PLAN)
        assert explain.plan.node_type == "Seq Scan"

        # Convert to IR
        adapter = PostgreSQLAdapter()
        ir_node = adapter.convert_plan_node(explain.plan)
        assert ir_node.is_full_table_scan
        assert ir_node.relation == "orders"
        assert ir_node.actual_rows == 248000

    def test_parse_join_then_convert(self):
        """Complex join plan round-trips through IR."""
        from querysense.parser.parser import parse_explain

        explain = parse_explain(PG_HASH_JOIN_PLAN)
        adapter = PostgreSQLAdapter()
        ir_node = adapter.convert_plan_node(explain.plan)

        assert ir_node.is_join
        assert ir_node.operator.is_hash_join
        assert ir_node.node_count == 4
