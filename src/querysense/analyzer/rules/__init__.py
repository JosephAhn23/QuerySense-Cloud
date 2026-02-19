"""Analyzer rules module - individual detection rules."""

from querysense.analyzer.rules.base import Rule, RuleConfig, discover_rules
from querysense.analyzer.rules.append_many_children import AppendManyChildren
from querysense.analyzer.rules.backward_index_scan import BackwardIndexScan
from querysense.analyzer.rules.bad_row_estimate import BadRowEstimate
from querysense.analyzer.rules.buffer_analysis import BufferAnalysis
from querysense.analyzer.rules.correlated_subquery import CorrelatedSubquery
from querysense.analyzer.rules.cost_hotspot import CostHotspot
from querysense.analyzer.rules.cpu_io_classifier import CPUIoClassifier
from querysense.analyzer.rules.excessive_result_width import ExcessiveResultWidth
from querysense.analyzer.rules.excessive_seq_scans import ExcessiveSeqScans
from querysense.analyzer.rules.foreign_key_index import ForeignKeyWithoutIndex
from querysense.analyzer.rules.gather_worker_shortage import GatherWorkerShortage
from querysense.analyzer.rules.gin_index_opportunity import GinIndexOpportunity
from querysense.analyzer.rules.hash_join_batches import HashJoinBatches
from querysense.analyzer.rules.implicit_cast_filter import ImplicitCastFilter
from querysense.analyzer.rules.inefficient_index_scan import InefficientIndexScan
from querysense.analyzer.rules.join_filter_high_ratio import JoinFilterHighRatio
from querysense.analyzer.rules.limit_without_index import LimitWithoutIndex
from querysense.analyzer.rules.materialize_large import MaterializeLarge
from querysense.analyzer.rules.memoize_miss_rate import MemoizeMissRate
from querysense.analyzer.rules.missing_buffers import MissingBuffers
from querysense.analyzer.rules.nested_loop_large_table import NestedLoopLargeTable
from querysense.analyzer.rules.parallel_query_not_used import ParallelQueryNotUsed
from querysense.analyzer.rules.partial_index_opportunity import PartialIndexOpportunity
from querysense.analyzer.rules.partition_pruning import PartitionPruningFailure
from querysense.analyzer.rules.redundant_sort import RedundantSort
from querysense.analyzer.rules.seq_scan_large_table import SeqScanLargeTable
from querysense.analyzer.rules.seq_scan_no_filter import SeqScanNoFilter
from querysense.analyzer.rules.sort_avoidable_with_index import SortAvoidableWithIndex
from querysense.analyzer.rules.spilling_to_disk import SpillingToDisk
from querysense.analyzer.rules.sql_rewrite_opportunities import SqlRewriteOpportunities
from querysense.analyzer.rules.work_mem_tuning import WorkMemTuning
from querysense.analyzer.rules.stale_statistics import StaleStatistics
from querysense.analyzer.rules.table_bloat import TableBloat
from querysense.analyzer.rules.tid_scan_performance import TidScanPerformance
from querysense.analyzer.rules.time_skew import TimeSkew
from querysense.analyzer.rules.window_function_cost import WindowFunctionCost
from querysense.analyzer.rules.orm_n_plus_one import ORMNPlusOne
from querysense.analyzer.rules.lateral_join_index import LateralJoinIndex
from querysense.analyzer.rules.index_column_order import IndexColumnOrder
from querysense.analyzer.rules.collation_sort_advisor import CollationSortAdvisor
from querysense.analyzer.rules.subplan_loop_detector import SubPlanLoopDetector
from querysense.analyzer.rules.toast_wide_row import ToastWideRow
from querysense.analyzer.rules.wal_full_page_writes import WALFullPageWrites

__all__ = [
    "Rule",
    "RuleConfig",
    "discover_rules",
    # Individual rules (alphabetical)
    "AppendManyChildren",
    "BackwardIndexScan",
    "BadRowEstimate",
    "BufferAnalysis",
    "CollationSortAdvisor",
    "CorrelatedSubquery",
    "CostHotspot",
    "CPUIoClassifier",
    "ExcessiveResultWidth",
    "ExcessiveSeqScans",
    "ForeignKeyWithoutIndex",
    "GatherWorkerShortage",
    "GinIndexOpportunity",
    "HashJoinBatches",
    "ImplicitCastFilter",
    "IndexColumnOrder",
    "InefficientIndexScan",
    "JoinFilterHighRatio",
    "LateralJoinIndex",
    "LimitWithoutIndex",
    "MaterializeLarge",
    "MemoizeMissRate",
    "MissingBuffers",
    "NestedLoopLargeTable",
    "ORMNPlusOne",
    "ParallelQueryNotUsed",
    "PartialIndexOpportunity",
    "PartitionPruningFailure",
    "RedundantSort",
    "SeqScanLargeTable",
    "SeqScanNoFilter",
    "SortAvoidableWithIndex",
    "SpillingToDisk",
    "SqlRewriteOpportunities",
    "StaleStatistics",
    "SubPlanLoopDetector",
    "TableBloat",
    "TidScanPerformance",
    "TimeSkew",
    "ToastWideRow",
    "WALFullPageWrites",
    "WindowFunctionCost",
    "WorkMemTuning",
]
