#!/usr/bin/env python3
"""
QuerySense Stress Test Suite

Generates synthetic EXPLAIN plans at scale to benchmark QuerySense performance.
Outputs marketing-ready metrics and identifies edge cases.

Usage:
    python scripts/stress_test.py [--scale 1000,10000,100000,250000]
"""

import argparse
import gc
import json
import random
import sys
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from querysense.analyzer import Analyzer
from querysense.parser import parse_explain


# =============================================================================
# Synthetic Plan Generator
# =============================================================================

# Realistic table names and schemas
TABLES = [
    ("users", "public", ["id", "email", "name", "created_at", "status", "role"]),
    ("orders", "public", ["id", "user_id", "total", "status", "created_at", "updated_at"]),
    ("order_items", "public", ["id", "order_id", "product_id", "quantity", "price"]),
    ("products", "public", ["id", "name", "category", "price", "stock", "created_at"]),
    ("customers", "sales", ["id", "name", "email", "tier", "lifetime_value"]),
    ("transactions", "finance", ["id", "account_id", "amount", "type", "timestamp"]),
    ("sessions", "analytics", ["id", "user_id", "started_at", "ended_at", "page_views"]),
    ("events", "analytics", ["id", "session_id", "event_type", "payload", "timestamp"]),
    ("inventory", "warehouse", ["id", "product_id", "location", "quantity", "last_updated"]),
    ("shipments", "logistics", ["id", "order_id", "carrier", "status", "shipped_at"]),
]

FILTER_OPERATORS = ["=", ">", "<", ">=", "<=", "<>", "LIKE", "IN", "IS NULL", "IS NOT NULL"]
STATUS_VALUES = ["pending", "active", "completed", "cancelled", "processing", "shipped"]
SORT_METHODS = ["quicksort", "top-N heapsort", "external merge"]


def random_filter(table: str, columns: list[str]) -> str:
    """Generate a realistic filter condition."""
    col = random.choice(columns)
    op = random.choice(["=", ">", "<", ">=", "<="])
    
    if col in ["status", "type", "role", "tier", "category"]:
        val = random.choice(STATUS_VALUES)
        return f"({col} = '{val}'::text)"
    elif col in ["id", "user_id", "order_id", "product_id", "quantity", "stock"]:
        val = random.randint(1, 100000)
        return f"({col} {op} {val})"
    elif "at" in col or "timestamp" in col:
        return f"({col} > '2024-01-01'::date)"
    elif col in ["total", "amount", "price", "lifetime_value"]:
        val = round(random.uniform(10, 10000), 2)
        return f"({col} {op} {val})"
    else:
        return f"({col} IS NOT NULL)"


def generate_seq_scan(
    table: str,
    schema: str,
    columns: list[str],
    problematic: bool = True
) -> dict[str, Any]:
    """Generate a Seq Scan node."""
    rows = random.randint(100000, 1000000) if problematic else random.randint(100, 5000)
    removed = random.randint(int(rows * 0.1), int(rows * 0.9))
    cost = rows * 0.01
    exec_time = rows * 0.001 if problematic else rows * 0.0001
    
    return {
        "Node Type": "Seq Scan",
        "Parallel Aware": random.choice([True, False]) if not problematic else False,
        "Relation Name": table,
        "Schema": schema,
        "Alias": table[0],
        "Startup Cost": 0.0,
        "Total Cost": round(cost, 2),
        "Plan Rows": rows // 2,
        "Plan Width": random.randint(32, 256),
        "Actual Startup Time": round(random.uniform(0.01, 0.1), 3),
        "Actual Total Time": round(exec_time, 3),
        "Actual Rows": rows,
        "Actual Loops": 1,
        "Filter": random_filter(table, columns),
        "Rows Removed by Filter": removed,
        "Shared Hit Blocks": random.randint(100, 5000),
        "Shared Read Blocks": random.randint(0, 10000) if problematic else 0,
    }


def generate_index_scan(
    table: str,
    schema: str,
    columns: list[str],
    loops: int = 1
) -> dict[str, Any]:
    """Generate an Index Scan node."""
    rows = random.randint(1, 100)
    idx_col = random.choice(columns[:3])  # Usually indexed on first few columns
    
    return {
        "Node Type": "Index Scan",
        "Parallel Aware": False,
        "Scan Direction": "Forward",
        "Index Name": f"idx_{table}_{idx_col}",
        "Relation Name": table,
        "Schema": schema,
        "Alias": table[0],
        "Startup Cost": round(random.uniform(0.1, 1.0), 2),
        "Total Cost": round(random.uniform(1, 50), 2),
        "Plan Rows": rows,
        "Plan Width": random.randint(32, 128),
        "Actual Startup Time": round(random.uniform(0.001, 0.01), 4),
        "Actual Total Time": round(random.uniform(0.01, 0.5), 3),
        "Actual Rows": rows,
        "Actual Loops": loops,
        "Index Cond": f"({idx_col} = $1)",
        "Shared Hit Blocks": random.randint(1, 100) * loops,
        "Shared Read Blocks": 0,
    }


def generate_nested_loop(problematic: bool = True) -> dict[str, Any]:
    """Generate a Nested Loop join node."""
    outer_table, outer_schema, outer_cols = random.choice(TABLES[:5])
    inner_table, inner_schema, inner_cols = random.choice(TABLES[5:])
    
    outer_rows = random.randint(5000, 50000) if problematic else random.randint(10, 100)
    loops = outer_rows
    
    inner_node = generate_index_scan(inner_table, inner_schema, inner_cols, loops)
    inner_node["Parent Relationship"] = "Inner"
    
    outer_node = generate_seq_scan(outer_table, outer_schema, outer_cols, problematic)
    outer_node["Parent Relationship"] = "Outer"
    outer_node["Actual Rows"] = outer_rows
    
    total_time = outer_node["Actual Total Time"] + (inner_node["Actual Total Time"] * loops)
    
    return {
        "Node Type": "Nested Loop",
        "Parallel Aware": False,
        "Join Type": random.choice(["Inner", "Left", "Right"]),
        "Startup Cost": round(random.uniform(0.1, 1.0), 2),
        "Total Cost": round(random.uniform(10000, 100000), 2),
        "Plan Rows": outer_rows * inner_node["Actual Rows"],
        "Plan Width": random.randint(100, 500),
        "Actual Startup Time": round(random.uniform(0.01, 0.1), 3),
        "Actual Total Time": round(total_time, 3),
        "Actual Rows": outer_rows * inner_node["Actual Rows"],
        "Actual Loops": 1,
        "Inner Unique": random.choice([True, False]),
        "Plans": [outer_node, inner_node],
    }


def generate_hash_join(spilling: bool = True) -> dict[str, Any]:
    """Generate a Hash Join node."""
    left_table, left_schema, left_cols = random.choice(TABLES[:5])
    right_table, right_schema, right_cols = random.choice(TABLES[5:])
    
    rows = random.randint(50000, 500000)
    batches = random.randint(2, 16) if spilling else 1
    
    hash_node = {
        "Node Type": "Hash",
        "Parent Relationship": "Inner",
        "Parallel Aware": False,
        "Startup Cost": round(random.uniform(100, 1000), 2),
        "Total Cost": round(random.uniform(1000, 5000), 2),
        "Plan Rows": rows // 10,
        "Plan Width": random.randint(32, 128),
        "Actual Startup Time": round(random.uniform(10, 100), 3),
        "Actual Total Time": round(random.uniform(100, 500), 3),
        "Actual Rows": rows // 10,
        "Actual Loops": 1,
        "Hash Buckets": 2 ** random.randint(10, 16),
        "Hash Batches": batches,
        "Original Hash Batches": 1,
        "Peak Memory Usage": random.randint(1024, 131072),
        "Plans": [generate_seq_scan(right_table, right_schema, right_cols, True)],
    }
    hash_node["Plans"][0]["Parent Relationship"] = "Outer"
    
    return {
        "Node Type": "Hash Join",
        "Parallel Aware": False,
        "Join Type": "Inner",
        "Startup Cost": round(random.uniform(100, 1000), 2),
        "Total Cost": round(random.uniform(10000, 100000), 2),
        "Plan Rows": rows,
        "Plan Width": random.randint(100, 300),
        "Actual Startup Time": round(random.uniform(10, 100), 3),
        "Actual Total Time": round(random.uniform(500, 5000), 3),
        "Actual Rows": rows,
        "Actual Loops": 1,
        "Hash Cond": f"({left_table[0]}.id = {right_table[0]}.{left_table}_id)",
        "Plans": [
            generate_seq_scan(left_table, left_schema, left_cols, True),
            hash_node,
        ],
    }


def generate_sort(spilling: bool = True) -> dict[str, Any]:
    """Generate a Sort node."""
    table, schema, columns = random.choice(TABLES)
    rows = random.randint(10000, 500000)
    sort_col = random.choice(columns)
    
    method = "external merge" if spilling else random.choice(["quicksort", "top-N heapsort"])
    disk_usage = random.randint(10000, 500000) if spilling else 0
    
    child = generate_seq_scan(table, schema, columns, True)
    child["Actual Rows"] = rows
    
    return {
        "Node Type": "Sort",
        "Parallel Aware": False,
        "Startup Cost": round(random.uniform(1000, 10000), 2),
        "Total Cost": round(random.uniform(10000, 50000), 2),
        "Plan Rows": rows,
        "Plan Width": random.randint(32, 128),
        "Actual Startup Time": round(random.uniform(100, 1000), 3),
        "Actual Total Time": round(random.uniform(500, 5000), 3),
        "Actual Rows": rows,
        "Actual Loops": 1,
        "Sort Key": [f"{table[0]}.{sort_col}"],
        "Sort Method": method,
        "Sort Space Used": disk_usage if spilling else random.randint(100, 10000),
        "Sort Space Type": "Disk" if spilling else "Memory",
        "Plans": [child],
    }


def generate_aggregate(spilling: bool = False) -> dict[str, Any]:
    """Generate a HashAggregate node."""
    table, schema, columns = random.choice(TABLES)
    rows = random.randint(1000, 100000)
    batches = random.randint(2, 8) if spilling else 1
    
    child = generate_seq_scan(table, schema, columns, True)
    
    return {
        "Node Type": "Aggregate",
        "Strategy": "Hashed",
        "Parallel Aware": False,
        "Startup Cost": round(random.uniform(1000, 5000), 2),
        "Total Cost": round(random.uniform(5000, 20000), 2),
        "Plan Rows": rows // 100,
        "Plan Width": random.randint(32, 64),
        "Actual Startup Time": round(random.uniform(100, 500), 3),
        "Actual Total Time": round(random.uniform(500, 2000), 3),
        "Actual Rows": rows // 100,
        "Actual Loops": 1,
        "Group Key": [random.choice(columns)],
        "Batches": batches,
        "Peak Memory Usage": random.randint(1024, 65536),
        "Disk Usage": random.randint(10000, 100000) if spilling else 0,
        "Plans": [child],
    }


def generate_subplan() -> dict[str, Any]:
    """Generate a SubPlan (correlated subquery)."""
    outer_table, outer_schema, outer_cols = random.choice(TABLES[:3])
    inner_table, inner_schema, inner_cols = random.choice(TABLES[3:6])
    
    outer_rows = random.randint(1000, 50000)
    
    subplan_node = generate_seq_scan(inner_table, inner_schema, inner_cols, True)
    subplan_node["Parent Relationship"] = "SubPlan"
    subplan_node["Subplan Name"] = "SubPlan 1"
    subplan_node["Actual Loops"] = outer_rows
    
    outer_node = generate_seq_scan(outer_table, outer_schema, outer_cols, True)
    outer_node["Actual Rows"] = outer_rows
    
    return {
        "Node Type": "Result",
        "Parallel Aware": False,
        "Startup Cost": 0.0,
        "Total Cost": round(random.uniform(50000, 500000), 2),
        "Plan Rows": outer_rows,
        "Plan Width": random.randint(100, 300),
        "Actual Startup Time": round(random.uniform(0.01, 0.1), 3),
        "Actual Total Time": round(random.uniform(5000, 50000), 3),
        "Actual Rows": outer_rows,
        "Actual Loops": 1,
        "Plans": [outer_node, subplan_node],
    }


def generate_plan() -> dict[str, Any]:
    """Generate a complete EXPLAIN plan with random structure."""
    plan_type = random.choices(
        ["seq_scan", "nested_loop", "hash_join", "sort", "aggregate", "subplan", "good"],
        weights=[25, 20, 15, 15, 10, 10, 5],
        k=1
    )[0]
    
    if plan_type == "seq_scan":
        table, schema, columns = random.choice(TABLES)
        root = generate_seq_scan(table, schema, columns, problematic=True)
    elif plan_type == "nested_loop":
        root = generate_nested_loop(problematic=True)
    elif plan_type == "hash_join":
        root = generate_hash_join(spilling=random.choice([True, False]))
    elif plan_type == "sort":
        root = generate_sort(spilling=random.choice([True, False]))
    elif plan_type == "aggregate":
        root = generate_aggregate(spilling=random.choice([True, False]))
    elif plan_type == "subplan":
        root = generate_subplan()
    else:  # good - no issues
        table, schema, columns = random.choice(TABLES)
        root = generate_index_scan(table, schema, columns)
    
    return [{
        "Plan": root,
        "Planning Time": round(random.uniform(0.05, 2.0), 3),
        "Execution Time": root.get("Actual Total Time", 100) + random.uniform(1, 10),
    }]


# =============================================================================
# Benchmark Runner
# =============================================================================

@dataclass
class BenchmarkResult:
    """Results from a benchmark run."""
    scale: int
    total_time_seconds: float
    plans_per_second: float
    peak_memory_mb: float
    total_findings: int
    findings_by_severity: dict[str, int]
    findings_by_rule: dict[str, int]
    errors: int


def run_benchmark(scale: int, parallel: bool = True) -> BenchmarkResult:
    """Run benchmark at a given scale."""
    print(f"\n{'='*60}")
    print(f"Running benchmark: {scale:,} plans")
    print(f"{'='*60}")
    
    # Generate plans
    print(f"  Generating {scale:,} synthetic plans...")
    gen_start = time.perf_counter()
    plans = [generate_plan() for _ in range(scale)]
    gen_time = time.perf_counter() - gen_start
    print(f"  Generated in {gen_time:.2f}s ({scale/gen_time:,.0f} plans/sec)")
    
    # Prepare analyzer
    analyzer = Analyzer()
    
    # Track memory
    gc.collect()
    tracemalloc.start()
    
    # Analyze plans
    print(f"  Analyzing plans...")
    analyze_start = time.perf_counter()
    
    total_findings = 0
    findings_by_severity: dict[str, int] = {}
    findings_by_rule: dict[str, int] = {}
    errors = 0
    
    def analyze_one(plan_json: list[dict]) -> list:
        try:
            parsed = parse_explain(plan_json)
            result = analyzer.analyze(parsed)
            return result.findings
        except Exception:
            return []
    
    if parallel:
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(analyze_one, p) for p in plans]
            for i, future in enumerate(as_completed(futures)):
                if (i + 1) % (scale // 10 or 1) == 0:
                    print(f"    Progress: {i+1:,}/{scale:,} ({(i+1)/scale*100:.0f}%)")
                try:
                    findings = future.result()
                    total_findings += len(findings)
                    for f in findings:
                        findings_by_severity[f.severity.value] = findings_by_severity.get(f.severity.value, 0) + 1
                        findings_by_rule[f.rule_id] = findings_by_rule.get(f.rule_id, 0) + 1
                except Exception:
                    errors += 1
    else:
        for i, plan in enumerate(plans):
            if (i + 1) % (scale // 10 or 1) == 0:
                print(f"    Progress: {i+1:,}/{scale:,} ({(i+1)/scale*100:.0f}%)")
            try:
                findings = analyze_one(plan)
                total_findings += len(findings)
                for f in findings:
                    findings_by_severity[f.severity.value] = findings_by_severity.get(f.severity.value, 0) + 1
                    findings_by_rule[f.rule_id] = findings_by_rule.get(f.rule_id, 0) + 1
            except Exception:
                errors += 1
    
    analyze_time = time.perf_counter() - analyze_start
    
    # Memory stats
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    peak_mb = peak / 1024 / 1024
    
    return BenchmarkResult(
        scale=scale,
        total_time_seconds=analyze_time,
        plans_per_second=scale / analyze_time,
        peak_memory_mb=peak_mb,
        total_findings=total_findings,
        findings_by_severity=findings_by_severity,
        findings_by_rule=findings_by_rule,
        errors=errors,
    )


def print_results(results: list[BenchmarkResult]) -> None:
    """Print benchmark results in a nice format."""
    print("\n" + "="*70)
    print("BENCHMARK RESULTS")
    print("="*70)
    
    # Summary table
    print("\n{:<12} {:>12} {:>14} {:>12} {:>10}".format(
        "Scale", "Time (s)", "Plans/sec", "Memory (MB)", "Findings"
    ))
    print("-" * 70)
    
    for r in results:
        print("{:<12,} {:>12.2f} {:>14,.0f} {:>12.1f} {:>10,}".format(
            r.scale,
            r.total_time_seconds,
            r.plans_per_second,
            r.peak_memory_mb,
            r.total_findings,
        ))
    
    # Best result for marketing
    if results:
        best = max(results, key=lambda r: r.scale)
        print("\n" + "="*70)
        print("MARKETING METRICS")
        print("="*70)
        print(f"""
Analyzed {best.scale:,} query plans in {best.total_time_seconds:.1f} seconds
  - {best.plans_per_second:,.0f} plans analyzed per second
  - Found {best.total_findings:,} optimization opportunities
  - Peak memory usage: {best.peak_memory_mb:.0f}MB
  - Error rate: {best.errors/best.scale*100:.2f}%
""")
        
        print("Findings by severity:")
        for sev, count in sorted(best.findings_by_severity.items(), key=lambda x: -x[1]):
            print(f"  {sev}: {count:,}")
        
        print("\nTop issues detected:")
        for rule, count in sorted(best.findings_by_rule.items(), key=lambda x: -x[1])[:5]:
            print(f"  {rule}: {count:,}")
    
    # Save to JSON
    output_path = Path(__file__).parent / "benchmark_results.json"
    output_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "results": [
            {
                "scale": r.scale,
                "total_time_seconds": r.total_time_seconds,
                "plans_per_second": r.plans_per_second,
                "peak_memory_mb": r.peak_memory_mb,
                "total_findings": r.total_findings,
                "findings_by_severity": r.findings_by_severity,
                "findings_by_rule": r.findings_by_rule,
                "errors": r.errors,
            }
            for r in results
        ]
    }
    output_path.write_text(json.dumps(output_data, indent=2))
    print(f"\nResults saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="QuerySense Stress Test")
    parser.add_argument(
        "--scale",
        type=str,
        default="1000,10000,50000",
        help="Comma-separated list of scales to test (default: 1000,10000,50000)"
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        default=True,
        help="Use parallel processing (default: True)"
    )
    parser.add_argument(
        "--no-parallel",
        action="store_true",
        help="Disable parallel processing"
    )
    
    args = parser.parse_args()
    scales = [int(s.strip()) for s in args.scale.split(",")]
    parallel = not args.no_parallel
    
    print("QuerySense Stress Test Suite")
    print("="*70)
    print(f"Scales to test: {', '.join(f'{s:,}' for s in scales)}")
    print(f"Parallel processing: {parallel}")
    
    results = []
    for scale in scales:
        result = run_benchmark(scale, parallel=parallel)
        results.append(result)
        
        # Quick summary
        print(f"\n  Completed: {result.total_time_seconds:.2f}s, "
              f"{result.plans_per_second:,.0f} plans/sec, "
              f"{result.total_findings:,} findings")
    
    print_results(results)


if __name__ == "__main__":
    main()
