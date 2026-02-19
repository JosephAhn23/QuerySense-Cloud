#!/usr/bin/env python3
"""
Generate real EXPLAIN output from Docker databases.

Usage:
    docker-compose up -d
    python scripts/generate_real_explains.py
"""

import json
import subprocess
import sys
from pathlib import Path


FIXTURES_DIR = Path(__file__).parent.parent / "tests" / "fixtures" / "real"
FIXTURES_DIR.mkdir(exist_ok=True)

# Queries that should trigger issues
PROBLEMATIC_QUERIES = {
    "seq_scan_status": """
        SELECT * FROM orders WHERE status = 'pending'
    """,
    "seq_scan_date_range": """
        SELECT * FROM orders 
        WHERE created_at > '2024-01-01' 
        ORDER BY created_at DESC
    """,
    "missing_join_index": """
        SELECT o.*, oi.* 
        FROM orders o 
        JOIN order_items oi ON o.id = oi.order_id 
        WHERE o.status = 'pending'
    """,
    "bad_row_estimate": """
        SELECT * FROM orders 
        WHERE status = 'pending' 
        AND total > 100
    """,
    "sort_without_index": """
        SELECT * FROM orders 
        ORDER BY total DESC 
        LIMIT 100
    """,
    "group_by_unindexed": """
        SELECT status, COUNT(*), AVG(total) 
        FROM orders 
        GROUP BY status
    """,
    "subquery_in_where": """
        SELECT * FROM orders 
        WHERE customer_id IN (
            SELECT id FROM users WHERE status = 'inactive'
        )
    """,
}

# Queries that should NOT trigger issues
GOOD_QUERIES = {
    "index_scan": """
        SELECT * FROM users WHERE email = 'user1@example.com'
    """,
    "indexed_join": """
        SELECT oi.*, p.name 
        FROM order_items oi 
        JOIN products p ON oi.product_id = p.id
        LIMIT 100
    """,
}


def run_postgres_explain(query: str) -> dict:
    """Run EXPLAIN ANALYZE on PostgreSQL and return JSON."""
    cmd = [
        "docker", "exec", "querysense-postgres",
        "psql", "-U", "querysense", "-d", "testdb", "-t", "-c",
        f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {query}"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"PostgreSQL error: {result.stderr}")
        return {}
    return json.loads(result.stdout.strip())


def run_mysql_explain(query: str) -> list:
    """Run EXPLAIN on MySQL and return JSON."""
    # MySQL traditional format
    cmd = [
        "docker", "exec", "querysense-mysql",
        "mysql", "-u", "querysense", "-pquerysense", "testdb",
        "-e", f"EXPLAIN FORMAT=JSON {query}"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"MySQL error: {result.stderr}")
        return []
    
    # Parse MySQL output (skip header line)
    lines = result.stdout.strip().split("\n")
    json_str = "\n".join(lines[1:]) if len(lines) > 1 else lines[0]
    return json.loads(json_str)


def main():
    print("Generating real EXPLAIN output from Docker databases...")
    print("=" * 60)
    
    # Check Docker is running
    result = subprocess.run(
        ["docker", "ps", "--filter", "name=querysense", "--format", "{{.Names}}"],
        capture_output=True, text=True
    )
    containers = result.stdout.strip().split("\n")
    
    postgres_running = "querysense-postgres" in containers
    mysql_running = "querysense-mysql" in containers
    
    if not postgres_running and not mysql_running:
        print("Error: No QuerySense containers running.")
        print("Run: docker-compose up -d")
        sys.exit(1)
    
    all_queries = {**PROBLEMATIC_QUERIES, **GOOD_QUERIES}
    
    # PostgreSQL
    if postgres_running:
        print("\nPostgreSQL EXPLAIN output:")
        pg_dir = FIXTURES_DIR / "postgres"
        pg_dir.mkdir(exist_ok=True)
        
        for name, query in all_queries.items():
            print(f"  - {name}...", end=" ")
            try:
                result = run_postgres_explain(query)
                if result:
                    (pg_dir / f"{name}.json").write_text(
                        json.dumps(result, indent=2)
                    )
                    print("OK")
                else:
                    print("SKIP (no result)")
            except Exception as e:
                print(f"ERROR: {e}")
    else:
        print("PostgreSQL not running, skipping...")
    
    # MySQL
    if mysql_running:
        print("\nMySQL EXPLAIN output:")
        mysql_dir = FIXTURES_DIR / "mysql"
        mysql_dir.mkdir(exist_ok=True)
        
        for name, query in all_queries.items():
            print(f"  - {name}...", end=" ")
            try:
                result = run_mysql_explain(query)
                if result:
                    (mysql_dir / f"{name}.json").write_text(
                        json.dumps(result, indent=2)
                    )
                    print("OK")
                else:
                    print("SKIP (no result)")
            except Exception as e:
                print(f"ERROR: {e}")
    else:
        print("MySQL not running, skipping...")
    
    print("\n" + "=" * 60)
    print(f"Fixtures saved to: {FIXTURES_DIR}")


if __name__ == "__main__":
    main()
