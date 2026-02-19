"""Functional test for zero-downtime migration planner."""
from querysense.migration import ZeroDowntimePlanner

planner = ZeroDowntimePlanner()

# Test ADD COLUMN NOT NULL
sql1 = "ALTER TABLE orders ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'"
plan1 = planner.plan(sql1)
print("=== ADD COLUMN NOT NULL ===")
print(plan1.format_text())
assert plan1.total_phases == 3, f"Expected 3 phases, got {plan1.total_phases}"
assert plan1.phases[0].phase_type.value == "expand"
assert plan1.phases[1].phase_type.value == "migrate"
assert plan1.phases[2].phase_type.value == "contract"

# Test DROP TABLE
plan2 = planner.plan("DROP TABLE legacy_data")
print("=== DROP TABLE ===")
print(plan2.format_text())
assert plan2.total_phases == 3
assert "RENAME" in plan2.phases[0].sql

# Test CREATE INDEX
plan3 = planner.plan("CREATE INDEX idx_orders_status ON orders(status)")
assert "CONCURRENTLY" in plan3.phases[0].sql
print("CREATE INDEX: rewritten to CONCURRENTLY")

# Test ADD CONSTRAINT
plan4 = planner.plan("ALTER TABLE orders ADD CONSTRAINT chk_amount CHECK (amount > 0)")
assert plan4.total_phases == 2
assert "NOT VALID" in plan4.phases[0].sql
assert "VALIDATE" in plan4.phases[1].sql
print("ADD CONSTRAINT: NOT VALID + VALIDATE pattern")

# Test ALTER TYPE
plan5 = planner.plan("ALTER TABLE users ALTER COLUMN age TYPE BIGINT")
assert plan5.total_phases == 3
print("ALTER TYPE: 3-phase swap")

# Test RENAME COLUMN
plan6 = planner.plan("ALTER TABLE users RENAME COLUMN name TO full_name")
assert plan6.total_phases == 4
print("RENAME COLUMN: 4-phase add-sync-swap")

# JSON output
import json
data = json.loads(plan1.to_json())
assert data["total_phases"] == 3

print("\nZERO-DOWNTIME PLANNER: ALL TESTS PASSED")
print(f"  ADD COLUMN NOT NULL: {plan1.total_phases} phases")
print(f"  DROP TABLE: {plan2.total_phases} phases")
print(f"  CREATE INDEX: CONCURRENTLY rewrite")
print(f"  ADD CONSTRAINT: NOT VALID + VALIDATE")
print(f"  ALTER TYPE: {plan5.total_phases} phases")
print(f"  RENAME COLUMN: {plan6.total_phases} phases")
