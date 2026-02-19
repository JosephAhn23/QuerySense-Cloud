"""
Transaction Safety Rules for Fintech.

Detects queries prone to financial data corruption:
- Weak isolation levels on financial tables
- Race conditions in balance checks
- Missing row-level locking

These issues can cause:
- Double-spend vulnerabilities
- Phantom reads in balance checks
- Inconsistent settlement states
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field

from querysense.analyzer.models import Finding, NodeContext, RulePhase, Severity
from querysense.analyzer.path import NodePath
from querysense.analyzer.rules.base import Rule, RuleConfig

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput


class TransactionSafetyConfig(RuleConfig):
    """Configuration for transaction safety checks."""
    
    # Tables that require strong isolation
    financial_tables: list[str] = Field(
        default=[
            "accounts", "balances", "transactions", "transfers",
            "settlements", "positions", "orders", "trades",
            "wallets", "ledger", "payments"
        ],
        description="Table names that require SERIALIZABLE isolation"
    )
    
    # Minimum required isolation level
    min_isolation_level: str = Field(
        default="REPEATABLE READ",
        description="Minimum isolation for financial operations"
    )
    
    # Row count thresholds
    concurrent_risk_threshold: int = Field(
        default=1,
        ge=1,
        description="Rows affected that indicate concurrent modification risk"
    )


class WeakIsolationLevel(Rule):
    """
    Detect queries on financial tables without proper isolation.
    
    Financial transactions MUST use SERIALIZABLE or REPEATABLE READ:
    - READ COMMITTED allows phantom reads
    - READ UNCOMMITTED allows dirty reads
    
    Both can cause:
    - Double-spend in balance transfers
    - Incorrect position calculations
    - Settlement mismatches
    
    Compliance: PCI-DSS 6.5.10 (broken transaction logic)
    """
    
    rule_id = "FINTECH_WEAK_ISOLATION"
    version = "1.0.0"
    severity = Severity.CRITICAL
    description = "Financial query may have weak isolation level"
    config_schema = TransactionSafetyConfig
    phase = RulePhase.AGGREGATE
    
    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Check for weak isolation on financial tables."""
        findings: list[Finding] = []
        config: TransactionSafetyConfig = self.config  # type: ignore
        
        # Check if query touches financial tables
        financial_tables_accessed = self._find_financial_tables(explain, config)
        
        if not financial_tables_accessed:
            return []
        
        # Check for modification operations (UPDATE, DELETE risk)
        # In EXPLAIN output, LockRows indicates FOR UPDATE
        has_locking = False
        modifies_data = False
        
        for node in explain.all_nodes:
            if node.node_type == "LockRows":
                has_locking = True
            if node.node_type in ("ModifyTable", "Insert", "Update", "Delete"):
                modifies_data = True
        
        # Flag if modifying financial data without explicit locking
        if modifies_data and not has_locking:
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=Severity.CRITICAL,
                context=NodeContext(
                    path=NodePath.root(),
                    node_type=explain.plan.node_type,
                    relation_name=", ".join(financial_tables_accessed),
                    actual_rows=explain.plan.actual_rows,
                    plan_rows=explain.plan.plan_rows,
                    total_cost=explain.plan.total_cost,
                    depth=0,
                ),
                title=f"Financial modification without row locking: {', '.join(financial_tables_accessed)}",
                description=(
                    f"This query modifies financial tables ({', '.join(financial_tables_accessed)}) "
                    f"without explicit row locking. This creates race condition risk: "
                    f"concurrent transactions may read stale data and produce incorrect results. "
                    f"Risk: double-spend, incorrect balances, settlement failures."
                ),
                suggestion=self._generate_isolation_fix(financial_tables_accessed),
                metrics={
                    "tables_at_risk": len(financial_tables_accessed),
                },
            ))
        
        return findings
    
    def _find_financial_tables(
        self,
        explain: "ExplainOutput",
        config: TransactionSafetyConfig
    ) -> list[str]:
        """Find financial tables accessed by the query."""
        financial = []
        for node in explain.all_nodes:
            if node.relation_name:
                table_lower = node.relation_name.lower()
                for fin_table in config.financial_tables:
                    if fin_table in table_lower:
                        financial.append(node.relation_name)
                        break
        return list(set(financial))
    
    def _generate_isolation_fix(self, tables: list[str]) -> str:
        """Generate isolation level fix."""
        return f"""-- CRITICAL: Add transaction isolation for financial safety

-- Option 1: Use SERIALIZABLE isolation
BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;
-- ... your query ...
COMMIT;

-- Option 2: Use explicit row locking (FOR UPDATE)
SELECT * FROM {tables[0]} WHERE id = ? FOR UPDATE;
-- Then perform modification

-- Option 3: Advisory locks for application-level control
SELECT pg_advisory_xact_lock(hashtext('{tables[0]}' || user_id::text));

-- Compliance: PCI-DSS 6.5.10, SOC2 CC6.1"""


class RaceConditionRisk(Rule):
    """
    Detect queries prone to race conditions in financial operations.
    
    Common patterns that cause race conditions:
    - SELECT balance, then UPDATE without FOR UPDATE
    - Time gap between READ and WRITE
    - Multiple queries checking same row
    
    Example vulnerability:
    - User balance: $100
    - Two concurrent $60 withdrawals
    - Both read $100, both approve → $20 overdraft
    
    Fix: SELECT ... FOR UPDATE NOWAIT
    """
    
    rule_id = "FINTECH_RACE_CONDITION_RISK"
    version = "1.0.0"
    severity = Severity.CRITICAL
    description = "Query pattern susceptible to race conditions"
    config_schema = TransactionSafetyConfig
    phase = RulePhase.AGGREGATE
    
    def analyze(
        self,
        explain: "ExplainOutput",
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Detect race condition patterns."""
        findings: list[Finding] = []
        config: TransactionSafetyConfig = self.config  # type: ignore
        
        # Find financial tables accessed
        financial_tables = self._find_financial_tables(explain, config)
        
        if not financial_tables:
            return []
        
        # Check for read-without-lock on financial tables
        for node in explain.all_nodes:
            if not node.relation_name:
                continue
            
            table_lower = node.relation_name.lower()
            is_financial = any(ft in table_lower for ft in config.financial_tables)
            
            if not is_financial:
                continue
            
            # Check if this is a read operation on balance-like columns
            is_scan = node.node_type in ("Seq Scan", "Index Scan", "Index Only Scan", "Bitmap Heap Scan")
            has_balance_filter = self._has_balance_filter(node)
            
            # Check if there's a LockRows node protecting this scan
            has_lock = self._has_lock_protection(explain, node)
            
            if is_scan and has_balance_filter and not has_lock:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=Severity.CRITICAL,
                    context=NodeContext(
                        path=NodePath.root(),
                        node_type=node.node_type,
                        relation_name=node.relation_name,
                        actual_rows=node.actual_rows,
                        plan_rows=node.plan_rows,
                        total_cost=node.total_cost,
                        filter=node.filter,
                        depth=0,
                    ),
                    title=f"Race condition risk: {node.relation_name} balance check without lock",
                    description=(
                        f"This query reads from '{node.relation_name}' (likely balance/amount data) "
                        f"without row locking. Concurrent transactions may read the same value "
                        f"before either commits, causing double-spend or overdraft. "
                        f"This is the classic 'check-then-act' race condition."
                    ),
                    suggestion=self._generate_race_fix(node.relation_name),
                    metrics={
                        "rows_at_risk": node.actual_rows or node.plan_rows or 1,
                    },
                ))
                break  # One finding per query
        
        return findings
    
    def _find_financial_tables(
        self,
        explain: "ExplainOutput",
        config: TransactionSafetyConfig
    ) -> list[str]:
        """Find financial tables in plan."""
        financial = []
        for node in explain.all_nodes:
            if node.relation_name:
                table_lower = node.relation_name.lower()
                for fin_table in config.financial_tables:
                    if fin_table in table_lower:
                        financial.append(node.relation_name)
                        break
        return list(set(financial))
    
    def _has_balance_filter(self, node) -> bool:
        """Check if node filters on balance-like columns."""
        filter_str = str(node.filter or "").lower()
        balance_keywords = ["balance", "amount", "quantity", "available", "limit", "credit"]
        return any(kw in filter_str for kw in balance_keywords)
    
    def _has_lock_protection(self, explain: "ExplainOutput", target_node) -> bool:
        """Check if a LockRows node protects the target node."""
        # Simple heuristic: if LockRows appears anywhere, assume it's protecting
        for node in explain.all_nodes:
            if node.node_type == "LockRows":
                return True
        return False
    
    def _generate_race_fix(self, table: str) -> str:
        """Generate race condition fix."""
        return f"""-- FIX: Add row-level locking to prevent race conditions

-- Option 1: SELECT ... FOR UPDATE (blocks concurrent reads)
SELECT balance FROM {table} 
WHERE user_id = $1 
FOR UPDATE;

-- Option 2: FOR UPDATE NOWAIT (fails fast if locked)
SELECT balance FROM {table} 
WHERE user_id = $1 
FOR UPDATE NOWAIT;

-- Option 3: FOR UPDATE SKIP LOCKED (for queue processing)
SELECT * FROM {table} 
WHERE status = 'pending' 
FOR UPDATE SKIP LOCKED 
LIMIT 1;

-- Application pattern:
BEGIN;
  SELECT balance FROM {table} WHERE user_id = ? FOR UPDATE;
  -- Check if balance >= withdrawal_amount
  UPDATE {table} SET balance = balance - ? WHERE user_id = ?;
COMMIT;

-- This prevents the double-spend race condition."""
