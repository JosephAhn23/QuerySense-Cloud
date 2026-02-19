"""
Cost comparison engine — shows what competitors would charge.

This is QuerySense's "Free Forever" moat:
Make the cost savings visceral, shareable, and undeniable.

Usage:
    from querysense.cost_compare import calculate_savings, format_report

    savings = calculate_savings(hosts=5, queries_per_day=50_000)
    print(format_report(savings))

CLI:
    querysense cost-compare --hosts 5 --queries 50000
    querysense cost-compare --hosts 5 --queries 50000 --social
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

# ── Competitor pricing models (public, as of 2026) ─────────────────

@dataclass(frozen=True)
class CompetitorPricing:
    """Pricing model for a single competitor."""
    name: str
    description: str
    base_per_host_month: float           # $/host/month
    additional_query_cost: float = 0.0   # per 1M queries
    minimum_monthly: float = 0.0         # minimum charge
    free_tier_hosts: int = 0
    free_tier_queries: int = 0
    notes: str = ""

    def monthly_cost(self, hosts: int, queries_per_day: int) -> float:
        """Calculate monthly cost for given workload."""
        monthly_queries = queries_per_day * 30

        billable_hosts = max(0, hosts - self.free_tier_hosts)
        host_cost = billable_hosts * self.base_per_host_month

        billable_queries = max(0, monthly_queries - self.free_tier_queries)
        query_cost = (billable_queries / 1_000_000) * self.additional_query_cost

        return max(host_cost + query_cost, self.minimum_monthly if hosts > 0 else 0)


# Pricing based on public pricing pages / user reports
COMPETITORS: list[CompetitorPricing] = [
    CompetitorPricing(
        name="Datadog Database Monitoring",
        description="APM + DBM bundle",
        base_per_host_month=70.0,
        additional_query_cost=0.0,
        notes="$70/host/mo for DBM. APM extra. Custom metrics add up fast.",
    ),
    CompetitorPricing(
        name="pganalyze",
        description="PostgreSQL performance monitoring SaaS",
        base_per_host_month=149.0,  # Scale plan starts at $749 for 5 servers
        free_tier_hosts=0,
        notes="Starts $149/server/mo on Scale plan. Enterprise plan required for teams.",
    ),
    CompetitorPricing(
        name="EverSQL",
        description="AI-powered SQL optimization",
        base_per_host_month=0.0,
        additional_query_cost=50.0,  # Based on query packs
        minimum_monthly=29.0,
        notes="$29/mo starter, $99/mo pro. Limited queries per month. No offline mode.",
    ),
    CompetitorPricing(
        name="Percona PMM (Enterprise)",
        description="Enterprise monitoring with support",
        base_per_host_month=75.0,
        notes="Free OSS version available, but Enterprise support/features extra.",
    ),
    CompetitorPricing(
        name="Harness Database DevOps",
        description="Enterprise CI/CD with database management",
        base_per_host_month=0.0,
        minimum_monthly=499.0,  # Team plan minimum
        notes="Developer plan free for 1 module. Team starts $499/mo. Enterprise custom.",
    ),
    CompetitorPricing(
        name="Liquibase Pro",
        description="Database change management",
        base_per_host_month=0.0,
        minimum_monthly=175.0,
        notes="$175/mo Pro. Rollbacks and policy checks paywalled. Free tier gutted.",
    ),
]


@dataclass
class CompetitorSavings:
    """Savings vs one competitor."""
    competitor: str
    monthly_cost: float
    annual_cost: float
    monthly_savings: float
    annual_savings: float
    notes: str


@dataclass
class SavingsReport:
    """Full cost comparison report."""
    hosts: int
    queries_per_day: int
    months_using: int
    competitors: list[CompetitorSavings]
    total_max_annual_savings: float
    total_avg_annual_savings: float
    querysense_cost: float = 0.0  # Always $0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "workload": {
                "hosts": self.hosts,
                "queries_per_day": self.queries_per_day,
                "months_using_querysense": self.months_using,
            },
            "querysense_cost": self.querysense_cost,
            "competitors": [
                {
                    "name": c.competitor,
                    "monthly_cost": round(c.monthly_cost, 2),
                    "annual_cost": round(c.annual_cost, 2),
                    "monthly_savings": round(c.monthly_savings, 2),
                    "annual_savings": round(c.annual_savings, 2),
                    "notes": c.notes,
                }
                for c in self.competitors
            ],
            "total_max_annual_savings": round(self.total_max_annual_savings, 2),
            "total_avg_annual_savings": round(self.total_avg_annual_savings, 2),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def calculate_savings(
    hosts: int = 5,
    queries_per_day: int = 50_000,
    months_using: int = 12,
) -> SavingsReport:
    """
    Calculate cost savings vs all competitors.

    Args:
        hosts: Number of database hosts
        queries_per_day: Average queries per day
        months_using: Months you've been using QuerySense (for cumulative)

    Returns:
        SavingsReport with per-competitor breakdown
    """
    savings_list: list[CompetitorSavings] = []

    for comp in COMPETITORS:
        monthly = comp.monthly_cost(hosts, queries_per_day)
        annual = monthly * 12
        savings_list.append(CompetitorSavings(
            competitor=comp.name,
            monthly_cost=monthly,
            annual_cost=annual,
            monthly_savings=monthly,  # QuerySense is $0
            annual_savings=annual,
            notes=comp.notes,
        ))

    max_annual = max(s.annual_savings for s in savings_list) if savings_list else 0
    avg_annual = (
        sum(s.annual_savings for s in savings_list) / len(savings_list)
        if savings_list else 0
    )

    return SavingsReport(
        hosts=hosts,
        queries_per_day=queries_per_day,
        months_using=months_using,
        competitors=savings_list,
        total_max_annual_savings=max_annual,
        total_avg_annual_savings=avg_annual,
    )


def format_report(report: SavingsReport, social: bool = False) -> str:
    """
    Format savings report for terminal display.

    Args:
        report: SavingsReport to format
        social: If True, include shareable summary for social media

    Returns:
        Formatted string
    """
    lines: list[str] = []

    lines.append("")
    lines.append("  WHAT COMPETITORS WOULD CHARGE YOU")
    lines.append("  " + "=" * 50)
    lines.append("")
    lines.append(f"  Your workload: {report.queries_per_day:,} queries/day")
    lines.append(f"  Database hosts: {report.hosts}")
    lines.append("")
    lines.append("  " + "-" * 50)

    # Sort by annual cost (most expensive first)
    sorted_comps = sorted(report.competitors, key=lambda c: -c.annual_cost)

    for comp in sorted_comps:
        if comp.monthly_cost > 0:
            lines.append(f"  {comp.competitor}")
            lines.append(f"    Monthly: ${comp.monthly_cost:,.0f}/mo")
            lines.append(f"    Annual:  ${comp.annual_cost:,.0f}/yr")
            if comp.notes:
                lines.append(f"    Note:    {comp.notes}")
            lines.append("")

    lines.append("  " + "-" * 50)
    lines.append(f"  QuerySense cost:     $0/mo (free forever)")
    lines.append("")
    lines.append(f"  Maximum annual savings: ${report.total_max_annual_savings:,.0f}")
    lines.append(f"  Average annual savings: ${report.total_avg_annual_savings:,.0f}")

    if report.months_using > 0:
        cumulative = report.total_avg_annual_savings * (report.months_using / 12)
        lines.append(f"  You've saved ~${cumulative:,.0f} over {report.months_using} months")

    lines.append("")

    if social:
        lines.append("  " + "=" * 50)
        lines.append("  SHARE THIS:")
        lines.append("")
        max_comp = sorted_comps[0] if sorted_comps else None
        if max_comp:
            lines.append(f'  "Switched from {max_comp.competitor} to QuerySense.')
            lines.append(f'   Saving ${max_comp.annual_savings:,.0f}/year.')
            lines.append(f'   Same features. Zero cost. #QuerySense #OpenSource"')
        lines.append("")

    return "\n".join(lines)


def format_report_markdown(report: SavingsReport) -> str:
    """Format savings report as markdown (for docs/sharing)."""
    lines: list[str] = []

    lines.append(f"# QuerySense Cost Comparison")
    lines.append("")
    lines.append(f"**Workload**: {report.queries_per_day:,} queries/day, {report.hosts} hosts")
    lines.append("")
    lines.append("| Competitor | Monthly | Annual | Annual Savings |")
    lines.append("|------------|---------|--------|----------------|")

    for comp in sorted(report.competitors, key=lambda c: -c.annual_cost):
        lines.append(
            f"| {comp.competitor} | ${comp.monthly_cost:,.0f} | "
            f"${comp.annual_cost:,.0f} | **${comp.annual_savings:,.0f}** |"
        )

    lines.append(f"| **QuerySense** | **$0** | **$0** | — |")
    lines.append("")
    lines.append(f"**Maximum annual savings: ${report.total_max_annual_savings:,.0f}**")

    return "\n".join(lines)
