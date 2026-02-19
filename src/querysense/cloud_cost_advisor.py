"""
Cloud Cost Advisor — RDS vs Aurora vs EKS/CloudNativePG cost comparison.

pganalyze's webinars highlight cost tradeoffs across AWS deployment options,
including the new AWS Database Savings Plans announced at re:Invent.

This module provides:
1. RDS vs Aurora I/O cost comparison
2. Aurora I/O-Optimized vs Standard cost analysis
3. CloudNativePG on EKS cost estimation
4. AWS Database Savings Plans calculator
5. Storage and compute cost breakdown

Usage:
    from querysense.cloud_cost_advisor import CloudCostAdvisor
    advisor = CloudCostAdvisor()
    report = advisor.compare_deployments(
        instance_type="db.r6g.xlarge",
        storage_gb=500,
        iops=5000,
        monthly_io_requests_millions=100,
    )
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ── AWS Pricing Data (us-east-1, as of Feb 2026) ────────────────────────

# These are approximate and should be updated periodically.
# Actual pricing varies by region and can change.

_RDS_PRICING = {
    "db.t3.micro": {"hourly": 0.017, "vcpu": 2, "memory_gb": 1},
    "db.t3.small": {"hourly": 0.034, "vcpu": 2, "memory_gb": 2},
    "db.t3.medium": {"hourly": 0.068, "vcpu": 2, "memory_gb": 4},
    "db.r6g.large": {"hourly": 0.260, "vcpu": 2, "memory_gb": 16},
    "db.r6g.xlarge": {"hourly": 0.520, "vcpu": 4, "memory_gb": 32},
    "db.r6g.2xlarge": {"hourly": 1.040, "vcpu": 8, "memory_gb": 64},
    "db.r6g.4xlarge": {"hourly": 2.080, "vcpu": 16, "memory_gb": 128},
    "db.r6g.8xlarge": {"hourly": 4.160, "vcpu": 32, "memory_gb": 256},
    "db.r6g.12xlarge": {"hourly": 6.240, "vcpu": 48, "memory_gb": 384},
    "db.r6g.16xlarge": {"hourly": 8.320, "vcpu": 64, "memory_gb": 512},
    "db.r7g.large": {"hourly": 0.273, "vcpu": 2, "memory_gb": 16},
    "db.r7g.xlarge": {"hourly": 0.546, "vcpu": 4, "memory_gb": 32},
    "db.r7g.2xlarge": {"hourly": 1.092, "vcpu": 8, "memory_gb": 64},
}

_AURORA_PREMIUM = 0.20  # Aurora compute is ~20% more than RDS

# Storage pricing per GB-month
_RDS_GP3_PER_GB = 0.08
_RDS_IO1_PER_GB = 0.125
_AURORA_STORAGE_PER_GB = 0.10
_AURORA_IO_OPT_STORAGE_PER_GB = 0.225  # I/O-Optimized: 2.25x storage, zero I/O cost

# I/O pricing per million requests
_RDS_GP3_IOPS_FREE = 3000
_RDS_GP3_IOPS_COST = 0.08  # per 1000 IOPS provisioned/month beyond free tier
_AURORA_IO_PER_MILLION = 0.20  # Standard: $0.20 per million I/O requests
_AURORA_IO_OPT_IO_COST = 0.0  # I/O-Optimized: $0 per I/O

# EKS pricing
_EKS_CLUSTER_HOURLY = 0.10  # $0.10/hr per cluster
_EC2_ON_DEMAND = {
    "r6g.large": 0.1008,
    "r6g.xlarge": 0.2016,
    "r6g.2xlarge": 0.4032,
    "r7g.large": 0.1071,
    "r7g.xlarge": 0.2142,
}

# Savings Plans discount
_SAVINGS_PLAN_1YR_DISCOUNT = 0.34  # ~34% off on-demand
_SAVINGS_PLAN_3YR_DISCOUNT = 0.56  # ~56% off on-demand


@dataclass
class DeploymentCost:
    """Monthly cost breakdown for a deployment option."""
    deployment: str  # rds, aurora_standard, aurora_io_optimized, eks_cnpg
    compute_monthly: float = 0
    storage_monthly: float = 0
    io_monthly: float = 0
    other_monthly: float = 0  # EKS cluster fee, backups, etc.
    total_monthly: float = 0
    total_annual: float = 0
    savings_plan_annual: float = 0  # With 1-year savings plan
    notes: list[str] = field(default_factory=list)
    instance_type: str = ""
    vcpu: int = 0
    memory_gb: int = 0


@dataclass
class CostComparisonReport:
    """Full cost comparison across deployment options."""
    deployments: list[DeploymentCost] = field(default_factory=list)
    cheapest: str = ""
    cheapest_monthly: float = 0
    recommendation: str = ""
    io_analysis: dict[str, Any] = field(default_factory=dict)
    aurora_io_breakeven: float = 0  # Millions of I/O requests where IO-Opt breaks even

    def to_dict(self) -> dict[str, Any]:
        return {
            "deployments": [
                {"deployment": d.deployment, "monthly": d.total_monthly,
                 "annual": d.total_annual, "savings_plan": d.savings_plan_annual}
                for d in self.deployments
            ],
            "cheapest": self.cheapest,
            "cheapest_monthly": self.cheapest_monthly,
            "recommendation": self.recommendation,
            "aurora_io_breakeven_millions": self.aurora_io_breakeven,
        }


class CloudCostAdvisor:
    """
    Compare cloud deployment costs for PostgreSQL.

    Supports:
    - RDS PostgreSQL (gp3 storage)
    - Aurora PostgreSQL (Standard I/O)
    - Aurora PostgreSQL (I/O-Optimized)
    - CloudNativePG on EKS
    """

    def compare_deployments(
        self,
        instance_type: str = "db.r6g.xlarge",
        storage_gb: int = 500,
        iops: int = 3000,
        monthly_io_requests_millions: float = 100,
        replicas: int = 0,
        multi_az: bool = True,
        region: str = "us-east-1",
    ) -> CostComparisonReport:
        """
        Compare monthly costs across deployment options.

        Args:
            instance_type: RDS/Aurora instance type (e.g., "db.r6g.xlarge")
            storage_gb: Total storage in GB
            iops: Provisioned IOPS (for gp3)
            monthly_io_requests_millions: Estimated monthly I/O requests
            replicas: Number of read replicas
            multi_az: Whether to use Multi-AZ (doubles compute for RDS)
        """
        report = CostComparisonReport()

        # 1. RDS PostgreSQL
        rds = self._calc_rds(
            instance_type, storage_gb, iops,
            multi_az, replicas,
        )
        report.deployments.append(rds)

        # 2. Aurora Standard
        aurora_std = self._calc_aurora_standard(
            instance_type, storage_gb,
            monthly_io_requests_millions, replicas,
        )
        report.deployments.append(aurora_std)

        # 3. Aurora I/O-Optimized
        aurora_io = self._calc_aurora_io_optimized(
            instance_type, storage_gb, replicas,
        )
        report.deployments.append(aurora_io)

        # 4. CloudNativePG on EKS
        eks = self._calc_eks_cnpg(
            instance_type, storage_gb, replicas,
        )
        report.deployments.append(eks)

        # Find cheapest
        cheapest = min(report.deployments, key=lambda d: d.total_monthly)
        report.cheapest = cheapest.deployment
        report.cheapest_monthly = cheapest.total_monthly

        # Aurora I/O breakeven
        report.aurora_io_breakeven = self._calc_aurora_io_breakeven(
            instance_type, storage_gb,
        )

        # I/O analysis
        report.io_analysis = {
            "monthly_io_millions": monthly_io_requests_millions,
            "aurora_io_cost": monthly_io_requests_millions * _AURORA_IO_PER_MILLION,
            "aurora_io_optimized_premium": (
                (_AURORA_IO_OPT_STORAGE_PER_GB - _AURORA_STORAGE_PER_GB) * storage_gb
            ),
            "breakeven_millions": report.aurora_io_breakeven,
            "recommendation": (
                "Use Aurora I/O-Optimized"
                if monthly_io_requests_millions > report.aurora_io_breakeven
                else "Use Aurora Standard"
            ),
        }

        # Recommendation
        report.recommendation = self._generate_recommendation(
            report, monthly_io_requests_millions,
        )

        return report

    def savings_plan_calculator(
        self,
        current_monthly: float,
        term_years: int = 1,
    ) -> dict[str, Any]:
        """
        Calculate savings from AWS Database Savings Plans.

        Args:
            current_monthly: Current monthly on-demand spend
            term_years: 1 or 3 year commitment
        """
        discount = (
            _SAVINGS_PLAN_1YR_DISCOUNT if term_years == 1
            else _SAVINGS_PLAN_3YR_DISCOUNT
        )
        savings_monthly = current_monthly * discount
        new_monthly = current_monthly - savings_monthly

        return {
            "current_monthly": current_monthly,
            "current_annual": current_monthly * 12,
            "with_savings_plan_monthly": new_monthly,
            "with_savings_plan_annual": new_monthly * 12,
            "savings_monthly": savings_monthly,
            "savings_annual": savings_monthly * 12,
            "discount_pct": discount * 100,
            "term_years": term_years,
            "total_commitment": new_monthly * 12 * term_years,
        }

    # ── Internal calculators ─────────────────────────────────────────

    def _calc_rds(
        self, instance_type: str, storage_gb: int,
        iops: int, multi_az: bool, replicas: int,
    ) -> DeploymentCost:
        pricing = _RDS_PRICING.get(instance_type, _RDS_PRICING["db.r6g.xlarge"])
        hours = 730  # avg hours per month

        instances = 1 + replicas
        if multi_az:
            instances *= 2  # Multi-AZ doubles primary

        compute = pricing["hourly"] * hours * instances
        storage = _RDS_GP3_PER_GB * storage_gb

        # IOPS cost (gp3 includes 3000 IOPS free)
        extra_iops = max(0, iops - _RDS_GP3_IOPS_FREE)
        io_cost = extra_iops * _RDS_GP3_IOPS_COST

        total = compute + storage + io_cost

        cost = DeploymentCost(
            deployment="rds",
            compute_monthly=round(compute, 2),
            storage_monthly=round(storage, 2),
            io_monthly=round(io_cost, 2),
            total_monthly=round(total, 2),
            total_annual=round(total * 12, 2),
            savings_plan_annual=round(total * 12 * (1 - _SAVINGS_PLAN_1YR_DISCOUNT), 2),
            instance_type=instance_type,
            vcpu=pricing["vcpu"],
            memory_gb=pricing["memory_gb"],
        )

        if multi_az:
            cost.notes.append("Multi-AZ: compute cost doubled for standby")
        if replicas:
            cost.notes.append(f"{replicas} read replica(s) included")

        return cost

    def _calc_aurora_standard(
        self, instance_type: str, storage_gb: int,
        io_millions: float, replicas: int,
    ) -> DeploymentCost:
        pricing = _RDS_PRICING.get(instance_type, _RDS_PRICING["db.r6g.xlarge"])
        hours = 730

        # Aurora pricing is ~20% more for compute
        hourly = pricing["hourly"] * (1 + _AURORA_PREMIUM)
        instances = 1 + replicas
        compute = hourly * hours * instances

        storage = _AURORA_STORAGE_PER_GB * storage_gb
        io_cost = io_millions * _AURORA_IO_PER_MILLION

        total = compute + storage + io_cost

        cost = DeploymentCost(
            deployment="aurora_standard",
            compute_monthly=round(compute, 2),
            storage_monthly=round(storage, 2),
            io_monthly=round(io_cost, 2),
            total_monthly=round(total, 2),
            total_annual=round(total * 12, 2),
            savings_plan_annual=round(total * 12 * (1 - _SAVINGS_PLAN_1YR_DISCOUNT), 2),
            instance_type=instance_type,
            vcpu=pricing["vcpu"],
            memory_gb=pricing["memory_gb"],
        )

        cost.notes.append("Aurora: Multi-AZ included by default")
        cost.notes.append(f"I/O: {io_millions}M requests @ ${_AURORA_IO_PER_MILLION}/M")
        if replicas:
            cost.notes.append(f"{replicas} Aurora replica(s)")

        return cost

    def _calc_aurora_io_optimized(
        self, instance_type: str, storage_gb: int, replicas: int,
    ) -> DeploymentCost:
        pricing = _RDS_PRICING.get(instance_type, _RDS_PRICING["db.r6g.xlarge"])
        hours = 730

        # Aurora I/O-Optimized: ~30% compute premium over standard Aurora
        hourly = pricing["hourly"] * (1 + _AURORA_PREMIUM) * 1.30
        instances = 1 + replicas
        compute = hourly * hours * instances

        storage = _AURORA_IO_OPT_STORAGE_PER_GB * storage_gb
        io_cost = 0  # Zero I/O cost — that's the point

        total = compute + storage + io_cost

        cost = DeploymentCost(
            deployment="aurora_io_optimized",
            compute_monthly=round(compute, 2),
            storage_monthly=round(storage, 2),
            io_monthly=0,
            total_monthly=round(total, 2),
            total_annual=round(total * 12, 2),
            savings_plan_annual=round(total * 12 * (1 - _SAVINGS_PLAN_1YR_DISCOUNT), 2),
            instance_type=instance_type,
            vcpu=pricing["vcpu"],
            memory_gb=pricing["memory_gb"],
        )

        cost.notes.append("Zero I/O cost — all I/O included in storage price")
        cost.notes.append("Best for I/O-heavy workloads (OLTP, high-write)")
        cost.notes.append("2.25x storage cost vs Aurora Standard")

        return cost

    def _calc_eks_cnpg(
        self, instance_type: str, storage_gb: int, replicas: int,
    ) -> DeploymentCost:
        # Map db.* to EC2 equivalent
        ec2_type = instance_type.replace("db.", "")
        ec2_pricing = _EC2_ON_DEMAND.get(ec2_type)

        if not ec2_pricing:
            # Estimate from RDS pricing (EC2 is typically 30-40% cheaper)
            rds_pricing = _RDS_PRICING.get(instance_type, _RDS_PRICING["db.r6g.xlarge"])
            ec2_pricing = rds_pricing["hourly"] * 0.65

        hours = 730
        instances = 1 + replicas + 1  # +1 for standby

        compute = ec2_pricing * hours * instances
        storage = 0.08 * storage_gb * instances  # EBS gp3 per node
        eks_fee = _EKS_CLUSTER_HOURLY * hours  # Cluster management fee

        total = compute + storage + eks_fee

        rds_pricing_data = _RDS_PRICING.get(instance_type, _RDS_PRICING["db.r6g.xlarge"])

        cost = DeploymentCost(
            deployment="eks_cnpg",
            compute_monthly=round(compute, 2),
            storage_monthly=round(storage, 2),
            io_monthly=0,
            other_monthly=round(eks_fee, 2),
            total_monthly=round(total, 2),
            total_annual=round(total * 12, 2),
            savings_plan_annual=round(total * 12 * (1 - _SAVINGS_PLAN_1YR_DISCOUNT), 2),
            instance_type=ec2_type,
            vcpu=rds_pricing_data["vcpu"],
            memory_gb=rds_pricing_data["memory_gb"],
        )

        cost.notes.append("CloudNativePG on EKS: full Postgres control")
        cost.notes.append("Requires Kubernetes expertise")
        cost.notes.append(f"EKS cluster fee: ${eks_fee:.2f}/mo")
        cost.notes.append("Backup, monitoring, HA are your responsibility")

        return cost

    def _calc_aurora_io_breakeven(
        self, instance_type: str, storage_gb: int,
    ) -> float:
        """
        Calculate the I/O request volume where Aurora I/O-Optimized
        becomes cheaper than Aurora Standard.
        """
        # Extra storage cost for I/O-Optimized
        storage_premium = (
            _AURORA_IO_OPT_STORAGE_PER_GB - _AURORA_STORAGE_PER_GB
        ) * storage_gb

        # Extra compute cost for I/O-Optimized (~30% more)
        pricing = _RDS_PRICING.get(instance_type, _RDS_PRICING["db.r6g.xlarge"])
        compute_premium = (
            pricing["hourly"] * (1 + _AURORA_PREMIUM) * 0.30 * 730
        )

        total_premium = storage_premium + compute_premium

        # Breakeven: premium = io_millions * AURORA_IO_PER_MILLION
        if _AURORA_IO_PER_MILLION > 0:
            return round(total_premium / _AURORA_IO_PER_MILLION, 1)
        return 0

    def _generate_recommendation(
        self, report: CostComparisonReport,
        io_millions: float,
    ) -> str:
        costs = {d.deployment: d.total_monthly for d in report.deployments}
        cheapest = report.cheapest

        if cheapest == "eks_cnpg":
            return (
                "CloudNativePG on EKS is cheapest but requires Kubernetes expertise. "
                "Choose this if your team has K8s experience and you need full Postgres "
                "control (extensions, custom configs, PG18 features)."
            )
        elif cheapest == "aurora_io_optimized":
            return (
                f"Aurora I/O-Optimized is cheapest at your I/O level ({io_millions}M "
                f"requests/mo). The zero I/O cost outweighs the storage premium. "
                f"Breakeven is {report.aurora_io_breakeven}M I/O requests/mo."
            )
        elif cheapest == "aurora_standard":
            return (
                f"Aurora Standard is cheapest at your I/O level ({io_millions}M "
                f"requests/mo). Switch to I/O-Optimized if I/O exceeds "
                f"{report.aurora_io_breakeven}M requests/mo."
            )
        else:
            return (
                "RDS PostgreSQL is cheapest. Consider Aurora if you need automatic "
                "failover, up to 15 read replicas, or distributed storage."
            )
