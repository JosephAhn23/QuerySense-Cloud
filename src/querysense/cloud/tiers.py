"""
Subscription tier definitions and feature limits.

Implements the four-tier pricing model:
- Community (free): 25 plans/day, no history, no API
- Pro ($29/mo): Unlimited plans, 90-day history, 10K API calls/mo
- Team ($49/user/mo): Unlimited, 1-year history, unlimited API, collaboration
- Enterprise (custom): Unlimited everything, self-hosted option, SSO/RBAC

The cardinal rule: never gate the core detection rules.
All analysis rules work on every tier. We gate volume, persistence,
collaboration, and compliance — not the analytical engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Tier(str, Enum):
    """Subscription tier."""

    COMMUNITY = "community"
    PRO = "pro"
    TEAM = "team"
    ENTERPRISE = "enterprise"


@dataclass(frozen=True)
class TierLimits:
    """Feature limits for a tier."""

    # Analysis
    plans_per_day: int  # 0 = unlimited
    api_calls_per_month: int  # 0 = unlimited

    # Storage
    history_retention_days: int  # 0 = forever
    max_stored_plans: int  # 0 = unlimited

    # Collaboration
    share_links: bool
    team_dashboards: bool
    annotations: bool

    # CI/CD
    ci_basic: bool  # pass/fail
    ci_pr_comments: bool  # PR annotations
    ci_regression_blocking: bool  # block on regression

    # Integrations
    github_actions: bool
    slack_integration: bool
    jira_integration: bool
    pagerduty_integration: bool

    # Enterprise
    sso_saml: bool
    rbac_custom_roles: bool
    audit_logs: bool
    self_hosted: bool
    custom_rules: bool
    dedicated_support: bool

    # Display
    display_name: str
    price_monthly: int | None  # None = custom pricing
    price_annual_monthly: int | None  # per-month when billed annually
    price_label: str


# ── Tier definitions ───────────────────────────────────────────────────

TIER_LIMITS: dict[Tier, TierLimits] = {
    Tier.COMMUNITY: TierLimits(
        plans_per_day=25,
        api_calls_per_month=0,
        history_retention_days=0,
        max_stored_plans=0,
        share_links=False,
        team_dashboards=False,
        annotations=False,
        ci_basic=False,
        ci_pr_comments=False,
        ci_regression_blocking=False,
        github_actions=False,
        slack_integration=False,
        jira_integration=False,
        pagerduty_integration=False,
        sso_saml=False,
        rbac_custom_roles=False,
        audit_logs=False,
        self_hosted=False,
        custom_rules=False,
        dedicated_support=False,
        display_name="Community",
        price_monthly=0,
        price_annual_monthly=0,
        price_label="Free",
    ),
    Tier.PRO: TierLimits(
        plans_per_day=0,  # unlimited
        api_calls_per_month=10_000,
        history_retention_days=90,
        max_stored_plans=1_000,
        share_links=True,
        team_dashboards=False,
        annotations=False,
        ci_basic=True,
        ci_pr_comments=False,
        ci_regression_blocking=False,
        github_actions=True,
        slack_integration=False,
        jira_integration=False,
        pagerduty_integration=False,
        sso_saml=False,
        rbac_custom_roles=False,
        audit_logs=False,
        self_hosted=False,
        custom_rules=False,
        dedicated_support=False,
        display_name="Pro",
        price_monthly=29,
        price_annual_monthly=19,
        price_label="$29/mo",
    ),
    Tier.TEAM: TierLimits(
        plans_per_day=0,  # unlimited
        api_calls_per_month=0,  # unlimited
        history_retention_days=365,
        max_stored_plans=10_000,
        share_links=True,
        team_dashboards=True,
        annotations=True,
        ci_basic=True,
        ci_pr_comments=True,
        ci_regression_blocking=True,
        github_actions=True,
        slack_integration=True,
        jira_integration=True,
        pagerduty_integration=False,
        sso_saml=False,
        rbac_custom_roles=False,
        audit_logs=False,
        self_hosted=False,
        custom_rules=True,
        dedicated_support=False,
        display_name="Team",
        price_monthly=49,
        price_annual_monthly=39,
        price_label="$49/user/mo",
    ),
    Tier.ENTERPRISE: TierLimits(
        plans_per_day=0,
        api_calls_per_month=0,
        history_retention_days=0,  # unlimited
        max_stored_plans=0,  # unlimited
        share_links=True,
        team_dashboards=True,
        annotations=True,
        ci_basic=True,
        ci_pr_comments=True,
        ci_regression_blocking=True,
        github_actions=True,
        slack_integration=True,
        jira_integration=True,
        pagerduty_integration=True,
        sso_saml=True,
        rbac_custom_roles=True,
        audit_logs=True,
        self_hosted=True,
        custom_rules=True,
        dedicated_support=True,
        display_name="Enterprise",
        price_monthly=None,
        price_annual_monthly=None,
        price_label="Custom",
    ),
}


def get_limits(tier: Tier) -> TierLimits:
    """Get feature limits for a tier."""
    return TIER_LIMITS[tier]


def tier_from_string(value: str) -> Tier:
    """Parse tier from string, defaulting to community."""
    try:
        return Tier(value.lower())
    except ValueError:
        return Tier.COMMUNITY
