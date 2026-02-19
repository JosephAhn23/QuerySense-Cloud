"""
QuerySense CLI - PostgreSQL query performance analyzer.

Thin entry point that wires up Typer apps and delegates
to command modules. All business logic lives in AnalysisService;
all rendering logic lives in querysense.output.

Usage:
    querysense analyze explain.json
    querysense fix explain.json
    querysense rules
    querysense ci analyze plans/**/*.json
    querysense ci baseline update plans/**/*.json
"""

from __future__ import annotations

from typing import Annotated, Optional

import typer
from rich.console import Console

from querysense import __version__

# ── Typer app hierarchy ──────────────────────────────────────────────────

app = typer.Typer(
    name="querysense",
    help="PostgreSQL query performance analyzer",
    no_args_is_help=True,
)

ci_app = typer.Typer(
    name="ci",
    help="CI/CD integration commands for pipeline gating",
    no_args_is_help=True,
)

baseline_app = typer.Typer(
    name="baseline",
    help="Manage plan baselines for regression detection",
    no_args_is_help=True,
)

policy_app = typer.Typer(
    name="policy",
    help="Manage query performance policies for enforcement",
    no_args_is_help=True,
)

upgrade_app = typer.Typer(
    name="upgrade",
    help="Post-upgrade plan validation commands",
    no_args_is_help=True,
)

upgrade_check_app = typer.Typer(
    name="upgrade-check",
    help="Post-upgrade plan validation checks (alias for upgrade)",
    no_args_is_help=True,
)

compliance_app = typer.Typer(
    name="compliance",
    help="Compliance enforcement and audit commands",
    no_args_is_help=True,
)

history_app = typer.Typer(
    name="history",
    help="Track plan performance over time (like pganalyze, but offline)",
    no_args_is_help=True,
)

profile_app = typer.Typer(
    name="profile",
    help="Manage performance profiles (git diff for database performance)",
    no_args_is_help=True,
)

simulate_app = typer.Typer(
    name="simulate",
    help="Test index recommendations without committing",
    no_args_is_help=True,
)

schema_app = typer.Typer(
    name="schema",
    help="Schema drift detection and comparison",
    no_args_is_help=True,
)

rollback_app = typer.Typer(
    name="rollback",
    help="Intelligent rollback generation with dependency tracking (beats Liquibase/Flyway)",
    no_args_is_help=True,
)

pr_app = typer.Typer(
    name="pr",
    help="GitOps PR integration: auto-review migrations and create fix PRs",
    no_args_is_help=True,
)

metrics_app = typer.Typer(
    name="metrics",
    help="Export metrics to Prometheus/Grafana (what Datadog charges $70/host for)",
    no_args_is_help=True,
)

budget_app = typer.Typer(
    name="budget",
    help="Performance budgets as code — enforce in CI (free Harness alternative)",
    no_args_is_help=True,
)

mysql_app = typer.Typer(
    name="mysql",
    help="MySQL/MariaDB analysis commands (production-ready)",
    no_args_is_help=True,
)

audit_app = typer.Typer(
    name="audit",
    help="Audit PostgreSQL config and schema design (Dombrovskaya Ch. 9-10)",
    no_args_is_help=True,
)

growth_app = typer.Typer(
    name="growth",
    help="Track table growth over time — size trends, bloat, capacity projections (beats pganalyze)",
    no_args_is_help=True,
)

index_app = typer.Typer(
    name="index",
    help="Constraint programming index advisor (pganalyze-grade CP-SAT optimization)",
    no_args_is_help=True,
)

cluster_app = typer.Typer(
    name="cluster",
    help="Cluster-aware index advisor — primary + replicas analyzed together (pganalyze Feb 2026 parity)",
    no_args_is_help=True,
)

advisor_app = typer.Typer(
    name="advisor",
    help="YAML-based advisor framework — configurable checks with intervals and severity (Percona PMM parity)",
    no_args_is_help=True,
)

patroni_app = typer.Typer(
    name="patroni",
    help="Patroni HA cluster monitoring — status, health, failover history",
    no_args_is_help=True,
)

mongodb_app = typer.Typer(
    name="mongodb",
    help="MongoDB query optimizer — indexes, schema, slow queries (first open-source MongoDB optimizer)",
    no_args_is_help=True,
)

sqlserver_app = typer.Typer(
    name="sqlserver",
    help="SQL Server analysis — execution plans, DMV queries, missing indexes, wait stats",
    no_args_is_help=True,
)

ai_app = typer.Typer(
    name="ai",
    help="AI-powered query explanations — works offline or with Ollama/OpenAI/Claude",
    no_args_is_help=True,
)

pg18_app = typer.Typer(
    name="pg18",
    help="PostgreSQL 18 readiness — Async I/O, Skip Scan, UUIDv7, VACUUM enhancements",
    no_args_is_help=True,
)

plans_app = typer.Typer(
    name="plans",
    help="Plan-level metrics tracking — pg_stat_plans integration, plan change detection",
    no_args_is_help=True,
)

cloud_cost_app = typer.Typer(
    name="cloud-cost",
    help="AWS cloud cost advisor — RDS vs Aurora vs EKS cost comparison, Savings Plans",
    no_args_is_help=True,
)

query_advisor_app = typer.Typer(
    name="query-advisor",
    help="Automatic slow query detection and rewrite suggestions (pganalyze Query Advisor parity)",
    no_args_is_help=True,
)

workbook_app = typer.Typer(
    name="workbook",
    help="Interactive Query Tuning Workbook — persistent, multi-step optimization (beats pganalyze Workbooks)",
    no_args_is_help=True,
)

planner_app = typer.Typer(
    name="planner",
    help="Planner analysis — Incremental Sort detection, plan statistics, buffer cache monitoring",
    no_args_is_help=True,
)

app.add_typer(ci_app, name="ci")
app.add_typer(baseline_app, name="baseline")
app.add_typer(history_app, name="history")
app.add_typer(profile_app, name="profile")
app.add_typer(schema_app, name="schema")
app.add_typer(simulate_app, name="simulate")
app.add_typer(upgrade_app, name="upgrade")
app.add_typer(compliance_app, name="compliance")
app.add_typer(policy_app, name="policy")
app.add_typer(upgrade_check_app, name="upgrade-check")
app.add_typer(mysql_app, name="mysql")
app.add_typer(budget_app, name="budget")
app.add_typer(rollback_app, name="rollback")
app.add_typer(pr_app, name="pr")
app.add_typer(metrics_app, name="metrics")
app.add_typer(audit_app, name="audit")
app.add_typer(growth_app, name="growth")
app.add_typer(index_app, name="index")
app.add_typer(cluster_app, name="cluster")
app.add_typer(advisor_app, name="advisor")
app.add_typer(patroni_app, name="patroni")
app.add_typer(mongodb_app, name="mongodb")
app.add_typer(sqlserver_app, name="sqlserver")
app.add_typer(ai_app, name="ai")
app.add_typer(pg18_app, name="pg18")
app.add_typer(plans_app, name="plans")
app.add_typer(cloud_cost_app, name="cloud-cost")
app.add_typer(query_advisor_app, name="query-advisor")
app.add_typer(workbook_app, name="workbook")
app.add_typer(planner_app, name="planner")

console = Console()

# ── Register command modules ──────────────────────────────────────────────

from querysense.cli.commands.analyze import register as register_analyze
from querysense.cli.commands.baseline import register as register_baseline
from querysense.cli.commands.check import register as register_check
from querysense.cli.commands.ci import register as register_ci
from querysense.cli.commands.init import register as register_init
from querysense.cli.commands.compliance import register as register_compliance
from querysense.cli.commands.diff import register as register_diff
from querysense.cli.commands.history import register as register_history
from querysense.cli.commands.policy import register as register_policy
from querysense.cli.commands.probe import register as register_probe
from querysense.cli.commands.upgrade import register as register_upgrade
from querysense.cli.commands.scan import register as register_scan
from querysense.cli.commands.verify import register as register_verify
from querysense.cli.commands.watch import register as register_watch
from querysense.cli.commands.watch_files import register as register_watch_files
from querysense.cli.commands.web import register as register_web
from querysense.cli.commands.ir import register as register_ir
from querysense.cli.commands.rewrite import register as register_rewrite
from querysense.cli.commands.profile import register as register_profile
from querysense.cli.commands.profile import register_check as register_profile_check
from querysense.cli.commands.simulate import register as register_simulate
from querysense.cli.commands.workload_cmd import register as register_workload
from querysense.cli.commands.predict import register as register_predict
from querysense.cli.commands.migrate import register as register_migrate
from querysense.cli.commands.schema_cmd import register as register_schema
from querysense.cli.commands.comment_pr import register as register_comment_pr
from querysense.cli.commands.graph import register as register_graph
from querysense.cli.commands.infra import register as register_infra
from querysense.cli.commands.migrate_check import register as register_migrate_check
from querysense.cli.commands.health import register as register_health
from querysense.cli.commands.rollback import register as register_rollback
from querysense.cli.commands.pr_review import register as register_pr
from querysense.cli.commands.metrics import register as register_metrics
from querysense.cli.commands.cost_compare import register as register_cost_compare
from querysense.cli.commands.budget import register as register_budget
from querysense.cli.commands.import_cmd import register as register_import
from querysense.cli.commands.audit import register as register_audit
from querysense.cli.commands.wizard_cmd import register as register_wizard
from querysense.cli.commands.orm import register as register_orm
from querysense.cli.commands.mysql import register as register_mysql
from querysense.cli.commands.coach_cmd import register as register_coach
from querysense.cli.commands.workload_dynamic import register as register_workload_advisor
from querysense.cli.commands.migration_plan import register as register_migration_plan
from querysense.cli.commands.bench import register as register_bench
from querysense.cli.commands.learn import register as register_learn
from querysense.cli.commands.zero_downtime import register as register_zero_downtime
from querysense.cli.commands.audit_log import register as register_audit_log
from querysense.cli.commands.tune import register as register_tune
from querysense.cli.commands.locks import register as register_locks
from querysense.cli.commands.growth import register as register_growth
from querysense.cli.commands.partitions import register as register_partitions
from querysense.cli.commands.optimize import register as register_optimize
from querysense.cli.commands.index_cmd import register as register_index, register_extra as register_index_extra
from querysense.cli.commands.pganalyze_parity import (
    register_audit_extras,
    register_index_advise,
    register_scan_workload,
)
from querysense.cli.commands.cluster_cmd import register as register_cluster
from querysense.cli.commands.advisor_cmd import (
    register_advisor,
    register_log_parser,
    register_patroni,
)
from querysense.cli.commands.mongodb_cmd import register as register_mongodb
from querysense.cli.commands.pg18_cmd import (
    register_pg18,
    register_plans,
    register_cloud_cost,
    register_query_advisor,
)
from querysense.cli.commands.sqlserver_cmd import register as register_sqlserver
from querysense.cli.commands.ai_cmd import register as register_ai
from querysense.cli.commands.predictive_cmd import register as register_predictive
from querysense.cli.commands.pganalyze_deep import register as register_pganalyze_deep
from querysense.cli.commands.pganalyze_deep import register_protocol as register_protocol_cmds
from querysense.cli.commands.validate import register as register_validate
from querysense.cli.commands.collector_cmd import (
    register_collect,
    register_monitor,
    register_vacuum_history,
)
from querysense.cli.commands.search_cmd import register as register_search
from querysense.cli.commands.workbook_cmd import register as register_workbook
from querysense.cli.commands.rds_cmd import register as register_rds
from querysense.cli.commands.index_advanced_cmd import register as register_index_advanced
from querysense.cli.commands.planner_cmd import (
    register_sort as register_planner_sort,
    register_plan_collector as register_planner_plans,
    register_buffer_cache as register_planner_cache,
)
from querysense.cli.commands.benchmark_cmd import register as register_benchmark
from querysense.cli.commands.tuning_cmd import (
    register_workbook_extras,
    register_hint_translator,
)
from querysense.cli.commands.roadmap_cmd import (
    register_pg18_async_io,
    register_uuid_audit,
    register_pool_tuner,
    register_checkpoint_predict,
)

register_analyze(app)
register_check(app)
register_ci(ci_app)
register_init(app)
register_baseline(baseline_app)
register_diff(app)
register_history(history_app)
register_policy(policy_app)
register_profile(profile_app)
register_profile_check(profile_app)
register_probe(app)
register_simulate(simulate_app)
register_upgrade(upgrade_app)
register_upgrade(upgrade_check_app)
register_compliance(compliance_app)
register_scan(app)
register_verify(app)
register_watch(app)
register_watch_files(app)
register_web(app)
register_ir(app)
register_rewrite(app)
register_workload(app)
register_predict(app)
register_migrate(app)
register_schema(schema_app)
register_comment_pr(app)
register_graph(app)
register_infra(app)
register_migrate_check(app)
register_health(app)
register_rollback(rollback_app)
register_pr(pr_app)
register_metrics(metrics_app)
register_cost_compare(app)
register_budget(budget_app)
register_import(app)
register_audit(audit_app)
register_wizard(app)
register_orm(app)
register_mysql(mysql_app)
register_coach(app)
register_workload_advisor(app)
register_migration_plan(app)
register_bench(app)
register_learn(app)
register_zero_downtime(app)
register_audit_log(audit_app)
register_locks(app)
register_growth(growth_app)
register_partitions(audit_app)
register_optimize(app)
register_index(index_app)
register_index_extra(index_app)
register_audit_extras(audit_app)
register_index_advise(index_app)
register_scan_workload(app)
register_cluster(cluster_app)
register_advisor(advisor_app)
register_log_parser(app)
register_patroni(patroni_app)
register_predictive(app)
register_pganalyze_deep(app)
register_protocol_cmds(app)
register_tune(app)
register_validate(app)
register_collect(app)
register_monitor(app)
register_vacuum_history(app)
register_search(app)
register_mongodb(mongodb_app)
register_sqlserver(sqlserver_app)
register_ai(ai_app)
register_pg18(pg18_app)
register_plans(plans_app)
register_cloud_cost(cloud_cost_app)
register_query_advisor(query_advisor_app)

register_index_advanced(index_app)
register_planner_sort(planner_app)
register_planner_plans(planner_app)
register_planner_cache(planner_app)

from querysense.cli.commands.vacuum_cmd import register_vacuum as register_vacuum_commands
register_vacuum_commands(app)

register_benchmark(app)
register_workbook(workbook_app)
register_rds(app)
register_workbook_extras(workbook_app)
register_hint_translator(app)

register_pg18_async_io(pg18_app)
register_uuid_audit(audit_app)
register_pool_tuner(audit_app)
register_checkpoint_predict(audit_app)


# ── Version callback ──────────────────────────────────────────────────────


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"QuerySense version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-v",
            help="Show version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """QuerySense - PostgreSQL query performance analyzer."""
    pass


if __name__ == "__main__":
    app()
