"""
CLI commands for cluster-aware index advisor.

    querysense cluster detect       — Detect cluster topology
    querysense cluster advise       — Cluster-aware CP-SAT index advisor
    querysense cluster unused       — Cluster-wide unused index detection
"""

from __future__ import annotations

import asyncio
import json
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def register(parent: typer.Typer) -> None:
    """Register cluster commands on the cluster sub-app."""

    @parent.command(name="detect")
    def cluster_detect(
        primary_dsn: Annotated[
            str,
            typer.Option("--primary", help="Primary server DSN"),
        ] = "postgresql://localhost:5432/postgres",
        replica_dsns: Annotated[
            str,
            typer.Option(
                "--replicas",
                help="Comma-separated replica DSNs",
            ),
        ] = "",
        cluster_id: Annotated[
            str,
            typer.Option("--cluster-id", help="Manual cluster identifier"),
        ] = "",
        json_output: Annotated[
            bool, typer.Option("--json", help="JSON output"),
        ] = False,
    ) -> None:
        """Detect PostgreSQL cluster topology (primary + replicas)."""
        from querysense.cluster import ClusterDetector

        detector = ClusterDetector()

        if replica_dsns:
            all_dsns = [primary_dsn] + [d.strip() for d in replica_dsns.split(",") if d.strip()]
            cluster = asyncio.run(detector.detect(all_dsns, cluster_id=cluster_id))
        else:
            cluster = asyncio.run(
                detector.detect_from_primary(primary_dsn, cluster_id=cluster_id)
            )

        if json_output:
            console.print_json(json.dumps(cluster.to_dict(), default=str))
            return

        console.print(Panel.fit(
            f"[bold]Cluster Topology[/bold]\n"
            f"Cluster ID: {cluster.cluster_id}\n"
            f"Detection: {cluster.detection_method}\n"
            f"Servers: {cluster.server_count}\n"
            f"Standalone: {'yes' if cluster.is_standalone else 'no'}",
            border_style="cyan",
        ))

        if cluster.primary:
            p = cluster.primary
            console.print(
                f"  [green]PRIMARY[/green] {p.host}:{p.port} "
                f"(system_id: {p.system_identifier[:16]}...)"
            )

        for r in cluster.replicas:
            lag = f"lag: {r.replication_lag_seconds:.1f}s" if r.replication_lag_seconds else "lag: unknown"
            console.print(
                f"  [yellow]REPLICA[/yellow] {r.host}:{r.port} ({lag})"
            )

    @parent.command(name="advise")
    def cluster_advise(
        primary_dsn: Annotated[
            str,
            typer.Option("--primary", help="Primary server DSN"),
        ] = "postgresql://localhost:5432/postgres",
        replica_dsns: Annotated[
            str,
            typer.Option(
                "--replicas",
                help="Comma-separated replica DSNs",
            ),
        ] = "",
        cluster_id: Annotated[
            str,
            typer.Option("--cluster-id", help="Manual cluster identifier"),
        ] = "",
        schema: Annotated[str, typer.Option("--schema")] = "public",
        tables: Annotated[
            str,
            typer.Option("--tables", help="Comma-separated tables (auto if empty)"),
        ] = "",
        max_indexes: Annotated[
            int, typer.Option("--max-indexes-per-table"),
        ] = 8,
        max_iwo: Annotated[
            float, typer.Option("--max-iwo", help="Max IWO budget"),
        ] = 50.0,
        top_queries: Annotated[
            int, typer.Option("--top-queries"),
        ] = 100,
        no_hypopg: Annotated[
            bool, typer.Option("--no-hypopg", help="Skip HypoPG verification"),
        ] = False,
        json_output: Annotated[
            bool, typer.Option("--json", help="JSON output"),
        ] = False,
        fix_script: Annotated[
            bool, typer.Option("--fix-script", help="Output fix SQL"),
        ] = False,
    ) -> None:
        """
        Cluster-aware CP-SAT index advisor.

        Merges scans from primary + all replicas before optimization.
        An index unused on primary but used on a replica won't be dropped.
        Recommendations are globally optimal across the entire cluster.
        """
        from querysense.cluster import ClusterDetector
        from querysense.index.cluster_advisor import ClusterIndexAdvisor

        # Detect cluster topology
        detector = ClusterDetector()
        if replica_dsns:
            all_dsns = [primary_dsn] + [d.strip() for d in replica_dsns.split(",") if d.strip()]
            cluster = asyncio.run(detector.detect(all_dsns, cluster_id=cluster_id))
        else:
            cluster = asyncio.run(
                detector.detect_from_primary(primary_dsn, cluster_id=cluster_id)
            )

        table_list = [t.strip() for t in tables.split(",") if t.strip()] if tables else None

        advisor = ClusterIndexAdvisor(
            max_indexes_per_table=max_indexes,
            max_iwo=max_iwo,
            use_hypopg=not no_hypopg,
            top_queries=top_queries,
        )

        result = asyncio.run(
            advisor.advise_cluster(cluster, schema=schema, tables=table_list)
        )

        if json_output:
            console.print_json(json.dumps(result.to_dict(), default=str))
            return

        if fix_script:
            console.print(result.fix_script)
            return

        # Rich output
        console.print(Panel.fit(
            f"[bold]Cluster-Aware Index Advisor[/bold]\n"
            f"Cluster: {result.cluster_id} ({result.server_count} servers)\n"
            f"Cluster-aware: {'[green]yes[/green]' if result.is_cluster_aware else '[dim]no (standalone)[/dim]'}\n"
            f"Scans: {result.total_scans_before_merge} raw → {result.total_scans_after_merge} merged\n"
            f"Scans unique to replicas: {result.scans_unique_to_replicas}\n"
            f"Tables analyzed: {result.tables_analyzed}\n"
            f"Candidates: {result.candidates_generated}\n"
            f"Recommended indexes: {len(result.recommended_indexes)}\n"
            f"Cost reduction: {result.total_cost_reduction_pct:.1f}%\n"
            f"Pipeline time: {result.total_time_ms:.0f}ms",
            border_style="green",
        ))

        # Server contributions
        if result.server_contributions:
            contrib_table = Table(title="Server Scan Contributions")
            contrib_table.add_column("Server")
            contrib_table.add_column("Role", justify="center")
            contrib_table.add_column("Scans", justify="right")
            contrib_table.add_column("Tables", justify="right")

            for c in result.server_contributions:
                role = "[green]PRIMARY[/green]" if c.is_primary else "[yellow]REPLICA[/yellow]"
                contrib_table.add_row(
                    c.server_label,
                    role,
                    str(c.scans_extracted),
                    str(len(c.tables)),
                )
            console.print(contrib_table)
            console.print()

        # Saved-by-replicas warnings
        if result.indexes_saved_by_replicas:
            console.print(
                "[bold yellow]Indexes unused on primary but USED on replicas "
                "(do NOT drop):[/bold yellow]"
            )
            saved_table = Table()
            saved_table.add_column("Index")
            saved_table.add_column("Primary Scans", justify="right")
            saved_table.add_column("Replica Scans", justify="right")
            saved_table.add_column("Used On")

            for s in result.indexes_saved_by_replicas:
                saved_table.add_row(
                    s["index_name"],
                    str(s["primary_scans"]),
                    str(s["replica_scans"]),
                    s["used_on"],
                )
            console.print(saved_table)
            console.print()

        # Recommended indexes
        if result.recommended_indexes:
            idx_table = Table(title="Recommended Indexes (create on primary)")
            idx_table.add_column("Table")
            idx_table.add_column("Columns")
            idx_table.add_column("Scans", justify="right")
            idx_table.add_column("Frequency", justify="right")
            idx_table.add_column("Improvement", justify="right")
            idx_table.add_column("IWO", justify="right")

            for idx in result.recommended_indexes:
                idx_table.add_row(
                    idx.table,
                    ", ".join(idx.columns),
                    str(idx.scans_covered),
                    f"{idx.total_frequency:,}",
                    f"{idx.improvement_ratio:.0%}",
                    f"{idx.iwo_score:.2f}",
                )
            console.print(idx_table)

            console.print("\n[bold]CREATE INDEX statements (run on primary):[/bold]")
            for idx in result.recommended_indexes:
                console.print(f"  {idx.create_sql}")
        else:
            console.print("[green]No additional indexes recommended.[/green]")

        # Truly unused
        if result.indexes_unused_cluster_wide:
            console.print(
                f"\n[bold red]Indexes unused on ALL {result.server_count} servers "
                f"(safe to drop):[/bold red]"
            )
            for idx_name in result.indexes_unused_cluster_wide:
                console.print(f"  DROP INDEX CONCURRENTLY IF EXISTS {idx_name};")

    @parent.command(name="unused")
    def cluster_unused(
        primary_dsn: Annotated[
            str,
            typer.Option("--primary", help="Primary server DSN"),
        ] = "postgresql://localhost:5432/postgres",
        replica_dsns: Annotated[
            str,
            typer.Option(
                "--replicas",
                help="Comma-separated replica DSNs",
            ),
        ] = "",
        cluster_id: Annotated[
            str,
            typer.Option("--cluster-id", help="Manual cluster identifier"),
        ] = "",
        schema: Annotated[str, typer.Option("--schema")] = "public",
        json_output: Annotated[
            bool, typer.Option("--json", help="JSON output"),
        ] = False,
    ) -> None:
        """
        Cluster-wide unused index detection.

        Only flags indexes as unused if they have zero scans on ALL servers.
        Prevents the dangerous mistake of dropping an index that's unused on
        the primary but critical for queries running on read replicas.
        """
        from querysense.cluster import ClusterDetector
        from querysense.index.cluster_advisor import ClusterIndexAdvisor

        detector = ClusterDetector()
        if replica_dsns:
            all_dsns = [primary_dsn] + [d.strip() for d in replica_dsns.split(",") if d.strip()]
            cluster = asyncio.run(detector.detect(all_dsns, cluster_id=cluster_id))
        else:
            cluster = asyncio.run(
                detector.detect_from_primary(primary_dsn, cluster_id=cluster_id)
            )

        advisor = ClusterIndexAdvisor()

        # We need per-server scans for the unused detection
        from querysense.scan_extractor import ScanExtractor
        per_server_scans: dict[str, object] = {}
        for server in cluster.all_servers:
            if not server.dsn:
                continue
            try:
                extractor = ScanExtractor()
                workload = asyncio.run(
                    extractor.extract_from_database(server.dsn, top_n=50)
                )
                per_server_scans[server.dsn] = workload
            except Exception:
                continue

        unused = asyncio.run(
            advisor._detect_unused_cluster_wide(cluster, per_server_scans, schema)
        )

        if json_output:
            console.print_json(json.dumps(unused, default=str))
            return

        console.print(Panel.fit(
            f"[bold]Cluster-Wide Unused Index Detection[/bold]\n"
            f"Cluster: {cluster.cluster_id} ({cluster.server_count} servers)\n"
            f"Truly unused (safe to drop): {len(unused['truly_unused'])}\n"
            f"Saved by replicas (do NOT drop): {len(unused['saved_by_replicas'])}",
            border_style="cyan",
        ))

        if unused["saved_by_replicas"]:
            console.print(
                "\n[bold yellow]Indexes SAVED by replica usage:[/bold yellow]"
            )
            saved_table = Table()
            saved_table.add_column("Index")
            saved_table.add_column("Primary Scans", justify="right")
            saved_table.add_column("Replica Scans", justify="right")
            saved_table.add_column("Used On")
            saved_table.add_column("Size")

            for s in unused["saved_by_replicas"]:
                saved_table.add_row(
                    s["index_name"],
                    str(s["primary_scans"]),
                    str(s["replica_scans"]),
                    s["used_on"],
                    f"{s.get('size_bytes', 0) // 1024}KB",
                )
            console.print(saved_table)

        if unused["truly_unused"]:
            console.print(
                f"\n[bold red]Indexes unused on ALL servers (safe to drop):[/bold red]"
            )
            for idx_name in unused["truly_unused"]:
                console.print(f"  DROP INDEX CONCURRENTLY IF EXISTS {idx_name};")
        else:
            console.print(
                "\n[green]No indexes are unused across the entire cluster.[/green]"
            )
