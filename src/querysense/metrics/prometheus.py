"""
Prometheus metrics exporter for QuerySense.

Exports analysis metrics in Prometheus exposition format, enabling
integration with Grafana, Datadog, and any Prometheus-compatible
monitoring stack — without paying Datadog's $70/host.

Usage:
    from querysense.metrics.prometheus import PrometheusExporter

    exporter = PrometheusExporter()
    exporter.record_analysis(result)
    print(exporter.render())  # Prometheus text format

As CLI:
    querysense metrics export --db production
    querysense metrics serve --port 9187  # /metrics endpoint
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class MetricSample:
    """A single Prometheus metric sample."""

    name: str
    value: float
    labels: dict[str, str] = field(default_factory=dict)
    help_text: str = ""
    metric_type: str = "gauge"
    timestamp_ms: int | None = None

    def render_line(self) -> str:
        """Render as Prometheus exposition format line."""
        if self.labels:
            label_str = ",".join(
                f'{k}="{v}"' for k, v in sorted(self.labels.items())
            )
            name_with_labels = f"{self.name}{{{label_str}}}"
        else:
            name_with_labels = self.name

        if self.timestamp_ms:
            return f"{name_with_labels} {self.value} {self.timestamp_ms}"
        return f"{name_with_labels} {self.value}"


class PrometheusExporter:
    """
    Collects QuerySense metrics and exports in Prometheus format.

    Metrics exported:
    - querysense_analyses_total: Total analyses performed
    - querysense_findings_total: Total findings by severity
    - querysense_plan_cost: Plan cost (total_cost from EXPLAIN)
    - querysense_execution_time_ms: Execution time in milliseconds
    - querysense_node_count: Number of plan nodes
    - querysense_index_usage_ratio: Index hit ratio (0-1)
    - querysense_regressions_total: Number of detected regressions
    - querysense_rollback_safe: Whether rollback is safe (1/0)
    - querysense_migration_risks_total: Migration risks by severity
    - querysense_schema_drift_count: Schema differences detected
    """

    def __init__(self) -> None:
        self._samples: list[MetricSample] = []
        self._metric_help: dict[str, str] = {
            "querysense_analyses_total": "Total number of analyses performed",
            "querysense_findings_total": "Total findings by severity",
            "querysense_plan_cost": "Total plan cost from EXPLAIN",
            "querysense_execution_time_ms": "Query execution time in milliseconds",
            "querysense_node_count": "Number of nodes in query plan",
            "querysense_index_usage_ratio": "Ratio of index scans to sequential scans",
            "querysense_regressions_total": "Number of detected regressions",
            "querysense_rollback_safe": "Whether migration rollback is safe (1=safe, 0=unsafe)",
            "querysense_migration_risks_total": "Migration risks by severity",
            "querysense_schema_drift_count": "Number of schema differences detected",
            "querysense_rewrite_suggestions_total": "Number of rewrite suggestions",
            "querysense_build_info": "QuerySense build information",
        }
        self._metric_types: dict[str, str] = {
            "querysense_analyses_total": "counter",
            "querysense_findings_total": "gauge",
            "querysense_plan_cost": "gauge",
            "querysense_execution_time_ms": "gauge",
            "querysense_node_count": "gauge",
            "querysense_index_usage_ratio": "gauge",
            "querysense_regressions_total": "counter",
            "querysense_rollback_safe": "gauge",
            "querysense_migration_risks_total": "gauge",
            "querysense_schema_drift_count": "gauge",
            "querysense_rewrite_suggestions_total": "gauge",
            "querysense_build_info": "gauge",
        }

    def record_analysis(self, result: Any, query_id: str = "") -> None:
        """Record metrics from an AnalysisResult."""
        labels = {"query_id": query_id} if query_id else {}
        ts = int(datetime.now(timezone.utc).timestamp() * 1000)

        summary = result.summary()

        self._samples.append(MetricSample(
            name="querysense_analyses_total",
            value=1,
            labels=labels,
            timestamp_ms=ts,
        ))

        for severity in ("critical", "warning", "info"):
            self._samples.append(MetricSample(
                name="querysense_findings_total",
                value=summary.get(severity, 0),
                labels={**labels, "severity": severity},
                timestamp_ms=ts,
            ))

        if hasattr(result, "metadata"):
            self._samples.append(MetricSample(
                name="querysense_node_count",
                value=result.metadata.node_count,
                labels=labels,
                timestamp_ms=ts,
            ))
            if result.metadata.execution_time_ms:
                self._samples.append(MetricSample(
                    name="querysense_execution_time_ms",
                    value=result.metadata.execution_time_ms,
                    labels=labels,
                    timestamp_ms=ts,
                ))

    def record_plan_cost(
        self, cost: float, query_id: str = "", db: str = ""
    ) -> None:
        """Record plan cost metric."""
        labels = {}
        if query_id:
            labels["query_id"] = query_id
        if db:
            labels["db"] = db

        self._samples.append(MetricSample(
            name="querysense_plan_cost",
            value=cost,
            labels=labels,
            timestamp_ms=int(datetime.now(timezone.utc).timestamp() * 1000),
        ))

    def record_regression(self, query_id: str, pct_change: float) -> None:
        """Record a regression detection."""
        self._samples.append(MetricSample(
            name="querysense_regressions_total",
            value=1,
            labels={"query_id": query_id, "pct_change": str(round(pct_change))},
            timestamp_ms=int(datetime.now(timezone.utc).timestamp() * 1000),
        ))

    def record_migration_check(
        self, file_name: str, critical: int, warning: int, info: int, safe: bool
    ) -> None:
        """Record migration safety check metrics."""
        labels = {"file": file_name}
        ts = int(datetime.now(timezone.utc).timestamp() * 1000)

        for severity, count in [("critical", critical), ("warning", warning), ("info", info)]:
            self._samples.append(MetricSample(
                name="querysense_migration_risks_total",
                value=count,
                labels={**labels, "severity": severity},
                timestamp_ms=ts,
            ))

        self._samples.append(MetricSample(
            name="querysense_rollback_safe",
            value=1 if safe else 0,
            labels=labels,
            timestamp_ms=ts,
        ))

    def record_schema_drift(self, source: str, target: str, count: int) -> None:
        """Record schema drift count."""
        self._samples.append(MetricSample(
            name="querysense_schema_drift_count",
            value=count,
            labels={"source": source, "target": target},
            timestamp_ms=int(datetime.now(timezone.utc).timestamp() * 1000),
        ))

    def record_build_info(self, version: str) -> None:
        """Record build info metric."""
        self._samples.append(MetricSample(
            name="querysense_build_info",
            value=1,
            labels={"version": version},
        ))

    def render(self) -> str:
        """
        Render all metrics in Prometheus exposition format.

        Returns text that can be served at /metrics endpoint
        or pushed to a Prometheus pushgateway.
        """
        lines: list[str] = []
        seen_metrics: set[str] = set()

        for sample in self._samples:
            if sample.name not in seen_metrics:
                seen_metrics.add(sample.name)
                help_text = self._metric_help.get(sample.name, "")
                metric_type = self._metric_types.get(sample.name, "gauge")
                if help_text:
                    lines.append(f"# HELP {sample.name} {help_text}")
                lines.append(f"# TYPE {sample.name} {metric_type}")

            lines.append(sample.render_line())

        lines.append("")  # Trailing newline
        return "\n".join(lines)

    def clear(self) -> None:
        """Clear all recorded samples."""
        self._samples.clear()

    def from_history_db(self, db_path: str, days: int = 7) -> None:
        """
        Load metrics from the local SQLite history database.

        This enables serving historical QuerySense metrics through
        Prometheus without any cloud infrastructure.
        """
        from pathlib import Path
        from querysense.temporal.sqlite_store import SQLiteTemporalStore

        p = Path(db_path).expanduser()
        if not p.exists():
            return

        store = SQLiteTemporalStore(p)
        trends = store.trends(days=days)

        for entry in trends:
            labels = {}
            if entry.get("query_id"):
                labels["query_id"] = entry["query_id"]

            ts = None
            if entry.get("timestamp"):
                try:
                    dt = datetime.fromisoformat(entry["timestamp"])
                    ts = int(dt.timestamp() * 1000)
                except (ValueError, TypeError):
                    pass

            for severity in ("critical", "warning", "info"):
                count_key = f"{severity}_count"
                if count_key in entry:
                    self._samples.append(MetricSample(
                        name="querysense_findings_total",
                        value=entry[count_key],
                        labels={**labels, "severity": severity},
                        timestamp_ms=ts,
                    ))

            if entry.get("execution_time_ms"):
                self._samples.append(MetricSample(
                    name="querysense_execution_time_ms",
                    value=entry["execution_time_ms"],
                    labels=labels,
                    timestamp_ms=ts,
                ))

            if entry.get("node_count"):
                self._samples.append(MetricSample(
                    name="querysense_node_count",
                    value=entry["node_count"],
                    labels=labels,
                    timestamp_ms=ts,
                ))
