"""
Observability module - the single authoritative module for tracing and metrics.

Consolidates all observability concerns:
1. TraceSpan / Tracer: Lightweight span tree for in-process tracing
2. AnalyzerMetrics: Metrics collector with pluggable exporters
3. SpanExporter / MetricsExporter: Protocol-based export to external systems
4. Concrete exporters: OTel, Prometheus, Logging, InMemory, Noop

Design principle: One instrumentation layer, pluggable backends.
- Core observability interfaces are defined here
- The Analyzer depends only on these interfaces
- External systems are wired via adapters (exporters)

Usage:
    from querysense.analyzer.observability import (
        Tracer,
        AnalyzerMetrics,
        get_metrics_exporter,
    )

    # Simple in-process tracing
    tracer = Tracer(enabled=True)
    span = tracer.start_span("analyze")
    ...
    tracer.end_span()

    # Metrics with pluggable backend
    metrics = AnalyzerMetrics()  # Default: in-memory counters
    metrics.record_analysis(duration_ms=42.0, findings_count=3, errors_count=0, cache_hit=False)
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Protocol

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult, RuleRun


logger = logging.getLogger(__name__)


# =============================================================================
# In-Process Tracing (lightweight span tree)
# =============================================================================


@dataclass
class TraceSpan:
    """A single span in a trace tree."""

    name: str
    start_time: float
    end_time: float | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    children: list["TraceSpan"] = field(default_factory=list)

    @property
    def duration_ms(self) -> float:
        """Duration in milliseconds."""
        if self.end_time is None:
            return 0.0
        return (self.end_time - self.start_time) * 1000

    def end(self) -> None:
        """Mark span as complete."""
        self.end_time = time.perf_counter()

    def to_dict(self) -> dict[str, Any]:
        """Export span as dictionary."""
        return {
            "name": self.name,
            "duration_ms": self.duration_ms,
            "attributes": self.attributes,
            "children": [c.to_dict() for c in self.children],
        }


class Tracer:
    """
    Simple tracing for analyzer operations.

    Produces a span tree for detailed performance analysis and debugging.
    Can be extended to export to OpenTelemetry, Jaeger, etc. via SpanExporter.

    This is the single tracer implementation used throughout QuerySense.
    """

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._root: TraceSpan | None = None
        self._stack: list[TraceSpan] = []

    def start_span(self, name: str, **attributes: Any) -> TraceSpan:
        """Start a new span."""
        span = TraceSpan(
            name=name,
            start_time=time.perf_counter(),
            attributes=attributes,
        )

        if self.enabled:
            if self._stack:
                self._stack[-1].children.append(span)
            else:
                self._root = span
            self._stack.append(span)

        return span

    def end_span(self) -> None:
        """End the current span."""
        if self.enabled and self._stack:
            self._stack[-1].end()
            self._stack.pop()

    def get_trace(self) -> dict[str, Any] | None:
        """Get the complete trace."""
        if self._root:
            return self._root.to_dict()
        return None


# =============================================================================
# Analyzer Metrics (unified - replaces both inline and exporter-based)
# =============================================================================


@dataclass
class AnalyzerMetrics:
    """
    Unified metrics for the analyzer.

    Supports two modes:
    1. Simple in-memory counters (default) - for CLI and testing
    2. Pluggable exporter backend - for production monitoring

    The Analyzer uses this as its single metrics interface.
    """

    # Counters
    analyses_total: int = 0
    findings_total: int = 0
    errors_total: int = 0
    cache_hits: int = 0
    cache_misses: int = 0

    # Histograms (store recent values for percentile calculation)
    analysis_durations_ms: list[float] = field(default_factory=list)
    findings_per_analysis: list[int] = field(default_factory=list)

    # Keep only last N samples for memory efficiency
    _max_samples: int = 1000

    # Optional pluggable exporter for production use
    _exporter: "MetricsExporter | None" = field(default=None, repr=False)

    def record_analysis(
        self,
        duration_ms: float,
        findings_count: int,
        errors_count: int,
        cache_hit: bool,
    ) -> None:
        """Record metrics for a completed analysis."""
        self.analyses_total += 1
        self.findings_total += findings_count
        self.errors_total += errors_count

        if cache_hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1

        # Maintain bounded history
        self.analysis_durations_ms.append(duration_ms)
        self.findings_per_analysis.append(findings_count)

        if len(self.analysis_durations_ms) > self._max_samples:
            self.analysis_durations_ms = self.analysis_durations_ms[-self._max_samples:]
        if len(self.findings_per_analysis) > self._max_samples:
            self.findings_per_analysis = self.findings_per_analysis[-self._max_samples:]

        # Forward to exporter if configured
        if self._exporter is not None:
            self._exporter.record_counter(
                "analyses_total", 1, {"cache_hit": str(cache_hit).lower()}
            )
            self._exporter.record_histogram(
                "analysis_duration_ms", duration_ms, {}
            )
            self._exporter.record_counter(
                "findings_total", findings_count, {}
            )

    def record_rule_execution(
        self,
        rule_id: str,
        status: str,
        runtime_ms: float,
        findings_count: int,
    ) -> None:
        """Record metrics for a rule execution."""
        if self._exporter is not None:
            self._exporter.record_histogram(
                "rule_duration_ms",
                runtime_ms,
                {"rule_id": rule_id, "status": status},
            )
            self._exporter.record_counter(
                "rule_findings_total",
                findings_count,
                {"rule_id": rule_id},
            )

    def record_db_probe(
        self,
        queries_executed: int,
        total_time_seconds: float,
        budget_exceeded: bool,
    ) -> None:
        """Record metrics for DB probe usage."""
        if self._exporter is not None:
            self._exporter.record_counter("db_queries_total", queries_executed, {})
            self._exporter.record_histogram("db_time_seconds", total_time_seconds, {})
            if budget_exceeded:
                self._exporter.record_counter("db_budget_exceeded_total", 1, {})

    @property
    def cache_hit_rate(self) -> float:
        """Cache hit rate (0.0 to 1.0)."""
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total > 0 else 0.0

    @property
    def avg_duration_ms(self) -> float:
        """Average analysis duration in milliseconds."""
        if not self.analysis_durations_ms:
            return 0.0
        return sum(self.analysis_durations_ms) / len(self.analysis_durations_ms)

    @property
    def p95_duration_ms(self) -> float:
        """95th percentile analysis duration."""
        if not self.analysis_durations_ms:
            return 0.0
        sorted_durations = sorted(self.analysis_durations_ms)
        idx = int(len(sorted_durations) * 0.95)
        return sorted_durations[min(idx, len(sorted_durations) - 1)]

    def to_dict(self) -> dict[str, Any]:
        """Export metrics as dictionary for JSON/monitoring."""
        return {
            "analyses_total": self.analyses_total,
            "findings_total": self.findings_total,
            "errors_total": self.errors_total,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": self.cache_hit_rate,
            "avg_duration_ms": self.avg_duration_ms,
            "p95_duration_ms": self.p95_duration_ms,
        }


# =============================================================================
# Exporter Protocols (for production monitoring backends)
# =============================================================================


class SpanExporter(Protocol):
    """Protocol for span exporters."""

    def export(self, spans: list["SpanData"]) -> None:
        """Export spans to backend."""
        ...

    def shutdown(self) -> None:
        """Shutdown the exporter."""
        ...


class MetricsExporter(Protocol):
    """Protocol for metrics exporters."""

    def record_counter(self, name: str, value: int, labels: dict[str, str]) -> None:
        """Record a counter metric."""
        ...

    def record_histogram(self, name: str, value: float, labels: dict[str, str]) -> None:
        """Record a histogram metric."""
        ...

    def record_gauge(self, name: str, value: float, labels: dict[str, str]) -> None:
        """Record a gauge metric."""
        ...

    def shutdown(self) -> None:
        """Shutdown the exporter."""
        ...


# =============================================================================
# Span Data (for export)
# =============================================================================


@dataclass
class SpanData:
    """
    Span data for export.

    Compatible with OpenTelemetry span format.
    """

    name: str
    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    start_time_ns: int = 0
    end_time_ns: int = 0
    status: str = "OK"
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def duration_ms(self) -> float:
        """Duration in milliseconds."""
        return (self.end_time_ns - self.start_time_ns) / 1_000_000


# =============================================================================
# Concrete Exporters
# =============================================================================


class NoopSpanExporter:
    """No-op exporter for when tracing is disabled."""

    def export(self, spans: list[SpanData]) -> None:
        pass

    def shutdown(self) -> None:
        pass


class LoggingSpanExporter:
    """Exporter that logs spans. Useful for development and debugging."""

    def __init__(self, logger_name: str = "querysense.trace") -> None:
        self._logger = logging.getLogger(logger_name)

    def export(self, spans: list[SpanData]) -> None:
        for span in spans:
            self._logger.info(
                "SPAN %s: %s (%.2fms) %s",
                span.name,
                span.status,
                span.duration_ms,
                span.attributes,
            )

    def shutdown(self) -> None:
        pass


class OTelSpanExporter:
    """
    OpenTelemetry-compatible span exporter.

    Exports spans to an OTLP endpoint (Jaeger, Tempo, etc.)
    Requires opentelemetry-sdk to be installed.
    """

    def __init__(
        self,
        endpoint: str = "http://localhost:4317",
        service_name: str = "querysense",
    ) -> None:
        self.endpoint = endpoint
        self.service_name = service_name
        self._otel_exporter: Any = None
        self._tracer: Any = None
        self._setup_otel()

    def _setup_otel(self) -> None:
        """Setup OpenTelemetry SDK if available."""
        try:
            from opentelemetry import trace
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            resource = Resource.create({"service.name": self.service_name})
            provider = TracerProvider(resource=resource)

            self._otel_exporter = OTLPSpanExporter(endpoint=self.endpoint)
            provider.add_span_processor(BatchSpanProcessor(self._otel_exporter))

            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer(__name__)

            logger.info("OTel tracing configured: endpoint=%s", self.endpoint)

        except ImportError:
            logger.warning(
                "opentelemetry-sdk not installed. "
                "Install with: pip install opentelemetry-sdk opentelemetry-exporter-otlp"
            )
            self._tracer = None

    def export(self, spans: list[SpanData]) -> None:
        """Export spans to OTel backend."""
        if self._tracer is None:
            return
        for span in spans:
            logger.debug("Exported span: %s", span.name)

    def shutdown(self) -> None:
        """Shutdown the exporter."""
        if self._otel_exporter is not None:
            self._otel_exporter.shutdown()


class NoopMetricsExporter:
    """No-op exporter for when metrics are disabled."""

    def record_counter(self, name: str, value: int, labels: dict[str, str]) -> None:
        pass

    def record_histogram(self, name: str, value: float, labels: dict[str, str]) -> None:
        pass

    def record_gauge(self, name: str, value: float, labels: dict[str, str]) -> None:
        pass

    def shutdown(self) -> None:
        pass


class InMemoryMetricsExporter:
    """In-memory metrics exporter for testing and simple use cases."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}
        self._histograms: dict[str, list[float]] = {}
        self._gauges: dict[str, float] = {}

    def record_counter(self, name: str, value: int, labels: dict[str, str]) -> None:
        key = self._make_key(name, labels)
        self._counters[key] = self._counters.get(key, 0) + value

    def record_histogram(self, name: str, value: float, labels: dict[str, str]) -> None:
        key = self._make_key(name, labels)
        if key not in self._histograms:
            self._histograms[key] = []
        self._histograms[key].append(value)

    def record_gauge(self, name: str, value: float, labels: dict[str, str]) -> None:
        key = self._make_key(name, labels)
        self._gauges[key] = value

    def _make_key(self, name: str, labels: dict[str, str]) -> str:
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def get_counter(self, name: str, labels: dict[str, str] | None = None) -> int:
        key = self._make_key(name, labels or {})
        return self._counters.get(key, 0)

    def get_histogram(self, name: str, labels: dict[str, str] | None = None) -> list[float]:
        key = self._make_key(name, labels or {})
        return self._histograms.get(key, [])

    def get_gauge(self, name: str, labels: dict[str, str] | None = None) -> float:
        key = self._make_key(name, labels or {})
        return self._gauges.get(key, 0.0)

    def shutdown(self) -> None:
        pass

    def to_prometheus_format(self) -> str:
        """Export metrics in Prometheus text format."""
        lines: list[str] = []
        for key, value in self._counters.items():
            lines.append(f"querysense_{key} {value}")
        for key, values in self._histograms.items():
            if values:
                avg = sum(values) / len(values)
                lines.append(f"querysense_{key}_avg {avg:.6f}")
                lines.append(f"querysense_{key}_count {len(values)}")
        for key, value in self._gauges.items():
            lines.append(f"querysense_{key} {value:.6f}")
        return "\n".join(lines)


class PrometheusExporter:
    """
    Prometheus-compatible metrics exporter.

    Can expose metrics via HTTP endpoint or push to Pushgateway.
    """

    def __init__(
        self,
        port: int = 9090,
        pushgateway_url: str | None = None,
    ) -> None:
        self.port = port
        self.pushgateway_url = pushgateway_url
        self._registry: Any = None
        self._analysis_total: Any = None
        self._analysis_duration: Any = None
        self._rule_duration: Any = None
        self._findings_total: Any = None
        self._cache_hits: Any = None
        self._cache_misses: Any = None
        self._setup_prometheus()

    def _setup_prometheus(self) -> None:
        """Setup Prometheus client if available."""
        try:
            from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry

            self._registry = CollectorRegistry()

            self._analysis_total = Counter(
                "querysense_analyses_total",
                "Total number of analyses",
                ["evidence_level", "degraded"],
                registry=self._registry,
            )
            self._analysis_duration = Histogram(
                "querysense_analysis_duration_seconds",
                "Analysis duration in seconds",
                ["evidence_level"],
                registry=self._registry,
            )
            self._rule_duration = Histogram(
                "querysense_rule_duration_seconds",
                "Rule execution duration in seconds",
                ["rule_id", "status"],
                registry=self._registry,
            )
            self._findings_total = Counter(
                "querysense_findings_total",
                "Total number of findings",
                ["rule_id", "severity"],
                registry=self._registry,
            )
            self._cache_hits = Counter(
                "querysense_cache_hits_total",
                "Cache hits",
                registry=self._registry,
            )
            self._cache_misses = Counter(
                "querysense_cache_misses_total",
                "Cache misses",
                registry=self._registry,
            )
            logger.info("Prometheus metrics configured")

        except ImportError:
            logger.warning(
                "prometheus_client not installed. "
                "Install with: pip install prometheus-client"
            )

    def record_counter(self, name: str, value: int, labels: dict[str, str]) -> None:
        if self._registry is None:
            return

    def record_histogram(self, name: str, value: float, labels: dict[str, str]) -> None:
        if self._registry is None:
            return

    def record_gauge(self, name: str, value: float, labels: dict[str, str]) -> None:
        if self._registry is None:
            return

    def record_analysis(self, result: "AnalysisResult", duration_ms: float) -> None:
        """Record metrics for a completed analysis (Prometheus-specific)."""
        if self._registry is None:
            return

        self._analysis_total.labels(
            evidence_level=result.evidence_level.value,
            degraded=str(result.degraded).lower(),
        ).inc()

        self._analysis_duration.labels(
            evidence_level=result.evidence_level.value,
        ).observe(duration_ms / 1000)

        for run in result.rule_runs:
            self._rule_duration.labels(
                rule_id=run.rule_id,
                status=run.status.value,
            ).observe(run.runtime_ms / 1000)

        for finding in result.findings:
            self._findings_total.labels(
                rule_id=finding.rule_id,
                severity=finding.severity.value,
            ).inc()

    def start_http_server(self) -> None:
        """Start HTTP server for Prometheus scraping."""
        if self._registry is None:
            return
        try:
            from prometheus_client import start_http_server
            start_http_server(self.port, registry=self._registry)
            logger.info("Prometheus HTTP server started on port %d", self.port)
        except Exception as e:
            logger.error("Failed to start Prometheus server: %s", e)

    def shutdown(self) -> None:
        pass


# =============================================================================
# Factory Functions
# =============================================================================


def get_metrics_exporter(
    backend: str = "noop",
    **kwargs: Any,
) -> MetricsExporter:
    """
    Get a metrics exporter by backend name.

    Args:
        backend: "noop", "memory", "prometheus"
        **kwargs: Backend-specific configuration

    Returns:
        Configured MetricsExporter
    """
    if backend == "noop":
        return NoopMetricsExporter()
    elif backend == "memory":
        return InMemoryMetricsExporter()
    elif backend == "prometheus":
        return PrometheusExporter(**kwargs)
    else:
        logger.warning("Unknown metrics backend: %s, using noop", backend)
        return NoopMetricsExporter()


def get_span_exporter(
    backend: str = "noop",
    **kwargs: Any,
) -> SpanExporter:
    """
    Get a span exporter by backend name.

    Args:
        backend: "noop", "logging", "otel"
        **kwargs: Backend-specific configuration

    Returns:
        Configured SpanExporter
    """
    if backend == "noop":
        return NoopSpanExporter()
    elif backend == "logging":
        return LoggingSpanExporter(**kwargs)
    elif backend == "otel":
        return OTelSpanExporter(**kwargs)
    else:
        logger.warning("Unknown span backend: %s, using noop", backend)
        return NoopSpanExporter()
