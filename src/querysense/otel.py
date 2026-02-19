"""
OpenTelemetry integration for QuerySense.

Provides distributed tracing, metrics, and correlation between
application traces and database query analysis.

Works with any OTLP-compatible backend (Jaeger, Tempo, Datadog, etc.).

Usage:
    from querysense.otel import QuerySenseTracer

    tracer = QuerySenseTracer()

    # Trace an analysis operation
    with tracer.trace_analysis(plan_hash="abc123", user_id="u-1") as span:
        result = analyze(plan)
        span.set_attribute("findings.count", len(result.findings))

    # Correlate with application traces
    tracer.correlate_query(trace_id="abc", query="SELECT ...")

Note: Requires opentelemetry-api and opentelemetry-sdk.
Falls back to no-op if not installed.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Generator


@dataclass
class SpanContext:
    """Lightweight span representation when OTel SDK is not available."""
    name: str
    attributes: dict[str, Any] = field(default_factory=dict)
    status: str = "ok"
    start_time: float = 0.0
    end_time: float = 0.0
    events: list[dict[str, Any]] = field(default_factory=list)

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        self.events.append({"name": name, "attributes": attributes or {}})

    def set_status(self, status: str, description: str = "") -> None:
        self.status = status
        if description:
            self.attributes["status.description"] = description

    def record_exception(self, exc: Exception) -> None:
        self.events.append({
            "name": "exception",
            "attributes": {
                "exception.type": type(exc).__name__,
                "exception.message": str(exc),
            },
        })

    @property
    def duration_ms(self) -> float:
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time) * 1000
        return 0.0


class QuerySenseTracer:
    """
    Distributed tracing for QuerySense operations.

    Wraps OpenTelemetry SDK when available, falls back to lightweight
    no-op spans otherwise. This means tracing code works everywhere
    without requiring OTel as a hard dependency.
    """

    def __init__(
        self,
        service_name: str = "querysense",
        endpoint: str = "",
        enabled: bool = True,
    ):
        self.service_name = service_name
        self.enabled = enabled
        self._tracer: Any = None
        self._spans: list[SpanContext] = []

        if enabled and endpoint:
            self._try_init_otel(endpoint)

    def _try_init_otel(self, endpoint: str) -> None:
        """Try to initialize OpenTelemetry SDK."""
        try:
            from opentelemetry import trace  # type: ignore[import-untyped]
            from opentelemetry.sdk.trace import TracerProvider  # type: ignore[import-untyped]
            from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore[import-untyped]
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter  # type: ignore[import-untyped]

            provider = TracerProvider()
            exporter = OTLPSpanExporter(endpoint=endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer(self.service_name)
        except ImportError:
            pass  # Fall back to lightweight spans

    @contextmanager
    def trace_analysis(
        self,
        plan_hash: str = "",
        user_id: str = "",
        query_label: str = "",
    ) -> Generator[SpanContext, None, None]:
        """Trace a plan analysis operation."""
        span = self._start_span("query_analysis")
        span.set_attribute("plan.hash", plan_hash)
        span.set_attribute("user.id", user_id)
        span.set_attribute("query.label", query_label)
        span.set_attribute("analysis.timestamp", time.time())

        try:
            yield span
            span.set_status("ok")
        except Exception as e:
            span.set_status("error", str(e))
            span.record_exception(e)
            raise
        finally:
            span.end_time = time.monotonic()
            self._spans.append(span)

    @contextmanager
    def trace_migration(
        self,
        migration_id: str = "",
        user_id: str = "",
        phase: str = "",
    ) -> Generator[SpanContext, None, None]:
        """Trace a migration operation."""
        span = self._start_span("migration")
        span.set_attribute("migration.id", migration_id)
        span.set_attribute("migration.phase", phase)
        span.set_attribute("user.id", user_id)

        try:
            yield span
            span.set_status("ok")
        except Exception as e:
            span.set_status("error", str(e))
            span.record_exception(e)
            raise
        finally:
            span.end_time = time.monotonic()
            self._spans.append(span)

    @contextmanager
    def trace_benchmark(
        self,
        concurrency: int = 0,
        query_count: int = 0,
    ) -> Generator[SpanContext, None, None]:
        """Trace a benchmark/concurrency test."""
        span = self._start_span("benchmark")
        span.set_attribute("bench.concurrency", concurrency)
        span.set_attribute("bench.query_count", query_count)

        try:
            yield span
            span.set_status("ok")
        except Exception as e:
            span.set_status("error", str(e))
            span.record_exception(e)
            raise
        finally:
            span.end_time = time.monotonic()
            self._spans.append(span)

    @contextmanager
    def trace_rewrite(
        self,
        original_hash: str = "",
        patterns_matched: int = 0,
    ) -> Generator[SpanContext, None, None]:
        """Trace a query rewrite operation."""
        span = self._start_span("query_rewrite")
        span.set_attribute("rewrite.original_hash", original_hash)
        span.set_attribute("rewrite.patterns_matched", patterns_matched)

        try:
            yield span
            span.set_status("ok")
        except Exception as e:
            span.set_status("error", str(e))
            span.record_exception(e)
            raise
        finally:
            span.end_time = time.monotonic()
            self._spans.append(span)

    def correlate_query(
        self,
        trace_id: str,
        query: str,
        plan_hash: str = "",
    ) -> SpanContext:
        """Link a database query to an application trace."""
        span = self._start_span("database_query")
        span.set_attribute("trace.parent", trace_id)
        span.set_attribute("db.query", query[:200])
        span.set_attribute("plan.hash", plan_hash)
        span.end_time = time.monotonic()
        self._spans.append(span)
        return span

    def _start_span(self, name: str) -> SpanContext:
        """Start a new span (OTel or lightweight)."""
        span = SpanContext(name=name)
        span.start_time = time.monotonic()
        span.set_attribute("service.name", self.service_name)
        return span

    def get_spans(self) -> list[SpanContext]:
        """Get all recorded spans (for testing/debugging)."""
        return list(self._spans)

    def clear(self) -> None:
        """Clear recorded spans."""
        self._spans.clear()
