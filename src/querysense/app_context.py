"""
Application Context Correlator — link slow queries to application traces.

Bridges the gap between "this query is slow" and "this endpoint calls it
1000 times per second." Integrates with OpenTelemetry, Datadog, and
New Relic to correlate EXPLAIN findings with application-level context.

Architecture:
    Application (OTel SDK) → SpanProcessor → QuerySense Correlator
    QuerySense Correlator → Enriched findings with endpoint, frequency, user context

v2 upgrades (closing gap with Datadog DBM):
- User session tracking: link queries to user sessions and browser flows
- Endpoint-level metrics: aggregate query stats per API endpoint
- Full-stack waterfall: browser → API → middleware → DB query chain
- Error correlation: track which queries fail and their error rates
- N+1 detection: identify repeated identical queries within a trace
- Connection pool metrics: track pool utilization per service

Supported trace formats:
- OpenTelemetry (OTLP)
- Datadog APM (via OTel bridge)
- W3C Trace Context headers

Usage:
    from querysense.app_context import AppContextCorrelator, QueryContext

    correlator = AppContextCorrelator()

    # Register from OTel span attributes
    correlator.register_query(
        sql_fingerprint="SELECT * FROM orders WHERE status = $1",
        endpoint="/api/orders",
        service="order-service",
        frequency_per_min=450,
        p99_latency_ms=120,
        trace_id="abc123",
    )

    # Enrich analysis results
    enriched = correlator.enrich_findings(findings, sql="SELECT * FROM orders WHERE status = 'pending'")

    # User session tracking
    correlator.register_session(
        session_id="sess_abc",
        user_id="user_123",
        trace_ids=["trace_001", "trace_002"],
    )

    # Endpoint-level metrics
    endpoint_stats = correlator.endpoint_metrics("/api/orders")
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ── User session tracking ──────────────────────────────────────────────


@dataclass
class UserSession:
    """Tracks a user session's database impact across multiple requests."""

    session_id: str
    user_id: str = ""
    started_at: float = 0
    last_active: float = 0
    trace_ids: list[str] = field(default_factory=list)
    total_queries: int = 0
    total_db_time_ms: float = 0
    distinct_endpoints: set[str] = field(default_factory=set)
    error_count: int = 0
    n_plus_one_count: int = 0  # N+1 query pattern detections
    user_agent: str = ""
    ip_address: str = ""

    @property
    def avg_query_time_ms(self) -> float:
        """Average DB time per query in this session."""
        return self.total_db_time_ms / max(self.total_queries, 1)

    @property
    def session_duration_s(self) -> float:
        """Session duration in seconds."""
        if self.started_at and self.last_active:
            return self.last_active - self.started_at
        return 0

    @property
    def db_load_pct(self) -> float:
        """What % of session wall time was spent in DB."""
        duration_ms = self.session_duration_s * 1000
        if duration_ms <= 0:
            return 0
        return min(100, (self.total_db_time_ms / duration_ms) * 100)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "total_queries": self.total_queries,
            "total_db_time_ms": round(self.total_db_time_ms, 2),
            "avg_query_time_ms": round(self.avg_query_time_ms, 2),
            "distinct_endpoints": list(self.distinct_endpoints),
            "error_count": self.error_count,
            "n_plus_one_count": self.n_plus_one_count,
            "session_duration_s": round(self.session_duration_s, 1),
            "db_load_pct": round(self.db_load_pct, 1),
        }


@dataclass
class EndpointMetrics:
    """Aggregated database metrics for an API endpoint."""

    endpoint: str
    service: str = ""
    total_queries: int = 0
    distinct_query_fingerprints: int = 0
    total_db_time_ms: float = 0
    avg_db_time_ms: float = 0
    p50_db_time_ms: float = 0
    p95_db_time_ms: float = 0
    p99_db_time_ms: float = 0
    error_rate: float = 0
    queries_per_request: float = 0  # avg queries fired per endpoint call
    n_plus_one_detected: bool = False
    hottest_query: str = ""  # fingerprint of the slowest query
    hottest_query_pct: float = 0  # % of DB time from the hottest query

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "service": self.service,
            "total_queries": self.total_queries,
            "distinct_query_fingerprints": self.distinct_query_fingerprints,
            "total_db_time_ms": round(self.total_db_time_ms, 2),
            "avg_db_time_ms": round(self.avg_db_time_ms, 2),
            "p50_db_time_ms": round(self.p50_db_time_ms, 2),
            "p95_db_time_ms": round(self.p95_db_time_ms, 2),
            "p99_db_time_ms": round(self.p99_db_time_ms, 2),
            "error_rate": round(self.error_rate, 4),
            "queries_per_request": round(self.queries_per_request, 1),
            "n_plus_one_detected": self.n_plus_one_detected,
            "hottest_query": self.hottest_query,
            "hottest_query_pct": round(self.hottest_query_pct, 1),
        }


@dataclass
class WaterfallSpan:
    """A span in the full-stack waterfall: browser → API → DB."""

    span_id: str
    parent_span_id: str | None
    service: str
    operation: str  # e.g., "GET /api/orders", "SELECT orders", "pg.query"
    layer: str  # "browser", "api", "middleware", "database"
    start_ms: float = 0
    duration_ms: float = 0
    status: str = "ok"  # ok, error
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "service": self.service,
            "operation": self.operation,
            "layer": self.layer,
            "start_ms": round(self.start_ms, 2),
            "duration_ms": round(self.duration_ms, 2),
            "status": self.status,
            "attributes": self.attributes,
        }


@dataclass
class NPlusOneDetection:
    """Detection of N+1 query pattern within a trace."""

    trace_id: str
    endpoint: str
    query_fingerprint: str
    repetition_count: int
    total_time_ms: float
    suggestion: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "endpoint": self.endpoint,
            "query_fingerprint": self.query_fingerprint,
            "repetition_count": self.repetition_count,
            "total_time_ms": round(self.total_time_ms, 2),
            "suggestion": self.suggestion,
        }


@dataclass
class QueryContext:
    """Application-level context for a query."""

    sql_fingerprint: str
    endpoint: str = ""
    service: str = ""
    frequency_per_min: float = 0
    p50_latency_ms: float = 0
    p99_latency_ms: float = 0
    error_rate: float = 0
    last_seen: float = 0
    trace_ids: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=list)
    source_file: str = ""        # e.g., "api/orders.py:45"
    caller_function: str = ""    # e.g., "get_pending_orders"
    # v2 additions
    session_ids: list[str] = field(default_factory=list)
    http_method: str = ""
    http_status_codes: list[int] = field(default_factory=list)
    connection_pool: str = ""    # which pool this query uses
    db_name: str = ""
    db_user: str = ""

    @property
    def is_hot_path(self) -> bool:
        """Query called >100 times/min is a hot path."""
        return self.frequency_per_min > 100

    @property
    def total_load_ms_per_min(self) -> float:
        """Total database time consumed per minute."""
        return self.frequency_per_min * self.p50_latency_ms

    @property
    def impact_category(self) -> str:
        """Categorize impact based on frequency and latency."""
        load = self.total_load_ms_per_min
        if load > 60000:  # >1 second of DB time per minute
            return "critical"
        elif load > 10000:
            return "high"
        elif load > 1000:
            return "medium"
        return "low"


@dataclass
class EnrichedFinding:
    """A QuerySense finding enriched with application context."""

    # Original finding fields
    rule_id: str
    title: str
    severity: str
    description: str
    suggestion: str
    impact_score: float

    # Application context
    endpoint: str = ""
    service: str = ""
    frequency_per_min: float = 0
    total_load_ms_per_min: float = 0
    is_hot_path: bool = False
    source_location: str = ""
    trace_id: str = ""
    adjusted_priority: float = 0  # Priority considering app context
    # v2 additions
    session_count: int = 0  # how many user sessions hit this
    error_rate: float = 0
    n_plus_one: bool = False
    http_method: str = ""
    db_load_pct: float = 0  # % of endpoint time spent in DB

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "suggestion": self.suggestion,
            "impact_score": self.impact_score,
            "endpoint": self.endpoint,
            "service": self.service,
            "frequency_per_min": self.frequency_per_min,
            "total_load_ms_per_min": self.total_load_ms_per_min,
            "is_hot_path": self.is_hot_path,
            "source_location": self.source_location,
            "trace_id": self.trace_id,
            "adjusted_priority": self.adjusted_priority,
            "session_count": self.session_count,
            "error_rate": self.error_rate,
            "n_plus_one": self.n_plus_one,
            "http_method": self.http_method,
            "db_load_pct": self.db_load_pct,
        }


def _sql_fingerprint(sql: str) -> str:
    """Normalize SQL into a fingerprint for matching."""
    # Replace literals with placeholders
    normalized = re.sub(r"'[^']*'", "'?'", sql)
    normalized = re.sub(r"\b\d+\b", "?", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip().lower()
    return hashlib.md5(normalized.encode()).hexdigest()[:16]


class AppContextCorrelator:
    """
    Correlate EXPLAIN findings with application-level context.

    Maintains a registry of known queries and their application context
    (endpoints, frequency, latency). When findings come in, enriches
    them with this context and adjusts priority scores.

    v2 capabilities:
    - User session tracking and per-session DB impact
    - Endpoint-level aggregated metrics
    - N+1 query pattern detection within traces
    - Full-stack waterfall construction (browser → API → DB)
    - Error correlation
    - Connection pool awareness
    """

    def __init__(self) -> None:
        self._contexts: dict[str, QueryContext] = {}
        self._fingerprint_map: dict[str, str] = {}
        # v2: session tracking
        self._sessions: dict[str, UserSession] = {}
        # v2: endpoint metrics accumulator
        self._endpoint_queries: dict[str, list[dict[str, Any]]] = defaultdict(list)
        # v2: per-trace query tracking for N+1 detection
        self._trace_queries: dict[str, list[dict[str, Any]]] = defaultdict(list)
        # v2: waterfall spans
        self._waterfall_spans: dict[str, list[WaterfallSpan]] = defaultdict(list)

    def register_query(
        self,
        sql_fingerprint: str,
        endpoint: str = "",
        service: str = "",
        frequency_per_min: float = 0,
        p50_latency_ms: float = 0,
        p99_latency_ms: float = 0,
        error_rate: float = 0,
        trace_id: str = "",
        source_file: str = "",
        caller_function: str = "",
        # v2 additions
        session_id: str = "",
        http_method: str = "",
        http_status: int = 0,
        connection_pool: str = "",
        db_name: str = "",
        db_user: str = "",
    ) -> QueryContext:
        """Register application context for a query fingerprint."""
        fp = _sql_fingerprint(sql_fingerprint)

        if fp in self._contexts:
            ctx = self._contexts[fp]
            # Update with latest data
            ctx.frequency_per_min = frequency_per_min or ctx.frequency_per_min
            ctx.p50_latency_ms = p50_latency_ms or ctx.p50_latency_ms
            ctx.p99_latency_ms = p99_latency_ms or ctx.p99_latency_ms
            ctx.error_rate = error_rate or ctx.error_rate
            ctx.last_seen = time.time()
            if trace_id and trace_id not in ctx.trace_ids:
                ctx.trace_ids.append(trace_id)
                if len(ctx.trace_ids) > 10:
                    ctx.trace_ids = ctx.trace_ids[-10:]
            if session_id and session_id not in ctx.session_ids:
                ctx.session_ids.append(session_id)
                if len(ctx.session_ids) > 50:
                    ctx.session_ids = ctx.session_ids[-50:]
            if http_method:
                ctx.http_method = http_method
            if http_status:
                ctx.http_status_codes.append(http_status)
                if len(ctx.http_status_codes) > 100:
                    ctx.http_status_codes = ctx.http_status_codes[-100:]
        else:
            ctx = QueryContext(
                sql_fingerprint=sql_fingerprint,
                endpoint=endpoint,
                service=service,
                frequency_per_min=frequency_per_min,
                p50_latency_ms=p50_latency_ms,
                p99_latency_ms=p99_latency_ms,
                error_rate=error_rate,
                last_seen=time.time(),
                trace_ids=[trace_id] if trace_id else [],
                source_file=source_file,
                caller_function=caller_function,
                session_ids=[session_id] if session_id else [],
                http_method=http_method,
                http_status_codes=[http_status] if http_status else [],
                connection_pool=connection_pool,
                db_name=db_name,
                db_user=db_user,
            )
            self._contexts[fp] = ctx

        self._fingerprint_map[sql_fingerprint] = fp

        # Track endpoint queries
        if endpoint:
            self._endpoint_queries[endpoint].append({
                "fingerprint": fp,
                "latency_ms": p50_latency_ms,
                "trace_id": trace_id,
                "timestamp": time.time(),
            })

        # Track queries per trace for N+1 detection
        if trace_id:
            self._trace_queries[trace_id].append({
                "fingerprint": fp,
                "sql": sql_fingerprint,
                "latency_ms": p50_latency_ms,
                "endpoint": endpoint,
            })

        # Update session if provided
        if session_id:
            self._update_session(
                session_id=session_id,
                trace_id=trace_id,
                endpoint=endpoint,
                db_time_ms=p50_latency_ms,
                error=(http_status >= 400) if http_status else False,
            )

        return ctx

    def get_context(self, sql: str) -> QueryContext | None:
        """Look up application context for a SQL query."""
        fp = _sql_fingerprint(sql)
        return self._contexts.get(fp)

    # ── User Session Tracking ─────────────────────────────────────────

    def register_session(
        self,
        session_id: str,
        user_id: str = "",
        user_agent: str = "",
        ip_address: str = "",
    ) -> UserSession:
        """Register or update a user session."""
        if session_id not in self._sessions:
            self._sessions[session_id] = UserSession(
                session_id=session_id,
                user_id=user_id,
                started_at=time.time(),
                last_active=time.time(),
                user_agent=user_agent,
                ip_address=ip_address,
            )
        else:
            session = self._sessions[session_id]
            session.last_active = time.time()
            if user_id:
                session.user_id = user_id

        return self._sessions[session_id]

    def _update_session(
        self,
        session_id: str,
        trace_id: str = "",
        endpoint: str = "",
        db_time_ms: float = 0,
        error: bool = False,
    ) -> None:
        """Update session with new query activity."""
        if session_id not in self._sessions:
            self.register_session(session_id)

        session = self._sessions[session_id]
        session.last_active = time.time()
        session.total_queries += 1
        session.total_db_time_ms += db_time_ms

        if trace_id and trace_id not in session.trace_ids:
            session.trace_ids.append(trace_id)
            if len(session.trace_ids) > 100:
                session.trace_ids = session.trace_ids[-100:]

        if endpoint:
            session.distinct_endpoints.add(endpoint)

        if error:
            session.error_count += 1

    def get_session(self, session_id: str) -> UserSession | None:
        """Get a user session by ID."""
        return self._sessions.get(session_id)

    def active_sessions(self, since_seconds: float = 300) -> list[UserSession]:
        """Get sessions active in the last N seconds."""
        cutoff = time.time() - since_seconds
        return sorted(
            [s for s in self._sessions.values() if s.last_active >= cutoff],
            key=lambda s: s.total_db_time_ms,
            reverse=True,
        )

    def heaviest_sessions(self, top_n: int = 10) -> list[UserSession]:
        """Get sessions with the most DB impact."""
        return sorted(
            self._sessions.values(),
            key=lambda s: s.total_db_time_ms,
            reverse=True,
        )[:top_n]

    # ── Endpoint-Level Metrics ────────────────────────────────────────

    def endpoint_metrics(self, endpoint: str) -> EndpointMetrics:
        """Compute aggregated database metrics for an API endpoint."""
        queries = self._endpoint_queries.get(endpoint, [])
        if not queries:
            return EndpointMetrics(endpoint=endpoint)

        latencies = [q["latency_ms"] for q in queries if q["latency_ms"] > 0]
        fingerprints = set(q["fingerprint"] for q in queries)
        trace_ids = set(q["trace_id"] for q in queries if q["trace_id"])

        # Compute percentiles
        sorted_lat = sorted(latencies) if latencies else [0]
        p50 = sorted_lat[len(sorted_lat) // 2] if sorted_lat else 0
        p95 = sorted_lat[int(len(sorted_lat) * 0.95)] if sorted_lat else 0
        p99 = sorted_lat[int(len(sorted_lat) * 0.99)] if sorted_lat else 0

        # Queries per request (approx)
        queries_per_req = len(queries) / max(len(trace_ids), 1)

        # Find hottest query
        fp_times: dict[str, float] = defaultdict(float)
        for q in queries:
            fp_times[q["fingerprint"]] += q["latency_ms"]
        total_time = sum(fp_times.values())
        hottest_fp = max(fp_times, key=fp_times.get) if fp_times else ""  # type: ignore[arg-type]
        hottest_pct = (fp_times[hottest_fp] / total_time * 100) if total_time > 0 else 0

        # Check for N+1
        n_plus_one = queries_per_req > 5 and len(fingerprints) < 3

        # Look up service from contexts
        service = ""
        for fp in fingerprints:
            ctx = self._contexts.get(fp)
            if ctx and ctx.service:
                service = ctx.service
                break

        return EndpointMetrics(
            endpoint=endpoint,
            service=service,
            total_queries=len(queries),
            distinct_query_fingerprints=len(fingerprints),
            total_db_time_ms=sum(latencies),
            avg_db_time_ms=sum(latencies) / len(latencies) if latencies else 0,
            p50_db_time_ms=p50,
            p95_db_time_ms=p95,
            p99_db_time_ms=p99,
            queries_per_request=queries_per_req,
            n_plus_one_detected=n_plus_one,
            hottest_query=hottest_fp,
            hottest_query_pct=hottest_pct,
        )

    def all_endpoint_metrics(self) -> list[EndpointMetrics]:
        """Get metrics for all tracked endpoints, sorted by total DB time."""
        metrics = [
            self.endpoint_metrics(ep)
            for ep in self._endpoint_queries
        ]
        return sorted(metrics, key=lambda m: m.total_db_time_ms, reverse=True)

    # ── N+1 Detection ─────────────────────────────────────────────────

    def detect_n_plus_one(self, threshold: int = 5) -> list[NPlusOneDetection]:
        """
        Detect N+1 query patterns across all traces.

        An N+1 pattern is when the same query fingerprint appears
        more than `threshold` times within a single trace.
        """
        detections: list[NPlusOneDetection] = []

        for trace_id, queries in self._trace_queries.items():
            # Count fingerprint occurrences
            fp_counts: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for q in queries:
                fp_counts[q["fingerprint"]].append(q)

            for fp, instances in fp_counts.items():
                if len(instances) >= threshold:
                    total_time = sum(i["latency_ms"] for i in instances)
                    endpoint = instances[0].get("endpoint", "")
                    sql_sample = instances[0].get("sql", "")

                    detections.append(NPlusOneDetection(
                        trace_id=trace_id,
                        endpoint=endpoint,
                        query_fingerprint=sql_sample[:100],
                        repetition_count=len(instances),
                        total_time_ms=total_time,
                        suggestion=(
                            f"Query executed {len(instances)} times in one request. "
                            f"Consider batch loading with IN clause or JOIN, "
                            f"or use a DataLoader pattern."
                        ),
                    ))

                    # Mark sessions
                    for session in self._sessions.values():
                        if trace_id in session.trace_ids:
                            session.n_plus_one_count += 1

        return sorted(detections, key=lambda d: d.total_time_ms, reverse=True)

    # ── Full-Stack Waterfall ──────────────────────────────────────────

    def build_waterfall(self, trace_id: str) -> list[WaterfallSpan]:
        """
        Build a full-stack waterfall for a trace.

        Returns spans ordered by start time, suitable for rendering
        as a timeline: browser → API → middleware → DB.
        """
        return sorted(
            self._waterfall_spans.get(trace_id, []),
            key=lambda s: s.start_ms,
        )

    def register_waterfall_span(
        self,
        trace_id: str,
        span_id: str,
        parent_span_id: str | None,
        service: str,
        operation: str,
        layer: str,
        start_ms: float,
        duration_ms: float,
        status: str = "ok",
        attributes: dict[str, Any] | None = None,
    ) -> WaterfallSpan:
        """Register a span for waterfall visualization."""
        span = WaterfallSpan(
            span_id=span_id,
            parent_span_id=parent_span_id,
            service=service,
            operation=operation,
            layer=layer,
            start_ms=start_ms,
            duration_ms=duration_ms,
            status=status,
            attributes=attributes or {},
        )
        self._waterfall_spans[trace_id].append(span)
        return span

    # ── Enrich Findings ───────────────────────────────────────────────

    def enrich_findings(
        self,
        findings: list[Any],
        sql: str = "",
    ) -> list[EnrichedFinding]:
        """
        Enrich QuerySense findings with application context.

        Each finding gets:
        - endpoint / service / frequency info
        - adjusted_priority: impact_score * frequency_weight * error_weight
        - is_hot_path flag
        - source_location link
        - session_count: how many user sessions are affected
        - n_plus_one flag
        - error_rate correlation
        """
        ctx = self.get_context(sql) if sql else None

        # Check for N+1 if context exists
        n_plus_one_detected = False
        if ctx:
            for trace_id in ctx.trace_ids[-5:]:
                queries = self._trace_queries.get(trace_id, [])
                fp = _sql_fingerprint(sql)
                count = sum(1 for q in queries if q["fingerprint"] == fp)
                if count >= 5:
                    n_plus_one_detected = True
                    break

        enriched: list[EnrichedFinding] = []
        for finding in findings:
            # Extract finding attributes (works with Finding dataclass or dict)
            if isinstance(finding, dict):
                rule_id = finding.get("rule_id", "")
                title = finding.get("title", "")
                severity = finding.get("severity", "info")
                description = finding.get("description", "")
                suggestion = finding.get("suggestion", "")
                impact_score = finding.get("impact_score", 0)
            else:
                rule_id = getattr(finding, "rule_id", "")
                title = getattr(finding, "title", "")
                severity = getattr(finding, "severity", "info")
                if hasattr(severity, "value"):
                    severity = severity.value
                description = getattr(finding, "description", "")
                suggestion = getattr(finding, "suggestion", "")
                impact_score = getattr(finding, "impact_score", 0)

            # Calculate adjusted priority (v2: includes error weight)
            freq_weight = 1.0
            error_weight = 1.0
            if ctx and ctx.frequency_per_min > 0:
                # Log scale: 10 calls/min = 1.0x, 100 = 2.0x, 1000 = 3.0x
                freq_weight = 1.0 + math.log10(max(ctx.frequency_per_min, 1))
            if ctx and ctx.error_rate > 0:
                # Errors boost priority: 5% error rate = 1.5x, 50% = 2.5x
                error_weight = 1.0 + min(1.5, ctx.error_rate * 3)

            adjusted = min(10.0, impact_score * freq_weight * error_weight)

            # N+1 detection boost
            if n_plus_one_detected:
                adjusted = min(10.0, adjusted * 1.5)

            ef = EnrichedFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                description=description,
                suggestion=suggestion,
                impact_score=impact_score,
                adjusted_priority=adjusted,
                n_plus_one=n_plus_one_detected,
            )

            if ctx:
                ef.endpoint = ctx.endpoint
                ef.service = ctx.service
                ef.frequency_per_min = ctx.frequency_per_min
                ef.total_load_ms_per_min = ctx.total_load_ms_per_min
                ef.is_hot_path = ctx.is_hot_path
                ef.source_location = (
                    f"{ctx.source_file}:{ctx.caller_function}"
                    if ctx.source_file else ""
                )
                ef.trace_id = ctx.trace_ids[-1] if ctx.trace_ids else ""
                ef.session_count = len(ctx.session_ids)
                ef.error_rate = ctx.error_rate
                ef.http_method = ctx.http_method

            enriched.append(ef)

        # Sort by adjusted priority (highest first)
        enriched.sort(key=lambda e: e.adjusted_priority, reverse=True)
        return enriched

    # ── OTel Import (v2: enhanced) ────────────────────────────────────

    def import_from_otel(self, spans: list[dict[str, Any]]) -> int:
        """
        Import query context from OpenTelemetry span data.

        v2: Also builds waterfall spans and detects sessions.

        Expects spans with:
        - attributes.db.statement: SQL query
        - attributes.http.route: endpoint
        - attributes.service.name: service
        - duration: span duration in nanoseconds
        - traceId: trace ID
        - attributes.session.id: session ID (optional)
        - attributes.enduser.id: user ID (optional)

        Returns count of queries registered.
        """
        frequency_counter: dict[str, int] = defaultdict(int)
        latency_collector: dict[str, list[float]] = defaultdict(list)
        span_info: dict[str, dict[str, Any]] = {}

        for span in spans:
            attrs = span.get("attributes", {})
            span_id = span.get("spanId", "")
            parent_span_id = span.get("parentSpanId", None)
            trace_id = span.get("traceId", "")
            duration_ns = span.get("duration", 0)
            duration_ms = duration_ns / 1_000_000
            start_ns = span.get("startTime", 0)

            sql = attrs.get("db.statement", "")
            service = attrs.get("service.name", "")
            endpoint = attrs.get("http.route", attrs.get("http.target", ""))
            session_id = attrs.get("session.id", "")
            user_id = attrs.get("enduser.id", "")
            http_method = attrs.get("http.method", "")
            http_status = int(attrs.get("http.status_code", 0) or 0)

            # Register session if present
            if session_id:
                self.register_session(
                    session_id=session_id,
                    user_id=user_id,
                    user_agent=attrs.get("http.user_agent", ""),
                )

            # Build waterfall span
            if trace_id and span_id:
                layer = "database" if sql else ("api" if endpoint else "middleware")
                operation = sql[:80] if sql else (f"{http_method} {endpoint}" if endpoint else service)
                self.register_waterfall_span(
                    trace_id=trace_id,
                    span_id=span_id,
                    parent_span_id=parent_span_id,
                    service=service,
                    operation=operation,
                    layer=layer,
                    start_ms=start_ns / 1_000_000,
                    duration_ms=duration_ms,
                    status="error" if http_status >= 400 else "ok",
                    attributes={
                        k: v for k, v in attrs.items()
                        if k in ("db.system", "db.name", "net.peer.name", "http.method")
                    },
                )

            # Only process DB spans for query registration
            if not sql:
                continue

            fp = _sql_fingerprint(sql)
            frequency_counter[fp] += 1
            latency_collector[fp].append(duration_ms)

            if fp not in span_info:
                span_info[fp] = {
                    "sql": sql,
                    "endpoint": endpoint,
                    "service": service,
                    "trace_id": trace_id,
                    "source_file": attrs.get("code.filepath", ""),
                    "caller_function": attrs.get("code.function", ""),
                    "session_id": session_id,
                    "http_method": http_method,
                    "http_status": http_status,
                    "connection_pool": attrs.get("db.connection_string", ""),
                    "db_name": attrs.get("db.name", ""),
                    "db_user": attrs.get("db.user", ""),
                }

        count = 0
        for fp, info in span_info.items():
            latencies = sorted(latency_collector.get(fp, []))
            p50 = latencies[len(latencies) // 2] if latencies else 0
            p99 = latencies[int(len(latencies) * 0.99)] if latencies else 0

            self.register_query(
                sql_fingerprint=info["sql"],
                endpoint=info["endpoint"],
                service=info["service"],
                frequency_per_min=frequency_counter.get(fp, 0),
                p50_latency_ms=p50,
                p99_latency_ms=p99,
                trace_id=info["trace_id"],
                source_file=info["source_file"],
                caller_function=info["caller_function"],
                session_id=info["session_id"],
                http_method=info["http_method"],
                http_status=info["http_status"],
                connection_pool=info["connection_pool"],
                db_name=info["db_name"],
                db_user=info["db_user"],
            )
            count += 1

        return count

    def summary(self) -> dict[str, Any]:
        """Return comprehensive summary statistics (v2)."""
        contexts = list(self._contexts.values())
        if not contexts:
            return {"total_queries": 0}

        # N+1 detections
        n_plus_ones = self.detect_n_plus_one()

        return {
            "total_queries": len(contexts),
            "hot_path_queries": sum(1 for c in contexts if c.is_hot_path),
            "total_load_ms_per_min": sum(c.total_load_ms_per_min for c in contexts),
            "top_endpoints": sorted(
                set(c.endpoint for c in contexts if c.endpoint),
                key=lambda ep: sum(
                    c.total_load_ms_per_min for c in contexts if c.endpoint == ep
                ),
                reverse=True,
            )[:10],
            "services": list(set(c.service for c in contexts if c.service)),
            # v2 additions
            "active_sessions": len(self.active_sessions()),
            "total_sessions": len(self._sessions),
            "n_plus_one_detections": len(n_plus_ones),
            "endpoints_tracked": len(self._endpoint_queries),
            "traces_tracked": len(self._trace_queries),
        }


def create_otel_span_processor(correlator: AppContextCorrelator) -> Any:
    """
    Create an OpenTelemetry SpanProcessor that feeds query context
    into QuerySense's correlator.

    v2: Also captures session IDs, HTTP metadata, connection pool info,
    and builds full-stack waterfall spans.

    Usage:
        from opentelemetry import trace
        from querysense.app_context import AppContextCorrelator, create_otel_span_processor

        correlator = AppContextCorrelator()
        processor = create_otel_span_processor(correlator)
        trace.get_tracer_provider().add_span_processor(processor)
    """
    try:
        from opentelemetry.sdk.trace import SpanProcessor
        from opentelemetry.trace import StatusCode
    except ImportError:
        raise ImportError(
            "OpenTelemetry SDK required: pip install opentelemetry-sdk"
        )

    class QuerySenseSpanProcessor(SpanProcessor):
        """OTel SpanProcessor that registers DB queries and builds waterfalls."""

        def on_end(self, span: Any) -> None:
            attrs = dict(span.attributes or {})
            sql = attrs.get("db.statement", "")

            duration_ms = 0
            start_ms = 0
            if span.end_time and span.start_time:
                duration_ms = (span.end_time - span.start_time) / 1_000_000
                start_ms = span.start_time / 1_000_000

            trace_id = format(span.context.trace_id, "032x") if span.context else ""
            span_id = format(span.context.span_id, "016x") if span.context else ""
            parent_id = format(span.parent.span_id, "016x") if span.parent else None
            service = str(attrs.get("service.name", ""))
            endpoint = str(attrs.get("http.route", attrs.get("http.target", "")))
            session_id = str(attrs.get("session.id", ""))
            http_method = str(attrs.get("http.method", ""))
            http_status = int(attrs.get("http.status_code", 0) or 0)

            # Build waterfall span for ALL spans (not just DB)
            if trace_id and span_id:
                layer = "database" if sql else ("api" if endpoint else "middleware")
                operation = str(sql)[:80] if sql else (
                    f"{http_method} {endpoint}" if endpoint else span.name
                )
                correlator.register_waterfall_span(
                    trace_id=trace_id,
                    span_id=span_id,
                    parent_span_id=parent_id,
                    service=service,
                    operation=operation,
                    layer=layer,
                    start_ms=start_ms,
                    duration_ms=duration_ms,
                    status="error" if http_status >= 400 else "ok",
                )

            # Register DB query with enriched context
            if sql:
                correlator.register_query(
                    sql_fingerprint=str(sql),
                    endpoint=endpoint,
                    service=service,
                    p50_latency_ms=duration_ms,
                    trace_id=trace_id,
                    source_file=str(attrs.get("code.filepath", "")),
                    caller_function=str(attrs.get("code.function", "")),
                    session_id=session_id,
                    http_method=http_method,
                    http_status=http_status,
                    connection_pool=str(attrs.get("db.connection_string", "")),
                    db_name=str(attrs.get("db.name", "")),
                    db_user=str(attrs.get("db.user", "")),
                )

            # Register session from HTTP spans
            if session_id and endpoint:
                user_id = str(attrs.get("enduser.id", ""))
                correlator.register_session(
                    session_id=session_id,
                    user_id=user_id,
                    user_agent=str(attrs.get("http.user_agent", "")),
                )

        def on_start(self, span: Any, parent_context: Any = None) -> None:
            pass

        def shutdown(self) -> None:
            pass

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            return True

    return QuerySenseSpanProcessor()
