"""
Prometheus metrics API endpoint.

    GET /api/v1/metrics

Returns metrics in Prometheus exposition format for scraping.
What Datadog charges $70/host for, we serve for free.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

router = APIRouter()


@router.get(
    "/metrics",
    response_class=PlainTextResponse,
    summary="Prometheus metrics endpoint",
)
async def get_metrics() -> PlainTextResponse:
    """
    Return QuerySense metrics in Prometheus exposition format.

    Can be scraped by Prometheus, Grafana Agent, Datadog Agent,
    or any OpenMetrics-compatible collector.

    **Prometheus scrape config:**
    ```yaml
    scrape_configs:
      - job_name: 'querysense'
        metrics_path: '/api/v1/metrics'
        static_configs:
          - targets: ['localhost:8000']
    ```
    """
    from querysense.metrics.prometheus import PrometheusExporter
    from querysense import __version__

    exporter = PrometheusExporter()
    exporter.record_build_info(__version__)

    # Try to load from default history DB
    try:
        exporter.from_history_db("~/.querysense/default.db", days=7)
    except Exception:
        pass

    return PlainTextResponse(
        content=exporter.render(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
