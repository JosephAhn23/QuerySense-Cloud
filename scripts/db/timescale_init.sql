-- TimescaleDB initialization for QuerySense query metrics
-- This runs automatically on first docker-compose up

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Query performance metrics (time-series)
CREATE TABLE IF NOT EXISTS query_metrics (
    time TIMESTAMPTZ NOT NULL,
    workspace_id TEXT NOT NULL,
    plan_id TEXT,
    query_hash TEXT NOT NULL,
    execution_time_ms DOUBLE PRECISION,
    rows_scanned BIGINT,
    rows_returned BIGINT,
    index_usage_pct DOUBLE PRECISION,
    cost DOUBLE PRECISION,
    findings_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    metadata JSONB
);

-- Convert to hypertable (time-series optimized)
SELECT create_hypertable('query_metrics', 'time', if_not_exists => TRUE);

-- Indexes for fast queries
CREATE INDEX IF NOT EXISTS idx_metrics_workspace_time
    ON query_metrics (workspace_id, time DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_query_hash
    ON query_metrics (query_hash, time DESC);

-- Continuous aggregate: hourly rollups
CREATE MATERIALIZED VIEW IF NOT EXISTS metrics_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', time) AS bucket,
    workspace_id,
    query_hash,
    AVG(execution_time_ms) AS avg_execution_time,
    MAX(execution_time_ms) AS max_execution_time,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY execution_time_ms) AS p95_execution_time,
    AVG(rows_scanned) AS avg_rows_scanned,
    AVG(index_usage_pct) AS avg_index_usage,
    AVG(cost) AS avg_cost,
    SUM(findings_count) AS total_findings,
    COUNT(*) AS sample_count
FROM query_metrics
GROUP BY bucket, workspace_id, query_hash;

-- Continuous aggregate: daily rollups for long-range trends
CREATE MATERIALIZED VIEW IF NOT EXISTS metrics_daily
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', time) AS bucket,
    workspace_id,
    query_hash,
    AVG(execution_time_ms) AS avg_execution_time,
    MAX(execution_time_ms) AS max_execution_time,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY execution_time_ms) AS p95_execution_time,
    AVG(rows_scanned) AS avg_rows_scanned,
    AVG(index_usage_pct) AS avg_index_usage,
    AVG(cost) AS avg_cost,
    SUM(findings_count) AS total_findings,
    COUNT(*) AS sample_count
FROM query_metrics
GROUP BY bucket, workspace_id, query_hash;

-- Retention policy: auto-delete raw data older than 90 days
-- (aggregated data in continuous aggregates is kept longer)
SELECT add_retention_policy('query_metrics', INTERVAL '90 days', if_not_exists => TRUE);

-- Refresh policies for continuous aggregates
SELECT add_continuous_aggregate_policy('metrics_hourly',
    start_offset => INTERVAL '3 hours',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

SELECT add_continuous_aggregate_policy('metrics_daily',
    start_offset => INTERVAL '3 days',
    end_offset => INTERVAL '1 day',
    schedule_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);
