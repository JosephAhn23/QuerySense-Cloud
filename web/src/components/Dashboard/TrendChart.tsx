/**
 * Performance trend chart using Recharts.
 *
 * Displays time-series query metrics with:
 * - Execution time / cost / index usage trends
 * - Anomaly markers (3-sigma detection from backend)
 * - Responsive layout for mobile
 */

import { useEffect, useState } from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceDot,
  CartesianGrid,
} from 'recharts';
import { api, type TrendPoint } from '../../services/api';

interface TrendChartProps {
  workspaceId: string;
  timeRange?: '1h' | '6h' | '24h' | '7d' | '30d' | '90d';
  metric?: 'execution_time' | 'cost' | 'index_usage';
  height?: number;
}

export const TrendChart: React.FC<TrendChartProps> = ({
  workspaceId,
  timeRange = '7d',
  metric = 'execution_time',
  height = 300,
}) => {
  const [data, setData] = useState<TrendPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [summary, setSummary] = useState<Record<string, unknown>>({});

  useEffect(() => {
    setLoading(true);
    api
      .getWorkspaceTrends(workspaceId, timeRange)
      .then((response) => {
        setData(response.points);
        setSummary(response.summary);
      })
      .catch(() => setData([]))
      .finally(() => setLoading(false));
  }, [workspaceId, timeRange]);

  if (loading) {
    return (
      <div
        className="animate-pulse bg-gray-200 rounded-lg"
        style={{ height }}
      />
    );
  }

  if (data.length === 0) {
    return (
      <div
        className="flex items-center justify-center bg-gray-50 rounded-lg border border-dashed border-gray-300 text-gray-500"
        style={{ height }}
      >
        No metric data yet. Analyze some plans to see trends.
      </div>
    );
  }

  const dataKey =
    metric === 'execution_time'
      ? 'avg_execution_time_ms'
      : metric === 'cost'
        ? 'avg_cost'
        : 'avg_index_usage_pct';

  const anomalies = data.filter((d) => d.anomaly);
  const trendLabel =
    (summary.trend as string) === 'improving'
      ? 'Improving'
      : (summary.trend as string) === 'degrading'
        ? 'Degrading'
        : 'Stable';

  const trendColor =
    (summary.trend as string) === 'improving'
      ? 'text-green-600'
      : (summary.trend as string) === 'degrading'
        ? 'text-red-600'
        : 'text-gray-600';

  return (
    <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-100">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-gray-700">
          {metric.replace('_', ' ')} Trend
        </h3>
        <div className="flex items-center gap-3 text-xs">
          {summary.mean_ms != null && (
            <span className="text-gray-500">
              Mean: {(summary.mean_ms as number).toFixed(1)}ms
            </span>
          )}
          {summary.p95_ms != null && (
            <span className="text-gray-500">
              P95: {(summary.p95_ms as number).toFixed(1)}ms
            </span>
          )}
          <span className={`font-medium ${trendColor}`}>
            {trendLabel}
            {summary.trend_pct != null && (
              <> ({(summary.trend_pct as number) > 0 ? '+' : ''}
              {(summary.trend_pct as number).toFixed(1)}%)</>
            )}
          </span>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
          <XAxis
            dataKey="timestamp"
            tickFormatter={(ts: string) => {
              const d = new Date(ts);
              return timeRange === '24h' || timeRange === '1h'
                ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                : d.toLocaleDateString([], { month: 'short', day: 'numeric' });
            }}
            tick={{ fontSize: 11 }}
            stroke="#94a3b8"
          />
          <YAxis tick={{ fontSize: 11 }} stroke="#94a3b8" />
          <Tooltip
            labelFormatter={(ts: string) => new Date(ts).toLocaleString()}
            formatter={(value: number) => [
              `${value.toFixed(2)}${metric === 'index_usage' ? '%' : 'ms'}`,
              metric.replace('_', ' '),
            ]}
          />
          <Line
            type="monotone"
            dataKey={dataKey}
            stroke="#3b82f6"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 4 }}
          />
          {/* Anomaly markers */}
          {anomalies.map((a, i) => (
            <ReferenceDot
              key={i}
              x={a.timestamp}
              y={a[dataKey as keyof TrendPoint] as number}
              r={5}
              fill="#dc2626"
              stroke="#fff"
              strokeWidth={2}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>

      {anomalies.length > 0 && (
        <p className="mt-2 text-xs text-red-600">
          {anomalies.length} anomal{anomalies.length === 1 ? 'y' : 'ies'} detected
        </p>
      )}
    </div>
  );
};
