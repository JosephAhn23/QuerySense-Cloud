/**
 * Main workspace dashboard — the landing page.
 *
 * Shows:
 * - Quick analyze panel (paste EXPLAIN plan)
 * - Performance trend chart
 * - Recent plans list
 * - Activity feed
 */

import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { TrendChart } from './TrendChart';
import { api, type ActivityItem } from '../../services/api';
import { useWebSocket } from '../../hooks/useWebSocket';
import { useWorkspaceStore } from '../../store/workspaceStore';

export const WorkspaceDashboard: React.FC = () => {
  const navigate = useNavigate();
  const workspaceId = useWorkspaceStore((s) => s.workspaceId);
  const [recentPlans, setRecentPlans] = useState<
    Array<{ id: string; title: string; created_at: string; findings_count: number }>
  >([]);
  const [activities, setActivities] = useState<ActivityItem[]>([]);
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d'>('7d');

  // Real-time updates via WebSocket
  const { lastEvent } = useWebSocket(
    workspaceId ? `/api/v1/ws/workspace/${workspaceId}` : '',
    { reconnect: !!workspaceId },
  );

  // Fetch recent plans
  useEffect(() => {
    api
      .listPlans(0, 10)
      .then((res) => setRecentPlans(res.items))
      .catch(() => {});
  }, [lastEvent]);

  // Fetch activity feed
  useEffect(() => {
    if (!workspaceId) return;
    api
      .getActivity(workspaceId, 20)
      .then((res) => setActivities(res.items))
      .catch(() => {});
  }, [workspaceId, lastEvent]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
          <p className="text-sm text-gray-500 mt-1">
            Query performance overview and team activity
          </p>
        </div>
        <button
          onClick={() => navigate('/analyze')}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium text-sm"
        >
          + Analyze Plan
        </button>
      </div>

      {/* Trend Chart */}
      {workspaceId && (
        <div>
          <div className="flex items-center gap-2 mb-3">
            <h2 className="text-lg font-semibold text-gray-800">
              Performance Trends
            </h2>
            <div className="flex gap-1 ml-auto">
              {(['24h', '7d', '30d'] as const).map((range) => (
                <button
                  key={range}
                  onClick={() => setTimeRange(range)}
                  className={`px-2 py-1 text-xs rounded ${
                    timeRange === range
                      ? 'bg-blue-100 text-blue-700 font-medium'
                      : 'text-gray-500 hover:bg-gray-100'
                  }`}
                >
                  {range}
                </button>
              ))}
            </div>
          </div>
          <TrendChart
            workspaceId={workspaceId}
            timeRange={timeRange}
            height={250}
          />
        </div>
      )}

      {/* Two-column layout: Plans + Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Plans */}
        <div className="lg:col-span-2">
          <h2 className="text-lg font-semibold text-gray-800 mb-3">
            Recent Plans
          </h2>
          <div className="bg-white rounded-lg shadow-sm border border-gray-100 divide-y divide-gray-100">
            {recentPlans.length === 0 ? (
              <div className="p-6 text-center text-gray-500">
                No plans yet. Click "Analyze Plan" to get started.
              </div>
            ) : (
              recentPlans.map((plan) => (
                <button
                  key={plan.id}
                  onClick={() => navigate(`/plans/${plan.id}`)}
                  className="w-full flex items-center justify-between p-4 hover:bg-gray-50 transition-colors text-left"
                >
                  <div>
                    <p className="font-medium text-gray-900">{plan.title}</p>
                    <p className="text-xs text-gray-500 mt-0.5">
                      {new Date(plan.created_at).toLocaleDateString()}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    {plan.findings_count > 0 && (
                      <span className="px-2 py-0.5 text-xs rounded-full bg-amber-100 text-amber-800">
                        {plan.findings_count} issue{plan.findings_count !== 1 ? 's' : ''}
                      </span>
                    )}
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Activity Feed */}
        <div>
          <h2 className="text-lg font-semibold text-gray-800 mb-3">
            Activity
          </h2>
          <div className="bg-white rounded-lg shadow-sm border border-gray-100 p-4 space-y-3">
            {activities.length === 0 ? (
              <p className="text-sm text-gray-500">No recent activity.</p>
            ) : (
              activities.slice(0, 15).map((a) => (
                <div key={a.id} className="flex items-start gap-2">
                  <div className="w-2 h-2 rounded-full bg-blue-400 mt-1.5 shrink-0" />
                  <div>
                    <p className="text-sm text-gray-700">
                      <span className="font-medium">{a.user_name}</span>{' '}
                      {formatAction(a.action)}
                    </p>
                    <p className="text-xs text-gray-400">
                      {new Date(a.created_at).toLocaleString()}
                    </p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

function formatAction(action: string): string {
  const map: Record<string, string> = {
    plan_uploaded: 'uploaded a plan',
    comment_added: 'commented on a plan',
    analysis_run: 'ran an analysis',
    share_created: 'shared a plan',
  };
  return map[action] || action.replace(/_/g, ' ');
}
