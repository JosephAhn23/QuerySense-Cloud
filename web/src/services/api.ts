/**
 * QuerySense API client.
 *
 * Thin typed wrapper over fetch() — talks to the FastAPI backend.
 * Handles auth tokens, error normalization, and plan size validation.
 */

const API_BASE = '/api/v1';

interface ApiError {
  detail: string;
  status: number;
}

class QuerySenseAPI {
  private token: string | null = null;

  setToken(token: string) {
    this.token = token;
  }

  private async request<T>(
    path: string,
    options: RequestInit = {},
  ): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers,
      credentials: 'include',
    });

    if (!response.ok) {
      const error: ApiError = {
        detail: 'Request failed',
        status: response.status,
      };
      try {
        const body = await response.json();
        error.detail = body.detail || error.detail;
      } catch {
        // Response body wasn't JSON
      }
      throw error;
    }

    return response.json();
  }

  // ── Analysis ──────────────────────────────────────────────────────

  async analyze(planJson: string, sql?: string) {
    return this.request<AnalysisResult>('/analyze', {
      method: 'POST',
      body: JSON.stringify({ plan_json: planJson, sql }),
    });
  }

  async compare(baselineJson: string, currentJson: string) {
    return this.request<CompareResult>('/compare', {
      method: 'POST',
      body: JSON.stringify({
        baseline_json: baselineJson,
        current_json: currentJson,
      }),
    });
  }

  // ── Plans ─────────────────────────────────────────────────────────

  async listPlans(offset = 0, limit = 20, search?: string) {
    const params = new URLSearchParams({
      offset: String(offset),
      limit: String(limit),
    });
    if (search) params.set('search', search);
    return this.request<PlanListResponse>(`/plans?${params}`);
  }

  async getPlan(planId: string) {
    return this.request<PlanDetail>(`/plans/${planId}`);
  }

  async uploadPlan(planJson: string, title: string, sql?: string) {
    return this.request<PlanDetail>('/plans', {
      method: 'POST',
      body: JSON.stringify({ plan_json: planJson, title, sql }),
    });
  }

  // ── Comments ──────────────────────────────────────────────────────

  async getComments(planId: string) {
    return this.request<CommentListResponse>(
      `/plans/${planId}/comments`,
    );
  }

  async addComment(planId: string, content: string, parentId?: string) {
    return this.request<Comment>(`/plans/${planId}/comments`, {
      method: 'POST',
      body: JSON.stringify({ content, parent_id: parentId }),
    });
  }

  // ── Trends ────────────────────────────────────────────────────────

  async getWorkspaceTrends(workspaceId: string, timeRange = '7d') {
    return this.request<TrendResponse>(
      `/workspaces/${workspaceId}/trends?time_range=${timeRange}`,
    );
  }

  // ── Activity ──────────────────────────────────────────────────────

  async getActivity(workspaceId: string, limit = 50) {
    return this.request<ActivityResponse>(
      `/workspaces/${workspaceId}/activity?limit=${limit}`,
    );
  }
}

export const api = new QuerySenseAPI();

// ── Types ─────────────────────────────────────────────────────────────

export interface Finding {
  rule_id: string;
  severity: 'critical' | 'warning' | 'info';
  title: string;
  description: string;
  suggestion?: string;
  impact_band?: string;
  context: {
    node_type?: string;
    relation_name?: string;
    path?: string;
  };
}

export interface AnalysisResult {
  summary: {
    total: number;
    critical: number;
    warning: number;
    info: number;
  };
  findings: Finding[];
  evidence_level: string;
  rule_runs: Array<{
    rule_id: string;
    status: string;
    runtime_ms: number;
  }>;
}

export interface CompareResult {
  verdict: string;
  summary: {
    fixed_count: number;
    new_count: number;
    is_regression: boolean;
    cost_delta_pct: number;
  };
  new_issues: Finding[];
  fixed_issues: Finding[];
}

export interface PlanDetail {
  id: string;
  title: string;
  plan_json: string;
  sql_text?: string;
  created_at: string;
  analysis?: AnalysisResult;
}

export interface PlanListResponse {
  items: Array<{
    id: string;
    title: string;
    created_at: string;
    findings_count: number;
    critical_count: number;
  }>;
  total: number;
}

export interface Comment {
  id: string;
  plan_id: string;
  user_id: string;
  user_name: string;
  content: string;
  resolved: boolean;
  created_at: string;
  reply_count: number;
}

export interface CommentListResponse {
  items: Comment[];
  total: number;
}

export interface TrendPoint {
  timestamp: string;
  avg_execution_time_ms?: number;
  avg_cost?: number;
  sample_count: number;
  anomaly: boolean;
}

export interface TrendResponse {
  points: TrendPoint[];
  anomalies: TrendPoint[];
  summary: {
    mean_ms?: number;
    p95_ms?: number;
    trend?: string;
    trend_pct?: number;
  };
}

export interface ActivityItem {
  id: string;
  action: string;
  target_type: string;
  user_name: string;
  created_at: string;
  metadata?: Record<string, unknown>;
}

export interface ActivityResponse {
  items: ActivityItem[];
  total: number;
}
