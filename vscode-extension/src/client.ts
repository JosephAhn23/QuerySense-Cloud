/**
 * QuerySense API client for the VS Code extension.
 *
 * Talks to the QuerySense Cloud API (or local instance).
 */

import * as https from 'https';
import * as http from 'http';

export interface Finding {
  rule_id: string;
  severity: 'critical' | 'warning' | 'info';
  title: string;
  description: string;
  suggestion?: string;
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

export class QuerySenseClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(baseUrl: string, apiKey: string) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.apiKey = apiKey;
  }

  async analyze(planOrSql: string): Promise<AnalysisResult> {
    // Detect if input is EXPLAIN JSON or raw SQL
    const trimmed = planOrSql.trim();
    const isJson = trimmed.startsWith('{') || trimmed.startsWith('[');

    const body = isJson
      ? { plan_json: planOrSql }
      : { plan_json: planOrSql, sql: planOrSql };

    return this.post<AnalysisResult>('/api/v1/analyze', body);
  }

  private post<T>(path: string, body: Record<string, unknown>): Promise<T> {
    return new Promise((resolve, reject) => {
      const url = new URL(`${this.baseUrl}${path}`);
      const isHttps = url.protocol === 'https:';
      const transport = isHttps ? https : http;

      const payload = JSON.stringify(body);

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload).toString(),
      };

      if (this.apiKey) {
        headers['Authorization'] = `Bearer ${this.apiKey}`;
      }

      const req = transport.request(
        {
          hostname: url.hostname,
          port: url.port,
          path: url.pathname,
          method: 'POST',
          headers,
        },
        (res) => {
          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => {
            if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
              try {
                resolve(JSON.parse(data));
              } catch {
                reject(new Error('Invalid JSON response'));
              }
            } else {
              try {
                const error = JSON.parse(data);
                reject(new Error(error.detail || `HTTP ${res.statusCode}`));
              } catch {
                reject(new Error(`HTTP ${res.statusCode}`));
              }
            }
          });
        },
      );

      req.on('error', (e) => reject(new Error(`Connection failed: ${e.message}`)));
      req.setTimeout(30000, () => {
        req.destroy();
        reject(new Error('Request timed out'));
      });

      req.write(payload);
      req.end();
    });
  }
}
