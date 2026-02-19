/**
 * Plan Analyzer page — paste an EXPLAIN plan and get instant analysis.
 *
 * Features:
 * - Paste EXPLAIN JSON input
 * - Interactive D3 plan graph
 * - Findings list with severity badges
 * - Copy-paste fix cards
 */

import { useState, useCallback } from 'react';
import { PlanGraph } from './PlanGraph';
import { api, type AnalysisResult, type Finding } from '../../services/api';

export const PlanAnalyzer: React.FC = () => {
  const [input, setInput] = useState('');
  const [sqlInput, setSqlInput] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [planData, setPlanData] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const analyze = useCallback(async () => {
    if (!input.trim()) return;
    setLoading(true);
    setError(null);

    try {
      const analysisResult = await api.analyze(input, sqlInput || undefined);
      setResult(analysisResult);

      // Parse plan for visualization
      try {
        let parsed = JSON.parse(input);
        if (Array.isArray(parsed)) parsed = parsed[0];
        const plan = parsed.Plan || parsed;
        setPlanData(plan);
      } catch {
        setPlanData(null);
      }
    } catch (e: unknown) {
      const err = e as { detail?: string };
      setError(err.detail || 'Analysis failed. Check your EXPLAIN JSON.');
      setResult(null);
      setPlanData(null);
    } finally {
      setLoading(false);
    }
  }, [input, sqlInput]);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Analyze Plan</h1>

      {/* Input section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            EXPLAIN (FORMAT JSON) output
          </label>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Paste your EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) output here..."
            className="w-full h-48 p-3 border border-gray-300 rounded-lg font-mono text-sm resize-y focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            SQL Query (optional — enables enhanced analysis)
          </label>
          <textarea
            value={sqlInput}
            onChange={(e) => setSqlInput(e.target.value)}
            placeholder="SELECT * FROM users WHERE..."
            className="w-full h-48 p-3 border border-gray-300 rounded-lg font-mono text-sm resize-y focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>
      </div>

      <button
        onClick={analyze}
        disabled={loading || !input.trim()}
        className="px-6 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium"
      >
        {loading ? 'Analyzing...' : 'Analyze'}
      </button>

      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-red-800 text-sm">
          {error}
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-6">
          {/* Summary bar */}
          <div className="flex items-center gap-4 p-4 bg-white rounded-lg shadow-sm border border-gray-100">
            <div className="text-center">
              <p className="text-2xl font-bold text-gray-900">
                {result.summary.total}
              </p>
              <p className="text-xs text-gray-500">Findings</p>
            </div>
            <div className="h-8 w-px bg-gray-200" />
            {result.summary.critical > 0 && (
              <div className="text-center">
                <p className="text-2xl font-bold text-red-600">
                  {result.summary.critical}
                </p>
                <p className="text-xs text-red-500">Critical</p>
              </div>
            )}
            {result.summary.warning > 0 && (
              <div className="text-center">
                <p className="text-2xl font-bold text-amber-600">
                  {result.summary.warning}
                </p>
                <p className="text-xs text-amber-500">Warnings</p>
              </div>
            )}
            {result.summary.info > 0 && (
              <div className="text-center">
                <p className="text-2xl font-bold text-blue-600">
                  {result.summary.info}
                </p>
                <p className="text-xs text-blue-500">Info</p>
              </div>
            )}
            <div className="ml-auto">
              <span className="px-2 py-1 text-xs rounded bg-gray-100 text-gray-600">
                Evidence: {result.evidence_level}
              </span>
            </div>
          </div>

          {/* Plan Graph */}
          {planData && (
            <div>
              <h2 className="text-lg font-semibold text-gray-800 mb-2">
                Plan Visualization
              </h2>
              <PlanGraph
                plan={planData as any}
                onNodeClick={(_node, path) => setSelectedNode(path)}
                highlightPaths={
                  selectedNode ? new Set([selectedNode]) : undefined
                }
              />
            </div>
          )}

          {/* Findings */}
          <div>
            <h2 className="text-lg font-semibold text-gray-800 mb-3">
              Findings
            </h2>
            <div className="space-y-3">
              {result.findings.map((finding, i) => (
                <FindingCard key={i} finding={finding} />
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const FindingCard: React.FC<{ finding: Finding }> = ({ finding }) => {
  const [expanded, setExpanded] = useState(false);

  const severityStyles = {
    critical: 'border-l-red-500 bg-red-50',
    warning: 'border-l-amber-500 bg-amber-50',
    info: 'border-l-blue-500 bg-blue-50',
  };

  const badgeStyles = {
    critical: 'bg-red-100 text-red-800',
    warning: 'bg-amber-100 text-amber-800',
    info: 'bg-blue-100 text-blue-800',
  };

  return (
    <div
      className={`border-l-4 rounded-r-lg p-4 ${severityStyles[finding.severity]}`}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span
              className={`px-2 py-0.5 text-xs rounded-full font-medium ${badgeStyles[finding.severity]}`}
            >
              {finding.severity}
            </span>
            <h3 className="font-medium text-gray-900">{finding.title}</h3>
          </div>
          <p className="text-sm text-gray-600 mt-1">{finding.description}</p>
          {finding.context?.relation_name && (
            <p className="text-xs text-gray-500 mt-1">
              Table: <code className="bg-gray-200 px-1 rounded">{finding.context.relation_name}</code>
            </p>
          )}
        </div>
        {finding.suggestion && (
          <button
            onClick={() => setExpanded(!expanded)}
            className="text-xs text-blue-600 hover:text-blue-800 ml-2 shrink-0"
          >
            {expanded ? 'Hide fix' : 'Show fix'}
          </button>
        )}
      </div>
      {expanded && finding.suggestion && (
        <div className="mt-3 p-3 bg-gray-900 text-green-400 rounded-lg font-mono text-sm relative">
          <button
            onClick={() => navigator.clipboard.writeText(finding.suggestion!)}
            className="absolute top-2 right-2 text-gray-400 hover:text-white text-xs"
          >
            Copy
          </button>
          <pre className="whitespace-pre-wrap">{finding.suggestion}</pre>
        </div>
      )}
    </div>
  );
};
