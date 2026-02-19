/**
 * QuerySense VS Code Extension
 *
 * Provides:
 * - Ctrl+Shift+Q: Analyze selected SQL / EXPLAIN plan
 * - Hover hints on SQL keywords
 * - CodeLens with inline analysis scores
 * - Results panel with D3 visualization
 */

import * as vscode from 'vscode';
import { QuerySenseClient, type AnalysisResult, type Finding } from './client';

let client: QuerySenseClient;

export function activate(context: vscode.ExtensionContext) {
  // Initialize client with settings
  const config = vscode.workspace.getConfiguration('querysense');
  client = new QuerySenseClient(
    config.get('apiUrl', 'http://localhost:8000'),
    config.get('apiKey', ''),
  );

  // ── Command: Analyze selection or file ──────────────────────────

  const analyzeCmd = vscode.commands.registerCommand(
    'querysense.analyze',
    async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage('No active editor');
        return;
      }

      const selection = editor.selection;
      const text = selection.isEmpty
        ? editor.document.getText()
        : editor.document.getText(selection);

      if (!text.trim()) {
        vscode.window.showWarningMessage('No text to analyze');
        return;
      }

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: 'QuerySense: Analyzing...',
          cancellable: false,
        },
        async (progress) => {
          progress.report({ increment: 30 });

          try {
            const result = await client.analyze(text);
            progress.report({ increment: 70 });

            showResultsPanel(context, result, text);
          } catch (e: unknown) {
            const err = e as Error;
            vscode.window.showErrorMessage(
              `QuerySense: ${err.message || 'Analysis failed'}`,
            );
          }
        },
      );
    },
  );

  // ── Command: Analyze EXPLAIN plan from file ─────────────────────

  const analyzeFileCmd = vscode.commands.registerCommand(
    'querysense.analyzeFile',
    async () => {
      const files = await vscode.window.showOpenDialog({
        canSelectMany: false,
        filters: { 'JSON files': ['json'] },
        title: 'Select EXPLAIN plan JSON',
      });

      if (!files || files.length === 0) return;

      const content = await vscode.workspace.fs.readFile(files[0]);
      const text = new TextDecoder().decode(content);

      try {
        const result = await client.analyze(text);
        showResultsPanel(
          context,
          result,
          text,
        );
      } catch (e: unknown) {
        const err = e as Error;
        vscode.window.showErrorMessage(`QuerySense: ${err.message}`);
      }
    },
  );

  // ── Hover provider for SQL files ────────────────────────────────

  const hoverProvider = vscode.languages.registerHoverProvider(
    ['sql', 'pgsql', 'plpgsql'],
    {
      provideHover(document, position) {
        if (!config.get('enableHover', true)) return undefined;

        const range = document.getWordRangeAtPosition(position, /\b\w+\b/);
        if (!range) return undefined;

        const word = document.getText(range).toUpperCase();

        // Quick tips for common SQL patterns
        const tips: Record<string, string> = {
          SELECT:
            '**QuerySense**: Avoid `SELECT *` — specify only needed columns to reduce I/O.',
          LIKE: '**QuerySense**: Leading wildcards (`%value`) prevent index usage. Consider full-text search.',
          OFFSET:
            '**QuerySense**: Large `OFFSET` values scan and discard rows. Use keyset pagination instead.',
          DISTINCT:
            '**QuerySense**: `DISTINCT` can be expensive. Consider if your JOIN logic produces duplicates.',
          HAVING:
            '**QuerySense**: Move conditions to `WHERE` when possible — `HAVING` filters after aggregation.',
        };

        const tip = tips[word];
        if (tip) {
          return new vscode.Hover(new vscode.MarkdownString(tip));
        }

        return undefined;
      },
    },
  );

  // ── CodeLens provider ───────────────────────────────────────────

  const codeLensProvider = vscode.languages.registerCodeLensProvider(
    ['sql', 'pgsql'],
    {
      provideCodeLenses(document) {
        if (!config.get('enableCodeLens', true)) return [];

        const text = document.getText();
        const lenses: vscode.CodeLens[] = [];

        // Add "Analyze with QuerySense" lens at top of SQL files
        if (text.trim().length > 0) {
          const range = new vscode.Range(0, 0, 0, 0);
          lenses.push(
            new vscode.CodeLens(range, {
              title: '$(beaker) Analyze with QuerySense',
              command: 'querysense.analyze',
              tooltip: 'Run QuerySense analysis on this file',
            }),
          );
        }

        return lenses;
      },
    },
  );

  context.subscriptions.push(
    analyzeCmd,
    analyzeFileCmd,
    hoverProvider,
    codeLensProvider,
  );

  // Watch for config changes
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('querysense')) {
        const updated = vscode.workspace.getConfiguration('querysense');
        client = new QuerySenseClient(
          updated.get('apiUrl', 'http://localhost:8000'),
          updated.get('apiKey', ''),
        );
      }
    }),
  );
}

export function deactivate() {}

// ── Results Panel ────────────────────────────────────────────────────

function showResultsPanel(
  context: vscode.ExtensionContext,
  result: AnalysisResult,
  planText: string,
) {
  const panel = vscode.window.createWebviewPanel(
    'querysenseResults',
    `QuerySense: ${result.summary.total} findings`,
    vscode.ViewColumn.Beside,
    { enableScripts: true },
  );

  panel.webview.html = getResultsHtml(result);
}

function getResultsHtml(result: AnalysisResult): string {
  const severityIcon = (s: string) =>
    s === 'critical' ? '!!!' : s === 'warning' ? '!' : 'i';

  const findingsHtml = result.findings
    .map(
      (f) => `
    <div class="finding ${f.severity}">
      <div class="header">
        <span class="badge badge-${f.severity}">${f.severity}</span>
        <strong>${escapeHtml(f.title)}</strong>
      </div>
      <p>${escapeHtml(f.description)}</p>
      ${f.suggestion ? `<pre class="fix">${escapeHtml(f.suggestion)}</pre>` : ''}
    </div>`,
    )
    .join('');

  return `<!DOCTYPE html>
<html>
<head>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 16px; color: var(--vscode-foreground); background: var(--vscode-editor-background); }
  .summary { display: flex; gap: 16px; margin-bottom: 24px; }
  .stat { text-align: center; padding: 12px; border-radius: 8px; background: var(--vscode-badge-background); }
  .stat .value { font-size: 24px; font-weight: bold; }
  .stat .label { font-size: 11px; opacity: 0.7; }
  .finding { padding: 12px; margin-bottom: 8px; border-left: 3px solid; border-radius: 4px; }
  .finding.critical { border-color: #dc2626; background: rgba(220,38,38,0.1); }
  .finding.warning { border-color: #f59e0b; background: rgba(245,158,11,0.1); }
  .finding.info { border-color: #3b82f6; background: rgba(59,130,246,0.1); }
  .badge { padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge-critical { background: #fecaca; color: #991b1b; }
  .badge-warning { background: #fef3c7; color: #92400e; }
  .badge-info { background: #dbeafe; color: #1e40af; }
  .fix { background: #1e293b; color: #4ade80; padding: 8px; border-radius: 4px; font-size: 12px; overflow-x: auto; }
  .header { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
</style>
</head>
<body>
  <h2>QuerySense Analysis</h2>
  <div class="summary">
    <div class="stat"><div class="value">${result.summary.total}</div><div class="label">Total</div></div>
    <div class="stat"><div class="value" style="color:#dc2626">${result.summary.critical}</div><div class="label">Critical</div></div>
    <div class="stat"><div class="value" style="color:#f59e0b">${result.summary.warning}</div><div class="label">Warning</div></div>
    <div class="stat"><div class="value" style="color:#3b82f6">${result.summary.info}</div><div class="label">Info</div></div>
  </div>
  <p style="font-size:12px;opacity:0.7">Evidence level: ${result.evidence_level}</p>
  ${findingsHtml || '<p>No issues found.</p>'}
</body>
</html>`;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
