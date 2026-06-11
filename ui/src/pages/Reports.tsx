import { useState, useEffect, useCallback } from 'react';
import { api, type ReportFileInfo } from '../api';
import FindingCard from '../components/FindingCard';

export default function Reports() {
  const [filePath, setFilePath] = useState('');
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [report, setReport] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [exportName, setExportName] = useState('');
  const [exportMsg, setExportMsg] = useState('');
  const [savedReports, setSavedReports] = useState<ReportFileInfo[]>([]);

  const refreshSaved = useCallback(() => {
    api.listReports().then(r => setSavedReports(r.reports)).catch(() => {});
  }, []);

  useEffect(() => {
    refreshSaved();
  }, [refreshSaved]);

  const loadReportFrom = useCallback(async (path: string) => {
    setError(null);
    setReport(null);
    try {
      const res = await api.loadReport(path);
      setReport(res.report);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const loadReport = useCallback(() => loadReportFrom(filePath), [loadReportFrom, filePath]);

  const exportReport = useCallback(async () => {
    if (!exportName || !report) return;
    setExportMsg('');
    try {
      const res = await api.exportReport(exportName, report);
      setExportMsg(`Saved to ${res.exported}`);
      refreshSaved();
    } catch (e) {
      setExportMsg(e instanceof Error ? e.message : String(e));
    }
  }, [exportName, report, refreshSaved]);

  const exportMarkdown = useCallback(() => {
    if (!report) return;
    const mode = report.mode;
    const lines: string[] = [];
    lines.push(`# MCP Security Sentinel — ${mode === 'inspect' ? 'Inspect' : 'Attack'} Report`);
    lines.push('');
    lines.push(`**Timestamp:** ${report.scanTimestamp}`);
    if (mode === 'inspect') {
      lines.push(`**Target:** ${report.target}`);
      lines.push(`**Servers Inspected:** ${report.serversInspected}`);
    } else {
      lines.push(`**Agent Model:** ${report.agentModel}`);
      lines.push(`**Judge Model:** ${report.judgeModel}`);
    }
    lines.push(`**Total Findings:** ${report.totalFindings}`);
    lines.push(`- Critical: ${report.criticalCount}`);
    lines.push(`- High: ${report.highCount}`);
    lines.push(`- Medium: ${report.mediumCount}`);
    lines.push(`- Low: ${report.lowCount}`);
    lines.push('');

    const findings = report.findings ?? [];
    for (const f of findings) {
      const id = f.ruleId ?? f.payloadId;
      const name = f.ruleName ?? f.payloadName;
      lines.push(`## ${id}: ${name} [${f.severity.toUpperCase()}]`);
      lines.push(`Risk Score: ${f.riskScore?.toFixed(1)}`);
      lines.push(`Remediation: ${f.remediation}`);
      lines.push('');
    }

    const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-report-${mode}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }, [report]);

  const isInspect = report?.mode === 'inspect';
  const isAttack = report?.mode === 'attack';
  const findings = (report?.findings ?? []).filter((f: { severity: string }) => {
    if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
    if (searchQuery) {
      return JSON.stringify(f).toLowerCase().includes(searchQuery.toLowerCase());
    }
    return true;
  });

  return (
    <div className="page reports">
      <div className="page-header">
        <h1>Reports</h1>
        <p className="page-subtitle">Load, review, and export saved scan reports</p>
      </div>

      <div className="card config-form">
        <div className="form-group">
          <label>Report File Path (JSON)</label>
          <input
            type="text"
            value={filePath}
            onChange={e => setFilePath(e.target.value)}
            placeholder="/path/to/report.json"
            className="input"
          />
        </div>
        <button className="btn btn-primary" onClick={loadReport} disabled={!filePath}>
          Load Report
        </button>
      </div>

      {savedReports.length > 0 && !report && (
        <div className="card saved-reports">
          <h3>Saved reports</h3>
          <div className="saved-list">
            {savedReports.map(r => (
              <button key={r.name} className="saved-item" onClick={() => loadReportFrom(r.name)}>
                <span className="saved-name">{r.name}</span>
                <span className="saved-meta">
                  {(r.size / 1024).toFixed(1)} KB · {new Date(r.modifiedAt).toLocaleString()}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}

      {error && <div className="alert alert-error">{error}</div>}

      {report && (
        <>
          <div className="result-summary card">
            <h2>{isInspect ? 'Inspect Report' : isAttack ? 'Attack Report' : 'Report'}</h2>
            <div className="summary-stats">
              <div className="stat">
                <span className="stat-value">{report.totalFindings}</span>
                <span className="stat-label">Findings</span>
              </div>
              <div className="stat severity-critical">
                <span className="stat-value">{report.criticalCount}</span>
                <span className="stat-label">Critical</span>
              </div>
              <div className="stat severity-high">
                <span className="stat-value">{report.highCount}</span>
                <span className="stat-label">High</span>
              </div>
              <div className="stat severity-medium">
                <span className="stat-value">{report.mediumCount}</span>
                <span className="stat-label">Medium</span>
              </div>
              <div className="stat severity-low">
                <span className="stat-value">{report.lowCount}</span>
                <span className="stat-label">Low</span>
              </div>
            </div>
            {isInspect && (
              <div className="summary-meta">
                <span>Target: {report.target}</span>
                <span>Servers: {report.serversInspected}</span>
                <span>Time: {report.scanTimestamp}</span>
              </div>
            )}
            {isAttack && (
              <div className="summary-meta">
                <span>Agent: {report.agentModel}</span>
                <span>Judge: {report.judgeModel}</span>
                <span>Runs: {report.runsPerPayload}</span>
                <span>Time: {report.scanTimestamp}</span>
              </div>
            )}
          </div>

          <div className="filter-bar">
            <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)} className="input input-sm">
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <input
              type="text"
              placeholder="Search by rule ID, payload, server, tool..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="input input-sm"
            />
          </div>

          <div className="findings-list">
            {findings
              .sort((a: { riskScore: number }, b: { riskScore: number }) => (b.riskScore ?? 0) - (a.riskScore ?? 0))
              .map((f: Record<string, unknown>, i: number) => <FindingCard key={i} finding={f as never} />)}
          </div>

          {findings.length === 0 && (
            <div className="empty-state">No findings match filters</div>
          )}

          <div className="export-section card">
            <h3>Export</h3>
            <div className="form-row">
              <input
                type="text"
                value={exportName}
                onChange={e => setExportName(e.target.value)}
                placeholder="my-report.json (saved to ./reports/)"
                className="input"
              />
              <button className="btn btn-sm" onClick={exportReport} disabled={!exportName}>
                Save JSON
              </button>
              <button className="btn btn-sm" onClick={exportMarkdown}>
                Download Markdown
              </button>
            </div>
            {exportMsg && <p className="text-muted">{exportMsg}</p>}
          </div>
        </>
      )}
    </div>
  );
}
