import { useState, useEffect, useCallback } from 'react';
import { api, subscribeToRun, type PayloadInfo } from '../api';
import FindingCard from '../components/FindingCard';

type Phase = 'config' | 'running' | 'results';

export default function Attack() {
  const [phase, setPhase] = useState<Phase>('config');
  const [hasApiKey, setHasApiKey] = useState<boolean | null>(null);
  const [payloads, setPayloads] = useState<PayloadInfo[]>([]);

  // Filters
  const [payloadId, setPayloadId] = useState('');
  const [category, setCategory] = useState('');
  const [severity, setSeverity] = useState('');
  const [runs, setRuns] = useState(3);
  const [agentModel, setAgentModel] = useState('claude-haiku-4-5-20251001');
  const [judgeModel, setJudgeModel] = useState('claude-sonnet-4-6');
  const [noBaseline, setNoBaseline] = useState(false);

  // Results
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [findings, setFindings] = useState<any[]>([]);
  const [progress, setProgress] = useState('');
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    api.health().then(h => setHasApiKey(h.hasApiKey));
    api.getPayloads().then(r => setPayloads(r.payloads));
  }, []);

  const categories = [...new Set(payloads.map(p => p.category))];

  const startAttack = useCallback(async () => {
    setError(null);
    setFindings([]);
    setResult(null);
    setPhase('running');

    try {
      const params: Record<string, unknown> = {
        runs,
        agentModel,
        judgeModel,
        noBaseline,
      };
      if (payloadId) params.payloadId = payloadId;
      if (category) params.category = category;
      if (severity) params.severity = severity;

      const { runId: id } = await api.startAttack(params);
      setRunId(id);

      subscribeToRun(id, (event, data) => {
        switch (event) {
          case 'finding':
            setFindings(prev => [...prev, data]);
            break;
          case 'progress':
            setProgress((data as { message: string }).message);
            break;
          case 'result': {
            setResult(data);
            // Sync from the final result — covers findings broadcast before
            // the EventSource connected
            const final = (data as { findings?: unknown[] }).findings;
            if (final) setFindings(final);
            setPhase('results');
            break;
          }
          case 'error':
            setError((data as { message: string }).message);
            setPhase('results');
            break;
          case 'done':
            if (!result) setPhase('results');
            break;
        }
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setPhase('config');
    }
  }, [payloadId, category, severity, runs, agentModel, judgeModel, noBaseline, result]);

  const cancelCurrentRun = useCallback(async () => {
    if (runId) await api.cancelRun(runId);
  }, [runId]);

  const filteredFindings = findings.filter(f => {
    if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return JSON.stringify(f).toLowerCase().includes(q);
    }
    return true;
  });

  const reset = useCallback(() => {
    setPhase('config');
    setFindings([]);
    setResult(null);
    setError(null);
    setRunId(null);
    setProgress('');
  }, []);

  return (
    <div className="page attack">
      <div className="page-header">
        <h1>Attack</h1>
        <p className="page-subtitle">Dynamic prompt-injection red-teaming against an AI agent</p>
      </div>
      <div className="alert alert-warn">
        Active testing mode — runs real prompt-injection payloads against an LLM agent and incurs API cost.
      </div>

      {hasApiKey === false && (
        <div className="alert alert-error">
          Attack mode requires <code>ANTHROPIC_API_KEY</code> environment variable.
          Set it before starting the UI server.
        </div>
      )}

      {phase === 'config' && (
        <div className="card config-form">
          <div className="form-grid">
            <div className="form-group">
              <label>Payload ID (optional)</label>
              <input
                type="text"
                value={payloadId}
                onChange={e => setPayloadId(e.target.value)}
                placeholder="e.g. INJ-001"
                className="input"
              />
            </div>
            <div className="form-group">
              <label>Category</label>
              <select value={category} onChange={e => setCategory(e.target.value)} className="input">
                <option value="">All Categories</option>
                {categories.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div className="form-group">
              <label>Min Severity</label>
              <select value={severity} onChange={e => setSeverity(e.target.value)} className="input">
                <option value="">All</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div className="form-group">
              <label>Runs per Payload</label>
              <input
                type="number"
                value={runs}
                onChange={e => setRuns(Number(e.target.value))}
                min={1}
                max={10}
                className="input"
              />
            </div>
            <div className="form-group">
              <label>Agent Model</label>
              <input
                type="text"
                value={agentModel}
                onChange={e => setAgentModel(e.target.value)}
                className="input"
              />
            </div>
            <div className="form-group">
              <label>Judge Model</label>
              <input
                type="text"
                value={judgeModel}
                onChange={e => setJudgeModel(e.target.value)}
                className="input"
              />
            </div>
          </div>

          <label className="checkbox-label">
            <input type="checkbox" checked={noBaseline} onChange={e => setNoBaseline(e.target.checked)} />
            No baseline (skip baseline comparison)
          </label>

          <button
            className="btn btn-accent"
            onClick={startAttack}
            disabled={hasApiKey === false}
          >
            Start Attack Tests
          </button>
        </div>
      )}

      {phase === 'running' && (
        <div className="running-status">
          <div className="spinner"></div>
          <p>{progress || 'Starting attack tests...'}</p>
          <button className="btn btn-ghost" onClick={cancelCurrentRun}>Cancel</button>
        </div>
      )}

      {phase === 'results' && (
        <>
          {error && <div className="alert alert-error">{error}</div>}

          {result && (
            <div className="result-summary card">
              <h2>Attack Results</h2>
              <div className="summary-stats">
                <div className="stat">
                  <span className="stat-value">{result.totalPayloadsTested}</span>
                  <span className="stat-label">Payloads Tested</span>
                </div>
                <div className="stat">
                  <span className="stat-value">{result.totalFindings}</span>
                  <span className="stat-label">Findings</span>
                </div>
                <div className="stat severity-critical">
                  <span className="stat-value">{result.criticalCount}</span>
                  <span className="stat-label">Critical</span>
                </div>
                <div className="stat severity-high">
                  <span className="stat-value">{result.highCount}</span>
                  <span className="stat-label">High</span>
                </div>
                <div className="stat severity-medium">
                  <span className="stat-value">{result.mediumCount}</span>
                  <span className="stat-label">Medium</span>
                </div>
                <div className="stat severity-low">
                  <span className="stat-value">{result.lowCount}</span>
                  <span className="stat-label">Low</span>
                </div>
              </div>
              <div className="summary-meta">
                <span>Agent: {result.agentModel}</span>
                <span>Judge: {result.judgeModel}</span>
                <span>Runs: {result.runsPerPayload}</span>
                <span>Baseline: {result.baselineEnabled ? 'enabled' : 'disabled'}</span>
              </div>
            </div>
          )}

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
              placeholder="Search findings..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="input input-sm"
            />
          </div>

          {filteredFindings.length === 0 && !error && (
            <div className="empty-state">No manipulation detected</div>
          )}

          <div className="findings-list">
            {filteredFindings
              .sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0))
              .map((f, i) => <FindingCard key={i} finding={f} />)}
          </div>

          <div className="action-buttons">
            <button className="btn btn-primary" onClick={reset}>New Test</button>
          </div>
        </>
      )}
    </div>
  );
}
