import { useState, useCallback } from 'react';
import { api, subscribeToRun, type ServerEntry } from '../api';
import ServerCard from '../components/ServerCard';
import FindingCard from '../components/FindingCard';
import Stepper from '../components/Stepper';

type Phase = 'config' | 'inventory' | 'running' | 'results';

const PHASE_STEPS = ['Configure', 'Approve servers', 'Scanning', 'Results'];
const PHASE_INDEX: Record<Phase, number> = { config: 0, inventory: 1, running: 2, results: 3 };

interface Warning {
  serverName?: string;
  message: string;
  path?: string;
}

export default function Inspect() {
  const [phase, setPhase] = useState<Phase>('config');
  const [configPath, setConfigPath] = useState('');
  const [noExecute, setNoExecute] = useState(false);
  const [readResources, setReadResources] = useState(false);
  const [maxResources, setMaxResources] = useState(10);
  const [maxResourceBytes, setMaxResourceBytes] = useState(1048576);
  const [timeoutMs, setTimeoutMs] = useState(10000);
  const [enumerationTimeoutMs, setEnumerationTimeoutMs] = useState(5000);
  const [resourceTimeoutMs, setResourceTimeoutMs] = useState(5000);

  const [servers, setServers] = useState<ServerEntry[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [resolvedPath, setResolvedPath] = useState('');

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [findings, setFindings] = useState<any[]>([]);
  const [warnings, setWarnings] = useState<Warning[]>([]);
  const [progress, setProgress] = useState('');
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  const parseConfig = useCallback(async () => {
    setError(null);
    try {
      const res = await api.parseConfig(configPath);
      setServers(res.servers);
      setResolvedPath(res.configPath);
      setSelected(new Set(res.servers.map(s => s.name)));
      setPhase('inventory');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [configPath]);

  const toggleServer = useCallback((name: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }, []);

  const selectAll = useCallback(() => {
    setSelected(new Set(servers.map(s => s.name)));
  }, [servers]);

  const selectNone = useCallback(() => {
    setSelected(new Set());
  }, []);

  const startInspect = useCallback(async (configOnly: boolean) => {
    setError(null);
    setFindings([]);
    setWarnings([]);
    setResult(null);
    setPhase('running');

    try {
      const params: Record<string, unknown> = {
        configPath: resolvedPath,
        noExecute: configOnly,
        readResources,
        maxResources,
        maxResourceBytes,
        timeoutMs,
        enumerationTimeoutMs,
        resourceTimeoutMs,
      };

      if (!configOnly) {
        params.approvedServers = Array.from(selected);
      }

      const { runId: id } = await api.startInspect(params);
      setRunId(id);

      subscribeToRun(id, (event, data) => {
        switch (event) {
          case 'finding':
            setFindings(prev => [...prev, data]);
            break;
          case 'warning':
            setWarnings(prev => [...prev, data as Warning]);
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
      setPhase('inventory');
    }
  }, [resolvedPath, selected, readResources, maxResources, maxResourceBytes, timeoutMs, enumerationTimeoutMs, resourceTimeoutMs, result]);

  const cancelCurrentRun = useCallback(async () => {
    if (runId) {
      await api.cancelRun(runId);
    }
  }, [runId]);

  const filteredFindings = findings.filter(f => {
    if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const text = JSON.stringify(f).toLowerCase();
      return text.includes(q);
    }
    return true;
  });

  const reset = useCallback(() => {
    setPhase('config');
    setServers([]);
    setSelected(new Set());
    setFindings([]);
    setWarnings([]);
    setResult(null);
    setError(null);
    setRunId(null);
    setProgress('');
  }, []);

  return (
    <div className="page inspect">
      <div className="page-header">
        <h1>Inspect</h1>
        <p className="page-subtitle">Static security analysis of MCP server configurations</p>
      </div>

      <Stepper steps={PHASE_STEPS} current={PHASE_INDEX[phase]} />

      {phase === 'config' && (
        <div className="card config-form">
          <div className="form-group">
            <label>Config File Path</label>
            <input
              type="text"
              value={configPath}
              onChange={e => setConfigPath(e.target.value)}
              placeholder="~/.config/claude/claude_desktop_config.json"
              className="input"
            />
          </div>

          <div className="form-row">
            <label className="checkbox-label">
              <input type="checkbox" checked={noExecute} onChange={e => setNoExecute(e.target.checked)} />
              No-execute (config review only)
            </label>
            <label className="checkbox-label">
              <input type="checkbox" checked={readResources} onChange={e => setReadResources(e.target.checked)} disabled={noExecute} />
              Read resources
            </label>
          </div>

          <details className="advanced-options">
            <summary>Advanced Options</summary>
            <div className="form-grid">
              <div className="form-group">
                <label>Max Resources</label>
                <input type="number" value={maxResources} onChange={e => setMaxResources(Number(e.target.value))} className="input input-sm" />
              </div>
              <div className="form-group">
                <label>Max Resource Bytes</label>
                <input type="number" value={maxResourceBytes} onChange={e => setMaxResourceBytes(Number(e.target.value))} className="input input-sm" />
              </div>
              <div className="form-group">
                <label>Connection Timeout (ms)</label>
                <input type="number" value={timeoutMs} onChange={e => setTimeoutMs(Number(e.target.value))} className="input input-sm" />
              </div>
              <div className="form-group">
                <label>Enumeration Timeout (ms)</label>
                <input type="number" value={enumerationTimeoutMs} onChange={e => setEnumerationTimeoutMs(Number(e.target.value))} className="input input-sm" />
              </div>
              <div className="form-group">
                <label>Resource Timeout (ms)</label>
                <input type="number" value={resourceTimeoutMs} onChange={e => setResourceTimeoutMs(Number(e.target.value))} className="input input-sm" />
              </div>
            </div>
          </details>

          <button className="btn btn-primary" onClick={parseConfig} disabled={!configPath}>
            Parse Config
          </button>
        </div>
      )}

      {phase === 'inventory' && (
        <>
          <div className="inventory-header">
            <h2>Server Inventory</h2>
            <p className="text-muted">Config: {resolvedPath}</p>
            <div className="inventory-actions">
              <button className="btn btn-sm" onClick={selectAll}>Select All</button>
              <button className="btn btn-sm" onClick={selectNone}>Select None</button>
            </div>
          </div>

          <div className="server-grid">
            {servers.map(s => (
              <ServerCard
                key={s.name}
                server={s}
                selected={selected.has(s.name)}
                onToggle={toggleServer}
              />
            ))}
          </div>

          <div className="action-buttons">
            <button
              className="btn btn-primary"
              onClick={() => startInspect(true)}
            >
              Config Review Only
            </button>
            <button
              className="btn btn-accent"
              onClick={() => startInspect(false)}
              disabled={selected.size === 0 || noExecute}
            >
              Inspect Selected ({selected.size})
            </button>
            <button className="btn btn-ghost" onClick={reset}>Back</button>
          </div>
        </>
      )}

      {phase === 'running' && (
        <div className="running-status">
          <div className="spinner"></div>
          <p>{progress || 'Starting inspection...'}</p>
          <button className="btn btn-ghost" onClick={cancelCurrentRun}>Cancel</button>
        </div>
      )}

      {phase === 'results' && (
        <>
          {error && <div className="alert alert-error">{error}</div>}

          {result && (
            <div className="result-summary card">
              <h2>Results</h2>
              <div className="summary-stats">
                <div className="stat">
                  <span className="stat-value">{result.serversInspected}</span>
                  <span className="stat-label">Servers Inspected</span>
                </div>
                <div className="stat">
                  <span className="stat-value">{result.totalFindings}</span>
                  <span className="stat-label">Total Findings</span>
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
            <div className="empty-state">No findings detected</div>
          )}

          <div className="findings-list">
            {filteredFindings
              .sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0))
              .map((f, i) => <FindingCard key={i} finding={f} />)}
          </div>

          {warnings.length > 0 && (
            <div className="warnings-section">
              <h3>Warnings</h3>
              {warnings.map((w, i) => (
                <div key={i} className="alert alert-warn">
                  {w.serverName && <strong>[{w.serverName}]</strong>} {w.message}
                  {w.path && <span className="text-muted"> ({w.path})</span>}
                </div>
              ))}
            </div>
          )}

          <div className="action-buttons">
            <button className="btn btn-primary" onClick={reset}>New Inspection</button>
          </div>
        </>
      )}
    </div>
  );
}
