import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, type HealthResponse } from '../api';
import { SearchIcon, ZapIcon, FileTextIcon, ShieldCheckIcon } from '../components/Icons';

export default function Dashboard() {
  const navigate = useNavigate();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.health().then(setHealth).catch(e => setError(e.message));
  }, []);

  return (
    <div className="page dashboard">
      <div className="hero">
        <div className="hero-badge">
          <ShieldCheckIcon size={14} />
          <span>11 static rules · 17 attack payloads · OWASP LLM Top 10</span>
        </div>
        <h1>
          Secure your <span className="gradient-text">MCP servers</span>
        </h1>
        <p className="hero-subtitle">
          Static configuration analysis and dynamic prompt-injection red-teaming
          for the Model Context Protocol — all running locally.
        </p>
      </div>

      {error && (
        <div className="alert alert-error">
          Backend not reachable: {error} — start it with <code>npm run ui</code>
        </div>
      )}

      <div className="action-grid">
        <div className="card action-card" onClick={() => navigate('/inspect')}>
          <div className="action-icon icon-blue">
            <SearchIcon size={22} />
          </div>
          <h2>Inspect</h2>
          <p>
            Parse MCP server configs, review launch commands, and run 11
            deterministic static security rules against the live tool surface.
          </p>
          <div className="action-tag">No API key required</div>
        </div>

        <div className="card action-card" onClick={() => navigate('/attack')}>
          <div className="action-icon icon-violet">
            <ZapIcon size={22} />
          </div>
          <h2>Attack</h2>
          <p>
            Red-team an AI agent with 17 prompt-injection payloads across 9
            categories, scored by deterministic oracles and an LLM judge.
          </p>
          <div className={`action-tag ${health?.hasApiKey ? 'tag-ok' : 'tag-warn'}`}>
            {health?.hasApiKey ? 'API key detected' : 'Requires ANTHROPIC_API_KEY'}
          </div>
        </div>

        <div className="card action-card" onClick={() => navigate('/reports')}>
          <div className="action-icon icon-teal">
            <FileTextIcon size={22} />
          </div>
          <h2>Reports</h2>
          <p>
            Load saved JSON reports from inspections or attack runs, filter
            findings by severity, and export JSON or Markdown summaries.
          </p>
          <div className="action-tag">View &amp; export</div>
        </div>
      </div>
    </div>
  );
}
