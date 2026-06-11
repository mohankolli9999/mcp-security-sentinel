import { useEffect, useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { api, type HealthResponse } from '../api';
import { ShieldIcon, GridIcon, SearchIcon, ZapIcon, FileTextIcon } from './Icons';

export default function Layout() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    api.health()
      .then(h => { setHealth(h); setOffline(false); })
      .catch(() => setOffline(true));
  }, []);

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-mark">
            <ShieldIcon size={20} />
          </div>
          <div className="brand-text">
            <span className="brand-name">MCP Sentinel</span>
            <span className="brand-tagline">Security Scanner</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          <NavLink to="/" end>
            <GridIcon size={17} />
            <span>Dashboard</span>
          </NavLink>
          <NavLink to="/inspect">
            <SearchIcon size={17} />
            <span>Inspect</span>
          </NavLink>
          <NavLink to="/attack">
            <ZapIcon size={17} />
            <span>Attack</span>
          </NavLink>
          <NavLink to="/reports">
            <FileTextIcon size={17} />
            <span>Reports</span>
          </NavLink>
        </nav>

        <div className="sidebar-footer">
          <div className={`status-pill ${offline ? 'offline' : 'online'}`}>
            <span className="status-dot" />
            {offline ? 'Backend offline' : health ? `Connected · v${health.version}` : 'Connecting…'}
          </div>
          {health && (
            <div className={`status-pill ${health.hasApiKey ? 'online' : 'neutral'}`}>
              <span className="status-dot" />
              {health.hasApiKey ? 'API key detected' : 'No API key (inspect only)'}
            </div>
          )}
        </div>
      </aside>

      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
