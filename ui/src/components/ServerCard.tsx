import type { ServerEntry } from '../api';

interface Props {
  server: ServerEntry;
  selected: boolean;
  onToggle: (name: string) => void;
}

export default function ServerCard({ server, selected, onToggle }: Props) {
  return (
    <div className={`card server-card ${selected ? 'selected' : ''}`}>
      <label className="server-label">
        <input
          type="checkbox"
          checked={selected}
          onChange={() => onToggle(server.name)}
        />
        <div className="server-info">
          <div className="server-name">{server.name}</div>
          <div className="server-meta">
            <span className="transport-badge">{server.transport}</span>
            {server.command && <span>Command: <code>{server.command}</code></span>}
            {server.args && server.args.length > 0 && (
              <span>Args: <code>{server.args.join(' ')}</code></span>
            )}
            {server.url && <span>URL: <code>{server.url}</code></span>}
            {server.envKeys.length > 0 && (
              <span>Env keys: {server.envKeys.join(', ')}</span>
            )}
          </div>
        </div>
      </label>
    </div>
  );
}
