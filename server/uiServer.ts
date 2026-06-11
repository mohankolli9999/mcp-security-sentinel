import 'dotenv/config';
import express from 'express';
import fs from 'fs';
import path from 'path';
import { parseConfigFile } from '../src/configParser.js';
import { redactSensitiveText } from '../src/reporter.js';
import { PAYLOADS } from '../src/payloads.js';
import {
  startInspectRun,
  startAttackRun,
  cancelRun,
  addClient,
} from './runManager.js';
import type { InspectStartParams, AttackStartParams } from './runManager.js';

const app = express();
app.use(express.json());

// Directory where UI-exported reports are written; exports may not escape it.
const REPORTS_DIR = path.resolve(import.meta.dirname, '..', 'reports');

// Reject requests whose Host header is not loopback. The server only binds
// 127.0.0.1, but this also defeats DNS-rebinding attacks from web pages.
const ALLOWED_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]']);
app.use((req, res, next) => {
  let hostname = '';
  try {
    hostname = new URL(`http://${req.headers.host ?? ''}`).hostname;
  } catch {
    // unparseable Host header falls through to rejection
  }
  if (!ALLOWED_HOSTNAMES.has(hostname)) {
    res.status(403).json({ error: 'Forbidden: this server only accepts local requests' });
    return;
  }
  next();
});

// Health check
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    hasApiKey: Boolean(process.env['ANTHROPIC_API_KEY']),
    version: '1.0.0',
  });
});

// Parse config file — returns inventory with env keys only, never values
app.post('/api/config/parse', (req, res) => {
  const { configPath } = req.body as { configPath?: string };
  if (!configPath || typeof configPath !== 'string') {
    res.status(400).json({ error: 'configPath is required' });
    return;
  }

  try {
    const resolved = path.resolve(configPath);
    if (!fs.existsSync(resolved)) {
      res.status(404).json({ error: `Config file not found: ${resolved}` });
      return;
    }

    const entries = parseConfigFile(resolved);
    // Strip env values — only return keys
    const safe = entries.map(e => ({
      name: e.name,
      transport: e.transport,
      command: e.command,
      args: e.args,
      url: e.url,
      envKeys: e.envKeys,
      sourcePath: e.sourcePath,
    }));

    res.json({ servers: safe, configPath: resolved });
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

// List available payloads (for attack filter UI)
app.get('/api/payloads', (_req, res) => {
  const safe = PAYLOADS.map(p => ({
    id: p.id,
    name: p.name,
    category: p.category,
    severity: p.severity,
    description: p.description,
    testSurface: p.testSurface,
  }));
  res.json({ payloads: safe });
});

// Start inspect run
app.post('/api/inspect/start', (req, res) => {
  const params = req.body as InspectStartParams;
  if (!params.configPath) {
    res.status(400).json({ error: 'configPath is required' });
    return;
  }

  const resolved = path.resolve(params.configPath);
  if (!fs.existsSync(resolved)) {
    res.status(404).json({ error: `Config file not found: ${resolved}` });
    return;
  }

  const runId = startInspectRun({ ...params, configPath: resolved });
  res.json({ runId });
});

// Start attack run
app.post('/api/attack/start', (req, res) => {
  const params = req.body as AttackStartParams;
  const result = startAttackRun(params);

  if (typeof result === 'string') {
    res.json({ runId: result });
  } else {
    res.status(400).json(result);
  }
});

// SSE stream for run events
app.get('/api/runs/:runId/events', (req, res) => {
  const { runId } = req.params;

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();

  const added = addClient(runId, res);
  if (!added) {
    res.write(`event: error\ndata: ${JSON.stringify({ message: 'Run not found' })}\n\n`);
    res.write(`event: done\ndata: {}\n\n`);
    res.end();
  }
});

// Cancel a run
app.post('/api/runs/:runId/cancel', (req, res) => {
  const { runId } = req.params;
  const cancelled = cancelRun(runId);
  res.json({ cancelled });
});

// List reports previously exported from the UI
app.get('/api/reports', (_req, res) => {
  try {
    if (!fs.existsSync(REPORTS_DIR)) {
      res.json({ reports: [] });
      return;
    }
    const reports = fs.readdirSync(REPORTS_DIR)
      .filter(f => f.endsWith('.json'))
      .map(f => {
        const stat = fs.statSync(path.join(REPORTS_DIR, f));
        return { name: f, size: stat.size, modifiedAt: stat.mtime.toISOString() };
      })
      .sort((a, b) => b.modifiedAt.localeCompare(a.modifiedAt));
    res.json({ reports });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

// Load a report file (any local .json path, e.g. CLI --output files)
app.post('/api/reports/load', (req, res) => {
  const { filePath } = req.body as { filePath?: string };
  if (!filePath || typeof filePath !== 'string') {
    res.status(400).json({ error: 'filePath is required' });
    return;
  }

  try {
    // Bare names resolve against the reports directory; paths resolve as given
    const resolved = path.isAbsolute(filePath) || filePath.includes(path.sep)
      ? path.resolve(filePath)
      : path.resolve(REPORTS_DIR, filePath);
    if (!resolved.endsWith('.json')) {
      res.status(400).json({ error: 'Only .json report files can be loaded' });
      return;
    }
    if (!fs.existsSync(resolved)) {
      res.status(404).json({ error: `Report file not found: ${resolved}` });
      return;
    }

    const raw = fs.readFileSync(resolved, 'utf-8');
    const report = JSON.parse(raw);

    // Redact any sensitive text in the loaded report
    const redacted = JSON.parse(redactSensitiveText(JSON.stringify(report)));
    res.json({ report: redacted });
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

// Export report into the reports directory (writes outside it are rejected)
app.post('/api/reports/export', (req, res) => {
  const { fileName, report } = req.body as { fileName?: string; report?: unknown };
  if (!fileName || typeof fileName !== 'string' || !report) {
    res.status(400).json({ error: 'fileName and report are required' });
    return;
  }

  try {
    const name = fileName.endsWith('.json') ? fileName : `${fileName}.json`;
    const resolved = path.resolve(REPORTS_DIR, name);
    if (!resolved.startsWith(REPORTS_DIR + path.sep)) {
      res.status(400).json({ error: 'Export path must stay within the reports directory' });
      return;
    }
    fs.mkdirSync(path.dirname(resolved), { recursive: true });
    const redacted = JSON.parse(redactSensitiveText(JSON.stringify(report)));
    fs.writeFileSync(resolved, JSON.stringify(redacted, null, 2), 'utf-8');
    res.json({ exported: resolved });
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

// Serve static UI in production
const uiDistPath = path.resolve(import.meta.dirname, '..', 'ui', 'dist');
if (fs.existsSync(uiDistPath)) {
  app.use(express.static(uiDistPath));
  // SPA fallback (Express 5 rejects bare '*' route patterns)
  app.use((req, res, next) => {
    if (req.method !== 'GET' || req.path.startsWith('/api/')) {
      next();
      return;
    }
    res.sendFile(path.join(uiDistPath, 'index.html'));
  });
}

const PORT = parseInt(process.env['UI_PORT'] ?? '3457', 10);

// Bind loopback only — this server can read local files and launch MCP
// server processes, so it must never be reachable from the network.
app.listen(PORT, '127.0.0.1', () => {
  console.log(`MCP Security Sentinel UI server running on http://localhost:${PORT}`);
  if (process.env['ANTHROPIC_API_KEY']) {
    console.log('  ANTHROPIC_API_KEY: detected (attack mode available)');
  } else {
    console.log('  ANTHROPIC_API_KEY: not set (inspect mode only)');
  }
});
