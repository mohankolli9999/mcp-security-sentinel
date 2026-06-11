const BASE = '';

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || res.statusText);
  }
  return res.json();
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || res.statusText);
  }
  return res.json();
}

export interface HealthResponse {
  status: string;
  hasApiKey: boolean;
  version: string;
}

export interface ServerEntry {
  name: string;
  transport: string;
  command?: string;
  args?: string[];
  url?: string;
  envKeys: string[];
  sourcePath: string;
}

export interface ConfigParseResponse {
  servers: ServerEntry[];
  configPath: string;
}

export interface PayloadInfo {
  id: string;
  name: string;
  category: string;
  severity: string;
  description: string;
  testSurface: string;
}

export interface ReportFileInfo {
  name: string;
  size: number;
  modifiedAt: string;
}

export const api = {
  health: () => get<HealthResponse>('/api/health'),
  parseConfig: (configPath: string) =>
    post<ConfigParseResponse>('/api/config/parse', { configPath }),
  getPayloads: () => get<{ payloads: PayloadInfo[] }>('/api/payloads'),
  startInspect: (params: Record<string, unknown>) =>
    post<{ runId: string }>('/api/inspect/start', params),
  startAttack: (params: Record<string, unknown>) =>
    post<{ runId: string }>('/api/attack/start', params),
  cancelRun: (runId: string) =>
    post<{ cancelled: boolean }>(`/api/runs/${runId}/cancel`),
  listReports: () => get<{ reports: ReportFileInfo[] }>('/api/reports'),
  loadReport: (filePath: string) =>
    post<{ report: unknown }>('/api/reports/load', { filePath }),
  exportReport: (fileName: string, report: unknown) =>
    post<{ exported: string }>('/api/reports/export', { fileName, report }),
};

export type SSEEvent = {
  event: string;
  data: unknown;
};

export function subscribeToRun(
  runId: string,
  onEvent: (event: string, data: unknown) => void,
): () => void {
  const es = new EventSource(`${BASE}/api/runs/${runId}/events`);

  const events = ['status', 'inventory', 'finding', 'warning', 'progress', 'result', 'error', 'done'];
  for (const eventName of events) {
    es.addEventListener(eventName, (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        onEvent(eventName, data);
      } catch {
        onEvent(eventName, e.data);
      }
    });
  }

  es.onerror = () => {
    es.close();
  };

  return () => es.close();
}
