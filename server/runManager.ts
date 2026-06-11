import type { ServerResponse } from 'http';
import type {
  McpConfigServerEntry,
  McpInspectionSurface,
  StaticFinding,
  InspectResult,
  ConnectOptions,
  Severity,
  InjectionPayload,
} from '../src/types.js';
import { parseConfigFile } from '../src/configParser.js';
import { runStaticRules, detectCrossServerCollisions } from '../src/staticRules.js';
import { inspectServer } from '../src/mcpClient.js';
import { redactSensitiveText } from '../src/reporter.js';

export type RunStatus = 'starting' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface RunState {
  id: string;
  mode: 'inspect' | 'attack';
  status: RunStatus;
  clients: Set<ServerResponse>;
  abortController: AbortController;
  findings: unknown[]; // buffered for replay to late-connecting SSE clients
  result?: unknown;
  error?: string;
}

const runs = new Map<string, RunState>();
let runCounter = 0;

function generateRunId(): string {
  return `run-${++runCounter}-${Date.now()}`;
}

export function getRun(runId: string): RunState | undefined {
  return runs.get(runId);
}

function sendSSE(res: ServerResponse, event: string, data: unknown): void {
  if (res.writableEnded) return;
  const json = JSON.stringify(data);
  res.write(`event: ${event}\ndata: ${json}\n\n`);
}

function broadcast(run: RunState, event: string, data: unknown): void {
  if (event === 'finding') run.findings.push(data);
  for (const client of run.clients) {
    sendSSE(client, event, data);
  }
}

function redactEntry(entry: McpConfigServerEntry): Record<string, unknown> {
  return {
    name: entry.name,
    transport: entry.transport,
    command: entry.command,
    args: entry.args,
    url: entry.url,
    envKeys: entry.envKeys,
    sourcePath: entry.sourcePath,
  };
}

function redactFinding(finding: StaticFinding): StaticFinding {
  return {
    ...finding,
    matches: finding.matches.map(m => ({
      ...m,
      evidence: redactSensitiveText(m.evidence),
      detail: redactSensitiveText(m.detail),
    })),
  };
}

function buildInspectResult(
  target: string,
  serversInspected: number,
  findings: StaticFinding[],
  warnings: Array<{ serverName?: string; message: string; path?: string }>,
): InspectResult {
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const mediumCount = findings.filter(f => f.severity === 'medium').length;
  const lowCount = findings.filter(f => f.severity === 'low').length;
  const totalFindings = findings.length;

  const parts: string[] = [];
  if (criticalCount) parts.push(`${criticalCount} critical`);
  if (highCount) parts.push(`${highCount} high`);
  if (mediumCount) parts.push(`${mediumCount} medium`);
  if (lowCount) parts.push(`${lowCount} low`);

  return {
    mode: 'inspect',
    target,
    scanTimestamp: new Date().toISOString(),
    serversInspected,
    totalFindings,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    findings,
    warnings,
    summary: totalFindings === 0
      ? `No findings across ${serversInspected} server(s)`
      : `${totalFindings} finding(s): ${parts.join(', ')} across ${serversInspected} server(s)`,
  };
}

export interface InspectStartParams {
  configPath: string;
  noExecute?: boolean;
  readResources?: boolean;
  maxResources?: number;
  maxResourceBytes?: number;
  timeoutMs?: number;
  enumerationTimeoutMs?: number;
  resourceTimeoutMs?: number;
  maxPages?: number;
  approvedServers?: string[]; // server names to inspect (empty = config-only)
}

export function startInspectRun(params: InspectStartParams): string {
  const runId = generateRunId();
  const run: RunState = {
    id: runId,
    mode: 'inspect',
    status: 'starting',
    clients: new Set(),
    abortController: new AbortController(),
    findings: [],
  };
  runs.set(runId, run);

  // Run async inspection without awaiting
  runInspectAsync(run, params).catch(() => {});
  return runId;
}

async function runInspectAsync(run: RunState, params: InspectStartParams): Promise<void> {
  try {
    run.status = 'running';
    broadcast(run, 'status', { status: 'running' });

    // Parse config
    let entries: McpConfigServerEntry[];
    try {
      entries = parseConfigFile(params.configPath);
    } catch (err) {
      run.status = 'failed';
      run.error = err instanceof Error ? err.message : String(err);
      broadcast(run, 'error', { message: run.error });
      broadcast(run, 'done', {});
      return;
    }

    // Send inventory (redacted)
    broadcast(run, 'inventory', {
      servers: entries.map(redactEntry),
    });

    // Config-level static rules
    const configFindings: StaticFinding[] = [];
    for (const entry of entries) {
      const configSurface: McpInspectionSurface = {
        serverName: entry.name,
        configEntry: entry,
        tools: [],
        resources: [],
        prompts: [],
        warnings: [],
      };
      const findings = runStaticRules(configSurface, { configOnly: true });
      for (const f of findings) {
        const redacted = redactFinding(f);
        configFindings.push(redacted);
        broadcast(run, 'finding', redacted);
      }
    }

    // If no-execute or no approved servers, return config-only results
    if (params.noExecute || !params.approvedServers || params.approvedServers.length === 0) {
      const result = buildInspectResult(params.configPath, 0, configFindings, []);
      run.result = result;
      run.status = 'completed';
      broadcast(run, 'result', result);
      broadcast(run, 'done', {});
      return;
    }

    // Filter to approved servers only
    const approved = entries.filter(e => params.approvedServers!.includes(e.name));
    const warnings: Array<{ serverName?: string; message: string; path?: string }> = [];
    const allFindings: StaticFinding[] = [...configFindings];
    const successSurfaces: McpInspectionSurface[] = [];

    for (let i = 0; i < approved.length; i++) {
      if (run.abortController.signal.aborted) {
        run.status = 'cancelled';
        broadcast(run, 'status', { status: 'cancelled' });
        broadcast(run, 'done', {});
        return;
      }

      const entry = approved[i];
      broadcast(run, 'progress', {
        current: i + 1,
        total: approved.length,
        serverName: entry.name,
        message: `Inspecting ${entry.name}...`,
      });

      const connectOpts: ConnectOptions = { entry };
      if (params.timeoutMs !== undefined) connectOpts.timeoutMs = params.timeoutMs;
      if (params.enumerationTimeoutMs !== undefined) connectOpts.enumerationTimeoutMs = params.enumerationTimeoutMs;
      if (params.maxPages !== undefined) connectOpts.maxPages = params.maxPages;
      if (params.readResources !== undefined) connectOpts.readResources = params.readResources;
      if (params.maxResources !== undefined) connectOpts.maxResources = params.maxResources;
      if (params.maxResourceBytes !== undefined) connectOpts.maxResourceBytes = params.maxResourceBytes;
      if (params.resourceTimeoutMs !== undefined) connectOpts.resourceTimeoutMs = params.resourceTimeoutMs;

      const outcome = await inspectServer(connectOpts);

      if (!outcome.success) {
        const warning = {
          serverName: outcome.serverName,
          message: outcome.error,
          path: outcome.sourcePath,
        };
        warnings.push(warning);
        broadcast(run, 'warning', warning);
        continue;
      }

      successSurfaces.push(outcome.surface);
      const findings = runStaticRules(outcome.surface);
      for (const f of findings) {
        const redacted = redactFinding(f);
        allFindings.push(redacted);
        broadcast(run, 'finding', redacted);
      }
    }

    // Cross-server collision detection
    const collisionFindings = detectCrossServerCollisions(successSurfaces);
    for (const f of collisionFindings) {
      const redacted = redactFinding(f);
      allFindings.push(redacted);
      broadcast(run, 'finding', redacted);
    }

    const result = buildInspectResult(params.configPath, successSurfaces.length, allFindings, warnings);
    run.result = result;
    run.status = 'completed';
    broadcast(run, 'result', result);
    broadcast(run, 'done', {});
  } catch (err) {
    run.status = 'failed';
    run.error = err instanceof Error ? err.message : String(err);
    broadcast(run, 'error', { message: run.error });
    broadcast(run, 'done', {});
  }
}

export interface AttackStartParams {
  payloadId?: string;
  category?: string;
  severity?: Severity;
  tool?: string;
  runs: number;
  agentModel: string;
  judgeModel: string;
  noBaseline: boolean;
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function startAttackRun(params: AttackStartParams): string | { error: string } {
  if (!process.env['ANTHROPIC_API_KEY']) {
    return { error: 'Attack mode requires ANTHROPIC_API_KEY environment variable' };
  }

  const runId = generateRunId();
  const run: RunState = {
    id: runId,
    mode: 'attack',
    status: 'starting',
    clients: new Set(),
    abortController: new AbortController(),
    findings: [],
  };
  runs.set(runId, run);

  runAttackAsync(run, params).catch(() => {});
  return runId;
}

async function runAttackAsync(run: RunState, params: AttackStartParams): Promise<void> {
  try {
    run.status = 'running';
    broadcast(run, 'status', { status: 'running' });

    const { PAYLOADS } = await import('../src/payloads.js');
    const { runScan } = await import('../src/scanner.js');

    let payloads: InjectionPayload[] = [...PAYLOADS];
    if (params.payloadId) payloads = payloads.filter(p => p.id === params.payloadId);
    if (params.category) payloads = payloads.filter(p => p.category === params.category);
    if (params.severity) {
      const threshold = SEVERITY_ORDER[params.severity];
      payloads = payloads.filter(p => SEVERITY_ORDER[p.severity] >= threshold);
    }
    if (params.tool) {
      const toolName = params.tool;
      payloads = payloads.filter(p => p.oracle.forbiddenToolCalls?.includes(toolName) ?? false);
    }

    if (payloads.length === 0) {
      run.status = 'failed';
      run.error = 'No payloads match the specified filters';
      broadcast(run, 'error', { message: run.error });
      broadcast(run, 'done', {});
      return;
    }

    broadcast(run, 'progress', {
      current: 0,
      total: payloads.length,
      message: `Testing ${payloads.length} payload(s) with ${params.runs} run(s) each...`,
    });

    const scanResult = await runScan({
      payloads,
      agentModel: params.agentModel,
      judgeModel: params.judgeModel,
      baselineEnabled: !params.noBaseline,
      runs: params.runs,
      targetServer: 'mock-mcp-server-v1',
    });

    // Redact sensitive text in findings
    const redactedFindings = scanResult.findings.map(f => ({
      ...f,
      agentResponse: redactSensitiveText(f.agentResponse),
      injectedPayload: redactSensitiveText(f.injectedPayload),
      evidence: f.evidence.map(e => ({
        ...e,
        excerpt: e.excerpt ? redactSensitiveText(e.excerpt) : undefined,
      })),
    }));

    const result = {
      mode: 'attack' as const,
      targetServer: scanResult.targetServer,
      scanTimestamp: scanResult.scanTimestamp,
      agentModel: scanResult.agentModel,
      judgeModel: scanResult.judgeModel,
      baselineEnabled: scanResult.baselineEnabled,
      runsPerPayload: scanResult.runsPerPayload,
      totalPayloadsTested: scanResult.totalPayloadsTested,
      totalFindings: scanResult.totalFindings,
      criticalCount: scanResult.criticalCount,
      highCount: scanResult.highCount,
      mediumCount: scanResult.mediumCount,
      lowCount: scanResult.lowCount,
      findings: redactedFindings.map(f => ({ ...f, mode: 'dynamic' as const })),
      summary: scanResult.summary,
    };

    for (const f of result.findings) {
      broadcast(run, 'finding', f);
    }

    run.result = result;
    run.status = 'completed';
    broadcast(run, 'result', result);
    broadcast(run, 'done', {});
  } catch (err) {
    run.status = 'failed';
    run.error = err instanceof Error ? err.message : String(err);
    broadcast(run, 'error', { message: run.error });
    broadcast(run, 'done', {});
  }
}

export function cancelRun(runId: string): boolean {
  const run = runs.get(runId);
  if (!run || run.status === 'completed' || run.status === 'failed' || run.status === 'cancelled') {
    return false;
  }
  run.abortController.abort();
  run.status = 'cancelled';
  broadcast(run, 'status', { status: 'cancelled' });
  broadcast(run, 'done', {});
  return true;
}

export function addClient(runId: string, res: ServerResponse): boolean {
  const run = runs.get(runId);
  if (!run) return false;

  run.clients.add(res);
  res.on('close', () => {
    run.clients.delete(res);
  });

  // Replay findings broadcast before this client connected
  for (const finding of run.findings) {
    sendSSE(res, 'finding', finding);
  }

  // If run already completed, send the result immediately
  if (run.status === 'completed' && run.result) {
    sendSSE(res, 'result', run.result);
    sendSSE(res, 'done', {});
  } else if (run.status === 'failed') {
    sendSSE(res, 'error', { message: run.error });
    sendSSE(res, 'done', {});
  } else if (run.status === 'cancelled') {
    sendSSE(res, 'status', { status: 'cancelled' });
    sendSSE(res, 'done', {});
  }

  return true;
}
