import type {
  McpConfigServerEntry,
  McpInspectionSurface,
  StaticFinding,
  InspectResult,
  ConnectOptions,
  Severity,
} from './types.js';
import { parseConfigFile } from './configParser.js';
import { runConfigGate } from './configGate.js';
import { inspectServer } from './mcpClient.js';
import { runStaticRules, detectCrossServerCollisions } from './staticRules.js';

export type { InspectResult };

export interface InspectOptions {
  mode: 'command' | 'config';
  command?: string;
  args?: string[];
  configPath?: string;
  server?: string;
  all?: boolean;
  yes?: boolean;
  noExecute?: boolean;
  readResources?: boolean;
  maxResources?: number;
  maxResourceBytes?: number;
  timeoutMs?: number;
  enumerationTimeoutMs?: number;
  resourceTimeoutMs?: number;
  maxPages?: number;
  severity?: Severity;
  failOn?: Severity;
  output?: string;
  sarif?: string;
  json?: boolean;
}

function buildConnectOptions(entry: McpConfigServerEntry, opts: InspectOptions): ConnectOptions {
  const result: ConnectOptions = { entry };
  if (opts.timeoutMs !== undefined) result.timeoutMs = opts.timeoutMs;
  if (opts.enumerationTimeoutMs !== undefined) result.enumerationTimeoutMs = opts.enumerationTimeoutMs;
  if (opts.maxPages !== undefined) result.maxPages = opts.maxPages;
  if (opts.readResources !== undefined) result.readResources = opts.readResources;
  if (opts.maxResources !== undefined) result.maxResources = opts.maxResources;
  if (opts.maxResourceBytes !== undefined) result.maxResourceBytes = opts.maxResourceBytes;
  if (opts.resourceTimeoutMs !== undefined) result.resourceTimeoutMs = opts.resourceTimeoutMs;
  return result;
}

function buildResult(
  target: string,
  serversInspected: number,
  findings: StaticFinding[],
  warnings: Array<{ serverName?: string; message: string; path?: string }>,
): InspectResult {
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  for (const f of findings) {
    if (f.severity === 'critical') criticalCount++;
    else if (f.severity === 'high') highCount++;
    else if (f.severity === 'medium') mediumCount++;
    else if (f.severity === 'low') lowCount++;
  }

  const totalFindings = findings.length;
  const parts: string[] = [];
  if (criticalCount) parts.push(`${criticalCount} critical`);
  if (highCount) parts.push(`${highCount} high`);
  if (mediumCount) parts.push(`${mediumCount} medium`);
  if (lowCount) parts.push(`${lowCount} low`);

  const summary = totalFindings === 0
    ? `No findings across ${serversInspected} server(s)`
    : `${totalFindings} finding(s): ${parts.join(', ')} across ${serversInspected} server(s)`;

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
    summary,
  };
}

async function inspectCommand(opts: InspectOptions): Promise<InspectResult> {
  const entry: McpConfigServerEntry = {
    name: opts.command ?? 'command',
    transport: 'stdio',
    command: opts.command,
    args: opts.args ?? [],
    envKeys: [],
    sourcePath: '',
    rawPath: '',
  };

  const warnings: Array<{ serverName?: string; message: string; path?: string }> = [];
  const connectOpts = buildConnectOptions(entry, opts);
  const outcome = await inspectServer(connectOpts);

  if (!outcome.success) {
    warnings.push({ serverName: outcome.serverName, message: outcome.error });
    return buildResult(opts.command ?? 'command', 0, [], warnings);
  }

  const findings = runStaticRules(outcome.surface);
  return buildResult(opts.command ?? 'command', 1, findings, warnings);
}

async function inspectConfig(opts: InspectOptions): Promise<InspectResult> {
  if (!opts.configPath) {
    throw new Error('configPath is required for config mode');
  }

  const entries = parseConfigFile(opts.configPath);
  const warnings: Array<{ serverName?: string; message: string; path?: string }> = [];

  // Config-level static rules: run on surfaces with just configEntry set
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
    configFindings.push(...runStaticRules(configSurface, { configOnly: true }));
  }

  const gateDecision = await runConfigGate(entries, configFindings, {
    server: opts.server,
    all: opts.all,
    yes: opts.yes,
    noExecute: opts.noExecute,
  });

  const executeMode = gateDecision.executeMode;

  if (!executeMode) {
    return buildResult(opts.configPath, 0, configFindings, warnings);
  }

  // Live inspection for approved servers
  const allFindings: StaticFinding[] = [...configFindings];
  const successSurfaces: McpInspectionSurface[] = [];

  for (const entry of gateDecision.approved) {
    const connectOpts = buildConnectOptions(entry, opts);
    const outcome = await inspectServer(connectOpts);

    if (!outcome.success) {
      warnings.push({
        serverName: outcome.serverName,
        message: outcome.error,
        path: outcome.sourcePath,
      });
      continue;
    }

    successSurfaces.push(outcome.surface);
    allFindings.push(...runStaticRules(outcome.surface));
  }

  // Cross-server collision detection
  const collisionFindings = detectCrossServerCollisions(successSurfaces);
  allFindings.push(...collisionFindings);

  const serversInspected = successSurfaces.length;
  return buildResult(opts.configPath, serversInspected, allFindings, warnings);
}

export async function runInspect(opts: InspectOptions): Promise<InspectResult> {
  if (opts.mode === 'command') {
    return inspectCommand(opts);
  }
  return inspectConfig(opts);
}
