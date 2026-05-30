// src/index.ts
import 'dotenv/config';
import type { Severity, SentinelResult } from './types.js';
import { printReport, writeJsonReport, toRedactedJson } from './reporter.js';
import type { InspectOptions } from './inspect.js';

const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
const SEVERITY_ORDER: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

// ─── Shared validation ───

const KNOWN_INSPECT_FLAGS = new Set([
  '--command', '--arg', '--config', '--server', '--all', '--yes', '--no-execute',
  '--read-resources', '--max-resources', '--max-resource-bytes',
  '--timeout-ms', '--enumeration-timeout-ms', '--resource-timeout-ms', '--max-pages',
  '--severity', '--fail-on', '--output', '--json', '--help', '-h',
]);

const KNOWN_ATTACK_FLAGS = new Set([
  '--payload', '--category', '--severity', '--tool', '--runs',
  '--agent-model', '--judge-model', '--no-baseline',
  '--fail-on', '--output', '--json', '--help', '-h',
]);

const VALUE_FLAGS_INSPECT = new Set([
  '--command', '--arg', '--config', '--server', '--max-resources', '--max-resource-bytes',
  '--timeout-ms', '--enumeration-timeout-ms', '--resource-timeout-ms', '--max-pages',
  '--severity', '--fail-on', '--output',
]);

const VALUE_FLAGS_ATTACK = new Set([
  '--payload', '--category', '--severity', '--tool', '--runs',
  '--agent-model', '--judge-model', '--fail-on', '--output',
]);

const NUMERIC_FLAGS = new Set([
  '--max-resources', '--max-resource-bytes', '--timeout-ms',
  '--enumeration-timeout-ms', '--resource-timeout-ms', '--max-pages', '--runs',
]);

function validateFlags(argv: string[], knownFlags: Set<string>, valueFlags: Set<string>): void {
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag.startsWith('-')) {
      if (!knownFlags.has(flag)) {
        throw new Error(`Unknown flag: ${flag}`);
      }
      if (valueFlags.has(flag)) {
        const val = argv[i + 1];
        // --arg values may look like flags (e.g. --port=3000), so skip the dash check for --arg
        if (val === undefined || (flag !== '--arg' && val.startsWith('-'))) {
          throw new Error(`Flag ${flag} requires a value`);
        }
        if (NUMERIC_FLAGS.has(flag)) {
          const num = parseInt(val, 10);
          if (!Number.isInteger(num) || num <= 0) {
            throw new Error(`Flag ${flag} must be a positive integer, got "${val}"`);
          }
        }
        i++; // skip value
      }
    }
  }
}

function validateSeverityValue(value: string, flagName: string): Severity {
  if (!VALID_SEVERITIES.includes(value as Severity)) {
    throw new Error(`${flagName} must be one of: ${VALID_SEVERITIES.join(', ')}`);
  }
  return value as Severity;
}

// ─── Inspect args ───

export function parseInspectArgs(argv: string[]): InspectOptions & { help?: boolean } {
  // Check for --help first (skip validation for help)
  if (argv.includes('--help') || argv.includes('-h')) {
    return { mode: 'command', help: true };
  }

  validateFlags(argv, KNOWN_INSPECT_FLAGS, VALUE_FLAGS_INSPECT);

  const opts: InspectOptions & { help?: boolean } = {
    mode: 'command',
    args: [],
    failOn: 'high' as Severity,
  };

  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '--command':       opts.mode = 'command'; opts.command = argv[++i]; break;
      case '--arg':           opts.args = opts.args ?? []; opts.args.push(argv[++i]); break;
      case '--config':        opts.mode = 'config'; opts.configPath = argv[++i]; break;
      case '--server':        opts.server = argv[++i]; break;
      case '--all':           opts.all = true; break;
      case '--yes':           opts.yes = true; break;
      case '--no-execute':    opts.noExecute = true; break;
      case '--read-resources': opts.readResources = true; break;
      case '--max-resources': opts.maxResources = parseInt(argv[++i], 10); break;
      case '--max-resource-bytes': opts.maxResourceBytes = parseInt(argv[++i], 10); break;
      case '--timeout-ms':    opts.timeoutMs = parseInt(argv[++i], 10); break;
      case '--enumeration-timeout-ms': opts.enumerationTimeoutMs = parseInt(argv[++i], 10); break;
      case '--resource-timeout-ms': opts.resourceTimeoutMs = parseInt(argv[++i], 10); break;
      case '--max-pages':     opts.maxPages = parseInt(argv[++i], 10); break;
      case '--severity':      opts.severity = validateSeverityValue(argv[++i], '--severity'); break;
      case '--fail-on':       opts.failOn = validateSeverityValue(argv[++i], '--fail-on'); break;
      case '--output':        opts.output = argv[++i]; break;
      case '--json':          opts.json = true; break;
    }
  }

  // Mutual exclusion: --command and --config
  if (opts.command && opts.configPath) {
    throw new Error('--command and --config are mutually exclusive');
  }

  // inspect requires one of --command or --config
  if (!opts.command && !opts.configPath) {
    throw new Error('inspect requires --command or --config');
  }

  // --arg requires --command
  if (opts.args && opts.args.length > 0 && !opts.command) {
    throw new Error('--arg requires --command');
  }

  // Config-only flags require --config
  const configOnlyUsed = opts.server || opts.all || opts.yes || opts.noExecute;
  if (configOnlyUsed && opts.mode !== 'config') {
    throw new Error('--server, --all, --yes, and --no-execute require --config');
  }

  // --yes requires --all or --server
  if (opts.yes && !opts.all && !opts.server) {
    throw new Error('--yes requires --all or --server');
  }

  // --read-resources with --no-execute errors
  if (opts.readResources && opts.noExecute) {
    throw new Error('--read-resources cannot be used with --no-execute');
  }

  return opts;
}

// ─── Attack args ───

export interface AttackOptions {
  payloadId?: string;
  category?: string;
  severity?: Severity;
  tool?: string;
  runs: number;
  agentModel: string;
  judgeModel: string;
  noBaseline: boolean;
  failOn: Severity;
  output?: string;
  json?: boolean;
  help?: boolean;
}

export function parseAttackArgs(argv: string[]): AttackOptions {
  // Check for --help first
  if (argv.includes('--help') || argv.includes('-h')) {
    return { runs: 3, agentModel: 'claude-haiku-4-5-20251001', judgeModel: 'claude-sonnet-4-6', noBaseline: false, failOn: 'high', help: true };
  }

  validateFlags(argv, KNOWN_ATTACK_FLAGS, VALUE_FLAGS_ATTACK);

  const opts: AttackOptions = {
    runs: 3,
    agentModel: 'claude-haiku-4-5-20251001',
    judgeModel: 'claude-sonnet-4-6',
    noBaseline: false,
    failOn: 'high',
  };

  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '--payload':       opts.payloadId = argv[++i]; break;
      case '--category':      opts.category = argv[++i]; break;
      case '--severity':      opts.severity = validateSeverityValue(argv[++i], '--severity'); break;
      case '--tool':          opts.tool = argv[++i]; break;
      case '--runs':          opts.runs = parseInt(argv[++i], 10); break;
      case '--agent-model':   opts.agentModel = argv[++i]; break;
      case '--judge-model':   opts.judgeModel = argv[++i]; break;
      case '--no-baseline':   opts.noBaseline = true; break;
      case '--fail-on':       opts.failOn = validateSeverityValue(argv[++i], '--fail-on'); break;
      case '--output':        opts.output = argv[++i]; break;
      case '--json':          opts.json = true; break;
    }
  }

  return opts;
}

// ─── Shared helpers ───

function filterFindingsBySeverity<T extends { severity: Severity }>(
  findings: T[],
  min?: Severity
): T[] {
  if (!min) return findings;
  const threshold = SEVERITY_ORDER[min];
  return findings.filter(f => SEVERITY_ORDER[f.severity] >= threshold);
}

function applyFailOn(findings: Array<{ severity: Severity }>, failOn: Severity): number {
  const threshold = SEVERITY_ORDER[failOn];
  const worst = Math.max(0, ...findings.map(f => SEVERITY_ORDER[f.severity]));
  return worst >= threshold ? 1 : 0;
}

function toAttackResult(scan: import('./types.js').ScanResult): import('./types.js').AttackResult {
  return {
    mode: 'attack',
    targetServer: scan.targetServer,
    scanTimestamp: scan.scanTimestamp,
    agentModel: scan.agentModel,
    judgeModel: scan.judgeModel,
    baselineEnabled: scan.baselineEnabled,
    runsPerPayload: scan.runsPerPayload,
    totalPayloadsTested: scan.totalPayloadsTested,
    totalFindings: scan.totalFindings,
    criticalCount: scan.criticalCount,
    highCount: scan.highCount,
    mediumCount: scan.mediumCount,
    lowCount: scan.lowCount,
    findings: scan.findings.map(f => ({ ...f, mode: 'dynamic' as const })),
    summary: scan.summary,
  };
}

function printUsage(): void {
  console.log(`MCP Security Sentinel — MCP server security inspector

Usage:
  mcpsentinel inspect [options]    Inspect MCP servers (no API key required)
  mcpsentinel attack [options]     Run injection tests (requires ANTHROPIC_API_KEY)

Run mcpsentinel <command> --help for details.`);
}

function printInspectUsage(): void {
  console.log(`mcpsentinel inspect — Inspect MCP servers for security risks

Connection (one required):
  --command <binary>         Launch and inspect an MCP server via stdio
  --arg <value>              Argument for --command (repeatable)
  --config <path>            Parse MCP config file

Config selection (--config only):
  --server <name>            Inspect one server from config
  --all                      Select all servers
  --yes                      Skip interactive prompt (requires --all or --server)
  --no-execute               Config risk review only, do not connect

Resource inspection:
  --read-resources           Read resource contents (default: disabled)
  --max-resources <n>        Max resources to read (default: 10)

Timeouts:
  --timeout-ms <n>           Connection timeout (default: 10000)
  --enumeration-timeout-ms <n>  Per-list-call timeout (default: 5000)
  --max-pages <n>            Pagination limit (default: 20)

Output:
  --severity <level>         Report filter (critical|high|medium|low)
  --fail-on <level>          Exit non-zero threshold (default: high)
  --output <path>            Write JSON report to file
  --json                     Print JSON to stdout`);
}

function printAttackUsage(): void {
  console.log(`mcpsentinel attack — Run dynamic injection tests

Payload selection:
  --payload <id>             Test specific payload (e.g. INJ-001)
  --category <cat>           Test payloads in category
  --severity <level>         Test payloads at or above severity
  --tool <name>              Filter by oracle.forbiddenToolCalls

Execution:
  --runs <n>                 Runs per payload (default: 3)
  --agent-model <model>      Victim model (default: claude-haiku-4-5-20251001)
  --judge-model <model>      Judge model (default: claude-sonnet-4-6)
  --no-baseline              Disable baseline comparison

Output:
  --fail-on <level>          Exit non-zero threshold (default: high)
  --output <path>            Write JSON report to file
  --json                     Print JSON to stdout`);
}

// ─── Main ───

async function main(): Promise<void> {
  const command = process.argv[2];

  switch (command) {
    case 'inspect': {
      const opts = parseInspectArgs(process.argv.slice(3));
      if (opts.help) { printInspectUsage(); process.exit(0); }

      const { runInspect } = await import('./inspect.js');
      const result = await runInspect(opts);

      // Apply --severity filter before output
      const filteredFindings = filterFindingsBySeverity(result.findings, opts.severity);
      const filteredResult: typeof result = {
        ...result,
        findings: filteredFindings,
        totalFindings: filteredFindings.length,
        criticalCount: filteredFindings.filter(f => f.severity === 'critical').length,
        highCount: filteredFindings.filter(f => f.severity === 'high').length,
        mediumCount: filteredFindings.filter(f => f.severity === 'medium').length,
        lowCount: filteredFindings.filter(f => f.severity === 'low').length,
        summary: `${filteredFindings.length} finding(s) across ${result.serversInspected} server(s) inspected.`,
      };

      if (opts.json) {
        console.log(JSON.stringify(toRedactedJson(filteredResult), null, 2));
      } else {
        printReport(filteredResult);
      }
      if (opts.output) writeJsonReport(filteredResult, opts.output);
      process.exit(applyFailOn(filteredFindings, opts.failOn!));
      break;
    }

    case 'attack': {
      const opts = parseAttackArgs(process.argv.slice(3));
      if (opts.help) { printAttackUsage(); process.exit(0); }

      if (!process.env['ANTHROPIC_API_KEY']) {
        console.error('ANTHROPIC_API_KEY is required for attack mode.');
        console.error('Run "mcpsentinel inspect" for no-key static analysis.');
        process.exit(1);
      }

      if (!Number.isInteger(opts.runs) || opts.runs < 1) {
        console.error('--runs must be a positive integer');
        process.exit(1);
      }
      if (!VALID_SEVERITIES.includes(opts.failOn)) {
        console.error('--fail-on must be one of: critical, high, medium, low');
        process.exit(1);
      }

      const { PAYLOADS } = await import('./payloads.js');
      const { runScan } = await import('./scanner.js');

      let payloads = [...PAYLOADS];
      if (opts.payloadId) payloads = payloads.filter(p => p.id === opts.payloadId);
      if (opts.category) payloads = payloads.filter(p => p.category === opts.category);
      if (opts.severity) {
        const threshold = SEVERITY_ORDER[opts.severity];
        payloads = payloads.filter(p => SEVERITY_ORDER[p.severity] >= threshold);
      }
      if (opts.tool) {
        const toolName = opts.tool;
        payloads = payloads.filter(p => p.oracle.forbiddenToolCalls?.includes(toolName) ?? false);
      }

      if (payloads.length === 0) {
        console.error('No payloads match the specified filters.');
        process.exit(1);
      }

      let spinner: ReturnType<typeof import('ora').default> | null = null;
      if (!opts.json) {
        const ora = (await import('ora')).default;
        spinner = ora(`Testing ${payloads.length} payload(s) with ${opts.runs} run(s) each...`).start();
      }

      let scanResult;
      try {
        scanResult = await runScan({
          payloads,
          agentModel: opts.agentModel,
          judgeModel: opts.judgeModel,
          baselineEnabled: !opts.noBaseline,
          runs: opts.runs,
          targetServer: 'mock-mcp-server-v1',
        });
      } catch (err) {
        spinner?.fail('Scan failed');
        throw err;
      }

      spinner?.succeed(`Scan complete — ${scanResult.totalFindings} finding(s) detected`);

      const attackResult = toAttackResult(scanResult);

      if (opts.json) {
        console.log(JSON.stringify(toRedactedJson(attackResult), null, 2));
      } else {
        printReport(attackResult);
      }
      if (opts.output) writeJsonReport(attackResult, opts.output);

      process.exit(applyFailOn(attackResult.findings, opts.failOn));
      break;
    }

    case '--help':
    case '-h':
      printUsage();
      process.exit(0);
      break;

    default:
      printUsage();
      process.exit(1);
  }
}

// Only run main when executed directly
if (process.argv[1]?.endsWith('index.ts') || process.argv[1]?.endsWith('index.js')) {
  main().catch(err => {
    console.error(err);
    process.exit(1);
  });
}
