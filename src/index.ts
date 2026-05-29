import ora from 'ora';
import { PAYLOADS } from './payloads.js';
import { runScan } from './scanner.js';
import { printReport, writeJsonReport } from './reporter.js';
import type { InjectionPayload, Severity } from './types.js';

export interface CliOptions {
  tool: string | null;
  severity: Severity | null;
  output: string | null;
  quick: boolean;
  runs: number;
  failOn: Severity;
  model: string;
  judgeModel: string;
  noBaseline: boolean;
  payloadId: string | null;
}

const DEFAULT_AGENT_MODEL = 'claude-haiku-4-5-20251001';
const DEFAULT_JUDGE_MODEL = 'claude-sonnet-4-6';
const SEVERITY_ORDER: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    tool: null,
    severity: null,
    output: null,
    quick: false,
    runs: 1,
    failOn: 'low',
    model: DEFAULT_AGENT_MODEL,
    judgeModel: DEFAULT_JUDGE_MODEL,
    noBaseline: false,
    payloadId: null,
  };

  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '--tool':         opts.tool = argv[++i]; break;
      case '--severity':     opts.severity = argv[++i] as Severity; break;
      case '--output':       opts.output = argv[++i]; break;
      case '--quick':        opts.quick = true; break;
      case '--runs':         opts.runs = parseInt(argv[++i], 10); break;
      case '--fail-on':      opts.failOn = argv[++i] as Severity; break;
      case '--model':        opts.model = argv[++i]; break;
      case '--judge-model':  opts.judgeModel = argv[++i]; break;
      case '--no-baseline':  opts.noBaseline = true; break;
      case '--payload':      opts.payloadId = argv[++i]; break;
    }
  }

  if (!Number.isInteger(opts.runs) || opts.runs < 1) {
    console.error(`--runs must be a positive integer`);
    process.exit(1);
  }

  const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
  if (!VALID_SEVERITIES.includes(opts.failOn)) {
    console.error(`--fail-on must be one of: critical, high, medium, low`);
    process.exit(1);
  }
  if (opts.severity !== null && !VALID_SEVERITIES.includes(opts.severity)) {
    console.error(`--severity must be one of: critical, high, medium, low`);
    process.exit(1);
  }

  return opts;
}

export function filterPayloads(payloads: InjectionPayload[], opts: CliOptions): InjectionPayload[] {
  let filtered = [...payloads];

  if (opts.payloadId) {
    filtered = filtered.filter(p => p.id === opts.payloadId);
  }
  if (opts.quick) {
    filtered = filtered.filter(p => p.severity === 'critical' || p.severity === 'high');
  }
  if (opts.severity) {
    filtered = filtered.filter(p => p.severity === opts.severity);
  }
  // --tool filters by oracle.forbiddenToolCalls — matches payloads that explicitly
  // forbid the named tool call, not all payloads targeting that tool's surface
  if (opts.tool) {
    const toolName = opts.tool;
    filtered = filtered.filter(p => p.oracle.forbiddenToolCalls?.includes(toolName) ?? false);
  }

  return filtered;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  const payloads = filterPayloads(PAYLOADS, opts);

  if (payloads.length === 0) {
    console.error('No payloads match the specified filters.');
    process.exit(1);
  }

  console.log('MCP Security Sentinel v1.0.0');
  if (opts.noBaseline) {
    console.log('⚠ --no-baseline: baseline disabled, findings may include false positives');
  }

  const spinner = ora(`Testing ${payloads.length} payload(s) with ${opts.runs} run(s) each...`).start();

  let result;
  try {
    result = await runScan({
      payloads,
      agentModel: opts.model,
      judgeModel: opts.judgeModel,
      baselineEnabled: !opts.noBaseline,
      runs: opts.runs,
      targetServer: 'mock-mcp-server-v1',
    });
  } catch (err) {
    spinner.fail('Scan failed');
    throw err;
  }

  spinner.succeed(`Scan complete — ${result.totalFindings} finding(s) detected`);

  printReport(result);

  if (opts.output) {
    writeJsonReport(result, opts.output);
    console.log(`JSON report written to: ${opts.output}`);
  }

  const failLevel = SEVERITY_ORDER[opts.failOn];
  const shouldFail = result.findings.some(f => SEVERITY_ORDER[f.severity] >= failLevel);
  process.exit(shouldFail ? 1 : 0);
}

// Only run main when executed directly (not when imported by tests)
if (process.argv[1]?.endsWith('index.ts') || process.argv[1]?.endsWith('index.js')) {
  main().catch(err => {
    console.error(err);
    process.exit(1);
  });
}
