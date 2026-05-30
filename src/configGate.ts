import chalk from 'chalk';
import readline from 'readline';
import type { McpConfigServerEntry, StaticFinding, GateDecision } from './types.js';

export interface GateFlags {
  server?: string;
  all?: boolean;
  yes?: boolean;
  noExecute?: boolean;
}

function displayInventory(entries: McpConfigServerEntry[]): void {
  console.log(chalk.bold('\nServer Inventory:'));
  console.log(chalk.dim('─'.repeat(60)));
  for (const e of entries) {
    const detail = e.url ?? e.command ?? '';
    console.log(`  ${chalk.cyan(e.name)}  [${e.transport}]  ${chalk.dim(detail)}`);
  }
  console.log(chalk.dim('─'.repeat(60)));
}

function displayConfigFindings(findings: StaticFinding[]): void {
  if (findings.length === 0) return;
  console.log(chalk.bold('\nConfig Findings:'));
  for (const f of findings) {
    const severityColors: Record<string, (s: string) => string> = {
      critical: (s: string) => chalk.red.bold(s),
      high: (s: string) => chalk.yellow.bold(s),
      medium: (s: string) => chalk.cyan.bold(s),
      low: (s: string) => chalk.white.bold(s),
    };
    const colorFn = severityColors[f.severity] ?? ((s: string) => s);
    console.log(`  ${colorFn(`[${f.severity.toUpperCase()}]`)} ${f.ruleId} — ${f.ruleName} (${f.serverName})`);
  }
}

async function promptUser(entries: McpConfigServerEntry[]): Promise<McpConfigServerEntry[]> {
  const names = entries.map(e => e.name);
  console.log(chalk.bold('\nSelect servers to approve (comma-separated names, "all", or "none"):'));
  console.log(`  Available: ${names.join(', ')}`);

  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question('  > ', (answer) => {
      rl.close();
      const trimmed = answer.trim().toLowerCase();
      if (trimmed === 'all') {
        resolve(entries);
      } else if (trimmed === 'none' || trimmed === '') {
        resolve([]);
      } else {
        const selected = trimmed.split(',').map(s => s.trim());
        resolve(entries.filter(e => selected.includes(e.name)));
      }
    });
  });
}

export async function runConfigGate(
  entries: McpConfigServerEntry[],
  configFindings: StaticFinding[],
  flags: GateFlags,
): Promise<GateDecision> {
  // Validate: --yes requires --all or --server
  if (flags.yes && !flags.all && !flags.server) {
    throw new Error('--yes requires --all or --server');
  }

  // Validate: --server name must exist
  if (flags.server) {
    const names = entries.map(e => e.name);
    if (!names.includes(flags.server)) {
      throw new Error(`Server "${flags.server}" not found. Available: ${names.join(', ')}`);
    }
  }

  // Always display inventory and findings
  displayInventory(entries);
  displayConfigFindings(configFindings);

  // --no-execute: deny all
  if (flags.noExecute) {
    return { approved: [], denied: [...entries], executeMode: false };
  }

  // --server: approve only that server
  if (flags.server) {
    const serverName = flags.server;
    const approved = entries.filter(e => e.name === serverName);
    const denied = entries.filter(e => e.name !== serverName);
    return { approved, denied, executeMode: true };
  }

  // --all: approve all
  if (flags.all) {
    return { approved: [...entries], denied: [], executeMode: true };
  }

  // Interactive prompt
  const approved = await promptUser(entries);
  const approvedNames = new Set(approved.map(e => e.name));
  const denied = entries.filter(e => !approvedNames.has(e.name));
  return { approved, denied, executeMode: true };
}
