import { describe, it, expect, vi, afterAll } from 'vitest';
import { runConfigGate } from '../src/configGate.js';
import type { McpConfigServerEntry, StaticFinding } from '../src/types.js';

const logs: string[] = [];
const originalLog = console.log;
console.log = (...args: unknown[]) => {
  logs.push(args.map(a => (typeof a === 'string' ? a : String(a))).join(' '));
};

afterAll(() => {
  console.log = originalLog;
});

function makeEntry(name: string, transport: McpConfigServerEntry['transport'] = 'stdio'): McpConfigServerEntry {
  return {
    name,
    transport,
    command: `run-${name}`,
    args: [],
    envKeys: [],
    sourcePath: '/fake/config.json',
    rawPath: `mcpServers.${name}`,
  };
}

function makeFinding(ruleId: string, serverName: string): StaticFinding {
  return {
    mode: 'static',
    ruleId,
    ruleName: `Rule ${ruleId}`,
    category: 'config_command_risk',
    severity: 'high',
    owaspRefs: [],
    slowmistRef: '',
    serverName,
    matches: [],
    riskScore: 5,
    remediation: 'fix it',
  };
}

describe('runConfigGate', () => {
  it('returns all denied with --no-execute', async () => {
    const entries = [makeEntry('a'), makeEntry('b')];
    const result = await runConfigGate(entries, [], { noExecute: true });
    expect(result.approved).toHaveLength(0);
    expect(result.denied).toHaveLength(2);
    expect(result.executeMode).toBe(false);
  });

  it('approves specific server with --server + --yes', async () => {
    const entries = [makeEntry('alpha'), makeEntry('beta')];
    const result = await runConfigGate(entries, [], { server: 'alpha', yes: true });
    expect(result.approved).toHaveLength(1);
    expect(result.approved[0].name).toBe('alpha');
    expect(result.denied).toHaveLength(1);
    expect(result.denied[0].name).toBe('beta');
    expect(result.executeMode).toBe(true);
  });

  it('errors when --server name not found', async () => {
    const entries = [makeEntry('alpha')];
    await expect(runConfigGate(entries, [], { server: 'missing', yes: true }))
      .rejects.toThrow(/missing/);
  });

  it('approves all with --all --yes', async () => {
    const entries = [makeEntry('x'), makeEntry('y'), makeEntry('z')];
    const result = await runConfigGate(entries, [], { all: true, yes: true });
    expect(result.approved).toHaveLength(3);
    expect(result.denied).toHaveLength(0);
    expect(result.executeMode).toBe(true);
  });

  it('errors when --yes used without --all or --server', async () => {
    const entries = [makeEntry('a')];
    await expect(runConfigGate(entries, [], { yes: true }))
      .rejects.toThrow(/--yes requires --all or --server/);
  });

  it('displays config findings in output', async () => {
    logs.length = 0;
    const entries = [makeEntry('srv')];
    const findings = [makeFinding('STATIC-007', 'srv')];
    await runConfigGate(entries, findings, { all: true });
    const output = logs.join('\n');
    expect(output).toMatch(/STATIC-007/);
  });

  it('displays server inventory even with --yes', async () => {
    logs.length = 0;
    const entry = makeEntry('myserver', 'http');
    await runConfigGate([entry], [], { all: true, yes: true });
    const output = logs.join('\n');
    expect(output).toMatch(/myserver/);
    expect(output).toMatch(/http/);
  });
});
