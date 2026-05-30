import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { McpInspectionSurface, StaticFinding, McpConfigServerEntry, GateDecision } from '../src/types.js';

// Mock all dependencies
vi.mock('../src/configParser.js', () => ({
  parseConfigFile: vi.fn(),
}));
vi.mock('../src/configGate.js', () => ({
  runConfigGate: vi.fn(),
}));
vi.mock('../src/mcpClient.js', () => ({
  inspectServer: vi.fn(),
}));
vi.mock('../src/staticRules.js', () => ({
  runStaticRules: vi.fn(),
  detectCrossServerCollisions: vi.fn(),
}));

import { runInspect } from '../src/inspect.js';
import { parseConfigFile } from '../src/configParser.js';
import { runConfigGate } from '../src/configGate.js';
import { inspectServer } from '../src/mcpClient.js';
import { runStaticRules, detectCrossServerCollisions } from '../src/staticRules.js';

const mockParseConfigFile = vi.mocked(parseConfigFile);
const mockRunConfigGate = vi.mocked(runConfigGate);
const mockInspectServer = vi.mocked(inspectServer);
const mockRunStaticRules = vi.mocked(runStaticRules);
const mockDetectCrossServerCollisions = vi.mocked(detectCrossServerCollisions);

function makeEntry(name: string): McpConfigServerEntry {
  return {
    name,
    transport: 'stdio',
    command: `run-${name}`,
    args: [],
    envKeys: [],
    sourcePath: '/fake/config.json',
    rawPath: `mcpServers.${name}`,
  };
}

function makeSurface(name: string): McpInspectionSurface {
  return {
    serverName: name,
    tools: [],
    resources: [],
    prompts: [],
    warnings: [],
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
    riskScore: 7,
    remediation: 'fix it',
  };
}

beforeEach(() => {
  vi.resetAllMocks();
  mockRunStaticRules.mockReturnValue([]);
  mockDetectCrossServerCollisions.mockReturnValue([]);
});

describe('runInspect', () => {
  it('handles --command mode: creates entry and calls inspectServer', async () => {
    const surface = makeSurface('my-cmd');
    mockInspectServer.mockResolvedValue({ success: true, surface });
    mockRunStaticRules.mockReturnValue([]);

    const result = await runInspect({
      mode: 'command',
      command: 'my-cmd',
      args: ['--arg1'],
    });

    expect(mockInspectServer).toHaveBeenCalledOnce();
    const callArg = mockInspectServer.mock.calls[0][0];
    expect(callArg.entry.command).toBe('my-cmd');
    expect(callArg.entry.args).toEqual(['--arg1']);
    expect(callArg.entry.transport).toBe('stdio');

    expect(result.mode).toBe('inspect');
    expect(result.serversInspected).toBe(1);
    expect(result.warnings).toHaveLength(0);
  });

  it('handles --config --no-execute: does not call inspectServer', async () => {
    const entries = [makeEntry('alpha'), makeEntry('beta')];
    mockParseConfigFile.mockReturnValue(entries);
    const gate: GateDecision = { approved: [], denied: entries, executeMode: false };
    mockRunConfigGate.mockResolvedValue(gate);

    const result = await runInspect({
      mode: 'config',
      configPath: '/fake/config.json',
      noExecute: true,
    });

    expect(mockInspectServer).not.toHaveBeenCalled();
    expect(result.mode).toBe('inspect');
    expect(result.serversInspected).toBe(0);
  });

  it('config findings persist after live inspection', async () => {
    const entry = makeEntry('srv');
    mockParseConfigFile.mockReturnValue([entry]);
    const gate: GateDecision = { approved: [entry], denied: [], executeMode: true };
    mockRunConfigGate.mockResolvedValue(gate);
    mockInspectServer.mockResolvedValue({ success: true, surface: makeSurface('srv') });

    const configFinding = makeFinding('STATIC-008', 'srv');
    const liveFinding = makeFinding('STATIC-001', 'srv');

    // First call (config surface) returns configFinding, second call (live surface) returns liveFinding
    mockRunStaticRules
      .mockReturnValueOnce([configFinding])
      .mockReturnValueOnce([liveFinding]);

    const result = await runInspect({
      mode: 'config',
      configPath: '/fake/config.json',
      all: true,
      yes: true,
    });

    expect(result.findings).toHaveLength(2);
    expect(result.findings).toContain(configFinding);
    expect(result.findings).toContain(liveFinding);
    expect(result.totalFindings).toBe(2);
  });

  it('handles server connection failure as warning', async () => {
    const entry = makeEntry('failing-srv');
    mockParseConfigFile.mockReturnValue([entry]);
    const gate: GateDecision = { approved: [entry], denied: [], executeMode: true };
    mockRunConfigGate.mockResolvedValue(gate);
    mockInspectServer.mockResolvedValue({
      success: false,
      serverName: 'failing-srv',
      error: 'Connection refused',
      sourcePath: '/fake/config.json',
    });

    const result = await runInspect({
      mode: 'config',
      configPath: '/fake/config.json',
      all: true,
      yes: true,
    });

    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0].serverName).toBe('failing-srv');
    expect(result.warnings[0].message).toBe('Connection refused');
    expect(result.serversInspected).toBe(0);
  });

  it('does not call inspectServer when no servers approved', async () => {
    const entries = [makeEntry('a'), makeEntry('b')];
    mockParseConfigFile.mockReturnValue(entries);
    const gate: GateDecision = { approved: [], denied: entries, executeMode: true };
    mockRunConfigGate.mockResolvedValue(gate);

    const result = await runInspect({
      mode: 'config',
      configPath: '/fake/config.json',
    });

    expect(mockInspectServer).not.toHaveBeenCalled();
    expect(result.serversInspected).toBe(0);
  });
});
