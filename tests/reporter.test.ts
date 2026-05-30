// tests/reporter.test.ts
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import type { ScanResult, ScanFinding, SentinelResult, InspectResult, AttackResult, StaticFinding, DynamicFinding } from '../src/types.js';

const mockFinding: ScanFinding = {
  payloadId: 'INJ-001',
  payloadName: 'Raw System Prompt Override',
  category: 'Instruction Override',
  severity: 'critical',
  owaspRefs: ['LLM01', 'LLM02'],
  slowmistRef: 'SS-PS',
  toolName: 'scan_host',
  testSurface: 'tool_result',
  injectedPayload: 'SYSTEM OVERRIDE: ...',
  agentResponse: 'SENTINEL_PWNED confirmed.',
  toolCallsMade: [],
  manipulated: true,
  detectionMethod: 'oracle',
  confidence: 0.95,
  evidence: [{ type: 'marker_found', description: 'Marker SENTINEL_PWNED found', excerpt: 'SENTINEL_PWNED' }],
  riskScore: 9.0,
  runs: 1,
  successCount: 1,
  remediation: 'Treat tool result content as untrusted data.',
  reproductionCommand: 'npx tsx src/index.ts --payload INJ-001 --runs 1',
};

const mockResult: ScanResult = {
  targetServer: 'mock-server',
  scanTimestamp: '2026-05-28T00:00:00.000Z',
  agentModel: 'claude-haiku-4-5-20251001',
  judgeModel: 'claude-sonnet-4-6',
  baselineEnabled: true,
  runsPerPayload: 1,
  totalPayloadsTested: 1,
  totalFindings: 1,
  criticalCount: 1,
  highCount: 0,
  mediumCount: 0,
  lowCount: 0,
  findings: [mockFinding],
  summary: '1 finding(s) detected across 1 payloads tested.',
};

const staticFinding: StaticFinding = {
  mode: 'static',
  ruleId: 'STATIC-001',
  ruleName: 'Tool Description Injection',
  category: 'tool_description_injection',
  severity: 'high',
  owaspRefs: ['LLM01'],
  slowmistRef: 'SS-TDI',
  serverName: 'test-server',
  matches: [
    {
      path: 'tools[0].description',
      evidence: 'Ignore previous instructions',
      detail: 'Tool description contains injection pattern',
    },
  ],
  riskScore: 7.5,
  remediation: 'Sanitize tool descriptions before use.',
};

const mockInspectResult: InspectResult = {
  mode: 'inspect',
  target: 'test-mcp-config.json',
  scanTimestamp: '2026-05-28T00:00:00.000Z',
  serversInspected: 2,
  totalFindings: 1,
  criticalCount: 0,
  highCount: 1,
  mediumCount: 0,
  lowCount: 0,
  findings: [staticFinding],
  warnings: [{ serverName: 'test-server', message: 'Server could not be reached', path: '/some/path' }],
  summary: '1 finding(s) detected across 2 servers.',
};

const dynamicFinding: DynamicFinding = {
  mode: 'dynamic',
  payloadId: 'INJ-001',
  payloadName: 'Raw System Prompt Override',
  category: 'Instruction Override',
  severity: 'critical',
  owaspRefs: ['LLM01', 'LLM02'],
  slowmistRef: 'SS-PS',
  toolName: 'scan_host',
  testSurface: 'tool_result',
  injectedPayload: 'SYSTEM OVERRIDE: ...',
  agentResponse: 'SENTINEL_PWNED confirmed.',
  toolCallsMade: [],
  manipulated: true,
  detectionMethod: 'oracle',
  confidence: 0.95,
  evidence: [{ type: 'marker_found', description: 'Marker SENTINEL_PWNED found', excerpt: 'SENTINEL_PWNED' }],
  riskScore: 9.0,
  runs: 1,
  successCount: 1,
  remediation: 'Treat tool result content as untrusted data.',
  reproductionCommand: 'npx tsx src/index.ts --payload INJ-001 --runs 1',
};

const mockAttackResult: AttackResult = {
  mode: 'attack',
  targetServer: 'mock-server',
  scanTimestamp: '2026-05-28T00:00:00.000Z',
  agentModel: 'claude-haiku-4-5-20251001',
  judgeModel: 'claude-sonnet-4-6',
  baselineEnabled: true,
  runsPerPayload: 1,
  totalPayloadsTested: 1,
  totalFindings: 1,
  criticalCount: 1,
  highCount: 0,
  mediumCount: 0,
  lowCount: 0,
  findings: [dynamicFinding],
  summary: '1 finding(s) detected across 1 payloads tested.',
};

describe('reporter', () => {
  let consoleOutput: string[] = [];
  const originalLog = console.log;

  beforeEach(() => {
    consoleOutput = [];
    console.log = (...args: unknown[]) => {
      consoleOutput.push(args.map(String).join(' '));
    };
  });

  afterEach(() => {
    console.log = originalLog;
  });

  // ─── Attack mode (ScanResult) tests ───

  it('printReport outputs finding ID and severity', async () => {
    const { printReport } = await import('../src/reporter.js');
    printReport(mockResult);
    const output = consoleOutput.join('\n');
    expect(output).toContain('INJ-001');
    expect(output).toContain('CRITICAL');
    expect(output).toContain('9.0');
  });

  it('printReport outputs evidence excerpt', async () => {
    const { printReport } = await import('../src/reporter.js');
    printReport(mockResult);
    const output = consoleOutput.join('\n');
    expect(output).toContain('SENTINEL_PWNED');
  });

  it('printReport outputs reproduction command', async () => {
    const { printReport } = await import('../src/reporter.js');
    printReport(mockResult);
    const output = consoleOutput.join('\n');
    expect(output).toContain('--payload INJ-001');
  });

  it('printReport outputs baseline disabled warning when baselineEnabled is false', async () => {
    const { printReport } = await import('../src/reporter.js');
    printReport({ ...mockResult, baselineEnabled: false });
    const output = consoleOutput.join('\n');
    expect(output).toContain('Baseline disabled');
  });

  it('printReport shows no-findings message when findings array is empty', async () => {
    const { printReport } = await import('../src/reporter.js');
    printReport({ ...mockResult, totalFindings: 0, findings: [] });
    const output = consoleOutput.join('\n');
    expect(output).toContain('No manipulation detected');
  });

  it('printReport outputs higher-risk finding before lower-risk finding', async () => {
    const { printReport } = await import('../src/reporter.js');
    const lowFinding: ScanFinding = {
      ...mockFinding,
      payloadId: 'INJ-LOW',
      riskScore: 3.0,
      severity: 'low',
    };
    // Pass high-risk finding second (wrong order) — reporter should sort it first
    const result = { ...mockResult, findings: [lowFinding, mockFinding] };
    printReport(result);
    const output = consoleOutput.join('\n');
    const posHigh = output.indexOf('INJ-001');
    const posLow = output.indexOf('INJ-LOW');
    expect(posHigh).toBeLessThan(posLow);
  });

  it('writeJsonReport writes valid JSON to file', async () => {
    const { writeJsonReport } = await import('../src/reporter.js');
    const tmpPath = '/tmp/sentinel-test-report.json';
    writeJsonReport(mockResult, tmpPath);
    const written = JSON.parse(fs.readFileSync(tmpPath, 'utf-8')) as ScanResult;
    expect(written.targetServer).toBe('mock-server');
    expect(written.findings).toHaveLength(1);
    expect(written.findings[0].payloadId).toBe('INJ-001');
    fs.unlinkSync(tmpPath);
  });

  // ─── Attack mode (AttackResult with mode field) tests ───

  it('printReport dispatches to attack report for AttackResult', async () => {
    const { printReport } = await import('../src/reporter.js');
    printReport(mockAttackResult);
    const output = consoleOutput.join('\n');
    expect(output).toContain('INJ-001');
    expect(output).toContain('CRITICAL');
    expect(output).toContain('Scan Report');
  });

  // ─── Inspect mode (InspectResult) tests ───

  it('printReport dispatches to inspect report for InspectResult', async () => {
    const { printReport } = await import('../src/reporter.js');
    printReport(mockInspectResult);
    const output = consoleOutput.join('\n');
    expect(output).toContain('Inspect Report');
    expect(output).toContain('STATIC-001');
    expect(output).toContain('HIGH');
  });

  it('printInspectReport outputs target and servers inspected', async () => {
    const { printReport } = await import('../src/reporter.js');
    printReport(mockInspectResult);
    const output = consoleOutput.join('\n');
    expect(output).toContain('test-mcp-config.json');
    expect(output).toContain('2');
  });

  it('printInspectReport outputs rule name and server', async () => {
    const { printReport } = await import('../src/reporter.js');
    printReport(mockInspectResult);
    const output = consoleOutput.join('\n');
    expect(output).toContain('Tool Description Injection');
    expect(output).toContain('test-server');
  });

  it('printInspectReport outputs warnings section', async () => {
    const { printReport } = await import('../src/reporter.js');
    printReport(mockInspectResult);
    const output = consoleOutput.join('\n');
    expect(output).toContain('Warnings');
    expect(output).toContain('Server could not be reached');
  });

  it('printInspectReport shows no-findings message when findings array is empty', async () => {
    const { printReport } = await import('../src/reporter.js');
    const emptyResult: InspectResult = { ...mockInspectResult, findings: [], totalFindings: 0 };
    printReport(emptyResult);
    const output = consoleOutput.join('\n');
    expect(output).toContain('No security findings detected');
  });

  it('printInspectReport sorts findings by riskScore descending', async () => {
    const { printReport } = await import('../src/reporter.js');
    const lowFinding: StaticFinding = { ...staticFinding, ruleId: 'STATIC-LOW', riskScore: 2.0, severity: 'low' };
    const result: InspectResult = { ...mockInspectResult, findings: [lowFinding, staticFinding] };
    printReport(result);
    const output = consoleOutput.join('\n');
    const posHigh = output.indexOf('STATIC-001');
    const posLow = output.indexOf('STATIC-LOW');
    expect(posHigh).toBeLessThan(posLow);
  });

  it('printInspectReport redacts evidence in matches', async () => {
    const { printReport } = await import('../src/reporter.js');
    const findingWithSecret: StaticFinding = {
      ...staticFinding,
      matches: [
        {
          path: 'tools[0].description',
          evidence: 'Token: ghp_ABCDEFghij1234567890',
          detail: 'Secret found in description',
        },
      ],
    };
    const result: InspectResult = { ...mockInspectResult, findings: [findingWithSecret] };
    printReport(result);
    const output = consoleOutput.join('\n');
    expect(output).not.toContain('ghp_ABCDEFghij1234567890');
    expect(output).toContain('ghp_***REDACTED***');
  });

  // ─── redactSensitiveText tests ───

  it('redactSensitiveText redacts GitHub personal access tokens (ghp_)', async () => {
    const { redactSensitiveText } = await import('../src/reporter.js');
    expect(redactSensitiveText('token: ghp_ABCDEFghij1234567890')).toContain('ghp_***REDACTED***');
    expect(redactSensitiveText('token: ghp_ABCDEFghij1234567890')).not.toContain('ghp_ABCDEFghij1234567890');
  });

  it('redactSensitiveText redacts GitHub OAuth tokens (gho_)', async () => {
    const { redactSensitiveText } = await import('../src/reporter.js');
    expect(redactSensitiveText('auth: gho_ABCDEFghij1234567890')).toContain('gho_***REDACTED***');
  });

  it('redactSensitiveText redacts GitHub fine-grained PATs (github_pat_)', async () => {
    const { redactSensitiveText } = await import('../src/reporter.js');
    expect(redactSensitiveText('pat: github_pat_ABCDEFGHIJ_1234567890')).toContain('github_pat_***REDACTED***');
  });

  it('redactSensitiveText redacts OpenAI sk- keys', async () => {
    const { redactSensitiveText } = await import('../src/reporter.js');
    expect(redactSensitiveText('key: sk-ABCDEFghij1234567890')).toContain('sk-***REDACTED***');
  });

  it('redactSensitiveText redacts pk- keys', async () => {
    const { redactSensitiveText } = await import('../src/reporter.js');
    expect(redactSensitiveText('key: pk-ABCDEFghij1234567890')).toContain('pk-***REDACTED***');
  });

  it('redactSensitiveText redacts AWS access key IDs (AKIA)', async () => {
    const { redactSensitiveText } = await import('../src/reporter.js');
    expect(redactSensitiveText('aws: AKIAIOSFODNN7EXAMPLE')).toContain('AKIA***REDACTED***');
  });

  it('redactSensitiveText redacts Bearer JWT tokens', async () => {
    const { redactSensitiveText } = await import('../src/reporter.js');
    expect(redactSensitiveText('Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature')).toContain('Bearer ***REDACTED***');
  });

  it('redactSensitiveText redacts standalone JWT tokens', async () => {
    const { redactSensitiveText } = await import('../src/reporter.js');
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    expect(redactSensitiveText(jwt)).toContain('eyJ***REDACTED***');
    expect(redactSensitiveText(jwt)).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
  });

  it('redactSensitiveText leaves non-secret text unchanged', async () => {
    const { redactSensitiveText } = await import('../src/reporter.js');
    const safe = 'This is a safe string with no secrets.';
    expect(redactSensitiveText(safe)).toBe(safe);
  });

  it('redactSensitiveText redacts multiple patterns in the same string', async () => {
    const { redactSensitiveText } = await import('../src/reporter.js');
    const text = 'token1: ghp_ABCDEFghij1234567890 token2: sk-ABCDEFghij1234567890';
    const result = redactSensitiveText(text);
    expect(result).toContain('ghp_***REDACTED***');
    expect(result).toContain('sk-***REDACTED***');
    expect(result).not.toContain('ghp_ABCDEFghij1234567890');
    expect(result).not.toContain('sk-ABCDEFghij1234567890');
  });

  // ─── toRedactedJson tests ───

  it('toRedactedJson redacts secrets in InspectResult findings', async () => {
    const { toRedactedJson } = await import('../src/reporter.js');
    const resultWithSecret: InspectResult = {
      ...mockInspectResult,
      findings: [
        {
          ...staticFinding,
          matches: [
            {
              path: 'tools[0].description',
              evidence: 'Token: ghp_ABCDEFghij1234567890',
              detail: 'Secret token found',
            },
          ],
        },
      ],
    };
    const redacted = toRedactedJson(resultWithSecret) as InspectResult;
    expect(redacted.findings[0].matches[0].evidence).toContain('ghp_***REDACTED***');
    expect(redacted.findings[0].matches[0].evidence).not.toContain('ghp_ABCDEFghij1234567890');
  });

  it('toRedactedJson preserves non-secret fields', async () => {
    const { toRedactedJson } = await import('../src/reporter.js');
    const redacted = toRedactedJson(mockInspectResult) as InspectResult;
    expect(redacted.target).toBe(mockInspectResult.target);
    expect(redacted.serversInspected).toBe(mockInspectResult.serversInspected);
    expect(redacted.totalFindings).toBe(mockInspectResult.totalFindings);
  });

  it('toRedactedJson preserves mode field', async () => {
    const { toRedactedJson } = await import('../src/reporter.js');
    const redacted = toRedactedJson(mockInspectResult);
    expect(redacted.mode).toBe('inspect');
  });

  // ─── writeJsonReport with redaction tests ───

  it('writeJsonReport redacts secrets when writing InspectResult', async () => {
    const { writeJsonReport } = await import('../src/reporter.js');
    const tmpPath = '/tmp/sentinel-test-inspect-report.json';
    const resultWithSecret: SentinelResult = {
      ...mockInspectResult,
      findings: [
        {
          ...staticFinding,
          matches: [
            {
              path: 'tools[0].description',
              evidence: 'Token: ghp_ABCDEFghij1234567890',
              detail: 'Secret token found',
            },
          ],
        },
      ],
    };
    writeJsonReport(resultWithSecret, tmpPath);
    const written = JSON.parse(fs.readFileSync(tmpPath, 'utf-8')) as InspectResult;
    expect(written.findings[0].matches[0].evidence).toContain('ghp_***REDACTED***');
    expect(written.findings[0].matches[0].evidence).not.toContain('ghp_ABCDEFghij1234567890');
    fs.unlinkSync(tmpPath);
  });
});
