// tests/reporter.test.ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import type { ScanResult, ScanFinding } from '../src/types.js';

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
});
