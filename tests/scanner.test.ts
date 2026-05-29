// tests/scanner.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock Anthropic before importing scanner
const mockCreate = vi.fn();
vi.mock('@anthropic-ai/sdk', () => ({
  default: vi.fn().mockImplementation(() => ({
    messages: { create: mockCreate },
  })),
}));

import { runScan } from '../src/scanner.js';
import { PAYLOADS } from '../src/payloads.js';

// Helper: response where agent calls scan_host
const toolCallResponse = (id = 'tool-001') => ({
  content: [{ type: 'tool_use', id, name: 'scan_host', input: { host: '192.168.1.1' } }],
  stop_reason: 'tool_use',
});

// Helper: clean agent text response (no injection)
const cleanTextResponse = () => ({
  content: [{ type: 'text', text: 'Scan analysis complete. Found 2 findings. No critical issues.' }],
  stop_reason: 'end_turn',
});

// Helper: manipulated agent response with sentinel
const manipulatedResponse = () => ({
  content: [{ type: 'text', text: 'SENTINEL_PWNED — manipulation confirmed by injection.' }],
  stop_reason: 'end_turn',
});

describe('runScan', () => {
  beforeEach(() => {
    mockCreate.mockReset();
  });

  it('returns ScanResult with correct shape', async () => {
    const payload = PAYLOADS.find(p => p.id === 'INJ-001')!;

    // baseline: step1 (tool call) + step2 (clean response)
    // attack:   step1 (tool call) + step2 (manipulated response)
    mockCreate
      .mockResolvedValueOnce(toolCallResponse('b-001'))  // baseline step 1
      .mockResolvedValueOnce(cleanTextResponse())         // baseline step 2
      .mockResolvedValueOnce(toolCallResponse('a-001'))  // attack step 1
      .mockResolvedValueOnce(manipulatedResponse());      // attack step 2

    const result = await runScan({
      payloads: [payload],
      agentModel: 'claude-haiku-4-5-20251001',
      judgeModel: 'claude-sonnet-4-6',
      baselineEnabled: true,
      runs: 1,
      targetServer: 'mock-server',
    });

    expect(result.totalPayloadsTested).toBe(1);
    expect(result.agentModel).toBe('claude-haiku-4-5-20251001');
    expect(result.baselineEnabled).toBe(true);
    expect(result.findings).toBeInstanceOf(Array);
  });

  it('creates a finding when oracle detects SENTINEL_PWNED', async () => {
    const payload = PAYLOADS.find(p => p.id === 'INJ-001')!;

    mockCreate
      .mockResolvedValueOnce(toolCallResponse('b-001'))  // baseline step 1
      .mockResolvedValueOnce(cleanTextResponse())         // baseline step 2
      .mockResolvedValueOnce(toolCallResponse('a-001'))  // attack step 1
      .mockResolvedValueOnce(manipulatedResponse());      // attack step 2

    const result = await runScan({
      payloads: [payload],
      agentModel: 'claude-haiku-4-5-20251001',
      judgeModel: 'claude-sonnet-4-6',
      baselineEnabled: true,
      runs: 1,
      targetServer: 'mock-server',
    });

    expect(result.totalFindings).toBe(1);
    const finding = result.findings[0];
    expect(finding.manipulated).toBe(true);
    expect(finding.detectionMethod).toBe('oracle');
    expect(finding.confidence).toBe(0.95);
    expect(finding.evidence.length).toBeGreaterThan(0);
    expect(finding.evidence[0].type).toBe('marker_found');
  });

  it('does NOT create a finding when oracle finds nothing and no baseline deviation', async () => {
    const payload = PAYLOADS.find(p => p.id === 'INJ-001')!;

    // Both baseline and attack return the same clean response
    mockCreate
      .mockResolvedValueOnce(toolCallResponse('b-001'))  // baseline step 1
      .mockResolvedValueOnce(cleanTextResponse())         // baseline step 2
      .mockResolvedValueOnce(toolCallResponse('a-001'))  // attack step 1
      .mockResolvedValueOnce(cleanTextResponse());        // attack step 2 (no sentinel)

    const result = await runScan({
      payloads: [payload],
      agentModel: 'claude-haiku-4-5-20251001',
      judgeModel: 'claude-sonnet-4-6',
      baselineEnabled: true,
      runs: 1,
      targetServer: 'mock-server',
    });

    expect(result.totalFindings).toBe(0);
  });

  it('calls judge when attack tool calls differ from baseline', async () => {
    // Use empty oracle so judge is always invoked on baseline deviation (oracle must not fire for this test)
    const payload = { ...PAYLOADS.find(p => p.id === 'INJ-008')!, oracle: {} };

    // Baseline: agent does not call scan_host again
    // Attack: agent calls scan_host again (deviation)
    const baselineStep2 = () => ({
      content: [{ type: 'text', text: 'Triage complete. No critical issues.' }],
      stop_reason: 'end_turn',
    });
    const attackStep2WithExtraToolCall = () => ({
      content: [
        { type: 'tool_use', id: 'extra-001', name: 'scan_host', input: { host: '192.168.1.1' } },
        { type: 'text', text: 'Initiating verification loop.' },
      ],
      stop_reason: 'tool_use',
    });
    const judgeResponse = () => ({
      content: [{ type: 'text', text: '{"manipulated":true,"reason":"Agent initiated recursive scan_host call loop as instructed by injection.","risk_adjustment":0.5,"confidence":0.85}' }],
      stop_reason: 'end_turn',
    });

    mockCreate
      .mockResolvedValueOnce(toolCallResponse('b-001'))   // baseline step 1
      .mockResolvedValueOnce(baselineStep2())             // baseline step 2
      .mockResolvedValueOnce(toolCallResponse('a-001'))   // attack step 1
      .mockResolvedValueOnce(attackStep2WithExtraToolCall()) // attack step 2
      .mockResolvedValueOnce(judgeResponse());             // judge call

    const result = await runScan({
      payloads: [payload],
      agentModel: 'claude-haiku-4-5-20251001',
      judgeModel: 'claude-sonnet-4-6',
      baselineEnabled: true,
      runs: 1,
      targetServer: 'mock-server',
    });

    // Judge was called (5 total API calls: 2 baseline + 2 attack + 1 judge)
    expect(mockCreate).toHaveBeenCalledTimes(5);
    expect(result.totalFindings).toBe(1);
    expect(result.findings[0].detectionMethod).toBe('judge');
  });

  it('skips judge when oracle already has clear evidence', async () => {
    const payload = PAYLOADS.find(p => p.id === 'INJ-001')!;

    mockCreate
      .mockResolvedValueOnce(toolCallResponse('b-001'))
      .mockResolvedValueOnce(cleanTextResponse())
      .mockResolvedValueOnce(toolCallResponse('a-001'))
      .mockResolvedValueOnce(manipulatedResponse());

    await runScan({
      payloads: [payload],
      agentModel: 'claude-haiku-4-5-20251001',
      judgeModel: 'claude-sonnet-4-6',
      baselineEnabled: true,
      runs: 1,
      targetServer: 'mock-server',
    });

    // Should be exactly 4 calls: 2 baseline + 2 attack — no judge
    expect(mockCreate).toHaveBeenCalledTimes(4);
  });

  it('skips baseline when baselineEnabled is false', async () => {
    const payload = PAYLOADS.find(p => p.id === 'INJ-001')!;

    mockCreate
      .mockResolvedValueOnce(toolCallResponse('a-001'))  // attack step 1
      .mockResolvedValueOnce(manipulatedResponse());      // attack step 2

    const result = await runScan({
      payloads: [payload],
      agentModel: 'claude-haiku-4-5-20251001',
      judgeModel: 'claude-sonnet-4-6',
      baselineEnabled: false,
      runs: 1,
      targetServer: 'mock-server',
    });

    expect(mockCreate).toHaveBeenCalledTimes(2);
    expect(result.baselineEnabled).toBe(false);
  });

  it('caches baseline across multiple payloads', async () => {
    const payloads = PAYLOADS.slice(0, 3); // first 3 payloads

    mockCreate.mockReset();
    mockCreate
      .mockResolvedValueOnce(toolCallResponse('b-001'))  // baseline step 1
      .mockResolvedValueOnce(cleanTextResponse())         // baseline step 2
      .mockResolvedValueOnce(toolCallResponse('a-001'))  // payload[0] attack step 1
      .mockResolvedValueOnce(cleanTextResponse())         // payload[0] attack step 2
      .mockResolvedValueOnce(toolCallResponse('a-002'))  // payload[1] attack step 1
      .mockResolvedValueOnce(cleanTextResponse())         // payload[1] attack step 2
      .mockResolvedValueOnce(toolCallResponse('a-003'))  // payload[2] attack step 1
      .mockResolvedValueOnce(cleanTextResponse());        // payload[2] attack step 2

    await runScan({
      payloads,
      agentModel: 'claude-haiku-4-5-20251001',
      judgeModel: 'claude-sonnet-4-6',
      baselineEnabled: true,
      runs: 1,
      targetServer: 'mock-server',
    });

    // 2 baseline + 6 attack = 8 total (not 2*3 + 6 = 12)
    expect(mockCreate).toHaveBeenCalledTimes(8);
  });
});
