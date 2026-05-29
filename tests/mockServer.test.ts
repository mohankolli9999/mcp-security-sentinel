import { describe, it, expect } from 'vitest';
import { MockMCPServer } from '../src/mockServer.js';

describe('MockMCPServer', () => {
  const server = new MockMCPServer();

  it('scan_host returns JSON with findings array', () => {
    const result = JSON.parse(server.handleToolCall('scan_host', { host: '10.0.0.1' }));
    expect(result.findings).toBeInstanceOf(Array);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0]).toHaveProperty('severity');
  });

  it('get_cve_details returns JSON with cvss_score', () => {
    const result = JSON.parse(server.handleToolCall('get_cve_details', { cve_id: 'CVE-2024-1234' }));
    expect(result.cvss_score).toBeTypeOf('number');
    expect(result.description).toBeTruthy();
  });

  it('triage_finding returns verdict', () => {
    const result = JSON.parse(server.handleToolCall('triage_finding', { finding_id: 'VULN-001' }));
    expect(result.verdict).toMatch(/^(true_positive|false_positive)$/);
    expect(result.confidence).toBeTypeOf('number');
  });

  it('send_report returns status sent', () => {
    const result = JSON.parse(server.handleToolCall('send_report', { recipient: 'a@b.com', subject: 'test' }));
    expect(result.status).toBe('sent');
    expect(result.message_id).toBeTruthy();
  });

  it('returns injectedResponse when provided, ignoring real tool logic', () => {
    const injected = '{"manipulated":true}';
    const result = server.handleToolCall('scan_host', { host: '10.0.0.1' }, injected);
    expect(result).toBe(injected);
  });

  it('returns injectedResponse even for an unknown tool name', () => {
    const injected = '{"pwned":true}';
    const result = server.handleToolCall('nonexistent_tool', {}, injected);
    expect(result).toBe(injected);
  });

  it('throws on unknown tool name', () => {
    expect(() => server.handleToolCall('unknown_tool', {})).toThrow('Unknown tool: unknown_tool');
  });
});
