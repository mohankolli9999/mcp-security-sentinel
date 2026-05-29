import { describe, it, expect } from 'vitest';
import { parseArgs, filterPayloads } from '../src/index.js';
import { PAYLOADS } from '../src/payloads.js';

describe('parseArgs', () => {
  it('returns defaults with no args', () => {
    const opts = parseArgs([]);
    expect(opts.quick).toBe(false);
    expect(opts.runs).toBe(1);
    expect(opts.failOn).toBe('low');
    expect(opts.noBaseline).toBe(false);
    expect(opts.payloadId).toBeNull();
    expect(opts.tool).toBeNull();
  });

  it('parses --quick flag', () => {
    const opts = parseArgs(['--quick']);
    expect(opts.quick).toBe(true);
  });

  it('parses --runs value', () => {
    const opts = parseArgs(['--runs', '3']);
    expect(opts.runs).toBe(3);
  });

  it('parses --no-baseline flag', () => {
    const opts = parseArgs(['--no-baseline']);
    expect(opts.noBaseline).toBe(true);
  });

  it('parses --payload id', () => {
    const opts = parseArgs(['--payload', 'INJ-004']);
    expect(opts.payloadId).toBe('INJ-004');
  });

  it('parses --severity', () => {
    const opts = parseArgs(['--severity', 'critical']);
    expect(opts.severity).toBe('critical');
  });

  it('parses --fail-on', () => {
    const opts = parseArgs(['--fail-on', 'high']);
    expect(opts.failOn).toBe('high');
  });

  it('parses --model and --judge-model', () => {
    const opts = parseArgs(['--model', 'claude-haiku-4-5-20251001', '--judge-model', 'claude-sonnet-4-6']);
    expect(opts.model).toBe('claude-haiku-4-5-20251001');
    expect(opts.judgeModel).toBe('claude-sonnet-4-6');
  });

  it('parses --output path', () => {
    const opts = parseArgs(['--output', '/tmp/report.json']);
    expect(opts.output).toBe('/tmp/report.json');
  });
});

describe('filterPayloads', () => {
  it('returns all payloads with default options', () => {
    const opts = parseArgs([]);
    expect(filterPayloads(PAYLOADS, opts)).toHaveLength(PAYLOADS.length);
  });

  it('--quick returns only critical and high payloads', () => {
    const opts = parseArgs(['--quick']);
    const filtered = filterPayloads(PAYLOADS, opts);
    expect(filtered.every(p => p.severity === 'critical' || p.severity === 'high')).toBe(true);
    expect(filtered.length).toBeGreaterThan(0);
  });

  it('--severity critical returns only critical payloads', () => {
    const opts = parseArgs(['--severity', 'critical']);
    const filtered = filterPayloads(PAYLOADS, opts);
    expect(filtered.every(p => p.severity === 'critical')).toBe(true);
  });

  it('--payload INJ-004 returns exactly one payload', () => {
    const opts = parseArgs(['--payload', 'INJ-004']);
    const filtered = filterPayloads(PAYLOADS, opts);
    expect(filtered).toHaveLength(1);
    expect(filtered[0].id).toBe('INJ-004');
  });

  it('--tool send_report returns payloads that forbid send_report calls', () => {
    const opts = parseArgs(['--tool', 'send_report']);
    const filtered = filterPayloads(PAYLOADS, opts);
    expect(filtered.length).toBeGreaterThan(0);
    expect(
      filtered.every(p => p.oracle.forbiddenToolCalls?.includes('send_report'))
    ).toBe(true);
  });
});
