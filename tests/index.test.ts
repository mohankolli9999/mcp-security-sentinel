import { describe, it, expect } from 'vitest';
import { parseInspectArgs, parseAttackArgs } from '../src/index.js';

describe('parseInspectArgs', () => {
  it('parses --command with --arg', () => {
    const opts = parseInspectArgs(['--command', 'node', '--arg', 'server.js', '--arg', '--port=3000']);
    expect(opts.mode).toBe('command');
    expect(opts.command).toBe('node');
    expect(opts.args).toEqual(['server.js', '--port=3000']);
  });

  it('parses --config', () => {
    const opts = parseInspectArgs(['--config', '/path/to/config.json']);
    expect(opts.mode).toBe('config');
    expect(opts.configPath).toBe('/path/to/config.json');
  });

  it('parses --server and --yes', () => {
    const opts = parseInspectArgs(['--config', 'c.json', '--server', 'github', '--yes']);
    expect(opts.server).toBe('github');
    expect(opts.yes).toBe(true);
  });

  it('parses --all and --no-execute', () => {
    const opts = parseInspectArgs(['--config', 'c.json', '--all', '--no-execute']);
    expect(opts.all).toBe(true);
    expect(opts.noExecute).toBe(true);
  });

  it('parses --read-resources with limits', () => {
    const opts = parseInspectArgs(['--command', 'node', '--read-resources', '--max-resources', '5']);
    expect(opts.readResources).toBe(true);
    expect(opts.maxResources).toBe(5);
  });

  it('parses timeout flags', () => {
    const opts = parseInspectArgs(['--command', 'node', '--timeout-ms', '5000', '--max-pages', '10']);
    expect(opts.timeoutMs).toBe(5000);
    expect(opts.maxPages).toBe(10);
  });

  it('parses --json and --output', () => {
    const opts = parseInspectArgs(['--command', 'node', '--json', '--output', '/tmp/r.json']);
    expect(opts.json).toBe(true);
    expect(opts.output).toBe('/tmp/r.json');
  });

  it('parses --severity and --fail-on', () => {
    const opts = parseInspectArgs(['--command', 'node', '--severity', 'high', '--fail-on', 'critical']);
    expect(opts.severity).toBe('high');
    expect(opts.failOn).toBe('critical');
  });

  it('sets help flag', () => {
    const opts = parseInspectArgs(['--help']);
    expect(opts.help).toBe(true);
  });
});

describe('parseAttackArgs', () => {
  it('parses attack-specific flags', () => {
    const opts = parseAttackArgs([
      '--payload', 'INJ-001', '--runs', '3',
      '--agent-model', 'claude-haiku-4-5-20251001',
      '--judge-model', 'claude-sonnet-4-6',
    ]);
    expect(opts.payloadId).toBe('INJ-001');
    expect(opts.runs).toBe(3);
    expect(opts.agentModel).toBe('claude-haiku-4-5-20251001');
    expect(opts.judgeModel).toBe('claude-sonnet-4-6');
  });

  it('parses --no-baseline', () => {
    const opts = parseAttackArgs(['--no-baseline']);
    expect(opts.noBaseline).toBe(true);
  });

  it('parses --json', () => {
    const opts = parseAttackArgs(['--json']);
    expect(opts.json).toBe(true);
  });

  it('has correct defaults', () => {
    const opts = parseAttackArgs([]);
    expect(opts.runs).toBe(3);
    expect(opts.failOn).toBe('high');
    expect(opts.noBaseline).toBe(false);
  });

  it('sets help flag', () => {
    const opts = parseAttackArgs(['--help']);
    expect(opts.help).toBe(true);
  });

  it('filters severity at or above threshold', () => {
    const opts = parseAttackArgs(['--severity', 'high']);
    expect(opts.severity).toBe('high');
  });
});

describe('parseInspectArgs validation', () => {
  it('rejects unknown flags', () => {
    expect(() => parseInspectArgs(['--command', 'node', '--bogus'])).toThrow(/unknown flag/i);
  });

  it('rejects --command and --config together', () => {
    expect(() => parseInspectArgs(['--command', 'node', '--config', 'c.json'])).toThrow(/mutually exclusive/i);
  });

  it('rejects inspect with no --command or --config', () => {
    expect(() => parseInspectArgs(['--json'])).toThrow(/requires --command or --config/i);
  });

  it('rejects --arg without --command', () => {
    expect(() => parseInspectArgs(['--config', 'c.json', '--arg', 'foo'])).toThrow(/--arg requires --command/i);
  });

  it('rejects --server without --config', () => {
    expect(() => parseInspectArgs(['--command', 'node', '--server', 'x'])).toThrow(/require --config/i);
  });

  it('rejects --yes without --all or --server', () => {
    expect(() => parseInspectArgs(['--config', 'c.json', '--yes'])).toThrow(/--yes requires/i);
  });

  it('rejects --read-resources with --no-execute', () => {
    expect(() => parseInspectArgs(['--config', 'c.json', '--read-resources', '--no-execute'])).toThrow(/cannot be used/i);
  });

  it('rejects invalid --severity value', () => {
    expect(() => parseInspectArgs(['--command', 'node', '--severity', 'extreme'])).toThrow(/must be one of/i);
  });

  it('rejects non-positive --max-pages', () => {
    expect(() => parseInspectArgs(['--command', 'node', '--max-pages', '0'])).toThrow(/positive integer/i);
  });

  it('rejects flag with missing value', () => {
    expect(() => parseInspectArgs(['--command'])).toThrow(/requires a value/i);
  });
});

describe('parseAttackArgs validation', () => {
  it('rejects unknown flags', () => {
    expect(() => parseAttackArgs(['--bogus'])).toThrow(/unknown flag/i);
  });

  it('rejects invalid --fail-on value', () => {
    expect(() => parseAttackArgs(['--fail-on', 'extreme'])).toThrow(/must be one of/i);
  });
});
