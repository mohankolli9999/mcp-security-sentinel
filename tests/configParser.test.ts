import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import { parseConfigFile } from '../src/configParser.js';

const TMP = '/tmp/sentinel-config-test';

beforeEach(() => { fs.mkdirSync(TMP, { recursive: true }); });
afterEach(() => { fs.rmSync(TMP, { recursive: true, force: true }); });

function writeConfig(name: string, content: unknown): string {
  const path = `${TMP}/${name}`;
  fs.writeFileSync(path, JSON.stringify(content), 'utf-8');
  return path;
}

describe('parseConfigFile', () => {
  it('parses Claude Desktop format (mcpServers)', () => {
    const path = writeConfig('claude.json', {
      mcpServers: {
        github: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-github'],
          env: { GITHUB_TOKEN: 'ghp_secret123' },
        },
      },
    });
    const entries = parseConfigFile(path);
    expect(entries).toHaveLength(1);
    expect(entries[0].name).toBe('github');
    expect(entries[0].transport).toBe('stdio');
    expect(entries[0].command).toBe('npx');
    expect(entries[0].args).toEqual(['-y', '@modelcontextprotocol/server-github']);
    expect(entries[0].envKeys).toEqual(['GITHUB_TOKEN']);
    expect(entries[0].env).toEqual({ GITHUB_TOKEN: 'ghp_secret123' });
    expect(entries[0].rawPath).toBe('mcpServers.github');
    expect(entries[0].sourcePath).toBe(path);
  });

  it('parses VS Code format (servers)', () => {
    const path = writeConfig('vscode.json', {
      servers: {
        filesystem: {
          type: 'stdio',
          command: 'node',
          args: ['./fs-server.js'],
        },
      },
    });
    const entries = parseConfigFile(path);
    expect(entries).toHaveLength(1);
    expect(entries[0].name).toBe('filesystem');
    expect(entries[0].transport).toBe('stdio');
    expect(entries[0].command).toBe('node');
    expect(entries[0].rawPath).toBe('servers.filesystem');
  });

  it('infers http transport from url', () => {
    const path = writeConfig('http.json', {
      servers: {
        remote: { url: 'https://mcp.example.com/api' },
      },
    });
    const entries = parseConfigFile(path);
    expect(entries[0].transport).toBe('http');
    expect(entries[0].url).toBe('https://mcp.example.com/api');
  });

  it('infers sse transport when type is sse', () => {
    const path = writeConfig('sse.json', {
      servers: {
        legacy: { type: 'sse', url: 'https://mcp.example.com/sse' },
      },
    });
    const entries = parseConfigFile(path);
    expect(entries[0].transport).toBe('sse');
  });

  it('returns empty envKeys when env is absent', () => {
    const path = writeConfig('noenv.json', {
      mcpServers: { simple: { command: 'node', args: ['server.js'] } },
    });
    const entries = parseConfigFile(path);
    expect(entries[0].envKeys).toEqual([]);
    expect(entries[0].env).toBeUndefined();
  });

  it('parses multiple servers', () => {
    const path = writeConfig('multi.json', {
      mcpServers: {
        a: { command: 'node', args: ['a.js'] },
        b: { command: 'node', args: ['b.js'] },
        c: { command: 'node', args: ['c.js'] },
      },
    });
    const entries = parseConfigFile(path);
    expect(entries).toHaveLength(3);
    expect(entries.map(e => e.name).sort()).toEqual(['a', 'b', 'c']);
  });

  it('throws on invalid JSON', () => {
    const path = `${TMP}/bad.json`;
    fs.writeFileSync(path, 'not-json', 'utf-8');
    expect(() => parseConfigFile(path)).toThrow();
  });

  it('throws on unrecognized format (no mcpServers or servers key)', () => {
    const path = writeConfig('unknown.json', { plugins: {} });
    expect(() => parseConfigFile(path)).toThrow(/unrecognized/i);
  });
});
