import fs from 'fs';
import type { McpConfigServerEntry } from './types.js';

interface RawServerEntry {
  command?: unknown;
  args?: unknown;
  env?: unknown;
  url?: unknown;
  type?: unknown;
}

function inferTransport(entry: RawServerEntry): McpConfigServerEntry['transport'] {
  if (typeof entry.command === 'string') return 'stdio';
  if (typeof entry.url === 'string') {
    if (entry.type === 'sse') return 'sse';
    return 'http';
  }
  return 'unknown';
}

function parseServerEntry(
  name: string,
  raw: RawServerEntry,
  rawPathPrefix: string,
  sourcePath: string
): McpConfigServerEntry {
  const entry: McpConfigServerEntry = {
    name,
    transport: inferTransport(raw),
    envKeys: [],
    sourcePath,
    rawPath: `${rawPathPrefix}.${name}`,
  };

  if (typeof raw.command === 'string') {
    entry.command = raw.command;
  }
  if (Array.isArray(raw.args)) {
    entry.args = raw.args.map(String);
  }
  if (typeof raw.url === 'string') {
    entry.url = raw.url;
  }
  if (raw.env !== null && typeof raw.env === 'object' && !Array.isArray(raw.env)) {
    const envObj = raw.env as Record<string, unknown>;
    entry.env = Object.fromEntries(
      Object.entries(envObj).map(([k, v]) => [k, String(v)])
    );
    entry.envKeys = Object.keys(envObj);
  }

  return entry;
}

function validateStructure(serverMap: Record<string, unknown>): void {
  for (const [name, entry] of Object.entries(serverMap)) {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`Server entry "${name}" must be an object`);
    }
    const e = entry as Record<string, unknown>;
    if (e.command !== undefined && typeof e.command !== 'string') {
      throw new Error(`Server "${name}": command must be a string`);
    }
    if (e.args !== undefined && !Array.isArray(e.args)) {
      throw new Error(`Server "${name}": args must be an array`);
    }
    if (e.env !== undefined && (e.env === null || typeof e.env !== 'object' || Array.isArray(e.env))) {
      throw new Error(`Server "${name}": env must be an object`);
    }
    if (e.url !== undefined && typeof e.url !== 'string') {
      throw new Error(`Server "${name}": url must be a string`);
    }
  }
}

export function parseConfigFile(filePath: string): McpConfigServerEntry[] {
  const raw = fs.readFileSync(filePath, 'utf-8');
  let config: Record<string, unknown>;
  try {
    config = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    throw new Error(`Invalid JSON in config file: ${filePath}`);
  }

  if (typeof config !== 'object' || config === null) {
    throw new Error(`Config file must contain a JSON object: ${filePath}`);
  }

  let serverMap: Record<string, unknown>;
  let rawPathPrefix: string;

  if ('mcpServers' in config && typeof config.mcpServers === 'object' && config.mcpServers !== null) {
    serverMap = config.mcpServers as Record<string, unknown>;
    rawPathPrefix = 'mcpServers';
  } else if ('servers' in config && typeof config.servers === 'object' && config.servers !== null) {
    serverMap = config.servers as Record<string, unknown>;
    rawPathPrefix = 'servers';
  } else {
    throw new Error(
      `Unrecognized config format in ${filePath}. Expected "mcpServers" (Claude Desktop) or "servers" (VS Code) key.`
    );
  }

  validateStructure(serverMap);

  return Object.entries(serverMap).map(([name, entry]) =>
    parseServerEntry(name, entry as RawServerEntry, rawPathPrefix, filePath)
  );
}
