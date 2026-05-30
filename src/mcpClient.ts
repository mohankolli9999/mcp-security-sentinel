import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

import type {
  McpConfigServerEntry,
  McpInspectionSurface,
  McpToolDefinition,
  McpResourceDefinition,
  McpPromptDefinition,
  McpServerInfo,
  ConnectOptions,
  ConnectResult,
  ConnectFailure,
  ConnectionOutcome,
} from './types.js';

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timerId: ReturnType<typeof setTimeout>;
  const timeout = new Promise<T>((_, reject) => {
    timerId = setTimeout(() => reject(new Error(`Timeout: ${label} exceeded ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timerId));
}

async function paginatedList<T>(
  listFn: (cursor?: string) => Promise<{ nextCursor?: string; [key: string]: unknown }>,
  resultKey: string,
  maxPages: number,
  timeoutMs: number,
  label: string
): Promise<{ items: T[]; limitReached: boolean }> {
  const items: T[] = [];
  let cursor: string | undefined;
  let pages = 0;

  while (true) {
    const response = await withTimeout(listFn(cursor), timeoutMs, label);
    const pageItems = (response[resultKey] as T[]) ?? [];
    items.push(...pageItems);
    pages++;
    cursor = response.nextCursor;

    if (pages >= maxPages && cursor !== undefined) {
      return { items, limitReached: true };
    }
    if (!cursor) break;
  }

  return { items, limitReached: false };
}

function createTransport(entry: McpConfigServerEntry) {
  if (entry.transport === 'stdio') {
    if (!entry.command) throw new Error(`stdio transport requires command for server "${entry.name}"`);
    return new StdioClientTransport({
      command: entry.command,
      args: entry.args ?? [],
      env: entry.env
        ? Object.fromEntries(
            Object.entries({ ...process.env, ...entry.env })
              .filter((kv): kv is [string, string] => kv[1] !== undefined)
          )
        : undefined,
    });
  }

  if (entry.transport === 'http') {
    if (!entry.url) throw new Error(`http transport requires url for server "${entry.name}"`);
    return new StreamableHTTPClientTransport(new URL(entry.url));
  }

  if (entry.transport === 'sse') {
    if (!entry.url) throw new Error(`sse transport requires url for server "${entry.name}"`);
    return new SSEClientTransport(new URL(entry.url));
  }

  throw new Error(`Unknown transport type "${entry.transport}" for server "${entry.name}"`);
}

export async function inspectServer(options: ConnectOptions): Promise<ConnectionOutcome> {
  const {
    entry,
    timeoutMs = 10000,
    enumerationTimeoutMs = 5000,
    maxPages = 20,
    readResources = false,
    maxResources = 10,
    maxResourceBytes = 1048576,
    resourceTimeoutMs = 5000,
  } = options;

  let transport: ReturnType<typeof createTransport>;
  try {
    transport = createTransport(entry);
  } catch (err) {
    const failure: ConnectFailure = {
      success: false,
      serverName: entry.name,
      error: err instanceof Error ? err.message : String(err),
      sourcePath: entry.sourcePath,
      rawPath: entry.rawPath,
    };
    return failure;
  }

  const client = new Client({ name: 'mcp-sentinel', version: '2.0.0' });
  const warnings: string[] = [];

  try {
    await withTimeout(client.connect(transport), timeoutMs, `connect to "${entry.name}"`);

    const rawVersion = client.getServerVersion?.();
    const rawCaps = client.getServerCapabilities?.();
    const serverInstructions = client.getInstructions?.();

    const serverInfo: McpServerInfo | undefined = rawVersion
      ? {
          name: rawVersion.name,
          version: rawVersion.version,
          capabilities: rawCaps ?? {},
        }
      : undefined;

    // Enumerate tools
    let tools: McpToolDefinition[] = [];
    try {
      const { items, limitReached } = await paginatedList<McpToolDefinition>(
        (cursor) => client.listTools(cursor ? { cursor } : undefined),
        'tools',
        maxPages,
        enumerationTimeoutMs,
        `listTools "${entry.name}"`
      );
      tools = items;
      if (limitReached) {
        warnings.push(`listTools reached maxPages (${maxPages}) limit for server "${entry.name}"`);
      }
    } catch (err) {
      warnings.push(`listTools failed for "${entry.name}": ${err instanceof Error ? err.message : String(err)}`);
    }

    // Enumerate resources
    let resources: McpResourceDefinition[] = [];
    try {
      const { items, limitReached } = await paginatedList<McpResourceDefinition>(
        (cursor) => client.listResources(cursor ? { cursor } : undefined),
        'resources',
        maxPages,
        enumerationTimeoutMs,
        `listResources "${entry.name}"`
      );
      resources = items;
      if (limitReached) {
        warnings.push(`listResources reached maxPages (${maxPages}) limit for server "${entry.name}"`);
      }
    } catch (err) {
      warnings.push(`listResources failed for "${entry.name}": ${err instanceof Error ? err.message : String(err)}`);
    }

    // Enumerate prompts
    let prompts: McpPromptDefinition[] = [];
    try {
      const { items, limitReached } = await paginatedList<McpPromptDefinition>(
        (cursor) => client.listPrompts(cursor ? { cursor } : undefined),
        'prompts',
        maxPages,
        enumerationTimeoutMs,
        `listPrompts "${entry.name}"`
      );
      prompts = items;
      if (limitReached) {
        warnings.push(`listPrompts reached maxPages (${maxPages}) limit for server "${entry.name}"`);
      }
    } catch (err) {
      warnings.push(`listPrompts failed for "${entry.name}": ${err instanceof Error ? err.message : String(err)}`);
    }

    // Optional resource content reading
    let resourceContents: Array<{ uri: string; text: string }> | undefined;
    if (readResources && resources.length > 0) {
      resourceContents = [];
      const toRead = resources.slice(0, maxResources);
      for (const resource of toRead) {
        try {
          const result = await withTimeout(
            client.readResource({ uri: resource.uri }),
            resourceTimeoutMs,
            `readResource "${resource.uri}"`
          );
          for (const content of result.contents) {
            if ('text' in content && content.text !== undefined) {
              if (Buffer.byteLength(content.text, 'utf8') <= maxResourceBytes) {
                resourceContents.push({ uri: content.uri, text: content.text });
              } else {
                warnings.push(`Resource content skipped (exceeds ${maxResourceBytes} bytes): ${resource.uri}`);
              }
            }
          }
        } catch (err) {
          warnings.push(`readResource failed for "${resource.uri}": ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    }

    const surface: McpInspectionSurface = {
      serverName: entry.name,
      serverInfo,
      serverInstructions,
      configEntry: entry,
      tools,
      resources,
      prompts,
      resourceContents,
      warnings,
    };

    const result: ConnectResult = { success: true, surface };
    return result;
  } catch (err) {
    const failure: ConnectFailure = {
      success: false,
      serverName: entry.name,
      error: err instanceof Error ? err.message : String(err),
      sourcePath: entry.sourcePath,
      rawPath: entry.rawPath,
    };
    return failure;
  } finally {
    try { await client.close(); } catch { /* swallow */ }
  }
}
