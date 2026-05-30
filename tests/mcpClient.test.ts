import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { McpConfigServerEntry } from '../src/types.js';

// Mock MCP SDK modules
vi.mock('@modelcontextprotocol/sdk/client/index.js', () => {
  const Client = vi.fn();
  Client.prototype.connect = vi.fn().mockResolvedValue(undefined);
  Client.prototype.close = vi.fn().mockResolvedValue(undefined);
  Client.prototype.getServerVersion = vi.fn().mockReturnValue(undefined);
  Client.prototype.getServerCapabilities = vi.fn().mockReturnValue(undefined);
  Client.prototype.getInstructions = vi.fn().mockReturnValue(undefined);
  Client.prototype.listTools = vi.fn().mockResolvedValue({ tools: [], nextCursor: undefined });
  Client.prototype.listResources = vi.fn().mockResolvedValue({ resources: [], nextCursor: undefined });
  Client.prototype.listPrompts = vi.fn().mockResolvedValue({ prompts: [], nextCursor: undefined });
  Client.prototype.readResource = vi.fn().mockResolvedValue({ contents: [] });
  return { Client };
});

vi.mock('@modelcontextprotocol/sdk/client/stdio.js', () => ({
  StdioClientTransport: vi.fn().mockImplementation(() => ({ type: 'stdio' })),
}));

vi.mock('@modelcontextprotocol/sdk/client/streamableHttp.js', () => ({
  StreamableHTTPClientTransport: vi.fn().mockImplementation(() => ({ type: 'streamableHttp' })),
}));

vi.mock('@modelcontextprotocol/sdk/client/sse.js', () => ({
  SSEClientTransport: vi.fn().mockImplementation(() => ({ type: 'sse' })),
}));

// Import after mocks
import { inspectServer } from '../src/mcpClient.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

function makeEntry(overrides: Partial<McpConfigServerEntry> = {}): McpConfigServerEntry {
  return {
    name: 'test-server',
    transport: 'stdio',
    command: 'node',
    args: ['server.js'],
    envKeys: [],
    sourcePath: '/path/to/config.json',
    rawPath: 'mcpServers.test-server',
    ...overrides,
  };
}

function getClientInstance(): InstanceType<typeof Client> {
  const MockClient = Client as unknown as { mock: { instances: InstanceType<typeof Client>[] } };
  return MockClient.mock.instances[MockClient.mock.instances.length - 1];
}

beforeEach(() => {
  vi.clearAllMocks();
  // Reset default mock implementations
  const MockClient = Client as unknown as new () => InstanceType<typeof Client>;
  MockClient.prototype.connect = vi.fn().mockResolvedValue(undefined);
  MockClient.prototype.close = vi.fn().mockResolvedValue(undefined);
  MockClient.prototype.getServerVersion = vi.fn().mockReturnValue(undefined);
  MockClient.prototype.getServerCapabilities = vi.fn().mockReturnValue(undefined);
  MockClient.prototype.getInstructions = vi.fn().mockReturnValue(undefined);
  MockClient.prototype.listTools = vi.fn().mockResolvedValue({ tools: [], nextCursor: undefined });
  MockClient.prototype.listResources = vi.fn().mockResolvedValue({ resources: [], nextCursor: undefined });
  MockClient.prototype.listPrompts = vi.fn().mockResolvedValue({ prompts: [], nextCursor: undefined });
  MockClient.prototype.readResource = vi.fn().mockResolvedValue({ contents: [] });
});

describe('inspectServer', () => {
  it('returns ConnectResult with empty surface for clean server', async () => {
    const outcome = await inspectServer({ entry: makeEntry() });
    expect(outcome.success).toBe(true);
    if (!outcome.success) throw new Error('Expected success');
    expect(outcome.surface.tools).toEqual([]);
    expect(outcome.surface.resources).toEqual([]);
    expect(outcome.surface.prompts).toEqual([]);
    expect(outcome.surface.warnings).toEqual([]);
    expect(outcome.surface.serverName).toBe('test-server');
  });

  it('populates tools from listTools response', async () => {
    const client = Client.prototype;
    client.listTools = vi.fn().mockResolvedValue({
      tools: [
        { name: 'my_tool', description: 'does stuff', inputSchema: { type: 'object' } },
      ],
      nextCursor: undefined,
    });

    const outcome = await inspectServer({ entry: makeEntry() });
    expect(outcome.success).toBe(true);
    if (!outcome.success) throw new Error('Expected success');
    expect(outcome.surface.tools).toHaveLength(1);
    expect(outcome.surface.tools[0].name).toBe('my_tool');
    expect(outcome.surface.tools[0].description).toBe('does stuff');
  });

  it('captures server instructions', async () => {
    Client.prototype.getInstructions = vi.fn().mockReturnValue('Be helpful and secure.');

    const outcome = await inspectServer({ entry: makeEntry() });
    expect(outcome.success).toBe(true);
    if (!outcome.success) throw new Error('Expected success');
    expect(outcome.surface.serverInstructions).toBe('Be helpful and secure.');
  });

  it('handles pagination for tools (nextCursor)', async () => {
    Client.prototype.listTools = vi.fn()
      .mockResolvedValueOnce({
        tools: [{ name: 'tool_1' }],
        nextCursor: 'cursor-1',
      })
      .mockResolvedValueOnce({
        tools: [{ name: 'tool_2' }],
        nextCursor: undefined,
      });

    const outcome = await inspectServer({ entry: makeEntry() });
    expect(outcome.success).toBe(true);
    if (!outcome.success) throw new Error('Expected success');
    expect(outcome.surface.tools).toHaveLength(2);
    expect(outcome.surface.tools[0].name).toBe('tool_1');
    expect(outcome.surface.tools[1].name).toBe('tool_2');
  });

  it('respects maxPages limit and adds warning', async () => {
    // maxPages=2: after 2 pages, if cursor is still present, stop with warning
    Client.prototype.listTools = vi.fn()
      .mockResolvedValueOnce({ tools: [{ name: 'tool_1' }], nextCursor: 'c1' })
      .mockResolvedValueOnce({ tools: [{ name: 'tool_2' }], nextCursor: 'c2' });

    const outcome = await inspectServer({ entry: makeEntry(), maxPages: 2 });
    expect(outcome.success).toBe(true);
    if (!outcome.success) throw new Error('Expected success');
    expect(outcome.surface.tools).toHaveLength(2);
    const hasWarning = outcome.surface.warnings.some((w) => w.includes('maxPages'));
    expect(hasWarning).toBe(true);
  });

  it('returns ConnectFailure on connection error', async () => {
    Client.prototype.connect = vi.fn().mockRejectedValue(new Error('Connection refused'));

    const outcome = await inspectServer({ entry: makeEntry() });
    expect(outcome.success).toBe(false);
    if (outcome.success) throw new Error('Expected failure');
    expect(outcome.serverName).toBe('test-server');
    expect(outcome.error).toContain('Connection refused');
  });

  it('returns partial surface when listResources fails (tools still populated, warning added)', async () => {
    Client.prototype.listTools = vi.fn().mockResolvedValue({
      tools: [{ name: 'good_tool' }],
      nextCursor: undefined,
    });
    Client.prototype.listResources = vi.fn().mockRejectedValue(new Error('Resources not supported'));

    const outcome = await inspectServer({ entry: makeEntry() });
    expect(outcome.success).toBe(true);
    if (!outcome.success) throw new Error('Expected success');
    expect(outcome.surface.tools).toHaveLength(1);
    expect(outcome.surface.tools[0].name).toBe('good_tool');
    expect(outcome.surface.resources).toEqual([]);
    const hasWarning = outcome.surface.warnings.some((w) => w.includes('listResources'));
    expect(hasWarning).toBe(true);
  });

  it('always calls close even on failure', async () => {
    Client.prototype.connect = vi.fn().mockRejectedValue(new Error('Connection refused'));

    await inspectServer({ entry: makeEntry() });

    const instance = getClientInstance();
    expect(instance.close).toHaveBeenCalled();
  });

  it('returns ConnectFailure for unknown transport', async () => {
    const entry = makeEntry({ transport: 'unknown' as McpConfigServerEntry['transport'] });
    const outcome = await inspectServer({ entry });
    expect(outcome.success).toBe(false);
    if (outcome.success) throw new Error('Expected failure');
    expect(outcome.error).toContain('Unknown transport');
  });

  it('creates StreamableHTTPClientTransport for http transport', async () => {
    const entry = makeEntry({ transport: 'http', url: 'http://localhost:3000/mcp' });
    await inspectServer({ entry });
    expect(StreamableHTTPClientTransport).toHaveBeenCalledWith(new URL('http://localhost:3000/mcp'));
  });

  it('creates SSEClientTransport for sse transport', async () => {
    const entry = makeEntry({ transport: 'sse', url: 'http://localhost:3000/sse' });
    await inspectServer({ entry });
    expect(SSEClientTransport).toHaveBeenCalledWith(new URL('http://localhost:3000/sse'));
  });
});
