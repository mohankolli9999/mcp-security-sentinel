import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

function readSrc(filename: string): string {
  return fs.readFileSync(path.join(__dirname, '..', 'src', filename), 'utf-8');
}

describe('import firewall', () => {
  it('static files do not import @anthropic-ai/sdk', () => {
    const staticFiles = [
      'configParser.ts', 'staticRules.ts', 'mcpClient.ts',
      'configGate.ts', 'inspect.ts',
    ];
    for (const file of staticFiles) {
      const content = readSrc(file);
      expect(content).not.toContain('@anthropic-ai/sdk');
    }
  });

  it('dynamic files do not import @modelcontextprotocol/sdk', () => {
    const dynamicFiles = ['scanner.ts', 'mockServer.ts', 'oracles.ts'];
    for (const file of dynamicFiles) {
      const content = readSrc(file);
      expect(content).not.toContain('@modelcontextprotocol/sdk');
    }
  });

  it('reporter.ts imports neither SDK', () => {
    const content = readSrc('reporter.ts');
    expect(content).not.toContain('@anthropic-ai/sdk');
    expect(content).not.toContain('@modelcontextprotocol/sdk');
  });

  it('types.ts imports neither SDK', () => {
    const content = readSrc('types.ts');
    expect(content).not.toContain('@anthropic-ai/sdk');
    expect(content).not.toContain('@modelcontextprotocol/sdk');
  });

  it('index.ts does not top-level import scanner.ts', () => {
    const content = readSrc('index.ts');
    const lines = content.split('\n');
    const topLevelImports = lines.filter(l =>
      l.startsWith('import') && l.includes('scanner')
    );
    expect(topLevelImports).toHaveLength(0);
  });
});
