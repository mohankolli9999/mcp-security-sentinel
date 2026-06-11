// src/sarif.ts — SARIF 2.1.0 conversion for CI/code-scanning integration
import fs from 'fs';
import type { SentinelResult, Severity, StaticFinding, DynamicFinding } from './types.js';
import { toRedactedJson } from './reporter.js';

const SARIF_SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';
const TOOL_INFO_URI = 'https://github.com/mohankolli9999/mcp-security-sentinel';
const TOOL_VERSION = '1.0.0';

export type SarifLevel = 'error' | 'warning' | 'note';

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  help?: { text: string };
  properties?: Record<string, unknown>;
}

export interface SarifLocation {
  physicalLocation?: { artifactLocation: { uri: string } };
  logicalLocations?: Array<{ fullyQualifiedName: string }>;
}

export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  message: { text: string };
  locations?: SarifLocation[];
  properties?: Record<string, unknown>;
}

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: Array<{
    tool: { driver: { name: string; version: string; informationUri: string; rules: SarifRule[] } };
    results: SarifResult[];
  }>;
}

const LEVEL_MAP: Record<Severity, SarifLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
};

interface RuleSource {
  id: string;
  name: string;
  remediation: string;
  owaspRefs: string[];
  slowmistRef: string;
  category: string;
}

function ruleFromFinding(f: StaticFinding | DynamicFinding): RuleSource {
  return f.mode === 'static'
    ? { id: f.ruleId, name: f.ruleName, remediation: f.remediation, owaspRefs: f.owaspRefs, slowmistRef: f.slowmistRef, category: f.category }
    : { id: f.payloadId, name: f.payloadName, remediation: f.remediation, owaspRefs: f.owaspRefs, slowmistRef: f.slowmistRef, category: f.category };
}

function staticMessage(f: StaticFinding): string {
  const details = f.matches.map(m => `${m.detail} (${m.path})`).join('; ');
  return details
    ? `${f.ruleName} on server "${f.serverName}": ${details}`
    : `${f.ruleName} on server "${f.serverName}"`;
}

function dynamicMessage(f: DynamicFinding): string {
  const evidence = f.evidence.map(e => e.description).join('; ');
  const rate = f.runs > 0 ? ` (${f.successCount}/${f.runs} runs succeeded)` : '';
  return evidence
    ? `${f.payloadName}: ${evidence}${rate}`
    : `${f.payloadName}${rate}`;
}

export function toSarif(result: SentinelResult): SarifLog {
  const rules: SarifRule[] = [];
  const ruleIndexById = new Map<string, number>();

  const indexForRule = (src: RuleSource): number => {
    const existing = ruleIndexById.get(src.id);
    if (existing !== undefined) return existing;
    const index = rules.length;
    ruleIndexById.set(src.id, index);
    rules.push({
      id: src.id,
      name: src.name,
      shortDescription: { text: src.name },
      help: { text: src.remediation },
      properties: {
        category: src.category,
        owaspRefs: src.owaspRefs,
        slowmistRef: src.slowmistRef,
      },
    });
    return index;
  };

  const results: SarifResult[] = result.findings.map(finding => {
    const src = ruleFromFinding(finding);
    const ruleIndex = indexForRule(src);

    if (finding.mode === 'static') {
      const target = result.mode === 'inspect' ? result.target : undefined;
      return {
        ruleId: src.id,
        ruleIndex,
        level: LEVEL_MAP[finding.severity],
        message: { text: staticMessage(finding) },
        locations: [{
          ...(target ? { physicalLocation: { artifactLocation: { uri: target } } } : {}),
          logicalLocations: finding.matches.length > 0
            ? finding.matches.map(m => ({ fullyQualifiedName: `${finding.serverName}/${m.path}` }))
            : [{ fullyQualifiedName: finding.serverName }],
        }],
        properties: {
          severity: finding.severity,
          riskScore: finding.riskScore,
          serverName: finding.serverName,
        },
      };
    }

    const target = result.mode === 'attack' ? result.targetServer : 'unknown';
    return {
      ruleId: src.id,
      ruleIndex,
      level: LEVEL_MAP[finding.severity],
      message: { text: dynamicMessage(finding) },
      locations: [{
        logicalLocations: [{ fullyQualifiedName: `${target}/${finding.toolName}` }],
      }],
      properties: {
        severity: finding.severity,
        riskScore: finding.riskScore,
        detectionMethod: finding.detectionMethod,
        confidence: finding.confidence,
        reproductionCommand: finding.reproductionCommand,
      },
    };
  });

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'MCP Security Sentinel',
          version: TOOL_VERSION,
          informationUri: TOOL_INFO_URI,
          rules,
        },
      },
      results,
    }],
  };
}

export function writeSarifReport(result: SentinelResult, outputPath: string): void {
  const sarif = toSarif(toRedactedJson(result));
  fs.writeFileSync(outputPath, JSON.stringify(sarif, null, 2), 'utf-8');
}
