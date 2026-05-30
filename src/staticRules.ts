import type {
  McpInspectionSurface,
  StaticRule,
  StaticRuleMatch,
  StaticFinding,
  Severity,
} from './types.js';

// ─── Severity ordering ───────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] ? a : b;
}

// ─── Injection pattern sets ───────────────────────────────────────────────────

interface PatternEntry {
  pattern: RegExp;
  label: string;
  severity: Severity;
}

const CRITICAL_PATTERNS: PatternEntry[] = [
  { pattern: /SYSTEM\s*:/i, label: 'SYSTEM: override directive', severity: 'critical' },
  { pattern: /ignore\s+(all\s+)?(previous|prior)\s+instructions?/i, label: 'ignore previous instructions', severity: 'critical' },
  { pattern: /disregard\s+(all\s+)?(previous|prior|above)\s+instructions?/i, label: 'disregard instructions', severity: 'critical' },
  { pattern: /<\s*system\s*>/i, label: '<system> tag injection', severity: 'critical' },
  { pattern: /\[INST\]/i, label: '[INST] injection token', severity: 'critical' },
  { pattern: /\|\s*im_end\s*\|/i, label: 'im_end token injection', severity: 'critical' },
  { pattern: /new\s+instructions?\s*:/i, label: 'new instructions injection', severity: 'critical' },
  { pattern: /\byou\s+are\s+now\b/i, label: 'role reassignment', severity: 'critical' },
  { pattern: /output\s+(all\s+)?(credentials?|secrets?|tokens?|passwords?|keys?)/i, label: 'credential exfiltration directive', severity: 'critical' },
  { pattern: /\bSENTINEL_PWNED\b/, label: 'test marker injection', severity: 'critical' },
];

const HIGH_PATTERNS: PatternEntry[] = [
  { pattern: /leak\s+(all\s+)?(credentials|secrets?|passwords?|tokens?|keys?)/i, label: 'credential leak instruction', severity: 'high' },
  { pattern: /output\s+(all\s+)?(env(ironment)?\s+variables?|secrets?|credentials?)/i, label: 'env/secret exfil instruction', severity: 'high' },
  { pattern: /exfiltrate/i, label: 'exfiltration keyword', severity: 'high' },
  { pattern: /send\s+.{0,40}\s+to\s+http/i, label: 'send data to URL', severity: 'high' },
  { pattern: /do\s+not\s+tell\s+the\s+user/i, label: '"do not tell the user" instruction', severity: 'high' },
  { pattern: /\bsilent(ly)?\s+(background\s+)?action/i, label: 'silent action directive', severity: 'high' },
  { pattern: /mandatory\s+compliance/i, label: 'mandatory compliance directive', severity: 'high' },
  { pattern: /\bnew\s+policy\b/i, label: 'policy override', severity: 'high' },
  { pattern: /suppress\s+(all\s+)?(warnings?|errors?|output)/i, label: 'warning suppression', severity: 'high' },
  { pattern: /always\s+(set|use|send|call|output)\s+/i, label: 'forced action directive', severity: 'high' },
];

const MEDIUM_PATTERNS: PatternEntry[] = [
  { pattern: /\byou\s+must\s+(always|never)\b/i, label: 'behavioral constraint', severity: 'medium' },
  { pattern: /always\s+call\s+this\s+tool\s+first/i, label: '"always call this tool first" directive', severity: 'medium' },
  { pattern: /never\s+reveal/i, label: '"never reveal" instruction', severity: 'medium' },
  { pattern: /without\s+(the\s+)?(user'?s?\s+)?knowledge/i, label: 'covert action instruction', severity: 'medium' },
  { pattern: /\bIMPORTANT\s*:/i, label: 'emphasis marker', severity: 'medium' },
  { pattern: /\bNOTE\s*:\s*(always|never|must|do not)/i, label: 'directive note', severity: 'medium' },
];

// ─── Base64 detection helper ──────────────────────────────────────────────────

const BASE64_RE = /[A-Za-z0-9+/]{20,}={0,2}/;
const SUSPICIOUS_WORDS = ['ignore', 'system', 'override', 'instruction', 'disregard', 'exfil', 'leak', 'secret', 'credential'];

function scanBase64(text: string): { found: boolean; decoded: string } {
  const matches = text.match(BASE64_RE);
  if (!matches) return { found: false, decoded: '' };
  for (const m of matches) {
    try {
      const decoded = Buffer.from(m, 'base64').toString('utf-8');
      if (decoded.length > 10 && /^[\x20-\x7E\s]+$/.test(decoded)) {
        const lower = decoded.toLowerCase();
        if (SUSPICIOUS_WORDS.some(w => lower.includes(w))) {
          return { found: true, decoded };
        }
      }
    } catch {
      // skip non-decodable
    }
  }
  return { found: false, decoded: '' };
}

// ─── Core scan helper ─────────────────────────────────────────────────────────

export function scanTextForInjection(opts: {
  text: string;
  path: string;
  contextLabel: string;
  authorityLevel: 'tool_description' | 'server_instruction' | 'resource' | 'prompt';
}): StaticRuleMatch[] {
  const { text, path, contextLabel, authorityLevel } = opts;
  const results: StaticRuleMatch[] = [];

  for (const entry of CRITICAL_PATTERNS) {
    const m = text.match(entry.pattern);
    if (m) {
      results.push({
        path,
        evidence: m[0],
        detail: `${entry.label} detected in ${contextLabel}`,
        severityOverride: 'critical',
      });
    }
  }

  for (const entry of HIGH_PATTERNS) {
    const m = text.match(entry.pattern);
    if (m) {
      const sev: Severity = authorityLevel === 'server_instruction' ? 'critical' : 'high';
      results.push({
        path,
        evidence: m[0],
        detail: `${entry.label} detected in ${contextLabel}`,
        severityOverride: sev,
      });
    }
  }

  for (const entry of MEDIUM_PATTERNS) {
    const m = text.match(entry.pattern);
    if (m) {
      results.push({
        path,
        evidence: m[0],
        detail: `${entry.label} detected in ${contextLabel}`,
        severityOverride: 'medium',
      });
    }
  }

  // Base64 check
  const b64 = scanBase64(text);
  if (b64.found) {
    results.push({
      path,
      evidence: b64.decoded.slice(0, 200),
      detail: 'Base64-encoded suspicious content detected',
      severityOverride: 'high',
    });
  }

  return results;
}

// ─── STATIC-002 sensitive names ───────────────────────────────────────────────

const SENSITIVE_TOOL_NAMES = new Set([
  'execute_command',
  'run_command',
  'shell_exec',
  'eval',
  'exec',
  'system',
  'subprocess',
  'bash',
  'sh',
  'cmd',
  'powershell',
  'read_file',
  'write_file',
  'delete_file',
  'list_files',
  'file_read',
  'file_write',
  'send_email',
  'send_message',
  'http_request',
  'web_request',
  'fetch_url',
  'get_credentials',
  'list_secrets',
  'read_env',
  'get_env',
]);

// ─── STATIC-003 schema scanner ────────────────────────────────────────────────

function scanSchemaProperties(
  schema: Record<string, unknown>,
  basePath: string,
): StaticRuleMatch[] {
  const results: StaticRuleMatch[] = [];

  // additionalProperties: true is a medium-severity finding
  if (schema.additionalProperties === true) {
    results.push({
      path: basePath,
      evidence: 'additionalProperties: true',
      detail: 'additionalProperties: true allows arbitrary fields to be injected',
      severityOverride: 'medium',
    });
  }

  const props = schema.properties as Record<string, unknown> | undefined;
  if (props && typeof props === 'object') {
    for (const [propName, propDef] of Object.entries(props)) {
      if (propDef && typeof propDef === 'object') {
        const def = propDef as Record<string, unknown>;
        if (typeof def.description === 'string') {
          const propPath = `${basePath}.properties.${propName}.description`;
          const matches = scanTextForInjection({
            text: def.description,
            path: propPath,
            contextLabel: `schema property ${propName}`,
            authorityLevel: 'tool_description',
          });
          results.push(...matches);
        }
      }
    }
  }

  return results;
}

// ─── Rules ────────────────────────────────────────────────────────────────────

export const STATIC_RULES: StaticRule[] = [
  // STATIC-001: Tool description injection
  {
    id: 'STATIC-001',
    name: 'Tool description injection',
    category: 'tool_description_injection',
    severity: 'high',
    description: 'Detects prompt-injection patterns embedded in MCP tool descriptions.',
    owaspRefs: ['LLM01'],
    slowmistRef: 'SS-TD',
    remediation: 'Review tool descriptions for coercive or override language. Remove any directives that attempt to subvert LLM behavior.',
    check(surface) {
      const results: StaticRuleMatch[] = [];
      for (const [i, tool] of surface.tools.entries()) {
        if (typeof tool.description === 'string') {
          const matches = scanTextForInjection({
            text: tool.description,
            path: `tools[${i}].description`,
            contextLabel: `tool ${tool.name} description`,
            authorityLevel: 'tool_description',
          });
          results.push(...matches);
        }
      }
      return results;
    },
  },

  // STATIC-002: Tool name shadowing
  {
    id: 'STATIC-002',
    name: 'Tool name shadowing',
    category: 'tool_name_shadowing',
    severity: 'medium',
    description: 'Detects MCP tool names that shadow sensitive built-in operations, which may mislead agents or hijack calls.',
    owaspRefs: ['LLM01', 'LLM05'],
    slowmistRef: 'SS-NS',
    remediation: 'Rename tools to avoid shadowing built-in or privileged operation names.',
    check(surface) {
      const results: StaticRuleMatch[] = [];
      for (const [i, tool] of surface.tools.entries()) {
        if (SENSITIVE_TOOL_NAMES.has(tool.name.toLowerCase())) {
          results.push({
            path: `tools[${i}].name`,
            evidence: tool.name,
            detail: `Tool name "${tool.name}" shadows a sensitive built-in operation name`,
            severityOverride: 'high',
          });
        }
      }
      return results;
    },
  },

  // STATIC-003: Schema poisoning
  {
    id: 'STATIC-003',
    name: 'Schema poisoning',
    category: 'schema_poisoning',
    severity: 'high',
    description: 'Detects injection patterns embedded in tool input/output schema property descriptions, or dangerously permissive schema settings.',
    owaspRefs: ['LLM01', 'LLM03'],
    slowmistRef: 'SS-SP',
    remediation: 'Audit schema property descriptions for coercive language. Avoid additionalProperties: true.',
    check(surface) {
      const results: StaticRuleMatch[] = [];
      for (const [i, tool] of surface.tools.entries()) {
        if (tool.inputSchema && typeof tool.inputSchema === 'object') {
          const matches = scanSchemaProperties(
            tool.inputSchema as Record<string, unknown>,
            `tools[${i}].inputSchema`,
          );
          results.push(...matches);
        }
        if (tool.outputSchema && typeof tool.outputSchema === 'object') {
          const matches = scanSchemaProperties(
            tool.outputSchema as Record<string, unknown>,
            `tools[${i}].outputSchema`,
          );
          results.push(...matches);
        }
      }
      return results;
    },
  },

  // STATIC-004: Resource injection
  {
    id: 'STATIC-004',
    name: 'Resource content injection',
    category: 'resource_injection',
    severity: 'critical',
    description: 'Detects prompt-injection patterns in fetched MCP resource text content.',
    owaspRefs: ['LLM01', 'LLM02'],
    slowmistRef: 'SS-RC',
    remediation: 'Sanitize resource content before exposing to LLM agents. Consider content filtering proxies.',
    check(surface) {
      const results: StaticRuleMatch[] = [];
      if (!surface.resourceContents) return results;
      for (const [i, rc] of surface.resourceContents.entries()) {
        const matches = scanTextForInjection({
          text: rc.text,
          path: `resourceContents[${i}].text`,
          contextLabel: `resource ${rc.uri}`,
          authorityLevel: 'resource',
        });
        results.push(...matches);
      }
      return results;
    },
  },

  // STATIC-005: Prompt injection
  {
    id: 'STATIC-005',
    name: 'Prompt template injection',
    category: 'prompt_injection',
    severity: 'high',
    description: 'Detects prompt-injection patterns in MCP prompt definitions and their argument descriptions.',
    owaspRefs: ['LLM01', 'LLM02'],
    slowmistRef: 'SS-PI',
    remediation: 'Review all prompt templates and argument descriptions for coercive or override language.',
    check(surface) {
      const results: StaticRuleMatch[] = [];
      for (const [i, prompt] of surface.prompts.entries()) {
        if (typeof prompt.description === 'string') {
          const matches = scanTextForInjection({
            text: prompt.description,
            path: `prompts[${i}].description`,
            contextLabel: `prompt ${prompt.name} description`,
            authorityLevel: 'prompt',
          });
          results.push(...matches);
        }
        if (prompt.arguments) {
          for (const [j, arg] of prompt.arguments.entries()) {
            if (typeof arg.description === 'string') {
              const matches = scanTextForInjection({
                text: arg.description,
                path: `prompts[${i}].arguments[${j}].description`,
                contextLabel: `prompt ${prompt.name} argument ${arg.name}`,
                authorityLevel: 'prompt',
              });
              results.push(...matches);
            }
          }
        }
      }
      return results;
    },
  },

  // STATIC-006 through STATIC-011: Placeholder stubs (completed in Task 4)
  {
    id: 'STATIC-006',
    name: 'Server metadata anomaly',
    category: 'server_metadata_anomaly',
    severity: 'medium',
    description: 'Detects anomalies in MCP server metadata (placeholder).',
    owaspRefs: ['LLM08'],
    slowmistRef: 'https://www.slowmist.com/mcp-security',
    remediation: 'Review server metadata for suspicious values.',
    check: () => [],
  },
  {
    id: 'STATIC-007',
    name: 'Capability overreach',
    category: 'capability_overreach',
    severity: 'medium',
    description: 'Detects servers advertising excessive capabilities (placeholder).',
    owaspRefs: ['LLM08'],
    slowmistRef: 'https://www.slowmist.com/mcp-security',
    remediation: 'Restrict server capabilities to the minimum required.',
    check: () => [],
  },
  {
    id: 'STATIC-008',
    name: 'Config command risk',
    category: 'config_command_risk',
    severity: 'high',
    description: 'Detects dangerous command patterns in MCP server config (placeholder).',
    owaspRefs: ['LLM08'],
    slowmistRef: 'https://www.slowmist.com/mcp-security',
    remediation: 'Audit server launch commands for dangerous patterns.',
    check: () => [],
  },
  {
    id: 'STATIC-009',
    name: 'Secret leakage via config',
    category: 'secret_leakage',
    severity: 'high',
    description: 'Detects secrets exposed in MCP server config env (placeholder).',
    owaspRefs: ['LLM06'],
    slowmistRef: 'https://www.slowmist.com/mcp-security',
    remediation: 'Use secret managers instead of embedding secrets in config.',
    check: () => [],
  },
  {
    id: 'STATIC-010',
    name: 'Exfiltration sink detection',
    category: 'exfil_sink',
    severity: 'high',
    description: 'Detects known exfiltration sink patterns in tool definitions (placeholder).',
    owaspRefs: ['LLM02', 'LLM06'],
    slowmistRef: 'https://www.slowmist.com/mcp-security',
    remediation: 'Block or audit tools that can transmit data to external endpoints.',
    check: () => [],
  },
  {
    id: 'STATIC-011',
    name: 'Server instruction injection',
    category: 'server_instruction_injection',
    severity: 'critical',
    description: 'Detects prompt-injection in MCP server-level instructions (placeholder).',
    owaspRefs: ['LLM01', 'LLM02'],
    slowmistRef: 'https://www.slowmist.com/mcp-security',
    remediation: 'Review server instructions for coercive or override language.',
    check: () => [],
  },
];

// ─── runStaticRules ───────────────────────────────────────────────────────────

const RISK_SCORE_MAP: Record<Severity, number> = {
  critical: 9,
  high: 7,
  medium: 5,
  low: 2,
};

export function runStaticRules(surface: McpInspectionSurface): StaticFinding[] {
  const findings: StaticFinding[] = [];

  for (const rule of STATIC_RULES) {
    const matches = rule.check(surface);
    if (matches.length === 0) continue;

    // Effective severity per match = severityOverride ?? rule.severity
    // Finding severity = highest effective across all matches
    let findingSeverity: Severity = rule.severity;
    for (const m of matches) {
      const effectiveSev = m.severityOverride ?? rule.severity;
      findingSeverity = maxSeverity(findingSeverity, effectiveSev);
    }

    findings.push({
      mode: 'static',
      ruleId: rule.id,
      ruleName: rule.name,
      category: rule.category,
      severity: findingSeverity,
      owaspRefs: rule.owaspRefs,
      slowmistRef: rule.slowmistRef,
      serverName: surface.serverName,
      matches,
      riskScore: RISK_SCORE_MAP[findingSeverity],
      remediation: rule.remediation,
    });
  }

  return findings;
}

// ─── detectCrossServerCollisions (Task 4 placeholder) ────────────────────────

export function detectCrossServerCollisions(
  _surfaces: McpInspectionSurface[],
): StaticFinding[] {
  return [];
}
