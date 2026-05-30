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

// ─── STATIC-006 generic server names ─────────────────────────────────────────

const GENERIC_SERVER_NAMES = new Set([
  'mcp server',
  'server',
  'test',
  'mcp',
  'example',
  'my server',
  'default',
  'unnamed',
  'localhost',
  'development',
  'dev',
]);

// ─── STATIC-008 command risk patterns ────────────────────────────────────────

const CRITICAL_CMD_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\$\(/, label: 'command substitution $()' },
  { pattern: /`[^`]+`/, label: 'backtick command substitution' },
  { pattern: /\|\s*(bash|sh|zsh|dash|ksh)\b/, label: 'pipe to shell' },
  { pattern: /curl\s.+\|\s*(bash|sh|zsh)\b/, label: 'curl pipe to shell' },
  { pattern: /wget\s.+\|\s*(bash|sh|zsh)\b/, label: 'wget pipe to shell' },
  { pattern: /\bsudo\b/, label: 'sudo usage' },
  { pattern: /\bnc\b.*-e\b|\bnetcat\b.*-e\b/, label: 'netcat reverse shell' },
];

const HIGH_CMD_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\bbash\s+-c\b/, label: 'bash -c inline execution' },
  { pattern: /\bsh\s+-c\b/, label: 'sh -c inline execution' },
  { pattern: /\bnode\s+-e\b/, label: 'node -e inline execution' },
  { pattern: /\bpython[23]?\s+-c\b/, label: 'python -c inline execution' },
  { pattern: /[>]{1,2}\s*\//, label: 'shell redirect to path' },
];

// ─── STATIC-009 secret patterns ───────────────────────────────────────────────

const SECRET_KEY_PATTERNS = [
  /api[_\-]?key/i,
  /secret/i,
  /token/i,
  /password/i,
  /credential/i,
  /private[_\-]?key/i,
  /client[_\-]?secret/i,
  /access[_\-]?token/i,
  /refresh[_\-]?token/i,
];

const SECRET_VALUE_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /ghp_[A-Za-z0-9]{36,}/, label: 'GitHub personal access token (ghp_)' },
  { pattern: /gho_[A-Za-z0-9]{36,}/, label: 'GitHub OAuth token (gho_)' },
  { pattern: /github_pat_[A-Za-z0-9_]{82,}/, label: 'GitHub fine-grained PAT' },
  { pattern: /sk-[A-Za-z0-9]{32,}/, label: 'API secret key (sk-)' },
  { pattern: /pk-[A-Za-z0-9]{32,}/, label: 'API public key (pk-)' },
  { pattern: /AKIA[0-9A-Z]{16}/, label: 'AWS access key ID' },
  { pattern: /Bearer\s+eyJ[A-Za-z0-9_\-]+/, label: 'Bearer JWT token' },
  { pattern: /eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}/, label: 'JWT token' },
];

// ─── STATIC-010 exfil sink fields ────────────────────────────────────────────

const EXFIL_FIELD_NAMES = new Set([
  'email',
  'recipient',
  'webhook',
  'url',
  'endpoint',
  'callback',
  'to',
  'destination',
  'target_url',
  'webhook_url',
  'notify_url',
]);

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

  // STATIC-006: Server metadata anomaly
  {
    id: 'STATIC-006',
    name: 'Server metadata anomaly',
    category: 'server_metadata_anomaly',
    severity: 'medium',
    description: 'Detects anomalies in MCP server metadata such as missing or generic server names and missing version.',
    owaspRefs: ['LLM06'],
    slowmistRef: 'SS-SM',
    remediation: 'Ensure server metadata includes a unique, descriptive name and a version string.',
    check(surface) {
      const results: StaticRuleMatch[] = [];
      const info = surface.serverInfo;
      if (!info) {
        results.push({
          path: 'serverInfo',
          evidence: 'missing',
          detail: 'Server did not provide serverInfo metadata',
          severityOverride: 'medium',
        });
        return results;
      }
      const nameLower = info.name.trim().toLowerCase();
      if (!nameLower || GENERIC_SERVER_NAMES.has(nameLower)) {
        results.push({
          path: 'serverInfo.name',
          evidence: info.name,
          detail: `Server name "${info.name}" is missing or generic`,
          severityOverride: 'medium',
        });
      }
      if (!info.version) {
        results.push({
          path: 'serverInfo.version',
          evidence: 'missing',
          detail: 'Server does not advertise a version string',
          severityOverride: 'low',
        });
      }
      return results;
    },
  },

  // STATIC-007: Capability overreach
  {
    id: 'STATIC-007',
    name: 'Capability overreach',
    category: 'capability_overreach',
    severity: 'high',
    description: 'Detects servers advertising excessive capabilities such as sampling or declaring tools capability with no tools exposed.',
    owaspRefs: ['LLM06', 'LLM09'],
    slowmistRef: 'SS-CO',
    remediation: 'Restrict server capabilities to the minimum required. Remove sampling capability unless explicitly needed.',
    check(surface) {
      const results: StaticRuleMatch[] = [];
      const caps = surface.serverInfo?.capabilities;
      if (!caps) return results;
      if (caps.sampling) {
        results.push({
          path: 'serverInfo.capabilities.sampling',
          evidence: JSON.stringify(caps.sampling),
          detail: 'Server advertises sampling capability, allowing it to make LLM calls on behalf of the client',
          severityOverride: 'high',
        });
      }
      if (caps.tools && surface.tools.length === 0) {
        results.push({
          path: 'serverInfo.capabilities.tools',
          evidence: JSON.stringify(caps.tools),
          detail: 'Server declares tools capability but exposes zero tools',
          severityOverride: 'medium',
        });
      }
      return results;
    },
  },

  // STATIC-008: Config command risk
  {
    id: 'STATIC-008',
    name: 'Config command risk',
    category: 'config_command_risk',
    severity: 'critical',
    description: 'Detects dangerous command patterns in MCP server launch configuration.',
    owaspRefs: ['LLM05', 'LLM06'],
    slowmistRef: 'SS-CC',
    remediation: 'Audit server launch commands for shell injection patterns. Avoid command substitution, inline execution, and unpinned package invocations.',
    check(surface) {
      const results: StaticRuleMatch[] = [];
      const cfg = surface.configEntry;
      if (!cfg) return results;
      const parts = [cfg.command ?? '', ...(cfg.args ?? [])];
      const fullCmd = parts.join(' ');

      for (const { pattern, label } of CRITICAL_CMD_PATTERNS) {
        const m = fullCmd.match(pattern);
        if (m) {
          results.push({
            path: 'configEntry.command',
            evidence: m[0],
            detail: `Dangerous pattern detected: ${label}`,
            severityOverride: 'critical',
          });
        }
      }

      for (const { pattern, label } of HIGH_CMD_PATTERNS) {
        const m = fullCmd.match(pattern);
        if (m) {
          results.push({
            path: 'configEntry.command',
            evidence: m[0],
            detail: `Risky execution pattern: ${label}`,
            severityOverride: 'high',
          });
        }
      }

      // Unpinned npx -y
      if (/npx\s+-y\b/.test(fullCmd)) {
        results.push({
          path: 'configEntry.command',
          evidence: fullCmd.match(/npx\s+-y\S*/)?.[0] ?? 'npx -y',
          detail: 'Unpinned npx -y executes latest package version without integrity check',
          severityOverride: 'high',
        });
      }

      return results;
    },
  },

  // STATIC-009: Secret leakage
  {
    id: 'STATIC-009',
    name: 'Secret leakage via config',
    category: 'secret_leakage',
    severity: 'high',
    description: 'Detects secret-like env key names or inline token values in MCP server config, resource URIs, and tool descriptions.',
    owaspRefs: ['LLM06', 'LLM09'],
    slowmistRef: 'SS-SL',
    remediation: 'Use secret managers instead of embedding secrets in config. Never hardcode tokens in resource URIs or tool descriptions.',
    check(surface) {
      const results: StaticRuleMatch[] = [];

      // Check env key names
      for (const key of (surface.configEntry?.envKeys ?? [])) {
        if (SECRET_KEY_PATTERNS.some(p => p.test(key))) {
          results.push({
            path: 'configEntry.envKeys',
            evidence: key,
            detail: `Environment key "${key}" matches secret key name pattern`,
            severityOverride: 'medium',
          });
        }
      }

      // Check resource URIs for inline token values
      for (const [i, resource] of surface.resources.entries()) {
        for (const { pattern, label } of SECRET_VALUE_PATTERNS) {
          const m = resource.uri.match(pattern);
          if (m) {
            results.push({
              path: `resources[${i}].uri`,
              evidence: m[0].slice(0, 20) + '...',
              detail: `Inline ${label} detected in resource URI`,
              severityOverride: 'critical',
            });
          }
        }
      }

      // Check tool descriptions for inline token values
      for (const [i, tool] of surface.tools.entries()) {
        if (typeof tool.description === 'string') {
          for (const { pattern, label } of SECRET_VALUE_PATTERNS) {
            const m = tool.description.match(pattern);
            if (m) {
              results.push({
                path: `tools[${i}].description`,
                evidence: m[0].slice(0, 20) + '...',
                detail: `Inline ${label} detected in tool description`,
                severityOverride: 'critical',
              });
            }
          }
        }
      }

      return results;
    },
  },

  // STATIC-010: Exfiltration sink detection
  {
    id: 'STATIC-010',
    name: 'Exfiltration sink detection',
    category: 'exfil_sink',
    severity: 'high',
    description: 'Detects known exfiltration sink field names in tool input schemas that could allow data to be sent to external destinations.',
    owaspRefs: ['LLM01', 'LLM06'],
    slowmistRef: 'SS-ES',
    remediation: 'Constrain exfil-sink fields with enum or allowlist. Audit tools that can transmit data to external endpoints.',
    check(surface) {
      const results: StaticRuleMatch[] = [];
      for (const [i, tool] of surface.tools.entries()) {
        const schema = tool.inputSchema;
        if (!schema || typeof schema !== 'object') continue;
        const props = (schema as Record<string, unknown>).properties as Record<string, unknown> | undefined;
        if (!props) continue;

        for (const [fieldName, fieldDef] of Object.entries(props)) {
          if (!EXFIL_FIELD_NAMES.has(fieldName.toLowerCase())) continue;

          const def = (fieldDef ?? {}) as Record<string, unknown>;

          // Skip if has enum constraint
          if (Array.isArray(def.enum)) continue;

          const desc = typeof def.description === 'string' ? def.description.toLowerCase() : '';
          const sendKeywords = /\b(send|upload|post|transmit|forward|relay)\b/;

          let sev: Severity;
          if (sendKeywords.test(desc)) {
            sev = 'critical';
          } else if (def.pattern || def.format) {
            sev = 'medium';
          } else {
            sev = 'high';
          }

          results.push({
            path: `tools[${i}].inputSchema.properties.${fieldName}`,
            evidence: fieldName,
            detail: `Unconstrained exfiltration sink field "${fieldName}" in tool "${tool.name}"`,
            severityOverride: sev,
          });
        }
      }
      return results;
    },
  },

  // STATIC-011: Server instruction injection
  {
    id: 'STATIC-011',
    name: 'Server instruction injection',
    category: 'server_instruction_injection',
    severity: 'critical',
    description: 'Detects prompt-injection patterns in MCP server-level instructions.',
    owaspRefs: ['LLM01', 'LLM06'],
    slowmistRef: 'SS-PS',
    remediation: 'Review server instructions for coercive or override language.',
    check(surface) {
      if (!surface.serverInstructions) return [];
      return scanTextForInjection({
        text: surface.serverInstructions,
        path: 'serverInstructions',
        contextLabel: 'server instructions',
        authorityLevel: 'server_instruction',
      });
    },
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

// ─── detectCrossServerCollisions ─────────────────────────────────────────────

export function detectCrossServerCollisions(
  surfaces: McpInspectionSurface[],
): StaticFinding[] {
  if (surfaces.length < 2) return [];

  // Build map: toolName → list of serverNames that expose it
  const toolToServers = new Map<string, string[]>();
  for (const surface of surfaces) {
    for (const tool of surface.tools) {
      const servers = toolToServers.get(tool.name) ?? [];
      servers.push(surface.serverName);
      toolToServers.set(tool.name, servers);
    }
  }

  const findings: StaticFinding[] = [];
  for (const [toolName, servers] of toolToServers) {
    if (servers.length < 2) continue;

    const severity: Severity = 'high';
    findings.push({
      mode: 'static',
      ruleId: 'STATIC-002',
      ruleName: 'Tool name shadowing',
      category: 'tool_name_shadowing',
      severity,
      owaspRefs: ['LLM01', 'LLM05'],
      slowmistRef: 'SS-NS',
      serverName: servers.join(', '),
      matches: servers.map(serverName => ({
        path: `${serverName}.tools[name=${toolName}]`,
        evidence: toolName,
        detail: `Tool "${toolName}" is exposed by multiple servers: ${servers.join(', ')}`,
        severityOverride: severity,
      })),
      riskScore: RISK_SCORE_MAP[severity],
      remediation: 'Rename tools to be unique across servers to prevent shadowing and unintended routing.',
    });
  }

  return findings;
}
