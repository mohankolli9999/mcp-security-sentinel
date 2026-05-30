export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type TestSurface =
  | 'tool_result'
  | 'tool_description'
  | 'tool_schema'
  | 'resource_content'
  | 'prompt_template'
  | 'server_metadata'
  | 'multi_server_collision'
  | 'session_transport';

export interface PayloadOracle {
  successMarkers?: string[];
  forbiddenToolCalls?: string[];
  forbiddenArgumentPatterns?: Array<{
    toolName: string;
    argumentPath: string; // e.g. "$.recipient"
    pattern: string;      // regex string
  }>;
  forbiddenResponsePatterns?: string[];
}

export interface InjectionPayload {
  id: string;
  name: string;
  category: string;
  description: string;
  severity: Severity;
  owaspRefs: string[];
  slowmistRef: string;
  priority: Severity;    // scheduling urgency — equals severity in V1; may diverge when exploitability/business context is factored in
  testSurface: TestSurface;
  payload: string;
  oracle: PayloadOracle;
  remediation: string;
}

export interface Evidence {
  type:
    | 'marker_found'
    | 'forbidden_tool_call'
    | 'forbidden_argument'
    | 'secret_leak'
    | 'instruction_acknowledged'
    | 'task_deviation';
  description: string;
  excerpt?: string;
  toolName?: string;
  argumentPath?: string;
}

export interface JudgeVerdict {
  manipulated: boolean;
  reason: string;
  riskAdjustment: number; // ±2.0
  confidence: number;      // 0.0–1.0
}

export interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
}

export interface ScanFinding {
  payloadId: string;
  payloadName: string;
  category: string;
  severity: Severity;
  owaspRefs: string[];
  slowmistRef: string;
  toolName: string;
  testSurface: TestSurface;
  injectedPayload: string;
  agentResponse: string;
  toolCallsMade: ToolCall[];
  manipulated: boolean;
  detectionMethod: 'oracle' | 'judge';
  confidence: number;
  evidence: Evidence[];
  riskScore: number; // 0–10, NOT CVSS
  runs: number;
  successCount: number;
  remediation: string;
  reproductionCommand: string;
}

export interface ScanResult {
  targetServer: string;
  scanTimestamp: string;
  agentModel: string;
  judgeModel: string;
  baselineEnabled: boolean;
  runsPerPayload: number;
  totalPayloadsTested: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  findings: ScanFinding[];
  summary: string;
}

export interface Scenario {
  id: string;
  userPrompt: string;
  allowedTools: string[];
  forbiddenTools: string[];
}

export interface BaselineResult {
  toolCallsMade: ToolCall[];
  agentTextResponse: string;
}

// ─── Static inspection types (v2) ───

export interface McpToolDefinition {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
}

export interface McpResourceDefinition {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

export interface McpPromptDefinition {
  name: string;
  description?: string;
  arguments?: Array<{ name: string; description?: string; required?: boolean }>;
}

export interface McpServerCapabilities {
  tools?: { listChanged?: boolean };
  resources?: { subscribe?: boolean; listChanged?: boolean };
  prompts?: { listChanged?: boolean };
  sampling?: Record<string, unknown>;
}

export interface McpServerInfo {
  name: string;
  version?: string;
  protocolVersion?: string;
  capabilities: McpServerCapabilities;
}

export interface McpConfigServerEntry {
  name: string;
  transport: 'stdio' | 'sse' | 'http' | 'unknown';
  command?: string;
  args?: string[];
  url?: string;
  env?: Record<string, string>;
  envKeys: string[];
  sourcePath: string;
  rawPath: string;
}

export interface McpInspectionSurface {
  serverName: string;
  serverInfo?: McpServerInfo;
  serverInstructions?: string;
  configEntry?: McpConfigServerEntry;
  tools: McpToolDefinition[];
  resources: McpResourceDefinition[];
  prompts: McpPromptDefinition[];
  resourceContents?: Array<{ uri: string; text: string }>;
  warnings: string[];
}

export type StaticRuleCategory =
  | 'tool_description_injection'
  | 'tool_name_shadowing'
  | 'schema_poisoning'
  | 'resource_injection'
  | 'prompt_injection'
  | 'server_metadata_anomaly'
  | 'capability_overreach'
  | 'config_command_risk'
  | 'secret_leakage'
  | 'exfil_sink'
  | 'server_instruction_injection';

export interface StaticRuleMatch {
  path: string;
  evidence: string;
  detail: string;
  severityOverride?: Severity;
  confidence?: number;
}

export interface StaticRule {
  id: string;
  name: string;
  category: StaticRuleCategory;
  severity: Severity;
  description: string;
  owaspRefs: string[];
  slowmistRef: string;
  remediation: string;
  check: (surface: McpInspectionSurface) => StaticRuleMatch[];
}

export interface StaticFinding {
  mode: 'static';
  ruleId: string;
  ruleName: string;
  category: StaticRuleCategory;
  severity: Severity;
  owaspRefs: string[];
  slowmistRef: string;
  serverName: string;
  matches: StaticRuleMatch[];
  riskScore: number;
  remediation: string;
}

export interface DynamicFinding {
  mode: 'dynamic';
  payloadId: string;
  payloadName: string;
  category: string;
  severity: Severity;
  owaspRefs: string[];
  slowmistRef: string;
  toolName: string;
  testSurface: TestSurface;
  injectedPayload: string;
  agentResponse: string;
  toolCallsMade: ToolCall[];
  manipulated: boolean;
  detectionMethod: 'oracle' | 'judge';
  confidence: number;
  evidence: Evidence[];
  riskScore: number;
  runs: number;
  successCount: number;
  remediation: string;
  reproductionCommand: string;
}

export type Finding = StaticFinding | DynamicFinding;

export interface InspectResult {
  mode: 'inspect';
  target: string;
  scanTimestamp: string;
  serversInspected: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  findings: StaticFinding[];
  warnings: Array<{ serverName?: string; message: string; path?: string }>;
  summary: string;
}

export interface AttackResult {
  mode: 'attack';
  targetServer: string;
  scanTimestamp: string;
  agentModel: string;
  judgeModel: string;
  baselineEnabled: boolean;
  runsPerPayload: number;
  totalPayloadsTested: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  findings: DynamicFinding[];
  summary: string;
}

export type SentinelResult = InspectResult | AttackResult;

export interface ConnectOptions {
  entry: McpConfigServerEntry;
  timeoutMs?: number;
  enumerationTimeoutMs?: number;
  maxPages?: number;
  readResources?: boolean;
  maxResources?: number;
  maxResourceBytes?: number;
  resourceTimeoutMs?: number;
}

export interface ConnectResult {
  success: true;
  surface: McpInspectionSurface;
}

export interface ConnectFailure {
  success: false;
  serverName: string;
  error: string;
  sourcePath?: string;
  rawPath?: string;
}

export type ConnectionOutcome = ConnectResult | ConnectFailure;

export interface GateDecision {
  approved: McpConfigServerEntry[];
  denied: McpConfigServerEntry[];
  executeMode: boolean;
}
