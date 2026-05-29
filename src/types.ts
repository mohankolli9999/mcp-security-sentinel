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
  priority: Severity;
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
  risk_adjustment: number; // ±2.0
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
  detectionMethod: 'oracle' | 'judge' | 'both';
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
