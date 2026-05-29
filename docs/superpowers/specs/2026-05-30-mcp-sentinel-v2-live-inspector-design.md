# MCP Security Sentinel v2 — Live Inspector Design

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a no-API-key MCP server inspector as the primary mode, making the existing AI-powered attack testing optional.

**Architecture:** Two-mode CLI — `inspect` (static analysis of live MCP servers, no AI key) and `attack` (dynamic victim+judge injection testing, requires Anthropic API key). Flat `src/` layout with strict import boundaries between modes.

**Tech Stack:** TypeScript ESM, `@modelcontextprotocol/sdk` (pinned version), `chalk`, `ora`, `vitest`, `dotenv`. Anthropic SDK used only in attack mode.

---

## 1. Product Modes

### inspect (primary mode, no API key)

Connects to live MCP servers via the MCP protocol, enumerates tools/resources/prompts/capabilities/server instructions, and runs deterministic static checks against all metadata and config entries.

`inspect` is the primary product mode, but the CLI still requires an explicit command: `mcpsentinel inspect` or `mcpsentinel attack`. Running `mcpsentinel` with no command prints usage and exits.

### attack (optional enhanced mode, requires API key)

Runs the existing victim+judge dynamic injection tests using the Anthropic API. This is the V1 scanner flow, now namespaced under the `attack` subcommand.

Requires `ANTHROPIC_API_KEY` as an environment variable. The project uses `dotenv` — developers can place a `.env` file in the project root for convenience.

---

## 2. File Layout

```
src/
  index.ts              # command router, arg parsing, help, exit codes
  inspect.ts            # inspect pipeline orchestration
  types.ts              # all interfaces, discriminated Finding union
  mcpClient.ts          # MCP SDK client: connect/enumerate/disconnect
  configParser.ts       # parse Claude Desktop / VS Code config files
  configGate.ts         # safety gate: display entries, show findings, handle approval
  staticRules.ts        # 11 STATIC_RULES + runStaticRules() + scanTextForInjection helper
  reporter.ts           # shared reporter for InspectResult | AttackResult + redaction
  scanner.ts            # existing dynamic attack engine (lazy-loaded)
  payloads.ts           # existing 17 injection payloads
  mockServer.ts         # existing mock server
  oracles.ts            # existing oracle checks
```

12 source files. Well under the 15-18 threshold for considering directory restructuring.

### Import firewall (hard rules)

- `mcpClient.ts`, `configParser.ts`, `configGate.ts`, `staticRules.ts` — **never import `@anthropic-ai/sdk`**
- `scanner.ts`, `payloads.ts`, `mockServer.ts`, `oracles.ts` — **never import `@modelcontextprotocol/sdk`**
- `reporter.ts`, `types.ts` — **never import either SDK**
- `index.ts` — lazy-loads `scanner.ts` via `await import('./scanner.js')` only when `attack` is invoked

### Module boundaries

| File | Does | Does NOT |
|------|------|----------|
| `index.ts` | parse CLI args, dispatch commands, print help, compute exit codes | connect to MCP, run rules, build results, format reports |
| `inspect.ts` | orchestrate inspect pipeline, aggregate results, manage timeouts | parse CLI args, print help, compute exit codes |
| `mcpClient.ts` | connect, enumerate, optionally read resources, disconnect | parse configs, run rules, display anything |
| `configParser.ts` | read JSON, detect format, return `McpConfigServerEntry[]` | execute commands, evaluate risk, prompt user |
| `configGate.ts` | display inventory, show config findings, handle approval UX | parse configs, run static rules, connect to servers |
| `staticRules.ts` | define rules, run checks, return matches | parse configs, connect to MCP, format reports |
| `reporter.ts` | format terminal/JSON output, redact secrets | import Anthropic or MCP SDK |

If `index.ts` starts accumulating config parsing, rule execution, or report formatting, the design is drifting.

---

## 3. Type System

### MCP inspection types

```typescript
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
  env?: Record<string, string>;       // INTERNAL ONLY: never serialized, printed, or included in findings
  envKeys: string[];                   // safe for display/reporting
  sourcePath: string;                  // config file path
  rawPath: string;                     // e.g. "mcpServers.github" or "servers.github"
}

export interface McpInspectionSurface {
  serverInfo?: McpServerInfo;          // optional: --no-execute has no server info
  serverInstructions?: string;         // MCP server initialization instructions
  configEntry?: McpConfigServerEntry;  // present for config-based inspection
  tools: McpToolDefinition[];
  resources: McpResourceDefinition[];
  prompts: McpPromptDefinition[];
  resourceContents?: Array<{ uri: string; text: string }>;
  warnings: string[];                  // always present, empty if clean
}
```

**Hard rule:** `McpConfigServerEntry.env` is internal-only and must never be serialized to JSON, printed, or included in findings. Only `envKeys` may appear in output.

### Static rules

```typescript
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

export interface StaticRule {
  id: string;
  name: string;
  category: StaticRuleCategory;
  severity: Severity;                  // default severity; may be overridden at match level
  description: string;
  owaspRefs: string[];
  slowmistRef: string;                 // Sentinel's internal mapping to SlowMist MCP checklist areas
  remediation: string;
  check: (surface: McpInspectionSurface) => StaticRuleMatch[];
}

export interface StaticRuleMatch {
  path: string;                        // e.g. "tools[2].description", "mcpServers.github.command"
  evidence: string;                    // what was found (raw; redacted at output time)
  detail: string;                      // human-readable explanation
  severityOverride?: Severity;         // if present, overrides rule default for this match
  confidence?: number;                 // 0.0-1.0
}
```

### Discriminated finding union

```typescript
export interface StaticFinding {
  mode: 'static';
  ruleId: string;
  ruleName: string;
  category: StaticRuleCategory;
  severity: Severity;                  // highest of rule default and match overrides
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
  detectionMethod: 'oracle' | 'judge' | 'both';
  confidence: number;
  evidence: Evidence[];
  riskScore: number;
  runs: number;
  successCount: number;
  remediation: string;
  reproductionCommand: string;
}

export type Finding = StaticFinding | DynamicFinding;
```

### Result types

```typescript
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
```

---

## 4. Static Rules — 11 Checks

| ID | Category | Severity | Surface | Detection |
|---|---|---|---|---|
| STATIC-001 | `tool_description_injection` | severity-sensitive | `tools[*].description` | Pattern-based via `scanTextForInjection()` |
| STATIC-002 | `tool_name_shadowing` | severity-sensitive | `tools[*].name` | Known-name set + cross-server collision |
| STATIC-003 | `schema_poisoning` | severity-sensitive | `tools[*].inputSchema`, `outputSchema` | Pattern-based on descriptions, structural on permissiveness |
| STATIC-004 | `resource_injection` | severity-sensitive | `resourceContents[*].text` | Pattern-based via `scanTextForInjection()` |
| STATIC-005 | `prompt_injection` | severity-sensitive | `prompts[*].description`, `arguments[*].description` | Pattern-based via `scanTextForInjection()` |
| STATIC-006 | `server_metadata_anomaly` | medium | `serverInfo` | Structural checks |
| STATIC-007 | `capability_overreach` | high | `serverInfo.capabilities` | Structural checks |
| STATIC-008 | `config_command_risk` | severity-sensitive | `configEntry.command`, `configEntry.args` | Pattern-based with sub-severities |
| STATIC-009 | `secret_leakage` | severity-sensitive | `configEntry.envKeys`, descriptions, URIs | Pattern-based + structural |
| STATIC-010 | `exfil_sink` | severity-sensitive | `tools[*].inputSchema.properties` | List-based + structural |
| STATIC-011 | `server_instruction_injection` | severity-sensitive | `serverInstructions` | Pattern-based via `scanTextForInjection()` |

### Severity-sensitive rules

Rules marked "severity-sensitive" use match-level `severityOverride` to produce findings at the appropriate severity. The `StaticFinding.severity` is the highest of the rule default and all match overrides.

### Severity tiers per rule

**STATIC-001 (tool_description_injection):**
- critical: explicit system/developer override, exfiltration instruction, hidden instruction, credential request
- high: suspicious role/instruction language
- medium: weak suspicious language without stronger indicators

**STATIC-002 (tool_name_shadowing):**
- critical: sensitive name + suspicious description/schema
- high: duplicate tool name across different servers (cross-server)
- medium: sensitive built-in-like name (read_file, write_file, execute_command, bash)

**STATIC-003 (schema_poisoning):**
- high: instructional text inside schema property descriptions
- medium: `additionalProperties: true` alone
- high: `additionalProperties: true` combined with exfil-like fields or tool side effects

**STATIC-004 (resource_injection):**
- critical: explicit system override, exfiltration directives
- high: suspicious instruction language
- medium: weak suspicious language

**STATIC-005 (prompt_injection):**
- critical: explicit system override, exfiltration directives
- high: role impersonation, hidden instructions
- medium: weak suspicious language

**STATIC-008 (config_command_risk):**
- critical: `curl|bash`, `wget|sh`, command substitution, pipe to shell, `sudo` with shell, reverse-shell patterns
- high: `bash -c`, `sh -c`, `node -e`, `python -c`, redirects, unpinned `npx`/`uvx`
- medium: relative executable path, broad env usage, unknown binary
- low: informational command hygiene

**STATIC-009 (secret_leakage):**
- critical: actual secret value appears in tool/resource/prompt/URI/description
- high: secret-like key passed to a risky command (from STATIC-008)
- medium/high: secret-like env key name passed to a server

**STATIC-010 (exfil_sink):**
- critical: destination field + suspicious description or send/upload/post/exfil wording
- high: unrestricted string destination field with no enum/pattern/format constraint
- medium: external destination field exists

**STATIC-011 (server_instruction_injection):**
- critical: explicit system/developer override, "ignore previous instructions", "you are now...", credential/exfiltration directives, instructions to call tools automatically, instructions to suppress warnings
- high: role impersonation, "new policy", "mandatory compliance", "do not tell the user", "silent background action"
- medium: weaker suspicious instruction language

### Shared helper

```typescript
function scanTextForInjection(opts: {
  text: string;
  path: string;
  contextLabel: string;
  authorityLevel: 'tool_description' | 'server_instruction' | 'resource' | 'prompt';
}): StaticRuleMatch[]
```

Used by STATIC-001, STATIC-004, STATIC-005, STATIC-011. Same pattern engine, separate rule identity.

### Cross-server collision detection

```typescript
export function detectCrossServerCollisions(
  surfaces: McpInspectionSurface[]
): StaticFinding[]
```

Called from `inspect.ts` after all per-server `runStaticRules()` calls complete. Emits STATIC-002 findings with paths like `servers.github.tools[2].name` and `servers.filesystem.tools[0].name`.

### SSRF/internal endpoint patterns

Included in STATIC-009 and STATIC-010 checks:
- `localhost`, `127.0.0.1`, `0.0.0.0`, `::1`
- `169.254.169.254`, `metadata.google.internal`
- Internal/private IP ranges
- `file://`, `ftp://`, `gopher://` URI schemes

### SlowMist reference disclaimer

`slowmistRef` values (e.g., `SS-TD`, `SS-PS`, `SS-DS`) are Sentinel's internal mapping to SlowMist MCP Security Checklist areas, not official SlowMist identifiers.

---

## 5. Config Parsing & Safety Gate

### Config formats supported

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json`):
```json
{ "mcpServers": { "name": { "command": "...", "args": [...], "env": {...} } } }
```

**VS Code** (`.vscode/mcp.json` or `settings.json`):
```json
{ "servers": { "name": { "type": "stdio", "command": "...", "args": [...], "env": {...} } } }
```

### `configParser.ts`

```typescript
export function parseConfigFile(filePath: string): McpConfigServerEntry[]
```

- Reads and parses JSON
- Detects format by presence of `mcpServers` (Claude Desktop) vs `servers` (VS Code)
- Extracts `name`, `command`, `args`, `url`, `env` (internal), `envKeys` (safe)
- Infers transport: `command` present => `stdio`, `url` + explicit `type: "sse"` => `sse`, `url` + `type: "http"` or absent => `http`, else `unknown`
- Preserves `rawPath` (e.g., `mcpServers.github`) for evidence trails
- Records `sourcePath` (config file path)
- Returns plain data. No validation beyond structural correctness.

**Structural validation:**
- Config is valid JSON object
- Server map exists
- Each server entry is an object
- `args` is array if present
- `env` is object if present
- `command` is string if present
- `url` is string if present

**Evidence paths preserve raw config shape:**
- Claude Desktop: `mcpServers.github.command`
- VS Code: `servers.github.command`
- Do not normalize all paths to `config.servers.*`

### `configGate.ts`

```typescript
export interface GateDecision {
  approved: McpConfigServerEntry[];
  denied: McpConfigServerEntry[];
  executeMode: boolean;
}

export async function runConfigGate(
  entries: McpConfigServerEntry[],
  configFindings: StaticFinding[],
  flags: { server?: string; all?: boolean; yes?: boolean; noExecute?: boolean }
): Promise<GateDecision>
```

**Flow:**

1. Display inventory for every entry: server name, transport, command/URL, env key names
2. Display config-level static findings (from `staticRules.ts`, computed before gate)
3. Always emit full risk summary, even with `--yes`
4. Apply selection logic:

| Flags | Behavior |
|-------|----------|
| `--no-execute` | Return `executeMode: false`, all entries in `denied` |
| `--server github` | Auto-approve `github` only. If not found in config, exit with error. |
| `--all` | Select all servers. May show confirmation prompt. |
| `--all --yes` | Select all, skip interactive prompt, still print risk summary. |
| `--yes` alone | Error: `--yes` requires `--all` or `--server` |
| none | Interactive prompt |

**Interactive prompt (raw `readline`):**
```
Select servers to inspect:
  [1] github (1 finding: STATIC-008 critical)
  [2] filesystem (no findings)
  [a] All
  [q] Quit

>
```

Accepted inputs: `1`, `1,2,3`, `a`, `q`, empty (deny/quit safely).

`configGate.ts` does NOT parse configs, run static rules, or connect to servers. It only displays findings produced by `staticRules.ts` and handles approval UX.

---

## 6. MCP Client

### `mcpClient.ts`

```typescript
export interface ConnectOptions {
  entry: McpConfigServerEntry;
  timeoutMs?: number;                  // connect/init, default 10_000
  enumerationTimeoutMs?: number;       // list calls per page, default 5_000
  maxPages?: number;                   // pagination guard, default 20
  readResources?: boolean;             // default false
  maxResources?: number;               // default 10
  maxResourceBytes?: number;           // default 1_048_576
  resourceTimeoutMs?: number;          // default 5_000
}

export interface ConnectResult {
  success: true;
  surface: McpInspectionSurface;
}

export interface ConnectFailure {
  success: false;
  serverName: string;
  error: string;
}

export type ConnectionOutcome = ConnectResult | ConnectFailure;

export async function inspectServer(options: ConnectOptions): Promise<ConnectionOutcome>
```

### Connection flow

1. Create transport based on `entry.transport` (stdio/HTTP/SSE)
2. Create `Client` with zero capabilities (no `sampling`, `elicitation`, `roots`)
3. Connect with timeout
4. Capture `serverInfo` and `serverInstructions` from initialization
5. Paginated enumeration: `listTools`, `listResources`, `listPrompts` — loop on `nextCursor` with `maxPages` guard
6. Optional: read resource contents if `--read-resources` (bounded by count/size/timeout)
7. Disconnect in `finally` block — always

### Passive client

The inspect client declares **zero capabilities**. It does not:
- Declare `sampling` (prevents server from requesting LLM calls)
- Declare `elicitation` (prevents server from requesting user input)
- Declare `roots` (prevents server from requesting filesystem access)
- Call `tools/call` (tool invocation is attack mode only)
- Call `prompts/get` (prompt rendering may have side effects; V1 inspects metadata only)

### Pagination

`listTools()`, `listResources()`, and `listPrompts()` may return paginated results. The client loops on `nextCursor` up to `maxPages` (default 20). If the limit is reached, a warning is added to the surface.

### Resource reading

Disabled by default. When enabled via `--read-resources`:
- Read at most `maxResources` (default 10)
- Skip resources exceeding `maxResourceBytes` (default 1MB)
- Timeout per resource read: `resourceTimeoutMs` (default 5s)
- Skip binary/blob content; normalize text-only content
- Do not follow nested links
- Failed reads become warnings, not fatal errors
- Redact secrets in report excerpts

### Timeout strategy

| Scope | Default | Guards |
|-------|---------|--------|
| Connection + init | 10s | Server startup, handshake |
| Per-enumeration page | 5s | listTools/listResources/listPrompts per page |
| Per-resource read | 5s | Individual resources/read calls |

Implementation: `Promise.race` against timeout rejection. Note: `Promise.race` does not cancel the underlying operation. On timeout, close client/transport in `finally`.

### Error handling

- Server won't start → `ConnectFailure`
- Init times out → `ConnectFailure`
- Init succeeds but list call fails → partial surface with warning
- Individual resource read fails → skip, add warning
- Never throws — always returns `ConnectionOutcome`

### Transport support

| Transport | V1 Support | Notes |
|-----------|-----------|-------|
| stdio | Full | Primary. Most MCP servers are local. |
| Streamable HTTP | Full | SDK primary HTTP transport. |
| SSE | Full | Legacy fallback for HTTP. |

For unknown remote URL transport, prefer Streamable HTTP first, fall back to SSE.

Auth for remote servers is out of scope for V1. If a server requires auth, return `ConnectFailure` with "authentication required."

### Process cleanup

Use `client.close()` for all transports. For Streamable HTTP, call `terminateSession()` before `client.close()` if the transport exposes it. Do not reach into `transport.process` unless the SDK officially exposes it.

### SDK pinning

Pin a specific MCP TypeScript SDK version before implementation and verify transport imports against that version. The SDK has changed across versions — do not assume import paths without verification.

---

## 7. CLI Interface

### Command structure

```
mcpsentinel <command> [options]

Commands:
  inspect    Inspect MCP servers for security risks (no API key required)
  attack     Run dynamic injection tests against an agent (requires ANTHROPIC_API_KEY)
```

No implicit default command. Running `mcpsentinel` with no command prints usage and exits.

### Inspect flags

```
mcpsentinel inspect [options]

Connection (one required):
  --command <binary>       Launch and inspect a single MCP server via stdio
  --arg <value>            Argument for --command (repeatable)

  --config <path>          Parse MCP config file and inspect defined servers

Config selection (--config only):
  --server <name>          Inspect only this server from config
  --all                    Select all servers from config
  --yes                    Skip interactive confirmation (requires --all or --server)
  --no-execute             Config inventory and risk review only; do not connect

Resource inspection:
  --read-resources         Read resource contents (default: disabled)
  --max-resources <n>      Max resources to read (default: 10)
  --max-resource-bytes <n> Max bytes per resource (default: 1048576)

Timeouts:
  --timeout-ms <n>         Connection/init timeout (default: 10000)
  --enumeration-timeout-ms <n>  Per-list-call timeout (default: 5000)
  --resource-timeout-ms <n>     Per-resource-read timeout (default: 5000)
  --max-pages <n>          Pagination limit per enumeration (default: 20)

Output:
  --severity <level>       Only report findings at or above this severity
  --fail-on <level>        Exit non-zero if any finding meets this severity (default: high)
  --output <path>          Write JSON report to file
  --json                   Print JSON to stdout, suppress human-readable output
  --help                   Show inspect help
```

### Attack flags

```
mcpsentinel attack [options]

Payload selection:
  --payload <id>           Test a specific payload (e.g. INJ-001)
  --category <cat>         Test payloads in a category
  --severity <level>       Test payloads at or above severity (filters payloads, not findings)
  --tool <name>            Filter by oracle.forbiddenToolCalls (not by target tool surface)

Execution:
  --runs <n>               Runs per payload (default: 3)
  --agent-model <model>    Victim agent model (default: claude-haiku-4-5-20251001)
  --judge-model <model>    Judge model (default: claude-sonnet-4-6)
  --no-baseline            Disable baseline comparison

Output:
  --fail-on <level>        Exit non-zero threshold (default: high)
  --output <path>          Write JSON report to file
  --json                   Print JSON to stdout, suppress human-readable output
  --help                   Show attack help
```

### --severity semantics (important difference)

- `inspect --severity` = **report/output filter** — filters findings before printing and JSON output
- `attack --severity` = **payload selection filter** — filters which payloads are tested

`--fail-on` operates on the filtered finding set, not hidden findings. Users will not get non-zero exits for findings they explicitly filtered out.

**Validation:** If `--fail-on` is lower priority than `--severity`, warn that the fail-on threshold may never trigger.

### --json behavior

- Prints full JSON result to stdout
- Suppresses chalk/human-readable output
- Errors still go to stderr
- `--output` still writes to file if provided
- No ANSI colors in JSON mode

### Strict validation

- Unknown flag → error + usage
- Missing value after flag → error + usage
- Invalid severity → error
- Invalid integer → error
- `--runs 0`, `--max-pages 0` → error
- `--yes` without `--all` or `--server` → error
- `--server <name>` not found in config → error, no fallback
- `--read-resources` with `--no-execute` → error

### `index.ts` routing (pseudocode)

```typescript
const command = process.argv[2];

switch (command) {
  case 'inspect': {
    const opts = parseInspectArgs(process.argv.slice(3));
    if (opts.help) { printInspectUsage(); process.exit(0); }
    const { runInspect } = await import('./inspect.js');
    const result = await runInspect(opts);
    printReport(result);
    if (opts.output) writeJsonReport(result, opts.output);
    process.exit(applyFailOn(result.findings, opts.failOn));
  }
  case 'attack': {
    const opts = parseAttackArgs(process.argv.slice(3));
    if (opts.help) { printAttackUsage(); process.exit(0); }
    if (!process.env['ANTHROPIC_API_KEY']) {
      console.error('ANTHROPIC_API_KEY is required for attack mode.');
      console.error('Run "mcpsentinel inspect" for no-key static analysis.');
      process.exit(1);
    }
    const { runScan } = await import('./scanner.js');
    const result = await runScan(opts);
    printReport(result);
    if (opts.output) writeJsonReport(result, opts.output);
    process.exit(applyFailOn(result.findings, opts.failOn));
  }
  default:
    printUsage();
    process.exit(command === '--help' || command === '-h' ? 0 : 1);
}
```

`parseInspectArgs()` and `parseAttackArgs()` live in `index.ts`. Only `runInspect` is imported from `inspect.ts`. Only `runScan` is imported from `scanner.ts`.

---

## 8. Inspect Pipeline (`inspect.ts`)

### Orchestration

```typescript
export async function runInspect(opts: InspectOptions): Promise<InspectResult>
```

**--command mode:**
1. Build `McpConfigServerEntry` from `--command` + `--arg` flags
2. Call `mcpClient.inspectServer(entry)` → `McpInspectionSurface`
3. Call `runStaticRules(surface)` → `StaticFinding[]`
4. Aggregate `InspectResult`

**--config mode:**
1. `configParser.parseConfigFile(path)` → `McpConfigServerEntry[]`
2. For each entry: `runStaticRules({ configEntry, tools:[], resources:[], prompts:[], warnings:[] })` → config-level `StaticFinding[]`
3. `configGate.runConfigGate(entries, configFindings, flags)` → `GateDecision`
4. If `--no-execute`: return `InspectResult` with config findings only
5. For each approved server:
   - `mcpClient.inspectServer(entry)` → `ConnectionOutcome`
   - If success: `runStaticRules(surface)` → live `StaticFinding[]`
   - If failure: add warning, continue (one server failure does not fail the whole run)
6. `detectCrossServerCollisions(allSurfaces)` → cross-server `StaticFinding[]`
7. Combine config + live + collision findings → `InspectResult`

**Config-level findings always persist** in the final `InspectResult`, even after live inspection.

### Guardrails

- Always disconnect MCP clients in `finally`
- Connection/enumeration timeouts from `ConnectOptions`
- Per-server failure is a warning, not total scan failure (unless all targets fail)
- Bound resource reads by count/size/time
- Preserve exact evidence paths in `StaticFinding.matches`

---

## 9. Reporter

### `printReport(result: SentinelResult): void`

Branches on `result.mode`:

**Inspect output:**
```
MCP Security Sentinel -- Inspect Report
Target: claude_desktop_config.json
Servers inspected: 3
Timestamp: 2026-05-30T10:00:00.000Z

Findings: 4 (2 critical, 1 high, 1 medium)

STATIC-008 [CRITICAL] Config Command Risk
  Server: github
  Risk: 9.0
  Matches:
    - Path: mcpServers.github.args[1]
      Evidence: -y (unpinned npx execution)
      Detail: Unpinned npx invocation can execute arbitrary package versions
  Remediation: Pin package versions in MCP server commands.

STATIC-001 [HIGH] Tool Description Injection
  Server: filesystem
  Risk: 7.5
  Matches:
    - Path: tools[2].description
      Evidence: "SYSTEM: ignore previous..."
      Detail: System-style override detected in tool "dangerous_tool"
    - Path: tools[4].inputSchema.properties.path.description
      Evidence: "do not tell the user"
      Detail: Hidden instruction detected
  Remediation: Sanitize tool descriptions.

Warnings:
  - listResources timed out on server "database"
```

**Attack output:** Existing format, uses `DynamicFinding` fields.

### `writeJsonReport(result: SentinelResult, path: string): void`

Preserves discriminated union structure. Does not flatten findings:

```json
{
  "mode": "inspect",
  "findings": [
    {
      "mode": "static",
      "ruleId": "STATIC-008",
      "matches": [...]
    }
  ]
}
```

### `redactSensitiveText(text: string): string`

Applied at the **output boundary** (print/serialize time), not when building `StaticRuleMatch`. Raw evidence stays intact in memory for cross-referencing.

Patterns redacted:
- `ghp_*`, `gho_*`, `github_pat_*` → `ghp_***REDACTED***`
- `Bearer eyJ...` → `Bearer ***REDACTED***`
- `sk-...`, `pk-...` → `sk-***REDACTED***`
- AWS access keys (`AKIA...`) → `AKIA***REDACTED***`
- Private key blocks → `***PRIVATE_KEY_REDACTED***`
- JWTs (`eyJ...`) → `eyJ***REDACTED***`
- Generic long hex/base64 strings that look like tokens

Applied to:
- `StaticRuleMatch.evidence`
- `StaticRuleMatch.detail` if needed
- `DynamicFinding.agentResponse`
- `DynamicFinding.injectedPayload` if it contains known test secrets
- Warning messages
- JSON output

### --severity filtering

Applied before printing and before JSON output. `--fail-on` operates on the filtered set.

### Display all matches

Static findings with multiple matches display all of them, not just the first.

### Warnings vs findings

Warnings are displayed in a separate section. They are not findings unless a static rule explicitly converts a warning into a risk finding.

---

## 10. Testing Strategy

### New test files

| File | Tests | Approach |
|------|-------|----------|
| `tests/staticRules.test.ts` | ~35-40 | Build `McpInspectionSurface` fixtures, assert matches per rule |
| `tests/configParser.test.ts` | ~8 | JSON fixtures for Claude Desktop + VS Code formats |
| `tests/configGate.test.ts` | ~10 | Mock readline, assert `GateDecision` (decision-focused, not output-brittle) |
| `tests/mcpClient.test.ts` | ~10 | Mock pinned SDK version, verify pagination/timeout/partial-failure |
| `tests/inspect.test.ts` | ~6 | Mock mcpClient + staticRules, verify pipeline orchestration |

### Updated test files

| File | Changes |
|------|---------|
| `tests/index.test.ts` | +6 tests: subcommand routing (inspect, attack, none, unknown, --help) |
| `tests/reporter.test.ts` | +4 tests: InspectResult printing, --json output, redaction |
| `tests/scanner.test.ts` | Minimal rename: `ScanResult` → `AttackResult` |
| `tests/payloads.test.ts` | Update count if payloads change |
| `tests/oracles.test.ts` | No changes |
| `tests/mockServer.test.ts` | No changes |

### Testing principles

**Static rules:** Each rule gets at least 3 tests:
1. Positive match — surface with known-bad pattern → matches with correct path/evidence
2. Negative match — clean surface → empty array
3. Severity sensitivity — weak vs strong patterns → correct `severityOverride`

**mcpClient:** Mock against the pinned SDK version. Do not write tests against guessed import paths before dependency pinning is finalized.

**configGate:** Test decisions strongly, output lightly. Assert `GateDecision.approved`/`denied` contents, not full formatting. Assert `--yes` alone errors. Assert empty input denies safely.

**inspect.ts integration:**
- `--config --no-execute` never calls `mcpClient.inspectServer`
- `--config --all --yes` calls mcpClient only after config findings are generated
- Config findings persist in final `InspectResult` after live inspection
- One server connection failure does not fail the whole inspect run
- Cross-server collision detection runs after multiple successful surfaces

**Redaction:**
- Static finding with GitHub token in evidence gets redacted
- Resource URI with token query param gets redacted
- Dynamic `agentResponse` with bearer token gets redacted
- JSON output is also redacted
- `env` values never appear in report output

**--json:**
- `inspect --json` suppresses chalk output
- `attack --json` suppresses chalk output
- `--json` + `--output` writes file and prints JSON to stdout
- `JSON.parse` succeeds on stdout output

### Estimated totals

~70-75 new tests + 49 existing = ~120 tests total.

---

## 11. Acceptance Criteria

1. `mcpsentinel inspect` works without `ANTHROPIC_API_KEY`.
2. `mcpsentinel inspect --config` never executes servers before showing the safety gate.
3. `mcpsentinel attack` is the only path requiring an AI key.
4. Static findings include exact evidence paths:
   - `tools[2].inputSchema.properties.recipient.description`
   - `resources[0].uri`
   - `mcpServers.github.command`
5. Existing dynamic scanner behavior remains mostly untouched.
6. `index.ts` stays thin — no config parsing, rule execution, or report formatting.
7. `McpConfigServerEntry.env` never appears in output (JSON, terminal, or findings).
8. `--yes` is only valid with `--all` or `--server`.
9. `--severity` and `--fail-on` interaction is documented and validated.
10. All static rules are severity-sensitive where specified.
11. Cross-server collision detection works for `--config` with multiple servers.
12. Reporter redacts secrets in evidence before printing or serializing.
13. `--json` produces parseable JSON on stdout with no ANSI codes.
14. Per-server connection failure is a warning, not total scan failure.
