# MCP Security Sentinel — UI Architecture

## Overview

Local-only web UI for MCP Security Sentinel. REST + SSE hybrid backend, React + TypeScript + Vite frontend.

## Project Structure

```
ui/
  package.json
  tsconfig.json
  vite.config.ts
  index.html
  src/
    main.tsx
    App.tsx
    App.css
    api.ts                    # REST + SSE client helpers
    types.ts                  # UI-specific types (re-exports core types)
    components/
      Layout.tsx              # Shell: nav, content area
      SeverityBadge.tsx       # Colored severity indicator
      FindingCard.tsx         # Static/dynamic finding display
      ServerCard.tsx          # Server inventory card
      FindingsTable.tsx       # Sortable findings list
    pages/
      Dashboard.tsx           # Landing page
      Inspect.tsx             # Inspect flow (config → inventory → approve → results)
      Attack.tsx              # Attack flow (filters → run → stream results)
      Reports.tsx             # Load/view/export JSON reports

server/
  uiServer.ts                # Express server with REST + SSE
  runManager.ts              # In-memory run state + SSE emitter
```

## Backend API

### REST Endpoints (stateless, fast)

| Method | Path | Purpose |
|--------|------|---------|
| GET | /api/health | Server status + API key presence |
| POST | /api/config/parse | Parse config file, return server entries (env keys only, never values) |
| POST | /api/inspect/start | Start inspect run, return `{ runId }` |
| POST | /api/attack/start | Start attack run, return `{ runId }` |
| GET | /api/runs/:runId/events | SSE stream for run progress |
| POST | /api/runs/:runId/cancel | Cancel a running scan |
| GET | /api/reports | List reports saved in the `reports/` directory |
| POST | /api/reports/load | Load a JSON report file from disk (`.json` only) |
| POST | /api/reports/export | Write result JSON into the `reports/` directory |

### SSE Event Types

```
status    — run state change (starting, running, completed, failed, cancelled)
inventory — server inventory after config parse
finding   — individual finding as discovered
warning   — warning message
progress  — progress update (e.g., "3/17 payloads tested")
result    — final complete result object
error     — error message
done      — stream complete, client should close
```

### Security Constraints

- Server binds `127.0.0.1` only — never reachable from the network
- All requests must carry a loopback `Host` header (localhost / 127.0.0.1 / [::1]); others get 403. Defeats DNS-rebinding attacks.
- `POST /api/reports/export` only writes inside the project `reports/` directory; path escapes are rejected
- `POST /api/reports/load` only reads `.json` files
- `POST /api/config/parse` strips `env` values, returns `envKeys` only
- `GET /api/health` returns `{ hasApiKey: boolean }`, never the key
- Attack mode reads `ANTHROPIC_API_KEY` from `process.env` only
- All evidence text passes through `redactSensitiveText()` before sending to client
- No auto-execution: config parse returns inventory; user must explicitly approve servers
- Run state stored in-memory `Map<string, RunState>`, no persistence

## Frontend Pages

### Dashboard
- Tool name + description
- Two action cards: "Inspect MCP Config" → /inspect, "Run Attack Tests" → /attack
- API key status indicator
- Link to report viewer

### Inspect Flow (/inspect)
1. **Config input**: file path, options (no-execute, read-resources, timeouts)
2. **Parse**: POST /api/config/parse → show server inventory
3. **Approve**: checkboxes per server, "Inspect Selected" / "Inspect All"
4. **Stream**: GET /api/runs/:runId/events → live findings
5. **Results**: findings grouped by severity, sortable, searchable

### Attack Flow (/attack)
1. **Config**: payload/category/severity filters, runs, models, no-baseline toggle
2. **API key check**: if missing, show message, disable start
3. **Stream**: GET /api/runs/:runId/events → live progress + findings
4. **Results**: findings with evidence, risk scores, reproduction commands

### Report Viewer (/reports)
- File picker (path input)
- Renders inspect or attack results
- Severity filter, search by rule/payload/server/tool
- Export JSON, export markdown summary

## Design

- Dark mode, monospace accents for code/evidence
- Severity colors: critical=red, high=orange, medium=blue/cyan, low=gray
- Cards + tables, minimal animations
- CSS variables for theming

## Integration Points

- `parseConfigFile()` from `src/configParser.ts`
- `runStaticRules()`, `detectCrossServerCollisions()` from `src/staticRules.ts`
- `inspectServer()` from `src/mcpClient.ts`
- `runScan()` from `src/scanner.ts`
- `redactSensitiveText()`, `toRedactedJson()` from `src/reporter.ts`
- `PAYLOADS` from `src/payloads.ts`
- All types from `src/types.ts`

## Run Command

```bash
npm run ui        # starts both backend (port 3457) and frontend dev server (port 5173)
npm run ui:build  # production build
npm run ui:serve  # serve production build
```
