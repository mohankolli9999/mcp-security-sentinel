# CLAUDE.md

Project-specific instructions for MCP Security Sentinel.

## Project Overview

MCP Security Sentinel is a security analysis CLI for the Model Context Protocol. It scans MCP server configurations and live servers for vulnerabilities using static rules, and optionally red-teams AI agents with prompt-injection payloads. It also includes a local web UI and supports SARIF 2.1.0 output.

## Repository Structure

```
src/            — Core CLI: scanner, inspector, MCP client, static rules, SARIF export, reporter
tests/          — Vitest test suite (one .test.ts per src module)
server/         — Express backend for the web UI (SSE streaming, run manager)
ui/             — React + Vite frontend (dashboard, inspect, attack, reports pages)
dist/           — Build output (gitignored)
```

Key source files:
- `src/index.ts` — CLI entrypoint (inspect / attack commands)
- `src/staticRules.ts` — Static security rules engine
- `src/scanner.ts` — Dynamic attack scanner
- `src/inspect.ts` — Live MCP server inspection
- `src/sarif.ts` — SARIF 2.1.0 export
- `src/reporter.ts` — Console/JSON report output
- `server/uiServer.ts` — Web UI API server (localhost-only, DNS rebinding protection)

## Commands

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Build for distribution
npm run build

# Run inspect mode
npx tsx src/index.ts inspect --config <path> --no-execute

# Run attack mode
npx tsx src/index.ts attack

# Start web UI (dev)
npm run ui

# Build web UI for production
npm run ui:build
```

## Tech Stack

- **Runtime:** Node.js ≥ 20, TypeScript (ESM)
- **Test framework:** Vitest
- **Frontend:** React + Vite
- **Backend:** Express 5
- **Key deps:** @anthropic-ai/sdk, @modelcontextprotocol/sdk, Zod, Chalk

## Coding Guidelines

**Simplicity first.** Minimum code that solves the problem. No speculative features, abstractions for single-use code, or error handling for impossible scenarios.

**Surgical changes.** Touch only what you must. Match existing style. Don't "improve" adjacent code. Remove imports/variables that YOUR changes made unused — don't remove pre-existing dead code unless asked.

**Goal-driven execution.** Transform tasks into verifiable goals. Write tests first when adding features or fixing bugs. Ensure `npm test` passes before and after changes.

**Think before coding.** State assumptions explicitly. If multiple interpretations exist, present them. Push back when a simpler approach exists.
