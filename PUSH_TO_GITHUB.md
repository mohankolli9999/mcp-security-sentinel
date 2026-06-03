# Push MCP Security Sentinel to GitHub

## What This Is

A fully implemented TypeScript CLI project called **mcp-security-sentinel** sitting at:

```
/Users/kollisai/Documents/Projects/mcpsentinel
```

It has 15 commits, 49 passing tests, and is ready to publish. It just needs to be pushed to GitHub.

---

## The Problem

- `gh` CLI is not installed (brew install gh is stuck downloading)
- SSH is not configured for GitHub (`Permission denied (publickey)`)
- Git is initialized and all commits are done — only the remote push is missing

---

## What Needs To Happen

### Step 1 — Create the GitHub repo

Go to: **https://github.com/new**

Fill in:
- **Repository name:** `mcp-security-sentinel`
- **Description:** `CLI red-team harness for MCP prompt injection testing — victim+judge Claude pattern, 17 payloads, OWASP LLM Top 10 + SlowMist mapping`
- **Visibility:** Public
- **Do NOT** initialize with README, .gitignore, or license (repo already has these)

Click **Create repository**.

---

### Step 2 — Generate a GitHub Personal Access Token

Go to: **https://github.com/settings/tokens/new**

- **Note:** `mcp-sentinel-push`
- **Expiration:** 7 days
- **Scope:** check `repo` (full control of private repositories)

Click **Generate token** and copy it.

---

### Step 3 — Push from terminal

Open Terminal, `cd` into the project directory, then run:

```bash
cd /Users/kollisai/Documents/Projects/mcpsentinel

git remote add origin https://github.com/mohankolli9999/mcp-security-sentinel.git

git push -u origin main
```

When prompted:
- **Username:** `mohankolli9999`
- **Password:** paste the personal access token from Step 2 (not your GitHub password)

---

## What Gets Pushed

| File | Purpose |
|------|---------|
| `src/types.ts` | All TypeScript interfaces |
| `src/payloads.ts` | 17 injection payloads (OWASP LLM Top 10 + SlowMist) |
| `src/mockServer.ts` | Fake MCP server that injects payloads into tool responses |
| `src/oracles.ts` | Deterministic detection: markers, forbidden tool calls, arg patterns, response patterns |
| `src/scanner.ts` | Scan engine: baseline caching, oracle-first detection, LLM judge fallback |
| `src/reporter.ts` | Terminal (chalk) + JSON file output |
| `src/index.ts` | CLI entrypoint with argument parsing |
| `tests/` | 49 unit tests across 6 test files |
| `README.md` | Full usage docs, payload table, framework mapping |

---

## Verification After Push

Once pushed, confirm at:

```
https://github.com/mohankolli9999/mcp-security-sentinel
```

The repo should show 15 commits and a README.
