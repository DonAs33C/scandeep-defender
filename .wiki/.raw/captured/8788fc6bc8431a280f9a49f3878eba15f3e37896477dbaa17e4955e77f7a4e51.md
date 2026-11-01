---
tags: [automation, claude-code, setup, hooks, mcp, skills, subagents]
created: 2025-01-15
project: ScanDeep Defender
---

# ScanDeep Defender - Automation Setup Guide

This document describes all Claude Code automations configured for this project.

## Overview

| Category | Tools | Purpose |
|----------|-------|---------|
| **MCP Servers** | context7, GitHub | Live docs lookup, GitHub integration |
| **Skills** | tauri-release, gen-tauri-command | Release automation, command scaffolding |
| **Hooks** | cargo-fmt-clippy-deny, lint-typecheck-test | Auto-quality gates on file edit |
| **Subagents** | security-reviewer, tauri-integration-reviewer | Specialized code review |
| **Plugins** | anthropic-agent-skills | Core productivity skills |
| **Documentation** | claude-obsidian wiki | Persistent knowledge base |

---

## 1. MCP Servers

### context7
Live documentation lookup for all project dependencies.

**Install:**
```bash
claude mcp add context7
```

**Usage:** When working with React, Tauri, rusqlite, reqwest, tokio, notify, keyring, or any crate - ask Claude to "look up the latest docs for X" and it will use context7.

### GitHub MCP
Direct GitHub operations from Claude.

**Install:**
```bash
claude mcp add github
# Requires: gh auth login
```

**Capabilities:**
- Create/manage issues and PRs
- View workflow runs and logs
- Manage releases
- Read/write repository files

---

## 2. Skills

Located in `.claude/skills/`

### tauri-release
Complete release automation for Windows builds.

**Invoke:** `/tauri-release [version]`

**What it does:**
1. Validates version consistency (Cargo.toml, package.json, tauri.conf.json)
2. Runs all quality gates (cargo test, clippy, fmt, deny + npm lint, typecheck, test)
3. Builds frontend + Tauri release artifacts
4. Creates git tag `v{version}`
5. Pushes tag to trigger GitHub Actions release workflow
6. Generates changelog from conventional commits

**Script:** `.claude/skills/tauri-release/release.sh`

### gen-tauri-command
Scaffold new Tauri commands with Rust + TypeScript boilerplate.

**Invoke:** `/gen-tauri-command <name> "<params>" "<return_type>"`

**Examples:**
```bash
/gen-tauri-command get_scan_status "scan_id: String" "ScanStatus"
/gen-tauri-command list_scans "limit: usize, offset: usize" "Vec<ScanRecord>"
```

**Generates:**
- Rust command in `src-tauri/src/commands/<domain>/`
- TypeScript types in `src/types/index.ts`
- Updates `main.rs` command registration (manual step)
- Frontend usage example

**Script:** `.claude/skills/gen-tauri-command/gen-tauri-command.sh`

---

## 3. Hooks

Configured in `.claude/settings.json`

### cargo-fmt-clippy-deny (Rust files)
**Trigger:** PostToolUse on Edit/Write/MultiEdit for `*.rs` files

**Runs:**
```bash
cd src-tauri && cargo fmt --all && cargo clippy --all-targets -- -D warnings
```

**Catches:** Formatting issues, clippy warnings (treated as errors), common bugs

### lint-typecheck-test (TypeScript/React files)
**Trigger:** PostToolUse on Edit/Write/MultiEdit for `*.ts`, `*.tsx` files

**Runs:**
```bash
npm run lint && npm run typecheck
```

**Catches:** ESLint errors, TypeScript type errors

**Note:** `npm test` intentionally excluded from hook (too slow) - run manually or in CI.

---

## 4. Subagents

Located in `.claude/agents/`

### security-reviewer
Specialized security auditor for desktop security applications.

**Focus Areas:**
- API key/secret management (keyring usage)
- File system & path security (traversal, quarantine isolation)
- Command injection (ClamAV execution)
- Network/API security (HTTPS, cert validation, rate limiting)
- Supply chain (cargo-deny policies)
- Tauri-specific (CSP, IPC validation, capabilities)

**Invoke:** Ask Claude to "run security review on <file/feature>"

### tauri-integration-reviewer
Specialized reviewer for Rust↔TypeScript boundary.

**Focus Areas:**
- Command signature matching (snake_case ↔ camelCase)
- Serde serialization compatibility
- State management (tauri::State, Arc<AppState>)
- AppHandle event emission
- Async command patterns
- Frontend invoke patterns

**Command Inventory:** 15 commands across scan, settings, history, quarantine domains

**Invoke:** Ask Claude to "review Tauri integration for <command/feature>"

---

## 5. Plugins

### anthropic-agent-skills
Core productivity skills bundle.

**Install:**
```bash
# Available via plugin marketplace
# Or: claude plugin install anthropic-agent-skills
```

**Includes:**
- `commit` - Conventional commit messages
- `pr-check` - PR description from changes
- `feature-dev` - Feature planning workflow
- `code-review` - Code review checklist
- `writing-rules` - Automation rule creation

---

## 6. Documentation (claude-obsidian)

**Location:** `.wiki/inbox/` (auto-ingested by Obsidian)

**Files:**
1. `01-project-architecture.md` - Complete architecture overview
2. `02-automation-setup.md` - This file
3. `03-security-considerations.md` - Security deep-dive
4. `04-tauri-command-patterns.md` - Command patterns & best practices
5. `05-release-process.md` - Release workflow details

**Obsidian Setup:**
1. Open Obsidian
2. "Open folder as vault" → Select `.wiki` folder
3. Enable "Community plugins" → Install "Canvas", "Dataview" if needed
4. Files in `inbox/` appear in file explorer for linking

---

## Quick Reference Commands

```bash
# Run all quality checks manually
cd src-tauri && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --all -- --check && cargo deny check
cd .. && npm run lint && npm run typecheck && npm test

# Build for development
npm run tauri:dev

# Build for production
npm run tauri:build

# Generate new Tauri command
/gen-tauri-command my_command "param: String" "MyReturnType"

# Create release
/tauri-release 2.1.0

# Security review
# Ask: "run security review on the quarantine feature"

# Tauri integration review
# Ask: "review Tauri integration for scan_file command"
```

---

## Troubleshooting

### Hooks not running
1. Check `.claude/settings.json` exists and is valid JSON
2. Restart Claude Code
3. Verify working directory matches project root

### MCP servers not connecting
1. Run `claude mcp list` to see status
2. For GitHub: ensure `gh auth status` shows authenticated
3. Check firewall/antivirus not blocking local connections

### Skill not found
1. Ensure `.claude/skills/<name>/SKILL.md` exists
2. Check `disable-model-invocation: true` for user-only skills
3. Restart Claude Code to reload skills

### Subagent not invoked
1. Check `.claude/agents/<name>.md` exists
2. Use explicit invocation: "use the security-reviewer agent to..."
3. Verify model compatibility (sonnet specified)