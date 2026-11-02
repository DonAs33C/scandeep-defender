#!/usr/bin/env bash
# Stop hook for ScanDeep Defender
# Runs session-end security checks

set -euo pipefail

PROJECT_ROOT="D:/ClaudeCode/Projects/ScanDeep Defender"

cd "$PROJECT_ROOT"

echo "Running session-end security checks..."

# Check for uncommitted secrets in staged files
if git diff --cached --name-only | xargs grep -lE '(api[_-]?key|secret|password|token|key\s*=\s*["\'][a-zA-Z0-9+/]{20,})' 2>/dev/null; then
    echo "WARNING: Potential secrets found in staged files!" >&2
    git diff --cached --name-only | xargs grep -nE '(api[_-]?key|secret|password|token|key\s*=\s*["\'][a-zA-Z0-9+/]{20,})' 2>/dev/null || true
fi

# Check for console.log statements in staged TypeScript/TSX files
if git diff --cached --name-only -- '*.ts' '*.tsx' | xargs grep -n 'console\.(log|debug|info|warn|error)' 2>/dev/null; then
    echo "WARNING: console.* statements found in staged files!" >&2
fi

# Check for TODO/FIXME in security-critical files
if git diff --cached --name-only | grep -E '(security|crypto|auth|key)' | xargs grep -nE '(TODO|FIXME|XXX)' 2>/dev/null; then
    echo "WARNING: TODO/FIXME in security-related files!" >&2
fi

# Check for uncommitted package-lock.json changes (might indicate dependency changes)
if git diff --cached --name-only | grep -q 'package-lock.json'; then
    echo "INFO: package-lock.json is staged - verify dependency changes are intentional" >&2
fi

echo "Session-end checks complete."
exit 0