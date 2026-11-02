#!/usr/bin/env bash
# Frontend linting and type-checking hook for ScanDeep Defender
# Runs npm run lint and npm run typecheck on the React frontend

set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"

cd "$PROJECT_ROOT"

echo "Running npm run lint..."
npm run lint 2>&1 | head -50

echo "Running npm run typecheck..."
npm run typecheck 2>&1 | head -50