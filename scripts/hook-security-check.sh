#!/usr/bin/env bash
# PreToolUse security hook for ScanDeep Defender
# Blocks dangerous shell commands before execution

set -euo pipefail

# Read the tool input from stdin
TOOL_INPUT=$(cat)

# Extract command if this is a Bash tool call
if echo "$TOOL_INPUT" | grep -q '"name": "Bash"'; then
    COMMAND=$(echo "$TOOL_INPUT" | grep -o '"command": "[^"]*"' | head -1 | cut -d'"' -f4)

    # Block dangerous patterns
    if echo "$COMMAND" | grep -qE '(rm -rf\s+/|rm -rf\s+\*|sudo\s+|chmod\s+777|dd\s+if=|mkfs|fdisk|:(){ :|:&};:|fork\s*bomb)'; then
        echo "BLOCKED: Dangerous command detected: $COMMAND" >&2
        exit 1
    fi

    # Block writing to sensitive locations
    if echo "$COMMAND" | grep -qE '(>\s*/etc/|>\s*/boot/|>\s*/sys/|>\s*/proc/)'; then
        echo "BLOCKED: Attempt to write to system directory" >&2
        exit 1
    fi
fi

# Allow the tool call
exit 0