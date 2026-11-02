#!/usr/bin/env bash
# Rust formatting and linting hook for ScanDeep Defender
# Runs cargo fmt and cargo clippy on the Tauri backend

set -euo pipefail

PROJECT_ROOT="D:/ClaudeCode/Projects/ScanDeep Defender"
TAURI_DIR="$PROJECT_ROOT/src-tauri"

cd "$TAURI_DIR"

echo "Running cargo fmt --all..."
cargo fmt --all

echo "Running cargo clippy --all-targets -- -D warnings..."
cargo clippy --all-targets -- -D warnings 2>&1 | head -50