---
name: tauri-release
description: Build, package, and release ScanDeep Defender for Windows (NSIS installer, MSI, portable ZIP)
disable-model-invocation: true
---

# Tauri Release Skill

Automates the complete release process for ScanDeep Defender on Windows.

## Usage

```
/tauri-release [version]
```

If version omitted, reads from `src-tauri/Cargo.toml` and `package.json` (must match).

## What It Does

1. **Validates** version consistency across `Cargo.toml`, `package.json`, `tauri.conf.json`
2. **Runs pre-release checks**: `cargo test`, `cargo clippy`, `cargo deny check`, `npm test`, `npm run lint`, `npm run typecheck`
3. **Builds** frontend: `npm run build`
4. **Builds** Tauri app: `cargo tauri build` (release mode)
5. **Verifies artifacts**: NSIS `.exe`, MSI `.msi`, portable `.zip` exist in `src-tauri/target/release/bundle/`
6. **Creates git tag**: `v{version}` with annotated message
7. **Pushes tag** to trigger GitHub Actions release workflow (`.github/workflows/build-windows.yml`)
8. **Generates changelog** from conventional commits since last tag

## Prerequisites

- Rust toolchain (stable) with `cargo-tauri` CLI
- Node.js 20+ with npm
- GitHub CLI (`gh`) authenticated for release management
- Windows target (run on Windows or CI)

## Files Created/Modified

- `.claude/skills/tauri-release/release.sh` - Main release script
- `.claude/skills/tauri-release/changelog.md` - Template for changelog generation

## Implementation

The skill provides a `release.sh` script that:
1. Checks working tree is clean
2. Validates version consistency
3. Runs all quality gates
4. Builds release artifacts
5. Creates and pushes git tag
6. Opens GitHub release page for manual notes (or auto-generates)

## Example

```bash
# Release version 2.1.2
/tauri-release 2.1.2

# Or auto-detect from Cargo.toml
/tauri-release
```