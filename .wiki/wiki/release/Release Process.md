---
type: reference
title: "Release Process"
created: 2025-01-15
updated: 2025-01-15
status: evergreen
tags:
  - release
  - deployment
  - ci-cd
  - tauri
  - windows
project: "ScanDeep Defender"
---

# ScanDeep Defender - Release Process

## Overview

ScanDeep Defender uses **GitHub Actions** for automated Windows builds and releases. The process is triggered by pushing a git tag matching `v*`.

## Release Workflow

### Trigger

```bash
git tag -a v2.1.0 -m "Release v2.1.0"
git push origin v2.1.0
```

This triggers `.github/workflows/build-windows.yml` on `windows-latest` runner.

### Build Process (GitHub Actions)

```yaml
# .github/workflows/build-windows.yml
jobs:
  build:
    runs-on: windows-latest
    steps:
      1. Checkout repository
      2. Setup Node.js (LTS)
      3. Install Rust stable (via dtolnay/rust-toolchain)
      4. Setup Rust cache (swatinem/rust-cache)
      5. npm install
      6. cargo update (in src-tauri)
      7. Tauri build (tauri-apps/tauri-action@v0)
         - tagName: ${{ github.ref_name }}
         - releaseName: "ScanDeep Defender ${{ github.ref_name }}"
         - releaseBody: "Automatic Release Windows"
      8. Upload artifacts:
         - NSIS installer (.exe)
         - MSI installer (.msi)
         - Portable ZIP (.zip)
```

### Artifacts Produced

| Artifact | Format | Use Case |
|----------|--------|----------|
| `ScanDeep Defender Setup.exe` | NSIS | Standard Windows installer with uninstaller |
| `ScanDeep Defender.msi` | MSI | Enterprise deployment, Group Policy |
| `ScanDeep Defender.zip` | ZIP | Portable, no installation required |

### Artifact Locations (after build)

```
src-tauri/target/release/bundle/
├── nsis/
│   ├── ScanDeep Defender Setup.exe
│   └── ScanDeep Defender.zip
└── msi/
    └── ScanDeep Defender.msi
```

## Local Release Process

### Using the tauri-release Skill

```bash
# Interactive (prompts for version)
/tauri-release

# Explicit version
/tauri-release 2.1.0
```

### What the Skill Does (`.claude/skills/tauri-release/release.sh`)

1. **Pre-flight Checks**
   - Git working tree clean
   - Version consistency across:
     - `src-tauri/Cargo.toml`
     - `package.json`
     - `src-tauri/tauri.conf.json`

2. **Quality Gates**
   ```bash
   # Rust
   cargo test --all-targets
   cargo clippy --all-targets -- -D warnings
   cargo fmt --all -- --check
   cargo deny check
   
   # Node
   npm run lint
   npm run typecheck
   npm test
   ```

3. **Build**
   ```bash
   npm run build          # Frontend → dist/
   cargo tauri build      # Tauri release build
   ```

4. **Verify Artifacts**
   - Checks all 3 artifact types exist
   - Reports file sizes

5. **Git Tag & Push**
   ```bash
   git tag -a v2.1.0 -m "Release v2.1.0"
   git push origin v2.1.0
   ```

6. **Changelog Generation**
   - From conventional commits since last tag
   - Outputs `RELEASE_NOTES.md`

7. **GitHub Release**
   - Opens draft release via `gh release create`
   - Or opens browser to manual release page

## Version Management

### Version Sources (must match)

| File | Field | Example |
|------|-------|---------|
| `src-tauri/Cargo.toml` | `version` | `2.1.0` |
| `package.json` | `version` | `2.1.0` |
| `src-tauri/tauri.conf.json` | `version` | `2.1.0` |

### Semantic Versioning

- **MAJOR**: Breaking changes (API, config format, data schema)
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, security patches

### Conventional Commits (for changelog)

```
feat: add Hybrid Analysis scanner
fix: handle missing keyring on first run
docs: update Settings UI labels
chore: update dependencies
ci: add cargo-deny to workflow
```

---

## Pre-Release Checklist

### Code Quality

- [ ] All CI checks pass (Rust + Node)
- [ ] `cargo deny check` passes (no high/critical vulnerabilities)
- [ ] `npm run test` passes (frontend tests)
- [ ] `cargo test --all-targets` passes (backend tests)
- [ ] No `unwrap()`/`expect()` in production code paths

### Functionality

- [ ] Manual test: Fresh install via NSIS
- [ ] Manual test: MSI install (admin + non-admin)
- [ ] Manual test: Portable ZIP extraction + run
- [ ] Scan with all 5 providers (VT, MD, HA, CM, ClamAV)
- [ ] Settings persist across restarts
- [ ] Quarantine/restore works
- [ ] History displays correctly
- [ ] Auto-scan watcher starts/stops
- [ ] WebView2 detection works

### Security

- [ ] No API keys in code, logs, or artifacts
- [ ] CSP header configured in `tauri.conf.json`
- [ ] Capabilities reviewed for least privilege
- [ ] `cargo audit` / `cargo deny check advisories` clean

### Documentation

- [ ] Changelog updated (`RELEASE_NOTES.md`)
- [ ] README.md version badges updated (if any)
- [ ] `.wiki/inbox/` docs reflect new features

---

## Release Day Steps

### 1. Final Verification (Local)

```bash
cd "D:/ClaudeCode/Projects/ScanDeep Defender"
/tauri-release 2.1.0
# Review RELEASE_NOTES.md
# Verify artifacts in src-tauri/target/release/bundle/
```

### 2. Create GitHub Release

The skill opens a draft release. Review and:
1. Edit release notes if needed
2. Verify all 3 artifacts uploaded
3. **Uncheck "This is a pre-release"** (unless beta)
4. Click "Publish release"

### 3. Post-Release Verification

- [ ] Release appears at: `https://github.com/DonAs33/ScanDeep-Defender/releases/tag/v2.1.0`
- [ ] All 3 assets downloadable
- [ ] Installer runs on clean Windows VM
- [ ] Portable version runs without install
- [ ] Auto-update check works (if implemented)

### 4. Announce

- GitHub Discussions / Release notes
- Update any external documentation

---

## Rollback Procedure

If critical issue found post-release:

### Option 1: Patch Release (Preferred)

```bash
# Fix issue
git commit -m "fix: critical bug in quarantine restore"

/tauri-release 2.1.1
```

### Option 2: Delete Release (If unpushed)

```bash
# Local only
git tag -d v2.1.0
```

### Option 3: Delete GitHub Release (If pushed)

```bash
gh release delete v2.1.0 --yes
git push origin --delete v2.1.0
# Then fix and re-release
```

---

## Troubleshooting

### Build Fails on GitHub Actions

| Error | Cause | Fix |
|-------|-------|-----|
| `cargo: command not found` | Rust not installed | Check `dtolnay/rust-toolchain` step |
| `npm: command not found` | Node not installed | Check `actions/setup-node` step |
| `tauri build failed` | Compilation error | Check logs, fix locally first |
| `Artifact not found` | Bundle config wrong | Check `tauri.conf.json` bundle targets |
| `Permission denied` | Windows AV blocking | Add exclusions, retry |

### Version Mismatch

```bash
# Check all versions
grep version src-tauri/Cargo.toml package.json src-tauri/tauri.conf.json

# Fix by updating all three to match
```

### Artifacts Not Uploaded

- Check `tauri-apps/tauri-action` version
- Verify `bundle.targets = "all"` in `tauri.conf.json`
- Check GitHub Actions logs for upload step

---

## Automation Integration

### tauri-release Skill

**File:** `.claude/skills/tauri-release/release.sh`

Automates steps 1-7 above. Run locally before pushing tag.

### GitHub Actions

**Files:**
- `.github/workflows/ci.yml` - PR validation
- `.github/workflows/build-windows.yml` - Release build

### cargo-deny

**File:** `deny.toml`

Blocks releases with:
- High/critical vulnerabilities
- Prohibited licenses (GPL, AGPL, SSPL)
- Yanked dependencies

---

## Future Enhancements

- [ ] **Auto-update**: Tauri updater integration
- [ ] **Code signing**: EV certificate for installer trust
- [ ] **Chocolatey/Scoop**: Package manager publishing
- [ ] **MSIX**: Modern Windows packaging
- [ ] **Staged rollouts**: Percentage-based release
- [ ] **SBOM**: Software Bill of Materials generation

---

## References

- [Tauri Distribution Guide](https://tauri.app/v2/guides/distribution/)
- [GitHub Actions for Tauri](https://tauri.app/v2/guides/ci-cd/github-actions/)
- [NSIS Installer](https://nsis.sourceforge.io/)
- [Windows MSI](https://learn.microsoft.com/en-us/windows/win32/msi/windows-installer-portal)
- [Semantic Versioning](https://semver.org/)
- [Conventional Commits](https://www.conventionalcommits.org/)