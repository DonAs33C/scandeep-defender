#!/usr/bin/env bash
# Tauri Release Script for ScanDeep Defender
# Usage: ./release.sh [version]

set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
SRC_TAURI="$PROJECT_ROOT/src-tauri"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Get version from argument or Cargo.toml
VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    VERSION=$(grep '^version = ' "$SRC_TAURI/Cargo.toml" | sed 's/version = "\(.*\)"/\1/')
    log_info "Auto-detected version: $VERSION"
fi

# Validate version format
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    log_error "Invalid version format: $VERSION (expected X.Y.Z)"
    exit 1
fi

TAG="v$VERSION"

cd "$PROJECT_ROOT"

# 1. Check working tree clean
log_info "Checking git status..."
if [[ -n $(git status --porcelain) ]]; then
    log_error "Working tree not clean. Commit or stash changes first."
    git status --short
    exit 1
fi
log_success "Working tree clean"

# 2. Validate version consistency
log_info "Validating version consistency..."
CARGO_VERSION=$(grep '^version = ' "$SRC_TAURI/Cargo.toml" | sed 's/version = "\(.*\)"/\1/')
PACKAGE_VERSION=$(grep '"version"' package.json | sed 's/.*"version": "\(.*\)".*/\1/')
TAURI_VERSION=$(grep '"version"' "$SRC_TAURI/tauri.conf.json" | sed 's/.*"version": "\(.*\)".*/\1/')

if [[ "$CARGO_VERSION" != "$VERSION" ]]; then
    log_error "Cargo.toml version ($CARGO_VERSION) doesn't match $VERSION"
    exit 1
fi
if [[ "$PACKAGE_VERSION" != "$VERSION" ]]; then
    log_error "package.json version ($PACKAGE_VERSION) doesn't match $VERSION"
    exit 1
fi
if [[ "$TAURI_VERSION" != "$VERSION" ]]; then
    log_error "tauri.conf.json version ($TAURI_VERSION) doesn't match $VERSION"
    exit 1
fi
log_success "All versions match: $VERSION"

# 3. Run quality gates
log_info "Running Rust quality checks..."
cd "$SRC_TAURI"
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check
log_success "Rust checks passed"

log_info "Running Node quality checks..."
cd "$PROJECT_ROOT"
npm run lint
npm run typecheck
npm test
log_success "Node checks passed"

# 4. Build frontend
log_info "Building frontend..."
npm run build
log_success "Frontend built"

# 5. Build Tauri app (release)
log_info "Building Tauri release..."
cd "$SRC_TAURI"
cargo tauri build
log_success "Tauri build complete"

# 6. Verify artifacts
log_info "Verifying release artifacts..."
ARTIFACTS=(
    "target/release/bundle/nsis/ScanDeep Defender Setup.exe"
    "target/release/bundle/msi/ScanDeep Defender.msi"
    "target/release/bundle/nsis/ScanDeep Defender.zip"
)

for artifact in "${ARTIFACTS[@]}"; do
    if [[ -f "$artifact" ]]; then
        SIZE=$(du -h "$artifact" | cut -f1)
        log_success "Found: $artifact ($SIZE)"
    else
        log_warn "Missing: $artifact"
    fi
done

# 7. Create and push tag
log_info "Creating git tag $TAG..."
cd "$PROJECT_ROOT"
git tag -a "$TAG" -m "Release $TAG"
git push origin "$TAG"
log_success "Tag $TAG pushed"

# 8. Generate changelog
log_info "Generating changelog..."
PREV_TAG=$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || echo "")
if [[ -n "$PREV_TAG" ]]; then
    CHANGELOG=$(git log --pretty=format:"- %s (%an)" "$PREV_TAG..HEAD")
else
    CHANGELOG=$(git log --pretty=format:"- %s (%an)")
fi

cat > RELEASE_NOTES.md << EOF
# ScanDeep Defender $TAG

$CHANGELOG

## Assets
- \`ScanDeep Defender Setup.exe\` - NSIS Installer
- \`ScanDeep Defender.msi\` - Windows Installer (MSI)
- \`ScanDeep Defender.zip\` - Portable Version

## System Requirements
- Windows 10/11 (64-bit)
- WebView2 Runtime (auto-installed if missing)
- Internet connection for cloud scanning APIs
- Optional: ClamAV for local scanning

## Installation
1. Download the installer or portable ZIP
2. Run installer or extract ZIP
3. Launch ScanDeep Defender
4. Configure API keys in Settings tab
EOF

log_success "Changelog generated: RELEASE_NOTES.md"

# 9. Open GitHub release page (optional)
if command -v gh &> /dev/null; then
    log_info "Opening GitHub release page..."
    gh release view "$TAG" --web 2>/dev/null || gh release create "$TAG" --title "ScanDeep Defender $TAG" --notes-file RELEASE_NOTES.md --draft
else
    log_warn "GitHub CLI (gh) not found. Create release manually at: https://github.com/DonAs33/ScanDeep-Defender/releases/new?tag=$TAG"
fi

log_success "Release $TAG complete!"
echo ""
echo "Next steps:"
echo "1. Review the draft release on GitHub"
echo "2. Upload artifacts if not auto-uploaded by CI"
echo "3. Publish the release"