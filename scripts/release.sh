#!/usr/bin/env bash
#
# scripts/release.sh — Mechanical release pipeline for substrate-guard
#
# Supports Discipline 3 from SUBSTRATE_GUARD_ROADMAP: all releases go
# through this script. Manual `git tag` forbidden.
#
# Usage: ./scripts/release.sh vX.Y.Z
#
# What it does:
#   1. Validates version format (semver)
#   2. Checks working tree clean
#   3. Checks we're on main branch
#   4. Checks version matches pyproject.toml + __init__.py (enforces Discipline = version sync)
#   5. Verifies docs/releases/vX.Y.Z.md exists
#   6. Runs tests (pytest) — must pass
#   7. Runs version sync test
#   8. Creates annotated tag
#   9. Pushes commits + tag
#  10. Prompts for GitHub Release creation (optional)
#
# Exit codes:
#   0 success
#   1 usage error
#   2 validation error (tree dirty, version mismatch, etc.)
#   3 test failure
#   4 git operation failure

set -euo pipefail

# -----------------------------------------------------------------------------
# Setup
# -----------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Colors for output (if tty)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------

if [ $# -ne 1 ]; then
    log_error "Usage: $0 vX.Y.Z"
    log_error "Example: $0 v13.2.16"
    exit 1
fi

TAG="$1"

# Validate semver format: vN.N.N (optionally vN.N.N-suffix)
if ! [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
    log_error "Invalid version format: $TAG"
    log_error "Expected: vMAJOR.MINOR.PATCH (e.g., v13.2.16)"
    exit 1
fi

# Extract version without 'v' prefix for pyproject/init checks
VERSION="${TAG#v}"

log_info "Releasing $TAG (version $VERSION)"

# -----------------------------------------------------------------------------
# Step 1: Validate working tree
# -----------------------------------------------------------------------------

log_info "Step 1/8: Checking working tree..."

if ! git diff --quiet HEAD; then
    log_error "Working tree has uncommitted changes"
    git status --short
    exit 2
fi

if ! git diff --cached --quiet; then
    log_error "Working tree has staged but uncommitted changes"
    git status --short
    exit 2
fi

log_ok "Working tree clean"

# -----------------------------------------------------------------------------
# Step 2: Validate branch
# -----------------------------------------------------------------------------

log_info "Step 2/8: Checking branch..."

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"

if [ "$CURRENT_BRANCH" != "main" ]; then
    log_error "Not on main branch (current: $CURRENT_BRANCH)"
    log_error "Release must be cut from main"
    exit 2
fi

log_ok "On main branch"

# -----------------------------------------------------------------------------
# Step 3: Check tag doesn't already exist
# -----------------------------------------------------------------------------

log_info "Step 3/8: Checking tag availability..."

if git rev-parse "$TAG" >/dev/null 2>&1; then
    log_error "Tag $TAG already exists"
    exit 2
fi

# Also check remote
git fetch origin --tags --quiet 2>/dev/null || true
if git rev-parse "origin/$TAG" >/dev/null 2>&1 || \
   git ls-remote --tags origin "$TAG" | grep -q "$TAG"; then
    log_error "Tag $TAG already exists on origin"
    exit 2
fi

log_ok "Tag $TAG available"

# -----------------------------------------------------------------------------
# Step 4: Verify version in pyproject.toml
# -----------------------------------------------------------------------------

log_info "Step 4/8: Checking pyproject.toml version..."

PYPROJECT_VERSION="$(grep -E '^version = ' pyproject.toml | head -1 | sed -E 's/version = "(.*)"/\1/')"

if [ -z "$PYPROJECT_VERSION" ]; then
    log_error "Could not extract version from pyproject.toml"
    exit 2
fi

if [ "$PYPROJECT_VERSION" != "$VERSION" ]; then
    log_error "Version mismatch:"
    log_error "  pyproject.toml: $PYPROJECT_VERSION"
    log_error "  requested tag:  $VERSION"
    log_error "Bump pyproject.toml first, commit, then retry."
    exit 2
fi

log_ok "pyproject.toml version: $PYPROJECT_VERSION"

# -----------------------------------------------------------------------------
# Step 5: Verify __version__ in substrate_guard/__init__.py
# -----------------------------------------------------------------------------

log_info "Step 5/8: Checking __init__.py __version__..."

INIT_VERSION="$(grep -E '^__version__ = ' substrate_guard/__init__.py | head -1 | sed -E 's/__version__ = "(.*)"/\1/')"

if [ -z "$INIT_VERSION" ]; then
    log_error "Could not extract __version__ from substrate_guard/__init__.py"
    exit 2
fi

if [ "$INIT_VERSION" != "$VERSION" ]; then
    log_error "Version mismatch:"
    log_error "  __init__.py:    $INIT_VERSION"
    log_error "  pyproject.toml: $PYPROJECT_VERSION"
    log_error "  requested tag:  $VERSION"
    log_error "Sync __version__ and commit first."
    exit 2
fi

log_ok "__init__.py __version__: $INIT_VERSION"

# -----------------------------------------------------------------------------
# Step 6: Verify release notes exist
# -----------------------------------------------------------------------------

log_info "Step 6/8: Checking release notes..."

RELEASE_NOTES="docs/releases/$TAG.md"

if [ ! -f "$RELEASE_NOTES" ]; then
    log_error "Release notes not found: $RELEASE_NOTES"
    log_error "Create release notes first, commit, then retry."
    exit 2
fi

if [ ! -s "$RELEASE_NOTES" ]; then
    log_error "Release notes file is empty: $RELEASE_NOTES"
    exit 2
fi

RELEASE_NOTES_LINES="$(wc -l < "$RELEASE_NOTES")"
if [ "$RELEASE_NOTES_LINES" -lt 5 ]; then
    log_warn "Release notes very short ($RELEASE_NOTES_LINES lines)"
    log_warn "Consider adding more detail"
fi

log_ok "Release notes: $RELEASE_NOTES ($RELEASE_NOTES_LINES lines)"

# -----------------------------------------------------------------------------
# Step 7: Run tests
# -----------------------------------------------------------------------------

log_info "Step 7/8: Running tests..."

if ! command -v pytest >/dev/null 2>&1; then
    log_warn "pytest not found in PATH — skipping test execution"
    log_warn "This is allowed but not recommended. Install with: pip install pytest"
    read -p "Continue without tests? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 3
    fi
else
    if ! pytest --quiet --tb=short 2>&1 | tail -20; then
        log_error "Tests failed"
        log_error "Fix tests before releasing"
        exit 3
    fi
    log_ok "All tests passed"
fi

# -----------------------------------------------------------------------------
# Step 8: Create tag and push
# -----------------------------------------------------------------------------

log_info "Step 8/8: Creating tag and pushing..."

# Show summary before final confirmation
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  RELEASE SUMMARY"
echo "════════════════════════════════════════════════════════════"
echo "  Tag:              $TAG"
echo "  Version:          $VERSION"
echo "  Branch:           $CURRENT_BRANCH"
echo "  Commit:           $(git rev-parse --short HEAD)"
echo "  Commit message:   $(git log -1 --format='%s')"
echo "  Release notes:    $RELEASE_NOTES"
echo "  Tests:            PASSED (or skipped)"
echo "════════════════════════════════════════════════════════════"
echo ""

read -p "Proceed with tag + push to origin? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_warn "Aborted by user — no tag created"
    exit 0
fi

# Create annotated tag with release notes content
log_info "Creating annotated tag..."
if ! git tag -a "$TAG" -F "$RELEASE_NOTES"; then
    log_error "Failed to create tag"
    exit 4
fi
log_ok "Tag $TAG created"

# Push commits
log_info "Pushing commits to origin/$CURRENT_BRANCH..."
if ! git push origin "$CURRENT_BRANCH"; then
    log_error "Failed to push branch"
    log_warn "Tag created locally but not pushed. Fix git issue and rerun:"
    log_warn "  git push origin $CURRENT_BRANCH"
    log_warn "  git push origin $TAG"
    exit 4
fi

# Push tag
log_info "Pushing tag to origin..."
if ! git push origin "$TAG"; then
    log_error "Failed to push tag"
    log_warn "Branch pushed but tag not. Fix git issue and rerun:"
    log_warn "  git push origin $TAG"
    exit 4
fi

log_ok "Tag $TAG pushed to origin"

# -----------------------------------------------------------------------------
# Optional: GitHub Release via gh CLI
# -----------------------------------------------------------------------------

if command -v gh >/dev/null 2>&1; then
    echo ""
    read -p "Create GitHub Release via gh CLI? [Y/n] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        if gh release create "$TAG" \
            --title "$TAG" \
            --notes-file "$RELEASE_NOTES"; then
            log_ok "GitHub Release created"
        else
            log_error "GitHub Release creation failed"
            log_warn "Create manually: https://github.com/octavuntila-prog/substrate-guard/releases/new?tag=$TAG"
        fi
    fi
else
    log_warn "gh CLI not found — create GitHub Release manually:"
    log_warn "  https://github.com/octavuntila-prog/substrate-guard/releases/new?tag=$TAG"
fi

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------

echo ""
echo "════════════════════════════════════════════════════════════"
log_ok "RELEASE $TAG COMPLETE"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo "  1. Verify on GitHub: https://github.com/octavuntila-prog/substrate-guard/releases/tag/$TAG"
echo "  2. Update production: ssh to servers and pull"
echo "  3. Announce if applicable"
echo ""
