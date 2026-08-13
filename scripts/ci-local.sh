#!/bin/bash
#
# Run this repo's CI locally, in CI's order, on CI's Node version.
#
# ## Why this exists
#
# CLAUDE.md states the order in prose, so everyone retypes it by hand and the
# list drifts from the workflows. It had already drifted: the documented order
# omitted `check:bundle-size`, so following it exercised everything except the
# tripwire guarding the one rule this repo cares most about.
#
# The Node check is the other half, and it is the reason this is a script rather
# than a doc. `nvm use 22` fails silently when NVM_DIR is not exported: it prints
# nothing, returns non-zero into a discarded status, and leaves you on whatever
# Node you already had. A whole session's worth of gates then ran on Node 25 and
# reported green. That is not a harmless mismatch here, because
# coverage-baseline.json was regenerated under 22 and V8 branch instrumentation
# differs between majors, so a ratchet result from another major is not evidence.
# This script refuses to run on the wrong major rather than proceeding quietly.
#
# Not a gate, and deliberately not registered in package.json `gateSelfTest`.
# It runs the gates; it does not add a rule of its own. CI remains the authority
# on what must pass, and .github/workflows/ci.yml is the source of truth for the
# order this mirrors.
#
# Usage:  ./scripts/ci-local.sh
#         COVERAGE_BASE_REF=origin/some-branch ./scripts/ci-local.sh

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

STEP_LOG="$(mktemp -t attestto-ci-local)"
trap 'rm -f "$STEP_LOG"' EXIT

# ── Node version ────────────────────────────────────────────────────
# .nvmrc is what both ci.yml and pages.yml resolve through node-version-file,
# so it is the version to match, and the only one whose coverage numbers line
# up with the committed baseline.

WANT="$(tr -dc '0-9.' < .nvmrc)"
WANT_MAJOR="${WANT%%.*}"

if [ -s "${NVM_DIR:-$HOME/.nvm}/nvm.sh" ]; then
  export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
  # shellcheck disable=SC1091
  . "$NVM_DIR/nvm.sh" >/dev/null 2>&1
  nvm use "$WANT_MAJOR" >/dev/null 2>&1
fi

HAVE_MAJOR="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null)"

if [ "$HAVE_MAJOR" != "$WANT_MAJOR" ]; then
  echo "REFUSING TO RUN: .nvmrc wants Node $WANT_MAJOR, this shell has ${HAVE_MAJOR:-none}."
  echo
  echo "  Coverage numbers are not comparable across Node majors: the committed"
  echo "  coverage-baseline.json was generated under $WANT_MAJOR, and V8 branch"
  echo "  instrumentation differs between versions. A green ratchet on the wrong"
  echo "  major is not evidence, which is exactly why this stops instead of warning."
  echo
  echo "  Fix:  nvm install $WANT_MAJOR && nvm use $WANT_MAJOR"
  exit 9
fi

echo "node $(node -v)   pnpm $(pnpm -v)   HEAD $(git rev-parse --short HEAD)"
echo

# ── Step runner ─────────────────────────────────────────────────────
# Exit codes are never swallowed. The first failure stops the run and prints the
# tail of that step's output, because a later step failing for an earlier step's
# reason is how a real cause gets buried.

step() {
  local name="$1"; shift
  if "$@" > "$STEP_LOG" 2>&1; then
    echo "  PASS  $name"
  else
    local rc=$?
    echo "  FAIL  $name (exit $rc)"
    echo
    tail -40 "$STEP_LOG" | sed 's/^/    | /'
    exit "$rc"
  fi
}

# ── The pipeline, in CI's order ─────────────────────────────────────
# Mirrors .github/workflows/ci.yml, plus the two gates that live in other
# workflows: the changelog gate (changelog.yml) and the tarball check.

step "1.  changelog gate"        node scripts/ci-changelog.mjs
step "2.  install --frozen"      pnpm install --frozen-lockfile
step "3.  gate-self-test"        pnpm gate-self-test
step "4.  lint"                  pnpm run lint
step "5.  test"                  pnpm test

# NO-DROP resolves a merge-base against this ref to prove the committed baseline
# was not lowered in the same commit that dropped coverage.
export COVERAGE_BASE_REF="${COVERAGE_BASE_REF:-origin/main}"
step "6.  coverage ratchet"      pnpm run coverage:check

step "7.  build"                 pnpm run build
step "8.  bundle-size tripwire"  pnpm run check:bundle-size

# ── 9. the publishable tarball ──────────────────────────────────────
# `pack`, NOT `publish --dry-run`: the latter also checks the registry and fails
# for any version already released, which is the normal state of main.
#
# Packing into /private/tmp rather than /tmp: on macOS /tmp is a symlink to
# /private/tmp, `find /tmp -maxdepth 1` does not resolve it, and the check then
# reports a missing main entry for a tarball that is perfectly fine.

PACK_DIR="$(cd /private/tmp 2>/dev/null && pwd || echo /tmp)"
PKG_NAME="$(node -p "require('./package.json').name.replace('@','').replace('/','-')")"
rm -f "$PACK_DIR/$PKG_NAME"-*.tgz
if pnpm pack --pack-destination "$PACK_DIR" >"$STEP_LOG" 2>&1; then
  TARBALL="$(find "$PACK_DIR" -maxdepth 1 -name "$PKG_NAME-*.tgz" | head -1)"
  MAIN="$(node -p "require('./package.json').main")"
  if [ -n "$TARBALL" ] && tar -tzf "$TARBALL" | grep -q "^package/$MAIN$"; then
    echo "  PASS  9.  tarball contains $MAIN"
  else
    echo "  FAIL  9.  tarball does not contain $MAIN, the package main entry"
    [ -n "$TARBALL" ] && tar -tzf "$TARBALL" | head -20 | sed 's/^/    | /'
    exit 1
  fi
  rm -f "$TARBALL"
else
  echo "  FAIL  9.  pnpm pack"
  tail -40 "$STEP_LOG" | sed 's/^/    | /'
  exit 1
fi

# ── 10. does it still merge ─────────────────────────────────────────
# Catches a stale branch before GitHub does. merge-tree exits 0 on a conflict it
# was able to represent, so the exit code is not the signal; the CONFLICT line is.

BASE_REF="${COVERAGE_BASE_REF:-origin/main}"
git fetch -q origin "${BASE_REF#origin/}" 2>/dev/null
if git merge-tree --write-tree "$BASE_REF" HEAD 2>&1 | grep -q '^CONFLICT'; then
  echo "  FAIL  10. conflicts with $BASE_REF"
  git merge-tree --write-tree "$BASE_REF" HEAD 2>&1 | grep '^CONFLICT' | sed 's/^/    | /'
  echo "    | rebase onto $BASE_REF before pushing"
  exit 1
fi
echo "  PASS  10. merges cleanly into $BASE_REF"

echo
echo "ALL STEPS PASSED under $(node -v)"
