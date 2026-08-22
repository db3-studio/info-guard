#!/usr/bin/env bash
# Info Guard installer — the redaction layer for Hermes Agent.
#
#   ./install.sh [--checkout DIR] [--force] [--no-config] [--no-test]
#
# What it does:
#   1. Locates the Hermes Agent checkout (git install).
#   2. Applies the registry-fed redaction patch (idempotent, marker-guarded;
#      ACTIVE + artifact mismatch = replaces the stale applied patch in
#      place; fails loudly instead of silently if the codebase has drifted).
#   3. Creates <home>/state/info-guard/ and seeds redact_patterns.json +
#      custom_literals.json (never overwrites existing files).
#   4. Points Hermes at the pattern file (security.redact_patterns config;
#      the code default already matches, so this is belt-and-braces).
#   5. Runs test.sh — the end-to-end verification battery.
#
# Exit codes: 0 = installed & verified, 1 = something failed.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH="$HERE/patch/redactor-registry-patterns.patch"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
STATE_DIR="$HERMES_HOME/state/info-guard"
PATTERNS_FILE="$STATE_DIR/redact_patterns.json"
CHECKOUT=""
FORCE=0
NO_CONFIG=0
NO_TEST=0

while [ $# -gt 0 ]; do
    case "$1" in
        --checkout) CHECKOUT="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        --no-config) NO_CONFIG=1; shift ;;
        --no-test) NO_TEST=1; shift ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

say() { printf '\033[1;34m[info-guard]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[info-guard]\033[0m %s\n' "$*" >&2; exit 1; }

# ── 1. locate checkout ──────────────────────────────────────────────────
if [ -z "$CHECKOUT" ]; then
    if [ -f "$HERMES_HOME/hermes-agent/agent/redact.py" ]; then
        CHECKOUT="$HERMES_HOME/hermes-agent"
    elif command -v hermes >/dev/null 2>&1; then
        CHECKOUT="$(hermes --version 2>/dev/null | sed -n 's/^Install directory: //p')"
    fi
fi
[ -n "$CHECKOUT" ] && [ -f "$CHECKOUT/agent/redact.py" ] \
    || die "could not find the Hermes Agent checkout — pass --checkout DIR"

say "checkout: $CHECKOUT"
if command -v hermes >/dev/null 2>&1; then
    say "hermes:   $(hermes --version 2>/dev/null | head -1 || echo unknown)"
fi

# ── 2. engine integrity (5 markers, external-audit B2/F5) ───────────────
# All present = ACTIVE; some = PARTIAL (half-reverted update); none = MISSING.
# ACTIVE + artifact mismatch = a stale applied patch (updated the package
# without re-running install.sh, or vice versa) — replaced in place.
_marker_count() {
    local n=0
    grep -q "_redact_registry_patterns" "$CHECKOUT/agent/redact.py" 2>/dev/null && n=$((n+1))
    grep -q "redact_patterns"            "$CHECKOUT/hermes_cli/config.py" 2>/dev/null && n=$((n+1))
    grep -q "HERMES_REDACT_PATTERNS"     "$CHECKOUT/hermes_cli/main.py" 2>/dev/null && n=$((n+1))
    grep -q "HERMES_REDACT_PATTERNS"     "$CHECKOUT/cli.py" 2>/dev/null && n=$((n+1))
    grep -q "HERMES_REDACT_PATTERNS"     "$CHECKOUT/gateway/run.py" 2>/dev/null && n=$((n+1))
    echo "$n"
}
MARKERS=$(_marker_count)
if [ "$MARKERS" = "5" ]; then
    if [ "$FORCE" = "1" ] || ! git -C "$CHECKOUT" apply --reverse --check "$PATCH" 2>/dev/null; then
        say "engine ACTIVE (5/5 markers) but the applied patch differs from this package's artifact — replacing it in place"
        git -C "$CHECKOUT" checkout -- agent/redact.py cli.py gateway/run.py hermes_cli/config.py hermes_cli/main.py \
            || die "could not reset the 5 patched files — resolve working-tree changes in $CHECKOUT, then re-run install.sh"
        git -C "$CHECKOUT" apply --check "$PATCH" \
            || die "patch no longer applies — the codebase has drifted (hermes update?). Rebase the patch against the current checkout, or use the upstream PR once merged."
        git -C "$CHECKOUT" apply "$PATCH"
        git -C "$CHECKOUT" apply --reverse --check "$PATCH" \
            || die "verification failed after replacing the patch — unexpected state in $CHECKOUT"
        say "patch replaced — checkout now matches this package's artifact"
    else
        say "engine ACTIVE (5/5 markers) — patch applied and matches this package's artifact"
    fi
elif [ "$MARKERS" != "0" ]; then
    die "engine PARTIAL ($MARKERS/5 markers) — a failed hermes update likely half-reverted the patch.
     Restore the patched files first, then re-run install.sh:
       git -C $CHECKOUT checkout -- agent/redact.py cli.py gateway/run.py hermes_cli/config.py hermes_cli/main.py"
elif [ "$FORCE" = "1" ]; then
    say "re-applying patch (--force)"
    git -C "$CHECKOUT" apply --check "$PATCH" \
        || die "patch no longer applies — the codebase has drifted (hermes update?). Rebase the patch against the current checkout, or use the upstream PR once merged."
    git -C "$CHECKOUT" apply "$PATCH"
    say "patch applied"
else
    git -C "$CHECKOUT" apply --check "$PATCH" \
        || die "patch does not apply — the codebase has drifted (hermes update?). Rebase the patch against the current checkout, or use the upstream PR once merged."
    git -C "$CHECKOUT" apply "$PATCH"
    say "patch applied"
fi

# ── 3. state dir + seed files (never clobber) ───────────────────────────
mkdir -p "$STATE_DIR"
if [ ! -f "$PATTERNS_FILE" ]; then
    cat > "$PATTERNS_FILE" <<'EOF'
{
  "mask": {"head": 2, "tail": 2, "floor": 12},
  "literals": [],
  "key_patterns": {},
  "generated": "seed — run `info-guard build` to populate from your .env files"
}
EOF
    chmod 600 "$PATTERNS_FILE"
    say "seeded $PATTERNS_FILE (run \`info-guard build\` to populate)"
else
    say "pattern file exists — left untouched"
fi
if [ ! -f "$STATE_DIR/custom_literals.json" ]; then
    echo '{"literals": []}' > "$STATE_DIR/custom_literals.json"
    chmod 600 "$STATE_DIR/custom_literals.json"
    say "seeded $STATE_DIR/custom_literals.json (edit it, then \`info-guard build\`)"
fi
# Install manifest: records WHICH package version installed the engine —
# the preflight report header and `check` show it. Rewritten on every
# install so re-installs update the recorded version.
# Portable version extraction (S3): `grep -oP` is GNU-only — BSD grep
# (macOS) would silently fall through to "unknown". awk is POSIX.
IG_VERSION="$(awk -F'"' '/_PACKAGE_VERSION = /{print $2; exit}' "$HERE/bin/info-guard")"
[ -n "$IG_VERSION" ] || IG_VERSION=unknown
cat > "$STATE_DIR/install.json" <<EOF
{"version": "$IG_VERSION", "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
EOF
chmod 600 "$STATE_DIR/install.json"
say "wrote $STATE_DIR/install.json (manifest: v$IG_VERSION)"

# ── 4. point Hermes at the pattern file ─────────────────────────────────
if [ "$NO_CONFIG" = "1" ]; then
    say "skipping config (--no-config) — the code default path already matches"
elif command -v hermes >/dev/null 2>&1; then
    hermes config set security.redact_patterns "$PATTERNS_FILE" >/dev/null 2>&1 \
        && say "config: security.redact_patterns = $PATTERNS_FILE" \
        || say "config: hermes config set not applicable here — the code default path already matches"
else
    say "no hermes CLI on PATH — pattern file will be picked up at the default path"
fi

# ── 5. verify ───────────────────────────────────────────────────────────
if [ "$NO_TEST" = "1" ]; then
    say "skipping tests (--no-test)"
else
    say "running verification battery…"
    bash "$HERE/test.sh" --checkout "$CHECKOUT"
fi
say "done — see docs/format-spec.md for the file format, docs/full-stack.md for the full stack."
