#!/usr/bin/env bash
# Info Guard uninstaller — cleanly reverses install.sh.
#
#   ./uninstall.sh [--checkout DIR] [--keep-state] [--no-config] [--yes]
#
# Removes:
#   1. The redaction patch (reverse-applied; skipped if not applied).
#   2. The security.redact_patterns config key (via `hermes config unset`;
#      skipped with --no-config or when the CLI is unavailable).
#   3. The state dir (<home>/state/info-guard/) — by DEFAULT moved to
#      <home>/state/info-guard.bak-<timestamp> instead of deleted (safety
#      copy; remove it yourself once you're sure). --keep-state leaves it
#      in place.
#
# Does NOT remove: gitleaks (optional dependency, useful standalone) or the
# pattern-file data inside the .bak (see above).
#
# After uninstall: restart Hermes processes so the patched code is unloaded
# from memory.
#
# Exit codes: 0 = uninstalled, 1 = something failed, 2 = aborted.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
STATE_DIR="$HERMES_HOME/state/info-guard"
CHECKOUT=""
KEEP_STATE=0
NO_CONFIG=0
YES=0

while [ $# -gt 0 ]; do
    case "$1" in
        --checkout) CHECKOUT="$2"; shift 2 ;;
        --keep-state) KEEP_STATE=1; shift ;;
        --no-config) NO_CONFIG=1; shift ;;
        --yes) YES=1; shift ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

say() { printf '\033[1;34m[info-guard]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[info-guard]\033[0m %s\n' "$*" >&2; exit 1; }

# ── locate checkout (same logic as install.sh) ──────────────────────────
if [ -z "$CHECKOUT" ]; then
    if [ -f "$HERMES_HOME/hermes-agent/agent/redact.py" ]; then
        CHECKOUT="$HERMES_HOME/hermes-agent"
    elif command -v hermes >/dev/null 2>&1; then
        CHECKOUT="$(hermes --version 2>/dev/null | sed -n 's/^Install directory: //p')"
    fi
fi
[ -n "$CHECKOUT" ] && [ -f "$CHECKOUT/agent/redact.py" ] \
    || die "could not find the Hermes Agent checkout — pass --checkout DIR"

# ── confirm ─────────────────────────────────────────────────────────────
if [ "$YES" != "1" ]; then
    if [ ! -t 0 ]; then
        die "destructive operation — run interactively or pass --yes"
    fi
    prompt="[info-guard] remove Info Guard from $CHECKOUT? (state backed up to"
    prompt="$prompt *.bak-<timestamp> unless --keep-state) [y/N] "
    read -r -p "$prompt" ans
    case "$ans" in
        y|Y) ;;
        *) echo "[info-guard] aborted"; exit 2 ;;
    esac
fi

# ── 1. reverse the patch (only if applied) ──────────────────────────────
# Same 5-marker integrity check as install.sh / `check` (external-audit
# B2/F5; S2 regression): a single-marker grep misses a partially-reverted
# patch and would report "nothing to reverse" while 4 files stay patched.
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
    git -C "$CHECKOUT" apply -R "$HERE/patch/redactor-registry-patterns.patch" \
        || die "reverse-apply failed — the checkout drifted; restore manually (git -C $CHECKOUT checkout -- agent/redact.py cli.py gateway/run.py hermes_cli/config.py hermes_cli/main.py)"
    say "patch removed (reverse-applied)"
elif [ "$MARKERS" != "0" ]; then
    die "engine PARTIAL ($MARKERS/5 markers) — a failed hermes update likely half-reverted the patch.
     Refusing to uninstall a partial engine. Restore the patched files first, then re-run uninstall.sh:
       git -C $CHECKOUT checkout -- agent/redact.py cli.py gateway/run.py hermes_cli/config.py hermes_cli/main.py"
else
    say "patch not applied — nothing to reverse"
fi

# ── 2. config key ───────────────────────────────────────────────────────
if [ "$NO_CONFIG" = "1" ]; then
    say "skipping config key (--no-config)"
elif command -v hermes >/dev/null 2>&1; then
    if hermes config unset security.redact_patterns >/dev/null 2>&1; then
        say "config: security.redact_patterns removed"
    else
        say "config: key absent or CLI could not unset — harmless (engine is gone)"
    fi
else
    say "no hermes CLI on PATH — config key left as-is (inert without the engine)"
fi

# ── 3. state dir ────────────────────────────────────────────────────────
if [ "$KEEP_STATE" = "1" ]; then
    say "state dir left in place (--keep-state): $STATE_DIR"
elif [ -d "$STATE_DIR" ]; then
    bak="${STATE_DIR}.bak-$(date +%Y%m%d-%H%M%S)"
    mv "$STATE_DIR" "$bak"
    say "state moved to $bak (delete it once you're sure — it holds your pattern file and custom literals)"
else
    say "no state dir present"
fi

say "done. Restart Hermes processes (gateway, web UI) to unload the patched code."
say "gitleaks (if installed) was left in place — it is a standalone tool."
