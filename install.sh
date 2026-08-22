#!/usr/bin/env bash
# Info Guard installer — the redaction layer for Hermes Agent.
#
#   ./install.sh [--checkout DIR] [--force] [--no-config] [--no-test]
#                [--cron [SCHEDULE]] [--no-cron]
#
# What it does:
#   1. Locates the Hermes Agent checkout (git install).
#   2. Applies the registry-fed redaction patch (idempotent, marker-guarded,
#      lock-first target-safety sequence, Wave C IG D113):
#        ACTIVE + artifact match  = nothing to do
#        ACTIVE + artifact mismatch = replaces the stale applied patch in
#           place (product residue; content attribution cannot distinguish a
#           stale patch from a pre-existing operator edit in this state —
#           replaced by design, documented in README/format-spec)
#        PARTIAL (1–4/5 markers)  = restore-and-reapply (a half-reverted
#           `hermes update` self-heals)
#        MISSING (0/5)            = apply
#        ACTIVE-by-upstream       = patch present in HEAD (PR #87953 merged):
#           accepted only when markers are in HEAD, both apply-checks fail
#           (not a working-tree patch, already in HEAD) AND the behavioral
#           battery passes — marker presence alone never establishes ACTIVE.
#      Dirty patched files in the attribution-exact MISSING/PARTIAL states
#      fail closed (exit 2, file preserved) — never overwrite operator edits.
#   3. Creates <home>/state/info-guard/ and seeds redact_patterns.json +
#      custom_literals.json (never overwrites existing files).
#   4. Points Hermes at the pattern file (security.redact_patterns config).
#   5. Runs test.sh — the end-to-end verification battery.
#   6. Optionally installs one managed cron line running `check` (--cron
#      [SCHEDULE], default 0 6 * * *; interactive TTY prompt when neither
#      --cron nor --no-cron is given; non-interactive default = no cron;
#      every internal invocation passes --no-cron — Wave C A14).
#
# Exit codes (Wave C §4.3 classification, single source):
#   0 = installed & verified
#   1 = completed verdict: broken — a repair/apply was ATTEMPTED and failed
#       (patch-apply failure, restore conflict, engine still not ACTIVE
#       after the attempt, behavioral battery failed, codebase drifted)
#   2 = usage OR operational failure — the operation could NOT be attempted
#       (unknown flag, missing checkout, target lock held, dirty patched
#       target file refusal, unwritable target, invalid/unreadable target
#       version, crontab unavailable)
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
CRON_MODE=""          # "" unset (TTY prompt) | "yes" (--cron) | "no" (--no-cron)
CRON_SCHEDULE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --checkout) CHECKOUT="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        --no-config) NO_CONFIG=1; shift ;;
        --no-test) NO_TEST=1; shift ;;
        --no-cron) CRON_MODE=no; shift ;;
        --cron)
            CRON_MODE=yes
            # optional SCHEDULE argument (a cron line never starts with --)
            if [ $# -gt 1 ] && ! [[ "$2" == --* ]]; then
                CRON_SCHEDULE="$2"; shift
            fi
            shift ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

say() { printf '\033[1;34m[info-guard]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[info-guard]\033[0m %s\n' "$*" >&2; exit 1; }
die2() { printf '\033[1;31m[info-guard]\033[0m %s\n' "$*" >&2; exit 2; }

# ── 1. locate checkout ──────────────────────────────────────────────────
if [ -z "$CHECKOUT" ]; then
    if [ -f "$HERMES_HOME/hermes-agent/agent/redact.py" ]; then
        CHECKOUT="$HERMES_HOME/hermes-agent"
    elif command -v hermes >/dev/null 2>&1; then
        CHECKOUT="$(hermes --version 2>/dev/null | sed -n 's/^Install directory: //p')"
    fi
fi
[ -n "$CHECKOUT" ] && [ -f "$CHECKOUT/agent/redact.py" ] \
    || die2 "could not find the Hermes Agent checkout — pass --checkout DIR"
[ -d "$CHECKOUT/.git" ] \
    || die2 "target is not a git checkout — the engine patch requires git ($CHECKOUT)"

say "checkout: $CHECKOUT"
if command -v hermes >/dev/null 2>&1; then
    say "hermes:   $(hermes --version 2>/dev/null | head -1 || echo unknown)"
fi

# ── 2. target-checkout lock FIRST (§4.1 step 1 — before any state read) ──
# The lock serializes cooperating Info Guard processes only; it never
# prevents external editors (detected by snapshot→revalidate, never
# described as external-write prevention).
LOCKFILE="$CHECKOUT/.git/info-guard.lock"
exec 9>"$LOCKFILE"
if ! flock -n 9; then
    die2 "another update/heal in progress (target lock held: $LOCKFILE)"
fi
trap 'flock -u 9 2>/dev/null || true' EXIT

# ── target version (§4.1 step 2 — same source rule as `check`) ──────────
# First usable git tag on the checkout, else `hermes --version`; normalized
# to the first dotted-numeric run (the tuple form the supported-range check
# accepts). Unreadable/malformed => operational failure, exit 2, no restore.
_target_version() {
    local tag t
    tag="$(git -C "$CHECKOUT" describe --tags --abbrev=0 2>/dev/null || true)"
    if [ -n "$tag" ]; then
        t="$(printf '%s' "$tag" | grep -o '[0-9][0-9.]*' | head -1)"
        [ -n "$t" ] && { printf '%s' "$t"; return 0; }
    fi
    if command -v hermes >/dev/null 2>&1; then
        local v
        v="$(hermes --version 2>/dev/null | grep -oE '\([0-9]{4}\.[0-9]{1,2}\.[0-9]{1,2}(\.[0-9]+)?\)' | head -1 | tr -d '()')"
        [ -n "$v" ] && { printf '%s' "$v"; return 0; }
    fi
    return 1
}

# ── snapshot + revalidation (§4.1 steps 2–4) ─────────────────────────────
# Captures repository identity, HEAD, the normalized version tuple, and the
# exact worktree+index state of the 5 patched files. Exact equality between
# the snapshot and the pre-restore revalidation is REQUIRED; any difference
# (from ANY process) aborts with exit 2 and instructions. The guarantee ends
# at the final revalidation — the residual sub-second window is documented.
_PATCHED_FILES=(agent/redact.py cli.py gateway/run.py hermes_cli/config.py hermes_cli/main.py)
_PATCHED_MARKERS=(_redact_registry_patterns HERMES_REDACT_PATTERNS HERMES_REDACT_PATTERNS redact_patterns HERMES_REDACT_PATTERNS)

_snapshot() {
    local id head ver
    id="$(git -C "$CHECKOUT" rev-parse --show-toplevel 2>/dev/null || echo MISSING)"
    head="$(git -C "$CHECKOUT" rev-parse HEAD 2>/dev/null || echo MISSING)"
    ver="$(_target_version || echo UNREADABLE)"
    printf 'id=%s\nhead=%s\nversion=%s\n' "$id" "$head" "$ver"
    for rel in "${_PATCHED_FILES[@]}"; do
        local wb idx
        wb="$(git -C "$CHECKOUT" hash-object "$CHECKOUT/$rel" 2>/dev/null || echo MISSING)"
        idx="$(git -C "$CHECKOUT" ls-files -s -- "$rel" 2>/dev/null | awk '{print $2, $3}' || echo MISSING)"
        printf 'file=%s worktree=%s index=%s\n' "$rel" "$wb" "$idx"
    done
}

# ── engine integrity (5 markers, external-audit B2/F5) ──────────────────
# All present = ACTIVE; some = PARTIAL (half-reverted update); none = MISSING.
_marker_count() {
    local n=0
    grep -q "_redact_registry_patterns" "$CHECKOUT/agent/redact.py" 2>/dev/null && n=$((n+1))
    grep -q "redact_patterns"            "$CHECKOUT/hermes_cli/config.py" 2>/dev/null && n=$((n+1))
    grep -q "HERMES_REDACT_PATTERNS"     "$CHECKOUT/hermes_cli/main.py" 2>/dev/null && n=$((n+1))
    grep -q "HERMES_REDACT_PATTERNS"     "$CHECKOUT/cli.py" 2>/dev/null && n=$((n+1))
    grep -q "HERMES_REDACT_PATTERNS"     "$CHECKOUT/gateway/run.py" 2>/dev/null && n=$((n+1))
    echo "$n"
}

# per-file dirty check (§1.3 branch-scoped expected state):
#   expected_patched=1  -> worktree must equal HEAD+this package's patch
#                          (per-file reverse-apply) AND the index must equal
#                          HEAD (patch is applied to the worktree only)
#   expected_patched=0  -> worktree+index must equal HEAD
# Returns 0 (dirty) / 1 (clean).
_file_dirty() {
    local rel="$1" patched="$2"
    if [ "$patched" = "1" ]; then
        git -C "$CHECKOUT" apply --reverse --check --include="$rel" "$PATCH" >/dev/null 2>&1 \
            || return 0
        git -C "$CHECKOUT" diff --cached --quiet HEAD -- "$rel" || return 0
    else
        git -C "$CHECKOUT" diff --quiet HEAD -- "$rel" || return 0
    fi
    return 1
}

_marker_in_head() {
    local rel="$1" marker="$2"
    git -C "$CHECKOUT" show "HEAD:$rel" 2>/dev/null | grep -q "$marker"
}

# ── 3. lock-first sequence: snapshot → inspect → revalidate → restore ────
SNAP_A="$(_snapshot)"
[ "$(printf '%s\n' "$SNAP_A" | sed -n 's/^version=//p')" != "UNREADABLE" ] \
    || die2 "could not determine the target Hermes version (no usable git tag, no hermes on PATH) — aborting before any restore (version_mismatch)"

MARKERS=$(_marker_count)
REVERSE_OK=0; FORWARD_OK=0; UPSTREAM_MARKERS=0
if git -C "$CHECKOUT" apply --reverse --check "$PATCH" >/dev/null 2>&1; then
    REVERSE_OK=1
elif git -C "$CHECKOUT" apply --check "$PATCH" >/dev/null 2>&1; then
    FORWARD_OK=1
else
    # both apply-checks fail: either the patch is already in HEAD (upstream
    # merge) or the codebase drifted. Markers in HEAD decide.
    n=0
    for i in "${!_PATCHED_FILES[@]}"; do
        _marker_in_head "${_PATCHED_FILES[$i]}" "${_PATCHED_MARKERS[$i]}" && n=$((n+1))
    done
    UPSTREAM_MARKERS=$n
fi

# dirty-file refusal — attribution-exact branches only (MISSING/PARTIAL);
# ACTIVE-mismatch is replace-in-place by design (A8, §1.3).
DIRTY=""
if [ "$MARKERS" = "0" ]; then
    for rel in "${_PATCHED_FILES[@]}"; do
        if _file_dirty "$rel" 0; then DIRTY="$rel"; break; fi
    done
elif [ "$MARKERS" -lt 5 ]; then
    for i in "${!_PATCHED_FILES[@]}"; do
        rel="${_PATCHED_FILES[$i]}"
        expected=0
        grep -q "${_PATCHED_MARKERS[$i]}" "$CHECKOUT/$rel" 2>/dev/null && expected=1
        if _file_dirty "$rel" "$expected"; then DIRTY="$rel"; break; fi
    done
fi
if [ -n "$DIRTY" ]; then
    die2 "patched file differs from its expected product state: $DIRTY — refusing to overwrite an operator change. Resolve it manually, then re-run install.sh (no file was modified)."
fi

# revalidate immediately before any restore
SNAP_B="$(_snapshot)"
if [ "$SNAP_A" != "$SNAP_B" ]; then
    die2 "target checkout changed during inspection (external modification detected) — aborting before restore. Re-run install.sh once the checkout is stable (no file was modified)."
fi

# ── 4. branch actions ───────────────────────────────────────────────────
RESTORED=0
if [ "$MARKERS" = "5" ] && [ "$REVERSE_OK" = "1" ] && [ "$FORCE" != "1" ]; then
    say "engine ACTIVE (5/5 markers) — patch applied and matches this package's artifact"
elif [ "$MARKERS" = "5" ] && [ "$UPSTREAM_MARKERS" = "5" ] && [ "$FORCE" != "1" ]; then
    # ACTIVE-by-upstream: patch is in HEAD (PR #87953 merged), not a
    # working-tree patch. Marker presence alone never establishes ACTIVE —
    # the behavioral battery (test.sh) below is the gate; if it fails the
    # install dies with "compatibility review required" (never silently
    # accepted). --force still replaces in place (branch below).
    say "engine ACTIVE-by-upstream — patch present in Hermes HEAD (upstream merge); behavioral battery required (markers alone never prove the engine masks)"
elif [ "$MARKERS" = "5" ]; then
    if [ "$FORCE" = "1" ]; then
        say "re-applying patch (--force) — replacing in place"
    else
        say "engine ACTIVE (5/5 markers) but the applied patch differs from this package's artifact — replacing it in place"
    fi
    git -C "$CHECKOUT" checkout -- "${_PATCHED_FILES[@]}" \
        || die "could not reset the 5 patched files — resolve working-tree changes in $CHECKOUT, then re-run install.sh"
    RESTORED=1
elif [ "$MARKERS" != "0" ]; then
    say "engine PARTIAL ($MARKERS/5 markers) — a failed hermes update likely half-reverted the patch; restoring and re-applying"
    git -C "$CHECKOUT" checkout -- "${_PATCHED_FILES[@]}" \
        || die "could not reset the 5 patched files — resolve working-tree changes in $CHECKOUT, then re-run install.sh"
    RESTORED=1
elif [ "$FORCE" = "1" ]; then
    say "re-applying patch (--force)"
    RESTORED=1
else
    say "engine MISSING (0/5 markers) — applying patch"
    RESTORED=1
fi
if [ "$RESTORED" = "1" ]; then
    git -C "$CHECKOUT" apply --check "$PATCH" \
        || die "patch no longer applies — the codebase has drifted (hermes update?). Rebase the patch against the current checkout, or use the upstream PR once merged."
    git -C "$CHECKOUT" apply "$PATCH"
    git -C "$CHECKOUT" apply --reverse --check "$PATCH" \
        || die "verification failed after applying the patch — unexpected state in $CHECKOUT"
    say "patch applied — checkout now matches this package's artifact"
fi

# ── 5. state dir + seed files (never clobber) ───────────────────────────
mkdir -p "$STATE_DIR" || die2 "state dir not writable: $STATE_DIR"
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

# ── 6. point Hermes at the pattern file ─────────────────────────────────
if [ "$NO_CONFIG" = "1" ]; then
    say "skipping config (--no-config) — the code default path already matches"
elif command -v hermes >/dev/null 2>&1; then
    hermes config set security.redact_patterns "$PATTERNS_FILE" >/dev/null 2>&1 \
        && say "config: security.redact_patterns = $PATTERNS_FILE" \
        || say "config: hermes config set not applicable here — the code default path already matches"
else
    say "no hermes CLI on PATH — pattern file will be picked up at the default path"
fi

# ── 7. verify (behavioral battery) ──────────────────────────────────────
if [ "$NO_TEST" = "1" ]; then
    say "skipping tests (--no-test)"
    if [ "$MARKERS" = "5" ] && [ "$UPSTREAM_MARKERS" = "5" ] && [ "$FORCE" != "1" ]; then
        say "warning: ACTIVE-by-upstream detected but behavioral verification skipped (--no-test) — compatibility not established; run ./test.sh to verify"
    fi
else
    say "running verification battery…"
    bash "$HERE/test.sh" --checkout "$CHECKOUT" \
        || die "behavioral battery FAILED — the engine does not mask correctly (compatibility review required if the patch is present in Hermes HEAD). No 'verified' claim is made."
fi

# ── 8. install manifest — atomic end-of-run write (Wave C §3.1.1) ───────
# The version record is written ONLY at the successful end of the run; the
# transaction records (previous_version / previous_commit / pending) are
# PRESERVED untouched — never regenerated wholesale (the update command owns
# them and re-asserts post-install).
IG_VERSION="$(awk -F'"' '/_PACKAGE_VERSION = /{print $2; exit}' "$HERE/bin/info-guard")"
[ -n "$IG_VERSION" ] || IG_VERSION=unknown
_write_manifest() {
    python3 - "$STATE_DIR" "$IG_VERSION" <<'PYEOF'
import json, os, sys, tempfile, time
state_dir, version = sys.argv[1], sys.argv[2]
path = os.path.join(state_dir, "install.json")
doc = {}
try:
    with open(path) as f:
        old = json.load(f)
    if isinstance(old, dict):
        doc = dict(old)
except (OSError, ValueError):
    doc = {}
doc["version"] = version
doc["installed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
for k in ("previous_version", "previous_commit", "pending"):
    doc.setdefault(k, None)
os.makedirs(state_dir, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix=".install-", suffix=".json", dir=state_dir)
try:
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
except BaseException:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
PYEOF
}
_write_manifest
say "wrote $STATE_DIR/install.json (manifest: v$IG_VERSION)"

# ── 9. cron offering (W6/S5 — opt-in only; internal calls pass --no-cron) ─
# Managed-line grammar (canonical quoted form — the quoted forms are ALWAYS
# emitted, never only when the path contains specials):
#   HERMES_HOME='<escaped>' '<escaped pkg>/bin/info-guard' check  # info-guard-managed:'<escaped pkg>'
# Every interpolated value is single-quote wrapped with the '\'' escape.
# '%' is REJECTED (never escaped) — cron's daemon layer parses '%' as an
# input separator BEFORE the shell, so shell quoting does not protect it.
_is_int() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

_cron_reject() { # any unsafe value -> 0 (reject). % / newline / control chars.
    local v
    for v in "$@"; do
        case "$v" in
            *'%'*) return 0 ;;
        esac
        printf '%s' "$v" | grep -q '[[:cntrl:]]' && return 0
    done
    return 1
}

_cron_quote() { # single-quote wrap with '\'' escaping (canonical form)
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

_cron_schedule_valid() { # strict 5-field grammar (proposal §7)
    local s="$1" i f
    case "$s" in
        *$'\n'*|*'%'*|*[!0-9*,\-[:space:]]*) return 1 ;;
    esac
    [ "$(printf '%s' "$s" | awk '{print NF}')" = "5" ] || return 1
    i=0
    # while-read (NOT `for f in $s` — an unquoted expansion would glob the
    # '*' fields against the cwd)
    while IFS= read -r f; do
        i=$((i+1))
        local min=0 max=0
        case $i in
            1) min=0; max=59 ;;
            2) min=0; max=23 ;;
            3) min=1; max=31 ;;
            4) min=1; max=12 ;;
            5) min=0; max=7 ;;
        esac
        case "$f" in
            '*') ;;
            *','*)
                # while-read over the comma parts (no glob expansion)
                while IFS= read -r part; do
                    _is_int "$part" || return 1
                    [ "$part" -ge "$min" ] && [ "$part" -le "$max" ] || return 1
                done <<< "$(printf '%s' "$f" | tr ',' '\n')" ;;
            *'-'*)
                local lo="${f%%-*}" hi="${f##*-}"
                _is_int "$lo" || return 1
                _is_int "$hi" || return 1
                [ "$lo" -ge "$min" ] && [ "$hi" -le "$max" ] && [ "$lo" -le "$hi" ] || return 1 ;;
            *)
                _is_int "$f" || return 1
                [ "$f" -ge "$min" ] && [ "$f" -le "$max" ] || return 1 ;;
        esac
    done <<< "$(printf '%s' "$s" | tr ' ' '\n')"
    return 0
}

_cron_managed_line() { # $1 = schedule; prints the canonical managed line
    # <schedule> HERMES_HOME='…' '<pkg>/bin/info-guard' check  # info-guard-managed:'<pkg>'
    # (the schedule prefix is REQUIRED — a crontab line without the 5
    # schedule fields is invalid cron; proposal §7 mandates it)
    printf "%s HERMES_HOME=%s %s check  # info-guard-managed:%s\n" \
        "$1" \
        "$(_cron_quote "$HERMES_HOME")" \
        "$(_cron_quote "$HERE/bin/info-guard")" \
        "$(_cron_quote "$HERE")"
}

_cron_install() { # $1 = schedule ("" -> default 0 6 * * *)
    local schedule="${1:-0 6 * * *}"
    # rejection block: unsafe package/state path -> exit 2, nothing written
    if _cron_reject "$HERE" "$HERMES_HOME"; then
        die2 "cron: package or state path contains '%' or control characters — refusing to write an unsafe managed line (nothing written, no ownership marker)"
    fi
    if ! _cron_schedule_valid "$schedule"; then
        die2 "cron: invalid schedule (strict 5-field grammar: minute 0-59, hour 0-23, day-of-month 1-31, month 1-12, weekday 0-7; '*' / int / lo-hi / a,b,c only; no steps, names, '%' or newlines) — nothing written"
    fi
    command -v crontab >/dev/null 2>&1 \
        || die2 "cron: crontab unavailable on PATH — cannot install a managed line (nothing written)"
    mkdir -p "$STATE_DIR" || die2 "cron: state dir not writable: $STATE_DIR (nothing written)"
    # product lockfile serializes every read-modify-write of the crontab
    exec 8>"$STATE_DIR/cron-install.lock"
    if ! flock -n 8; then
        die2 "cron: another cron operation in progress (lock held: $STATE_DIR/cron-install.lock) — nothing written"
    fi
    local line marker
    line="$(_cron_managed_line "$schedule")"
    marker="# info-guard-managed:$(_cron_quote "$HERE")"
    local current kept
    current="$(crontab -l 2>/dev/null || true)"
    # replace ONLY this package's exact managed lines; preserve every
    # unrelated entry byte-for-byte; never touch another package's lines
    kept="$(printf '%s\n' "$current" | grep -vF -- "$marker" | sed '/^$/d' || true)"
    local out
    out="$(printf '%s\n%s\n' "$kept" "$line")"
    if printf '%s\n' "$out" | crontab -; then
        local n
        n="$(crontab -l 2>/dev/null | grep -cF -- "$marker" || true)"
        say "cron: installed one managed line (schedule: $schedule; ${n} owned line(s) present)"
        say "cron: command: $line"
    else
        die2 "cron: crontab write failed — nothing changed"
    fi
}

if [ "$CRON_MODE" = "yes" ]; then
    _cron_install "$CRON_SCHEDULE"
elif [ "$CRON_MODE" = "no" ]; then
    say "skipping cron (--no-cron)"
elif [ -t 0 ]; then
    # interactive TTY: ask (never silently installs a job)
    printf '[info-guard] install a managed cron line running `info-guard check`? (default schedule 0 6 * * *) [y/N] '
    ans=""
    read -r -p "" ans || ans=""
    case "$ans" in
        y|Y) _cron_install "" ;;
        *) say "no cron installed" ;;
    esac
else
    say "no cron installed (non-interactive default — pass --cron to opt in)"
fi

say "done — see docs/format-spec.md for the file format, docs/full-stack.md for the full stack."
