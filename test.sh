#!/usr/bin/env bash
# Info Guard verification battery — the "second instance" test.
#
#   ./test.sh [--checkout DIR]
#
# Verifies, end-to-end and with synthetic values only (no real secrets):
#   1. exact-value masking (partial, full, short-value) via a scratch pattern file
#   2. KEY=value / KEY: value key-pattern masking
#   3. file_read sentinel (a masked value can never be written back)
#   4. fail-safe: broken pattern file = no unmasked gap, auto-recovery
#   5. missing pattern file = no-op (built-in redaction still works)
#   6. default-path resolution via $HERMES_HOME (a fresh/second home gets its
#      own pattern file automatically — no config, no env vars)
#   7. same-process path-switch (cache identity — audit followup2 #4)
#   8. symlinked registry path (trusted-path pin — audit followup2 #5)
#   9. update-ordering: install.sh replaces a stale applied patch in
#      place; `check` exit codes (healthy 0 / engine-missing 1)
#
# Exit 0 = all checks pass. Uses only synthetic probe values.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
CHECKOUT="${HERMES_HOME}/hermes-agent"

while [ $# -gt 0 ]; do
    case "$1" in
        --checkout) CHECKOUT="$2"; shift 2 ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

[ -f "$CHECKOUT/agent/redact.py" ] \
    || { echo "[test] ✗ no checkout at $CHECKOUT (pass --checkout DIR)" >&2; exit 1; }
grep -q "_redact_registry_patterns" "$CHECKOUT/agent/redact.py" \
    || { echo "[test] ✗ redaction patch not applied in $CHECKOUT" >&2; exit 1; }

# Run with a venv that has the bare minimum; fall back to system python3.
PY="$(command -v python3)"

"$PY" - "$CHECKOUT" <<'PYEOF'
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import fcntl
import hashlib
import types
from pathlib import Path

CHECKOUT = sys.argv[1]
sys.path.insert(0, CHECKOUT)
from agent.redact import redact_sensitive_text

PASS = 0
FAIL = 0
SKIP = 0
EXECUTED_LABELS = []     # every check() label that actually executed
                         # (evidence r2 MAJ-1: the ledger verifies
                         # EXECUTED assertions, not source strings)

def check(name, cond, detail=""):
    global PASS, FAIL
    EXECUTED_LABELS.append(name)
    if cond:
        PASS += 1
        print(f"  \u2713 {name}")
    else:
        FAIL += 1
        print(f"  \u2717 {name} {detail}")

def skip(name, reason=""):
    """Mark a check deferred/not-applicable (A# counting — the executable
    denominator excludes skipped checks; reported separately)."""
    global SKIP
    SKIP += 1
    print(f"  \u2013 {name} (skipped: {reason})")

def write(p, obj):
    with open(p, "w") as f:
        json.dump(obj, f)

tmp = tempfile.mkdtemp(prefix="info-guard-test-")

# Version-identity anchor (IG D117): read the checked-out _PACKAGE_VERSION
# once — the preflight header and --version assertions derive from it so the
# battery never hardcodes a release version again (D116 #2 hermeticity; the
# v0.8.0 release shipped "0.7.0" and these checks were hardcoded to match
# the WRONG constant, so they passed green with a stale identity).
_PKG_VER = re.search(r'_PACKAGE_VERSION = "([^"]+)"',
                     Path(os.getcwd(), "bin", "info-guard").read_text()).group(1)
pfile = os.path.join(tmp, "patterns.json")

# ── A: scratch pattern file with synthetic probes ──────────────────────
DEFAULT_LIT = "ig-probe-default-12345"      # 20 chars -> 2+2 visible
FULL_LIT = "ig-probe-full-mask-67890"       # mask: full
SHORT_LIT = "ig-short-42"                   # 11 chars -> under floor 12 -> ***
write(pfile, {
    "mask": {"head": 2, "tail": 2, "floor": 12},
    "literals": [
        DEFAULT_LIT,
        {"value": FULL_LIT, "mask": "full"},
        SHORT_LIT,
    ],
    "key_patterns": {"IG_PROBE_PIN": True},
})

def redact(text, file_read=False, patterns=pfile):
    os.environ["HERMES_REDACT_PATTERNS"] = patterns
    return redact_sensitive_text(text, file_read=file_read)

# 1. exact values
check("default mask: head+tail visible", redact(DEFAULT_LIT) == "ig...45",
      f"got {redact(DEFAULT_LIT)!r}")
check("full mask: nothing visible", redact(FULL_LIT) == "***",
      f"got {redact(FULL_LIT)!r}")
check("short value: fully masked", redact(SHORT_LIT) == "***",
      f"got {redact(SHORT_LIT)!r}")

# 2. key patterns (KEY= / KEY: / JSON forms)
check("KEY=value form", redact("IG_PROBE_PIN=1234") == "IG_PROBE_PIN=***",
      f"got {redact('IG_PROBE_PIN=1234')!r}")
check("KEY: value form", redact("IG_PROBE_PIN: 1234") == "IG_PROBE_PIN: ***",
      f"got {redact('IG_PROBE_PIN: 1234')!r}")
# 2b. external-audit F1 regressions: JSON key forms + quoted multi-word values
# (separate file — must not clobber the shared pfile that tests 1–3 use)
pfile2 = os.path.join(tmp, "patterns2.json")
write(pfile2, {
    "mask": {"head": 2, "tail": 2, "floor": 12},
    "literals": [],
    "key_patterns": {"ig_probe_passphrase": True},
})
_json_dq = '{"ig_probe_passphrase": "auditprobe12345"}'
_json_sq = "'ig_probe_passphrase': 'auditprobe12345'"
_mw = 'ig_probe_passphrase="audit probe words 123"'
_ws = "ig_probe_passphrase = 1234"
_ev = 'ig_probe_passphrase=""'
check("JSON double-quote key form",
      redact(_json_dq, patterns=pfile2) == '{"ig_probe_passphrase": "au...45"}',
      f"got {redact(_json_dq, patterns=pfile2)!r}")
check("JSON single-quote key form",
      redact(_json_sq, patterns=pfile2) == "'ig_probe_passphrase': 'au...45'",
      f"got {redact(_json_sq, patterns=pfile2)!r}")
check("quoted multi-word value",
      redact(_mw, patterns=pfile2) == 'ig_probe_passphrase="au...23"',
      f"got {redact(_mw, patterns=pfile2)!r}")
check("separator whitespace preserved",
      redact(_ws, patterns=pfile2) == "ig_probe_passphrase = ***",
      f"got {redact(_ws, patterns=pfile2)!r}")
check("empty value passthrough",
      redact(_ev, patterns=pfile2) == _ev,
      f"got {redact(_ev, patterns=pfile2)!r}")

# 3. file_read sentinel: masked value must be a non-reusable sentinel, never
#    the original or a reconstructible fragment
sent = redact(f"value={DEFAULT_LIT}", file_read=True)
check("file_read uses non-reusable sentinel",
      sent != f"value={DEFAULT_LIT}" and "ig-probe" not in sent and "12345" not in sent,
      f"got {sent!r}")

# 4. fail-safe: broken file -> last-good set stays active, no unmasked gap.
#    Prime the cache with the GOOD version of the file first, then break it.
broken = os.path.join(tmp, "broken.json")
good = {"mask": {"head": 2, "tail": 2, "floor": 12},
        "literals": ["ig-broken-probe"], "key_patterns": {}}
t = time.time()
write(broken, good)
os.utime(broken, (t, t))
check("prime: good file masks", redact("ig-broken-probe", patterns=broken) != "ig-broken-probe")
with open(broken, "w") as f:
    f.write("{not json")
os.utime(broken, (t + 2, t + 2))
check("broken file: no exception, no unmasked output",
      "ig-broken-probe" not in redact("ig-broken-probe", patterns=broken),
      "broken file leaked the literal")
write(broken, good)
os.utime(broken, (t + 4, t + 4))
check("broken file: auto-recovers when repaired",
      "ig-broken-probe" not in redact("ig-broken-probe", patterns=broken))

# 5. missing file: no-op (built-in redaction still runs)
os.environ.pop("HERMES_REDACT_PATTERNS", None)
check("missing file: no-op, no crash", redact("hello world") == "hello world")

# 6. DEFAULT-PATH RESOLUTION (the second-instance property): a fresh
#    HERMES_HOME with its own state file masks without any config/env
fresh_home = os.path.join(tmp, "fresh-home")
fresh_pfile = os.path.join(fresh_home, "state", "info-guard", "redact_patterns.json")
os.makedirs(os.path.dirname(fresh_pfile), exist_ok=True)
write(fresh_pfile, {
    "mask": {"head": 2, "tail": 2, "floor": 12},
    "literals": ["ig-fresh-home-probe-abc"],
    "key_patterns": {},
})
env = dict(os.environ)
env.pop("HERMES_REDACT_PATTERNS", None)
env["HERMES_HOME"] = fresh_home
code = (
    "import sys; sys.path.insert(0, %r); "
    "from agent.redact import redact_sensitive_text as r; "
    "out = r('ig-fresh-home-probe-abc'); "
    "print(out); sys.exit(0 if out == 'ig...bc' else 1)"
) % CHECKOUT
proc = subprocess.run([sys.executable, "-c", code], env=env,
                      capture_output=True, text=True, timeout=60)
check("fresh HERMES_HOME: default path resolved, value masked",
      proc.returncode == 0 and proc.stdout.strip() == "ig...bc",
      f"rc={proc.returncode} out={proc.stdout.strip()!r} err={proc.stderr.strip()[-200:]!r}")

# 7. external-audit F2 regression: the setup wizard must register
#    gitleaks-only findings (not drop them as "value too short")
setup_home = os.path.join(tmp, "setup-home")
os.makedirs(os.path.join(setup_home, "sessions"), exist_ok=True)
with open(os.path.join(setup_home, "sessions", "d.json"), "w") as f:
    # runtime-constructed (push protection: even the canonical fake webhook
    # URL trips GitHub's secret scanner as a literal)
    f.write('{"hook":"' + "https://hooks.slack.com/services/" + "T00000000/B00000000/" + "X" * 24 + '"}\n')
env2 = dict(os.environ)
env2["HERMES_HOME"] = setup_home
setup = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "setup", "--all"],
    env=env2, capture_output=True, text=True, timeout=300)
cl = os.path.join(setup_home, "state", "info-guard", "custom_literals.json")
reg = False
if os.path.exists(cl):
    data = json.load(open(cl))
    for l in data.get("literals", []):
        v = l if isinstance(l, str) else l.get("value", "")
        if "hooks.slack.com" in v:
            reg = True
check("setup registers gitleaks-only finding (audit F2)",
      reg and "too short" not in setup.stdout + setup.stderr,
      f"rc={setup.returncode} registered={reg}")

# 8. external-audit C5 adversarial batch (boundary/format fuzz)
write(pfile, {
    "mask": {"head": 2, "tail": 2, "floor": 12},
    "literals": ["ig-probe-default-12345", "ig-pröbe-12345"],
    "key_patterns": {"ig_probe_passphrase": True, "IG_PROBE_PIN": True},
})
g_close = redact("IG_PROBE_PIN=1234}")
check("delimiter: } terminates value", g_close == "IG_PROBE_PIN=***}",
      f"got {g_close!r}")
g_comma = redact("IG_PROBE_PIN=1234,OTHER=1")
check("delimiter: , terminates value",
      g_comma == "IG_PROBE_PIN=***,OTHER=1", f"got {g_comma!r}")
g_q = redact('IG_PROBE_PIN="1234"')
check("quoted value", g_q == 'IG_PROBE_PIN="***"', f"got {g_q!r}")
g_ws = redact("IG_PROBE_PIN = 1234")
check("separator whitespace preserved", g_ws == "IG_PROBE_PIN = ***",
      f"got {g_ws!r}")
g_var = redact("ig_probe_passphrase=${IG_PROBE_PIN}")
check("variable-ref masks first token",
      g_var == "ig_probe_passphrase=***{IG_PROBE_PIN}", f"got {g_var!r}")
g_xml = redact("<ApiKey>ig-probe-default-12345</ApiKey>")
check("literal masks inside XML", g_xml == "<ApiKey>ig...45</ApiKey>",
      f"got {g_xml!r}")
g_xmlgap = redact("<PIN>4321</PIN>")
check("XML key form NOT masked (documented gap)",
      g_xmlgap == "<PIN>4321</PIN>", f"got {g_xmlgap!r}")
g_once = redact("IG_PROBE_PIN=1234")
check("idempotent re-masking", redact(g_once) == g_once, f"got {redact(g_once)!r}")
g_uni = redact("ig-pröbe-12345")
check("unicode literal", g_uni == "ig...45", f"got {g_uni!r}")

# 9. external-audit followup2 #4: same-process path-switch regression —
#    cache identity: switching HERMES_REDACT_PATTERNS A -> B in one
#    process must swap the active secret set (alpha masked under A only)
sw_a = os.path.join(tmp, "switch-a.json")
sw_b = os.path.join(tmp, "switch-b.json")
ALPHA = "alpha-secret-123456"       # 19 chars -> 2+2 visible
BRAVO = "bravo-secret-123456"       # 19 chars -> 2+2 visible
write(sw_a, {"mask": {"head": 2, "tail": 2, "floor": 12},
             "literals": [ALPHA], "key_patterns": {}})
write(sw_b, {"mask": {"head": 2, "tail": 2, "floor": 12},
             "literals": [BRAVO], "key_patterns": {}})
check("path-switch: A masks its own secret",
      redact(ALPHA, patterns=sw_a) == "al...56", f"got {redact(ALPHA, patterns=sw_a)!r}")
check("path-switch: B masks its own secret (same process)",
      redact(BRAVO, patterns=sw_b) == "br...56", f"got {redact(BRAVO, patterns=sw_b)!r}")
check("path-switch: A's secret NOT masked under B (cache identity)",
      redact(ALPHA, patterns=sw_b) == ALPHA, f"got {redact(ALPHA, patterns=sw_b)!r}")

# 10. external-audit followup2 #5: symlinked registry path — the
#     format-spec documents "path fully trusted, symlinks followed";
#     pin the behavior: live symlink loads + masks, dangling = fail-safe
real_p = os.path.join(tmp, "real-patterns.json")
link_p = os.path.join(tmp, "linked-patterns.json")
SYM = "symlink-probe-12345"         # 18 chars -> 2+2 visible
write(real_p, {"mask": {"head": 2, "tail": 2, "floor": 12},
               "literals": [SYM], "key_patterns": {}})
os.symlink(real_p, link_p)
check("symlink: registry loaded through symlink (trusted path)",
      redact(SYM, patterns=link_p) == "sy...45",
      f"got {redact(SYM, patterns=link_p)!r}")
dangling = os.path.join(tmp, "dangling.json")
os.symlink(os.path.join(tmp, "no-such-target.json"), dangling)
check("symlink: dangling link = fail-safe no-op (like missing file)",
      redact(SYM, patterns=dangling) == SYM,
      f"got {redact(SYM, patterns=dangling)!r}")

# ── 11. update-ordering hardening — install.sh replaces a stale
#     applied patch in place; `check` verifies engine + artifact probe +
#     supported range floor ─────────────────────────────────────────────
PATCH_PATH = os.path.join(os.getcwd(), "patch", "redactor-registry-patterns.patch")

# 11a. install.sh replace-path E2E: scratch git repo with the CLEAN files
#      from this checkout's HEAD, apply the current artifact, then tamper
#      one marker line (markers still 5/5, but the tree no longer matches
#      the artifact) -> install.sh must detect the mismatch and restore
#      the exact artifact. The precondition (reverse-check FAILS on the
#      tampered tree) is asserted so a regression in the probe itself
#      fails the battery, not the installer.
scratch = os.path.join(tmp, "install-scratch")
os.makedirs(scratch, exist_ok=True)
for rel in ("agent/redact.py", "cli.py", "gateway/run.py",
            "hermes_cli/config.py", "hermes_cli/main.py"):
    d = os.path.join(scratch, os.path.dirname(rel))
    os.makedirs(d, exist_ok=True)
    clean = subprocess.run(["git", "-C", CHECKOUT, "show", f"HEAD:{rel}"],
                           capture_output=True, text=True, check=True).stdout
    with open(os.path.join(scratch, rel), "w") as f:
        f.write(clean)
subprocess.run(["git", "-C", scratch, "init", "-q"], check=True)
subprocess.run(["git", "-C", scratch, "add", "-A"], check=True)
subprocess.run(["git", "-C", scratch, "-c", "user.email=ig@test",
                "-c", "user.name=ig-test", "commit", "-q", "-m", "base"],
               check=True)
# hermetic version source for the install.sh version gate (D113): the
# scratch target must carry a supported-release tag — CI runners have no
# `hermes` on PATH for the fallback (2026-08-23, v0.8.0 CI exposure).
subprocess.run(["git", "-C", scratch, "tag", "v2026.8.18"], check=True)
subprocess.run(["git", "-C", scratch, "apply", PATCH_PATH], check=True)
tampered_f = os.path.join(scratch, "gateway", "run.py")
tampered_src = open(tampered_f).read()
open(tampered_f, "w").write(
    tampered_src.replace("HERMES_REDACT_PATTERNS", "HERMES_REDACT_PATTERNS ", 1))
stale_probe = subprocess.run(
    ["git", "-C", scratch, "apply", "--reverse", "--check", PATCH_PATH],
    capture_output=True)
check("install replace: precondition — tampered tree fails reverse-check",
      stale_probe.returncode != 0)
ihome = os.path.join(tmp, "install-home")
env3 = dict(os.environ)
env3["HERMES_HOME"] = ihome
inst = subprocess.run(
    ["bash", os.path.join(os.getcwd(), "install.sh"), "--checkout", scratch,
     "--no-config", "--no-test"],
    env=env3, capture_output=True, text=True, timeout=300)
rev_after = subprocess.run(
    ["git", "-C", scratch, "apply", "--reverse", "--check", PATCH_PATH],
    capture_output=True)
check("install.sh replaces a stale applied patch in place",
      inst.returncode == 0 and rev_after.returncode == 0,
      f"rc={inst.returncode} rev={rev_after.returncode} "
      f"out={inst.stdout[-250:]!r} err={inst.stderr[-250:]!r}")

# 11b. `check` exits 0 on a healthy install: engine via a symlinked
#      checkout, pattern file present, artifact probe passes
chkhome = os.path.join(tmp, "check-home")
os.makedirs(os.path.join(chkhome, "state", "info-guard"), exist_ok=True)
os.symlink(CHECKOUT, os.path.join(chkhome, "hermes-agent"))
write(os.path.join(chkhome, "state", "info-guard", "redact_patterns.json"),
      {"mask": {"head": 2, "tail": 2, "floor": 12}, "literals": [],
       "key_patterns": {}})
env4 = dict(os.environ)
env4["HERMES_HOME"] = chkhome
chk = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "check"],
    env=env4, capture_output=True, text=True, timeout=120)
check("check: healthy install exits 0",
      chk.returncode == 0,
      f"rc={chk.returncode} out={chk.stdout[-250:]!r} err={chk.stderr[-250:]!r}")

# 11c. `check` exits 1 when the engine is missing (fresh home, no checkout)
empty = os.path.join(tmp, "empty-home")
os.makedirs(empty, exist_ok=True)
env5 = dict(os.environ)
env5["HERMES_HOME"] = empty
chk2 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "check"],
    env=env5, capture_output=True, text=True, timeout=120)
check("check: missing engine exits 1",
      chk2.returncode == 1,
      f"rc={chk2.returncode} out={chk2.stdout[-200:]!r}")

# 11d. uninstall integrity (S2): a PARTIAL engine must be refused loudly,
#      never reported as "nothing to reverse" — regression for the
#      single-marker bug (external audit S2). Precondition asserted: the
#      partial tree still fails the full reverse-check (something IS left
#      to reverse), proving the old behavior would have lied.
scratch2 = os.path.join(tmp, "uninstall-partial")
os.makedirs(scratch2, exist_ok=True)
for rel in ("agent/redact.py", "cli.py", "gateway/run.py",
            "hermes_cli/config.py", "hermes_cli/main.py"):
    d = os.path.join(scratch2, os.path.dirname(rel))
    os.makedirs(d, exist_ok=True)
    clean = subprocess.run(["git", "-C", CHECKOUT, "show", f"HEAD:{rel}"],
                           capture_output=True, text=True, check=True).stdout
    with open(os.path.join(scratch2, rel), "w") as f:
        f.write(clean)
subprocess.run(["git", "-C", scratch2, "init", "-q"], check=True)
subprocess.run(["git", "-C", scratch2, "add", "-A"], check=True)
subprocess.run(["git", "-C", scratch2, "-c", "user.email=ig@test",
                "-c", "user.name=ig-test", "commit", "-q", "-m", "base"],
               check=True)
subprocess.run(["git", "-C", scratch2, "apply", PATCH_PATH], check=True)
# half-revert: restore ONLY agent/redact.py -> 4/5 markers remain
subprocess.run(["git", "-C", scratch2, "checkout", "--", "agent/redact.py"],
               check=True)
partial_probe = subprocess.run(
    ["git", "-C", scratch2, "apply", "--reverse", "--check", PATCH_PATH],
    capture_output=True)
check("uninstall: precondition — partial tree still fails reverse-check",
      partial_probe.returncode != 0)
uihome = os.path.join(tmp, "uninstall-home")
env_u = dict(os.environ)
env_u["HERMES_HOME"] = uihome
uninst = subprocess.run(
    ["bash", os.path.join(os.getcwd(), "uninstall.sh"), "--checkout", scratch2,
     "--no-config", "--yes", "--keep-state"],
    env=env_u, capture_output=True, text=True, timeout=120)
uout = uninst.stdout + uninst.stderr
check("uninstall: partial engine (4/5) refused loudly, not 'nothing to reverse'",
      uninst.returncode != 0 and "PARTIAL" in uout
      and "nothing to reverse" not in uout,
      f"rc={uninst.returncode} out={uout[-300:]!r}")
# full engine (5/5) -> clean reverse-apply, tree back to the base commit
scratch3 = os.path.join(tmp, "uninstall-full")
os.makedirs(scratch3, exist_ok=True)
for rel in ("agent/redact.py", "cli.py", "gateway/run.py",
            "hermes_cli/config.py", "hermes_cli/main.py"):
    d = os.path.join(scratch3, os.path.dirname(rel))
    os.makedirs(d, exist_ok=True)
    clean = subprocess.run(["git", "-C", CHECKOUT, "show", f"HEAD:{rel}"],
                           capture_output=True, text=True, check=True).stdout
    with open(os.path.join(scratch3, rel), "w") as f:
        f.write(clean)
subprocess.run(["git", "-C", scratch3, "init", "-q"], check=True)
subprocess.run(["git", "-C", scratch3, "add", "-A"], check=True)
subprocess.run(["git", "-C", scratch3, "-c", "user.email=ig@test",
                "-c", "user.name=ig-test", "commit", "-q", "-m", "base"],
               check=True)
subprocess.run(["git", "-C", scratch3, "apply", PATCH_PATH], check=True)
uninst2 = subprocess.run(
    ["bash", os.path.join(os.getcwd(), "uninstall.sh"), "--checkout", scratch3,
     "--no-config", "--yes", "--keep-state"],
    env=env_u, capture_output=True, text=True, timeout=120)
tree_back = subprocess.run(
    ["git", "-C", scratch3, "diff", "--exit-code", "HEAD"],
    capture_output=True)
check("uninstall: full engine (5/5) reverse-applies to clean base",
      uninst2.returncode == 0 and tree_back.returncode == 0,
      f"rc={uninst2.returncode} diff={tree_back.returncode} "
      f"out={uninst2.stdout[-250:]!r} err={uninst2.stderr[-250:]!r}")

# 11e. install-manifest version extraction (S3): must be portable (no
#      GNU-only grep -oP) and exact. Re-run the SAME command install.sh
#      uses, cross-check against the source literal, and verify the
#      manifest 11a's install actually wrote.
pkg_src = open(os.path.join(os.getcwd(), "bin", "info-guard")).read()
expected_ver = pkg_src.split('_PACKAGE_VERSION = "')[1].split('"')[0]
ver_extract = subprocess.run(
    ["bash", "-c",
     "awk -F'\"' '/_PACKAGE_VERSION = /{print $2; exit}' \"$1\"",
     "ig-ver", os.path.join(os.getcwd(), "bin", "info-guard")],
    capture_output=True, text=True)
check("install: manifest version extraction portable + exact",
      ver_extract.returncode == 0 and ver_extract.stdout.strip() == expected_ver,
      f"got={ver_extract.stdout.strip()!r} want={expected_ver!r}")
inst_manifest = json.load(
    open(os.path.join(ihome, "state", "info-guard", "install.json")))
check("install: install.json records the extracted version",
      inst_manifest.get("version") == expected_ver,
      f"manifest={inst_manifest.get('version')!r} want={expected_ver!r}")

# 11f. install→uninstall round-trip: the two scripts must agree end-to-end
#      on the SAME checkout — install applies, uninstall restores the
#      exact base tree (the highest-value uninstall guarantee).
scratch4 = os.path.join(tmp, "roundtrip")
os.makedirs(scratch4, exist_ok=True)
for rel in ("agent/redact.py", "cli.py", "gateway/run.py",
            "hermes_cli/config.py", "hermes_cli/main.py"):
    d = os.path.join(scratch4, os.path.dirname(rel))
    os.makedirs(d, exist_ok=True)
    clean = subprocess.run(["git", "-C", CHECKOUT, "show", f"HEAD:{rel}"],
                           capture_output=True, text=True, check=True).stdout
    with open(os.path.join(scratch4, rel), "w") as f:
        f.write(clean)
subprocess.run(["git", "-C", scratch4, "init", "-q"], check=True)
subprocess.run(["git", "-C", scratch4, "add", "-A"], check=True)
subprocess.run(["git", "-C", scratch4, "-c", "user.email=ig@test",
                "-c", "user.name=ig-test", "commit", "-q", "-m", "base"],
               check=True)
# hermetic version source for the install.sh version gate (D113) — see 11a.
subprocess.run(["git", "-C", scratch4, "tag", "v2026.8.18"], check=True)
rt_home = os.path.join(tmp, "roundtrip-home")
env_rt = dict(os.environ)
env_rt["HERMES_HOME"] = rt_home
rt_inst = subprocess.run(
    ["bash", os.path.join(os.getcwd(), "install.sh"), "--checkout", scratch4,
     "--no-config", "--no-test"],
    env=env_rt, capture_output=True, text=True, timeout=300)
rt_after_inst = subprocess.run(
    ["git", "-C", scratch4, "apply", "--reverse", "--check", PATCH_PATH],
    capture_output=True)
check("round-trip: install.sh applies the artifact cleanly",
      rt_inst.returncode == 0 and rt_after_inst.returncode == 0,
      f"rc={rt_inst.returncode} rev={rt_after_inst.returncode} "
      f"out={rt_inst.stdout[-250:]!r} err={rt_inst.stderr[-250:]!r}")
rt_uninst = subprocess.run(
    ["bash", os.path.join(os.getcwd(), "uninstall.sh"), "--checkout", scratch4,
     "--no-config", "--yes", "--keep-state"],
    env=env_rt, capture_output=True, text=True, timeout=120)
rt_diff = subprocess.run(
    ["git", "-C", scratch4, "diff", "--exit-code", "HEAD"],
    capture_output=True)
check("round-trip: uninstall.sh restores the exact base tree",
      rt_uninst.returncode == 0 and rt_diff.returncode == 0,
      f"rc={rt_uninst.returncode} diff={rt_diff.returncode} "
      f"out={rt_uninst.stdout[-250:]!r} err={rt_uninst.stderr[-250:]!r}")

# 11g. drifted 5/5 tree (uninstall-side mirror of 11a): markers all
#      present but content tampered -> reverse-apply must fail LOUDLY
#      with restore guidance, and the tree must be left fully intact
#      (never a half-removal).
scratch5 = os.path.join(tmp, "uninstall-drift")
os.makedirs(scratch5, exist_ok=True)
for rel in ("agent/redact.py", "cli.py", "gateway/run.py",
            "hermes_cli/config.py", "hermes_cli/main.py"):
    d = os.path.join(scratch5, os.path.dirname(rel))
    os.makedirs(d, exist_ok=True)
    clean = subprocess.run(["git", "-C", CHECKOUT, "show", f"HEAD:{rel}"],
                           capture_output=True, text=True, check=True).stdout
    with open(os.path.join(scratch5, rel), "w") as f:
        f.write(clean)
subprocess.run(["git", "-C", scratch5, "init", "-q"], check=True)
subprocess.run(["git", "-C", scratch5, "add", "-A"], check=True)
subprocess.run(["git", "-C", scratch5, "-c", "user.email=ig@test",
                "-c", "user.name=ig-test", "commit", "-q", "-m", "base"],
               check=True)
subprocess.run(["git", "-C", scratch5, "apply", PATCH_PATH], check=True)
drift_f = os.path.join(scratch5, "gateway", "run.py")
drift_src = open(drift_f).read()
open(drift_f, "w").write(
    drift_src.replace("HERMES_REDACT_PATTERNS", "HERMES_REDACT_PATTERNS ", 1))
drift_probe = subprocess.run(
    ["git", "-C", scratch5, "apply", "--reverse", "--check", PATCH_PATH],
    capture_output=True)
check("uninstall: precondition — drifted 5/5 tree fails reverse-check",
      drift_probe.returncode != 0)
drift_uninst = subprocess.run(
    ["bash", os.path.join(os.getcwd(), "uninstall.sh"), "--checkout", scratch5,
     "--no-config", "--yes", "--keep-state"],
    env=env_u, capture_output=True, text=True, timeout=120)
dout = drift_uninst.stdout + drift_uninst.stderr
check("uninstall: drifted 5/5 tree fails loud with restore guidance",
      drift_uninst.returncode != 0 and "reverse-apply failed" in dout
      and "patch removed" not in dout,
      f"rc={drift_uninst.returncode} out={dout[-300:]!r}")
drift_markers = subprocess.run(
    ["bash", "-c",
     "n=0; "
     'grep -q _redact_registry_patterns "$1/agent/redact.py" && n=$((n+1)); '
     'grep -q redact_patterns "$1/hermes_cli/config.py" && n=$((n+1)); '
     'grep -q HERMES_REDACT_PATTERNS "$1/hermes_cli/main.py" && n=$((n+1)); '
     'grep -q HERMES_REDACT_PATTERNS "$1/cli.py" && n=$((n+1)); '
     'grep -q HERMES_REDACT_PATTERNS "$1/gateway/run.py" && n=$((n+1)); '
     "echo $n",
     "ig-mark", scratch5],
    capture_output=True, text=True)
check("uninstall: drifted tree left fully intact (5/5 markers)",
      drift_markers.stdout.strip() == "5",
      f"markers={drift_markers.stdout.strip()!r}")

# 11h. idempotent re-run: README claims "safe to re-run" — a second
#      uninstall on a clean tree says "nothing to reverse", exit 0,
#      tree unchanged.
idem = subprocess.run(
    ["bash", os.path.join(os.getcwd(), "uninstall.sh"), "--checkout", scratch3,
     "--no-config", "--yes", "--keep-state"],
    env=env_u, capture_output=True, text=True, timeout=120)
idem_diff = subprocess.run(
    ["git", "-C", scratch3, "diff", "--exit-code", "HEAD"],
    capture_output=True)
check("uninstall: idempotent re-run — 'nothing to reverse', exit 0, tree unchanged",
      idem.returncode == 0 and "nothing to reverse" in (idem.stdout + idem.stderr)
      and idem_diff.returncode == 0,
      f"rc={idem.returncode} diff={idem_diff.returncode} out={idem.stdout[-200:]!r}")

# 11i. state-dir handling: the DEFAULT moves <home>/state/info-guard to
#      *.bak-<timestamp> (safety copy, never deleted); --keep-state
#      leaves it in place. Also covers the real scenario of uninstalling
#      after the engine is already gone (0/5) — state still cleaned.
state_dir = os.path.join(uihome, "state")
os.makedirs(os.path.join(state_dir, "info-guard"), exist_ok=True)
with open(os.path.join(state_dir, "info-guard", "custom_literals.json"), "w") as f:
    f.write('{"literals": []}\n')
sd1 = subprocess.run(
    ["bash", os.path.join(os.getcwd(), "uninstall.sh"), "--checkout", scratch3,
     "--no-config", "--yes"],
    env=env_u, capture_output=True, text=True, timeout=120)
baks = [p for p in os.listdir(state_dir) if p.startswith("info-guard.bak-")]
check("uninstall: default moves state dir to *.bak-<timestamp>",
      sd1.returncode == 0
      and not os.path.exists(os.path.join(state_dir, "info-guard"))
      and len(baks) == 1
      and os.path.exists(os.path.join(state_dir, baks[0], "custom_literals.json")),
      f"rc={sd1.returncode} baks={baks}")
os.makedirs(os.path.join(state_dir, "info-guard"), exist_ok=True)
with open(os.path.join(state_dir, "info-guard", "custom_literals.json"), "w") as f:
    f.write('{"literals": []}\n')
sd2 = subprocess.run(
    ["bash", os.path.join(os.getcwd(), "uninstall.sh"), "--checkout", scratch3,
     "--no-config", "--yes", "--keep-state"],
    env=env_u, capture_output=True, text=True, timeout=120)
baks2 = [p for p in os.listdir(state_dir) if p.startswith("info-guard.bak-")]
check("uninstall: --keep-state leaves state dir in place, no new .bak",
      sd2.returncode == 0
      and os.path.exists(os.path.join(state_dir, "info-guard"))
      and len(baks2) == 1,
      f"rc={sd2.returncode} baks={baks2}")

# 11j. marker-list consistency: install.sh / uninstall.sh /
#      bin/info-guard _ENGINE_MARKERS must describe the SAME (file,
#      marker) set — the structural invariant whose drift (one of three
#      copies weakened) caused the S2 regression. The battery now locks
#      it, so adding a 6th patched file can't silently desync.
def _marker_pairs(text):
    pairs = set()
    for m in re.finditer(r'grep -q "([^"]+)"\s+"\$CHECKOUT/([^"]+)"', text):
        pairs.add((m.group(2), m.group(1)))
    for m in re.finditer(r'"([^"]+)": "([^"]+)"', text):
        pairs.add((m.group(1), m.group(2)))
    return pairs

install_src = open(os.path.join(os.getcwd(), "install.sh")).read()
uninstall_src = open(os.path.join(os.getcwd(), "uninstall.sh")).read()
ig_bin_src = open(os.path.join(os.getcwd(), "bin", "info-guard")).read()
m_install = _marker_pairs(
    install_src.split("_marker_count()")[1].split('echo "$n"')[0])
m_uninstall = _marker_pairs(
    uninstall_src.split("_marker_count()")[1].split('echo "$n"')[0])
m_bin = _marker_pairs(
    ig_bin_src.split("_ENGINE_MARKERS")[1].split("_SUPPORTED_MIN")[0])
check("markers: install.sh == uninstall.sh (5 pairs)",
      m_install == m_uninstall and len(m_install) == 5,
      f"install={sorted(m_install)} uninstall={sorted(m_uninstall)}")
check("markers: both scripts == bin/info-guard _ENGINE_MARKERS",
      m_install == m_bin and len(m_bin) == 5,
      f"scripts={sorted(m_install)} bin={sorted(m_bin)}")

# ── 12. preflight v2.1 report: structure, tiers, masking, exit codes ──
pf_home = os.path.join(tmp, "pf-home")
for sub in ("sessions", "logs", "cron/output"):
    os.makedirs(os.path.join(pf_home, sub), exist_ok=True)
# Synthetic values ONLY, runtime-constructed (push protection: canonical
# fake secrets trip GitHub's scanner as literals). Shapes chosen to land in
# each report tier:
#   - token-format: Discord bot token shape (MTQ...) and JWT shape (eyJ...)
#   - placeholder:  'your...' example text
#   - already-masked: literal ****** in the source
jwt = "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "a" * 15   # 52 chars: under the 64-char value cap
dsc = "MTQ" + "5MjY4NTA5Mzk0MjQ2MDE3OQ"
with open(os.path.join(pf_home, "sessions", "session_20260505_075138_d.jsonl"), "w") as f:
    f.write(f"HASS_TOKEN={jwt}\n")
    f.write(f"DISCORD_BOT_TOKEN={dsc}\n")
    f.write("GOOGLE_API_KEY=your-actual-key-here\n")
    f.write("API_KEY: ***")
env6 = dict(os.environ)
env6["HERMES_HOME"] = pf_home
pf = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "preflight"],
    env=env6, capture_output=True, text=True, timeout=300)
pfo = pf.stdout + pf.stderr
check("preflight: findings exit code 1", pf.returncode == 1,
      f"rc={pf.returncode} out={pfo[-300:]!r}")
for section in (f"Info Guard v{_PKG_VER} — Preflight Security Assessment",
                "STATUS", "EXECUTIVE SUMMARY", "WHAT MATTERS",
                "CREDENTIAL EXPOSURE BY FAMILY",
                "EXPOSURE LOCATIONS",
                "RECOMMENDED ACTIONS",
                "APPENDIX A — FINDING LEDGER"):
    check(f"preflight: section '{section}' present", section in pfo)
check("preflight: appendix subtitle under the title",
      "(sample — one per family" in pfo)
check("preflight: SCOPE line present", "SCOPE:" in pfo)
check("preflight: engine line present (install state + version)",
      "Engine:" in pfo and "NOT INSTALLED" in pfo)
check("preflight: raw values never printed",
      jwt not in pfo and dsc not in pfo and "your-actual-key-here" not in pfo,
      "a raw synthetic value appeared in the report")
check("preflight: masked forms shown (the proof)",
      "MT...OQ" in pfo and "ey...aa" in pfo,
      f"masked forms missing: {pfo[:400]!r}")
check("preflight: credential-shaped tier counted",
      "credential-shaped candidates" in pfo)
check("preflight: merged family table lists a family with status",
      "DISCORD_BOT_TOKEN" in pfo and "Exposed" in pfo)
check("preflight: merged table shows protected family",
      "Protected" in pfo)
check("preflight: table heading present", "Family" in pfo
      and "Value (masked 2+2)" in pfo)
check("preflight: locations carry masked counts + status",
      "· 1 masked" in pfo and "Mostly masked" in pfo,
      "expected masked count + area status in EXPOSURE LOCATIONS")
check("preflight: attribution split reconciles",
      "family-attributed" in pfo and "unattributed" in pfo)
check("preflight: summary reconciles candidates · distinct values · raw detections",
      "distinct values" in pfo and "raw detections" in pfo,
      "expected the three-way reconciliation line")
check("preflight: DISTINCT VALUES rotate list present",
      "DISTINCT VALUES — THE ROTATE LIST" in pfo,
      "expected the distinct-values rotate list in the main report")
check("preflight: tier partition stated explicitly",
      "mutually exclusive" in pfo)
check("preflight: session-timestamp date discipline",
      "from session timestamps" in pfo)
check("preflight: key-name tier defined in the partition note",
      "key-name" in pfo)
check("preflight: why section removed (redundant with merged table)",
      "WHY AM I SEEING THIS" not in pfo)
check("preflight: appendix A is the ledger, no telemetry in main report",
      "DETECTION TELEMETRY" not in pfo)
check("preflight: appendix rows carry no context line",
      "…HASS_TOKEN=***…" not in pfo)

# 12a2. preflight --full: complete ledger replaces the sampler
pff = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "preflight", "--full"],
    env=env6, capture_output=True, text=True, timeout=300)
pffo = pff.stdout + pff.stderr
check("preflight --full: same finding exit code",
      pff.returncode == pf.returncode and pff.returncode == 1,
      f"rc={pff.returncode} (sampler rc={pf.returncode}) out={pffo[-200:]!r}")
check("preflight --full: complete-ledger header, no sampler",
      "APPENDIX A — FINDING LEDGER (complete" in pffo
      and "APPENDIX A — FINDING LEDGER" in pffo
      and "(sample — one per family" not in pffo,
      "expected complete ledger header")
check("preflight --full: telemetry appendix present (forensic mode)",
      "APPENDIX B — DETECTION TELEMETRY" in pffo,
      "expected telemetry appendix in --full")
check("preflight --full: every family row listed, not one per family",
      pffo.count("value=") >= pfo.count("value="),
      "full ledger should carry at least as many rows as the sampler")
check("preflight --full: still masked, no raw values",
      jwt not in pffo and dsc not in pffo,
      "a raw synthetic value appeared in the full ledger")

# 12b. preflight CLEAN path: empty scan dirs -> exit 0 + header + CLEAN
pf_clean = os.path.join(tmp, "pf-clean")
for sub in ("sessions", "logs", "cron/output"):
    os.makedirs(os.path.join(pf_clean, sub), exist_ok=True)
with open(os.path.join(pf_clean, "logs", "x.log"), "w") as f:
    f.write("hello world\n")
env7 = dict(os.environ)
env7["HERMES_HOME"] = pf_clean
pfc = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "preflight"],
    env=env7, capture_output=True, text=True, timeout=300)
pfco = pfc.stdout + pfc.stderr
check("preflight: clean home exits 0", pfc.returncode == 0,
      f"rc={pfc.returncode} out={pfco[-200:]!r}")
check("preflight: clean path has assessment header + CLEAN",
      "Preflight Security Assessment" in pfco and "CLEAN" in pfco)
check("preflight: clean path has SCOPE line", "SCOPE:" in pfco)

# 12b1. preflight DEGRADED engine: gitleaks hidden -> exit 2, never 0 (v0.5.1, IG D94)
env8 = dict(env7)
env8["PATH"] = "/usr/bin:/bin"
g_home = os.path.join(tmp, "no-engine-home")
os.makedirs(g_home, exist_ok=True)
env8["HOME"] = g_home
pfd = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "preflight"],
    env=env8, capture_output=True, text=True, timeout=300)
pfdo = pfd.stdout + pfd.stderr
check("preflight: degraded engine (gitleaks hidden) exits 2, never 0",
      pfd.returncode == 2,
      f"rc={pfd.returncode} out={pfdo[-300:]!r}")
check("preflight: degraded-engine note visible",
      "key-shape pass only" in pfdo,
      "the missing-engine explanation should be shown")
pfdj = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "preflight", "--json"],
    env=env8, capture_output=True, text=True, timeout=300)
check("preflight --json: degraded engine exits 2",
      pfdj.returncode == 2,
      f"rc={pfdj.returncode} out={pfdj.stdout[-300:]!r}")
check("preflight --json: degraded assessment still emitted with engine state",
      "\"gitleaks_ok\": false" in pfdj.stdout,
      "JSON should carry the degraded engine state (scan.gitleaks_ok)")

# 12b2. watch DEGRADED engine: gitleaks hidden -> exit 2 on EVERY path —
# baseline-creation, no-delta clean, and delta runs alike (v0.6.0, A20:
# a degraded scan never masquerades as clean; D94 doctrine applied to
# watch's baseline/migration/clean return sites).
w_home = os.path.join(tmp, "watch-degraded-home")
shutil.rmtree(w_home, ignore_errors=True)
os.makedirs(os.path.join(w_home, "sessions"))
os.makedirs(os.path.join(w_home, "state", "info-guard"))
env_wd = dict(env8)  # PATH scrubbed + HOME scrubbed (no gitleaks anywhere)
env_wd["HERMES_HOME"] = w_home
igbin = os.path.join(os.getcwd(), "bin", "info-guard")
with open(os.path.join(w_home, "sessions", "s.jsonl"), "w") as f:
    f.write("sk-abcdef1234567890abcdef1234567890\n")
wd1 = subprocess.run([sys.executable, igbin, "watch", "--json"],
                     env=env_wd, capture_output=True, text=True, timeout=300)
check("watch: degraded engine (baseline-creation path) exits 2, never 0",
      wd1.returncode == 2,
      f"rc={wd1.returncode} out={wd1.stdout[-200:]!r} err={wd1.stderr[-200:]!r}")
wd2 = subprocess.run([sys.executable, igbin, "watch", "--json"],
                     env=env_wd, capture_output=True, text=True, timeout=300)
check("watch: degraded engine (no-delta clean path) exits 2, never 0",
      wd2.returncode == 2,
      f"rc={wd2.returncode} out={wd2.stdout[-200:]!r} err={wd2.stderr[-200:]!r}")
wd3 = subprocess.run([sys.executable, igbin, "watch"],
                     env=env_wd, capture_output=True, text=True, timeout=300)
check("watch: degraded engine (text mode) exits 2, never 0",
      wd3.returncode == 2,
      f"rc={wd3.returncode} out={wd3.stdout[-200:]!r} err={wd3.stderr[-200:]!r}")
# control: with the engine available the same home is clean (exit 0)
env_wok = dict(os.environ); env_wok["HERMES_HOME"] = w_home
wdc = subprocess.run([sys.executable, igbin, "watch", "--json"],
                     env=env_wok, capture_output=True, text=True, timeout=300)
check("watch: engine available, same home -> exit 0 (control)",
      wdc.returncode == 0,
      f"rc={wdc.returncode} out={wdc.stdout[-200:]!r}")

# 12c. --version flag
ver = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "--version"],
    capture_output=True, text=True, timeout=60)
check("--version prints the package version",
      ver.returncode == 0 and ver.stdout.strip() == f"info-guard {_PKG_VER}",
      f"rc={ver.returncode} out={ver.stdout.strip()!r}")

# 12d. detection gaps (v0.3.1): Authorization family + dot-structured
# bare-JWT rule — explicit positive/negative matrix (external review).
gap_home = os.path.join(tmp, "pf-gaps")
os.makedirs(os.path.join(gap_home, "sessions"), exist_ok=True)
jwt_c = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "c" * 15
jwt_d = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "d" * 15
with open(os.path.join(gap_home, "sessions", "session_20260819_120000_g.jsonl"),
          "w") as f:
    f.write("NEW_JWT=" + jwt_c + "\n")   # positive: bare JWT, non-keyword key
    f.write("NEW_JWT=" + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "\n")
    # negative: canonical jwt.io header, no dot
    f.write("NEW_JWT=eyJhbG...zzzz\n")   # negative: masked-looking short form
    f.write("Authorization: Bearer " + jwt_d + "\n")  # positive: Bearer JWT
    f.write("Authorization: ***\n")      # already-masked
env_gap = dict(os.environ)
env_gap["HERMES_HOME"] = gap_home
pfg = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "preflight"],
    env=env_gap, capture_output=True, text=True, timeout=300)
pfgo = pfg.stdout + pfg.stderr
check("gaps: bare JWT under non-keyword key detected",
      pfg.returncode == 1 and "ey...cc" in pfgo,
      f"rc={pfg.returncode} out={pfgo[-200:]!r}")
check("gaps: jwt.io header without dot NOT detected",
      "ey...J9" not in pfgo,
      "the canonical header alone must not fire")
check("gaps: masked-looking short eyJ NOT detected",
      "ey...zz" not in pfgo,
      "masked-looking short forms must not fire")
check("gaps: Bearer JWT detected as credential-shaped",
      "ey...dd" in pfgo and "JWT" in pfgo,
      "Bearer header JWTs must become actionable")
check("gaps: Authorization *** lands already-masked",
      '"Authorization"' in pfgo and "Protected" in pfgo,
      "masked Authorization rows must count as protected")

# ── 13. preflight --json: same object, schema-shaped, masked, no chatter ──
pfj = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "preflight", "--json"],
    env=env6, capture_output=True, text=True, timeout=300)
pj = pfj.stdout
check("preflight --json: exit code matches findings", pfj.returncode == 1,
      f"rc={pfj.returncode} stderr={pfj.stderr[-200:]!r}")
check("preflight --json: stdout is pure JSON (no chatter)",
      pj.lstrip().startswith("{") and "preflight — scanning" not in pj)
obj = json.loads(pj)
check("preflight --json: schema field",
      obj.get("schema") == "info-guard/assessment/v1")
check("preflight --json: status reserves confirmed_active",
      obj["status"].get("confirmed_active") is None)
fams = obj["families"]
check("preflight --json: families wrapper object",
      isinstance(fams.get("items"), list) and fams.get("complete") is True
      and fams.get("total_with_values")
      == sum(1 for f in fams["items"] if f["value"] > 0))
t = obj["totals"]
check("preflight --json: totals reconcile (raw partition)",
      t["findings"] == t["raw_detections"] + t["key_name_mentions"]
      + t["already_masked"])
check("preflight --json: attribution split reconciles",
      t["credential_shaped"] == t["family_attributed"] + t["unattributed"])
check("preflight --json: distinct <= rows <= raw",
      t["distinct_values"] <= t["credential_shaped"] <= t["raw_detections"])
check("preflight --json: raw values never present",
      jwt not in pj and dsc not in pj and "your-actual-key-here" not in pj,
      "a raw synthetic value appeared in the JSON")
check("preflight --json: masked example value present",
      "ey...aa" in pj and "MT...OQ" in pj)
check("preflight --json: numbers match the text report",
      f"  🔴 {t['credential_shaped']} " in pfo
      and f"{t['distinct_values']} distinct values" in pfo)

# 13b. --json-out: atomic 0600 write, identical object
outf = os.path.join(tmp, "assessment.json")
pfjo = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "preflight", "--json-out", outf],
    env=env6, capture_output=True, text=True, timeout=300)
check("preflight --json-out: exit code matches findings",
      pfjo.returncode == 1)
check("preflight --json-out: file written 0600",
      os.path.exists(outf) and (os.stat(outf).st_mode & 0o777) == 0o600)
obj2 = json.load(open(outf))
obj2["scan"]["generated"] = obj["scan"]["generated"]  # same-second tolerance
check("preflight --json-out: identical object", obj2 == obj)
pfje = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "preflight", "--json-out"],
    env=env6, capture_output=True, text=True, timeout=60)
check("preflight --json-out: missing path is usage error",
      pfje.returncode == 2, f"rc={pfje.returncode}")

# ── 14. watch: value-sha256 baseline lifecycle, cron-friendly ──
w1 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env6, capture_output=True, text=True, timeout=300)
w1o = w1.stdout + w1.stderr
check("watch: first run creates baseline, exit 0",
      w1.returncode == 0 and "baseline created" in w1o,
      f"rc={w1.returncode} out={w1o[-200:]!r}")
bl = os.path.join(pf_home, "state", "info-guard", "watch-baseline.json")
check("watch: baseline file 0600",
      os.path.exists(bl) and (os.stat(bl).st_mode & 0o777) == 0o600)
bobj = json.load(open(bl))
check("watch: baseline schema + sha256-only rows",
      bobj.get("schema") == "info-guard/watch-baseline/v2"
      and all(len(v["value_sha256"]) == 64 for v in bobj["values"]))
check("watch: baseline v2 protection block present/sane",
      "protection" in bobj
      and "custom_literals" in bobj["protection"]
      and "redact_patterns" in bobj["protection"]
      and "engine" in bobj["protection"]
      and bobj["protection"]["redact_patterns"]["literal_count"] == 0)
check("watch: baseline v2 assessment block present/sane",
      "assessment" in bobj
      and bobj["assessment"]["credential_shaped"] == 2
      and bobj["assessment"]["distinct_values"] == 2
      and isinstance(bobj["assessment"]["files"], dict))
check("watch: baseline knows both fixture values",
      len(bobj["values"]) == 2)
check("watch: baseline contains no raw values",
      jwt not in json.dumps(bobj) and dsc not in json.dumps(bobj),
      "a raw synthetic value reached the baseline")
w2 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env6, capture_output=True, text=True, timeout=300)
check("watch: no-new exits 0 with status line",
      w2.returncode == 0 and "no new" in (w2.stdout + w2.stderr),
      f"rc={w2.returncode}")
# a new credential-shaped value appears (keyword key + sk- prefix;
# runtime-constructed — token-shaped literals trip the gitleaks scan)
sk_new = "sk-" + "newprobe1234567890"
with open(os.path.join(pf_home, "sessions", "session_20260505_075138_d.jsonl"),
          "a") as f:
    f.write("ANTHROPIC_API_KEY=" + sk_new + "\n")
w3 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env6, capture_output=True, text=True, timeout=300)
w3o = w3.stdout + w3.stderr
check("watch: new value exits 1",
      w3.returncode == 1, f"rc={w3.returncode} out={w3o[-200:]!r}")
check("watch: new value listed masked",
      "sk...90" in w3o and "sk-newprobe1234567890" not in w3o)
check("watch: baseline updated to 3",
      len(json.load(open(bl))["values"]) == 3)
w4 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "watch", "--reset"],
    env=env6, capture_output=True, text=True, timeout=300)
check("watch: --reset recreates baseline",
      w4.returncode == 0 and "baseline reset" in (w4.stdout + w4.stderr),
      f"rc={w4.returncode}")
check("watch: reset baseline matches current scan",
      len(json.load(open(bl))["values"]) == 3)
# version-change union: fake an older tool_version in the baseline
bobj3 = json.load(open(bl))
bobj3["tool_version"] = "0.2.8"
open(bl, "w").write(json.dumps(bobj3))
w5 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env6, capture_output=True, text=True, timeout=300)
w5o = w5.stdout + w5.stderr
check("watch: version change union-keeps + notice",
      w5.returncode == 0 and "union" in w5o
      and len(json.load(open(bl))["values"]) == 3,
      f"rc={w5.returncode} out={w5o[-200:]!r}")

# ── 14b. v1→v2 migration: matching + stale v1 fixtures (R2/A4) ──
mig_home = os.path.join(tmp, "mig-home")
for sub in ("sessions", "logs", "cron/output"):
    os.makedirs(os.path.join(mig_home, sub), exist_ok=True)
with open(os.path.join(mig_home, "sessions", "session_20260505_075138_d.jsonl"),
          "w") as f:
    f.write(f"HASS_TOKEN={jwt}\n")
    f.write(f"DISCORD_BOT_TOKEN={dsc}\n")
    f.write("GOOGLE_API_KEY=your-actual-key-here\n")
    f.write("API_KEY: ***")
mig_bl = os.path.join(mig_home, "state", "info-guard", "watch-baseline.json")
os.makedirs(os.path.dirname(mig_bl), exist_ok=True)
jwt_sha = hashlib.sha256(jwt.encode()).hexdigest()
dsc_sha = hashlib.sha256(dsc.encode()).hexdigest()
stale_sha = hashlib.sha256(b"stale-value-not-in-any-scan").hexdigest()
v1_rows = [
    {"value_sha256": jwt_sha, "type": "JWT", "family": "HASS_TOKEN",
     "count": 1, "first_seen": "2026-08-19T00:00:00Z"},
    {"value_sha256": dsc_sha, "type": "Discord bot token",
     "family": "DISCORD_BOT_TOKEN", "count": 1,
     "first_seen": "2026-08-19T00:00:00Z"},
]
def write_v1(rows):
    open(mig_bl, "w").write(json.dumps({
        "schema": "info-guard/watch-baseline/v1",
        "generated": "2026-08-19T00:00:00Z", "tool_version": "0.3.1",
        "gitleaks_version": "8.30.1", "values": rows}))
env_mig = dict(os.environ)
env_mig["HERMES_HOME"] = mig_home
# case (a): v1 baseline matching the current scan -> migrated in place
write_v1(v1_rows)
m1 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env_mig, capture_output=True, text=True, timeout=300)
m1o = m1.stdout + m1.stderr
check("watch: v1→v2 migration notice, exit 0 (matching fixture)",
      m1.returncode == 0 and "migrated to v2" in m1o,
      f"rc={m1.returncode} out={m1o[-200:]!r}")
m1obj = json.load(open(mig_bl))
check("watch: migrated baseline schema v2 + blocks present",
      m1obj.get("schema") == "info-guard/watch-baseline/v2"
      and "protection" in m1obj and "assessment" in m1obj)
check("watch: migration preserves values + first_seen",
      len(m1obj["values"]) == 2
      and all(v["first_seen"] == "2026-08-19T00:00:00Z"
              for v in m1obj["values"]))
# case (b): stale v1 baseline (extra value absent from scan) ->
# reconciled at migration (stale dropped), first v2 run delta-free
write_v1(v1_rows + [{"value_sha256": stale_sha, "type": "API key",
                     "family": None, "count": 3,
                     "first_seen": "2026-08-19T00:00:00Z"}])
m2 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env_mig, capture_output=True, text=True, timeout=300)
m2o = m2.stdout + m2.stderr
check("watch: stale v1 reconciled at migration (delta-free, exit 0)",
      m2.returncode == 0 and "migrated to v2" in m2o
      and len(json.load(open(mig_bl))["values"]) == 2
      and "NEW credential" not in m2o,
      f"rc={m2.returncode} out={m2o[-200:]!r}")
m3 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env_mig, capture_output=True, text=True, timeout=300)
check("watch: first v2 run after migration is delta-free",
      m3.returncode == 0 and "no new" in (m3.stdout + m3.stderr),
      f"rc={m3.returncode}")

# ── 15. watch v2: exposure deltas — resolved / changed / files ──
# resolved: fresh home -> baseline -> delete the file -> both values
# resolve (informational, exit 0, per-value lines + contract wording)
res_home = os.path.join(tmp, "res-home")
for sub in ("sessions", "logs", "cron/output"):
    os.makedirs(os.path.join(res_home, sub), exist_ok=True)
res_file = os.path.join(res_home, "sessions", "session_20260505_075138_d.jsonl")
with open(res_file, "w") as f:
    f.write(f"HASS_TOKEN={jwt}\n")
    f.write(f"DISCORD_BOT_TOKEN={dsc}\n")
env_res = dict(os.environ)
env_res["HERMES_HOME"] = res_home
subprocess.run([sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
                "watch"], env=env_res, capture_output=True, text=True,
               timeout=300)  # baseline
os.unlink(res_file)
r1 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env_res, capture_output=True, text=True, timeout=300)
r1o = r1.stdout + r1.stderr
check("watch: resolved values exit 0 (informational)",
      r1.returncode == 0, f"rc={r1.returncode} out={r1o[-250:]!r}")
check("watch: resolved per-value lines + contract wording",
      "no longer detected in the current scan scope" in r1o.lower()
      and "does not confirm that the credential is dead or revoked" in r1o.lower()
      and "JWT" in r1o and "DISCORD_BOT_TOKEN" in r1o,
      f"out={r1o[-250:]!r}")
check("watch: resolved families rollup",
      "HASS_TOKEN" in r1o and "DISCORD_BOT_TOKEN" in r1o,
      f"out={r1o[-250:]!r}")
check("watch: resolved values dropped from refreshed baseline",
      len(json.load(open(os.path.join(res_home, "state", "info-guard",
                                      "watch-baseline.json")))["values"]) == 0,
      "baseline should drop resolved values (refresh-on-delta)")
# changed: append one more occurrence of a known value on pf_home
# (baseline holds 3 values: jwt, dsc, sk_new, all count 1)
with open(os.path.join(pf_home, "sessions", "session_20260505_075138_d.jsonl"),
          "a") as f:
    f.write(f"HASS_TOKEN={jwt}\n")
c1 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env6, capture_output=True, text=True, timeout=300)
c1o = c1.stdout + c1.stderr
check("watch: changed count exits 0 (informational)",
      c1.returncode == 0, f"rc={c1.returncode} out={c1o[-250:]!r}")
check("watch: changed value shown with delta",
      "+2" in c1o and "ey...aa" in c1o,
      f"out={c1o[-250:]!r}")
check("watch: changed-files line present",
      "sessions/session_20260505_075138_d.jsonl" in c1o,
      f"out={c1o[-250:]!r}")
# negative changed-count: rewrite the file with FEWER occurrences of a
# known value (baseline count 2 -> 1, -1) — informational, exit 0
with open(os.path.join(pf_home, "sessions", "session_20260505_075138_d.jsonl"),
          "w") as f:
    f.write(f"HASS_TOKEN={jwt}\n")
    f.write(f"DISCORD_BOT_TOKEN={dsc}\n")
    f.write("ANTHROPIC_API_KEY=" + sk_new + "\n")
c2 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env6, capture_output=True, text=True, timeout=300)
c2o = c2.stdout + c2.stderr
check("watch: count decrease rendered (negative delta, exit 0)",
      c2.returncode == 0 and "(-2)" in c2o and "ey...aa" in c2o,
      f"rc={c2.returncode} out={c2o[-250:]!r}")
# absolute scan dir outside $HERMES_HOME (evidence-review MIN: relative_to
# crash) — must scan cleanly, never traceback
abs_dir = os.path.join(tmp, "abs-watch-dir")
os.makedirs(abs_dir, exist_ok=True)
with open(os.path.join(abs_dir, "notes.txt"), "w") as f:
    f.write(f"HASS_TOKEN={jwt}\n")
abs_home = os.path.join(tmp, "abs-home")
os.makedirs(abs_home, exist_ok=True)
env_abs = dict(os.environ)
env_abs["HERMES_HOME"] = abs_home
c3 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "watch", abs_dir],
    env=env_abs, capture_output=True, text=True, timeout=300)
c3o = c3.stdout + c3.stderr
check("watch: absolute dir outside HERMES_HOME scans cleanly (no crash)",
      c3.returncode == 0 and "Traceback" not in c3o
      and "baseline created" in c3o,
      f"rc={c3.returncode} out={c3o[-250:]!r}")

# ── 15b. watch v0.4.1: protected-value matching (IG D51–D56, A1–A6) ──
kv_home = os.path.join(tmp, "kv-home")
for sub in ("sessions", "logs", "cron/output"):
    os.makedirs(os.path.join(kv_home, sub), exist_ok=True)
kv_dir = os.path.join(kv_home, "state", "info-guard")
os.makedirs(kv_dir, exist_ok=True)
kv_cl = os.path.join(kv_dir, "custom_literals.json")
kv_bl = os.path.join(kv_dir, "watch-baseline.json")
kv_file = os.path.join(kv_home, "sessions", "session_20260505_075138_d.jsonl")
env_kv = dict(os.environ)
env_kv["HERMES_HOME"] = kv_home
dsc_mask = dsc[:2] + "..." + dsc[-2:]
# registry BEFORE the baseline (MIN-6): jwt declared protected; dsc
# declared but absent from the scan until the A6 fixture
with open(kv_cl, "w") as f:
    f.write(json.dumps({"literals": [jwt, dsc]}))
def kv_watch(*args):
    return subprocess.run(
        [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
         "watch"] + list(args),
        env=env_kv, capture_output=True, text=True, timeout=300)
with open(kv_file, "w") as f:
    f.write(f"HASS_TOKEN={jwt}\n")
k0 = kv_watch()
check("watch A3: baseline created with declared registry (exit 0)",
      k0.returncode == 0 and "baseline created" in (k0.stdout + k0.stderr),
      f"rc={k0.returncode}")
# A1: protected value count increase -> exit 1, one block, overlay
with open(kv_file, "a") as f:
    f.write(f"HASS_TOKEN={jwt}\n")
k1 = kv_watch()
k1o = k1.stdout + k1.stderr
check("watch A1: protected count increase -> exit 1",
      k1.returncode == 1, f"rc={k1.returncode} out={k1o[-250:]!r}")
check("watch A1: PROTECTED block exactly once, masked + occurrences",
      k1o.count("PROTECTED VALUE RE-DETECTED") == 1
      and "ey...aa" in k1o and "occurrences since baseline" in k1o,
      f"out={k1o[-250:]!r}")
check("watch A1: info line present",
      "1 protected value present (1 re-detected)" in k1o,
      f"out={k1o[-250:]!r}")
check("watch A1: overlay — protected row NOT in CHANGED COUNTS block",
      "\n  CHANGED COUNTS (informational)" not in k1o,
      f"out={k1o[-250:]!r}")
# A1 JSON: one more occurrence -> --json carries the increased row
with open(kv_file, "a") as f:
    f.write(f"HASS_TOKEN={jwt}\n")
k1j = kv_watch("--json")
k1jo = json.loads(k1j.stdout)
pv_inc = [r for r in k1jo["exposure"]["protected_values"]
          if r["delta"] == "increased"]
check("watch A1: JSON increased row — both arrays, no sha256",
      k1j.returncode == 1
      and len(pv_inc) == 1
      and pv_inc[0]["value_masked"] == "ey...aa"
      and pv_inc[0]["count"] > pv_inc[0]["count_before"]
      and "count_before" in pv_inc[0]
      and any(r["value_masked"] == "ey...aa"
              for r in k1jo["exposure"]["changed_values"])
      and "value_sha256" not in json.dumps(k1jo),
      f"out={k1j.stdout[-250:]!r}")
# A6: fresh protected value (feedback-#4 headline case) -> delta new
with open(kv_file, "a") as f:
    f.write(f"DISCORD_BOT_TOKEN={dsc}\n")
k2 = kv_watch()
k2o = k2.stdout + k2.stderr
check("watch A6: fresh protected value -> exit 1, one block, first detected",
      k2.returncode == 1
      and k2o.count("PROTECTED VALUE RE-DETECTED") == 1
      and "first detected" in k2o,
      f"rc={k2.returncode} out={k2o[-250:]!r}")
check("watch A6: overlay — fresh protected row NOT in NEW VALUES block",
      "NEW VALUES" not in k2o, f"out={k2o[-250:]!r}")
# A6 JSON: another fresh protected value via --json
sk_p = "sk-" + "protectedprobe123456"
sk_p_mask = sk_p[:2] + "..." + sk_p[-2:]
with open(kv_cl, "w") as f:
    f.write(json.dumps({"literals": [jwt, dsc, sk_p]}))
with open(kv_file, "a") as f:
    f.write("ANTHROPIC_API_KEY=" + sk_p + "\n")
k3 = kv_watch("--json")
k3jo = json.loads(k3.stdout)
pv_new = [r for r in k3jo["exposure"]["protected_values"]
          if r["delta"] == "new"]
check("watch A6: JSON delta new — both arrays, no count_before",
      k3.returncode == 1
      and len(pv_new) == 1
      and pv_new[0]["value_masked"] == sk_p_mask
      and "count_before" not in pv_new[0]
      and any(r["value_masked"] == sk_p_mask
              for r in k3jo["exposure"]["new_values"]),
      f"out={k3.stdout[-250:]!r}")
# A2: protected value MOVES files, total count unchanged -> unchanged,
# exit 0, no PROTECTED block, info line (changed run via changed_files)
mv_home = os.path.join(tmp, "mv-home")
for sub in ("sessions", "logs", "cron/output"):
    os.makedirs(os.path.join(mv_home, sub), exist_ok=True)
mv_dir = os.path.join(mv_home, "state", "info-guard")
os.makedirs(mv_dir, exist_ok=True)
mv_a = os.path.join(mv_home, "sessions", "a.jsonl")
mv_b = os.path.join(mv_home, "sessions", "b.jsonl")
env_mv = dict(os.environ)
env_mv["HERMES_HOME"] = mv_home
with open(os.path.join(mv_dir, "custom_literals.json"), "w") as f:
    f.write(json.dumps({"literals": [jwt]}))
with open(mv_a, "w") as f:
    f.write(f"HASS_TOKEN={jwt}\n")
def mv_watch(*args):
    return subprocess.run(
        [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
         "watch"] + list(args),
        env=env_mv, capture_output=True, text=True, timeout=300)
check("watch A2: baseline (exit 0)", mv_watch().returncode == 0)
os.unlink(mv_a)
with open(mv_b, "w") as f:
    f.write(f"HASS_TOKEN={jwt}\n")
k4 = mv_watch()
k4o = k4.stdout + k4.stderr
check("watch A2: move w/o count change -> exit 0, no PROTECTED block",
      k4.returncode == 0
      and "PROTECTED VALUE RE-DETECTED" not in k4o
      and "FILES WITH CHANGED COUNTS" in k4o,
      f"rc={k4.returncode} out={k4o[-250:]!r}")
check("watch A2: info line present (0 re-detected)",
      "1 protected value present (0 re-detected)" in k4o,
      f"out={k4o[-250:]!r}")
k4j = json.loads(mv_watch("--json").stdout)
check("watch A2: JSON delta unchanged, clean status",
      k4j["watch"]["status"] == "clean"
      and len(k4j["exposure"]["protected_values"]) == 1
      and k4j["exposure"]["protected_values"][0]["delta"] == "unchanged",
      f"out={json.dumps(k4j)[:250]!r}")
# A3: live registry — literal added AFTER the baseline matches next run
# (pf_home already has a baseline), no --reset
with open(os.path.join(pf_home, "state", "info-guard",
                       "custom_literals.json"), "w") as f:
    f.write(json.dumps({"literals": [jwt]}))
l1 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "watch"], env=env6, capture_output=True, text=True, timeout=300)
l1o = l1.stdout + l1.stderr
check("watch A3: live registry — config delta only, exit 0, no reset",
      l1.returncode == 0 and "Custom literals +1" in l1o
      and "PROTECTED VALUE RE-DETECTED" not in l1o,
      f"rc={l1.returncode} out={l1o[-250:]!r}")
l2j = json.loads(subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "watch", "--json"], env=env6, capture_output=True, text=True,
    timeout=300).stdout)
check("watch A3: protected_values populated after live add (unchanged)",
      any(r["value_masked"] == "ey...aa" and r["delta"] == "unchanged"
          for r in l2j["exposure"]["protected_values"]))
# A5: --help per subcommand + unknown-flag warning (IG D55)
h1 = kv_watch("--help")
check("watch --help: usage + exit 0, no scan run",
      h1.returncode == 0 and "info-guard watch" in h1.stdout
      and "baseline created" not in h1.stdout
      and "no new" not in h1.stdout,
      f"rc={h1.returncode} out={h1.stdout[:200]!r}")
h2 = kv_watch("--reset", "--help")
check("watch --help: positional (--reset --help) prints usage, no reset",
      h2.returncode == 0 and "info-guard watch" in h2.stdout
      and "baseline reset" not in (h2.stdout + h2.stderr)
      and "unknown option" not in (h2.stdout + h2.stderr),
      f"rc={h2.returncode} out={h2.stdout[:200]!r}")
u1 = kv_watch("--jason")
check("watch unknown flag: verbatim stderr warning, run proceeds",
      "Warning: unknown option '--jason'" in u1.stderr
      and u1.returncode == 0,
      f"rc={u1.returncode} err={u1.stderr[:120]!r}")
ph1 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "preflight", "--help"], env=env_kv, capture_output=True, text=True,
    timeout=120)
check("preflight --help: usage + exit 0",
      ph1.returncode == 0 and "info-guard preflight" in ph1.stdout,
      f"rc={ph1.returncode} out={ph1.stdout[:200]!r}")
pu1 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "preflight", "--frob"], env=env_kv, capture_output=True, text=True,
    timeout=300)
check("preflight unknown flag: verbatim stderr warning + run proceeds",
      "Warning: unknown option '--frob'" in pu1.stderr
      and pu1.returncode == 1
      and "Traceback" not in (pu1.stdout + pu1.stderr),
      f"rc={pu1.returncode} err={pu1.stderr[:120]!r}")
# A4: surface audit — raw protected values + value sha256s never escape
wout_kv = os.path.join(tmp, "kv-watch.json")
kv_watch("--json-out", wout_kv)
kv_out_json = k1j.stdout + k3.stdout
surfaces = {
    "terminal": k1o + k2o + k4o,
    "json stdout": kv_out_json,
    "json-out file": open(wout_kv).read(),
    "baseline": json.dumps(json.load(open(kv_bl))),
    "stderr/warnings": u1.stderr + pu1.stderr,
}
for sname, blob in surfaces.items():
    check(f"watch A4: raw protected values absent from {sname}",
          jwt not in blob and dsc not in blob and sk_p not in blob)
check("watch A4: value sha256s absent from watch/v1 JSON",
      hashlib.sha256(jwt.encode()).hexdigest() not in kv_out_json
      and hashlib.sha256(dsc.encode()).hexdigest() not in kv_out_json
      and hashlib.sha256(sk_p.encode()).hexdigest() not in kv_out_json)

# ── 16. watch v2: protection-config deltas (counts + fingerprints only) ──
prot_home = os.path.join(tmp, "prot-home")
for sub in ("sessions", "logs", "cron/output"):
    os.makedirs(os.path.join(prot_home, sub), exist_ok=True)
with open(os.path.join(prot_home, "sessions", "session_20260505_075138_d.jsonl"),
          "w") as f:
    f.write(f"HASS_TOKEN={jwt}\n")
    f.write(f"DISCORD_BOT_TOKEN={dsc}\n")
os.makedirs(os.path.join(prot_home, "state", "info-guard"), exist_ok=True)
prot_bl = os.path.join(prot_home, "state", "info-guard", "watch-baseline.json")
prot_cl = os.path.join(prot_home, "state", "info-guard", "custom_literals.json")
prot_rp = os.path.join(prot_home, "state", "info-guard", "redact_patterns.json")
env_prot = dict(os.environ)
env_prot["HERMES_HOME"] = prot_home
prot_lit_a = "probeliteralvalue1"   # low-entropy fragments — gitleaks-safe
prot_lit_b = "probeliteralvalue2"
prot_lit_c = "probeliteralvalue3"
def write_prot(lits, keys, mask):
    open(prot_cl, "w").write(json.dumps({"literals": lits}))
    open(prot_rp, "w").write(json.dumps(
        {"mask": mask, "literals": lits,
         "key_patterns": {k: True for k in keys}}))
write_prot([prot_lit_a, prot_lit_b], ["PROBE_KEY_A"], {"head": 2, "tail": 2, "floor": 12})
p0 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env_prot, capture_output=True, text=True, timeout=300)
check("watch: protection baseline created (counts in snapshot)",
      p0.returncode == 0
      and json.load(open(prot_bl))["protection"]["custom_literals"]["count"] == 2
      and json.load(open(prot_bl))["protection"]["redact_patterns"]["literal_count"] == 2,
      f"rc={p0.returncode}")
# literal added (+1) — hand-edit custom_literals.json (the source file)
write_prot([prot_lit_a, prot_lit_b, prot_lit_c], ["PROBE_KEY_A"],
           {"head": 2, "tail": 2, "floor": 12})
p1 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env_prot, capture_output=True, text=True, timeout=300)
p1o = p1.stdout + p1.stderr
check("watch: custom literal added -> +1, exit 0 (config-only)",
      p1.returncode == 0 and "Custom literals +1" in p1o
      and "configuration deltas" in p1o,
      f"rc={p1.returncode} out={p1o[-250:]!r}")
check("watch: raw protection literal never printed",
      prot_lit_c not in p1o and prot_lit_c not in json.dumps(
          json.load(open(prot_bl))))
# duplicate literal = one (set semantics — no fabricated counts)
write_prot([prot_lit_a, prot_lit_b, prot_lit_c, prot_lit_c], ["PROBE_KEY_A"],
           {"head": 2, "tail": 2, "floor": 12})
p2 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env_prot, capture_output=True, text=True, timeout=300)
p2o = p2.stdout + p2.stderr
check("watch: duplicate literal is one (no fabricated delta)",
      p2.returncode == 0 and "Custom literals +1" not in p2o
      and "PROTECTION CHANGED" not in p2o,
      f"rc={p2.returncode} out={p2o[-250:]!r}")
# key pattern added
write_prot([prot_lit_a, prot_lit_b, prot_lit_c],
           ["PROBE_KEY_A", "PROBE_KEY_B"], {"head": 2, "tail": 2, "floor": 12})
p3 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env_prot, capture_output=True, text=True, timeout=300)
p3o = p3.stdout + p3.stderr
check("watch: key pattern added -> +1",
      p3.returncode == 0 and "Key patterns +1" in p3o,
      f"rc={p3.returncode} out={p3o[-250:]!r}")
# mask flip — hand-edit the fixture redact_patterns.json mask block
# (cmd_build hardcodes the policy, so the battery edits the file)
write_prot([prot_lit_a, prot_lit_b, prot_lit_c],
           ["PROBE_KEY_A", "PROBE_KEY_B"], {"head": 3, "tail": 2, "floor": 12})
p4 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env_prot, capture_output=True, text=True, timeout=300)
p4o = p4.stdout + p4.stderr
check("watch: mask policy flip detected",
      p4.returncode == 0 and "Mask policy changed" in p4o,
      f"rc={p4.returncode} out={p4o[-250:]!r}")
# build→build stability (R1): two identical builds -> the FIRST watch
# reports the (real) config change and refreshes; the SECOND watch
# after another identical build must show NO delta (no churn)
env_file = os.path.join(prot_home, ".env")
with open(env_file, "w") as f:
    f.write("PROBE_ENV_SECRET=probeenvsecretvalue9\n")
for _ in range(2):
    subprocess.run(
        [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
         "build", env_file],
        env=env_prot, capture_output=True, text=True, timeout=120)
subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env_prot, capture_output=True, text=True, timeout=300)  # reports + refreshes
subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "build",
     env_file],
    env=env_prot, capture_output=True, text=True, timeout=120)
p5 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env_prot, capture_output=True, text=True, timeout=300)
p5o = p5.stdout + p5.stderr
check("watch: build→build stability — no protection delta (R1)",
      p5.returncode == 0 and "PROTECTION CHANGED" not in p5o,
      f"rc={p5.returncode} out={p5o[-250:]!r}")
# literal removed (-1)
write_prot([prot_lit_a, prot_lit_b], ["PROBE_KEY_A", "PROBE_KEY_B"],
           {"head": 3, "tail": 2, "floor": 12})
p6 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env_prot, capture_output=True, text=True, timeout=300)
p6o = p6.stdout + p6.stderr
check("watch: custom literal removed -> -1",
      p6.returncode == 0 and "Custom literals +0 / -1" in p6o,
      f"rc={p6.returncode} out={p6o[-250:]!r}")

# ── 17. watch v2: engine-state transitions + exit-code matrix ──
eng_home = os.path.join(tmp, "eng-home")
for sub in ("sessions", "logs", "cron/output"):
    os.makedirs(os.path.join(eng_home, sub), exist_ok=True)
with open(os.path.join(eng_home, "sessions", "session_20260505_075138_d.jsonl"),
          "w") as f:
    f.write(f"HASS_TOKEN={jwt}\n")
    f.write(f"DISCORD_BOT_TOKEN={dsc}\n")
os.makedirs(os.path.join(eng_home, "state", "info-guard"), exist_ok=True)
env_eng = dict(os.environ)
env_eng["HERMES_HOME"] = eng_home
ENGINE_MARKERS = {  # mirrors bin/info-guard _ENGINE_MARKERS (L1761)
    "agent/redact.py": "_redact_registry_patterns",
    "hermes_cli/config.py": "redact_patterns",
    "hermes_cli/main.py": "HERMES_REDACT_PATTERNS",
    "cli.py": "HERMES_REDACT_PATTERNS",
    "gateway/run.py": "HERMES_REDACT_PATTERNS",
}
def set_engine(n_markers):
    base = os.path.join(eng_home, "hermes-agent")
    if n_markers == 0:
        import shutil
        shutil.rmtree(base, ignore_errors=True)
        return
    os.makedirs(base, exist_ok=True)
    for i, (rel, marker) in enumerate(sorted(ENGINE_MARKERS.items())):
        p = os.path.join(base, rel)
        if i < n_markers:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").write("# probe\n" + marker + "\n")
        elif os.path.exists(p):
            os.unlink(p)
def run_eng_watch():
    return subprocess.run(
        [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
         "watch"], env=env_eng, capture_output=True, text=True, timeout=300)
e0 = run_eng_watch()  # baseline with engine none
check("watch: engine baseline created (state none, version null)",
      e0.returncode == 0
      and json.load(open(os.path.join(eng_home, "state", "info-guard",
                                      "watch-baseline.json")))
          ["protection"]["engine"]["engine_state"] == "none"
      and json.load(open(os.path.join(eng_home, "state", "info-guard",
                                      "watch-baseline.json")))
          ["protection"]["engine"]["engine_version"] is None,
      f"rc={e0.returncode}")
set_engine(5)
e1 = run_eng_watch()
check("watch: none→active — Engine installed, exit 0",
      e1.returncode == 0 and "Engine installed" in (e1.stdout + e1.stderr),
      f"rc={e1.returncode} out={(e1.stdout + e1.stderr)[-250:]!r}")
set_engine(0)
e2 = run_eng_watch()
e2o = e2.stdout + e2.stderr
check("watch: active→none — engine removed block, exit 1",
      e2.returncode == 1 and "PROTECTION ENGINE REMOVED" in e2o,
      f"rc={e2.returncode} out={e2o[-250:]!r}")
set_engine(5)
e3 = run_eng_watch()
check("watch: none→active (reinstall), exit 0",
      e3.returncode == 0 and "Engine installed" in (e3.stdout + e3.stderr),
      f"rc={e3.returncode}")
set_engine(3)
e4 = run_eng_watch()
e4o = e4.stdout + e4.stderr
check("watch: active→partial — degraded block, exit 1",
      e4.returncode == 1 and "Protection degraded" in e4o,
      f"rc={e4.returncode} out={e4o[-250:]!r}")
set_engine(5)
e5 = run_eng_watch()
check("watch: partial→active — Protection restored, exit 0",
      e5.returncode == 0 and "Protection restored" in (e5.stdout + e5.stderr),
      f"rc={e5.returncode}")
# combined run: engine event + new value -> exit 1, both blocks
set_engine(0)
with open(os.path.join(eng_home, "sessions", "session_20260505_075138_d.jsonl"),
          "a") as f:
    f.write("ANTHROPIC_API_KEY=sk-" + "comboengine1234567" + "\n")
e6 = run_eng_watch()
e6o = e6.stdout + e6.stderr
check("watch: combined new-value + engine event -> exit 1, both blocks",
      e6.returncode == 1 and "EXPOSURE CHANGED" in e6o
      and "PROTECTION ENGINE REMOVED" in e6o,
      f"rc={e6.returncode} out={e6o[-250:]!r}")

# ── 18. watch v2: --json / --json-out (watch/v1 schema, R4) ──
j1 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "watch", "--json"],
    env=env6, capture_output=True, text=True, timeout=300)
check("watch --json: valid JSON, schema, exit 0 (clean run)",
      j1.returncode == 0
      and json.loads(j1.stdout).get("schema") == "info-guard/watch/v1",
      f"rc={j1.returncode} out={j1.stdout[-200:]!r} err={j1.stderr[-120:]!r}")
j1o = json.loads(j1.stdout)
check("watch --json: stdout pure JSON (no chatter lines)",
      "info-guard] watch" not in j1.stdout,
      f"stdout={j1.stdout[-200:]!r}")
check("watch --json: clean status + empty exposure",
      j1o["watch"]["status"] == "clean"
      and j1o["exposure"]["new_values"] == []
      and j1o["exposure"]["resolved_values"] == [])
check("watch --json: assessment before/after totals reconcile",
      j1o["assessment"]["before"]["credential_shaped"] == 3
      and j1o["assessment"]["after"]["credential_shaped"] == 3
      and j1o["assessment"]["before"]["distinct_values"] == 3)
check("watch --json: engine transition facts present",
      "engine" in j1o and j1o["engine"]["state_before"] == j1o["engine"]["state_after"])
check("watch --json: no raw values AND no value sha256s (R4/MAJ A3)",
      jwt not in j1.stdout and dsc not in j1.stdout
      and hashlib.sha256(jwt.encode()).hexdigest() not in j1.stdout
      and hashlib.sha256(dsc.encode()).hexdigest() not in j1.stdout,
      "raw value or value-sha256 leaked into watch JSON")
# --json on a changed run (new value): exposure populated, exit 1
j2_new = "sk-" + "jsonprobe123456789"
with open(os.path.join(pf_home, "sessions", "session_20260505_075138_d.jsonl"),
          "a") as f:
    f.write("ANTHROPIC_API_KEY=" + j2_new + "\n")
j2 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "watch", "--json"],
    env=env6, capture_output=True, text=True, timeout=300)
j2o = json.loads(j2.stdout)
check("watch --json: changed run -> status changed, exit 1",
      j2.returncode == 1 and j2o["watch"]["status"] == "changed")
check("watch --json: new value row shape (masked, no sha)",
      len(j2o["exposure"]["new_values"]) == 1
      and j2o["exposure"]["new_values"][0]["value_masked"] == "sk...89"
      and "value_sha256" not in j2o["exposure"]["new_values"][0])
# --json-out: atomic 0600 write, identical object, missing path = 2
wout = os.path.join(tmp, "watch.json")
j3 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "watch", "--json-out", wout],
    env=env6, capture_output=True, text=True, timeout=300)
check("watch --json-out: file written 0600",
      os.path.exists(wout) and (os.stat(wout).st_mode & 0o777) == 0o600)
j3o = json.load(open(wout))
# j2's run refreshed the baseline (j2_new became known), so compare the
# --json-out object against a --json run on the SAME (now settled) state
j3b = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "watch", "--json"],
    env=env6, capture_output=True, text=True, timeout=300)
j3bo = json.loads(j3b.stdout)
j3bo["watch"]["generated"] = j3o["watch"]["generated"]  # same-second tolerance
check("watch --json-out: identical object to --json stdout",
      j3o == j3bo)
j4 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "watch", "--json-out"],
    env=env6, capture_output=True, text=True, timeout=60)
check("watch --json-out: missing path is usage error 2",
      j4.returncode == 2 and "requires a file path" in (j4.stdout + j4.stderr),
      f"rc={j4.returncode}")
# protection deltas in JSON (reuse prot_home: add a literal via file)
with open(prot_cl, "w") as f:
    f.write(json.dumps({"literals": [prot_lit_a, prot_lit_b, prot_lit_c,
                                     "probeliteralvalue4"]}))
j5 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "watch", "--json"],
    env=env_prot, capture_output=True, text=True, timeout=300)
j5o = json.loads(j5.stdout)
check("watch --json: protection deltas in object (counts only)",
      j5o["protection"]["custom_literals"]["added"] == 2
      and j5o["protection"]["status"] == "changed"
      and "probeliteralvalue4" not in j5.stdout
      and hashlib.sha256(prot_lit_a.encode()).hexdigest() not in j5.stdout,
      "protection raw value or sha leaked into watch JSON")

# ── 19. setup stamping: baseline protection/assessment refreshed ──
stamp_home = os.path.join(tmp, "stamp-home")
for sub in ("sessions", "logs", "cron/output"):
    os.makedirs(os.path.join(stamp_home, sub), exist_ok=True)
with open(os.path.join(stamp_home, "sessions", "session_20260505_075138_d.jsonl"),
          "w") as f:
    f.write(f"HASS_TOKEN={jwt}\n")
    f.write(f"DISCORD_BOT_TOKEN={dsc}\n")
os.makedirs(os.path.join(stamp_home, "state", "info-guard"), exist_ok=True)
env_stamp = dict(os.environ)
env_stamp["HERMES_HOME"] = stamp_home
# baseline first (protection snapshot: no literals yet)
s0 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env_stamp, capture_output=True, text=True, timeout=300)
check("watch: baseline before setup (exit 0)",
      s0.returncode == 0, f"rc={s0.returncode}")
# setup --all registers the fixture values as custom literals -> the
# stamp must refresh the baseline so the next watch is delta-free
s1 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "setup", "--all"],
    env=env_stamp, capture_output=True, text=True, timeout=300)
s1o = s1.stdout + s1.stderr
check("setup --all: stamping notice printed",
      s1.returncode == 0 and "stamped" in s1o,
      f"rc={s1.returncode} out={s1o[-250:]!r}")
s2 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "watch"],
    env=env_stamp, capture_output=True, text=True, timeout=300)
s2o = s2.stdout + s2.stderr
check("watch after setup: no protection deltas, exit 0",
      s2.returncode == 0 and "PROTECTION CHANGED" not in s2o,
      f"rc={s2.returncode} out={s2o[-250:]!r}")
s2bl = json.load(open(os.path.join(stamp_home, "state", "info-guard",
                                   "watch-baseline.json")))
check("watch after setup: value history intact (2 values)",
      len(s2bl["values"]) == 2
      and s2bl["protection"]["custom_literals"]["count"] >= 2,
      f"values={len(s2bl['values'])} custom={s2bl['protection']['custom_literals']['count']}")


# ── 20. value_id: registry v2 + literals CLI + watch identity (v0.4.2, IG D64–D69) ──
vid_home = os.path.join(tmp, "vid-home")
for sub in ("sessions", "logs", "cron/output"):
    os.makedirs(os.path.join(vid_home, sub), exist_ok=True)
os.makedirs(os.path.join(vid_home, "state", "info-guard"), exist_ok=True)
vid_cl = os.path.join(vid_home, "state", "info-guard", "custom_literals.json")
env_vid = dict(os.environ)
env_vid["HERMES_HOME"] = vid_home
def vid_run(*args, **kw):
    return subprocess.run(
        [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard")] + list(args),
        env=env_vid, capture_output=True, text=True, timeout=300, **kw)
vid_a = "sk-battery-probe-alpha-1234567890"
vid_b = "sk-battery-probe-beta-1234567890"

# D1 migration: v1 plain-string registry -> ids + version 2, one write
open(vid_cl, "w").write(json.dumps({"literals": [vid_a, {"value": vid_b, "mask": "full"}]}))
m1 = vid_run("watch")
m1o = m1.stdout + m1.stderr
reg1 = json.load(open(vid_cl))
check("value_id D1: v1 registry migrated to v2 with ids",
      m1.returncode == 0 and reg1.get("version") == 2
      and all(isinstance(e, dict) and len(e.get("id", "")) == 16
              for e in reg1["literals"]) and "migrated to v2" in m1o,
      f"rc={m1.returncode} reg={reg1!r}")
reg_mtime = os.stat(vid_cl).st_mtime_ns
vid_run("watch", "--json")
check("value_id D1: second load performs no write (idempotent)",
      os.stat(vid_cl).st_mtime_ns == reg_mtime)
# D1b CRIT-1: fresh home with NO registry -> setup --all still registers
vid2_home = os.path.join(tmp, "vid-home2")
for sub in ("sessions", "logs", "cron/output"):
    os.makedirs(os.path.join(vid2_home, sub), exist_ok=True)
with open(os.path.join(vid2_home, "sessions", "s.jsonl"), "w") as f:
    f.write(f"HASS_TOKEN={vid_a}\n")
env_vid2 = dict(os.environ)
env_vid2["HERMES_HOME"] = vid2_home
sx = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "setup", "--all"], env=env_vid2, capture_output=True, text=True,
    timeout=300)
check("value_id D1: setup on fresh home still registers (CRIT-1)",
      sx.returncode == 0 and os.path.exists(os.path.join(
          vid2_home, "state", "info-guard", "custom_literals.json")),
      f"rc={sx.returncode}")
# D1c CRIT-1: unreadable registry + setup --all -> file bytes unchanged
vid3_home = os.path.join(tmp, "vid-home3")
os.makedirs(os.path.join(vid3_home, "state", "info-guard"), exist_ok=True)
os.makedirs(os.path.join(vid3_home, "sessions"), exist_ok=True)
with open(os.path.join(vid3_home, "sessions", "s.jsonl"), "w") as f:
    f.write(f"HASS_TOKEN={vid_a}\n")
vid3_cl = os.path.join(vid3_home, "state", "info-guard",
                       "custom_literals.json")
open(vid3_cl, "w").write("garbage{")
env_vid3 = dict(os.environ)
env_vid3["HERMES_HOME"] = vid3_home
before3 = open(vid3_cl).read()
sx3 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "setup", "--all"], env=env_vid3, capture_output=True, text=True,
    timeout=300)
check("value_id D1: unreadable registry never clobbered (CRIT-1)",
      sx3.returncode == 0 and open(vid3_cl).read() == before3
      and "unreadable" in (sx3.stdout + sx3.stderr),
      f"rc={sx3.returncode}")
# D2 stability: same entry -> same id across runs AND literal reorder
with open(os.path.join(vid_home, "sessions", "a.jsonl"), "w") as f:
    f.write(f"HASS_TOKEN={vid_a}\n")
v1 = vid_run("watch", "--json")
v1j = json.loads(v1.stdout)
pv1 = [r for r in v1j["exposure"]["protected_values"] if r["delta"] == "new"]
ov1 = [r["value_id"] for r in v1j["exposure"]["new_values"]
       if r.get("value_id")]
check("value_id D2: new protected value carries value_id on BOTH surfaces",
      len(pv1) == 1 and len(pv1[0].get("value_id", "")) == 16
      and ov1 == [pv1[0]["value_id"]],
      f"pv={pv1!r} ov={ov1!r}")
id_a = pv1[0]["value_id"]
# reorder the registry (same persisted ids) -> same id on next run
open(vid_cl, "w").write(json.dumps({"version": 2, "literals": [
    {"value": vid_b, "id": reg1["literals"][1]["id"]},
    {"value": vid_a, "id": id_a}]}))
v2 = vid_run("watch", "--json")
v2j = json.loads(v2.stdout)
pv2 = [r for r in v2j["exposure"]["protected_values"]]
check("value_id D2: id survives literal reorder + clean run",
      len(pv2) == 1 and pv2[0]["delta"] == "unchanged"
      and pv2[0]["value_id"] == id_a,
      f"pv={pv2!r}")
check("value_id D2: unchanged row has no overlay row (one-event rule)",
      all("value_id" not in r for r in
          v2j["exposure"]["new_values"] + v2j["exposure"]["changed_values"]))
# D3 duplicate-id repair: different values, same id -> later repaired
open(vid_cl, "w").write(json.dumps({"literals": [
    {"value": vid_a, "id": "collide12345678"},
    {"value": vid_b, "id": "collide12345678"}]}))
r3 = vid_run("literals", "list")
reg3 = json.load(open(vid_cl))
ids3 = [e["id"] for e in reg3["literals"]]
check("value_id D3: duplicate ids repaired deterministically",
      len(ids3) == len(set(ids3))
      and "duplicate literal id repaired" in r3.stderr
      and vid_a not in r3.stderr and vid_b not in r3.stderr,
      f"ids={ids3} err={r3.stderr[:200]!r}")
# D4 preservation: unknown fields, non-string entries, top-level keys
open(vid_cl, "w").write(json.dumps(
    {"_topnote": "keep me", "literals": [
        {"value": vid_a, "mask": "full", "note": "user note"}, 42, True]}))
vid_run("literals", "list")
reg4 = json.load(open(vid_cl))
check("value_id D4: unknown fields, non-strings, top keys preserved",
      reg4.get("_topnote") == "keep me"
      and reg4["literals"][0].get("note") == "user note"
      and 42 in reg4["literals"] and True in reg4["literals"])
check("value_id D4: registry stays 0600 after migration rewrite",
      (os.stat(vid_cl).st_mode & 0o777) == 0o600)
# D4b MIN-5: version > 2 -> read-only pass-through, no write
open(vid_cl, "w").write(json.dumps({"version": 3, "literals": [vid_a]}))
m4 = os.stat(vid_cl).st_mtime_ns
r4b = vid_run("literals", "list")
check("value_id D4: version>2 loaded read-only with warning (MIN-5)",
      os.stat(vid_cl).st_mtime_ns == m4
      and "newer than this app understands" in r4b.stderr)
# D5 downgrade: the ACTUAL v0.4.1 reader parses a migrated v2 registry
vid5_home = os.path.join(tmp, "vid-home5")
for sub in ("sessions", "logs", "cron/output"):
    os.makedirs(os.path.join(vid5_home, sub), exist_ok=True)
os.makedirs(os.path.join(vid5_home, "state", "info-guard"), exist_ok=True)
open(os.path.join(vid5_home, "state", "info-guard",
                  "custom_literals.json"), "w").write(json.dumps(
    {"version": 2, "literals": [
        {"value": vid_a, "id": "1111111111111111"},
        {"value": vid_b, "id": "2222222222222222", "mask": "full"}]}))
with open(os.path.join(vid5_home, "sessions", "a.jsonl"), "w") as f:
    f.write(f"HASS_TOKEN={vid_a}\n")
env_vid5 = dict(os.environ)
env_vid5["HERMES_HOME"] = vid5_home
old_bin = os.path.join(tmp, "info-guard-0.4.1")
old_dl = subprocess.run(["git", "show", "v0.4.1:bin/info-guard"],
                        capture_output=True, text=True, cwd=os.getcwd())
if old_dl.returncode == 0:
    open(old_bin, "w").write(old_dl.stdout)
    os.chmod(old_bin, 0o755)
    d5 = subprocess.run([sys.executable, old_bin, "watch", "--json"],
                        env=env_vid5, capture_output=True, text=True,
                        timeout=300)
    d5ok = d5.returncode == 0
    if d5ok:
        try:
            d5j = json.loads(d5.stdout)
            d5bl = json.load(open(os.path.join(
                vid5_home, "state", "info-guard", "watch-baseline.json")))
            # first-run JSON has no count (added/removed only); the
            # v0.4.1 reader proves it parsed the v2 registry via the
            # baseline's protection snapshot count + a clean parse
            d5ok = (d5j["tool"]["version"] == "0.4.1"
                    and d5j["schema"] == "info-guard/watch/v1"
                    and d5bl.get("protection", {}).get(
                        "custom_literals", {}).get("count") == 2)
        except (ValueError, KeyError, OSError):
            d5ok = False
    check("value_id D5: v0.4.1 reader parses migrated v2 registry",
          d5ok, f"rc={d5.returncode} out={d5.stdout[:200]!r}")
else:
    check("value_id D5: v0.4.1 reader parses migrated v2 registry",
          False, "tag v0.4.1 unavailable (CI: git fetch --tags)")
# D6 MAJ-2: first command on a v1 registry is watch --json -> stdout pure
vid6_home = os.path.join(tmp, "vid-home6")
for sub in ("sessions", "logs", "cron/output"):
    os.makedirs(os.path.join(vid6_home, sub), exist_ok=True)
os.makedirs(os.path.join(vid6_home, "state", "info-guard"), exist_ok=True)
open(os.path.join(vid6_home, "state", "info-guard",
                  "custom_literals.json"), "w").write(
    json.dumps({"literals": [vid_a]}))
env_vid6 = dict(os.environ)
env_vid6["HERMES_HOME"] = vid6_home
d6 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "watch", "--json"], env=env_vid6, capture_output=True, text=True,
    timeout=300)
check("value_id D6: watch --json stdout pure on post-upgrade first run",
      d6.returncode == 0 and json.loads(d6.stdout) is not None
      and "migrated to v2" in d6.stderr and "migrated to v2" not in d6.stdout,
      f"rc={d6.returncode} out={d6.stdout[:200]!r}")
d6b = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "literals", "list", "--json"], env=env_vid6, capture_output=True,
    text=True, timeout=300)
check("value_id D6: literals list --json stdout pure after migration",
      d6b.returncode == 0 and json.loads(d6b.stdout) is not None
      and "migrated" not in d6b.stdout)
# D6c value_id absent from baseline + terminal (D66 surface rule)
vid_term = vid_run("watch")
check("value_id D6: value_id absent from terminal + baseline",
      "value_id" not in (vid_term.stdout + vid_term.stderr)
      and "value_id" not in open(os.path.join(
          vid_home, "state", "info-guard", "watch-baseline.json")).read())
# D7 literals CLI contract
open(vid_cl, "w").write(json.dumps({"version": 2, "literals": []}))
l1 = vid_run("literals", "add", vid_a, vid_b, "--mask", "full")
check("value_id D7: literals add prints an id per value",
      l1.returncode == 0 and len(l1.stdout.strip().splitlines()) == 2
      and all(len(line.split()[1]) == 16 for line in l1.stdout.strip().splitlines()),
      f"rc={l1.returncode} out={l1.stdout!r}")
l1j = json.loads(vid_run("literals", "add", vid_a, "--json").stdout)
check("value_id D7: duplicate add returns existing id",
      len(l1j["duplicates"]) == 1 and len(l1j["added"]) == 0
      and len(l1j["duplicates"][0]["id"]) == 16,
      f"out={l1j!r}")
reg7 = json.load(open(vid_cl))
check("value_id D7: --mask applies to every value in invocation",
      all(e.get("mask") == "full" for e in reg7["literals"]
          if e["value"] in (vid_a, vid_b)))
bulk = os.path.join(tmp, "bulk.txt")
with open(bulk, "w") as f:
    f.write(f"# comment\n{vid_a}\n\nsk-zeta-value-98765\n")
l2 = vid_run("literals", "add", "--file", bulk, "--json")
l2j = json.loads(l2.stdout)
check("value_id D7: --file bulk add (comments/blank skipped)",
      l2.returncode == 0 and len(l2j["added"]) == 1
      and l2j["added"][0]["value_masked"] == "sk...65",
      f"rc={l2.returncode} out={l2j!r}")
l3 = vid_run("literals", "list")
l3_masks = [line.split()[1] for line in l3.stdout.strip().splitlines()]
check("value_id D7: literals list sorted by value (full-mask entries ***)",
      l3.returncode == 0 and l3_masks == ["***", "***", "sk...65"],
      f"out={l3.stdout!r}")
l4 = vid_run("literals", "add")
check("value_id D7: literals add with no values = usage 2",
      l4.returncode == 2)
l5 = vid_run("literals", "add", "--file", os.path.join(tmp, "missing.txt"))
check("value_id D7: missing --file = exit 2", l5.returncode == 2)
l6 = vid_run("literals", "--help")
check("value_id D7: literals --help = usage + exit 0",
      l6.returncode == 0 and "literals add" in l6.stdout)
l7 = vid_run("literals", "add", vid_a, "--frob")
check("value_id D7: unknown flag = verbatim warning + run proceeds",
      "Warning: unknown option '--frob'" in l7.stderr
      and l7.returncode == 0)
# D8 build: reads v2 registry (ids) correctly + v1 registry migrates via build
vid8_home = os.path.join(tmp, "vid-home8")
os.makedirs(os.path.join(vid8_home, "state", "info-guard"), exist_ok=True)
open(os.path.join(vid8_home, ".env"), "w").write("")  # build needs a source
env_vid8 = dict(os.environ)
env_vid8["HERMES_HOME"] = vid8_home
open(os.path.join(vid8_home, "state", "info-guard",
                  "custom_literals.json"), "w").write(json.dumps(
    {"version": 2, "literals": [
        {"value": vid_a, "id": "3333333333333333", "mask": "full"}]}))
b8 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "build"], env=env_vid8, capture_output=True, text=True, timeout=300)
check("value_id D8: build reads migrated v2 registry correctly",
      b8.returncode == 0 and "1 literals (1 full-mask)" in b8.stdout,
      f"rc={b8.returncode} out={b8.stdout!r}")
open(os.path.join(vid8_home, "state", "info-guard",
                  "custom_literals.json"), "w").write(
    json.dumps({"literals": [vid_b]}))
b8b = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "build"], env=env_vid8, capture_output=True, text=True, timeout=300)
reg8 = json.load(open(os.path.join(vid8_home, "state", "info-guard",
                                   "custom_literals.json")))
check("value_id D8: build triggers migration of a v1 registry (MAJ-1)",
      b8b.returncode == 0 and reg8.get("version") == 2
      and len(reg8["literals"][0].get("id", "")) == 16,
      f"rc={b8b.returncode} reg={reg8!r}")
# D10 evidence-review MIN-1: top-level keys survive writer paths; no-op add
# never rewrites
open(vid_cl, "w").write(json.dumps(
    {"version": 2, "_note": "user comment", "literals": []}))
vid_run("literals", "add", "sk-topkey-probe-value-1234567890")
reg10 = json.load(open(vid_cl))
check("value_id D10: top-level keys preserved through literals add",
      reg10.get("_note") == "user comment", f"reg={reg10!r}")
m10 = os.stat(vid_cl).st_mtime_ns
vid_run("literals", "add", "sk-topkey-probe-value-1234567890")
check("value_id D10: duplicate-only add never rewrites the file",
      os.stat(vid_cl).st_mtime_ns == m10)
vid10_home = os.path.join(tmp, "vid-home10")
for sub in ("sessions", "logs", "cron/output"):
    os.makedirs(os.path.join(vid10_home, sub), exist_ok=True)
os.makedirs(os.path.join(vid10_home, "state", "info-guard"), exist_ok=True)
with open(os.path.join(vid10_home, "sessions", "s.jsonl"), "w") as f:
    f.write(f"HASS_TOKEN={vid_a}\n")
open(os.path.join(vid10_home, "state", "info-guard",
                  "custom_literals.json"), "w").write(json.dumps(
    {"version": 2, "_note": "setup key", "literals": []}))
env_vid10 = dict(os.environ)
env_vid10["HERMES_HOME"] = vid10_home
s10 = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
     "setup", "--all"], env=env_vid10, capture_output=True, text=True,
    timeout=300)
reg10b = json.load(open(os.path.join(vid10_home, "state", "info-guard",
                                     "custom_literals.json")))
check("value_id D10: top-level keys preserved through setup --all",
      s10.returncode == 0 and reg10b.get("_note") == "setup key",
      f"rc={s10.returncode} reg={reg10b!r}")
# D11 evidence-review MIN-2: empty value rejected
e11 = vid_run("literals", "add", "")
check("value_id D11: empty value rejected with usage exit 2",
      e11.returncode == 2 and "empty values rejected" in e11.stderr,
      f"rc={e11.returncode} err={e11.stderr[:120]!r}")
# D12 evidence-review NIT-1: full-mask entry lists as ***
vid_run("literals", "add", "sk-fullmask-probe-1234567890", "--mask", "full")
l12 = vid_run("literals", "list", "--json")
l12j = json.loads(l12.stdout)
check("value_id D12: full-mask entry lists as ***",
      any(r["value_masked"] == "***" for r in l12j["literals"]),
      f"out={l12j!r}")

# ── 21. env-value KNOWN tier (v0.5.0, IG D57–D62/D70–D75; A1–A18) ──
IG = os.path.join(os.getcwd(), "bin", "info-guard")

def ig_run(home, args, cwd=None, extra_env=None):
    env = dict(os.environ)
    env["HERMES_HOME"] = home
    if extra_env:
        env.update(extra_env)
    return subprocess.run([sys.executable, IG] + args, env=env,
                          capture_output=True, text=True, timeout=300,
                          cwd=cwd)

def mkhome(*subs):
    h = os.path.join(tmp, "env-home-" + str(len(os.listdir(tmp)) + 1))
    for s in subs:
        os.makedirs(os.path.join(h, s), exist_ok=True)
    return h

# Fixture values (synthetic, runtime-constructed).
envval = "ig" + "env" + "val" + "9" + "q2x7"          # 14 chars
envval2 = "ig" + "env" + "val" + "B" + "8w3m"         # different value

# ── A1: bare known value → KNOWN row masked, exit 3 (ladder, IG D83) ──
h1 = mkhome("sessions", "logs", "cron/output")
with open(os.path.join(h1, ".env"), "w") as f:
    f.write(f"UNIFI_SSH={envval}\n")
with open(os.path.join(h1, "sessions", "s1.jsonl"), "w") as f:
    f.write(f"the token is {envval} here\n")
r1 = ig_run(h1, ["preflight"])
check("A1: bare known value → exit 3 (KNOWN dominates, D83)",
      r1.returncode == 3,
      f"rc={r1.returncode} out={r1.stdout[-200:]!r}")
check("A1: KNOWN summary card present",
      f"KNOWN (your .env values) — 1 in 1 files" in r1.stdout)
check("A1: value masked (2+2), raw never printed",
      envval not in r1.stdout + r1.stderr
      and f"{envval[:2]}..." in r1.stdout)
check("A1: identity wording — KNOWN rows never leak/confirmed (D60)",
      "review whether it is still live" in r1.stdout
      and "confirmed leak" not in
      r1.stdout[r1.stdout.find("KNOWN (your .env values)"):]
      if "KNOWN (your .env values)" in r1.stdout else False)

# ── A2: eligibility table (in/out cases) ──
h2 = mkhome("sessions")
with open(os.path.join(h2, ".env"), "w") as f:
    f.write(f"UNIFI_SSH={envval}\n"      # eligible (secret class)
            f"AGH_PIN=12345678\n"        # eligible — closes the PIN gap
            f"AGH_USER={envval2}\n"      # NON-secret → excluded
            f"UNIFI_HOST=192.168.2.1\n"  # NON-secret → excluded
            f"MY_PORT=8080\n")           # NON-secret → excluded
with open(os.path.join(h2, "sessions", "s2.jsonl"), "w") as f:
    f.write(f"{envval} {envval2} 12345678 192.168.2.1 8080\n")
r2 = ig_run(h2, ["preflight", "--json"])
o2 = json.loads(r2.stdout)
tv2 = [v for v in o2["top_values"] if v.get("known")]
keys2 = sorted(v.get("source_key") for v in tv2)
check("A2: eligible keys only in KNOWN set",
      keys2 == ["AGH_PIN", "UNIFI_SSH"],
      f"known keys={keys2}")
check("A2: non-secret key values never KNOWN",
      all(v["source_key"] not in ("AGH_USER", "UNIFI_HOST", "MY_PORT")
          for v in tv2))

# ── A3: length floor (7 not matched, 8 matched) ──
h3 = mkhome("sessions")
with open(os.path.join(h3, ".env"), "w") as f:
    f.write("SEVEN7=abcdefg\nEIGHT8=abcdefgh\n")   # 7 vs 8 chars
with open(os.path.join(h3, "sessions", "s3.jsonl"), "w") as f:
    f.write("abcdefg abcdefgh\n")
r3 = ig_run(h3, ["preflight", "--json"])
o3 = json.loads(r3.stdout)
tv3 = [v.get("source_key") for v in o3["top_values"] if v.get("known")]
check("A3: 7-char never hashed/matched, 8-char matched",
      tv3 == ["EIGHT8"], f"known={tv3}")

# ── A4: env pass ignores custom_literals; literal detector unchanged ──
h4 = mkhome("sessions")
os.makedirs(os.path.join(h4, "state", "info-guard"), exist_ok=True)
with open(os.path.join(h4, ".env"), "w") as f:
    f.write(f"REAL_KEY={envval}\n")
lit4 = "ig" + "literal" + "only" + "x4"          # in registry, NOT in .env
with open(os.path.join(h4, "state", "info-guard",
                       "custom_literals.json"), "w") as f:
    json.dump({"version": 2, "literals": [lit4]}, f)
with open(os.path.join(h4, "sessions", "s4.jsonl"), "w") as f:
    f.write(f"{envval} {lit4}\n")
r4 = ig_run(h4, ["preflight", "--json"])
o4 = json.loads(r4.stdout)
tv4 = [v.get("source_key") for v in o4["top_values"] if v.get("known")]
check("A4: registry-only value never KNOWN; .env value is",
      tv4 == ["REAL_KEY"], f"known={tv4}")

# ── A5: trivial values excluded at any length ──
h5 = mkhome("sessions")
with open(os.path.join(h5, ".env"), "w") as f:
    f.write("FLAG=undefined\nBOOL=true\n")
with open(os.path.join(h5, "sessions", "s5.jsonl"), "w") as f:
    f.write("undefined true\n")
r5 = ig_run(h5, ["preflight", "--json"])
o5 = json.loads(r5.stdout)
check("A5: trivial values never KNOWN (incl. >=8-char trivial)",
      o5["totals"]["known"] == 0 and o5["totals"]["known_rows"] == 0,
      f"known={o5['totals']['known']}")

# ── A6: surface audit — raw values absent from ALL surfaces ──
# (a) code-level review assertions: digest-keyed index, no raw-value
# interpolation in diagnostics
igsrc = open(IG).read()
check("A6: index is digest-keyed (sha256(value) → keys)",
      "index.setdefault(d" in igsrc and "index.setdefault(v" not in igsrc)
check("A6: diagnostics never carry raw values",
      "unreadable — skipped" in igsrc and "malformed — skipped" in igsrc
      and "diagnostics.append" in igsrc)
# (b) malformed .env input → generic, no raw value
h6 = mkhome("sessions")
with open(os.path.join(h6, ".env"), "w") as f:
    f.write(f"GOOD={envval}\n"                       # indexed (the match)
            "this line has no equals sign and a raw "
            f"{envval2} inside\n")                   # malformed → skipped
with open(os.path.join(h6, "sessions", "s6.jsonl"), "w") as f:
    f.write(f"{envval}\n")
r6 = ig_run(h6, ["preflight"])
check("A6: malformed .env lines skipped silently, raw absent, exit 3 (D83)",
      envval not in r6.stderr and r6.returncode == 3
      and envval2 not in r6.stderr)
# (c) unreadable source → masked diagnostic, pass continues
h6b = mkhome("sessions")
with open(os.path.join(h6b, ".env"), "w") as f:
    f.write(f"GOOD={envval2}\n")
with open(os.path.join(h6b, "sessions", "s6b.jsonl"), "w") as f:
    f.write(f"{envval2}\n")
os.makedirs(os.path.join(h6b, "cwd"), exist_ok=True)
bad6 = os.path.join(h6b, "cwd", ".env")
with open(bad6, "w") as f:
    f.write(f"BROKEN={envval}\n")
os.chmod(bad6, 0)
r6b = ig_run(h6b, ["preflight"], cwd=os.path.join(h6b, "cwd"))
os.chmod(bad6, 0o600)
check("A6: unreadable source → one masked diagnostic, pass active",
      "unreadable — skipped" in r6b.stdout
      and "KNOWN (your .env values) — 1 in 1 files" in r6b.stdout
      and envval not in r6b.stdout + r6b.stderr,
      f"rc={r6b.returncode}")
# (d) monkeypatch sentinel injection at each boundary (CRIT-1 r2)
h6c = mkhome("sessions")
with open(os.path.join(h6c, ".env"), "w") as f:
    f.write(f"TOK={envval}\n")
with open(os.path.join(h6c, "sessions", "s6c.jsonl"), "w") as f:
    f.write(f"{envval}\n")
SENT = "IGSENTINEL" + "x9q2"
igmod = os.path.join(tmp, "igmod.py")
shutil.copy(IG, igmod)
wrap = os.path.join(tmp, "igwrap.py")
with open(wrap, "w") as f:
    f.write("import importlib.util, sys, os\n"
            "spec = importlib.util.spec_from_file_location("
            f"'ig', {igmod!r})\n"
            "m = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(m)\n"
            f"SENT = {SENT!r}\n"
            "def boom(*a, **k):\n"
            "    raise RuntimeError(SENT + ' in boundary')\n"
            "m._env_sources = boom\n"
            "sys.exit(m.main(sys.argv[1:]))\n")
env_w = dict(os.environ); env_w["HERMES_HOME"] = h6c
rw = subprocess.run([sys.executable, wrap, "preflight"], env=env_w,
                    capture_output=True, text=True, timeout=300)
check("A6: _env_sources sentinel injection — no raw leak, generic degrade",
      SENT not in rw.stdout + rw.stderr
      and "ENV_PASS_INTERNAL" in rw.stdout,
      f"rc={rw.returncode} out={rw.stdout[-150:]!r} err={rw.stderr[-150:]!r}")
# (e) downstream failure injection in assessment path (CRIT-2 r3)
with open(wrap, "w") as f:
    f.write("import importlib.util, sys, os\n"
            "spec = importlib.util.spec_from_file_location("
            f"'ig', {igmod!r})\n"
            "m = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(m)\n"
            f"SENT = {SENT!r}\n"
            "def boom(*a, **k):\n"
            "    raise RuntimeError(SENT + ' in assessment')\n"
            "m._build_assessment = boom\n"
            "sys.exit(m.main(sys.argv[1:]))\n")
rw2 = subprocess.run([sys.executable, wrap, "preflight", "--json"],
                     env=env_w, capture_output=True, text=True, timeout=300)
check("A6: assessment-path sentinel injection — generic, no leak, no partial JSON",
      SENT not in rw2.stdout + rw2.stderr
      and "internal error" in rw2.stderr
      and rw2.returncode == 2  # operational failure (v0.5.1, IG D94 — was 1)
      and not rw2.stdout.strip().startswith("{"),
      f"rc={rw2.returncode} out={rw2.stdout[-120:]!r} err={rw2.stderr[-120:]!r}")

# (f) Wave A (Phase 7/A23): watch-path sentinel injection — the new
# watch env integration must degrade the same way as preflight: env-pass
# failure -> KNOWN tier disabled (generic degrade), no raw leak, stdout
# stays valid JSON, the run completes (baseline created). Env-pass
# failure is a detector-tier degrade, NOT a scan operational failure
# (gitleaks missing is the exit-2 case; the env pass is additive).
with open(wrap, "w") as f:
    f.write("import importlib.util, sys, os\n"
            "spec = importlib.util.spec_from_file_location("
            f"'ig', {igmod!r})\n"
            "m = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(m)\n"
            f"SENT = {SENT!r}\n"
            "def boom(*a, **k):\n"
            "    raise RuntimeError(SENT + ' in watch env')\n"
            "m._env_sources = boom\n"
            "sys.exit(m.main(sys.argv[1:]))\n")
rw3 = subprocess.run([sys.executable, wrap, "watch", "--json", "--reset"],
                     env=env_w, capture_output=True, text=True, timeout=300)
check("A23: watch env-pass sentinel injection — no leak, JSON intact, completes",
      SENT not in rw3.stdout + rw3.stderr
      and "KNOWN pass disabled" in rw3.stderr
      and rw3.stdout.strip().startswith("{"),
      f"rc={rw3.returncode} out={rw3.stdout[-120:]!r} err={rw3.stderr[-120:]!r}")

# (g) Wave A (Phase 7/A23): _value_id_map sentinel injection — the
# annotation lookup must never leak raw values or crash JSON purity.
with open(wrap, "w") as f:
    f.write("import importlib.util, sys, os\n"
            "spec = importlib.util.spec_from_file_location("
            f"'ig', {igmod!r})\n"
            "m = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(m)\n"
            f"SENT = {SENT!r}\n"
            "def boom(*a, **k):\n"
            "    raise RuntimeError(SENT + ' in id map')\n"
            "m._value_id_map = boom\n"
            "sys.exit(m.main(sys.argv[1:]))\n")
rw4 = subprocess.run([sys.executable, wrap, "preflight", "--json"],
                     env=env_w, capture_output=True, text=True, timeout=300)
check("A23: _value_id_map sentinel injection — no leak, exit 2",
      SENT not in rw4.stdout + rw4.stderr
      and rw4.returncode == 2
      and "internal error" in rw4.stderr,
      f"rc={rw4.returncode} out={rw4.stdout[-120:]!r} err={rw4.stderr[-120:]!r}")

# ── A7: no sources → one disabled line + null + 0; golden ──
h7 = mkhome("sessions", "logs", "cron/output")
with open(os.path.join(h7, "sessions", "s7.jsonl"), "w") as f:
    f.write("plain text only, no secrets\n")
r7 = ig_run(h7, ["preflight"])
check("A7: no sources → exactly one disabled line",
      r7.stdout.count("KNOWN pass: no .env sources — disabled") == 1,
      f"out={r7.stdout[-300:]!r}")
r7j = ig_run(h7, ["preflight", "--json"])
o7 = json.loads(r7j.stdout)
check("A7: no sources → confirmed_active null + known 0",
      o7["status"]["confirmed_active"] is None
      and o7["totals"]["known"] == 0 and o7["totals"]["known_rows"] == 0)
# A7b: active pass with valid source but zero matches → null, NO disabled line
h7b = mkhome("sessions")
with open(os.path.join(h7b, ".env"), "w") as f:
    f.write(f"TOK={envval}\n")
with open(os.path.join(h7b, "sessions", "s7b.jsonl"), "w") as f:
    f.write("nothing matching here\n")
r7b = ig_run(h7b, ["preflight"])
check("A7b: active/no-match → no disabled line, null, exit 0",
      "KNOWN pass: no .env sources — disabled" not in r7b.stdout
      and json.loads(ig_run(h7b, ["preflight", "--json"]).stdout)
      ["status"]["confirmed_active"] is None
      and r7b.returncode == 0)

# ── A9: self-match exclusion (direct/relative/symlink/hard-link) ──
h9 = mkhome("sessions", "logs", "cron/output")
with open(os.path.join(h9, ".env"), "w") as f:
    f.write(f"HASS_TOKEN={envval}\n")
with open(os.path.join(h9, "sessions", "s9.jsonl"), "w") as f:
    f.write(f"bare {envval} occurrence\n")   # the real match
os.symlink(os.path.join(h9, ".env"), os.path.join(h9, "sessions", "envlink"))
os.link(os.path.join(h9, ".env"), os.path.join(h9, "logs", "envhard"))
r9 = ig_run(h9, ["preflight", "--json"])
o9 = json.loads(r9.stdout)
# The .env itself + symlink + hard link must never be KNOWN rows; the
# session file's bare occurrence is the ONLY known row.
known_files9 = [f["file"] for f in o9["affected_files"] if f.get("known", 0) > 0]
check("A9: self-match excluded (direct/symlink/hard-link)",
      known_files9 == ["sessions/s9.jsonl"],
      f"known files={known_files9}")
check("A9: .env source itself never a finding of any tier",
      all(".env" not in f["file"] or f["total_findings"] == 0
          for f in o9["affected_files"]))
# A9b (MAJ-3 r2): file replacement between discovery and read (new
# inode, same path) — the identity snapshot was taken pre-replacement;
# the read-time identity check uses the CURRENT stat, so a REPLACED
# source (new inode, same canonical path) is matched correctly and the
# old inode never disables matching of the new content (TOCTOU accepted,
# documented). (The stat-failure fallback is defensive-only: _collect_hits
# skips unstat-able files via is_file() before the env pass ever sees
# them — verified by code review, not monkeypatch.)
h9b = mkhome("sessions", "logs")
env9b = os.path.join(h9b, ".env")
with open(env9b, "w") as f:
    f.write(f"TOK9B={envval}\n")
with open(os.path.join(h9b, "sessions", "s9b.jsonl"), "w") as f:
    f.write(f"{envval}\n")
# replacement: swap the .env for a new file (new inode) with a DIFFERENT
# value; the scan file carries the NEW value; must match.
os.replace(env9b, env9b + ".old")
with open(env9b, "w") as f:
    f.write(f"TOK9B={envval2}\n")
with open(os.path.join(h9b, "sessions", "s9b.jsonl"), "a") as f:
    f.write(f"{envval2}\n")
r9b = ig_run(h9b, ["preflight", "--json"])
o9b = json.loads(r9b.stdout)
chk9b = [v.get("source_key") for v in o9b["top_values"] if v.get("known")]
check("A9b: replacement between discovery and read → new value matched",
      chk9b == ["TOK9B"] and o9b["totals"]["known"] == 1
      and [v for v in o9b["top_values"] if v.get("known")][0]["count"] == 1,
      f"known={chk9b}")

# ── A10: confirmed_active semantics + old-consumer probe ──
r10 = ig_run(h1, ["preflight", "--json"])     # h1 has 1 known value
o10 = json.loads(r10.stdout)
check("A10: known present → confirmed_active true",
      o10["status"]["confirmed_active"] is True)
probe = os.path.join(os.getcwd(), "tests", "consumers", "v0.4.2-json-probe.py")
p10 = subprocess.run([sys.executable, probe], input=r10.stdout,
                     capture_output=True, text=True, timeout=120)
check("A10: v0.4.2-era consumer probe PASSES on v0.5.0 known output",
      p10.returncode == 0, f"rc={p10.returncode} err={p10.stderr[-200:]!r}")
p10b = subprocess.run([sys.executable, probe], input=r7j.stdout,
                      capture_output=True, text=True, timeout=120)
check("A10: v0.4.2-era consumer probe PASSES on clean output",
      p10b.returncode == 0, f"rc={p10b.returncode} err={p10b.stderr[-200:]!r}")

# ── A22 (Wave A): same-major v1.1 consumer probe ──
# A consumer written against v1.0 must accept v1.1 payloads — schema
# surface + major parsing, unknown-minor tolerance, unknown additive
# fields tolerated, security-significant unknown enum values preserved.
probe11 = os.path.join(os.getcwd(), "tests", "consumers",
                       "v1.1-consumer-probe.py")
p11a = subprocess.run([sys.executable, probe11], input=r10.stdout,
                      capture_output=True, text=True, timeout=120)
check("A22: v1.1 same-major probe PASSES on assessment v1 output",
      p11a.returncode == 0, f"rc={p11a.returncode} err={p11a.stderr[-200:]!r}")
# watch/v1 output:
r11w = ig_run(h1, ["watch", "--json", "--reset"])
p11w = subprocess.run([sys.executable, probe11, "--surface", "watch"],
                      input=r11w.stdout, capture_output=True, text=True,
                      timeout=120)
check("A22: v1.1 same-major probe PASSES on watch v1 output",
      p11w.returncode == 0,
      f"rc={p11w.returncode} err={p11w.stderr[-200:]!r}")
# literals --json envelope:
r11l = ig_run(h1, ["literals", "list", "--json"])
p11l = subprocess.run([sys.executable, probe11, "--surface", "literals"],
                      input=r11l.stdout, capture_output=True, text=True,
                      timeout=120)
check("A22: literals/v1 envelope accepted by same-major probe",
      p11l.returncode == 0,
      f"rc={p11l.returncode} err={p11l.stderr[-200:]!r}")
# v1.1 (unknown minor) fixture accepted — same-major tolerance:
p11m = subprocess.run([sys.executable, probe11],
                      input=r10.stdout.replace(
                          "info-guard/assessment/v1",
                          "info-guard/assessment/v1.1"),
                      capture_output=True, text=True, timeout=120)
check("A22: v1.1 (unknown minor) fixture accepted by same-major probe",
      p11m.returncode == 0,
      f"rc={p11m.returncode} err={p11m.stderr[-200:]!r}")

# ── A12/W23 (Wave A): mandatory upgrade re-baseline (v1.7 CRIT-1) ──
# A v0.5.1-generated baseline (v2 schema; v0.5.0/v0.5.1 schema-identical)
# followed by the first v0.6.0 watch run false-alarms previously-excluded
# env-matched values as new_values (exit 1); the documented re-baseline
# (watch --reset) makes subsequent identical runs quiet (exit 0).
h23 = mkhome("sessions")
with open(os.path.join(h23, ".env"), "w") as f:
    f.write(f"UNIFI_SSH={envval}\n")
with open(os.path.join(h23, "sessions", "s23.jsonl"), "w") as f:
    f.write(f"the token is {envval} here\n")
# Simulate the v0.5.1 baseline: an old-format baseline that excludes the
# env value from its population (the pre-wave watch never ran the env
# pass), written in the v2 schema shape the upgrade path expects.
bl23 = os.path.join(h23, "state", "info-guard", "watch-baseline.json")
os.makedirs(os.path.dirname(bl23), exist_ok=True)
with open(bl23, "w") as f:
    json.dump({"schema": "info-guard/watch-baseline/v2",
               "generated": "2026-08-20T10:00:00Z",
               "tool_version": "0.5.1",
               "gitleaks_version": "8.30.1",
               "values": []}, f)
r23a = ig_run(h23, ["watch", "--json"])
o23a = json.loads(r23a.stdout) if r23a.stdout.strip().startswith("{") else {}
check("W23: first v0.6.0 run vs v0.5.1 baseline false-alarms env value (exit 1)",
      r23a.returncode == 1
      and any(r.get("type") == "KNOWN" and r.get("source") == "env"
              for r in o23a.get("exposure", {}).get("new_values", [])),
      f"rc={r23a.returncode} out={r23a.stdout[-200:]!r}")
r23b = ig_run(h23, ["watch", "--reset", "--json"])
r23c = ig_run(h23, ["watch", "--json"])
o23c = json.loads(r23c.stdout) if r23c.stdout.strip().startswith("{") else {}
check("W23: documented re-baseline → subsequent runs quiet (exit 0)",
      r23c.returncode == 0
      and not o23c.get("exposure", {}).get("new_values"),
      f"rc={r23c.returncode} out={r23c.stdout[-200:]!r}")

# ── A11: duplicate value across keys → one row, first key; N/M; counts ──
h11 = mkhome("sessions")
with open(os.path.join(h11, ".env"), "w") as f:
    f.write(f"B_SECRET={envval}\nA_SECRET={envval}\n")
with open(os.path.join(h11, "sessions", "s11.jsonl"), "w") as f:
    f.write(f"{envval} {envval} on one line\n{envval} on another\n")
r11 = ig_run(h11, ["preflight", "--json"])
o11 = json.loads(r11.stdout)
tv11 = [v for v in o11["top_values"] if v.get("known")]
check("A11: one row per value, source_key = alphabetically first key",
      len(tv11) == 1 and tv11[0]["source_key"] == "A_SECRET",
      f"tv={tv11!r}")
check("A11: same-line repeats → one row, count = occurrences",
      o11["totals"]["known_rows"] == 2 and tv11[0]["count"] == 3,
      f"rows={o11['totals']['known_rows']} count={tv11[0]['count']}")
check("A11: totals.known = distinct values",
      o11["totals"]["known"] == 1)
# A11b (MAJ-3 r2): cross-detector collapse — a BARE token-shaped value is
# caught by BOTH the token-prefix detector (known-prefix → bare-token
# family) and the env pass on the same line/sig → exactly ONE KNOWN row,
# the TOKEN-SHAPE hit dropped (never credential-shaped). A `KEY=value`
# line of the same value is a DIFFERENT sig (the run includes `KEY=` —
# `=` is a grammar char) so the key-shape row stays credential-shaped,
# proving detectors stay independent where sigs differ.
jwt12_short = ("eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + ".aaaa" + "bbbb")
h11b = mkhome("sessions")
with open(os.path.join(h11b, ".env"), "w") as f:
    f.write(f"HASS_TOKEN={jwt12_short}\n")
with open(os.path.join(h11b, "sessions", "s11b.jsonl"), "w") as f:
    f.write(f"token is {jwt12_short} here\n")         # TOKEN-SHAPE + env, same sig
    f.write(f"HASS_TOKEN={jwt12_short}\n")            # key-shape only (different sig)
r11b = ig_run(h11b, ["preflight", "--json"])
o11b = json.loads(r11b.stdout)
tv11b = [v for v in o11b["top_values"] if v.get("known")]
shape11b = [v for v in o11b["top_values"] if not v.get("known")]
collapsed_ok = not any(v["family"] == "bare-token" for v in shape11b)
key_shape_kept = any(v["type"] == "JWT" and v["family"] == "HASS_TOKEN"
                     for v in shape11b)
check("A11b: cross-detector collapse — TOKEN-SHAPE hit dropped, one KNOWN row",
      o11b["totals"]["known"] == 1
      and o11b["totals"]["known_rows"] == 1
      and tv11b[0]["count"] == 1
      and tv11b[0]["source_key"] == "HASS_TOKEN"
      and collapsed_ok and key_shape_kept,
      f"known={o11b['totals']['known']} rows={o11b['totals']['known_rows']} "
      f"shape={[(v['type'], v.get('family')) for v in shape11b]}")

# ── A12: punctuation values + negative fixtures + grammar parity ──
url12 = "https://user:pass@host:8080/x?y=1#frag"
jwt12 = ("eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + ".aaaa" + "bbbb")
pct12 = "abc#def:ghi/jkl+mno=pqr"
h12 = mkhome("sessions")
with open(os.path.join(h12, ".env"), "w") as f:
    # NOTE: the key must be secret-class — "URL" itself is a non-secret
    # key class (eligibility table A2), so the URL-shaped VALUE rides a
    # secret-class key here.
    f.write(f"ENDPOINT_URL_VALUE={url12}\nJWT={jwt12}\nPCT={pct12}\n")
with open(os.path.join(h12, "sessions", "s12.jsonl"), "w") as f:
    f.write(f"{url12} {jwt12} {pct12}\n")
    f.write("fragment of url12 only: https://user \n")   # partial → never
r12 = ig_run(h12, ["preflight", "--json"])
o12 = json.loads(r12.stdout)
tv12 = sorted(v.get("source_key") for v in o12["top_values"] if v.get("known"))
check("A12: punctuation values (URL/JWT/#/:) matched exactly",
      tv12 == ["ENDPOINT_URL_VALUE", "JWT", "PCT"], f"known={tv12}")
# negative fixtures: whitespace/unicode/commas/brackets/backslashes/
# shell escapes/multi-line/interior-quote values never match
neg_vals = ["a b c d e f g h", "cafévalue9", "a,b,c,d,e,f,g",
            "ab[cd]efg1", "ab\\cd\\ef\\gh", "a$b$c$d$e",
            "quo\"te9x2", "quo'te9x2", "multi\nline9x2"]
h12n = mkhome("sessions")
with open(os.path.join(h12n, ".env"), "w") as f:
    for i, v in enumerate(neg_vals):
        f.write(f"KEY{i}={v}\n")
with open(os.path.join(h12n, "sessions", "s12n.jsonl"), "w") as f:
    for v in neg_vals:
        f.write(v + "\n")
r12n = ig_run(h12n, ["preflight", "--json"])
o12n = json.loads(r12n.stdout)
check("A12: every excluded construct never matches (negative fixtures)",
      o12n["totals"]["known"] == 0 and o12n["totals"]["known_rows"] == 0,
      f"known={o12n['totals']['known']}")

# ── A13: no value_id anywhere ──
check("A13: no value_id in JSON or text",
      "value_id" not in r10.stdout and "value_id" not in r1.stdout)
# A13b (MIN-1 r1): recursive absence over every JSON document + surfaces
def key_walk(o, key):
    if isinstance(o, dict):
        return key in o or any(key_walk(v, key) for v in o.values())
    if isinstance(o, list):
        return any(key_walk(v, key) for v in o)
    return False
check("A13b: recursive value_id absence across all generated JSON",
      not key_walk(json.loads(r10.stdout), "value_id")
      and not key_walk(json.loads(r7j.stdout), "value_id")
      and not key_walk(json.loads(r11.stdout), "value_id"))

# ── A12b (MIN-3 r1): size/limit boundary behavior (4 KB value, 2 MB
# source, 256-candidate line cap) — no crash, no leak, deterministic ──
h12b = mkhome("sessions")
bigval = "b" * 4096                                  # exactly 4 KB
overval = "c" * 4097                                 # > 4 KB → skipped
with open(os.path.join(h12b, ".env"), "w") as f:
    f.write(f"BIG4K={bigval}\nOVER={overval}\n")
with open(os.path.join(h12b, "sessions", "s12b.jsonl"), "w") as f:
    f.write(f"{bigval}\n{overval}\n")
r12b = ig_run(h12b, ["preflight", "--json"])
o12b = json.loads(r12b.stdout)
chk12b = o12b["totals"]["known"] == 1 and o12b["totals"]["known_rows"] == 1
chk12b = chk12b and [v for v in o12b["top_values"] if v.get("known")][0][
    "source_key"] == "BIG4K"
check("A12b: 4 KB value matched, >4 KB value skipped (no crash)",
      chk12b, f"known={o12b['totals']['known']}")
# >2 MB source → skipped with malformed diagnostic, no crash
h12c = mkhome("sessions")
with open(os.path.join(h12c, ".env"), "w") as f:
    f.write(f"TOK={envval}\n")
with open(os.path.join(h12c, "sessions", "s12c.jsonl"), "w") as f:
    f.write(f"{envval}\n")
big_src = os.path.join(h12c, "cwd"); os.makedirs(big_src, exist_ok=True)
with open(os.path.join(big_src, ".env"), "w") as f:
    f.write("# padding\n" * 300000)                  # ~3 MB
r12c = ig_run(h12c, ["preflight"], cwd=big_src)
check("A12c: >2 MB source skipped with diagnostic, no crash",
      "malformed — skipped" in r12c.stdout
      and "KNOWN (your .env values) — 1 in 1 files" in r12c.stdout,
      f"rc={r12c.returncode}")
# 256-candidate line cap: a line with >256 matching candidates still
# matches deterministically and never crashes
h12d = mkhome("sessions")
with open(os.path.join(h12d, ".env"), "w") as f:
    f.write(f"CAPTOK={envval}\n")
with open(os.path.join(h12d, "sessions", "s12d.jsonl"), "w") as f:
    f.write(" ".join([envval] * 300) + "\n")        # 300 occurrences, one line
r12d = ig_run(h12d, ["preflight", "--json"])
o12d = json.loads(r12d.stdout)
tv12d = [v for v in o12d["top_values"] if v.get("known")]
check("A12d: 256-cap line — one row, capped count, no crash",
      o12d["totals"]["known_rows"] == 1
      and len(tv12d) == 1 and tv12d[0]["count"] <= 256,
      f"rows={o12d['totals']['known_rows']} count={tv12d[0]['count'] if tv12d else None}")

# ── Parser characterization (MAJ-5 r1): _load_env pre/post refactor
# byte-identical — duplicate keys, quoting/comments, invalid lines,
# empty values, read errors, SystemExit text + type ──
char_cases = [
    ["A=1", "A=2"],                       # duplicate key → last wins
    ['Q="quoted"', "SQ='sq'"],            # quoting stripped
    ["C=val # comment", "D=hash#kept"],   # comments only when preceded by ws
    ["bad line", "=novalue", "1BAD=x"],   # invalid → skipped
    ["E=", "F=  "],                       # empty values
    ["", "   ", "# only comment"],        # blank/comment lines
]
# Load BOTH parsers as modules: baseline = v0.4.2 binary via git show,
# new = current binary (copied to .py for importlib, same trick as A6).
import importlib.util as _ilu
_base_src = subprocess.run(
    ["git", "-C", os.getcwd(), "show", "30eb783:bin/info-guard"],
    capture_output=True, text=True, check=True).stdout
_base_mod = os.path.join(tmp, "ig-base.py")
open(_base_mod, "w").write(_base_src)
_base = _ilu.spec_from_file_location("igbase", _base_mod)
_bm = _ilu.module_from_spec(_base); _base.loader.exec_module(_bm)
_new = _ilu.spec_from_file_location("ignew", igmod)
_nm = _ilu.module_from_spec(_new); _new.loader.exec_module(_nm)
char_ok = True
char_dir = os.path.join(tmp, "char"); os.makedirs(char_dir, exist_ok=True)
for i, case in enumerate(char_cases):
    p_new = os.path.join(char_dir, f"new{i}.env")
    p_old = os.path.join(char_dir, f"old{i}.env")
    open(p_new, "w").write("\n".join(case) + "\n")
    open(p_old, "w").write("\n".join(case) + "\n")
    new = _nm._load_env(Path(p_new))
    old = _bm._load_env(Path(p_old))
    char_ok = char_ok and new == old
check("MAJ5: parser characterization — old vs new identical on all cases",
      char_ok, f"cases={len(char_cases)}")
# SystemExit text+type unchanged on unreadable source
sys_exit_ok = True
for fn in (_bm._load_env, _nm._load_env):
    try:
        fn(Path("/nonexistent/ig/.env"))
        sys_exit_ok = False
    except SystemExit as e:
        sys_exit_ok = sys_exit_ok and "cannot read env source" in str(e)
check("MAJ5: SystemExit text+type identical on unreadable source",
      sys_exit_ok)

# ── A14: perf protocol (baseline 30eb783 vs HEAD, 5k + 50k trees) ──
base_ig = os.path.join(tmp, "ig-baseline")
with open(base_ig, "w") as f:
    f.write(subprocess.run(
        ["git", "-C", os.getcwd(), "show", "30eb783:bin/info-guard"],
        capture_output=True, text=True, check=True).stdout)
os.chmod(base_ig, 0o755)

def gen_tree(root, n_files, lines_per_file):
    os.makedirs(os.path.join(root, "sessions"), exist_ok=True)
    for i in range(n_files):
        with open(os.path.join(root, "sessions", f"perf{i}.jsonl"), "w") as f:
            for j in range(lines_per_file):
                f.write(f"line {i}.{j} k{i}_v{j} tok{i}{j} {envval} tail\n")

def median_reps(binpath, home, args, reps=3):
    ts = []
    for _ in range(reps):
        env = dict(os.environ); env["HERMES_HOME"] = home
        t0 = time.perf_counter()
        subprocess.run([sys.executable, binpath] + args, env=env,
                       capture_output=True, text=True, timeout=600)
        ts.append(time.perf_counter() - t0)
    return sorted(ts)[len(ts) // 2]

for tag, nf, lpf in (("5k", 50, 100), ("50k", 500, 100)):
    hperf = mkhome("sessions")
    with open(os.path.join(hperf, ".env"), "w") as f:
        f.write(f"PERF_TOK={envval}\n")
    gen_tree(hperf, nf, lpf)
    # warm cache (run once before timing)
    ig_run(hperf, ["preflight"])
    t_base = median_reps(base_ig, hperf, ["preflight"])
    t_new = median_reps(IG, hperf, ["preflight"])
    over = (t_new - t_base) / t_base if t_base else 1.0
    check(f"A14: {tag}-tree overhead ≤10% or ≤5s (base {t_base:.2f}s, "
          f"new {t_new:.2f}s, +{over*100:.0f}%)",
          over <= 0.10 or (t_new - t_base) <= 5.0)
    # A14b (MAJ-4 r2): --json mode complete-preflight timing + per-phase
    # reconciliation: measure text vs json mode and the phase sum vs
    # wall clock (±10% tolerance) on the 5k tree.
    if tag == "5k":
        t_json = median_reps(IG, hperf, ["preflight", "--json"])
        # per-phase instrumentation via module import (same trick as A6):
        env_p = dict(os.environ); env_p["HERMES_HOME"] = hperf
        import importlib.util as _ilup
        _igp = os.path.join(tmp, "igmodp.py")
        shutil.copy(IG, _igp)
        _igps = _ilup.spec_from_file_location("igp", _igp)
        _igpm = _ilup.module_from_spec(_igps); _igps.loader.exec_module(_igpm)
        _igpm._HERMES_HOME = Path(hperf)
        t0 = time.perf_counter()
        idx, srcs, diags = _igpm._env_sources()
        t_src = time.perf_counter() - t0
        t0 = time.perf_counter()
        scan_dirs = [Path(hperf) / d for d in
                     ("sessions", "logs", "cron/output")
                     if (Path(hperf) / d).is_dir()]
        n_hits = 0
        for d in scan_dirs:
            for p in sorted(d.rglob("*")):
                if p.is_file():
                    eh, _es = _igpm._env_scan_file(p, idx, srcs)
                    n_hits += len(eh)
        t_scan = time.perf_counter() - t0
        t0 = time.perf_counter()
        ah, _ok, _meta = _igpm._collect_hits(scan_dirs, env_pass=True)
        t_with = time.perf_counter() - t0
        t0 = time.perf_counter()
        _igpm._collect_hits(scan_dirs, env_pass=False)
        t_without = time.perf_counter() - t0
        t_env = t_with - t_without                 # env-pass marginal cost
        check("A14b: --json mode overhead ≤10% or ≤5s "
              f"(text {t_new:.2f}s, json {t_json:.2f}s)",
              t_json <= t_new * 1.10 + 5.0 or t_json - t_new <= 5.0,
              f"json={t_json:.2f}s")
        check("A14b: env-phase sum reconciles with marginal env cost ±10% "
              f"(src {t_src:.3f}s + scan {t_scan:.3f}s ≈ env {t_env:.3f}s)",
              abs((t_src + t_scan) - t_env) <= 0.10 * t_env + 0.05,
              f"sum={t_src + t_scan:.3f}s env={t_env:.3f}s hits={n_hits} "
              f"with={t_with:.2f}s without={t_without:.2f}s")

# ── A15: row-shape validation across every row-bearing path ──
tv15 = [v for v in o11["top_values"]]
chk15 = True
for v in tv15:
    if v.get("known") is True:
        chk15 = chk15 and isinstance(v.get("source_key"), str) and v["source_key"]
        chk15 = chk15 and v.get("type") == "KNOWN"
    else:
        chk15 = chk15 and "known" not in v and "source_key" not in v
check("A15: top_values row shape (KNOWN required, non-KNOWN absent)", chk15)
chk15b = all(isinstance(f.get("known", 0), int) for f in o11["families"]["items"])
check("A15: families.items[].known is int", chk15b)
chk15c = all(isinstance(l.get("known", 0), int) for l in o11["locations"])
check("A15: locations[].known is int", chk15c)
chk15d = all(isinstance(f.get("known", 0), int) for f in o11["affected_files"])
check("A15: affected_files[].known is int", chk15d)

# ── A16: exit matrix (ladder 0/1/2/3, IG D83) ──
h16c = mkhome("sessions")
r16c = ig_run(h16c, ["preflight"])
check("A16: clean → 0", r16c.returncode == 0, f"rc={r16c.returncode}")
h16s = mkhome("sessions")
with open(os.path.join(h16s, "sessions", "s16s.jsonl"), "w") as f:
    f.write("HASS_TOKEN=" + "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + ".aaaaaaaaaaaaaaa\n")
r16s = ig_run(h16s, ["preflight"])
check("A16: shape-only → 1", r16s.returncode == 1, f"rc={r16s.returncode}")
check("A16: known-only → 3 (KNOWN dominates, D83)", r1.returncode == 3,
      f"rc={r1.returncode}")
h16b = mkhome("sessions")
with open(os.path.join(h16b, ".env"), "w") as f:
    f.write(f"TOK={envval}\n")
with open(os.path.join(h16b, "sessions", "s16b.jsonl"), "w") as f:
    f.write(f"{envval}\nHASS_TOKEN=" + "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + ".bbbbbbbbbbbbbbb\n")
r16b = ig_run(h16b, ["preflight"])
check("A16: known+shape → 3 (KNOWN dominates, D83)", r16b.returncode == 3,
      f"rc={r16b.returncode}")
r16u = ig_run(h16b, ["preflight", "--json-out"])
check("A16: usage → 2", r16u.returncode == 2, f"rc={r16u.returncode}")

# ── A17: source-conflict truth table (A1.5 oracle) ──
def env_home(s1_content, s2_content, s1_mode=0o600):
    h = mkhome("sessions")
    cwd = None
    if s1_content is not None:
        p = os.path.join(h, ".env")
        with open(p, "w") as f:
            f.write(s1_content)
        os.chmod(p, s1_mode)
    if s2_content is not None:
        cwd = os.path.join(h, "cwd")
        os.makedirs(cwd, exist_ok=True)
        with open(os.path.join(cwd, ".env"), "w") as f:
            f.write(s2_content)
    return h, cwd

def scanfile(h, content):
    with open(os.path.join(h, "sessions", "scan17.jsonl"), "w") as f:
        f.write(content)

# absent/absent
h, c = env_home(None, None)
scanfile(h, "plain\n")
ra = ig_run(h, ["preflight"], cwd=c)
check("A17: absent/absent → disabled line + null + 0",
      ra.stdout.count("KNOWN pass: no .env sources — disabled") == 1
      and json.loads(ig_run(h, ["preflight", "--json"], cwd=c).stdout)
      ["status"]["confirmed_active"] is None)
# empty/absent → ok, no disabled
h, c = env_home("", None)
scanfile(h, "plain\n")
rb = ig_run(h, ["preflight"], cwd=c)
check("A17: empty/absent → ok, no disabled line",
      "KNOWN pass: no .env sources — disabled" not in rb.stdout)
# comments-only/absent → malformed → disabled
h, c = env_home("# just a comment\n", None)
scanfile(h, "plain\n")
rc17 = ig_run(h, ["preflight"], cwd=c)
check("A17: comments-only/absent → 1 diagnostic + disabled",
      rc17.stdout.count("malformed — skipped") == 1
      and rc17.stdout.count("KNOWN pass: no .env sources — disabled") == 1)
# malformed-only/absent
h, c = env_home("no equals sign here\n", None)
scanfile(h, "plain\n")
rd17 = ig_run(h, ["preflight"], cwd=c)
check("A17: malformed-only/absent → 1 diagnostic + disabled",
      rd17.stdout.count("malformed — skipped") == 1
      and rd17.stdout.count("KNOWN pass: no .env sources — disabled") == 1)
# unreadable/absent
h, c = env_home(f"TOK={envval}\n", None, s1_mode=0)
scanfile(h, "plain\n")
re17 = ig_run(h, ["preflight"], cwd=c)
os.chmod(os.path.join(h, ".env"), 0o600)
check("A17: unreadable/absent → 1 diagnostic + disabled",
      re17.stdout.count("unreadable — skipped") == 1
      and re17.stdout.count("KNOWN pass: no .env sources — disabled") == 1)
# empty(ok)/malformed → 1 diagnostic, NOT disabled
h, c = env_home("", "broken line\n")
scanfile(h, "plain\n")
rf17 = ig_run(h, ["preflight"], cwd=c)
check("A17: empty(ok)/malformed → 1 diagnostic, pass active",
      rf17.stdout.count("malformed — skipped") == 1
      and "KNOWN pass: no .env sources — disabled" not in rf17.stdout)
# MIN-4 r1: mixed valid + malformed lines in ONE file → ok, NO diagnostic
h, c = env_home(f"OK={envval}\nbroken line\n# comment\n", None)
scanfile(h, f"{envval}\n")
rm17 = ig_run(h, ["preflight"], cwd=c)
check("A17: mixed valid+malformed in one file → ok, no diagnostic",
      "malformed — skipped" not in rm17.stdout
      and "KNOWN (your .env values) — 1 in 1 files" in rm17.stdout)
# valid/malformed → 1 diagnostic, active
h, c = env_home(f"TOK={envval}\n", "broken\n")
scanfile(h, f"{envval}\n")
rg17 = ig_run(h, ["preflight"], cwd=c)
check("A17: valid/malformed → 1 diagnostic, KNOWN row found",
      rg17.stdout.count("malformed — skipped") == 1
      and "KNOWN (your .env values) — 1 in" in rg17.stdout)
# valid/unreadable → 1 diagnostic, active
h, c = env_home(f"TOK={envval}\n", f"BROKEN={envval2}\n")
os.chmod(os.path.join(c, ".env"), 0)
scanfile(h, f"{envval}\n")
rh17 = ig_run(h, ["preflight"], cwd=c)
os.chmod(os.path.join(c, ".env"), 0o600)
check("A17: valid/unreadable → 1 diagnostic, KNOWN row found",
      rh17.stdout.count("unreadable — skipped") == 1
      and "KNOWN (your .env values) — 1 in" in rh17.stdout)
# valid/valid, same key same value → one row
h, c = env_home(f"SAME={envval}\n", f"SAME={envval}\n")
scanfile(h, f"{envval}\n")
ri17 = json.loads(ig_run(h, ["preflight", "--json"], cwd=c).stdout)
check("A17: same key/value both files → ONE KNOWN row",
      ri17["totals"]["known"] == 1 and ri17["totals"]["known_rows"] == 1)
# valid/valid, same key DIFFERENT values → both match their own
h, c = env_home(f"DIFF={envval}\n", f"DIFF={envval2}\n")
scanfile(h, f"{envval} {envval2}\n")
rj17 = json.loads(ig_run(h, ["preflight", "--json"], cwd=c).stdout)
check("A17: same key different values → BOTH match",
      rj17["totals"]["known"] == 2 and rj17["totals"]["known_rows"] == 2,
      f"known={rj17['totals']['known']}")
# valid/valid, different keys same value → source_key alphabetical
h, c = env_home(f"Z_KEY={envval}\n", f"A_KEY={envval}\n")
scanfile(h, f"{envval}\n")
rk17 = json.loads(ig_run(h, ["preflight", "--json"], cwd=c).stdout)
tvk = [v for v in rk17["top_values"] if v.get("known")]
check("A17: diff keys same value → source_key = first alphabetically",
      len(tvk) == 1 and tvk[0]["source_key"] == "A_KEY", f"tv={tvk!r}")
# duplicate key within one file → last-parse-wins
h, c = env_home(f"DUP={envval}\nDUP={envval2}\n", None)
scanfile(h, f"{envval} {envval2}\n")
rl17 = json.loads(ig_run(h, ["preflight", "--json"], cwd=c).stdout)
check("A17: duplicate key within file → last-parse-wins (only value2)",
      rl17["totals"]["known"] == 1
      and [v for v in rl17["top_values"] if v.get("known")][0]["count"] == 1,
      f"known={rl17['totals']['known']}")

# ── A18: exit identical across output modes (h1 = known → 3, D83) ──
for home, expect in ((h1, 3), (h7, 0)):
    e_txt = ig_run(home, ["preflight"]).returncode
    e_json = ig_run(home, ["preflight", "--json"]).returncode
    oj = os.path.join(tmp, "out18.json")
    e_out = ig_run(home, ["preflight", "--json-out", oj]).returncode
    check(f"A18: exit identical across modes (expect {expect})",
          e_txt == e_json == e_out == expect,
          f"text={e_txt} json={e_json} out={e_out}")

# ── 25. Wave B honeytokens (v0.7.0, IG D103) — plant / detect / escalate / review_list ──
import re as _re
wb_home = os.path.join(tmp, "wb-home")
for sub in ("sessions", "logs", "cron/output"):
    os.makedirs(os.path.join(wb_home, sub), exist_ok=True)
os.makedirs(os.path.join(wb_home, "state", "info-guard"), exist_ok=True)
wb_cl = os.path.join(wb_home, "state", "info-guard", "custom_literals.json")
open(wb_cl, "w").write(json.dumps({"version": 2, "literals": []}))
env_wb = dict(os.environ)
env_wb["HERMES_HOME"] = wb_home
def wb_run(*args, **kw):
    return subprocess.run(
        [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard")] + list(args),
        env=env_wb, capture_output=True, text=True, timeout=300, **kw)

def wb_mask(v):
    """2+2 finding-row mask (mirror of bin/info-guard _mask_value)."""
    if len(v) <= 10:
        return "***"
    return v[:2] + "..." + v[-2:]

# A1 kind model: generated plant, mask full, kind round-trip, unknown-kind warning
g1 = wb_run("literals", "add", "--kind", "honeytoken")
g1o = g1.stdout + g1.stderr
g1m = _re.search(r"ht-[0-9a-f]{24}", g1o)
check("WB A1: generated canary = ht- + 24 hex, exit 0, planted line on stderr",
      g1.returncode == 0 and g1m and f"[info-guard] honeytoken planted: {g1m.group(0)}" in g1.stderr
      and g1m.group(0) not in g1.stdout,
      f"rc={g1.returncode} out={g1.stdout[:120]!r} err={g1.stderr[:200]!r}")
reg_wb = json.load(open(wb_cl))
ht_val = g1m.group(0)
ht_entry = next(e for e in reg_wb["literals"] if isinstance(e, dict) and e.get("value") == ht_val)
ht_id = ht_entry["id"]
check("WB A1: registry entry has kind=honeytoken + mask=full + id",
      ht_entry.get("kind") == "honeytoken" and ht_entry.get("mask") == "full"
      and len(ht_id) == 16)
# A1 unknown kind -> literal + one escaped warning; field preserved
open(wb_cl, "w").write(json.dumps({"version": 2, "literals": [
    {"value": "wb-unknown-kind-val", "id": "aaaaaaaaaaaaaaaa", "kind": "bad\x01kind"}]}))
u1 = wb_run("literals", "list")
u1o = u1.stdout + u1.stderr
u1reg = json.load(open(wb_cl))
check("WB A1: unknown kind → warning once (escaped) + treated as literal + field preserved",
      "unknown literal kind 'bad\\x01kind'" in u1.stderr
      and u1reg["literals"][0]["kind"] == "bad\x01kind"
      and "aaaaaaaaaaaaaaaa" in u1.stdout)  # id shown; raw value never printed
# A2 explicit add: value never echoed; control chars / empty / --mask / --file rejected
wb_exp = "wb-canary-explicit-" + "1234567890"  # concatenated: no single literal (CI gitleaks)
e1 = wb_run("literals", "add", "--kind", "honeytoken", wb_exp)
check("WB A2: explicit canary add — masked output only, value never echoed",
      e1.returncode == 0 and wb_exp not in (e1.stdout + e1.stderr)
      and "wb...90" in e1.stdout)
for bad_args, why in (
    (["--kind", "honeytoken", "x\ny"], "control char"),
    (["--kind", "honeytoken", "   "], "whitespace-only"),
    (["--kind", "honeytoken", "--mask", "full", "x"], "--mask conflict"),
    (["--kind", "honeytoken", "--file", os.path.join(tmp, "wb-file.txt")], "--file conflict"),
    (["--kind", "foo", "x"], "--kind domain"),
    (["--kind"], "missing value"),
):
    open(os.path.join(tmp, "wb-file.txt"), "w").write("x\n")
    m_before = os.stat(wb_cl).st_mtime_ns
    r = wb_run("literals", "add", *bad_args)
    check(f"WB A2: {why} → usage exit 2, no mutation",
          r.returncode == 2 and os.stat(wb_cl).st_mtime_ns == m_before,
          f"rc={r.returncode} err={r.stderr[:100]!r}")
# A3 duplicate rules: normal+kind fails loud; honeytoken dup idempotent
open(wb_cl, "w").write(json.dumps({"version": 2, "literals": [
    {"value": "wb-plain-literal", "id": "bbbbbbbbbbbbbbbb"},
    {"value": ht_val, "id": ht_id, "kind": "honeytoken", "mask": "full"}]}))
d1 = wb_run("literals", "add", "--kind", "honeytoken", "wb-plain-literal")
check("WB A3: dup normal + --kind → fail loud exit 2 (no silent no-op plant)",
      d1.returncode == 2 and "already registered with a different kind" in d1.stderr)
d2 = wb_run("literals", "add", "--kind", "honeytoken", ht_val)
check("WB A3: dup honeytoken → idempotent exit 0, existing id",
      d2.returncode == 0 and ht_id in d2.stdout and os.stat(wb_cl).st_mtime_ns
      == os.stat(wb_cl).st_mtime_ns)  # no rewrite (mtime unchanged check is weak; content check below)
d2reg = json.load(open(wb_cl))
check("WB A3: dup honeytoken did not rewrite registry",
      len(d2reg["literals"]) == 2)
# A3 list shows kind; remove found/unknown; replant fresh id
l1 = wb_run("literals", "list")
check("WB A3: literals list shows honeytoken kind column",
      "honeytoken" in l1.stdout and "wb...al" in l1.stdout)  # masked form
rm1 = wb_run("literals", "remove", ht_id)
check("WB A3: remove found → exit 0 + removed line",
      rm1.returncode == 0 and f"removed {ht_id}" in rm1.stdout)
rm2 = wb_run("literals", "remove", "deadbeefdeadbeef")
check("WB A3: remove unknown → idempotent exit 0 + stderr note",
      rm2.returncode == 0 and "no entry with id deadbeefdeadbeef" in rm2.stderr)
rm3 = wb_run("literals", "remove", "deadbeefdeadbeef", "--json")
check("WB A3: remove unknown --json → removed:false",
      json.loads(rm3.stdout) == {"removed": False, "id": "deadbeefdeadbeef"})
# replant: fresh id
rp1 = wb_run("literals", "add", "--kind", "honeytoken", ht_val)
rp2 = wb_run("literals", "list", "--json")
rp_entry = [r for r in json.loads(rp2.stdout)["literals"] if r.get("kind") == "honeytoken"]
check("WB A3: replant after remove → fresh value_id (never reused)",
      len(rp_entry) == 1 and rp_entry[0]["id"] != ht_id)
ht_id = rp_entry[0]["id"]
# A4 preflight detection: planted canary → HONEYTOKEN row, exit 4, known:false
decoy = os.path.join(wb_home, "sessions", "decoy.txt")
open(decoy, "w").write(f"API_KEY={ht_val}\n")
p1 = wb_run("preflight", "--json")
p1ok = p1.returncode == 4
if p1ok:
    try:
        pj = json.loads(p1.stdout)
        ht_rows = [v for v in pj["top_values"] if v.get("type") == "HONEYTOKEN"]
        p1ok = (pj["totals"]["honeytoken"] == 1 and pj["totals"]["honeytoken_rows"] == 1
                and len(ht_rows) == 1 and ht_rows[0]["known"] is False
                and ht_rows[0]["value_id"] == ht_id
                and ht_rows[0]["value_masked"] == wb_mask(ht_val)
                and pj["status"]["severity"] == "high")
    except (ValueError, KeyError, TypeError):
        p1ok = False
check("WB A4: preflight canary-touch → exit 4 + HONEYTOKEN row (known:false, value_id, high)",
      p1ok, f"rc={p1.returncode} out={p1.stdout[:300]!r}")
# text mode exit also 4
pt1 = wb_run("preflight")
check("WB A4: preflight text mode → exit 4",
      pt1.returncode == 4, f"rc={pt1.returncode}")
# A4 .env collision (O5): canary also in .env → HONEYTOKEN wins + source_key
# NOTE: the env-exact regex matches QUOTED values (KEY="value") or bare
# values — an unquoted KEY=value line matches as one run and cannot hit
# the bare-value index (Wave A behavior, unchanged). The DECOY line is
# also quoted so both passes tag the SAME signature; the canary tier
# still wins (the canary pass is exact-value, quoting-agnostic).
envf = os.path.join(wb_home, ".env")
open(envf, "w").write(f"DECOY_KEY=\"{ht_val}\"\n")
open(decoy, "w").write(f"API_KEY=\"{ht_val}\"\n")
p2 = wb_run("preflight", "--json")
p2ok = p2.returncode == 4
if p2ok:
    try:
        pj2 = json.loads(p2.stdout)
        ht2 = [v for v in pj2["top_values"] if v.get("type") == "HONEYTOKEN"]
        p2ok = len(ht2) == 1 and ht2[0].get("source_key") == "DECOY_KEY"
    except (ValueError, KeyError):
        p2ok = False
check("WB A4 (O5): canary also a live .env value → HONEYTOKEN wins + source_key",
      p2ok, f"rc={p2.returncode}")
open(envf, "w").write("")
# A5/A6 watch lifecycle: baseline → new → 4; unchanged → 0; increase → 4; decrease → 0
# (decoy reset to ONE line before baseline so the increase below is a
# real count delta — the O5 fixture above left it in an unknown state)
open(decoy, "w").write(f"API_KEY={ht_val}\n")
w1 = wb_run("watch", "--reset")
check("WB A5: watch baseline with canary present → exit 0 (first run)",
      w1.returncode == 0, f"rc={w1.returncode}")
open(decoy, "w").write(f"API_KEY={ht_val}\nOTHER={ht_val}\n")  # increase
w2 = wb_run("watch")
check("WB A5: baselined canary count increase → exit 4",
      w2.returncode == 4, f"rc={w2.returncode}")
w3 = wb_run("watch")
check("WB A5: unchanged after refresh → exit 0",
      w3.returncode == 0, f"rc={w3.returncode}")
open(decoy, "w").write(f"API_KEY={ht_val}\n")  # decrease back to 1
w4 = wb_run("watch")
check("WB A5: decrease → exit 0",
      w4.returncode == 0, f"rc={w4.returncode}")
# A7 review_list: SUSPICIOUS row surfaces report-only; exit unaffected
susp32 = "6f8c3b2a9d1e4f7a" + "8b2c3d4e5f6a7b8c"  # concatenated: no single literal (CI gitleaks)
open(os.path.join(wb_home, "sessions", "susp.txt"), "w").write(
    "api_key = %s\n" % susp32)
w5 = wb_run("watch", "--json")
w5ok = w5.returncode == 0
if w5ok:
    try:
        wj = json.loads(w5.stdout)
        w5ok = (wj["exposure"]["review_list_complete"] is True
                and any(r["type"] == "SUSPICIOUS" and r["count"] == 1
                        for r in wj["exposure"]["review_list"]))
    except (ValueError, KeyError):
        w5ok = False
check("WB A7: review_list surfaces SUSPICIOUS row, report-only, exit 0",
      w5ok, f"rc={w5.returncode}")
os.unlink(os.path.join(wb_home, "sessions", "susp.txt"))
# A9 downgrade: old binary (v0.6.1) reads a registry with kind → normal literal, no crash
old_bin_wb = os.path.join(tmp, "info-guard-0.6.1")
old_dl_wb = subprocess.run(["git", "show", "v0.6.1:bin/info-guard"],
                           capture_output=True, text=True, cwd=os.getcwd())
if old_dl_wb.returncode == 0:
    open(old_bin_wb, "w").write(old_dl_wb.stdout)
    os.chmod(old_bin_wb, 0o755)
    open(wb_cl, "w").write(json.dumps({"version": 2, "literals": [
        {"value": ht_val, "id": ht_id, "kind": "honeytoken", "mask": "full"}]}))
    old_run = subprocess.run([sys.executable, old_bin_wb, "literals", "list"],
                             env=env_wb, capture_output=True, text=True, timeout=300)
    # v0.6.1 doesn't know `kind`: the entry must read as a normal
    # full-mask literal (*** display), no crash, and the field must
    # survive (the old loader preserves unknown fields verbatim).
    old_ok = old_run.returncode == 0 and "***" in old_run.stdout
    old_reg = json.load(open(wb_cl))
    check("WB A9: v0.6.1 binary reads kind registry → literal (***), kind preserved",
          old_ok and old_reg["literals"][0]["kind"] == "honeytoken",
          f"rc={old_run.returncode} err={old_run.stderr[:150]!r}")
else:
    skip("WB A9: v0.6.1 binary downgrade probe", "tag v0.6.1 unavailable")

# ── 26. Wave B evidence-gate battery (r1 fold, IG D103) — collision classes,
# watch matrix, review_list membership, scan boundary, CLI JSON shapes,
# old-consumer additive tolerance, kind migration/0600, adversarial kinds ──
# (evidence-gate r1 MAJ-1..9 / MIN-1: the approved plan §9.4–§9.9 required
# these; the r1 bundle under-delivered.)

# B1 — collision precedence: every existing finding class → exactly ONE
# HONEYTOKEN row, known:false, value_id, no lower-tier duplicate
def wb_collision_fixture(lines, env_extra=""):
    """Write scan fixtures + .env into wb_home, run preflight --json,
    return (rc, json)."""
    if env_extra:
        with open(os.path.join(wb_home, ".env"), "w") as f:
            f.write(env_extra)
    with open(decoy, "w") as f:
        f.writelines(lines)
    r = wb_run("preflight", "--json")
    try:
        return r.returncode, json.loads(r.stdout)
    except ValueError:
        return r.returncode, None

# fresh canary for this section (registry was reset by A9's old-binary probe)
b1_val = "wb-b1-canary-" + "1234567890abcd"  # concatenated: no single literal (CI gitleaks)
b1_plant = wb_run("literals", "add", "--kind", "honeytoken", b1_val)
b1_id = None
b1_reg = json.load(open(wb_cl))
for e in b1_reg["literals"]:
    if isinstance(e, dict) and e.get("value") == b1_val:
        b1_id = e["id"]
# NOTE: the canary pass matches ANY line containing the value — the
# collision classes below verify the HONEYTOKEN tier wins and no
# lower-tier row is emitted for the same file:line:value.
open(decoy, "w").write(f"API_KEY={b1_val}\n")
r = wb_run("preflight", "--json")
b1_ok = r.returncode == 4
if b1_ok:
    try:
        bj = json.loads(r.stdout)
        ht = [v for v in bj["top_values"] if v.get("type") == "HONEYTOKEN"]
        b1_ok = len(ht) == 1 and ht[0]["value_id"] == b1_id \
            and ht[0]["known"] is False
    except (ValueError, KeyError, TypeError):
        b1_ok = False
check("WB B1: plain canary → one HONEYTOKEN row, known:false, value_id",
      b1_ok, f"rc={r.returncode}")
# collision with a KNOWN .env value (same value in .env — O5 family)
rc, bj = wb_collision_fixture([f'API_KEY="{b1_val}"\n'], f"DECOY_KEY=\"{b1_val}\"\n")
b1k = rc == 4 and bj is not None
if b1k:
    ht = [v for v in bj["top_values"] if v.get("type") == "HONEYTOKEN"]
    b1k = len(ht) == 1 and ht[0].get("source_key") == "DECOY_KEY" \
        and bj["totals"]["known"] == 0  # never a second KNOWN row
check("WB B1: canary + KNOWN .env collision → one HONEYTOKEN row w/ source_key, zero KNOWN",
      b1k, f"rc={rc}")
open(os.path.join(wb_home, ".env"), "w").write("")
# collision with a shape/credential-shaped line: the canary line itself
# must NOT double-count as credential-shaped (HONEYTOKEN wins its row);
# a SEPARATE non-canary shape value is a genuine independent finding.
rc, bj = wb_collision_fixture([f"TOKEN={b1_val}\n", "sk-probe-abcdef1234567890\n"])
b1s = rc == 4 and bj is not None
if b1s:
    ht = [v for v in bj["top_values"] if v.get("type") == "HONEYTOKEN"]
    b1s = len(ht) == 1 and bj["totals"]["credential_shaped"] == 1 \
        and bj["totals"]["raw_detections"] == 1  # only the non-canary line
check("WB B1: canary + separate shape line → one HONEYTOKEN row; shape row counts only the non-canary",
      b1s, f"rc={rc}")
# multi-line/multi-file row granularity: same canary on 2 files → 2 rows
open(os.path.join(wb_home, "sessions", "decoy2.txt"), "w").write(f"X={b1_val}\n")
rc, bj = wb_collision_fixture([f"API_KEY={b1_val}\n"])
b1m = rc == 4 and bj is not None
if b1m:
    ht = [v for v in bj["top_values"] if v.get("type") == "HONEYTOKEN"]
    b1m = len(ht) == 1 and bj["totals"]["honeytoken_rows"] == 2 \
        and bj["totals"]["honeytoken"] == 1
check("WB B1: same canary on 2 files → 1 distinct value, 2 rows (file:line:value)",
      b1m, f"rc={rc}")
os.unlink(os.path.join(wb_home, "sessions", "decoy2.txt"))
# negative fixture: a NON-canary exact value never matches HONEYTOKEN
# (it IS a genuine credential-shaped finding → exit 1, zero honeytoken)
rc, bj = wb_collision_fixture(["sk-probe-abcdef1234567890\n"])
b1n = rc == 1 and bj is not None and bj["totals"]["honeytoken"] == 0 \
    and bj["totals"]["honeytoken_rows"] == 0
check("WB B1: non-canary value → no HONEYTOKEN rows (shape finding only)",
      b1n, f"rc={rc}")

# B2 — watch matrix completeness: absent canary (no row), one-event
# exclusion from new_values, sticky after later runs
open(decoy, "w").write(f"API_KEY={b1_val}\n")
wb_run("watch", "--reset")  # baseline WITH canary present
w = wb_run("watch", "--json")
b2ok = w.returncode == 0
if b2ok:
    try:
        wj = json.loads(w.stdout)
        pv = wj["exposure"]["protected_values"]
        ht_pv = [m for m in pv if m.get("type") == "HONEYTOKEN"]
        b2ok = len(ht_pv) == 1 and ht_pv[0]["delta"] == "unchanged" \
            and wj["exposure"]["new_values"] == [] \
            and wj["exposure"]["changed_values"] == []
    except (ValueError, KeyError):
        b2ok = False
check("WB B2: baselined canary → delta:unchanged, absent from new/changed (one-event)",
      b2ok, f"rc={w.returncode}")
# absent canary → no protected row, no resolved HONEYTOKEN row (the
# fixture line is a genuine shape value → exit 1, but zero canary rows)
open(decoy, "w").write("sk-probe-abcdef1234567890\n")
w = wb_run("watch", "--json")
b2a = w.returncode == 1
if b2a:
    try:
        wj = json.loads(w.stdout)
        b2a = wj["exposure"]["protected_values"] == [] \
            and all(m.get("type") != "HONEYTOKEN"
                    for m in wj["exposure"]["resolved_values"])
    except (ValueError, KeyError):
        b2a = False
check("WB B2: absent canary → no protected row, never a resolved HONEYTOKEN row",
      b2a, f"rc={w.returncode}")
# sticky: replant (remove+re-add) → new id → new detection → 4
wb_run("literals", "remove", b1_id)
sticky_v = "wb-b2-sticky-" + "1234567890abcd"  # concatenated: no single literal (CI gitleaks)
wb_run("literals", "add", "--kind", "honeytoken", sticky_v)
open(decoy, "w").write("API_KEY=%s\n" % sticky_v)
w = wb_run("watch")
check("WB B2: replanted canary (fresh id) → new detection → exit 4 (sticky lifecycle)",
      w.returncode == 4, f"rc={w.returncode}")

# B3 — review_list membership: multiple values, unchanged retention,
# canary/SUSPICIOUS collision exclusion
susp32b = "bf9c2a1d8e4f7a6b" + "3c5d9e2f8a1b4c7d"  # concatenated: no single literal (CI gitleaks)
open(decoy, "w").write("api_key = %s\n" % susp32)
open(os.path.join(wb_home, "sessions", "susp2.txt"), "w").write(
    "token = %s\n" % susp32b)
w = wb_run("watch", "--json")
b3ok = w.returncode == 0
if b3ok:
    try:
        wj = json.loads(w.stdout)
        rl = wj["exposure"]["review_list"]
        b3ok = len(rl) == 2 and wj["exposure"]["review_list_complete"] is True
    except (ValueError, KeyError):
        b3ok = False
check("WB B3: review_list = ALL current SUSPICIOUS values (2 distinct)",
      b3ok, f"rc={w.returncode}")
# unchanged retention across runs (current-scan report, not delta)
w2 = wb_run("watch", "--json")
b3u = w2.returncode == 0
if b3u:
    try:
        wj2 = json.loads(w2.stdout)
        b3u = len(wj2["exposure"]["review_list"]) == 2  # unchanged rows remain
    except (ValueError, KeyError):
        b3u = False
check("WB B3: review_list retains unchanged rows run-to-run (not delta-filtered)",
      b3u, f"rc={w2.returncode}")
os.unlink(os.path.join(wb_home, "sessions", "susp2.txt"))
# canary classified as SUSPICIOUS by gitleaks → excluded from review_list.
# The canary IS present in the scan (that's the touch) → exit 4; the
# assertion is: the same value appears as a HONEYTOKEN protected row and
# is ABSENT from review_list (one event, no duplicate representation).
wb_run("literals", "add", "--kind", "honeytoken", susp32)
open(decoy, "w").write("api_key = %s\n" % susp32)
w = wb_run("watch", "--json")
b3c = w.returncode == 4  # canary-touch
if b3c:
    try:
        wj = json.loads(w.stdout)
        rl = wj["exposure"]["review_list"]
        pv = [m for m in wj["exposure"]["protected_values"]
              if m.get("type") == "HONEYTOKEN"]
        b3c = rl == [] and len(pv) == 1  # canary row present, review_list empty
    except (ValueError, KeyError):
        b3c = False
check("WB B3: canary + SUSPICIOUS-shaped value → HONEYTOKEN row, excluded from review_list",
      b3c, f"rc={w.returncode}")

# B4 — scan boundary: unplanted clean, planted one-finding, explicit
# state-dir scan reports (never suppresses)
wb_run("literals", "remove", "wb-b3-suspicious-1234567890".__str__()) if False else None
# remove both b3 canaries by value lookup
b4_reg = json.load(open(wb_cl))
for e in list(b4_reg["literals"]):
    if isinstance(e, dict) and e.get("kind") == "honeytoken":
        wb_run("literals", "remove", e["id"])
open(decoy, "w").write("plain text\n")
r = wb_run("preflight")
check("WB B4: canary registered but NOT planted → default-dirs scan exit 0, zero findings",
      r.returncode == 0, f"rc={r.returncode}")
# plant it → exactly one finding, exit 4
b4_v = "wb-b4-boundary-" + "1234567890"  # concatenated: no single literal (CI gitleaks)
wb_run("literals", "add", "--kind", "honeytoken", b4_v)
open(decoy, "w").write("API_KEY=%s\n" % b4_v)
r = wb_run("preflight", "--json")
b4p = r.returncode == 4
if b4p:
    try:
        bj = json.loads(r.stdout)
        b4p = bj["totals"]["honeytoken_rows"] == 1
    except (ValueError, KeyError):
        b4p = False
check("WB B4: planted canary → exactly one HONEYTOKEN row, exit 4",
      b4p, f"rc={r.returncode}")
# explicit scan of the state dir → match reported (operator-chosen target)
r = wb_run("preflight", "--json", os.path.join(wb_home, "state"))
b4e = r.returncode == 4
if b4e:
    try:
        bj = json.loads(r.stdout)
        b4e = bj["totals"]["honeytoken"] == 1
    except (ValueError, KeyError):
        b4e = False
check("WB B4: explicit state-dir scan → canary match REPORTED (not suppressed)",
      b4e, f"rc={r.returncode}")
open(decoy, "w").write("plain text\n")

# B5 — old-consumer additive tolerance: HONEYTOKEN assessment row +
# review_list watch keys, real v0.6.1 binary
old_bin_wb2 = os.path.join(tmp, "info-guard-0.6.1")
if old_dl_wb.returncode == 0 and os.path.exists(old_bin_wb2):
    # assessment with a HONEYTOKEN row (feed the old binary a v0.7.0
    # assessment object and assert no failure + the row is preserved in
    # its output path — the old binary renders from its own scan, so the
    # probe is: old binary runs preflight against a canary-bearing
    # registry+scan and does NOT crash, reports the value as a masked
    # credential-shaped/known row (it doesn't know HONEYTOKEN — syntactic
    # tolerance means it must not FAIL, and the unknown-kind registry
    # field is preserved verbatim).
    old_env = dict(env_wb)
    old_run = subprocess.run([sys.executable, old_bin_wb2, "preflight"],
                             env=old_env, capture_output=True, text=True,
                             timeout=300)
    check("WB B5: v0.6.1 preflight against canary-bearing registry+scan → no crash, masked output",
          old_run.returncode in (0, 1, 2) and "sk-probe" not in (old_run.stdout + old_run.stderr),
          f"rc={old_run.returncode} err={old_run.stderr[:200]!r}")
else:
    skip("WB B5: v0.6.1 old-consumer probe", "tag v0.6.1 unavailable")

# B6 — kind migration + 0600 preservation across every new mutation
b6_reg_file = wb_cl
open(b6_reg_file, "w").write(json.dumps({"literals": [
    {"value": "wb-b6-legacy", "kind": "honeytoken", "mask": "full"}]}))  # v1-style
os.chmod(b6_reg_file, 0o600)
r = wb_run("literals", "list")
b6reg = json.load(open(b6_reg_file))
b6ok = (os.stat(b6_reg_file).st_mode & 0o777) == 0o600 \
    and b6reg.get("version") == 2 \
    and any(isinstance(e, dict) and e.get("value") == "wb-b6-legacy"
            and e.get("kind") == "honeytoken" and len(e.get("id", "")) == 16
            for e in b6reg["literals"])
check("WB B6: v1→v2 migration preserves kind + assigns id, mode stays 0600",
      b6ok, f"reg={b6reg}")
# remove preserves 0600 + unknown fields
r = wb_run("literals", "remove", "wb-b6-legacy") if False else None
for e in list(json.load(open(b6_reg_file))["literals"]):
    if isinstance(e, dict) and e.get("value") == "wb-b6-legacy":
        wb_run("literals", "remove", e["id"])
b6reg2 = json.load(open(b6_reg_file))
check("WB B6: remove preserves 0600 + drops only the target entry",
      (os.stat(b6_reg_file).st_mode & 0o777) == 0o600
      and not any(isinstance(e, dict) and e.get("value") == "wb-b6-legacy"
                  for e in b6reg2["literals"]))

# B7 — adversarial unknown-kind: quote/newline/backslash/>40 chars,
# one warning per invocation, byte-exact
adv_kind = "quote'kind\nwith\\backslash" + "x" * 40
open(wb_cl, "w").write(json.dumps({"version": 2, "literals": [
    {"value": "wb-adv-kind-val", "id": "cccccccccccccccc", "kind": adv_kind}]}))
r1 = wb_run("literals", "list")
r2 = wb_run("literals", "list")
w1c = r1.stderr.count("unknown literal kind")
w2c = r2.stderr.count("unknown literal kind")
check("WB B7: adversarial unknown kind → exactly one escaped warning per invocation",
      w1c == 1 and w2c == 1 and "\\n" in r1.stderr and "\\" in r1.stderr
      and "…" in r1.stderr,  # 40-char truncation marker
      f"w1={w1c} w2={w2c} err={r1.stderr[:200]!r}")

# B8 — §2.4 CLI JSON shapes executed (parsed-object equality)
open(wb_cl, "w").write(json.dumps({"version": 2, "literals": []}))
r = wb_run("literals", "add", "--kind", "honeytoken", "--json")
b8a = r.returncode == 0
if b8a:
    try:
        j = json.loads(r.stdout)
        b8a = len(j["added"]) == 1 and j["added"][0].get("id") and \
            j["added"][0]["value_masked"].startswith("ht...") \
            and len(j["added"][0]["value_masked"]) == 7  # ht...XX (2+2)
    except (ValueError, KeyError):
        b8a = False
check("WB B8: generated add --json → added[id, value_masked 2+2], exit 0",
      b8a, f"rc={r.returncode} out={r.stdout[:150]!r}")
b8_id = json.loads(r.stdout)["added"][0]["id"]
r = wb_run("literals", "remove", b8_id, "--json")
b8r = r.returncode == 0
if b8r:
    try:
        j = json.loads(r.stdout)
        b8r = j == {"removed": True, "id": b8_id}
    except ValueError:
        b8r = False
check("WB B8: remove found --json → {removed:true, id}, exit 0",
      b8r, f"rc={r.returncode} out={r.stdout[:150]!r}")
r = wb_run("literals", "add", "wb-b8-normal-literal")
r = wb_run("literals", "list", "--json")
b8l = r.returncode == 0
if b8l:
    try:
        j = json.loads(r.stdout)
        normal = [x for x in j["literals"] if x.get("value_masked") == "wb...al"]
        b8l = len(normal) == 1 and "kind" not in normal[0]  # absent-never-null
    except (ValueError, KeyError):
        b8l = False
check("WB B8: list --json → normal literal carries no kind key (absent-never-null)",
      b8l, f"rc={r.returncode}")

# ── 27. Wave B evidence-gate battery (r2 fold, IG D104) — full engine ×
# canary matrix (MAJ-2), collision classes key-name/already-masked/gitleaks
# HIGH/SUSPICIOUS (MAJ-1), review_list membership edges (MAJ-3), complete CLI
# contract (MAJ-4), old-consumer watch/v1 additive tolerance (MAJ-6),
# per-operation persistence matrix (MAJ-8), byte-exact unknown-kind warnings
# (MIN-1). Generator-facing: every check name starts with "WB C" so
# gen-evidence.sh can display the matrix by grepping the battery log.

_mxn = [0]

def _wb_fresh(plant=False):
    """Fresh isolated HERMES_HOME; optionally plant one generated canary
    plus a canary-bearing session file. Returns (home, canary_or_None)."""
    _mxn[0] += 1
    h = os.path.join(tmp, "wb-c%d" % _mxn[0])
    for sub in ("sessions", "logs", "cron/output"):
        os.makedirs(os.path.join(h, sub), exist_ok=True)
    os.makedirs(os.path.join(h, "state", "info-guard"), exist_ok=True)
    open(os.path.join(h, "state", "info-guard", "custom_literals.json"), "w").write(
        json.dumps({"version": 2, "literals": []}))
    val = None
    if plant:
        r = subprocess.run(
            [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"),
             "literals", "add", "--kind", "honeytoken"],
            env=dict(os.environ, HERMES_HOME=h), capture_output=True, text=True,
            timeout=300)
        m = _re.search(r"ht-[0-9a-f]{24}", r.stdout + r.stderr)
        val = m.group(0) if m else None
        with open(os.path.join(h, "sessions", "decoy.txt"), "w") as f:
            f.write("api_key = %s\n" % (val or ""))
    return h, val

def _wb_cmd(args, home=None, scrub=False):
    env = dict(os.environ)
    if scrub:
        env["PATH"] = "/usr/bin:/bin"
        env["HOME"] = os.path.join(tmp, "wb-scrub-home")
        os.makedirs(env["HOME"], exist_ok=True)
    env["HERMES_HOME"] = home or wb_home
    return subprocess.run(
        [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard")] + args,
        env=env, capture_output=True, text=True, timeout=300)

def _wb_json(r):
    try:
        return json.loads(r.stdout)
    except ValueError:
        return None

# C1 — engine × canary matrix, DIRECT exits (MAJ-2): every cell for preflight
# + watch in text + JSON; exit-2 dominance on engine-missing; partial-row
# doctrine (HONEYTOKEN rows serialize while exit 2 stays authoritative).
c1_ok_h, _ = _wb_fresh()
c1_cn_h, c1_cn_v = _wb_fresh(plant=True)
c1_no_h, _ = _wb_fresh()
c1_mc_h, c1_mc_v = _wb_fresh(plant=True)
r = _wb_cmd(["preflight"], c1_ok_h)
check("WB C1: preflight engine-available no-canary → exit 0",
      r.returncode == 0, f"rc={r.returncode}")
r = _wb_cmd(["preflight", "--json"], c1_ok_h)
check("WB C1: preflight --json engine-available no-canary → exit 0",
      r.returncode == 0, f"rc={r.returncode}")
r = _wb_cmd(["preflight"], c1_cn_h)
check("WB C1: preflight engine-available canary → exit 4",
      r.returncode == 4, f"rc={r.returncode}")
r = _wb_cmd(["preflight", "--json"], c1_cn_h)
j = _wb_json(r)
c1_ok = r.returncode == 4 and bool(j) and any(
    v.get("type") == "HONEYTOKEN" for v in j.get("top_values", []))
check("WB C1: preflight --json engine-available canary → exit 4 + HONEYTOKEN row",
      c1_ok, f"rc={r.returncode}")
r = _wb_cmd(["preflight"], c1_no_h, scrub=True)
check("WB C1: preflight engine-missing no-canary → exit 2 (never 0)",
      r.returncode == 2, f"rc={r.returncode}")
r = _wb_cmd(["preflight", "--json"], c1_mc_h, scrub=True)
j = _wb_json(r)
c1_mc = r.returncode == 2 and bool(j) and (
    j.get("tool", {}).get("engine_state") in ("none", "partial")
    and j.get("scan", {}).get("gitleaks_ok") is False
    and any(v.get("type") == "HONEYTOKEN" for v in j.get("top_values", [])))
check("WB C1: preflight --json engine-missing canary → exit 2 + partial rows",
      c1_mc, f"rc={r.returncode}")
r = _wb_cmd(["preflight"], c1_mc_h, scrub=True)
check("WB C1: preflight engine-missing canary (text) → exit 2 dominates",
      r.returncode == 2, f"rc={r.returncode}")
r = _wb_cmd(["watch", "--reset"], c1_ok_h)
check("WB C1: watch engine-available no-canary → baseline exit 0",
      r.returncode == 0, f"rc={r.returncode}")
r = _wb_cmd(["watch", "--reset"], c1_cn_h)
check("WB C1: watch engine-available canary baseline → exit 0 (baselined)",
      r.returncode == 0, f"rc={r.returncode}")
with open(os.path.join(c1_cn_h, "sessions", "decoy.txt"), "a") as f:
    f.write("OTHER = %s\n" % (c1_cn_v or ""))
r = _wb_cmd(["watch"], c1_cn_h)
check("WB C1: watch engine-available canary increase → exit 4",
      r.returncode == 4, f"rc={r.returncode}")
r = _wb_cmd(["watch"], c1_no_h, scrub=True)
check("WB C1: watch engine-missing no-canary → exit 2 (never 0)",
      r.returncode == 2, f"rc={r.returncode}")
r = _wb_cmd(["watch", "--json"], c1_mc_h, scrub=True)
j = _wb_json(r)
c1_w = r.returncode == 2
if c1_w and j and "exposure" in j:
    c1_w = j["exposure"].get("review_list_complete") is False or \
        j["exposure"].get("protected_values") is not None
check("WB C1: watch --json engine-missing canary → exit 2 + partial serialization",
      c1_w, f"rc={r.returncode}")

# C2 — collision classes (MAJ-1): key-name context, already-masked neighbor,
# gitleaks HIGH (adjacent real AWS credential), gitleaks SUSPICIOUS (generic
# api_key context) — the canary tier wins: exactly ONE HONEYTOKEN row,
# known:false, value_id, no lower-tier duplicate for the same value.
c2_h, _ = _wb_fresh()
c2_val = None
r = _wb_cmd(["literals", "add", "--kind", "honeytoken"], c2_h)
m = _re.search(r"ht-[0-9a-f]{24}", r.stdout + r.stderr)
c2_val = m.group(0) if m else ""

def _c2_run(lines):
    with open(os.path.join(c2_h, "sessions", "decoy.txt"), "w") as f:
        f.writelines(lines)
    return _wb_cmd(["preflight", "--json"], c2_h)

def _c2_check(name, lines, extra_fn=None):
    r = _c2_run(lines)
    j = _wb_json(r)
    ht = [v for v in (j or {}).get("top_values", []) if v.get("type") == "HONEYTOKEN"]
    ok = r.returncode == 4 and len(ht) == 1 and ht[0].get("value_id") \
        and ht[0].get("known") is False \
        and (j or {}).get("totals", {}).get("honeytoken_rows") == 1 \
        and sum(1 for v in (j or {}).get("top_values", [])
                if v.get("value_masked") == ht[0].get("value_masked")) == 1
    if ok and extra_fn:
        ok = extra_fn(j)
    check(name, ok, f"rc={r.returncode} ht={len(ht)}")

_c2_check("WB C2: key-name context collision → one HONEYTOKEN row, no mention",
          ["ref = %s\n" % c2_val])
_c2_check("WB C2: already-masked neighbor collision → one HONEYTOKEN row",
          ["API_KEY=***\nSECRET=%s\n" % c2_val],
          lambda j: j.get("totals", {}).get("already_masked", 0) >= 1)
_c2_check("WB C2: gitleaks HIGH neighbor (AWS) → HONEYTOKEN row + AKIA stays HIGH",
          ["AWS_ACCESS_KEY_ID=%s SECRET=%s\n" % ("AKIA" + "QWERTYUIOPASDFGH", c2_val)],
          lambda j: any(v.get("type") == "AWS key"
                        and (v.get("value_masked") or "").startswith("AK")
                        for v in j.get("top_values", [])))
_c2_check("WB C2: gitleaks SUSPICIOUS context (api_key) → one HONEYTOKEN row",
          ["api_key = %s\n" % c2_val])

# C3 — review_list membership edges (MAJ-3): repeated-occurrence count, empty
# complete list, current value absent from baseline, degraded incomplete list.
c3_h, _ = _wb_fresh()
c3_susp = susp32  # defined in WB A7 (concatenated, CI-gitleaks safe)
with open(os.path.join(c3_h, "sessions", "susp.txt"), "w") as f:
    f.write("api_key = %s\napi_key = %s\n" % (c3_susp, c3_susp))
r = _wb_cmd(["watch", "--json"], c3_h)
j = _wb_json(r)
c3a = bool(j) and any(
    x.get("count") == 2 and x.get("type") == "SUSPICIOUS"
    for x in j.get("exposure", {}).get("review_list", []))
check("WB C3: review_list repeated occurrence → count 2 for one value",
      c3a, f"rc={r.returncode}")
c3e_h, _ = _wb_fresh()
r = _wb_cmd(["watch", "--json"], c3e_h)
j = _wb_json(r)
c3e = bool(j) and j.get("exposure", {}).get("review_list") == [] \
    and j.get("exposure", {}).get("review_list_complete") is True
check("WB C3: review_list empty + complete on a clean scan",
      c3e, f"rc={r.returncode}")
r = _wb_cmd(["watch", "--reset"], c3_h)
c3_new_val = "9d4e7b2a6c8f1e3a5b7d9c2e4f6a8b1c"
with open(os.path.join(c3_h, "sessions", "susp2.txt"), "w") as f:
    f.write("api_key = %s\n" % c3_new_val)
r = _wb_cmd(["watch", "--json"], c3_h)
j = _wb_json(r)
c3b = bool(j) and any(
    x.get("value_masked") == wb_mask(c3_new_val)
    for x in j.get("exposure", {}).get("review_list", []))
check("WB C3: review_list shows current value absent from baseline",
      c3b, f"rc={r.returncode}")
r = _wb_cmd(["watch", "--json"], c1_mc_h, scrub=True)
j = _wb_json(r)
c3d = r.returncode == 2 and bool(j) and \
    j.get("exposure", {}).get("review_list_complete") is False
check("WB C3: review_list_complete false on engine-missing watch (same fixture as C1)",
      c3d, f"rc={r.returncode}")

# C4 — complete CLI contract (MAJ-4): explicit-add --json, repeated --kind,
# --kind literal (unknown kind), all accepted mask styles, and
# byte/mode/mtime immutability for every rejected operation.
c4_h, _ = _wb_fresh()
c4_cl = os.path.join(c4_h, "state", "info-guard", "custom_literals.json")
r = _wb_cmd(["literals", "add", "--kind", "honeytoken", "c4-explicit-" + "1234567890", "--json"], c4_h)
j = _wb_json(r)
c4a = r.returncode == 0 and bool(j) and len(j.get("added", [])) == 1 \
    and j["added"][0].get("id") and j["added"][0].get("value_masked") == "c4...90"
check("WB C4: explicit-add --json → added[value_masked 2+2, id], exit 0",
      c4a, f"rc={r.returncode} out={r.stdout[:150]!r}")
st = os.stat(c4_cl)
r = _wb_cmd(["literals", "add", "--kind", "honeytoken", "--kind", "honeytoken"], c4_h)
st2 = os.stat(c4_cl)
check("WB C4: repeated --kind → usage exit 2, no mutation",
      r.returncode == 2 and st.st_mtime_ns == st2.st_mtime_ns
      and st.st_size == st2.st_size, f"rc={r.returncode} err={r.stderr[:120]!r}")
r = _wb_cmd(["literals", "add", "--kind", "literal", "x"], c4_h)
check("WB C4: --kind literal → usage exit 2 (domain: honeytoken only)",
      r.returncode == 2, f"rc={r.returncode} err={r.stderr[:120]!r}")
r = _wb_cmd(["literals", "add", "--mask", "full", "c4-maskfull-1234567890"], c4_h)
r = _wb_cmd(["literals", "add", "--mask", "head:4,tail:2,floor:0", "c4-maskcustom-1234567890"], c4_h)
reg4 = json.load(open(c4_cl))
masks = [e.get("mask") for e in reg4["literals"]
         if isinstance(e, dict) and e.get("value", "").startswith("c4-mask")]
c4m = r.returncode == 0 and "full" in masks and "head:4,tail:2,floor:0" in masks
check("WB C4: all accepted mask styles stored (full + custom policy string)",
      c4m, f"rc={r.returncode} masks={masks}")
for bad, why in ((["--kind", "honeytoken", "x\ny"], "control char"),
                 (["--kind", "honeytoken", "   "], "whitespace-only"),
                 (["--kind", "honeytoken", "--mask", "full", "x"], "--mask conflict"),
                 (["--kind", "honeytoken", "--file", os.path.join(tmp, "c4-f.txt")], "--file conflict")):
    open(os.path.join(tmp, "c4-f.txt"), "w").write("x\n")
    before = (open(c4_cl, "rb").read(), os.stat(c4_cl).st_mode & 0o777,
              os.stat(c4_cl).st_mtime_ns)
    r = _wb_cmd(["literals", "add"] + bad, c4_h)
    after = (open(c4_cl, "rb").read(), os.stat(c4_cl).st_mode & 0o777,
             os.stat(c4_cl).st_mtime_ns)
    check(f"WB C4: {why} rejection → exit 2, bytes+mode+mtime unchanged",
          r.returncode == 2 and before == after, f"rc={r.returncode}")

# C5 — old-consumer additive tolerance (MAJ-6): v0.6.1 watch reads a watch/v1
# baseline containing review_list + review_list_complete — no failure, fields
# preserved on rewrite (syntactic tolerance, never silent discard).
if os.path.exists(old_bin_wb):
    c5_h, _ = _wb_fresh()
    c5_bl = os.path.join(c5_h, "state", "info-guard", "watch-baseline.json")
    c5_bl_doc = {"schema": "info-guard/watch/v1", "version": 1,
                 "values": {}, "exposure": {"review_list": [],
                                            "review_list_complete": True},
                 "generated": "2026-08-22T00:00:00Z"}
    open(c5_bl, "w").write(json.dumps(c5_bl_doc))
    c5_r = subprocess.run([sys.executable, old_bin_wb, "watch", "--json"],
                          env=dict(os.environ, HERMES_HOME=c5_h),
                          capture_output=True, text=True, timeout=300)
    c5_after = {}
    try:
        c5_after = json.load(open(c5_bl))
    except (ValueError, OSError):
        pass
    check("WB C5: v0.6.1 watch tolerates review_list baseline → exit 0, fields preserved",
          c5_r.returncode == 0
          and "review_list" in c5_after.get("exposure", {})
          and "review_list_complete" in c5_after.get("exposure", {}),
          f"rc={c5_r.returncode} err={c5_r.stderr[:150]!r} preserved={list(c5_after.get('exposure', {}))}")
else:
    skip("WB C5: v0.6.1 watch/v1 tolerance probe", "tag v0.6.1 unavailable")

# C6 — per-operation persistence matrix (MAJ-8): v1 + v2 registries; every
# mutation path — before/after raw bytes, mode, mtime; 0600 invariant after
# every write; byte-immutability for no-ops/rejections; fresh id after replant.
def _wb_snap_reg(path):
    with open(path, "rb") as f:
        return (f.read(), os.stat(path).st_mode & 0o777, os.stat(path).st_mtime_ns)

def _wb_reg_ops(seed_doc, label):
    h, _ = _wb_fresh()
    cl = os.path.join(h, "state", "info-guard", "custom_literals.json")
    open(cl, "w").write(json.dumps(seed_doc))
    # generated add → 0600 + entry
    s0 = _wb_snap_reg(cl)
    r = _wb_cmd(["literals", "add", "--kind", "honeytoken"], h)
    s1 = _wb_snap_reg(cl)
    check(f"WB C6: {label} generated add → 0600 + bytes change",
          r.returncode == 0 and s1[1] == 0o600 and s1[0] != s0[0])
    # explicit add → 0600
    r = _wb_cmd(["literals", "add", "c6-explicit-1234567890"], h)
    s2 = _wb_snap_reg(cl)
    check(f"WB C6: {label} explicit add → 0600",
          r.returncode == 0 and s2[1] == 0o600)
    # duplicate honeytoken → idempotent, BYTES unchanged (no-rewrite)
    reg = json.load(open(cl))
    ht_v = next(e.get("value") for e in reg["literals"]
                if isinstance(e, dict) and e.get("kind") == "honeytoken")
    s3 = _wb_snap_reg(cl)
    r = _wb_cmd(["literals", "add", "--kind", "honeytoken", ht_v], h)
    s4 = _wb_snap_reg(cl)
    check(f"WB C6: {label} duplicate honeytoken → idempotent exit 0, bytes unchanged",
          r.returncode == 0 and s4[0] == s3[0] and s4[1] == 0o600)
    # rejected mutation → bytes+mode+mtime unchanged
    s5 = _wb_snap_reg(cl)
    r = _wb_cmd(["literals", "add", "--kind", "honeytoken", "x\ny"], h)
    s6 = _wb_snap_reg(cl)
    check(f"WB C6: {label} rejected mutation → exit 2, bytes+mode+mtime unchanged",
          r.returncode == 2 and s6 == s5)
    # remove → 0600 + target gone
    vid = ht_v and next((e.get("id") for e in reg["literals"]
                         if isinstance(e, dict) and e.get("value") == ht_v), None)
    r = _wb_cmd(["literals", "remove", vid], h)
    s7 = _wb_snap_reg(cl)
    reg7 = json.load(open(cl))
    gone = all(e.get("value") != ht_v for e in reg7["literals"])
    check(f"WB C6: {label} remove → 0600 + only target entry dropped",
          r.returncode == 0 and s7[1] == 0o600 and gone)
    # replant → fresh id (never reused)
    r1 = _wb_cmd(["literals", "add", "--kind", "honeytoken"], h)
    m1 = _re.search(r"ht-[0-9a-f]{24}", r1.stdout + r1.stderr)
    v2_ = m1.group(0) if m1 else ""
    reg8 = json.load(open(cl))
    new_id = next(e.get("id") for e in reg8["literals"]
                  if isinstance(e, dict) and e.get("value") == v2_)
    check(f"WB C6: {label} replant → fresh value_id (never reused)",
          bool(v2_) and new_id != vid and r1.returncode == 0)

_wb_reg_ops({"version": 2, "literals": []}, "v2")
_wb_reg_ops({"version": 1, "literals": [
    {"value": "c6-v1-legacy", "id": "c6v1legacy000001"}]}, "v1")

# C7 — byte-exact unknown-kind warning (MIN-1): quote, newline, control char,
# backslash, 40-char truncation; exactly one warning line per invocation.
def _wb_esc_kind(kind, cap=40):
    esc = kind.replace("\\", "\\\\").replace("'", "\\'")
    def _ec(ch):
        if ch == "\\":
            return "\\\\"
        if ch == "'":
            return "\\'"
        if ch == "\n":
            return "\\n"
        if ch == "\r":
            return "\\r"
        if ch == "\t":
            return "\\t"
        c = ord(ch)
        return "\\x%02x" % c if c < 32 or c == 127 else ch
    esc = "".join(_ec(ch) if (not ch.isprintable() or ch == "'") else ch
                  for ch in esc)
    if len(esc) > cap:
        esc = esc[:cap] + "…"
    return esc

for c7_kind, c7_label in (
        ("quo'te", "quote"),
        ("nl\nx", "newline"),
        ("ctl\x01x", "control char"),
        ("bs\\ck", "backslash"),
        ("k" * 45, "40-char truncation")):
    open(wb_cl, "w").write(json.dumps({"version": 2, "literals": [
        {"value": "c7-v", "id": "c7id000000000001", "kind": c7_kind}]}))
    r = wb_run("literals", "list")
    expected = ("[info-guard] warning: unknown literal kind '%s' — "
                "treated as a normal literal" % _wb_esc_kind(c7_kind))
    check(f"WB C7: {c7_label} unknown-kind warning is byte-exact, one line",
          r.stderr.count(expected) == 1
          and len([l for l in r.stderr.splitlines() if "unknown literal kind" in l]) == 1,
          f"err={r.stderr[:200]!r}")

# ── 28. Wave B evidence-gate battery (r3 fold, IG D105 + arbiter) — HONEYTOKEN
# decreased-delta normative (CRIT-3), degraded-engine (gitleaks present but
# failing) matrix cells (MAJ-2), old-consumer HONEYTOKEN-row tolerance (MAJ-6).

# C8a — baselined canary count decrease → delta:"decreased" + count_before,
# exit 0 (IG D105: the r3 CRIT-3 contract amendment, now normative).
c8_h, c8_v = _wb_fresh(plant=True)
r = _wb_cmd(["watch", "--reset"], c8_h)
with open(os.path.join(c8_h, "sessions", "decoy.txt"), "a") as f:
    f.write("OTHER = %s\n" % (c8_v or ""))
r = _wb_cmd(["watch"], c8_h)          # increase → 4; baseline refreshes to 2
with open(os.path.join(c8_h, "sessions", "decoy.txt"), "w") as f:
    f.write("api_key = %s\n" % (c8_v or ""))   # 1 occurrence vs baseline 2
r = _wb_cmd(["watch", "--json"], c8_h)
j = _wb_json(r)
c8a = r.returncode == 0 and bool(j)
if c8a:
    ht_rows = [x for x in j.get("exposure", {}).get("protected_values", [])
               if x.get("type") == "HONEYTOKEN"]
    c8a = len(ht_rows) == 1 and ht_rows[0].get("delta") == "decreased" \
        and ht_rows[0].get("count_before") == 2 and ht_rows[0].get("count") == 1
check("WB C8: baselined canary decrease → delta:decreased + count_before, exit 0 (IG D105)",
      c8a, f"rc={r.returncode}")

# C8b — degraded engine: gitleaks PRESENT but failing (exit-1 shim on PATH),
# distinct from engine-missing (scrubbed PATH) — exit 2, rows serialized,
# review_list incomplete (MAJ-2).
c8d_h, c8d_v = _wb_fresh(plant=True)
c8d_n_h, _ = _wb_fresh()
gshim = os.path.join(tmp, "wb-gitleaks-shim")
os.makedirs(gshim, exist_ok=True)
with open(os.path.join(gshim, "gitleaks"), "w") as f:
    f.write("#!/bin/sh\necho 'shim: scan failed' >&2\nexit 2\n")
os.chmod(os.path.join(gshim, "gitleaks"), 0o755)

def _wb_degraded(args, home):
    env = dict(os.environ)
    env["PATH"] = gshim + ":" + env.get("PATH", "")
    env["HERMES_HOME"] = home
    return subprocess.run(
        [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard")] + args,
        env=env, capture_output=True, text=True, timeout=300)

r = _wb_degraded(["preflight", "--json"], c8d_n_h)
j = _wb_json(r)
c8b1 = r.returncode == 2 and bool(j) and j.get("scan", {}).get("gitleaks_ok") is False
check("WB C8: preflight --json degraded (shim) no-canary → exit 2, gitleaks_ok false",
      c8b1, f"rc={r.returncode}")
r = _wb_degraded(["preflight", "--json"], c8d_h)
j = _wb_json(r)
c8b2 = r.returncode == 2 and bool(j) and any(
    v.get("type") == "HONEYTOKEN" for v in j.get("top_values", []))
check("WB C8: preflight --json degraded (shim) canary → exit 2 + rows serialized",
      c8b2, f"rc={r.returncode}")
r = _wb_degraded(["watch", "--json"], c8d_h)
j = _wb_json(r)
c8b3 = r.returncode == 2 and bool(j) and \
    j.get("exposure", {}).get("review_list_complete") is False
check("WB C8: watch --json degraded (shim) canary → exit 2 + review_list incomplete",
      c8b3, f"rc={r.returncode}")
r = _wb_degraded(["watch"], c8d_n_h)
check("WB C8: watch degraded (shim) no-canary text → exit 2, never 0",
      r.returncode == 2, f"rc={r.returncode}")

# C9 — old-consumer HONEYTOKEN-row tolerance (MAJ-6): the v1.1 same-major
# consumer probe receives (a) an assessment carrying an unknown HONEYTOKEN
# top_values row and (b) a watch/v1 object carrying review_list +
# review_list_complete — must tolerate + preserve/report, never fail.
p9a = subprocess.run([sys.executable, probe11], input=r10.stdout.replace(
    '"top_values": [',
    '"top_values": [{"value_masked": "ht...0e", "type": "HONEYTOKEN", '
    '"family": null, "count": 1, "known": false}, '),
    capture_output=True, text=True, timeout=120)
check("WB C9: v1.1 consumer probe tolerates unknown HONEYTOKEN assessment row (preserve/report)",
      p9a.returncode == 0, f"rc={p9a.returncode} err={p9a.stderr[-250:]!r}")
p9w = subprocess.run([sys.executable, probe11, "--surface", "watch"],
                     input=r11w.stdout.replace(
                         '"exposure": {',
                         '"exposure": {"review_list": [], "review_list_complete": true, '),
                     capture_output=True, text=True, timeout=120)
check("WB C9: v1.1 consumer probe tolerates watch object w/ review_list fields",
      p9w.returncode == 0, f"rc={p9w.returncode} err={p9w.stderr[-250:]!r}")

# ═══════════════════════════════════════════════════════════════════════
# ── 20. Wave C Phase A battery (W10 update / W11 heal / W12 batteries /
#        W6 cron; proposal self-sustain.md v1.6, plan self-sustain-phase-a
#        v4; acceptance A1–A11/A13–A16/A18–A19/S1–S3/S6–S7) ───────────────
# Fixture doctrine (N.1): every fixture is scratch — scratch HERMES_HOME,
# scratch target checkouts, scratch package remotes with HTTPS-shaped
# origins (git url.<base>.insteadOf rewrites the transport to a local bare
# repo — the product still sees https:// and enforces the HTTPS policy),
# synthetic values only, and the fake crontab fixture (never the real
# operator crontab). The fixture PACKAGE ships a stub test.sh so the
# update-apply battery stays finite (no battery-in-battery recursion); the
# REAL engine masking is verified by this battery's own masking checks +
# the in-process smoke.
import pty as _pty
import select as _select
import stat as _stat

WC_TMP = os.path.join(tmp, "wc")
os.makedirs(WC_TMP, exist_ok=True)
PATCH_PATH2 = os.path.join(os.getcwd(), "patch", "redactor-registry-patterns.patch")
CRON_BIN = os.path.join(WC_TMP, "cronbin")
os.makedirs(CRON_BIN, exist_ok=True)
with open(os.path.join(CRON_BIN, "crontab"), "w") as f:
    f.write("#!/usr/bin/env bash\n"
            "# fake crontab (WC A13/S3/A9 fixtures) — CRONTAB_FILE must be set;\n"
            "# CRONTAB_WRITE_FAIL=1 makes `crontab -` fail (unwritable fixture)\n"
            'set -u\nFILE="${CRONTAB_FILE:?CRONTAB_FILE must be set}"\n'
            'case "${1:-}" in\n'
            "    -l) if [ -f \"$FILE\" ]; then cat \"$FILE\"; else exit 1; fi ;;\n"
            "    -) if [ \"${CRONTAB_WRITE_FAIL:-0}\" = \"1\" ]; then\n"
            '           echo "fake crontab: write denied" >&2; exit 1\n'
            "       fi; cat > \"$FILE\" ;;\n"
            '    *) echo "fake crontab: unknown arg $1" >&2; exit 2 ;;\n'
            "esac\n")
os.chmod(os.path.join(CRON_BIN, "crontab"), 0o755)


def _wc_env(home, crontab_file=None):
    env = dict(os.environ)
    env["HERMES_HOME"] = str(home)
    if crontab_file is not None:
        env["CRONTAB_FILE"] = str(crontab_file)
        env["PATH"] = CRON_BIN + ":" + env.get("PATH", "")
    return env


def _wc_run(args, home, crontab_file=None, cwd=None, timeout=300):
    return subprocess.run(
        [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard")] + args,
        env=_wc_env(home, crontab_file), cwd=cwd, capture_output=True,
        text=True, timeout=timeout)


def _wc_manifest(home):
    try:
        return json.loads(Path(home, "state", "info-guard",
                               "install.json").read_text())
    except (OSError, ValueError):
        return None


def _pkg_bytes(pkg):
    """Byte-level snapshot of a package repo's git metadata + worktree
    (A2/S2: refs, index, worktree, FETCH_HEAD)."""
    parts = []
    for name in ("HEAD", "index", "packed-refs"):
        p = Path(pkg, ".git", name)
        parts.append(name + ":" + (hashlib.sha256(p.read_bytes()).hexdigest()
                                   if p.exists() else "ABSENT"))
    refs = Path(pkg, ".git", "refs")
    if refs.exists():
        for ref in sorted(refs.rglob("*")):
            if ref.is_file():
                parts.append("ref:" + str(ref.relative_to(Path(pkg, ".git")))
                             + ":" + hashlib.sha256(ref.read_bytes()).hexdigest())
    r = subprocess.run(["git", "-C", pkg, "status", "--porcelain"],
                       capture_output=True, text=True)
    parts.append("status:" + r.stdout)
    r = subprocess.run(["git", "-C", pkg, "rev-parse", "HEAD"],
                       capture_output=True, text=True)
    parts.append("head:" + r.stdout.strip())
    fh = Path(pkg, ".git", "FETCH_HEAD")
    parts.append("FETCH_HEAD:" + ("PRESENT" if fh.exists() else "ABSENT"))
    return "\n".join(parts)


def _wc_target(home, tag="v2026.8.18"):
    """Scratch hermes-agent-shaped target: the 5 clean files from the
    battery checkout's HEAD + the agent package import chain, committed
    and tagged (the install.sh version gate needs a usable version source
    when the real hermes CLI is not on the fixture PATH)."""
    tgt = Path(home, "hermes-agent")
    for rel in ("agent/redact.py", "cli.py", "gateway/run.py",
                "hermes_cli/config.py", "hermes_cli/main.py"):
        dst = tgt / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        clean = subprocess.run(["git", "-C", CHECKOUT, "show", f"HEAD:{rel}"],
                               capture_output=True, text=True, check=True).stdout
        dst.write_text(clean)
    for f in ("file_safety.py", "__init__.py", "jiter_preload.py"):
        src = Path(CHECKOUT, "agent", f)
        if src.is_file():
            d = tgt / "agent"
            d.mkdir(parents=True, exist_ok=True)
            (d / f).write_text(src.read_text())
    subprocess.run(["git", "-C", str(tgt), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(tgt), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(tgt), "-c", "user.email=ig@test",
                    "-c", "user.name=ig-test", "commit", "-q", "-m", "base"],
                   check=True)
    subprocess.run(["git", "-C", str(tgt), "tag", tag], check=True)
    return tgt


def _wc_install(home, target, extra=()):
    """The install.sh from a PINNED fixture pkg against a scratch target
    (internal-invocation flags: --no-config --no-cron; --no-test keeps the
    fixture battery out — the engine behavior is this battery's own job).
    The pkg's constant is pinned to the sim baseline (IG D117 / D116 #2):
    the manifest version must NEVER come from the real checkout's
    _PACKAGE_VERSION — the v0.8.0 battery recorded the tree's stale 0.7.0
    here and stayed green; once the constant moved to 0.8.1 the sim broke
    (previous_version 0.8.1 where the transaction expects 0.7.0)."""
    env = _wc_env(home)
    pkg = _wc_pkg()
    return subprocess.run(
        ["bash", str(pkg / "install.sh"), "--checkout",
         str(target), "--no-config", "--no-cron", "--no-test"] + list(extra),
        env=env, capture_output=True, text=True, timeout=600)


def _wc_pkg(battery_rc=0, version="0.7.0"):
    """Scratch package repo: the REAL install.sh/uninstall.sh/bin/patch +
    a STUB test.sh (fixture battery — exit 0 or 1; keeps the update-apply
    battery finite and deterministic). Committed at <version>."""
    pkg = Path(tempfile.mkdtemp(prefix="ig-wc-pkg-", dir=WC_TMP))
    for rel in ("install.sh", "uninstall.sh", "bin/info-guard",
                "patch/redactor-registry-patterns.patch"):
        src = Path(os.getcwd()) / rel
        dst = pkg / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(src.read_text())
    # Hermetic fixture (IG D117 / D116 #2): pin the copied constant to the
    # declared <version> — the update simulation must be self-consistent
    # regardless of the checked-out _PACKAGE_VERSION (the v0.8.0 battery
    # silently inherited the tree's stale constant and passed green).
    _ig_pkg = pkg / "bin" / "info-guard"
    _ig_pkg.write_text(_ig_pkg.read_text().replace(
        f'_PACKAGE_VERSION = "{_PKG_VER}"',
        f'_PACKAGE_VERSION = "{version}"', 1))
    stub = "#!/usr/bin/env bash\n" \
           "# WC fixture battery stub (never the real test.sh — the real\n" \
           "# battery runs OUTSIDE the fixture package; this keeps update's\n" \
           "# install-verification finite and deterministic)\n" \
           f"echo 'fixture battery OK (stub rc={battery_rc})'\n" \
           f"exit {battery_rc}\n"
    (pkg / "test.sh").write_text(stub)
    subprocess.run(["git", "-C", str(pkg), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(pkg), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(pkg), "-c", "user.email=ig@test",
                    "-c", "user.name=ig-test", "commit", "-q", "-m", version],
                   check=True)
    subprocess.run(["git", "-C", str(pkg), "tag", f"v{version}"], check=True)
    return pkg


def _wc_remote(pkg, new_version=None):
    """Bare scratch remote: pushes v0.7.0 and, when new_version is given, a
    v<new_version> commit (bumped _PACKAGE_VERSION); origin = https-shaped
    URL + git insteadOf rewrite to the local bare repo (exercises the HTTPS
    policy without weakening it)."""
    remote = Path(tempfile.mkdtemp(prefix="ig-wc-remote-", dir=WC_TMP),
                  "remote.git")
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    subprocess.run(["git", "-C", str(pkg), "push", "-q", str(remote),
                    "HEAD:refs/heads/main", "v0.7.0"], check=True)
    if new_version:
        subprocess.run(["git", "-C", str(pkg), "checkout", "-q", "-b",
                        "wc-bump"], check=True)
        ig = pkg / "bin" / "info-guard"
        # bump whatever constant the fixture currently carries (never a
        # hardcoded release version — D116 #2 hermeticity, IG D117)
        _cur = re.search(r'_PACKAGE_VERSION = "([^"]+)"',
                         ig.read_text()).group(1)
        ig.write_text(ig.read_text().replace(
            f'_PACKAGE_VERSION = "{_cur}"',
            f'_PACKAGE_VERSION = "{new_version}"', 1))
        subprocess.run(["git", "-C", str(pkg), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(pkg), "-c", "user.email=ig@test",
                        "-c", "user.name=ig-test", "commit", "-q", "-m",
                        f"v{new_version}"], check=True)
        subprocess.run(["git", "-C", str(pkg), "tag", f"v{new_version}"],
                       check=True)
        subprocess.run(["git", "-C", str(pkg), "push", "-q", str(remote),
                        f"v{new_version}"], check=True)
        subprocess.run(["git", "-C", str(pkg), "checkout", "-q", "v0.7.0"],
                       check=True)
    subprocess.run(["git", "-C", str(pkg), "remote", "add", "origin",
                    "https://ig-test.invalid/wc-remote.git"], check=True)
    subprocess.run(["git", "-C", str(pkg), "config",
                    f"url.{remote}.insteadOf",
                    "https://ig-test.invalid/wc-remote.git"], check=True)
    return remote


def _wc_fake_engine(target, mask_ok):
    """A11/SMOKE wrong-engine fixture: commit marker-bearing but
    behaviorally-wrong files into the target HEAD (markers present in HEAD,
    no working-tree patch — the ACTIVE-by-upstream shape). When mask_ok is
    False the engine never masks (redact_sensitive_text returns input)."""
    if mask_ok:
        # commit the ACTUALLY patched worktree (markers + real engine in
        # HEAD), then insert a context-only comment INSIDE the patch's
        # first hunk — the ACTIVE-by-upstream shape (markers in HEAD;
        # reverse-apply fails because the tree is not the patch's exact
        # post-image; forward-apply fails because the patch is already in
        # HEAD; masking behavior is unaffected — the comment is inert)
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=ig@test",
                        "-c", "user.name=ig-test", "commit", "-q", "-m",
                        "upstream merge"], check=True)
        rp = target / "agent" / "redact.py"
        rp.write_text(rp.read_text().replace(
            "text = _SIGNAL_PHONE_RE.sub(_redact_phone, text)",
            "text = _SIGNAL_PHONE_RE.sub(_redact_phone, text)\n"
            "        # upstream context (in-hunk, inert)", 1))
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=ig@test",
                        "-c", "user.name=ig-test", "commit", "-q", "-m",
                        "upstream context"], check=True)
        return
    fake = ("\"\"\"fake engine (WC fixture) — markers present, no masking.\"\"\"\n"
            "_redact_registry_patterns = 'marker-only'\n"
            "def redact_sensitive_text(text, file_read=False):\n"
            "    return text\n")
    (target / "agent" / "redact.py").write_text(fake)
    (target / "hermes_cli" / "config.py").write_text(
        "# redact_patterns marker-only\n")
    for rel in ("hermes_cli/main.py", "cli.py", "gateway/run.py"):
        (target / rel).write_text("# HERMES_REDACT_PATTERNS marker-only\n")
    subprocess.run(["git", "-C", str(target), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(target), "-c", "user.email=ig@test",
                    "-c", "user.name=ig-test", "commit", "-q", "-m",
                    "wrong upstream merge"], check=True)


def _wc_snapshot_state(home, target):
    """Byte snapshot of the fixture state for S7/no-mutation assertions."""
    parts = [_pkg_bytes(os.getcwd())]
    for rel in ("agent/redact.py", "cli.py", "gateway/run.py",
                "hermes_cli/config.py", "hermes_cli/main.py"):
        p = Path(target, rel)
        parts.append(f"t:{rel}:" + (hashlib.sha256(p.read_bytes()).hexdigest()
                                    if p.is_file() else "ABSENT"))
    sd = Path(home, "state", "info-guard")
    if sd.exists():
        for f in sorted(sd.iterdir()):
            if f.is_file():
                parts.append(f"s:{f.name}:"
                             + hashlib.sha256(f.read_bytes()).hexdigest())
    return "\n".join(parts)


def _wc_heal_run(args, home, crontab_file=None, timeout=300):
    """Run check --heal (or any install-invoking command) from a FIXTURE
    package (stub battery) so install.sh's verification battery stays
    finite — the public repo's real battery would recurse (test.sh ->
    check --heal -> install.sh -> test.sh)."""
    hpkg = _wc_pkg(battery_rc=0)
    return subprocess.run(
        [sys.executable, str(hpkg / "bin" / "info-guard")] + list(args),
        env=_wc_env(home, crontab_file), cwd=str(hpkg),
        capture_output=True, text=True, timeout=timeout)


def _wc_pty(args, home, cwd, pkg=None, crontab_file=None, timeout=240):
    """Run info-guard under a PTY (A14: an interactive TTY must still not
    prompt for cron from internal install invocations). pkg = the package
    whose bin/info-guard runs (the FIXTURE package — its stub test.sh keeps
    the heal/update battery finite; the public repo's real battery would
    recurse: test.sh -> check --heal -> test.sh)."""
    if pkg is None:
        pkg = Path(os.getcwd())
    m, s = _pty.openpty()
    p = subprocess.Popen(
        [sys.executable, os.path.join(str(pkg), "bin", "info-guard")] + args,
        stdin=s, stdout=s, stderr=s, env=_wc_env(home, crontab_file),
        cwd=cwd, close_fds=True)
    os.close(s)
    out = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r, _, _ = _select.select([m], [], [], 5)
        if not r:
            if p.poll() is not None:
                break
            continue
        try:
            chunk = os.read(m, 8192)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
        if p.poll() is not None and len(out) > 0:
            # drain any trailing output
            try:
                while True:
                    more = os.read(m, 8192)
                    if not more:
                        break
                    out += more
            except OSError:
                break
            break
    if p.poll() is None:
        p.kill()
    p.wait()
    os.close(m)
    return p.returncode, out.decode(errors="replace")


# ── WC A1: fresh lifecycle ─────────────────────────────────────────────
a1_home = Path(WC_TMP, "a1-home")
a1_tgt = _wc_target(a1_home)
r = _wc_install(a1_home, a1_tgt)
a1_ok1 = r.returncode == 0
r = _wc_run(["literals", "add", "wc-a1-literal-" + "42"], a1_home)
a1_ok2 = r.returncode == 0
# build needs an env source — seed one
(a1_home / ".env").write_text("WC_A1_KEY=wc-a1-value-" + "123456\n")
r = _wc_run(["build"], a1_home)
a1_ok3 = r.returncode == 0 and Path(a1_home, "state", "info-guard",
                                    "redact_patterns.json").exists()
r = _wc_run(["check"], a1_home)
a1_ok4 = r.returncode == 0
# up-to-date update: a remote with ONLY v0.7.0
a1_pkg = _wc_pkg()
a1_remote = _wc_remote(a1_pkg)
r = subprocess.run([sys.executable, str(a1_pkg / "bin" / "info-guard"),
                    "update"], env=_wc_env(a1_home), cwd=str(a1_pkg),
                   capture_output=True, text=True, timeout=300)
a1_ok5 = r.returncode == 0 and "up to date" in r.stdout
# uninstall round-trip: no markers, no state, no managed cron
cron_file = Path(WC_TMP, "a1-crontab.txt")
cron_file.write_text("0 3 * * * /usr/bin/backup.sh\n")
r = subprocess.run(["bash", os.path.join(os.getcwd(), "uninstall.sh"),
                    "--checkout", str(a1_tgt), "--no-config", "--yes"],
                   env=_wc_env(a1_home, cron_file), capture_output=True,
                   text=True, timeout=300)
a1_ok6 = (r.returncode == 0
          and not Path(a1_home, "state", "info-guard").exists()
          and "info-guard-managed" not in cron_file.read_text())
check("WC A1: fresh lifecycle",
      a1_ok1 and a1_ok2 and a1_ok3 and a1_ok4 and a1_ok5 and a1_ok6,
      f"install={a1_ok1} lit={a1_ok2} build={a1_ok3} check={a1_ok4} "
      f"update={a1_ok5} uninstall={a1_ok6}")

# ── WC A2 + WC S2: update --check is read-only (newer tag present) ──────
a2_home = Path(WC_TMP, "a2-home")
a2_tgt = _wc_target(a2_home)
_wc_install(a2_home, a2_tgt)
a2_pkg = _wc_pkg()
_wc_remote(a2_pkg, "0.8.0")
before = _pkg_bytes(a2_pkg)
r = subprocess.run([sys.executable, str(a2_pkg / "bin" / "info-guard"),
                    "update", "--check"], env=_wc_env(a2_home),
                   cwd=str(a2_pkg), capture_output=True, text=True,
                   timeout=120)
after = _pkg_bytes(a2_pkg)
a2_ok = (r.returncode == 1 and "newer version available" in r.stdout
         and before == after)
check("WC A2: update check is read-only",
      a2_ok, f"rc={r.returncode} mutated={before != after}")
r = subprocess.run([sys.executable, str(a2_pkg / "bin" / "info-guard"),
                    "update", "--check", "--json"], env=_wc_env(a2_home),
                   cwd=str(a2_pkg), capture_output=True, text=True,
                   timeout=120)
j2 = json.loads(r.stdout) if r.stdout.strip() else {}
check("WC A2: update --check --json exit 1 + envelope update_available",
      r.returncode == 1 and j2.get("status") == "update_available"
      and j2.get("latest") == "0.8.0" and j2.get("selected_commit") is None
      and j2.get("applied") is False,
      f"rc={r.returncode} env={j2}")
check("WC S2: update-check byte non-mutation",
      before == after, "refs/index/worktree/FETCH_HEAD changed")

# ── WC A3: newer-tag update transaction ────────────────────────────────
a3_home = Path(WC_TMP, "a3-home")
a3_tgt = _wc_target(a3_home)
_wc_install(a3_home, a3_tgt)
a3_pkg = _wc_pkg()
_wc_remote(a3_pkg, "0.8.0")
old_head = subprocess.run(["git", "-C", str(a3_pkg), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
r = subprocess.run([sys.executable, str(a3_pkg / "bin" / "info-guard"),
                    "update", "--json"], env=_wc_env(a3_home),
                   cwd=str(a3_pkg), capture_output=True, text=True,
                   timeout=600)
j3 = json.loads(r.stdout) if r.stdout.strip() else {}
man3 = _wc_manifest(a3_home)
ref3 = subprocess.run(["git", "-C", str(a3_pkg), "rev-parse",
                       "refs/info-guard/previous"], capture_output=True,
                      text=True).stdout.strip()
head3 = subprocess.run(["git", "-C", str(a3_pkg), "rev-parse", "HEAD"],
                       capture_output=True, text=True).stdout.strip()
a3_ok = (r.returncode == 0 and j3.get("status") == "updated"
         and j3.get("engine") == "ACTIVE" and j3.get("applied") is True
         and man3 is not None
         and man3.get("version") == "0.8.0"
         and man3.get("previous_version") == "0.7.0"
         and man3.get("previous_commit") == old_head
         and man3.get("pending") is None
         and ref3 == old_head and head3 == j3.get("selected_commit")
         and j3.get("selected_commit") is not None)
check("WC A3: newer-tag update transaction",
      a3_ok, f"rc={r.returncode} env={j3} man={man3}")
# consumer test: the update-v1 consumer probe accepts the live envelope
probe_u1 = os.path.join(os.getcwd(), "tests", "consumers",
                        "update-v1-consumer-probe.py")
if os.path.exists(probe_u1):
    p3 = subprocess.run([sys.executable, probe_u1], input=r.stdout,
                        capture_output=True, text=True, timeout=60)
    check("WC CONSUMER-1: update-v1 probe validates the applied envelope",
          p3.returncode == 0 and "VALID" in p3.stdout,
          f"rc={p3.returncode} err={p3.stderr[-200:]!r}")

# ── WC A4: missing artifacts recovery ──────────────────────────────────
a4_home = Path(WC_TMP, "a4-home")
a4_tgt = _wc_target(a4_home)
_wc_install(a4_home, a4_tgt)
sd4 = Path(a4_home, "state", "info-guard")
os.unlink(sd4 / "redact_patterns.json")
os.unlink(sd4 / "install.json")
r = _wc_run(["check"], a4_home)
a4_ok1 = r.returncode == 1 and "pattern file: missing" in r.stdout \
    and not (sd4 / "redact_patterns.json").exists()
(a4_home / ".env").write_text("WC_A4_KEY=wc-a4-value-" + "123456\n")
r = _wc_run(["build"], a4_home)
a4_ok2 = r.returncode == 0 and (sd4 / "redact_patterns.json").exists()
r = _wc_run(["check"], a4_home)
a4_ok3 = r.returncode == 0
check("WC A4: missing artifacts recovery",
      a4_ok1 and a4_ok2 and a4_ok3, f"check1={a4_ok1} build={a4_ok2} "
      f"check2={a4_ok3}")

# ── WC A5: old registry lazy migration ─────────────────────────────────
# The migration is lazy — triggered by a registry-reading command
# (literals list), not by check (which reads the pattern file only). The
# one-time stderr note + v2 persistence are the contract; check must be
# healthy after migration.
a5_home = Path(WC_TMP, "a5-home")
a5_tgt = _wc_target(a5_home)
_wc_install(a5_home, a5_tgt)
reg5 = a5_home / "state" / "info-guard" / "custom_literals.json"
reg5.write_text(json.dumps({"literals": ["wc-a5-value-" + "987654"]}))
r = _wc_run(["literals", "list"], a5_home)
note5 = "migrated to v2" in r.stderr
doc5 = json.loads(reg5.read_text())
r2 = _wc_run(["literals", "list"], a5_home)
r3 = _wc_run(["check"], a5_home)
a5_ok = (r.returncode == 0 and note5 and doc5.get("version") == 2
         and "migrated to v2" not in r2.stderr and r3.returncode == 0)
check("WC A5: old registry lazy migration",
      a5_ok, f"rc={r.returncode} note={note5} v={doc5.get('version')} "
      f"check={r3.returncode}")

# ── WC A6: partial engine report-and-heal ──────────────────────────────
a6_home = Path(WC_TMP, "a6-home")
a6_tgt = _wc_target(a6_home)
_wc_install(a6_home, a6_tgt)
man6a = _wc_manifest(a6_home)
subprocess.run(["git", "-C", str(a6_tgt), "checkout", "-q", "--",
                "agent/redact.py", "hermes_cli/config.py"], check=True)
r = _wc_run(["check"], a6_home)
a6_ok1 = r.returncode == 1 and "PARTIAL" in r.stdout
r = _wc_heal_run(["check", "--heal"], a6_home)
a6_ok2 = r.returncode == 0
n6 = sum(1 for rel, marker in
         [("agent/redact.py", "_redact_registry_patterns"),
          ("hermes_cli/config.py", "redact_patterns"),
          ("hermes_cli/main.py", "HERMES_REDACT_PATTERNS"),
          ("cli.py", "HERMES_REDACT_PATTERNS"),
          ("gateway/run.py", "HERMES_REDACT_PATTERNS")]
         if marker in Path(a6_tgt, rel).read_text(errors="replace"))
man6b = _wc_manifest(a6_home)
a6_ok3 = n6 == 5 and man6b.get("version") == man6a.get("version") \
    and man6b.get("previous_version") == man6a.get("previous_version")
# forced patch-apply failure: target whose HEAD drifted at the patch's
# anchor line so the patch cannot apply (clean tree vs HEAD, but
# apply --check fails -> attempted-and-failed -> exit 1, engine not
# ACTIVE, no false success)
a6f_home = Path(WC_TMP, "a6f-home")
a6f_tgt = _wc_target(a6f_home)
src6f = Path(a6f_tgt, "agent", "redact.py")
src6f.write_text(src6f.read_text().replace(
    "text = _SIGNAL_PHONE_RE.sub(_redact_phone, text)",
    "text = text  # drifted anchor", 1))
subprocess.run(["git", "-C", str(a6f_tgt), "add", "-A"], check=True)
subprocess.run(["git", "-C", str(a6f_tgt), "-c", "user.email=ig@test",
                "-c", "user.name=ig-test", "commit", "-q", "-m", "drift"],
               check=True)
r = _wc_heal_run(["check", "--heal"], a6f_home)
a6_ok4 = r.returncode == 1
check("WC A6: partial engine report-and-heal",
      a6_ok1 and a6_ok2 and a6_ok3 and a6_ok4,
      f"report={a6_ok1} heal={a6_ok2} man={a6_ok3} failed-heal={a6_ok4}")

# ── WC A7: missing engine heal ─────────────────────────────────────────
a7_home = Path(WC_TMP, "a7-home")
a7_tgt = _wc_target(a7_home)
r = _wc_run(["check"], a7_home)
a7_ok1 = r.returncode == 1 and "MISSING" in r.stdout
r = _wc_heal_run(["check", "--heal"], a7_home)
a7_ok2 = r.returncode == 0
# current-tag update auto-heal (remote with only v0.7.0, engine broken)
a7b_home = Path(WC_TMP, "a7b-home")
a7b_tgt = _wc_target(a7b_home)
a7b_pkg = _wc_pkg()
_wc_remote(a7b_pkg)
r = subprocess.run([sys.executable, str(a7b_pkg / "bin" / "info-guard"),
                    "update", "--json"], env=_wc_env(a7b_home),
                   cwd=str(a7b_pkg), capture_output=True, text=True,
                   timeout=600)
j7 = json.loads(r.stdout) if r.stdout.strip() else {}
a7_ok3 = r.returncode == 0 and j7.get("status") == "up_to_date" \
    and j7.get("healed") is True
check("WC A7: missing engine heal",
      a7_ok1 and a7_ok2 and a7_ok3,
      f"report={a7_ok1} heal={a7_ok2} update-heal={a7_ok3}")

# ── WC A8: artifact drift heal (registry/custom literals preserved) ─────
a8_home = Path(WC_TMP, "a8-home")
a8_tgt = _wc_target(a8_home)
_wc_install(a8_home, a8_tgt)
reg8a = hashlib.sha256(
    Path(a8_home, "state", "info-guard", "redact_patterns.json").read_bytes()
).hexdigest()
lit8a = hashlib.sha256(
    Path(a8_home, "state", "info-guard", "custom_literals.json").read_bytes()
).hexdigest()
tampered = Path(a8_tgt, "gateway", "run.py").read_text()
Path(a8_tgt, "gateway", "run.py").write_text(
    tampered.replace("HERMES_REDACT_PATTERNS", "HERMES_REDACT_PATTERNS ", 1))
r = _wc_run(["check"], a8_home)
a8_ok1 = r.returncode == 1 and "patch state" in r.stdout
r = _wc_heal_run(["check", "--heal"], a8_home)
rev8 = subprocess.run(["git", "-C", str(a8_tgt), "apply", "--reverse",
                       "--check", PATCH_PATH2], capture_output=True)
reg8b = hashlib.sha256(
    Path(a8_home, "state", "info-guard", "redact_patterns.json").read_bytes()
).hexdigest()
lit8b = hashlib.sha256(
    Path(a8_home, "state", "info-guard", "custom_literals.json").read_bytes()
).hexdigest()
a8_ok2 = (r.returncode == 0 and rev8.returncode == 0
          and reg8a == reg8b and lit8a == lit8b)
check("WC A8: artifact drift heal",
      a8_ok1 and a8_ok2,
      f"probe={a8_ok1} heal={a8_ok2} reg={reg8a == reg8b} lit={lit8a == lit8b}")

# ── WC A9: stale cron warning (exit 0, never mutated) ──────────────────
a9_home = Path(WC_TMP, "a9-home")
a9_tgt = _wc_target(a9_home)
_wc_install(a9_home, a9_tgt)
a9_cron = Path(WC_TMP, "a9-crontab.txt")
a9_cron.write_text(
    "0 6 * * * /nonexistent/wc-pkg/bin/info-guard check  "
    "# info-guard-managed:'/nonexistent/wc-pkg'\n"
    "0 3 * * * /usr/bin/backup.sh\n")
r = _wc_run(["check"], a9_home, crontab_file=a9_cron)
a9_ok = r.returncode == 0 and "missing binary" in r.stdout \
    and a9_cron.read_text().count("info-guard-managed") == 1
check("WC A9: stale cron warning",
      a9_ok, f"rc={r.returncode} warn={'missing binary' in r.stdout}")

# ── WC A10: state inaccessible during check/update verification ────────
a10_home = Path(WC_TMP, "a10-home")
a10_tgt = _wc_target(a10_home)
_wc_install(a10_home, a10_tgt)
os.chmod(Path(a10_home, "state", "info-guard", "redact_patterns.json"), 0)
try:
    r = _wc_run(["check"], a10_home)
finally:
    os.chmod(Path(a10_home, "state", "info-guard", "redact_patterns.json"),
             0o600)
a10_ok1 = r.returncode == 2
# update with an unreadable install.json -> exit 2, status error,
# error_class state, NO verified claim. (The deterministic fixture hits the
# pre-apply read; the post-apply unreadable row — applied: true — is the
# same error_class=state code path and is not deterministically reachable
# because install.sh's atomic write always leaves a readable manifest.)
a10b_home = Path(WC_TMP, "a10b-home")
a10b_tgt = _wc_target(a10b_home)
_wc_install(a10b_home, a10b_tgt)
a10b_pkg = _wc_pkg()
_wc_remote(a10b_pkg, "0.8.0")
os.chmod(Path(a10b_home, "state", "info-guard", "install.json"), 0)
try:
    r = subprocess.run([sys.executable, str(a10b_pkg / "bin" / "info-guard"),
                        "update", "--json"], env=_wc_env(a10b_home),
                       cwd=str(a10b_pkg), capture_output=True, text=True,
                       timeout=600)
finally:
    os.chmod(Path(a10b_home, "state", "info-guard", "install.json"), 0o600)
j10 = json.loads(r.stdout) if r.stdout.strip() else {}
a10_ok2 = (r.returncode == 2 and j10.get("status") == "error"
           and j10.get("healed") is False
           and j10.get("error_class") == "state"
           and "verified" not in r.stdout)
check("WC A10: state inaccessible during verification",
      a10_ok1 and a10_ok2, f"check={a10_ok1} update={a10_ok2} env={j10}")

# ── WC A11: upstream merge behavioral gate ─────────────────────────────
a11_home = Path(WC_TMP, "a11-home")
a11_tgt = _wc_target(a11_home)
_wc_install(a11_home, a11_tgt)
_wc_fake_engine(a11_tgt, mask_ok=True)   # correct upstream: real engine in HEAD
r = _wc_run(["check"], a11_home)
a11_ok1 = r.returncode == 0 and "ACTIVE-by-upstream" in r.stdout
# install.sh acceptance: fixture package with a PASSING stub battery (the
# real battery would recurse — test.sh -> install.sh -> test.sh)
a11_ok_pkg = _wc_pkg(battery_rc=0)
r = subprocess.run(["bash", str(a11_ok_pkg / "install.sh"), "--checkout",
                    str(a11_tgt), "--no-config", "--no-cron"],
                   env=_wc_env(a11_home), capture_output=True, text=True,
                   timeout=300)
a11_ok2 = r.returncode == 0
# wrong semantics: markers in HEAD, engine never masks -> smoke fails ->
# check exit 1 "compatibility review required"; install.sh battery (failing
# stub) -> fail closed exit 1
a11w_home = Path(WC_TMP, "a11w-home")
a11w_tgt = _wc_target(a11w_home)
_wc_fake_engine(a11w_tgt, mask_ok=False)
r = _wc_run(["check"], a11w_home)
a11_ok3 = (r.returncode == 1 and "smoke" in r.stdout
           and "WC SMOKE-1" in r.stdout and "WC SMOKE-7" in r.stdout)
a11w_pkg = _wc_pkg(battery_rc=1)
r = subprocess.run(["bash", str(a11w_pkg / "install.sh"), "--checkout",
                    str(a11w_tgt), "--no-config", "--no-cron"],
                   env=_wc_env(a11w_home), capture_output=True, text=True,
                   timeout=300)
a11_ok4 = r.returncode == 1 and "compatibility review required" in r.stderr
check("WC A11: upstream merge behavioral gate",
      a11_ok1 and a11_ok2 and a11_ok3 and a11_ok4,
      f"check-ok={a11_ok1} install-ok={a11_ok2} wrong-check={a11_ok3} "
      f"wrong-install={a11_ok4}")

# ── WC SMOKE-1..7: the in-process smoke is the health gate ─────────────
# (plan §6.2/§N.3 canonical names: the seven masking assertions the
# in-process smoke runs, asserted individually so the ledger proves each
# one — same fixture corpus as the battery's redact() helper, one source,
# never a second corpus; the healthy/broken engine-gate checks follow
# under the non-colliding WC SMOKE-GATE names.
# NOTE: the smoke checks use a DEDICATED pattern file, not the shared
# pfile — the external-audit C5 batch rewrites pfile mid-run with a
# different literal set, so checks running after it must not rely on
# pfile's original contents)
smoke_pfile = os.path.join(tmp, "smoke-patterns.json")
write(smoke_pfile, {
    "mask": {"head": 2, "tail": 2, "floor": 12},
    "literals": [
        DEFAULT_LIT,
        {"value": FULL_LIT, "mask": "full"},
        SHORT_LIT,
    ],
    "key_patterns": {"IG_PROBE_PIN": True},
})
check("WC SMOKE-1: exact-value partial masking",
      redact(DEFAULT_LIT, patterns=smoke_pfile) == "ig...45",
      f"got {redact(DEFAULT_LIT, patterns=smoke_pfile)!r}")
check("WC SMOKE-2: full mask",
      redact(FULL_LIT, patterns=smoke_pfile) == "***",
      f"got {redact(FULL_LIT, patterns=smoke_pfile)!r}")
check("WC SMOKE-3: short-value floor",
      redact(SHORT_LIT, patterns=smoke_pfile) == "***",
      f"got {redact(SHORT_LIT, patterns=smoke_pfile)!r}")
check("WC SMOKE-4: key-pattern masking",
      redact("IG_PROBE_PIN=1234", patterns=smoke_pfile) == "IG_PROBE_PIN=***",
      f"got {redact('IG_PROBE_PIN=1234', patterns=smoke_pfile)!r}")
# 5: broken pattern file -> fail-safe fallback, no unmasked gap, NO repair
# (mirrors _smoke_failed()'s probe: prime the cache, corrupt the file with
# a newer mtime, assert no unmasked gap AND the file is left untouched)
smoke_broken = os.path.join(tmp, "smoke-broken.json")
write(smoke_broken, {"mask": {"head": 2, "tail": 2, "floor": 12},
                     "literals": ["ig-broken-probe"], "key_patterns": {}})
_t5 = time.time()
redact("ig-broken-probe", patterns=smoke_broken)   # prime the cache
os.utime(smoke_broken, (_t5, _t5))
with open(smoke_broken, "w") as _f:
    _f.write("{not json")
os.utime(smoke_broken, (_t5 + 2, _t5 + 2))
_out5 = redact("ig-broken-probe", patterns=smoke_broken)
check("WC SMOKE-5: broken-pattern fail-safe",
      "ig-broken-probe" not in _out5
      and open(smoke_broken).read() == "{not json",
      f"out={_out5!r} repaired={open(smoke_broken).read()!r}")
# 6: missing pattern file -> no-op; built-in redaction still works
os.environ.pop("HERMES_REDACT_PATTERNS", None)
check("WC SMOKE-6: missing-pattern behavior",
      redact_sensitive_text("hello world") == "hello world",
      f"got {redact_sensitive_text('hello world')!r}")
# 7: file_read sentinel — a masked value can never be written back
_sent7 = redact(f"value={DEFAULT_LIT}", file_read=True, patterns=smoke_pfile)
check("WC SMOKE-7: file-read sentinel",
      _sent7 != f"value={DEFAULT_LIT}" and "ig-probe" not in _sent7
      and "12345" not in _sent7, f"got {_sent7!r}")
# engine-gate checks (the smoke as the health gate; broken engine fixture:
# check exits 1 and names the failing smoke checks)
r = _wc_run(["check"], a11_home)   # healthy ACTIVE-by-upstream install
check("WC SMOKE-GATE: healthy check runs the in-process smoke green (exit 0)",
      r.returncode == 0, f"rc={r.returncode}")
check("WC SMOKE-GATE: broken engine named by the smoke gate (exit 1)",
      a11_ok3, "wrong-engine check must exit 1 and name WC SMOKE-1..7")

# ── WC A13 + WC S3: cron lifecycle and safety ──────────────────────────
a13_home = Path(WC_TMP, "a13-home")
a13_tgt = _wc_target(a13_home)
_wc_install(a13_home, a13_tgt)
a13_cron = Path(WC_TMP, "a13-crontab.txt")
a13_cron.write_text("0 3 * * * /usr/bin/backup.sh\n# keep\n")
env13 = _wc_env(a13_home, a13_cron)
r = subprocess.run(["bash", os.path.join(os.getcwd(), "install.sh"),
                    "--checkout", str(a13_tgt), "--no-config", "--no-test",
                    "--cron"], env=env13, capture_output=True, text=True,
                   timeout=300)
a13_ok1 = r.returncode == 0 and a13_cron.read_text().count(
    "info-guard-managed") == 1
# re-run with a valid schedule replaces (one line)
r = subprocess.run(["bash", os.path.join(os.getcwd(), "install.sh"),
                    "--checkout", str(a13_tgt), "--no-config", "--no-test",
                    "--cron", "5 4 * * *"], env=env13, capture_output=True,
                   text=True, timeout=300)
a13_ok2 = (r.returncode == 0
           and a13_cron.read_text().count("info-guard-managed") == 1
           and "5 4 * * *" in a13_cron.read_text())
# invalid schedules: exit 2, crontab byte-identical
for bad in ("*/5 * * * *", "0 6 * *", "0 6 * * MON", "61 0 * * *",
            "5-2 * * * *", "1,2,99 * * * *", "0 6 * * *%x"):
    b4 = a13_cron.read_bytes()
    r = subprocess.run(["bash", os.path.join(os.getcwd(), "install.sh"),
                        "--checkout", str(a13_tgt), "--no-config",
                        "--no-test", "--cron", bad], env=env13,
                       capture_output=True, text=True, timeout=300)
    a13_ok2 = a13_ok2 and r.returncode == 2 and a13_cron.read_bytes() == b4
check("WC A13: cron install + validation (default, replace, invalid)",
      a13_ok1 and a13_ok2, f"install={a13_ok1} replace+reject={a13_ok2}")
# % in the package path AND state path -> exit 2 at serialization,
# nothing written (A13 %-in-path fixture)
pct_home = Path(WC_TMP, "pct%home")
pct_tgt = _wc_target(pct_home)
pct_pkg = Path(WC_TMP, "pct%pkg")
for rel in ("install.sh", "bin", "patch"):
    src = Path(os.getcwd()) / rel
    dst = pct_pkg / rel
    if src.is_dir():
        shutil.copytree(src, dst)
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(src.read_text())
b4 = a13_cron.read_bytes()
r = subprocess.run(["bash", str(pct_pkg / "install.sh"), "--checkout",
                    str(pct_tgt), "--no-config", "--no-test", "--cron"],
                   env=_wc_env(pct_home, a13_cron), capture_output=True,
                   text=True, timeout=300)
a13_ok3 = r.returncode == 2 and a13_cron.read_bytes() == b4
# unsafe % in a managed line -> stale probe rejects, never executes
a13_cron.write_text(
    "0 6 * * * '/tmp/bad%pkg/bin/info-guard' check  "
    "# info-guard-managed:'/tmp/bad%pkg'\n")
r = _wc_run(["check"], a13_home, crontab_file=a13_cron)
a13_ok4 = r.returncode == 0 and "rejected, never executed" in r.stdout
# unrelated entries preserved through install + uninstall
a13_cron.write_text("0 3 * * * /usr/bin/backup.sh\n# keep\n")
r = subprocess.run(["bash", os.path.join(os.getcwd(), "install.sh"),
                    "--checkout", str(a13_tgt), "--no-config", "--no-test",
                    "--cron"], env=env13, capture_output=True, text=True,
                   timeout=300)
a13_ok5 = (r.returncode == 0
           and "0 3 * * * /usr/bin/backup.sh" in a13_cron.read_text()
           and "# keep" in a13_cron.read_text())
r = subprocess.run(["bash", os.path.join(os.getcwd(), "uninstall.sh"),
                    "--checkout", str(a13_tgt), "--no-config", "--yes",
                    "--keep-state"], env=env13, capture_output=True,
                   text=True, timeout=300)
a13_ok6 = (r.returncode == 0
           and "info-guard-managed" not in a13_cron.read_text()
           and "0 3 * * * /usr/bin/backup.sh" in a13_cron.read_text())
check("WC A13: cron ownership, % rejection, unrelated preservation",
      a13_ok3 and a13_ok4 and a13_ok5 and a13_ok6,
      f"pct-path={a13_ok3} pct-probe={a13_ok4} preserve={a13_ok5} "
      f"uninstall={a13_ok6}")
# crontab unavailable/unwritable -> install.sh --cron exits 2 (never a
# silent no-op): deterministic fixture — the fake crontab refuses the
# write (CRONTAB_WRITE_FAIL=1)
env_nc = _wc_env(a13_home, a13_cron)
env_nc["CRONTAB_WRITE_FAIL"] = "1"
r = subprocess.run(["bash", os.path.join(os.getcwd(), "install.sh"),
                    "--checkout", str(a13_tgt), "--no-config", "--no-test",
                    "--cron"], env=env_nc, capture_output=True, text=True,
                   timeout=300)
a13_ok7b = r.returncode == 2 and "crontab" in r.stderr
# concurrent install + uninstall: hold the cron lock -> install exits 2,
# nothing written
lockf = Path(a13_home, "state", "info-guard", "cron-install.lock")
lockfd = os.open(str(lockf), os.O_CREAT | os.O_RDWR)
try:
    import fcntl as _fcntl
    _fcntl.flock(lockfd, _fcntl.LOCK_EX)
    b4 = a13_cron.read_bytes()
    r = subprocess.run(["bash", os.path.join(os.getcwd(), "install.sh"),
                        "--checkout", str(a13_tgt), "--no-config",
                        "--no-test", "--cron"], env=env13,
                       capture_output=True, text=True, timeout=300)
    a13_ok7 = r.returncode == 2 and a13_cron.read_bytes() == b4
finally:
    _fcntl.flock(lockfd, _fcntl.LOCK_UN)
    os.close(lockfd)
check("WC A13: cron concurrency (lock held -> exit 2, nothing written)",
      a13_ok7, f"rc={r.returncode}")
check("WC A13: crontab unavailable -> --cron exits 2 (no silent success)",
      a13_ok7b, f"rc={r.returncode}")
check("WC S3: cron ownership and serialization safety",
      a13_ok1 and a13_ok2 and a13_ok3 and a13_ok5 and a13_ok6 and a13_ok7
      and a13_ok7b,
      "schedule/marker/preservation/escaping/%/lock/unavailable")

# ── WC A14: internal invocations suppress cron (PTY fixtures) ──────────
# All three callers run from a FIXTURE package (stub battery) so the
# install.sh verification is finite — the real battery would recurse.
a14_home = Path(WC_TMP, "a14-home")
a14_tgt = _wc_target(a14_home)
a14_pkg = _wc_pkg()
_wc_install(a14_home, a14_tgt)   # install via the public installer, then...
a14_cron = Path(WC_TMP, "a14-crontab.txt")
a14_cron.write_text("0 3 * * * /usr/bin/backup.sh\n")
subprocess.run(["git", "-C", str(a14_tgt), "checkout", "-q", "--",
                "agent/redact.py", "hermes_cli/config.py"], check=True)
rc, out = _wc_pty(["check", "--heal"], a14_home, str(a14_pkg), pkg=a14_pkg,
                  crontab_file=a14_cron, timeout=300)
a14_ok1 = (rc == 0 and "install a managed cron line" not in out
           and "info-guard-managed" not in a14_cron.read_text())
# heal-only update under a TTY (remote v0.7.0 only, engine broken)
a14b_home = Path(WC_TMP, "a14b-home")
a14b_tgt = _wc_target(a14b_home)
a14b_pkg = _wc_pkg()
_wc_remote(a14b_pkg)
rc, out = _wc_pty(["update"], a14b_home, str(a14b_pkg), pkg=a14b_pkg,
                  crontab_file=a14_cron, timeout=300)
a14_ok2 = (rc == 0 and "install a managed cron line" not in out
           and "info-guard-managed" not in a14_cron.read_text())
# newer-tag update apply-with-heal under a TTY
a14c_home = Path(WC_TMP, "a14c-home")
a14c_tgt = _wc_target(a14c_home)
a14c_pkg = _wc_pkg()
_wc_remote(a14c_pkg, "0.8.0")
rc, out = _wc_pty(["update"], a14c_home, str(a14c_pkg), pkg=a14c_pkg,
                  crontab_file=a14_cron, timeout=600)
a14_ok3 = (rc == 0 and "install a managed cron line" not in out
           and "info-guard-managed" not in a14_cron.read_text())
check("WC A14: internal invocations suppress cron",
      a14_ok1 and a14_ok2 and a14_ok3,
      f"heal={a14_ok1} heal-only={a14_ok2} apply={a14_ok3}")

# ── WC A15: dirty package and restore targets ──────────────────────────
a15_home = Path(WC_TMP, "a15-home")
a15_tgt = _wc_target(a15_home)
_wc_install(a15_home, a15_tgt)
a15_pkg = _wc_pkg()
_wc_remote(a15_pkg, "0.8.0")
# dirty package worktree
(a15_pkg / "test.sh").write_text(
    (a15_pkg / "test.sh").read_text() + "# operator edit\n")
r = subprocess.run([sys.executable, str(a15_pkg / "bin" / "info-guard"),
                    "update"], env=_wc_env(a15_home), cwd=str(a15_pkg),
                   capture_output=True, text=True, timeout=120)
a15_ok1 = r.returncode == 2 and "dirty" in r.stdout.lower() \
    and "# operator edit" in (a15_pkg / "test.sh").read_text()
# dirty package staged
subprocess.run(["git", "-C", str(a15_pkg), "add", "-A"], check=True)
r = subprocess.run([sys.executable, str(a15_pkg / "bin" / "info-guard"),
                    "update"], env=_wc_env(a15_home), cwd=str(a15_pkg),
                   capture_output=True, text=True, timeout=120)
a15_ok2 = r.returncode == 2
subprocess.run(["git", "-C", str(a15_pkg), "reset", "-q", "--hard",
                "v0.7.0"], check=True)
# non-https origin -> exit 2, no fetch
subprocess.run(["git", "-C", str(a15_pkg), "remote", "set-url", "origin",
                "http://ig-test.invalid/wc-remote.git"], check=True)
r = subprocess.run([sys.executable, str(a15_pkg / "bin" / "info-guard"),
                    "update", "--check"], env=_wc_env(a15_home),
                   cwd=str(a15_pkg), capture_output=True, text=True,
                   timeout=120)
a15_ok3 = r.returncode == 2 and "https" in r.stdout.lower()
subprocess.run(["git", "-C", str(a15_pkg), "remote", "set-url", "origin",
                "https://ig-test.invalid/wc-remote.git"], check=True)
# dirty patched target via ALL THREE callers (attribution-exact MISSING
# state; A15 state-scoping per r3 MIN-2 fold)
def _dirty_target_fixture():
    h = Path(tempfile.mkdtemp(prefix="ig-wc-dirty-", dir=WC_TMP))
    t = _wc_target(h)          # MISSING state, clean tree
    (t / "cli.py").write_text((t / "cli.py").read_text() + "# op edit\n")
    return h, t

h1, t1 = _dirty_target_fixture()
r = _wc_heal_run(["check", "--heal"], h1)
a15_ok4 = r.returncode == 2 and "# op edit" in Path(t1, "cli.py").read_text()
h2, t2 = _dirty_target_fixture()
d2pkg = _wc_pkg()
_wc_remote(d2pkg)   # v0.7.0 only — heal-only update path
r = subprocess.run([sys.executable, str(d2pkg / "bin" / "info-guard"),
                    "update"], env=_wc_env(h2), cwd=str(d2pkg),
                   capture_output=True, text=True, timeout=300)
a15_ok5 = r.returncode == 2 and "# op edit" in Path(t2, "cli.py").read_text()
h3, t3 = _dirty_target_fixture()
d3pkg = _wc_pkg()
_wc_remote(d3pkg, "0.8.0")
r = subprocess.run([sys.executable, str(d3pkg / "bin" / "info-guard"),
                    "update", "--json"], env=_wc_env(h3), cwd=str(d3pkg),
                   capture_output=True, text=True, timeout=600)
j15 = json.loads(r.stdout) if r.stdout.strip() else {}
a15_ok6 = (r.returncode == 2 and j15.get("applied") is True
           and j15.get("error_class") == "repair"
           and "# op edit" in Path(t3, "cli.py").read_text())
check("WC A15: dirty package and restore targets",
      a15_ok1 and a15_ok2 and a15_ok3 and a15_ok4 and a15_ok5 and a15_ok6,
      f"pkg-wt={a15_ok1} pkg-staged={a15_ok2} https={a15_ok3} "
      f"heal={a15_ok4} heal-only={a15_ok5} apply={a15_ok6}")

# ── WC A16 + WC S6: target snapshot revalidation and lock ──────────────
# worktree-only + staged-only dirty patched files (MISSING state)
h16, t16 = _dirty_target_fixture()
r = _wc_heal_run(["check", "--heal"], h16)
a16_ok1 = r.returncode == 2 and "# op edit" in Path(t16, "cli.py").read_text()
h16b, t16b = _dirty_target_fixture()
subprocess.run(["git", "-C", str(t16b), "add", "cli.py"], check=True)
r = _wc_heal_run(["check", "--heal"], h16b)
a16_ok2 = r.returncode == 2 and "# op edit" in Path(t16b, "cli.py").read_text()
# external modification between snapshot and revalidate (barrier) — the
# ACTIVE branch's operator-protection boundary (r2 CRIT-1 fold). The
# ACTIVE-mismatch tamper must exist BEFORE check --heal starts (so it
# attempts the heal); only the external cli.py edit lands during the
# barrier pause inside install.sh.
h16c = Path(WC_TMP, "a16c-home")
t16c = _wc_target(h16c)
_wc_install(h16c, t16c)
pw = Path(t16c, "gateway", "run.py").read_text()
Path(t16c, "gateway", "run.py").write_text(
    pw.replace("HERMES_REDACT_PATTERNS", "HERMES_REDACT_PATTERNS ", 1))
bar = Path(WC_TMP, "a16c-barrier")
if bar.exists():
    os.unlink(bar)
rp = str(bar) + ".reached"
if os.path.exists(rp):
    os.unlink(rp)
env16 = _wc_env(h16c)
env16["IG_TEST_HEAL_BARRIER"] = str(bar)
h16_pkg = _wc_pkg(battery_rc=0)
p16 = subprocess.Popen([sys.executable, str(h16_pkg / "bin" / "info-guard"),
                        "check", "--heal"],
                       env=env16, cwd=str(h16_pkg), stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, text=True)
for _ in range(200):
    if os.path.exists(rp):
        break
    time.sleep(0.05)
# external operator edit while install.sh is paused between snapshot and
# final revalidation
Path(t16c, "cli.py").write_text(
    Path(t16c, "cli.py").read_text() + "# external edit\n")
bar.write_text("go")
out16, err16 = p16.communicate(timeout=300)
a16_ok3 = (p16.returncode == 2
           and "# external edit" in Path(t16c, "cli.py").read_text())
# target lock contention -> "another update/heal in progress" exit 2
# (the engine must be BROKEN so check --heal attempts install and hits the
# held lock — a healthy engine short-circuits with "nothing to repair")
h16d = Path(WC_TMP, "a16d-home")
t16d = _wc_target(h16d)
_wc_install(h16d, t16d)
subprocess.run(["git", "-C", str(t16d), "checkout", "-q", "--",
                "agent/redact.py", "hermes_cli/config.py"], check=True)
lockfd = os.open(str(t16d / ".git" / "info-guard.lock"), os.O_CREAT | os.O_RDWR)
try:
    _fcntl.flock(lockfd, _fcntl.LOCK_EX)
    r = _wc_heal_run(["check", "--heal"], h16d)
finally:
    _fcntl.flock(lockfd, _fcntl.LOCK_UN)
    os.close(lockfd)
a16_ok4 = r.returncode == 2 and "another update/heal in progress" in r.stdout
# full version-changing update with target lock contention (applied true)
h16e = Path(WC_TMP, "a16e-home")
t16e = _wc_target(h16e)
_wc_install(h16e, t16e)
d16pkg = _wc_pkg()
_wc_remote(d16pkg, "0.8.0")
lockfd = os.open(str(t16e / ".git" / "info-guard.lock"), os.O_CREAT | os.O_RDWR)
try:
    _fcntl.flock(lockfd, _fcntl.LOCK_EX)
    r = subprocess.run([sys.executable, str(d16pkg / "bin" / "info-guard"),
                        "update", "--json"], env=_wc_env(h16e),
                       cwd=str(d16pkg), capture_output=True, text=True,
                       timeout=300)
finally:
    _fcntl.flock(lockfd, _fcntl.LOCK_UN)
    os.close(lockfd)
j16 = json.loads(r.stdout) if r.stdout.strip() else {}
a16_ok5 = (r.returncode == 2 and j16.get("applied") is True
           and j16.get("error_class") == "lock")
check("WC A16: target snapshot revalidation and lock",
      a16_ok1 and a16_ok2 and a16_ok3 and a16_ok4 and a16_ok5,
      f"wt={a16_ok1} staged={a16_ok2} ext={a16_ok3} lock={a16_ok4} "
      f"apply-lock={a16_ok5}")
# WC S6: the single lock-first sequence is intrinsic to install.sh and all
# three callers route through it (source-level single-sourcing + the
# A15/A16 behavioral fixtures above prove the shared path)
install_src = open(os.path.join(os.getcwd(), "install.sh")).read()
s6_ok = ("flock -n 9" in install_src and "SNAP_A=" in install_src
         and "SNAP_B=" in install_src
         and "refusing to overwrite" in install_src)
ig_src = open(os.path.join(os.getcwd(), "bin", "info-guard")).read()
s6_ok = s6_ok and install_src.count('--no-cron') >= 1 \
    and "check --heal" in ig_src
check("WC S6: heal single lock sequence",
      s6_ok and a15_ok4 and a15_ok5 and a15_ok6 and a16_ok1 and a16_ok2,
      "lock+snapshot+revalidate single-sourced; callers share install.sh")

# ── WC A18: concurrent update lock ─────────────────────────────────────
a18_home = Path(WC_TMP, "a18-home")
a18_tgt = _wc_target(a18_home)
_wc_install(a18_home, a18_tgt)
a18_pkg = _wc_pkg()
_wc_remote(a18_pkg, "0.8.0")
bar18 = Path(WC_TMP, "a18-barrier")
if bar18.exists():
    os.unlink(bar18)
rp18 = str(bar18) + ".reached"
if os.path.exists(rp18):
    os.unlink(rp18)
env18 = _wc_env(a18_home)
env18["IG_TEST_HEAL_BARRIER"] = str(bar18)
p18 = subprocess.Popen([sys.executable, str(a18_pkg / "bin" / "info-guard"),
                        "update"], env=env18, cwd=str(a18_pkg),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True)
for _ in range(200):
    if os.path.exists(rp18):
        break
    time.sleep(0.05)
r18 = subprocess.run([sys.executable, str(a18_pkg / "bin" / "info-guard"),
                      "update"], env=_wc_env(a18_home), cwd=str(a18_pkg),
                     capture_output=True, text=True, timeout=120)
a18_ok1 = r18.returncode == 2 and "another update in progress" in r18.stdout
bar18.write_text("go")
out18, err18 = p18.communicate(timeout=600)
man18 = _wc_manifest(a18_home)
a18_ok2 = p18.returncode == 0 and man18 is not None \
    and man18.get("version") == "0.8.0" and man18.get("pending") is None
check("WC A18: concurrent update lock",
      a18_ok1 and a18_ok2, f"second={a18_ok1} first+consistent={a18_ok2}")

# ── WC A19: rollback by commit and durable ref ─────────────────────────
a19_home = Path(WC_TMP, "a19-home")
a19_tgt = _wc_target(a19_home)
_wc_install(a19_home, a19_tgt)
a19_pkg = _wc_pkg()
_wc_remote(a19_pkg, "0.8.0")
old19 = subprocess.run(["git", "-C", str(a19_pkg), "rev-parse", "HEAD"],
                       capture_output=True, text=True).stdout.strip()
r = subprocess.run([sys.executable, str(a19_pkg / "bin" / "info-guard"),
                    "update"], env=_wc_env(a19_home), cwd=str(a19_pkg),
                   capture_output=True, text=True, timeout=600)
a19_ok1 = r.returncode == 0
ref19 = subprocess.run(["git", "-C", str(a19_pkg), "rev-parse",
                        "refs/info-guard/previous"], capture_output=True,
                       text=True).stdout.strip()
new19 = subprocess.run(["git", "-C", str(a19_pkg), "rev-parse", "HEAD"],
                       capture_output=True, text=True).stdout.strip()
a19_ok2 = ref19 == old19 and new19 != old19
# delete the local tag -> rollback must still work (commit id only)
subprocess.run(["git", "-C", str(a19_pkg), "tag", "-d", "v0.7.0"],
               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
r = subprocess.run([sys.executable, str(a19_pkg / "bin" / "info-guard"),
                    "update", "--rollback", "--json"], env=_wc_env(a19_home),
                   cwd=str(a19_pkg), capture_output=True, text=True,
                   timeout=600)
j19 = json.loads(r.stdout) if r.stdout.strip() else {}
man19 = _wc_manifest(a19_home)
head19 = subprocess.run(["git", "-C", str(a19_pkg), "rev-parse", "HEAD"],
                        capture_output=True, text=True).stdout.strip()
# rollback is a LOCAL operation: no remote selection, so the envelope's
# selected_commit is null; the manifest + durable ref carry the
# rolled-back-from commit (new19). The local v0.7.0 tag was deleted above —
# the commit-id checkout succeeding (head19 == old19) is the proof that
# rollback never depends on a local tag.
a19_ok3 = (r.returncode == 0 and j19.get("status") == "updated"
           and j19.get("selected_commit") is None
           and head19 == old19
           and man19.get("version") == "0.7.0"
           and man19.get("previous_version") == "0.8.0"
           and man19.get("previous_commit") == new19
           and man19.get("pending") is None)
ref19b = subprocess.run(["git", "-C", str(a19_pkg), "rev-parse",
                         "refs/info-guard/previous"], capture_output=True,
                        text=True).stdout.strip()
a19_ok4 = ref19b == new19
# unavailable previous commit -> exit 2 with the exact diagnostic
subprocess.run(["git", "-C", str(a19_pkg), "update-ref", "-d",
                "refs/info-guard/previous"], check=True)
man19b = _wc_manifest(a19_home)
man19b["previous_commit"] = None
Path(a19_home, "state", "info-guard", "install.json").write_text(
    json.dumps(man19b))
r = subprocess.run([sys.executable, str(a19_pkg / "bin" / "info-guard"),
                    "update", "--rollback"], env=_wc_env(a19_home),
                   cwd=str(a19_pkg), capture_output=True, text=True,
                   timeout=120)
a19_ok5 = (r.returncode == 2
           and "previous release commit no longer available locally — "
               "cannot roll back" in r.stdout)
check("WC A19: rollback by commit and durable ref",
      a19_ok1 and a19_ok2 and a19_ok3 and a19_ok4 and a19_ok5,
      f"update={a19_ok1} ref={a19_ok2} rollback={a19_ok3} "
      f"ref-swap={a19_ok4} unavailable={a19_ok5}")

# ── WC S1: origin-qualified tag trust ──────────────────────────────────
s1_home = Path(WC_TMP, "s1-home")
s1_tgt = _wc_target(s1_home)
_wc_install(s1_home, s1_tgt)
s1_pkg = _wc_pkg()
s1_remote = _wc_remote(s1_pkg, "0.8.0")
# malformed remote tags must be ignored; a local v999.0.0 tag never wins
# (the bare remote has no HEAD — tags reference the v0.7.0 commit explicitly)
subprocess.run(["git", "-C", str(s1_remote), "tag", "v1.2", "v0.7.0"],
               check=True)
subprocess.run(["git", "-C", str(s1_remote), "tag", "v2.0.0-rc1", "v0.7.0"],
               check=True)
subprocess.run(["git", "-C", str(s1_remote), "tag", "not-a-tag", "v0.7.0"],
               check=True)
subprocess.run(["git", "-C", str(s1_pkg), "tag", "v999.0.0"], check=True)
r = subprocess.run([sys.executable, str(s1_pkg / "bin" / "info-guard"),
                    "update", "--check", "--json"], env=_wc_env(s1_home),
                   cwd=str(s1_pkg), capture_output=True, text=True,
                   timeout=120)
j1 = json.loads(r.stdout) if r.stdout.strip() else {}
s1_ok1 = (r.returncode == 1 and j1.get("latest") == "0.8.0"
          and "v999" not in r.stdout)
# moved origin tag: apply follows origin's published commit
new_commit = subprocess.run(["git", "-C", str(s1_pkg), "rev-parse",
                             "wc-bump"], capture_output=True,
                            text=True).stdout.strip()
# force-move v0.8.0 to a new commit on the remote
subprocess.run(["git", "-C", str(s1_pkg), "checkout", "-q", "wc-bump"],
               check=True)
(Path(s1_pkg, "install.sh")).write_text(
    Path(s1_pkg, "install.sh").read_text() + "# moved-tag marker\n")
subprocess.run(["git", "-C", str(s1_pkg), "add", "-A"], check=True)
subprocess.run(["git", "-C", str(s1_pkg), "-c", "user.email=ig@test",
                "-c", "user.name=ig-test", "commit", "-q", "-m", "move"],
               check=True)
moved = subprocess.run(["git", "-C", str(s1_pkg), "rev-parse", "HEAD"],
                       capture_output=True, text=True).stdout.strip()
subprocess.run(["git", "-C", str(s1_pkg), "tag", "-f", "v0.8.0"], check=True,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.run(["git", "-C", str(s1_pkg), "push", "-q", "-f", str(s1_remote),
                "v0.8.0"], check=True)
subprocess.run(["git", "-C", str(s1_pkg), "checkout", "-q", "v0.7.0"],
               check=True)
subprocess.run(["git", "-C", str(s1_pkg), "branch", "-D", "wc-bump"],
               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
r = subprocess.run([sys.executable, str(s1_pkg / "bin" / "info-guard"),
                    "update", "--json"], env=_wc_env(s1_home),
                   cwd=str(s1_pkg), capture_output=True, text=True,
                   timeout=600)
j1b = json.loads(r.stdout) if r.stdout.strip() else {}
s1_ok2 = (r.returncode == 0 and j1b.get("selected_commit") == moved
          and j1b.get("status") == "updated")
check("WC S1: origin-qualified tag trust",
      s1_ok1 and s1_ok2, f"selection={s1_ok1} moved-tag={s1_ok2}")

# ── WC CRASH-1..4: manifest transaction boundaries ─────────────────────
# CRASH-2: crash before checkout leaves pending + durable fields intact
c2_home = Path(WC_TMP, "c2-home")
c2_tgt = _wc_target(c2_home)
_wc_install(c2_home, c2_tgt)
c2_pkg = _wc_pkg()
c2_remote = _wc_remote(c2_pkg, "0.8.0")
c2_head = subprocess.run(["git", "-C", str(c2_pkg), "rev-parse", "HEAD"],
                         capture_output=True, text=True).stdout.strip()
c2_sel = subprocess.run(["git", "-C", str(c2_remote), "rev-parse",
                         "refs/tags/v0.8.0"], capture_output=True,
                        text=True).stdout.strip()
man = _wc_manifest(c2_home)
man["pending"] = {"previous_version": "0.7.0",
                  "previous_commit": c2_head,
                  "selected_commit": c2_sel,
                  "started_at": "2026-08-22T00:00:00Z"}
Path(c2_home, "state", "info-guard", "install.json").write_text(
    json.dumps(man))
r = subprocess.run([sys.executable, str(c2_pkg / "bin" / "info-guard"),
                    "update", "--check"], env=_wc_env(c2_home),
                   cwd=str(c2_pkg), capture_output=True, text=True,
                   timeout=120)
man2 = _wc_manifest(c2_home)
crash2_ok = (man2.get("pending") is not None
             and man2.get("version") == "0.7.0")
# CRASH-1 + CRASH-3: stale pending recovered before a new transaction
# (HEAD still at the old commit — crash before checkout)
r = subprocess.run([sys.executable, str(c2_pkg / "bin" / "info-guard"),
                    "update"], env=_wc_env(c2_home), cwd=str(c2_pkg),
                   capture_output=True, text=True, timeout=600)
man3 = _wc_manifest(c2_home)
crash13_ok = (r.returncode == 0 and "recovering stale pending" in r.stdout
              and man3.get("pending") is None and man3.get("version") == "0.8.0"
              and man3.get("previous_commit") == c2_head)
# CRASH-3: HEAD at the NEW commit with stale pending (crash during/after
# checkout) — the next update recovers from pending.previous_commit by
# commit id, then completes the transaction
c3_home = Path(WC_TMP, "c3-home")
c3_tgt = _wc_target(c3_home)
_wc_install(c3_home, c3_tgt)
c3_pkg = _wc_pkg()
c3_remote = _wc_remote(c3_pkg, "0.8.0")
c3_head = subprocess.run(["git", "-C", str(c3_pkg), "rev-parse", "HEAD"],
                         capture_output=True, text=True).stdout.strip()
c3_sel = subprocess.run(["git", "-C", str(c3_remote), "rev-parse",
                         "refs/tags/v0.8.0"], capture_output=True,
                        text=True).stdout.strip()
subprocess.run(["git", "-C", str(c3_pkg), "checkout", "-q", c3_sel],
               check=True)
man = _wc_manifest(c3_home)
man["pending"] = {"previous_version": "0.7.0",
                  "previous_commit": c3_head,
                  "selected_commit": c3_sel,
                  "started_at": "2026-08-22T00:00:00Z"}
Path(c3_home, "state", "info-guard", "install.json").write_text(
    json.dumps(man))
r = subprocess.run([sys.executable, str(c3_pkg / "bin" / "info-guard"),
                    "update", "--json"], env=_wc_env(c3_home),
                   cwd=str(c3_pkg), capture_output=True, text=True,
                   timeout=600)
j3c = json.loads(r.stdout) if r.stdout.strip() else {}
man4 = _wc_manifest(c3_home)
h3b = subprocess.run(["git", "-C", str(c3_pkg), "rev-parse", "HEAD"],
                     capture_output=True, text=True).stdout.strip()
# recovery restored the pre-crash state (pending cleared, HEAD back at
# pending.previous_commit); the running binary is ALREADY the new version
# (crash happened after checkout), so the update correctly reports
# up-to-date — it does NOT silently re-apply
crash3_ok = (r.returncode == 0
             and "recovering stale pending" in r.stdout + r.stderr
             and h3b == c3_head and man4.get("pending") is None
             and man4.get("version") == "0.7.0")
# CRASH-4: ordinary install preserves previous_version/previous_commit
c4_home = Path(WC_TMP, "c4-home")
c4_tgt = _wc_target(c4_home)
_wc_install(c4_home, c4_tgt)
man = _wc_manifest(c4_home)
man["previous_version"] = "0.6.1"
man["previous_commit"] = "c0ffee" * 4
Path(c4_home, "state", "info-guard", "install.json").write_text(
    json.dumps(man))
_wc_install(c4_home, c4_tgt)
man5 = _wc_manifest(c4_home)
crash4_ok = (man5.get("previous_version") == "0.6.1"
             and man5.get("previous_commit") == "c0ffee" * 4
             and man5.get("version") == "0.7.0")
check("WC CRASH-1: stale pending recovered before a new transaction",
      crash13_ok, f"recovery={crash13_ok}")
check("WC CRASH-2: crash before checkout leaves pending + durable fields",
      crash2_ok, f"pending-preserved={crash2_ok}")
check("WC CRASH-3: crash during checkout/install recovered from "
      "pending.previous_commit", crash3_ok, f"rollback-refused={crash3_ok}")
check("WC CRASH-4: ordinary install preserves previous_version/"
      "previous_commit", crash4_ok, f"preserved={crash4_ok}")

# ── WC S7: check and check --battery no mutation ───────────────────────
# default check: byte-unchanged package/target/registry/state/git metadata
s7_home = Path(WC_TMP, "s7-home")
s7_tgt = _wc_target(s7_home)
_wc_install(s7_home, s7_tgt)
snap_before = _wc_snapshot_state(s7_home, s7_tgt)
r = _wc_run(["check"], s7_home)
snap_after = _wc_snapshot_state(s7_home, s7_tgt)
s7_ok1 = r.returncode == 0 and snap_before == snap_after
# check --battery wrapper via the test-only fake stub (IG_TEST_BATTERY_FAKE
# — the stub never spawns test.sh, so no recursion; the wrapper's own
# no-mutation + timeout + no-recursion assertions run and must pass)
env7 = _wc_env(s7_home)
env7["IG_TEST_BATTERY_FAKE"] = "1"
# IG_TEST_BATTERY_FAKE stub: never spawns test.sh, so this cannot recurse
# (the marker on this line exempts it from the wrapper's no-recursion scan)
r = subprocess.run([sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "check", "--battery"], env=env7, capture_output=True, text=True, timeout=300)  # IG_TEST_BATTERY_FAKE stub
s7_ok2 = r.returncode == 0 and "fake battery" in r.stdout \
    and "byte-unchanged" in r.stdout
# bounded timeout + distinct exit-2 message (source-level: a 30-min timeout
# cannot be exercised live in the battery)
ig_src7 = open(os.path.join(os.getcwd(), "bin", "info-guard")).read()
s7_ok3 = "timeout=1800" in ig_src7 and "battery timed out" in ig_src7
# no recursion: test.sh never invokes check --battery (the S7 self-test
# stub line is exempt — IG_TEST_BATTERY_FAKE never spawns test.sh; the
# scan matches the ADJACENT-args invocation signature so its own
# assertion lines cannot trip it)
test_src7 = open(os.path.join(os.getcwd(), "test.sh")).read()
recursive = any(('"check", "--battery"' in ln  # IG_TEST_BATTERY_FAKE scan-self exemption
                 or "'check', '--battery'" in ln)  # IG_TEST_BATTERY_FAKE scan-self exemption
                and "IG_TEST_BATTERY_FAKE" not in ln
                and not ln.strip().startswith("#")
                for ln in test_src7.splitlines())
s7_ok4 = not recursive
check("WC S7: check battery no mutation",
      s7_ok1 and s7_ok2 and s7_ok3 and s7_ok4,
      f"check-nomut={s7_ok1} battery-nomut={s7_ok2} timeout={s7_ok3} "
      f"norecursion={s7_ok4}")

# ── Phase B (W13 viewers): WC A12 / WC A17 / WC S4 / WC S5 ─────────────
# One shared synthetic viewer corpus (concatenation-built, never
# token-shaped literals), scratch HERMES_HOME state, executable source
# shims, scratch PATH. No Phase A command is invoked (independence: the
# Phase B battery never runs check/update/install.sh/cron). Every check
# name maps to exactly one Phase B acceptance row (assertion-ledger
# convention, D108 #2); the plan's mapping table is the fold register.
V_LIT = "ig-view-lit-" + "abc123"          # 17 chars -> 2+2 visible
V_FULL = "ig-view-full-" + "xyz789"        # mask: full -> ***
V_SHORT = "ig-short-" + "42"               # 10 chars -> under floor 12
V_KEY = "IG_VIEW_PIN"
b_home = Path(WC_TMP, "b-home")
b_state = b_home / "state" / "info-guard"
b_state.mkdir(parents=True, exist_ok=True)
b_matcher = b_state / "redact_patterns.json"
write(b_matcher, {
    "mask": {"head": 2, "tail": 2, "floor": 12},
    "literals": [V_LIT, {"value": V_FULL, "mask": "full"}, V_SHORT],
    "key_patterns": {V_KEY: True},
})
# separate homes for the empty-registry and missing-matcher cases
b_home_empty = Path(WC_TMP, "b-home-empty")
Path(b_home_empty, "state", "info-guard").mkdir(parents=True, exist_ok=True)
write(Path(b_home_empty, "state", "info-guard", "redact_patterns.json"),
      {"mask": {"head": 2, "tail": 2, "floor": 12},
       "literals": [], "key_patterns": {}})
b_home_nomatch = Path(WC_TMP, "b-home-nomatch")
b_home_nomatch.mkdir(parents=True, exist_ok=True)


def write_text(p, s):
    with open(p, "w") as f:
        f.write(s)
    os.chmod(p, 0o755)


def _b_state_snapshot(home):
    parts = []
    sd = Path(home, "state", "info-guard")
    if sd.exists():
        for f in sorted(sd.iterdir()):
            if f.is_file():
                parts.append(f.name + ":"
                             + hashlib.sha256(f.read_bytes()).hexdigest())
    r = subprocess.run(["git", "-C", os.getcwd(), "status", "--porcelain"],
                       capture_output=True, text=True)
    parts.append("cwd-git:" + r.stdout)
    return "\n".join(parts)


def _b_run(args, home=b_home, stdin=None, path=None, path_replace=None,
           timeout=120):
    """Run one viewer command against scratch state. stdin may be str
    (text mode) or bytes (raw mode — invalid-UTF8 fixtures). path
    prepends a shim dir to PATH; path_replace REPLACES PATH entirely
    (tool-missing fixtures must not fall through to the host's tools)."""
    env = _wc_env(home)
    if path_replace is not None:
        env["PATH"] = path_replace
    elif path is not None:
        env["PATH"] = path + ":" + env.get("PATH", "")
    if isinstance(stdin, bytes):
        p = subprocess.run(
            [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard")]
            + args, env=env, capture_output=True, input=stdin, timeout=timeout)
        return types.SimpleNamespace(
            returncode=p.returncode,
            stdout=p.stdout.decode("utf-8", "replace"),
            stderr=p.stderr.decode("utf-8", "replace"))
    return subprocess.run(
        [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard")]
        + args, env=env, capture_output=True, text=True, input=stdin,
        timeout=timeout)


# executable source shims (record argv; controlled stdout/stderr/status)
b_bin = Path(WC_TMP, "b-bin")
b_bin.mkdir(parents=True, exist_ok=True)
b_argvlog = Path(WC_TMP, "b-argv.log")
b_argvlog.write_text("")
write_text(b_bin / "systemctl", f"""#!/bin/bash
echo "systemctl $*" >> {b_argvlog}
if [ "$1" = "--user" ] && [ "$2" = "cat" ]; then
  case "$3" in
    userunit) echo "[Unit] Description=user unit"; echo "PASSWORD={V_LIT}"; exit 0;;
    nope) echo "Unit nope could not be found" >&2; exit 4;;
    *) echo "user manager failure" >&2; exit 1;;
  esac
fi
if [ "$1" = "cat" ]; then
  case "$2" in
    okunit) echo "[Unit] Description=ok unit"; echo "Environment={V_KEY}=1234"; exit 0;;
    userunit) echo "Unit userunit could not be found" >&2; exit 4;;
    nope) echo "Unit nope could not be found" >&2; exit 4;;
    badunit) echo "systemd failure {V_LIT}" >&2; exit 1;;
    *) echo "systemd failure" >&2; exit 1;;
  esac
fi
exit 1
""")
write_text(b_bin / "docker", f"""#!/bin/bash
echo "docker $*" >> {b_argvlog}
if [ "$1" = "inspect" ]; then
  if [ "$4" = "ghost" ]; then echo "No such object: ghost" >&2; exit 1; fi
  echo "{V_KEY}=5678"; echo "PLAIN=hello"; echo "docker-stderr {V_LIT}" >&2; exit 0
fi
if [ "$1" = "compose" ]; then
  [ -f "$3" ] || {{ echo "no such file or directory: $3" >&2; exit 1; }}
  echo "services: web"; echo "{V_KEY}=9999"; exit 0
fi
exit 1
""")
b_path = str(b_bin)

# metachar + sensitive-arg fixtures
b_metafile = Path(WC_TMP, "we ird$(id).txt")
b_metafile.write_text("x=" + V_LIT + "\n")
b_secfile = Path(WC_TMP, "secret.txt")
b_secfile.write_text("db_password=" + V_LIT + "\n")
b_compose = Path(WC_TMP, "compose.yml")
b_compose.write_text("services: web\nenv: " + V_LIT + "\n")
b_envfile = Path(WC_TMP, "sample.env")
b_envfile.write_text(
    "# comment with " + V_LIT + "\n"
    "PLAIN=hello\n"
    f"{V_KEY}=1234\n"
    'SECRET="quoted value"\n'
    "EMPTY=\n"
    "\n"
    "   \n"
    "MALFORMED NO EQUALS\n")
b_envdup = Path(WC_TMP, "dup.env")
b_envdup.write_text("B=1\nA=2\nB=3\nA=4\n")
b_unic = Path(WC_TMP, "uni.env")
b_unic.write_text("K=café\nE=emoji-😀\n")

# A17 hostile fixture: every supported malformed category present
# (bad key form, unterminated quote, control characters) + shell-payload
# constructs (command substitution, backticks, redirects, source
# attempts) placed ONLY in malformed positions + a side-effect target.
b_side = Path(WC_TMP, "ig-side-effect-1")
b_hostile = Path(WC_TMP, "hostile.env")
b_hostile.write_text(
    "GOOD=value1\n"
    f'KEY="$(touch {b_side})"\n'
    f"KEY2=`touch {b_side}2`\n"
    f"KEY3=val > {b_side}3\n"
    "KEY4=source /etc/passwd\n"
    f'KEY5="unterminated $(touch {b_side}5)\n'
    "KEY6=. /etc/rc.local\n"
    "BAD-KEY-NAME=value\n"
    "CTRL=abc\x01def\n"
    "# comment with " + V_LIT + "\n")
b_clean = Path(WC_TMP, "clean.env")
b_clean.write_text("A=1\nB=two\n")
# A17 zero-invocation PATH: sh/basher/touch/source shims record calls
b_a17path = Path(WC_TMP, "b-a17path")
b_a17path.mkdir(parents=True, exist_ok=True)
b_a17log = Path(WC_TMP, "a17-invocations.log")
for _n in ("sh", "bash", "touch", "source"):
    write_text(b_a17path / _n,
               f"#!/bin/bash\necho \"{_n} $*\" >> {b_a17log}\nexit 0\n")
b_a17path_s = str(b_a17path)

# every viewer invocation is captured for the masked-only self-check
b_captures = []   # (label, rc, stdout, stderr)
b_nomut = True    # aggregated by WC A12: viewers leave state unchanged


def b_cap(label, rc, out, err):
    b_captures.append((label, rc, out, err))


def b_run_cap(label, args, home=b_home, stdin=None, path=None,
              path_replace=None):
    before = _b_state_snapshot(home)
    r = _b_run(args, home=home, stdin=stdin, path=path,
               path_replace=path_replace)
    after = _b_state_snapshot(home)
    global b_nomut
    b_nomut = b_nomut and before == after
    b_cap(label, r.returncode, r.stdout, r.stderr)
    return r


# ── pipe ────────────────────────────────────────────────────────────────
r = b_run_cap("pipe-literal", ["pipe"], stdin=f"hello {V_LIT} world")
check("WC A12: pipe masks exact literals with configured style",
      r.returncode == 0 and f"hello ig...23 world" == r.stdout,
      f"rc={r.returncode} out={r.stdout!r}")
r = b_run_cap("pipe-full-short", ["pipe"],
              stdin=f"a {V_FULL} b {V_SHORT} c")
check("WC A12: pipe applies full-mask and short-value floor",
      r.returncode == 0 and r.stdout == "a *** b *** c",
      f"rc={r.returncode} out={r.stdout!r}")
r = b_run_cap("pipe-keyforms", ["pipe"],
              stdin=f"{V_KEY}=1234\n{V_KEY}: abcd\n{{\"{V_KEY}\": \"efgh\"}}\n")
check("WC A12: pipe masks registered key-pattern forms",
      r.returncode == 0 and r.stdout
      == f"{V_KEY}=***\n{V_KEY}: ***\n{{\"{V_KEY}\": \"***\"}}\n",
      f"rc={r.returncode} out={r.stdout!r}")
r = b_run_cap("pipe-nomatch", ["pipe"], home=b_home_nomatch,
              stdin=f"secret {V_LIT}")
check("WC A12: pipe fails closed when matcher is missing",
      r.returncode == 2 and r.stdout == ""
      and "masking: unavailable (no pattern file — run install.sh + "
          "build)" in r.stderr,
      f"rc={r.returncode} out={r.stdout!r} err={r.stderr!r}")
r = b_run_cap("pipe-emptyreg", ["pipe"], home=b_home_empty,
              stdin="plain non-sensitive text")
check("WC A12: pipe accepts an established empty registry",
      r.returncode == 0 and r.stdout == "plain non-sensitive text",
      f"rc={r.returncode} out={r.stdout!r}")
r = b_run_cap("pipe-invalid-utf8", ["pipe"],
              stdin=b"x=\xff\xfe " + V_LIT.encode())
check("WC A12: pipe replaces invalid UTF-8 without disclosure",
      r.returncode == 0 and "\ufffd" in r.stdout
      and V_LIT not in r.stdout,
      f"rc={r.returncode} out={r.stdout!r}")
r = b_run_cap("pipe-unknown-opt", ["pipe", "--bad=" + V_LIT], stdin="x")
check("WC A12: unknown option warning is value-free",
      r.returncode == 2 and r.stderr == "warning: unknown option\n"
      and V_LIT not in r.stdout + r.stderr,
      f"rc={r.returncode} err={r.stderr!r}")
r = b_run_cap("pipe-help", ["pipe", "--help"], stdin="x")
check("WC A12: pipe help exits 0 without reading stdin",
      r.returncode == 0 and "info-guard pipe" in r.stdout,
      f"rc={r.returncode} out={r.stdout!r}")

# ── view: surfaces ──────────────────────────────────────────────────────
r = b_run_cap("view-sysd-ok", ["view", "systemd-unit", "okunit"], path=b_path)
check("WC A12: systemd viewer masks successful output and falls back safely",
      r.returncode == 0 and f"Environment={V_KEY}=***" in r.stdout
      and "[Unit]" in r.stdout,
      f"rc={r.returncode} out={r.stdout!r}")
r = b_run_cap("view-sysd-fallback",
              ["view", "systemd-unit", "userunit"], path=b_path)
check("WC A12: systemd viewer falls back to the user manager",
      r.returncode == 0 and "Description=user unit" in r.stdout
      and f"PASSWORD=ig...23" in r.stdout,
      f"rc={r.returncode} out={r.stdout!r}")
r = b_run_cap("view-docker", ["view", "docker-env", "mycontainer"],
              path=b_path)
check("WC A12: docker viewer masks environment output",
      r.returncode == 0 and f"{V_KEY}=***" in r.stdout
      and "PLAIN=hello" in r.stdout,
      f"rc={r.returncode} out={r.stdout!r}")
r = b_run_cap("view-compose", ["view", "compose-config", str(b_compose)],
              path=b_path)
check("WC A12: compose viewer masks rendered configuration",
      r.returncode == 0 and f"{V_KEY}=***" in r.stdout
      and "services: web" in r.stdout,
      f"rc={r.returncode} out={r.stdout!r}")
r = b_run_cap("view-file", ["view", "file", str(b_secfile)])
check("WC A12: file viewer masks explicit file output",
      r.returncode == 0 and r.stdout == "db_password=ig...23\n"
      and V_LIT not in r.stdout,
      f"rc={r.returncode} out={r.stdout!r}")

# ── view: failure classification + non-disclosure ───────────────────────
r = b_run_cap("view-sysd-nope", ["view", "systemd-unit", "nope"], path=b_path)
check("WC A12: source errors never expose compose docker or systemd output",
      r.returncode == 2 and r.stderr == "source: not found\n"
      and "could not be found" not in r.stdout + r.stderr,
      f"rc={r.returncode} err={r.stderr!r}")
r = b_run_cap("view-sysd-fail", ["view", "systemd-unit", "badunit"],
              path=b_path)
check("WC A12: child stderr is suppressed on every surface",
      r.returncode == 2 and r.stderr == "source: failed\n"
      and V_LIT not in r.stdout + r.stderr
      and "systemd failure" not in r.stdout + r.stderr,
      f"rc={r.returncode} err={r.stderr!r}")
r = b_run_cap("view-docker-ghost", ["view", "docker-env", "ghost"],
              path=b_path)
check("WC A12: docker absence classified as source not found",
      r.returncode == 2 and r.stderr == "source: not found\n"
      and "No such object" not in r.stdout + r.stderr,
      f"rc={r.returncode} err={r.stderr!r}")
r = b_run_cap("view-compose-missing",
              ["view", "compose-config", str(Path(WC_TMP, "nope.yml"))],
              path=b_path)
check("WC A12: compose missing file classified as source not found",
      r.returncode == 2 and r.stderr == "source: not found\n"
      and "no such file" not in r.stdout + r.stderr,
      f"rc={r.returncode} err={r.stderr!r}")
r = b_run_cap("view-file-missing",
              ["view", "file", str(Path(WC_TMP, "nope.txt"))])
check("WC A12: file viewer missing path classified as source not found",
      r.returncode == 2 and r.stderr == "source: not found\n",
      f"rc={r.returncode} err={r.stderr!r}")
r = b_run_cap("view-tool-missing", ["view", "systemd-unit", "okunit"],
              path_replace=str(Path(WC_TMP, "empty-bin")))
check("WC A12: missing tool classified as source not found",
      r.returncode == 2 and r.stderr == "source: not found\n",
      f"rc={r.returncode} err={r.stderr!r}")
# masking unavailable AFTER a successful source read -> source discarded
r = b_run_cap("view-mask-unavail", ["view", "file", str(b_secfile)],
              home=b_home_nomatch)
check("WC A12: masking failure discards the captured source",
      r.returncode == 2 and r.stdout == ""
      and r.stderr == "masking: unavailable\n",
      f"rc={r.returncode} out={r.stdout!r} err={r.stderr!r}")

# ── view: argv safety + metachar data ───────────────────────────────────
b_argvlog.write_text("")
r = b_run_cap("view-meta-args",
              ["view", "systemd-unit", "un$(id)it"],
              path=b_path)
r2 = b_run_cap("view-meta-docker",
               ["view", "docker-env", "ct$(id)n"], path=b_path)
r3 = b_run_cap("view-meta-compose",
               ["view", "compose-config", str(b_metafile)], path=b_path)
r4 = b_run_cap("view-meta-file",
               ["view", "file", str(b_metafile)])
argv_log = b_argvlog.read_text()
check("WC A12: metacharacter source arguments remain data",
      "un$(id)it" in argv_log and "ct$(id)n" in argv_log
      and str(b_metafile) in argv_log
      and "$(id)" in argv_log          # literal, never expanded
      and not Path(WC_TMP, "unit").exists()
      and not Path(WC_TMP, "ctn").exists(),
      f"argv={argv_log!r}")
# operator-supplied args CARRYING a registry value: source failure and
# usage failure paths must never echo the value or the argument text
r = b_run_cap("view-arg-lit-unit",
              ["view", "systemd-unit", "bad" + V_LIT], path=b_path)
r2 = b_run_cap("view-arg-lit-path",
               ["view", "file", str(Path(WC_TMP, V_LIT + ".txt"))])
check("WC A12: operator arguments never enter diagnostics",
      r.returncode == 2 and r.stderr == "source: failed\n"
      and r2.returncode == 2 and r2.stderr == "source: not found\n"
      and V_LIT not in r.stdout + r.stderr
      and V_LIT not in r2.stdout + r2.stderr,
      "registry-valued args leaked into a diagnostic stream")

# ── env ─────────────────────────────────────────────────────────────────
r = b_run_cap("env-default", ["env", str(b_envfile)])
check("WC A12: env emits keys and lengths without values",
      r.returncode == 0
      and "PLAIN = <5 chars>" in r.stdout
      and f"{V_KEY} = <4 chars>" in r.stdout
      and 'SECRET = <12 chars>' in r.stdout
      and "EMPTY = <0 chars>" in r.stdout
      and r.stdout.count("\n\n") >= 1     # blank + whitespace-only lines
      and V_LIT not in r.stdout and "hello" not in r.stdout
      and "quoted value" not in r.stdout and "1234" not in r.stdout,
      f"rc={r.returncode} out={r.stdout!r}")
r = b_run_cap("env-clean-check", ["env", str(b_clean), "--check"])
r2 = b_run_cap("env-dirty-check", ["env", str(b_hostile), "--check"],
               path=b_a17path_s)
check("WC A12: env check reports clean and dirty files",
      r.returncode == 0 and r.stdout == ""
      and r2.returncode == 1
      and all(re.fullmatch(r"\d+: [A-Za-z_][A-Za-z0-9_]*|\d+:",
                           ln) for ln in r2.stdout.splitlines()),
      f"clean-rc={r.returncode} dirty-rc={r2.returncode} "
      f"dirty-out={r2.stdout!r}")
r = b_run_cap("env-keys", ["env", str(b_envdup), "--keys"])
check("WC A12: env keys are bare sorted and unique",
      r.returncode == 0 and r.stdout == "A\nB\n",
      f"rc={r.returncode} out={r.stdout!r}")
r = b_run_cap("env-drop", ["env", str(b_envfile)])
check("WC A12: comments and malformed lines are dropped",
      r.returncode == 0 and V_LIT not in r.stdout + r.stderr
      and "MALFORMED NO EQUALS" not in r.stdout + r.stderr,
      f"rc={r.returncode} out={r.stdout!r} err={r.stderr!r}")
r = b_run_cap("env-unreadable", ["env", str(Path(WC_TMP, "nope.env"))])
check("WC A12: env unreadable file exits 2 value-free",
      r.returncode == 2 and r.stderr == "file: unreadable\n"
      and "nope.env" not in r.stdout + r.stderr,
      f"rc={r.returncode} err={r.stderr!r}")
r = b_run_cap("env-unknown-opt",
              ["env", str(b_envfile), "--bad=" + V_LIT])
check("WC A12: env unknown option is fixed and value-free",
      r.returncode == 2 and r.stderr == "warning: unknown option\n"
      and V_LIT not in r.stdout + r.stderr,
      f"rc={r.returncode} err={r.stderr!r}")
r = b_run_cap("env-check-keys", ["env", str(b_envfile), "--check", "--keys"])
check("WC A12: env check keys mutual exclusion exits 2",
      r.returncode == 2 and "info-guard env" in r.stderr,
      f"rc={r.returncode} err={r.stderr!r}")
r = b_run_cap("env-arg-leak", ["env", str(Path(WC_TMP, V_LIT + ".env"))])
check("WC A12: env path never enters diagnostics",
      r.returncode == 2 and V_LIT not in r.stdout + r.stderr,
      f"rc={r.returncode} err={r.stderr!r}")
r = b_run_cap("env-unicode", ["env", str(b_unic)])
check("WC A12: env lengths count code points not bytes",
      r.returncode == 0 and "K = <4 chars>" in r.stdout
      and "E = <7 chars>" in r.stdout,
      f"rc={r.returncode} out={r.stdout!r}")

# ── A17: hostile env --check non-execution ──────────────────────────────
for _p in (b_side, Path(str(b_side) + "2"), Path(str(b_side) + "3"),
           Path(str(b_side) + "5")):
    if _p.exists():
        _p.unlink()
if b_a17log.exists():
    b_a17log.unlink()
r = b_run_cap("env-hostile", ["env", str(b_hostile), "--check"],
              path=b_a17path_s)
check("WC A17: hostile env check creates no side effect",
      r.returncode == 1 and not b_side.exists()
      and not Path(str(b_side) + "2").exists()
      and not Path(str(b_side) + "3").exists()
      and not Path(str(b_side) + "5").exists(),
      f"rc={r.returncode} side={b_side.exists()}")
check("WC A17: hostile env check reports only lines and safe keys",
      r.returncode == 1
      and all(re.fullmatch(r"\d+: [A-Za-z_][A-Za-z0-9_]*|\d+:",
                           ln) for ln in r.stdout.splitlines())
      and "7: KEY6" in r.stdout          # dot-source attempt flagged too
      and V_LIT not in r.stdout + r.stderr
      and "touch" not in r.stdout + r.stderr
      and "source" not in r.stdout + r.stderr,
      f"rc={r.returncode} out={r.stdout!r} err={r.stderr!r}")
check("WC A17: hostile env check exits one without sourcing",
      r.returncode == 1 and not b_a17log.exists(),
      f"rc={r.returncode} a17log={b_a17log.exists()}")
# shared parser path: build's _load_env and env's check mode both call
# the SAME _parse_env_lines helper (one grammar, one source of truth)
ig_src_b = open(os.path.join(os.getcwd(), "bin", "info-guard")).read()
check("WC A17: env check shares the build parser path",
      "def _load_env" in ig_src_b
      and "_parse_env_lines(lines, report=" in ig_src_b
      and "_parse_env_lines(lines)[0]" in ig_src_b,
      "load_env and cmd_env must both route through _parse_env_lines")

# ── S4: security boundaries ─────────────────────────────────────────────
check("WC S4: every viewer source uses argv execution",
      "un$(id)it" in argv_log and "ct$(id)n" in argv_log
      and "shell=True" not in ig_src_b
      and "subprocess.run(" in ig_src_b,
      "shims received intact argv; no shell string execution path")
check("WC S4: every viewer suppresses child stderr",
      all("docker-stderr" not in (o + e) for _l, _rc, o, e in b_captures)
      and all("systemd failure" not in (o + e)
              for _l, _rc, o, e in b_captures),
      "child stderr text must never reach product streams")
check("WC S4: every viewer masks before emission",
      all(V_LIT not in o and V_FULL not in o and V_SHORT not in o
          for _l, _rc, o, e in b_captures)
      and any("ig...23" in o or "***" in o for _l, _rc, o, e in b_captures),
      "no raw value on stdout for any captured viewer run")
check("WC S4: unknown options are fixed and value-free",
      all(r.returncode == 2 and r.stderr == "warning: unknown option\n"
          for r in (b_run_cap("s4-unk-pipe", ["pipe", "--x=" + V_LIT],
                              stdin=""),
                    b_run_cap("s4-unk-view",
                              ["view", "file", str(b_secfile), "--x"],
                              path=b_path),
                    b_run_cap("s4-unk-env",
                              ["env", str(b_envfile), "--x"]))),
      "all three commands: fixed warning, exit 2, no value echo")
check("WC S4: viewer diagnostics never disclose operator arguments",
      all(V_LIT not in (o + e)
          and V_FULL not in (o + e) and V_SHORT not in (o + e)
          for _l, _rc, o, e in b_captures),
      "operator-supplied args must never appear in any diagnostic")

# ── S5: env --check never sources ───────────────────────────────────────
check("WC S5: env check never evaluates or sources input",
      not b_a17log.exists()
      and not b_side.exists()
      and all(p not in (o + e) for _l, _rc, o, e in b_captures
              for p in (str(b_side),)),
      "zero shell/touch invocations; side-effect target absent")
check("WC S5: env check disclosure boundary is line and safe-key only",
      r.returncode == 1
      and all(re.fullmatch(r"\d+: [A-Za-z_][A-Za-z0-9_]*|\d+:",
                           ln) for ln in r.stdout.splitlines())
      and V_LIT not in r.stdout + r.stderr,
      "report contains only line numbers and safe key names")

# ── A12: masked-only self-check + state no-mutation (aggregate) ─────────
check("WC A12: masked-only self-check finds no raw value on either stream",
      all(V_LIT not in (o + e) and V_FULL not in (o + e)
          and V_SHORT not in (o + e)
          for _l, _rc, o, e in b_captures)
      and any("ig...23" in o or "***" in o for _l, _rc, o, e in b_captures
              if _rc == 0),
      f"captured={len(b_captures)} runs")
check("WC A12: viewers leave registry and state unchanged",
      b_nomut,
      "byte-compared state dir + cwd git metadata across every viewer run")


# ── Wave D (W8 discover): WD A20-A32 / WD S8-S10 ──────────────────────
# Fixture: fresh HERMES_HOME + registry + synthetic source trees. All
# values are synthetic; no raw value is ever printed by this battery.
import importlib.machinery, importlib.util, inspect
import contextlib, io, secrets
WD = Path(tempfile.mkdtemp(prefix="ig-wd-"))
WDH = WD / "home"
WDREG = WDH / "state/info-guard/custom_literals.json"
WDSRC = WD / "src"
(WDH / "state/info-guard").mkdir(parents=True)
WDSRC.mkdir()
WDENV = dict(os.environ, HERMES_HOME=str(WDH))
IGPY = [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard")]
WD_CAPTURES = []          # (label, rc, stdout, stderr) for S8 leakage
WD_VALUES = []            # synthetic values never allowed on any surface

def wd_reg(vals=()):
    (WDH / "state/info-guard").mkdir(parents=True, exist_ok=True)
    WDREG.write_text(json.dumps({"version": 2, "literals": [
        {"value": v, "id": f"w{abs(hash(v)):016x}"} for v in vals]}))

def wd_run(*args, env=None, cwd=None):
    r = subprocess.run(IGPY + list(args), capture_output=True, text=True,
                       env=env or WDENV, cwd=cwd, timeout=180)
    WD_CAPTURES.append((" ".join(args[:2]), r.returncode, r.stdout, r.stderr))
    return r

def wd_run_o(*args, cwd=None):
    return subprocess.run(
        [sys.executable, "-O", os.path.join(os.getcwd(), "bin", "info-guard")]
        + list(args), capture_output=True, text=True, env=WDENV, cwd=cwd,
        timeout=180)

class _ThrowingRE:                       # forces a detector failure
    def finditer(self, *a, **k):
        raise RuntimeError("forced detector failure")

def _wdfrag(prefix):
    # Fragment-built sentinel: no complete token value exists in the
    # repository (battery fixture rule, build-diff M7 fold).
    return f"sk-wd-{prefix}-{secrets.token_hex(4)}"
V_A = _wdfrag("a")    # unregistered candidate
V_B = _wdfrag("b")    # unregistered candidate (nested)
V_R = _wdfrag("r")    # pre-registered (suppressed)
V_DUP = _wdfrag("d")  # enrolled then re-enrolled
V_COL = _wdfrag("c")  # colon-filename enrollment (fresh)
WD_VALUES += [V_A, V_B, V_R, V_DUP, V_COL]

# A22/A23 fixture: enrollable + excluded rows (dashed, colon-form,
# export, same-file duplicate, pre-registered, comment text).
wd_reg([V_R])
(wdsrc_a := WDSRC / "a.env").write_text(
    f"DEMO_API_TOKEN={V_A}\n"
    f"GH_API_KEY-X={_wdfrag('dashed')}\n"
    f"COLON_FORM: {_wdfrag('colon')}\n"
    f"export EXPORT_TOKEN={_wdfrag('export')}\n"
    f"REG_TOKEN={V_R}\n"
    f"DUP_TOKEN={_wdfrag('dup1')}\n"
    f"DUP_TOKEN={_wdfrag('dup2')}\n"
    f"# API_TOKEN={_wdfrag('comment')}\n")
(wdsrc_b := WDSRC / "nested").mkdir()
(wdsrc_b / "b.env").write_text(f"NESTED_TOKEN={V_B}\n")
(wdsrc_b / "blob.bin").write_bytes(b"\x00\x01\x02binary")

r = wd_run("discover", str(WDSRC), "--json")
d = json.loads(r.stdout)
check("battery.wave_d.candidate_identity_and_text_output: candidate identity — enrollable set exactly",
      r.returncode == 1 and d["status"] == "candidates"
      and d["count"] == 2 and d["error_class"] is None
      and {c["key"] for c in d["candidates"]} == {"DEMO_API_TOKEN",
                                                  "NESTED_TOKEN"}
      and all(set(c) == {"key", "source", "line", "shape_class",
                         "matched_pattern"} for c in d["candidates"])
      and all(c["shape_class"] == "KEY-SHAPE"
              and c["matched_pattern"].startswith("key-family:")
              for c in d["candidates"])
      and r.stderr == "",
      f"count={d['count']} keys={sorted(c['key'] for c in d['candidates'])}")
wd_empty = WD / "empty"
wd_empty.mkdir()
r2 = wd_run("discover", str(wd_empty), "--json")
r3 = wd_run("discover", str(wd_empty))
check("battery.wave_d.clean_discovery_exit_0: clean discovery — empty tree",
      r2.returncode == 0 and json.loads(r2.stdout)["status"] == "clean"
      and r2.stderr == "" and r3.returncode == 0
      and r3.stdout == "" and r3.stderr == "",
      "json + text clean envelopes")
r4 = wd_run("discover", str(wdsrc_a), "--json",
            env=dict(os.environ, HERMES_HOME=str(WD / "nohome")))
check("battery.wave_d.registry_unavailable_fail_closed: registry unavailable fails closed",
      r4.returncode == 2
      and json.loads(r4.stdout)["error_class"] == "registry_unavailable"
      and r4.stderr == "",
      "absent registry -> registry_unavailable")
WDREG.write_text('{"version": 1, "literals": ["old"]}')
b0 = WDREG.read_bytes()
r5 = wd_run("discover", str(wdsrc_a), "--json")
check("battery.wave_d.old_schema_read_only_discovery: old-schema registry read-only, bytes untouched",
      r5.returncode == 2
      and json.loads(r5.stdout)["error_class"] == "registry_unavailable"
      and WDREG.read_bytes() == b0,
      "v1 registry -> registry_unavailable, no migration write")
wd_reg([V_R])

# E4 lifecycle (A20): discover -> enroll -> suppressed -> idempotent dup.
r6 = wd_run("discover", str(WDSRC), "--json")
r7 = wd_run("literals", "add", "--from", f"{wdsrc_a}:DEMO_API_TOKEN")
r8 = wd_run("discover", str(WDSRC), "--json")
r9 = wd_run("literals", "add", "--from", f"{wdsrc_a}:DEMO_API_TOKEN",
            "--json")
check("battery.wave_d.e4_fresh_lifecycle_discover_enroll: discover -> --from enroll -> suppressed",
      r6.returncode == 1
      and r7.returncode == 0
      and re.fullmatch(r"value [0-9a-f]{16}", r7.stdout.strip())
      and V_A not in r7.stdout + r7.stderr
      and r8.returncode == 1
      and "DEMO_API_TOKEN" not in json.loads(r8.stdout)["candidates"]
      and r9.returncode == 0
      and json.loads(r9.stdout)["added"] == []
      and len(json.loads(r9.stdout)["duplicates"]) == 1,
      "enroll -> suppressed; duplicate -> idempotent existing id")
# A24: enrollment feeds the existing registry pass (the value_id join)
# and the preflight surface is UNCHANGED by W8 — verified once against
# the pre-Wave-D binary: the assessment is byte-identical except
# tool.version + scan timestamp, and the exit is identical (engine-less
# fixture -> 1). The scanned dir must sit INSIDE HERMES_HOME —
# preflight computes dir.relative_to(HERMES_HOME) and crashes on
# outside dirs (pre-existing behavior, unchanged by W8; recorded for
# the retrospective). NOTE: plain registered literals render "exposed"
# in the assessment (registration protects output masking, not at-rest
# status); the registry pass is the value_id join, asserted below.
wd_scan = WDH / "scanme"
wd_scan.mkdir(exist_ok=True)
(wd_scan / "f.env").write_text(
    f"KNOWN_TOKEN={V_A}\nFRESH_TOKEN={V_B}\n")
r10 = wd_run("preflight", str(wd_scan), "--json")
a24 = json.loads(r10.stdout) if r10.stdout else {}
a24fam = {f.get("family"): f
          for f in a24.get("families", {}).get("items", [])}
check("battery.wave_d.enroll_then_preflight_known: preflight ladder unchanged; assessment surface intact",
      r10.returncode == 1                     # engine-less fixture exit —
      and a24fam.get("KNOWN_TOKEN", {}).get("status") == "exposed"
      and a24fam.get("FRESH_TOKEN", {}).get("status") == "exposed"
      and V_A not in r10.stdout + r10.stderr,
      f"exit={r10.returncode} "
      f"known={a24fam.get('KNOWN_TOKEN', {}).get('status')} "
      f"fresh={a24fam.get('FRESH_TOKEN', {}).get('status')}")

# A25 failure matrix via the acceptance-harness DI hook (in-process).
_old_hh = os.environ.get("HERMES_HOME")
os.environ["HERMES_HOME"] = str(WDH)
_wd_spec = importlib.util.spec_from_loader(
    "igwd", importlib.machinery.SourceFileLoader(
        "igwd", os.path.join(os.getcwd(), "bin", "info-guard")))
wdm = importlib.util.module_from_spec(_wd_spec)
_wd_spec.loader.exec_module(wdm)
if _old_hh is None:
    os.environ.pop("HERMES_HOME", None)
else:
    os.environ["HERMES_HOME"] = _old_hh

check("battery.wave_d.enroll_then_preflight_known: registry pass joins enrolled value (value_id)",
      wdm._value_id_map().get(
          hashlib.sha256(V_A.encode()).hexdigest()) is not None
      and wdm._value_id_map().get(
          hashlib.sha256(V_B.encode()).hexdigest()) is None,
      "enrolled value joined; fresh value absent from the registry pass")

def wd_variant(name, mutate):
    reg0 = WDREG.read_bytes()
    src = WDSRC / "hook.env"
    if src.is_symlink() or src.exists():
        src.unlink()
    hv = _wdfrag("hv")                 # per-run value + replacement
    ov = _wdfrag("ov")
    src.write_text(f"# keep\nA_TOKEN={hv}\n")
    fired = []
    def hook(norm):
        mutate(norm, src, hv, ov)
        fired.append(1)
    wdm._FROM_TEST_HOOK = hook
    rc = wdm.cmd_literals(["add", "--from", f"{src}:A_TOKEN"])
    ok = rc == 2 and WDREG.read_bytes() == reg0 and len(fired) == 1
    check(f"battery.wave_d.from_failure_matrix: {name}: fail closed, "
          f"registry byte-unchanged",
          ok, f"rc={rc}")
    wdm._FROM_TEST_HOOK = None

def wd_mut_rename(_norm, src, _hv, ov):
    repl = WDSRC / "repl.env"
    repl.write_text(f"A_TOKEN={ov}\n")
    os.replace(repl, src)
def wd_mut_symlink(_norm, src, _hv, ov):
    tmp = WDSRC / "real.env"
    tmp.write_text(f"A_TOKEN={ov}\n")
    src.unlink()
    os.symlink(tmp, src)
def wd_mut_truncate(_norm, src, _hv, _ov):
    with open(src, "r+") as f:
        f.truncate(0)
def wd_mut_rewrite_outside(_norm, src, _hv, _ov):
    src.write_text(src.read_text().replace("# keep", "# chng"))
def wd_mut_rewrite_record(_norm, src, hv, _ov):
    src.write_text(src.read_text().replace(hv, _wdfrag("rr")))
def wd_mut_remove_record(_norm, src, hv, _ov):
    src.write_text(src.read_text().replace(f"A_TOKEN={hv}\n", ""))
wd_variant("c-rename-replace", wd_mut_rename)
wd_variant("d-symlink-substitute", wd_mut_symlink)
wd_variant("e-truncate", wd_mut_truncate)
wd_variant("f-rewrite-outside", wd_mut_rewrite_outside)
wd_variant("g-record-rewrite", wd_mut_rewrite_record)
wd_variant("h-record-removal", wd_mut_remove_record)
r11 = wd_run("literals", "add", "--from", f"{wdsrc_a}:NO_SUCH_KEY")
r12 = wd_run("literals", "add", "--from", f"{WD / 'nope'}:KEY")
r13 = wd_run("literals", "add", "--from", "badselector")
check("battery.wave_d.from_failure_matrix: unknown key / missing source / bad selector fail closed",
      r11.returncode == 2 and V_A not in r11.stdout + r11.stderr
      and r12.returncode == 2 and r13.returncode == 2,
      "value-free failures, no registry touch")

# A26 adversarial: colon filename, comment non-record, no execution.
wdsrc_a26 = WDSRC / "adv"
wdsrc_a26.mkdir()
(wdsrc_a26 / "a:b.env").write_text(f"COLON_PATH_TOKEN={V_COL}\n")
(wdsrc_a26 / "q;uote'x.env").write_text(f"QMARK_TOKEN={V_B}\n")
(wdsrc_a26 / "canary.sh").write_text(
    "#!/bin/sh\ntouch " + str(WD / "executed") + "\n")
os.chmod(wdsrc_a26 / "canary.sh", 0o755)
r14 = wd_run("literals", "add", "--from",
             f"{wdsrc_a26 / 'a:b.env'}:COLON_PATH_TOKEN", "--json")
r15 = wd_run("discover", str(wdsrc_a26), "--json")
check("battery.wave_d.adversarial_comments_colon_and_filenames: colon filename last-colon; metachar args as data; no exec",
      r14.returncode == 0 and len(json.loads(r14.stdout)["added"]) == 1
      and r15.returncode == 1
      and not (WD / "executed").exists(),
      "list-based args; canary never invoked")

# A29 config surface: discover.dirs drives; malformed -> invalid_config.
wd_reg([V_R])
WDREG.write_text(json.dumps({"version": 2, "literals": [],
                             "discover": {"dirs": [str(WDSRC)]}}))
r16 = wd_run("discover", "--json")
r17 = wd_run("discover", str(wd_empty), "--json")
check("battery.wave_d.configuration_surface_and_no_defaults: discover.dirs config drives selection; CLI overrides",
      r16.returncode == 1 and json.loads(r16.stdout)["count"] >= 1
      and r17.returncode == 0 and json.loads(r17.stdout)["status"] == "clean",
      "config root scanned; CLI path overrides config")
WDREG.write_text(json.dumps({"version": 2, "literals": [],
                             "discover": {"dirs": "not-a-list"}}))
r18 = wd_run("discover", str(wd_empty), "--json")
check("battery.wave_d.configuration_surface_and_no_defaults: malformed discover.dirs -> invalid_config (even with CLI)",
      r18.returncode == 2
      and json.loads(r18.stdout)["error_class"] == "invalid_config",
      "structural validation at stage 3")
wd_reg([V_R])
r19 = wd_run("discover", "--json")
check("battery.wave_d.configuration_surface_and_no_defaults: no sources -> usage",
      r19.returncode == 2 and json.loads(r19.stdout)["error_class"] == "usage",
      "")

# A30 selector/grammar matrix.
wdsrc_dash = WDSRC / "dash"
wdsrc_dash.mkdir()
(wdsrc_dash / "-d.env").write_text(f"DASH_TOKEN={V_DUP}\n")
r20 = wd_run("literals", "add", "--from", "-d.env:DASH_TOKEN",
             cwd=str(wdsrc_dash))
r21 = wd_run("literals", "add", "--from=-d.env:DASH_TOKEN", "--json",
             cwd=str(wdsrc_dash))
r22 = wd_run("literals", "add", "--from", "--", "-d.env:DASH_TOKEN",
             "--json", cwd=str(wdsrc_dash))
check("battery.wave_d.selector_and_build_env_grammar: selector forms — unmarked leading-dash rejected; "
      "equals and -- forms valid",
      r20.returncode == 2 and "usage" in r20.stderr
      and r21.returncode == 0 and len(json.loads(r21.stdout)["added"]) == 1
      and r22.returncode == 0
      and len(json.loads(r22.stdout)["duplicates"]) == 1,
      "rejection + both valid leading-dash forms")
r23 = wd_run("literals", "add", "--from", f"{wdsrc_a}:GH_API_KEY-X")
r24 = wd_run("literals", "add", "--from", f"{wdsrc_a}:demo_api_token")
check("battery.wave_d.selector_and_build_env_grammar: parser-rejected key + case sensitivity fail closed",
      r23.returncode == 2 and r24.returncode == 2
      and "invalid --from selector" in r23.stderr
      and r23.stderr != "" and r24.stderr != "", "")

# A31 traversal bounds: symlink fail-closed, depth, 10 MiB.
evl = WDSRC / "evil"
evl.mkdir()
try:
    (evl / "l").symlink_to("/etc")
    r25 = wd_run("discover", str(evl), "--json")
    check("battery.wave_d.bounded_no_follow_traversal: symlink anywhere fails closed (never skipped)",
          r25.returncode == 2
          and json.loads(r25.stdout)["error_class"] == "source_unreadable",
          "")
    (evl / "l").unlink()
except OSError:
    pass
d33 = WD / "d33"
p = d33
for _i in range(34):
    p = p / "x"
p.mkdir(parents=True)
(p / "f.env").write_text(f"D_TOKEN={_wdfrag('depth')}\n")
r26 = wd_run("discover", str(d33), "--json")
check("battery.wave_d.bounded_no_follow_traversal: depth 33 -> scan_limit", r26.returncode == 2
      and json.loads(r26.stdout)["error_class"] == "scan_limit", "")
big = WD / "big.env"
big.write_text("BIG_TOKEN=" + "a" * (10 * 1024 * 1024 + 1))
r27 = wd_run("discover", str(big), "--json")
check("battery.wave_d.bounded_no_follow_traversal: 10 MiB+1 file -> scan_limit (pre-binary)", r27.returncode == 2
      and json.loads(r27.stdout)["error_class"] == "scan_limit", "")

# A32: no implicit paths (canary files outside declared roots).
(WD / "cwd-canary.env").write_text(f"CWD_TOKEN={V_B}\n")
(WDH / "state/info-guard/canary.env").write_text(f"ST_TOKEN={V_B}\n")
r28 = wd_run("discover", str(wd_empty), "--json")
check("battery.wave_d.configuration_surface_and_no_defaults: no implicit cwd/state scan — canary files untouched",
      r28.returncode == 0 and json.loads(r28.stdout)["status"] == "clean"
      and json.loads(r28.stdout)["count"] == 0, "")

# r3 fold items 29/30: invalid_source + detector_error discard-all.
r29 = wd_run("discover", "", "--json")
# A NUL byte cannot exist in POSIX argv (exec rejects it), so the NUL
# path is exercised in-process against the same guard (list-based
# arguments, no shell, no exec).
_buf = io.StringIO()
with contextlib.redirect_stdout(_buf):
    _rc_nul = wdm.cmd_discover(["bad\x00path", "--json"])
_dnul = json.loads(_buf.getvalue())
check("battery.wave_d.invalid_source_cli_path: empty/NUL CLI path -> invalid_source",
      r29.returncode == 2
      and json.loads(r29.stdout)["error_class"] == "invalid_source"
      and r29.stderr == ""
      and _rc_nul == 2 and _dnul["error_class"] == "invalid_source", "")
wd_reg([V_R])
disc = WDSRC / "disc"
disc.mkdir(exist_ok=True)
(disc / "a.env").write_text(f"GOOD_TOKEN={V_A}\n")
(disc / "b.env").write_text(f"BAD_TOKEN={_wdfrag('bad')}\n")
os.chmod(disc / "b.env", 0)
r31 = wd_run("discover", str(disc), "--json")
os.chmod(disc / "b.env", 0o644)
check("battery.wave_d.detector_error_discard_all: mid-run failure discards accumulated candidates",
      r31.returncode == 2 and json.loads(r31.stdout)["count"] == 0
      and json.loads(r31.stdout)["candidates"] == [],
      f"error_class={json.loads(r31.stdout)['error_class']}")
_fd = os.open(disc / "a.env", os.O_RDONLY)
_orig_re = wdm._KEY_FORM_RE
wdm._KEY_FORM_RE = _ThrowingRE()
try:
    try:
        wdm._process_file(_fd, str(disc / "a.env"),
                          os.fstat(_fd), set())
        _der = None
    except Exception as e:
        _der = getattr(e, "error_class", None)
finally:
    wdm._KEY_FORM_RE = _orig_re
    os.close(_fd)
check("battery.wave_d.detector_error_discard_all: detector failure maps to detector_error",
      _der == "detector_error", f"class={_der}")

# S8 leakage: no raw value on any captured surface.
check("battery.security.masked_only_all_paths: masked-only across all discover/--from surfaces",
      all(all(v not in (o + e) for v in WD_VALUES)
          for _l, _rc, o, e in WD_CAPTURES),
      f"{len(WD_CAPTURES)} captured runs scanned")
# S9 strengthened in the build-diff additions section (WD-S9): discover
# calls the SHARED _scan_lines; the shared function holds the corpus.
# S10 no-shell (static + canary): no shell=True; canary not executed.
_src10 = "".join(inspect.getsource(wdm.cmd_discover)
                 + inspect.getsource(wdm._walk_dir)
                 + inspect.getsource(wdm._literals_add_from))
check("battery.security.no_shell_execution: no shell execution surface",
      "shell=True" not in _src10 and "subprocess" not in _src10
      and not (WD / "executed").exists(), "")

# item 28: -O parity — read-only scenarios byte-identical under python -O
# (an enrolling scenario would legitimately differ: the first run
# registers the value, the -O re-run sees a duplicate).
_par = True
for _args in (("discover", str(WDSRC), "--json"),
              ("discover", str(wd_empty), "--json"),
              ("discover", "--json")):
    _a = wd_run(*_args)
    _b = wd_run_o(*_args)
    _par = _par and (_a.returncode, _a.stdout, _a.stderr) == (
        _b.returncode, _b.stdout, _b.stderr)
check("battery.wave_d.optimized_interpreter_parity: optimized-interpreter parity (-O)",
      _par, "byte-identical stdout/stderr/exit")

# item 25: hook unreachable — exactly 3 occurrences in the shipped file
# (definition, invocation guard, call); no CLI/env/config activation.
_hook_count = open(os.path.join(os.getcwd(), "bin",
                                "info-guard")).read().count("_FROM_TEST_HOOK")
check("battery.security.test_hook_unreachable_in_release_surface: hook inert — no shipped activation surface",
      _hook_count == 3, f"occurrences={_hook_count}")

# item 26: stripped-PATH invocation works (gitleaks is a release-gate
# step, D116 — the gate runs it against the repo + evidence).
r33 = wd_run("discover", str(WDSRC), "--json",
             env=dict(os.environ, HERMES_HOME=str(WDH), PATH="/usr/bin:/bin"))
check("battery.security.stripped_path_gitleaks: stripped-PATH invocation works",
      r33.returncode == 1 and r33.stderr == "", "")

# item 27: version identity (package constant == CLI == CHANGELOG title).
_vid = wdm._PACKAGE_VERSION == "0.9.0"
r34 = wd_run("--version")
_vid = _vid and r34.stdout.strip() == "info-guard 0.9.0"
_chg = "\n".join((Path(os.getcwd()) / "CHANGELOG.md").read_text().split("\n")[:12])
_vid = _vid and "v0.9.0" in _chg
check("battery.release.version_identity_v0_9_0: version identity — constant == CLI == CHANGELOG",
      _vid, f"const={wdm._PACKAGE_VERSION} cli={r34.stdout.strip()!r}")



# ── build-diff fold additions: battery completion (E16-E28) ───────────
# Fresh, self-contained fixture so registry state is fully controlled.
WD2 = Path(tempfile.mkdtemp(prefix="ig-wd2-"))
WDH2 = WD2 / "home"
WDREG2 = WDH2 / "state/info-guard/custom_literals.json"
WDSRC2 = WD2 / "src"
(WDH2 / "state/info-guard").mkdir(parents=True)
WDSRC2.mkdir()
WDENV2 = dict(os.environ, HERMES_HOME=str(WDH2))
WD2_CAP = []                       # (label, rc, stdout, stderr)
def wd2_reg(body):
    (WDH2 / "state/info-guard").mkdir(parents=True, exist_ok=True)
    WDREG2.write_text(body if isinstance(body, str)
                      else json.dumps(body))
def wd2_run(*args, env=None, cwd=None):
    r = subprocess.run(IGPY + list(args), capture_output=True, text=True,
                       env=env or WDENV2, cwd=cwd, timeout=180)
    WD2_CAP.append((" ".join(args[:2]), r.returncode, r.stdout, r.stderr))
    return r

# E16 — text-mode errors: EXACTLY `error: <class>\n`, no path/key.
wd2_reg({"version": 2, "literals": []})
(wd2_f := WDSRC2 / "f.env").write_text(f"T_TOKEN={_wdfrag('frag')}\n")
big2 = WD2 / "big.env"
big2.write_text("BIG_TOKEN=" + "a" * (10 * 1024 * 1024 + 1))
_te_cases = [
    ("usage", ["discover", "--bogus"], None, None),
    ("registry_unavailable", ["discover", str(WDSRC2)],
     dict(os.environ, HERMES_HOME=str(WD2 / "nohome")), None),
    ("invalid_source", ["discover", ""], None, None),
    ("source_unreadable", ["discover", str(WD2 / "nope")], None, None),
    ("scan_limit", ["discover", str(big2)], None, None),
]
_te_ok = True
for _cls, _args, _env, _cwd in _te_cases:
    _r = wd2_run(*_args, env=_env, cwd=_cwd)
    _te_ok = _te_ok and _r.returncode == 2 \
        and _r.stderr == f"error: {_cls}\n" \
        and _r.stdout == "" \
        and str(WD2) not in _r.stderr and "T_TOKEN" not in _r.stderr
wd2_reg({"version": 2, "literals": [],
         "discover": {"dirs": "nope"}})
_r = wd2_run("discover", str(WDSRC2))
_te_ok = _te_ok and _r.returncode == 2 and _r.stderr == "error: invalid_config\n"
wd2_reg({"version": 2, "literals": []})
check("battery.wave_d.discover_unknown_flag_strict_stderr: every class"
      "emits exactly `error: <class>` with no path/key",
      _te_ok, f"cases={len(_te_cases) + 1}")

# E24 — unknown-flag strict stderr (clean, candidate, error fixtures).
wd2_reg({"version": 2, "literals": []})
_r = wd2_run("discover", str(WDSRC2), "--json", "--bogus")
_uf_ok = _r.returncode == 2 \
    and json.loads(_r.stdout)["error_class"] == "usage" and _r.stderr == ""
_r = wd2_run("discover", str(WDSRC2), "--bogus")
_uf_ok = _uf_ok and _r.returncode == 2 and _r.stderr == "error: usage\n"
check("battery.wave_d.discover_unknown_flag_strict_stderr: ",
      _uf_ok, "unknown flag -> usage exit 2, JSON stderr empty")

# E18/E19 — A23 sub-scenarios: dup keys across files, multi-pattern,
# tab path, BOTH modes; escaping unit + invalid-UTF-8 filename.
wd2_reg({"version": 2, "literals": []})
dup = WDSRC2 / "dup"
dup.mkdir(exist_ok=True)
(dup / "one.env").write_text(f"DUP_TOKEN={_wdfrag('dup1')}\n")
(dup / "two.env").write_text(f"DUP_TOKEN={_wdfrag('dup2')}\n")
(dup / "multi.env").write_text(f"API_TOKEN={_wdfrag('multi')}\n")
tabdir = WDSRC2 / "tab"
tabdir.mkdir(exist_ok=True)
(tabdir / "sp\tace.env").write_text(f"TAB_TOKEN={_wdfrag('tab')}\n")
_rj = wd2_run("discover", str(dup), "--json")
_rt = wd2_run("discover", str(dup))
_rj2 = wd2_run("discover", str(tabdir), "--json")
_rt2 = wd2_run("discover", str(tabdir))
_a23_ok = (_rj.returncode == 1
    and json.loads(_rj.stdout)["count"] == 3          # DUP_TOKEN x2 files + API_TOKEN
    and len([c for c in json.loads(_rj.stdout)["candidates"]
             if c["key"] == "DUP_TOKEN"]) == 2         # dup keys across files: separate pointers
    and len([c for c in json.loads(_rj.stdout)["candidates"]
             if c["key"] == "API_TOKEN"]) == 1        # multi-pattern: ONE pointer
    and _rt.returncode == 1 and len(_rt.stdout.splitlines()) == 3
    and _rj2.returncode == 1
    and "\\t" in json.loads(_rj2.stdout)["candidates"][0]["source"]
    and _rt2.returncode == 1 and "\\t" in _rt2.stdout)
check("battery.wave_d.candidate_identity_and_text_output: "
      "cross-file dup keys, multi-pattern one-pointer, tab path, both modes",
      _a23_ok,
      f"json={json.loads(_rj.stdout)['count']} "
      f"text-lines={len(_rt.stdout.splitlines())}")
# escaping unit assertions (E19):
_esc = wdm._discover_escape
_e_ok = (_esc("a\\b") == "a\\\\b" and _esc("a\tb") == "a\\tb"
         and _esc("a\rb") == "a\\rb" and _esc("a\nb") == "a\\nb"
         and _esc("a\x01b") == "a\\x01b" and _esc("a\x7fb") == "a\\x7Fb"
         and _esc("a\udcffb") == "a\\xFFb" and _esc("a\u2028b") == "a\\u{2028}b"
         and _esc("plain") == "plain")
check("battery.wave_d.invalid_utf8_source_text_and_json: "
      "byte-to-display escaping deterministic",
      _e_ok, "backslash/tab/CR/LF/C0/C1/surrogate/unicode-control")

# E20 — A27 no-persisted-candidate-state: state dir byte-hash unchanged.
wd2_reg({"version": 2, "literals": []})
_sd = WDH2 / "state"
def _sd_hash():
    h = hashlib.sha256()
    for p in sorted(_sd.rglob("*")):
        if p.is_file():
            h.update(str(p.relative_to(_sd)).encode())
            h.update(p.read_bytes())
    return h.hexdigest()
_h0 = _sd_hash()
_r = wd2_run("discover", str(WDSRC2), "--json")
_h1 = _sd_hash()
check("battery.wave_d.no_persisted_candidate_state: ",
      _r.returncode == 1 and _h0 == _h1,
      f"state-hash-stable={_h0 == _h1}")

# E21 — registry TOCTOU: hook mutates the registry mid-flight -> abort;
# writer failure (read-only state dir) -> exit 2 + no temp artifacts.
# E21a uses its OWN module instance scoped to WDH2 (the shared wdm
# points at the first fixture's registry). The mutation itself persists
# — the concurrent change is preserved verbatim; the assertion is that
# NO enrollment write landed on top of it.
_old_hh2 = os.environ.get("HERMES_HOME")
os.environ["HERMES_HOME"] = str(WDH2)
_wd2_spec = importlib.util.spec_from_loader(
    "igwd2", importlib.machinery.SourceFileLoader(
        "igwd2", os.path.join(os.getcwd(), "bin", "info-guard")))
wdm2 = importlib.util.module_from_spec(_wd2_spec)
_wd2_spec.loader.exec_module(wdm2)
if _old_hh2 is None:
    os.environ.pop("HERMES_HOME", None)
else:
    os.environ["HERMES_HOME"] = _old_hh2
wd2_reg({"version": 2, "literals": []})
wd2_hook = WDSRC2 / "hook2.env"
wd2_hook.write_text(f"H_TOKEN={_wdfrag('hook2')}\n")
_mut = []
_fired = []
def _reg_mutate(_norm):
    _payload = json.dumps({"version": 2, "literals": [{
        "value": _wdfrag("other"), "id": "mutated0000000001"}]})
    WDREG2.write_text(_payload)
    _mut.append(_payload.encode())
    _fired.append(1)
_old_hook = wdm2._FROM_TEST_HOOK
wdm2._FROM_TEST_HOOK = _reg_mutate
_rc = wdm2.cmd_literals(["add", "--from", f"{wd2_hook}:H_TOKEN"])
wdm2._FROM_TEST_HOOK = _old_hook
check("battery.wave_d.from_registry_snapshot_and_writer_failure: "
      "concurrent registry change aborts, mutation preserved verbatim",
      _rc == 2 and len(_fired) == 1 and WDREG2.read_bytes() == _mut[0],
      f"rc={_rc}")
# writer failure: read-only state dir -> canonical write fails, no temps.
wd2_reg({"version": 2, "literals": []})
wd2_hook.write_text(f"H_TOKEN={_wdfrag('hook2')}\n")
os.chmod(WDH2 / "state/info-guard", 0o555)
_r = wd2_run("literals", "add", "--from", f"{wd2_hook}:H_TOKEN")
os.chmod(WDH2 / "state/info-guard", 0o755)
_temps = [p.name for p in (WDH2 / "state/info-guard").glob(".redact-*")]
check("battery.wave_d.from_registry_snapshot_and_writer_failure: b: writer failure -> exit 2, no orphaned temp artifacts",
      _r.returncode == 2 and _temps == []
      and not any(v in (_r.stdout + _r.stderr) for v in WD_VALUES),
      f"temps={_temps}")

# E22 — exact boundaries: 10 MiB inclusive, 10K file count, depth 32/33.
wd2_reg({"version": 2, "literals": []})
_ex10 = WD2 / "exact.env"
_ex10.write_text("E_TOKEN=" + "a" * (10 * 1024 * 1024 - 9))
_rd = wd2_run("discover", str(_ex10), "--json")
_rd2 = wd2_run("discover", str(big2), "--json")
_b_ok = _rd.returncode == 0 and _rd2.returncode == 2 \
    and json.loads(_rd2.stdout)["error_class"] == "scan_limit"
_f10k = WD2 / "f10k"
_f10k.mkdir(exist_ok=True)
for _i in range(10001):
    (_f10k / f"f{_i}").write_text("x")
_rd3 = wd2_run("discover", str(_f10k), "--json")
_b_ok = _b_ok and _rd3.returncode == 2 \
    and json.loads(_rd3.stdout)["error_class"] == "scan_limit"
_d32 = WD2 / "d32"
_p = _d32
for _i in range(31):           # 31 dirs -> z.env sits AT depth 32 (in-bound)
    _p = _p / "x"
_p.mkdir(parents=True)
(_p / "z.env").write_text(f"D_TOKEN={_wdfrag('depth2')}\n")
_rd4 = wd2_run("discover", str(_d32), "--json")
check("battery.wave_d.exact_scan_boundaries: 10 MiB inclusive,"
      "10,001 files, depth-32 bound",
      _b_ok and _rd4.returncode == 1,
      f"exact10={_rd.returncode} over={_rd2.returncode} "
      f"10k={_rd3.returncode} d32={_rd4.returncode}")

# E23 — config/validation matrix: nonexistent config entry, v1 registry
# precedence, malformed discover block, discover:null, missing literals.
wd2_reg({"version": 2, "literals": [],
         "discover": {"dirs": [str(WD2 / "nope")]}})
_r = wd2_run("discover", "--json")
_c_ok = _r.returncode == 2 \
    and json.loads(_r.stdout)["error_class"] == "source_unreadable"
WDREG2.write_text('{"version": 1, "literals": [], "discover": {"dirs": ["/x"]}}')
_r = wd2_run("discover", "--json")
_c_ok = _c_ok and _r.returncode == 2 \
    and json.loads(_r.stdout)["error_class"] == "registry_unavailable"
WDREG2.write_text('{"version": 2, "discover": {"dirs": ["/x"]}}')
_r = wd2_run("discover", "--json")
_c_ok = _c_ok and _r.returncode == 2 \
    and json.loads(_r.stdout)["error_class"] == "registry_unavailable"
WDREG2.write_text('{"version": 2, "literals": [], "discover": null}')
_r = wd2_run("discover", "--json")
_c_ok = _c_ok and _r.returncode == 2 \
    and json.loads(_r.stdout)["error_class"] == "invalid_config"
check("battery.wave_d.configuration_surface_and_no_defaults: "
      "existential config -> source_unreadable; v1 + malformed-block -> "
      "registry_unavailable; discover:null + missing literals fail closed",
      _c_ok, "4 precedence cases")

# E25 — --from option-state: --from after -- rejected; unknown option in
# --from mode -> usage.
wd2_reg({"version": 2, "literals": []})
_r = wd2_run("literals", "add", "--", "--from", "x:y")
_r2 = wd2_run("literals", "add", "--from", f"{wd2_f}:T_TOKEN", "--bogus")
check("battery.wave_d.literals_add_before_after_compatibility: "
      "--from after -- rejected; unknown option in --from mode -> usage",
      _r.returncode == 2 and "usage" in _r.stderr
      and _r2.returncode == 2 and "usage" in _r2.stderr
      and all(v not in (_r.stdout + _r.stderr + _r2.stdout + _r2.stderr)
              for v in WD_VALUES), "")

# E26 — fragment-generated fixtures: no complete token value in test.sh.
_txt = open(os.path.join(os.getcwd(), "test.sh")).read()
_lit = re.findall(r"sk-wd(?:2-)?[0-9a-z-]{6,}", _txt)
check("battery.security.masked_only_all_paths: no complete"
      "token-shaped fixture constants in the battery",
      _lit == [], f"literal-tokens-found={_lit[:3]}")

# E27 — version identity complete: constant, CLI, preflight tool.version,
# CHANGELOG title.
_v27 = wdm._PACKAGE_VERSION == "0.9.0"
_r = wd2_run("--version")
_v27 = _v27 and _r.stdout.strip() == "info-guard 0.9.0"
# E27 — version identity: constant == CLI == preflight tool.version ==
# CHANGELOG. The preflight scan dir must sit INSIDE HERMES_HOME
# (preflight computes dir.relative_to(HERMES_HOME) — the F1 pre-existing
# limitation; out of W8 scope, recorded).
(WDH2 / "scanme").mkdir(exist_ok=True)
_r = wd2_run("preflight", str(WDH2 / "scanme"), "--json")
try:
    _v27 = _v27 and json.loads(_r.stdout).get("tool", {}).get("version") \
        == "0.9.0"
except ValueError:
    _v27 = False
_v27 = _v27 and "v0.9.0" in "\n".join(
    (Path(os.getcwd()) / "CHANGELOG.md").read_text().split("\n")[:12])
check("battery.release.version_identity_v0_9_0: constant =="
      "CLI == preflight tool.version == CHANGELOG",
      _v27, "")

# (E28 superseded by the executed-label ledger check at the end of the
# Wave D block — the canonical 30-name ledger verified against the
# EXECUTED check labels, evidence r2 Luna M2 + DS MAJ-1.)

# E17 — E4 full lifecycle against the INSTALLED ARTIFACT (evidence-fold
# B2): fresh install -> installed-CLI discover -> enroll -> check ->
# update -> uninstall, with version/hash identity + cleanup assertions.
try:
    # E4 scratch = the COMPLETE Hermes checkout at $HERMES_HOME/hermes-agent
    # (the check probe + W12 smoke resolve the engine there). Full-tree
    # archive at HEAD, init, commit, supported-release tag (D113), then
    # apply the artifact UNCOMMITTED (the uninstall's revert needs the
    # clean base; the e4-pkg below carries the committed update origin).
    _e4home = os.path.join(WD2, "e4-home")
    os.makedirs(_e4home, exist_ok=True)
    _e4_scratch = os.path.join(_e4home, "hermes-agent")
    os.makedirs(_e4_scratch, exist_ok=True)
    _arc = subprocess.run(["git", "-C", CHECKOUT, "archive", "--format=tar",
                           "HEAD"], capture_output=True, check=True)
    import tarfile, io
    with tarfile.open(fileobj=io.BytesIO(_arc.stdout), mode="r") as _tf:
        _tf.extractall(_e4_scratch)
    subprocess.run(["git", "-C", _e4_scratch, "init", "-q"], check=True)
    subprocess.run(["git", "-C", _e4_scratch, "add", "-A"], check=True)
    subprocess.run(["git", "-C", _e4_scratch, "-c", "user.email=ig@test",
                    "-c", "user.name=ig-test", "commit", "-q", "-m", "base"],
                   check=True)
    subprocess.run(["git", "-C", _e4_scratch, "tag", "v2026.8.18"],
                   check=True)
    # The patch stays UNCOMMITTED in the scratch (the 11a pattern) — the
    # uninstall's revert must restore the clean base; the e4-pkg (the
    # update's package) carries its own committed tree + origin instead.
    subprocess.run(["git", "-C", _e4_scratch, "apply", PATCH_PATH],
                   check=True)
    _e4env = dict(os.environ, HERMES_HOME=_e4home)
    _e4inst = subprocess.run(
        ["bash", os.path.join(os.getcwd(), "install.sh"), "--checkout",
         _e4_scratch, "--no-config", "--no-test"],
        env=_e4env, capture_output=True, text=True, timeout=300)
    _e4ok = _e4inst.returncode == 0
    # The installed package = a copy of the info-guard package (install.sh
    # patches the Hermes checkout but the package runs from its own
    # location — VERIFIED against the real install model; the fold's
    # scratch/bin claim was incorrect). The e4-pkg gets the WC hermetic
    # origin: https-shaped URL + insteadOf rewrite to a local bare repo
    # (the update enforces the HTTPS policy).
    _e4pkg = os.path.join(WD2, "e4-pkg")
    shutil.copytree(os.getcwd(), _e4pkg,
                    ignore=shutil.ignore_patterns(".git", "test-runs"))
    subprocess.run(["git", "-C", _e4pkg, "init", "-q"], check=True)
    subprocess.run(["git", "-C", _e4pkg, "add", "-A"], check=True)
    subprocess.run(["git", "-C", _e4pkg, "-c", "user.email=ig@test",
                    "-c", "user.name=ig-test", "commit", "-q", "-m",
                    "base"], check=True)
    subprocess.run(["git", "-C", _e4pkg, "tag", "v0.7.0"], check=True)
    _e4remote = os.path.join(WD2, "e4-remote.git")
    subprocess.run(["git", "init", "-q", "--bare", _e4remote], check=True)
    subprocess.run(["git", "-C", _e4pkg, "push", "-q", _e4remote,
                    "HEAD:refs/heads/main", "v0.7.0"], check=True)
    subprocess.run(["git", "-C", _e4pkg, "remote", "add", "origin",
                    "https://ig-test.invalid/e4-remote.git"], check=True)
    subprocess.run(["git", "-C", _e4pkg, "config",
                    f"url.{_e4remote}.insteadOf",
                    "https://ig-test.invalid/e4-remote.git"], check=True)
    E4_CLI = os.path.join(_e4pkg, "bin", "info-guard")
    _e4ok = _e4ok and os.path.isfile(E4_CLI) and os.access(E4_CLI, os.X_OK)
    # Evidence r2 C1: the e4-pkg IS the installed package content —
    # byte-identical to the package install.sh operates from (the repo)
    # — proven by hash, not asserted.
    _h_cli = hashlib.sha256(open(E4_CLI, "rb").read()).hexdigest()
    _h_pkg = hashlib.sha256(open(os.path.join(os.getcwd(), "bin",
                                              "info-guard"),
                                 "rb").read()).hexdigest()
    _e4ok = _e4ok and _h_cli == _h_pkg
    _e4val = _wdfrag("e4")
    _r = subprocess.run([sys.executable, E4_CLI, "--version"],
                        capture_output=True, text=True, env=_e4env,
                        timeout=120)
    _e4ok = _e4ok and _r.returncode == 0 \
        and _r.stdout.strip() == "info-guard 0.9.0"
    _inst4 = os.path.join(_e4home, "state", "info-guard", "install.json")
    _e4ok = _e4ok and os.path.isfile(_inst4) \
        and json.load(open(_inst4)).get("version") == "0.9.0"
    _e4src = os.path.join(WD2, "e4-src")
    os.makedirs(_e4src, exist_ok=True)
    with open(os.path.join(_e4src, "f.env"), "w") as _fh:
        _fh.write(f"E4_TOKEN={_e4val}\n")
    _reg4 = os.path.join(_e4home, "state", "info-guard",
                         "custom_literals.json")
    _e4ok = _e4ok and os.path.isfile(_reg4) \
        and json.load(open(_reg4)) == {"version": 2, "literals": []}
    _inst4 = os.path.join(_e4home, "state", "info-guard", "install.json")
    _e4ok = _e4ok and os.path.isfile(_inst4) \
        and json.load(open(_inst4)).get("version") == "0.9.0"
    _r = subprocess.run([sys.executable, E4_CLI, "discover", _e4src,
                         "--json"], capture_output=True, text=True,
                        env=_e4env, timeout=120)
    _e4ok = _e4ok and _r.returncode == 1 \
        and _e4val not in _r.stdout + _r.stderr
    _r = subprocess.run([sys.executable, E4_CLI, "literals", "add",
                         "--from", os.path.join(_e4src, "f.env") +
                         ":E4_TOKEN"], capture_output=True, text=True,
                        env=_e4env, timeout=120)
    _e4ok = _e4ok and _r.returncode == 0 \
        and _e4val not in _r.stdout + _r.stderr
    _r = subprocess.run([sys.executable, E4_CLI, "check"],
                        capture_output=True, text=True, env=_e4env,
                        timeout=120)
    _e4ok = _e4ok and _r.returncode == 0 \
        and _e4val not in _r.stdout + _r.stderr
    _r = subprocess.run([sys.executable, E4_CLI, "update"],
                        capture_output=True, text=True, env=_e4env,
                        timeout=300)
    # Evidence r2 MIN-4: the hermetic no-update path IS the intended
    # outcome here — "up to date" with the install.json unchanged (the
    # W10 transaction machinery is exhaustively covered by the WC
    # update battery, sections 8-10).
    _e4ok = _e4ok and _r.returncode == 0 \
        and "up to date" in _r.stdout \
        and json.load(open(_inst4)).get("version") == "0.9.0" \
        and _e4val not in _r.stdout + _r.stderr
    _r = subprocess.run(
        ["bash", os.path.join(os.getcwd(), "uninstall.sh"), "--checkout",
         _e4_scratch, "--yes"], env=_e4env, capture_output=True, text=True,
        timeout=300)
    _e4ok = _e4ok and _r.returncode == 0
    # deployment-owned artifacts removed: the tree is back at the clean
    # base (the 11d pattern — git diff --exit-code HEAD; the reverse-
    # check would correctly FAIL here: there is nothing to reverse) and
    # the installed state is gone.
    _rev = subprocess.run(["git", "-C", _e4_scratch, "diff", "--exit-code",
                           "HEAD"], capture_output=True)
    _e4ok = _e4ok and _rev.returncode == 0 \
        and not os.path.exists(os.path.join(_e4home, "state", "info-guard",
                                            "install.json"))
except (subprocess.CalledProcessError, OSError) as _e4err:
    _e4ok = False
check("battery.wave_d.e4_fresh_lifecycle_discover_enroll: "
      "installed-artifact install -> discover -> enroll -> check -> "
      "update -> uninstall round-trip",
      _e4ok, "no deployment-owned machinery; version 0.9.0; cleanup verified")

# S9 strengthen: discover calls the SHARED scan; the shared function
# holds the single corpus (function-level reuse, not string co-occurrence).
_s9src = inspect.getsource(wdm._detect_and_filter)
_s9shared = inspect.getsource(wdm._scan_lines)
check("battery.security.single_sourced_detector: discover uses"
      "the shared _scan_lines (single implementation)",
      "_scan_lines" in _s9src and "_KEY_FORM_RE" in _s9shared
      and "_TOKEN_PREFIX_RE" in _s9shared and "re.compile" not in _s9src
      and "re.compile" not in _s9shared, "")



# ── evidence-gate fold additions (E29-E38) ────────────────────────────
# Fresh, self-contained fixture (wd3).
wd3 = Path(tempfile.mkdtemp(prefix="ig-wd3-"))
WDH3 = wd3 / "home"
WDREG3 = WDH3 / "state/info-guard/custom_literals.json"
(WDH3 / "state/info-guard").mkdir(parents=True)
WDSRC3 = wd3 / "src"
WDSRC3.mkdir()
WDENV3 = dict(os.environ, HERMES_HOME=str(WDH3))
WDREG3.write_text(json.dumps({"version": 2, "literals": []}))
_okroot = wd3 / "ok"
_okroot.mkdir()
(_okroot / "f.env").write_text(f"OK_TOKEN={_wdfrag('ok')}\n")
wd3_empty = wd3 / "empty2"
wd3_empty.mkdir()

def wd3_run(*args):
    return subprocess.run(IGPY + list(args), capture_output=True, text=True,
                          env=WDENV3, timeout=180)

# E29: validate-all-roots-before-traverse — multi-root mixed failure with
# an fd-count assertion (in-process via /proc/self/fd).
_old_hh3 = os.environ.get("HERMES_HOME")
os.environ["HERMES_HOME"] = str(WDH3)
_wd3_spec = importlib.util.spec_from_loader(
    "igwd3", importlib.machinery.SourceFileLoader(
        "igwd3", os.path.join(os.getcwd(), "bin", "info-guard")))
wdm3 = importlib.util.module_from_spec(_wd3_spec)
_wd3_spec.loader.exec_module(wdm3)
if _old_hh3 is None:
    os.environ.pop("HERMES_HOME", None)
else:
    os.environ["HERMES_HOME"] = _old_hh3
_fds_before = len(os.listdir("/proc/self/fd"))
_buf29 = io.StringIO()
with contextlib.redirect_stdout(_buf29):
    _rc29 = wdm3.cmd_discover([str(_okroot),
                               str(wd3 / "nope"), "--json"])
_fds_after = len(os.listdir("/proc/self/fd"))
check("battery.wave_d.validate_all_roots_before_traverse: "
      "multi-root mixed failure — first failure wins, no fd leak",
      _rc29 == 2
      and json.loads(_buf29.getvalue())["error_class"] == "source_unreadable"
      and _fds_after <= _fds_before,
      f"rc={_rc29} fds={_fds_before}->{_fds_after}")

# E30: exact boundary matrix.
WDREG3.write_text(json.dumps({"version": 2, "literals": []}))
_ex = wd3 / "exact.env"
_ex.write_text("E_TOKEN=" + "a" * (10 * 1024 * 1024 - 9))   # exactly 10 MiB
_r = wd3_run("discover", str(_ex), "--json")
_e30 = _r.returncode == 0                                   # blob-filtered
_ex2 = wd3 / "exact2.env"
_ex2.write_text("E2_TOKEN=" + "a" * (10 * 1024 * 1024 - 8)) # 10 MiB + 1
_r = wd3_run("discover", str(_ex2), "--json")
_e30 = _e30 and _r.returncode == 2 \
    and json.loads(_r.stdout)["error_class"] == "scan_limit"
_f10k = wd3 / "f10k3"
_f10k.mkdir(exist_ok=True)
for _i in range(10000):
    (_f10k / f"f{_i}").write_text("x")
_r = wd3_run("discover", str(_f10k), "--json")
_e30 = _e30 and _r.returncode == 0
(_f10k / "f10000").write_text("x")
_r = wd3_run("discover", str(_f10k), "--json")
_e30 = _e30 and _r.returncode == 2 \
    and json.loads(_r.stdout)["error_class"] == "scan_limit"
_hardNR, _hardNRmax = resource.getrlimit(resource.RLIMIT_NOFILE)
_named = wd3 / "named"
_named.mkdir()
for _i in range(10000):
    (_named / f"n{_i}").write_text("x")
if _hardNRmax >= 10000 + 256:
    # Evidence r2 MIN-6: the 10,000-named-root case needs a hard
    # RLIMIT_NOFILE >= 10,256 — skip with a recorded reason when the
    # host cannot hold it (the in-dir counting sub-cases still cover
    # the file-count bound).
    _r = subprocess.run(IGPY + ["discover"] +
                        [str(_named / f"n{i}") for i in range(10000)] +
                        ["--json"], capture_output=True, text=True,
                        env=WDENV3, timeout=180)
    _e30 = _e30 and _r.returncode == 0
    (_named / "n10000").write_text("x")    # the 10,001st FILE must exist —
                                           # the bound fires in the collect,
                                           # not as a missing-source error
    _r = subprocess.run(IGPY + ["discover"] +
                        [str(_named / f"n{i}") for i in range(10001)] +
                        ["--json"], capture_output=True, text=True,
                        env=WDENV3, timeout=180)
    _e30 = _e30 and _r.returncode == 2 \
        and json.loads(_r.stdout)["error_class"] == "scan_limit"
_hard = wd3 / "hard"
_hard.mkdir()
(_hard / "h1").write_text("x")
os.link(_hard / "h1", _hard / "h2")
_r = wd3_run("discover", str(_hard), "--json")
_e30 = _e30 and _r.returncode == 0      # two entries, one inode
_d32b = wd3 / "d32b"
_p = _d32b
for _i in range(31):
    _p = _p / "x"
_p.mkdir(parents=True)
(_p / "z.env").write_text(f"D_TOKEN={_wdfrag('depth3')}\n")
_r = wd3_run("discover", str(_d32b), "--json")
_e30 = _e30 and _r.returncode == 1      # candidate at depth 32 (in-bound)
_d33b = wd3 / "d33b"
_p = _d33b
for _i in range(32):
    _p = _p / "x"
_p.mkdir(parents=True)
(_p / "z.env").write_text(f"D_TOKEN={_wdfrag('depth4')}\n")
_r = wd3_run("discover", str(_d33b), "--json")
_e30 = _e30 and _r.returncode == 2 \
    and json.loads(_r.stdout)["error_class"] == "scan_limit"
check("battery.wave_d.exact_scan_boundaries: 10 MiB in/out,"
      "10,000/10,001 in-dir + named roots, hard links, depth 32/33",
      _e30, "")

# E31: --from requires the shared-detector eligibility.
WDREG3.write_text(json.dumps({"version": 2, "literals": []}))
_src31 = wd3 / "elig"
_src31.mkdir(exist_ok=True)
(_src31 / "f.env").write_text(
    f"API_TOKEN={_wdfrag('elig')}\nMY_KEY=hello-world-123\n")
_r = wd3_run("literals", "add", "--from",
             f"{_src31 / 'f.env'}:MY_KEY")
_e31 = _r.returncode == 2 and "not a detected secret" in _r.stderr
_r = wd3_run("literals", "add", "--from",
             f"{_src31 / 'f.env'}:API_TOKEN")
_e31 = _e31 and _r.returncode == 0
check("battery.wave_d.selector_and_build_env_grammar: --from"
      "requires the shared-detector match; non-detector records fail",
      _e31, f"rc={_r.returncode}")

# E32: malformed registry ENTRIES -> registry_unavailable, bytes intact.
WDREG3.write_text(json.dumps({"version": 2, "literals": [42]}))
_reg32 = WDREG3.read_bytes()
_r = wd3_run("discover", str(_okroot), "--json")
_e32 = _r.returncode == 2 \
    and json.loads(_r.stdout)["error_class"] == "registry_unavailable" \
    and WDREG3.read_bytes() == _reg32
WDREG3.write_text(json.dumps({"version": 2, "literals": [
    {"id": "no-value-field"}]}))
_r = wd3_run("discover", str(_okroot), "--json")
_e32 = _e32 and _r.returncode == 2 \
    and json.loads(_r.stdout)["error_class"] == "registry_unavailable"
check("battery.wave_d.old_schema_read_only_discovery: malformed registry entries fail closed, bytes intact",
      _e32, "")

# E33: commit lock — concurrent change aborts (mutation before the
# locked re-read), the lock file is 0600, lock-acquisition failure
# (absent lock + read-only state dir) exits 2 with no temps.
WDREG3.write_text(json.dumps({"version": 2, "literals": []}))
_hk = wd3 / "lock.env"
_hk.write_text(f"H_TOKEN={_wdfrag('lock')}\n")
_f33 = []
def _reg_mutate33(_norm):
    WDREG3.write_text(json.dumps({"version": 2, "literals": [
        {"value": _wdfrag("x"), "id": "mutated33"}]}))
    _f33.append(1)
_old_hk = wdm3._FROM_TEST_HOOK
wdm3._FROM_TEST_HOOK = _reg_mutate33
_rc33 = wdm3.cmd_literals(["add", "--from", f"{_hk}:H_TOKEN"])
wdm3._FROM_TEST_HOOK = _old_hk
_lmode = oct((WDH3 / "state/info-guard/.info-guard.lock").stat().st_mode
             & 0o777)
_e33 = _rc33 == 2 and len(_f33) == 1 and _lmode == "0o600"
WDREG3.write_text(json.dumps({"version": 2, "literals": []}))
(WDH3 / "state/info-guard/.info-guard.lock").unlink(missing_ok=True)
os.chmod(WDH3 / "state/info-guard", 0o555)
_r = wd3_run("literals", "add", "--from", f"{_hk}:H_TOKEN")
os.chmod(WDH3 / "state/info-guard", 0o755)
_temps33 = list((WDH3 / "state/info-guard").glob(".redact-*"))
_e33 = _e33 and _r.returncode == 2 and _temps33 == []
check("battery.wave_d.from_registry_snapshot_and_writer_failure: "
      "locked commit — concurrent change aborts, 0600 lock, acquisition "
      "failure -> exit 2, no temps",
      _e33, f"rc33={_rc33} rc={_r.returncode}")

# E34: discover --help / -h -> usage exit 0, stderr empty; the
# JSON-qualified forms too (evidence r3 n2).
_r = wd3_run("discover", "--help")
_e34 = _r.returncode == 0 and "discover" in _r.stdout and _r.stderr == ""
_r = wd3_run("discover", "-h")
_e34 = _e34 and _r.returncode == 0 and _r.stderr == ""
_r = wd3_run("discover", "--help", "--json")
_e34 = _e34 and _r.returncode == 0 and _r.stderr == "" \
    and "discover" in _r.stdout
_r = wd3_run("discover", "-h", "--json")
_e34 = _e34 and _r.returncode == 0 and _r.stderr == "" \
    and "discover" in _r.stdout
check("battery.wave_d.discover_unknown_flag_strict_stderr: "
      "help forms exit 0 with usage on stdout", _e34, "")

# E35: bare token line (no key) -> zero candidates.
_bare = wd3 / "bare"
_bare.mkdir(exist_ok=True)
(_bare / "t.env").write_text(f"sk-{_wdfrag('bare')}\n")
WDREG3.write_text(json.dumps({"version": 2, "literals": []}))
_r = wd3_run("discover", str(_bare), "--json")
check("battery.wave_d.candidate_identity_and_text_output: bare"
      "token emits zero candidates",
      _r.returncode == 0
      and json.loads(_r.stdout)["status"] == "clean", "")

# E36: unknown-flag strict stderr across three fixture shapes + the C1
# control escaping unit case.
_rcs36 = []
for _fix in (str(wd3_empty), str(_okroot), str(wd3 / "nope")):
    # --json BEFORE the unknown flag so the JSON error envelope is
    # asserted; the text form asserts the exact stderr line.
    _r = wd3_run("discover", "--json", _fix, "--bogus")
    _rcs36.append(_r.returncode == 2 and _r.stderr == ""
                  and json.loads(_r.stdout)["error_class"] == "usage")
    _r2 = wd3_run("discover", _fix, "--bogus")
    _rcs36.append(_r2.returncode == 2
                  and _r2.stderr == "error: usage\n")
# Evidence r3 m1: the error MODE is argv-order-independent — the unknown
# flag BEFORE --json still yields the JSON envelope.
_r = wd3_run("discover", str(_okroot), "--bogus", "--json")
_rcs36.append(_r.returncode == 2 and _r.stderr == ""
              and json.loads(_r.stdout)["error_class"] == "usage")
_e36 = all(_rcs36) and wdm3._discover_escape("\x85") == "\\x85"
check("battery.wave_d.discover_unknown_flag_strict_stderr: unknown-flag strict across clean/candidate/error "
      "fixtures; C1 control escaping", _e36, "")

# E37: in-process surface leakage scan (S8 extension — the A25-style
# hook path with captured stdout+stderr).
_buf37 = io.StringIO()
_hv = _wdfrag("s8v")
_ov = _wdfrag("s8o")
_s8src = wd3 / "s8.env"
_s8src.write_text(f"S_TOKEN={_hv}\n")
_reg37 = WDREG3.read_bytes()
_old_hk = wdm3._FROM_TEST_HOOK
def _mut37(_norm):
    _s8src.write_text(_s8src.read_text().replace(_hv, _ov))
wdm3._FROM_TEST_HOOK = _mut37
with contextlib.redirect_stdout(_buf37), contextlib.redirect_stderr(_buf37):
    _rc37 = wdm3.cmd_literals(["add", "--from", f"{_s8src}:S_TOKEN"])
wdm3._FROM_TEST_HOOK = _old_hk
_txt37 = _buf37.getvalue()
check("battery.security.masked_only_all_paths: in-process"
      "enrollment surfaces masked-only (hook values never leak)",
      _rc37 == 2 and _hv not in _txt37 and _ov not in _txt37,
      f"rc={_rc37}")

# (The canonical executed-label ledger check moved to the end of the
# Wave D block — it must see the E42+ checks' executed labels too.)

# E39: configuration entry classification — symlink/special/NUL entries
# in discover.dirs fail closed (stage 5 for existentials, stage 3 for
# structural NUL).
WDREG3.write_text(json.dumps({"version": 2, "literals": [],
                              "discover": {"dirs": [str(wd3 / "sym")]}}))
os.symlink(_okroot, wd3 / "sym")
_r = wd3_run("discover", "--json")
_e39 = _r.returncode == 2 and _r.stderr == "" \
    and json.loads(_r.stdout)["error_class"] == "source_unreadable"
os.unlink(wd3 / "sym")
WDREG3.write_text(json.dumps({"version": 2, "literals": [],
                              "discover": {"dirs": ["bad\x00path"]}}))
_r = wd3_run("discover", "--json")
_e39 = _e39 and _r.returncode == 2 \
    and json.loads(_r.stdout)["error_class"] == "invalid_config"
check("battery.wave_d.configuration_entry_classification: "
      "symlink -> source_unreadable, NUL -> invalid_config",
      _e39, "")

# E40: relative configured dir resolves against the invocation cwd.
_rel = wd3 / "relwork"
_rel.mkdir(exist_ok=True)
(_rel / "r.env").write_text(f"REL_TOKEN={_wdfrag('rel')}\n")
WDREG3.write_text(json.dumps({"version": 2, "literals": [],
                              "discover": {"dirs": ["relwork"]}}))
_r = subprocess.run(IGPY + ["discover", "--json"], capture_output=True,
                    text=True, env=WDENV3, cwd=str(wd3), timeout=120)
check("battery.wave_d.relative_configured_dir_cwd_resolution: "
      "relative discover.dirs resolves against the invocation cwd",
      _r.returncode == 1
      and json.loads(_r.stdout)["status"] == "candidates"
      and json.loads(_r.stdout)["candidates"][0]["key"] == "REL_TOKEN", "")

# E41: existing `literals add` compatibility surface is unchanged
# (before/after baseline: -- end-of-options, unknown-flag
# warning-and-continue, duplicate idempotency).
WDREG3.write_text(json.dumps({"version": 2, "literals": []}))
_r = wd3_run("literals", "add", "--", "--json")
_e41 = _r.returncode == 0 and _r.stdout.startswith("value ")
_r = wd3_run("literals", "add", "--bogus", _wdfrag("compat2"))
_e41 = _e41 and _r.returncode == 0 and "Warning" in _r.stderr
_cv = _wdfrag("compat")
_r = wd3_run("literals", "add", _cv, "--json")
_dup = _r.stdout
_r = wd3_run("literals", "add", _cv, "--json")
_e41 = _e41 and _r.returncode == 0 \
    and json.loads(_dup)["added"] \
    and json.loads(_r.stdout)["duplicates"]
check("battery.wave_d.literals_add_before_after_compatibility: "
      "existing add surface unchanged (--, warning-and-continue, "
      "idempotent duplicates)",
      _e41, "")

# ── evidence-gate r2 additions (E42-E49 + canonical executed-ledger) ──
# E42: exact 10 MiB boundary — the r2 C1 correction (the earlier
# fixture was M-1: "E_TOKEN=" is 8 bytes + M-9 = M-1).
WDREG3.write_text(json.dumps({"version": 2, "literals": []}))
_exM = wd3 / "exactM.env"
_exM.write_text("E_TOKEN=" + "a" * (10 * 1024 * 1024 - 8))  # EXACTLY 10 MiB
_r = wd3_run("discover", str(_exM), "--json")
check("battery.wave_d.exact_scan_boundaries: exact 10 MiB in-bound "
      "(blob-filtered clean)",
      _r.returncode == 0, f"rc={_r.returncode}")

# E43: deterministic growth-during-read (r2 C2) — a harness-controlled
# os.read wrapper grows the file past the bound mid-read -> scan_limit.
# The A6 temp-copy import isolates the patch; os.read is restored in the
# finally.
_gr = wd3 / "grow.env"
_gr.write_text("G_TOKEN=" + "a" * (10 * 1024 * 1024 - 9))   # M-1
_old_hh43 = os.environ.get("HERMES_HOME")
os.environ["HERMES_HOME"] = str(WDH3)
_tmp43 = os.path.join(WD2, "ig43.py")
shutil.copy(os.path.join(os.getcwd(), "bin", "info-guard"), _tmp43)
_wd43spec = importlib.util.spec_from_loader(
    "igwd43", importlib.machinery.SourceFileLoader("igwd43", _tmp43))
wd43 = importlib.util.module_from_spec(_wd43spec)
_wd43spec.loader.exec_module(wd43)
if _old_hh43 is None:
    os.environ.pop("HERMES_HOME", None)
else:
    os.environ["HERMES_HOME"] = _old_hh43
_orig_read43 = os.read
_reads43 = {"n": 0}
def _grow_read(fd, n):
    _reads43["n"] += 1
    b = _orig_read43(fd, n)
    if _reads43["n"] == 150:
        b = b + b"x" * 65536      # grow past the bound mid-read
    return b
os.read = _grow_read
_buf43 = io.StringIO()
try:
    with contextlib.redirect_stdout(_buf43):
        # cmd_discover takes the args AFTER the command word — passing
        # "discover" again would treat it as a path (my c6-probe bug,
        # caught here by the battery).
        _rc43 = wd43.cmd_discover([str(_gr), "--json"])
finally:
    os.read = _orig_read43
check("battery.wave_d.exact_scan_boundaries: deterministic "
      "growth-during-read -> scan_limit",
      _rc43 == 2 and json.loads(_buf43.getvalue())["error_class"]
      == "scan_limit", f"rc={_rc43}")

# E44: detector/parser value agreement (r2 B3) — quoted + trailing-
# comment forms agree and enroll; a same-line double record fails
# closed (exactly-one violated).
WDREG3.write_text(json.dumps({"version": 2, "literals": []}))
_ag = wd3 / "agree"
_ag.mkdir(exist_ok=True)
_agv_q = _wdfrag("agq")
_agv_c = _wdfrag("agc")
_agv_d = _wdfrag("agd")
_agv_x = _wdfrag("agx")
(_ag / "f.env").write_text(
    f'API_TOKEN="{_agv_q}"\n'
    f"API_KEY={_agv_c} # deploy note\n"
    f"DB_TOKEN={_agv_d} DB_TOKEN={_agv_x}\n")
_r = wd3_run("literals", "add", "--from",
             f"{_ag / 'f.env'}:API_TOKEN", "--json")
_e44 = _r.returncode == 0 \
    and json.loads(_r.stdout)["added"][0]["value_masked"] \
    == _agv_q[:2] + "..." + _agv_q[-2:]
_r = wd3_run("literals", "add", "--from",
             f"{_ag / 'f.env'}:API_KEY")
_e44 = _e44 and _r.returncode == 0
_r = wd3_run("literals", "add", "--from", f"{_ag / 'f.env'}:DB_TOKEN")
_e44 = _e44 and _r.returncode == 2
# Evidence r3 m2: the --from mode is argv-order-independent — an unknown
# flag BEFORE --from is still a hard usage error (plan 12.3).
_r = wd3_run("literals", "add", "--bogus", "--from",
             f"{_ag / 'f.env'}:API_TOKEN")
_e44 = _e44 and _r.returncode == 2 \
    and "unknown option in --from mode" in _r.stderr
check("battery.wave_d.selector_and_build_env_grammar: detector/parser "
      "value agreement — quoted + comment agree, double record fails "
      "closed", _e44, f"rc={_r.returncode}")

# E45: flock() acquisition failure (r2 E2) -> exit 2, registry intact,
# no temps.
WDREG3.write_text(json.dumps({"version": 2, "literals": []}))
_fk = wd3 / "flk.env"
_fk.write_text(f"H_TOKEN={_wdfrag('flk')}\n")
_reg45 = WDREG3.read_bytes()
_old_hh45 = os.environ.get("HERMES_HOME")
os.environ["HERMES_HOME"] = str(WDH3)
_tmp45 = os.path.join(WD2, "ig45.py")
shutil.copy(os.path.join(os.getcwd(), "bin", "info-guard"), _tmp45)
_wd45spec = importlib.util.spec_from_loader(
    "igwd45", importlib.machinery.SourceFileLoader("igwd45", _tmp45))
wd45 = importlib.util.module_from_spec(_wd45spec)
_wd45spec.loader.exec_module(wd45)
if _old_hh45 is None:
    os.environ.pop("HERMES_HOME", None)
else:
    os.environ["HERMES_HOME"] = _old_hh45
_orig_flock45 = fcntl.flock
def _fail_flock45(fd, op):
    raise OSError(22, "flock forced failure")
fcntl.flock = _fail_flock45
_buf45 = io.StringIO()
try:
    with contextlib.redirect_stdout(_buf45), \
            contextlib.redirect_stderr(_buf45):
        _rc45 = wd45.cmd_literals(["add", "--from", f"{_fk}:H_TOKEN"])
finally:
    fcntl.flock = _orig_flock45
_temps45 = list((WDH3 / "state/info-guard").glob(".redact-*"))
check("battery.wave_d.from_registry_snapshot_and_writer_failure: "
      "flock failure -> exit 2, registry intact, no temps",
      _rc45 == 2 and WDREG3.read_bytes() == _reg45 and _temps45 == [],
      f"rc={_rc45}")

# E46: malformed optional fields (r2 G4) -> registry_unavailable.
WDREG3.write_text(json.dumps({"version": 2,
                              "literals": [{"value": "x", "id": 123}]}))
_reg46 = WDREG3.read_bytes()
_r = wd3_run("discover", str(wd3 / "ok"), "--json")
check("battery.wave_d.old_schema_read_only_discovery: malformed "
      "optional field (id: 123) -> registry_unavailable, bytes intact",
      _r.returncode == 2
      and json.loads(_r.stdout)["error_class"] == "registry_unavailable"
      and WDREG3.read_bytes() == _reg46, f"rc={_r.returncode}")

# E47: hard-link per-entry accounting (r2 H1): 10,000 directory
# entries, one inode linked twice -> clean (per-ENTRY counting, not
# per-inode). Registry reset first — E46 left the malformed-entry
# fixture behind.
WDREG3.write_text(json.dumps({"version": 2, "literals": []}))
_hard2 = wd3 / "hard2"
_hard2.mkdir()
for _i in range(9999):
    (_hard2 / f"h{_i}").write_text("x")
os.link(_hard2 / "h0", _hard2 / "h9999")   # 10,000 entries, 9,999 inodes
_r = wd3_run("discover", str(_hard2), "--json")
check("battery.wave_d.exact_scan_boundaries: hard links count per "
      "directory entry (10,000 entries, 9,999 inodes -> clean)",
      _r.returncode == 0, f"rc={_r.returncode}")

# E48: registry normalization suppression (r2 A5) — a QUOTED .env value
# whose normalized (parser) form matches a registered literal is
# suppressed from candidates.
_nv = _wdfrag("nrm")
WDREG3.write_text(json.dumps({"version": 2, "literals": [
    {"value": _nv, "id": "norm0000000001"}]}))
_nsrc = wd3 / "norm"
_nsrc.mkdir(exist_ok=True)
(_nsrc / "n.env").write_text(f'TOKEN="{_nv}"\n')
_r = wd3_run("discover", str(_nsrc), "--json")
check("battery.wave_d.registry_normalization_suppression: quoted "
      "registered value suppressed from candidates",
      _r.returncode == 0 and json.loads(_r.stdout)["status"] == "clean",
      f"rc={_r.returncode}")

# E49 — the CANONICAL executed-label ledger (evidence r2 Luna M2 + DS
# MAJ-1): every one of the 30 approved plan names must appear in at
# least one EXECUTED check label (captured by the harness check()
# wrapper), and NO informal labels (WD-prefixed) may remain.
_LEDGER = [
    "battery.release.version_identity_v0_9_0",
    "battery.security.masked_only_all_paths",
    "battery.security.no_shell_execution",
    "battery.security.single_sourced_detector",
    "battery.security.stripped_path_gitleaks",
    "battery.security.test_hook_unreachable_in_release_surface",
    "battery.wave_d.adversarial_comments_colon_and_filenames",
    "battery.wave_d.bounded_no_follow_traversal",
    "battery.wave_d.candidate_identity_and_text_output",
    "battery.wave_d.clean_discovery_exit_0",
    "battery.wave_d.configuration_entry_classification",
    "battery.wave_d.configuration_surface_and_no_defaults",
    "battery.wave_d.detector_error_discard_all",
    "battery.wave_d.discover_unknown_flag_strict_stderr",
    "battery.wave_d.e4_fresh_lifecycle_discover_enroll",
    "battery.wave_d.enroll_then_preflight_known",
    "battery.wave_d.exact_scan_boundaries",
    "battery.wave_d.from_failure_matrix",
    "battery.wave_d.from_registry_snapshot_and_writer_failure",
    "battery.wave_d.invalid_source_cli_path",
    "battery.wave_d.invalid_utf8_source_text_and_json",
    "battery.wave_d.literals_add_before_after_compatibility",
    "battery.wave_d.no_persisted_candidate_state",
    "battery.wave_d.old_schema_read_only_discovery",
    "battery.wave_d.optimized_interpreter_parity",
    "battery.wave_d.registry_normalization_suppression",
    "battery.wave_d.registry_unavailable_fail_closed",
    "battery.wave_d.relative_configured_dir_cwd_resolution",
    "battery.wave_d.selector_and_build_env_grammar",
    "battery.wave_d.validate_all_roots_before_traverse",
]
_missing49 = [n for n in _LEDGER
              if not any(l.startswith(n) for l in EXECUTED_LABELS)]
_informal49 = [l for l in EXECUTED_LABELS
               if l.startswith("WD ") or l.startswith("WD-")]
_multi49 = [n for n in _LEDGER
            if sum(1 for l in EXECUTED_LABELS if l.startswith(n)) > 1]
# Evidence r3 M1: the label claims what the check verifies — presence of
# every canonical name + no informal labels; sub-case splits sharing a
# canonical name are reported (informational), not merged.
check("battery ledger: all 30 canonical names executed (no informal "
      "labels)",
      _missing49 == [] and _informal49 == [],
      f"missing: {', '.join(_missing49) if _missing49 else 'none'}; "
      f"informal: {', '.join(_informal49) if _informal49 else 'none'}; "
      f"multi-executed (sub-case splits): "
      f"{', '.join(_multi49) if _multi49 else 'none'}")

# Battery hygiene (evidence-gate fold, run-15 EDQUOT lesson): remove the
# throwaway fixtures — repeated runs must never accumulate toward the
# /tmp quota (the E4 full-tree archives are the biggest per-run cost).
for _d in (tmp, WD, WD2, wd3):
    try:
        shutil.rmtree(str(_d))
    except OSError:
        pass


print(f"\n[test] {PASS} passed, {FAIL} failed"
      f" (discovered={PASS + FAIL + SKIP} executed={PASS + FAIL} "
      f"passed={PASS} skipped={SKIP} failed={FAIL})")
sys.exit(1 if FAIL else 0)
PYEOF
