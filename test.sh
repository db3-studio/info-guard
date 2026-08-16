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
import subprocess
import sys
import tempfile
import time

CHECKOUT = sys.argv[1]
sys.path.insert(0, CHECKOUT)
from agent.redact import redact_sensitive_text

PASS = 0
FAIL = 0

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  \u2713 {name}")
    else:
        FAIL += 1
        print(f"  \u2717 {name} {detail}")

def write(p, obj):
    with open(p, "w") as f:
        json.dump(obj, f)

tmp = tempfile.mkdtemp(prefix="info-guard-test-")
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


print(f"\n[test] {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
PYEOF
