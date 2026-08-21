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
import shutil
import subprocess
import sys
import tempfile
import time
import hashlib
from pathlib import Path

CHECKOUT = sys.argv[1]
sys.path.insert(0, CHECKOUT)
from agent.redact import redact_sensitive_text

PASS = 0
FAIL = 0
SKIP = 0

def check(name, cond, detail=""):
    global PASS, FAIL
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
for section in ("Info Guard v0.6.0 — Preflight Security Assessment",
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

# 12c. --version flag
ver = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "--version"],
    capture_output=True, text=True, timeout=60)
check("--version prints the package version",
      ver.returncode == 0 and ver.stdout.strip() == "info-guard 0.6.0",
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

print(f"\n[test] {PASS} passed, {FAIL} failed"
      f" (discovered={PASS + FAIL + SKIP} executed={PASS + FAIL} "
      f"passed={PASS} skipped={SKIP} failed={FAIL})")
sys.exit(1 if FAIL else 0)
PYEOF
