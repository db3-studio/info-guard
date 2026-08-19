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
for section in ("Info Guard v0.2.5 — Preflight Security Assessment",
                "STATUS", "EXECUTIVE SUMMARY", "WHAT MATTERS",
                "CREDENTIAL EXPOSURE BY FAMILY",
                "EXPOSURE LOCATIONS",
                "WHY AM I SEEING THIS", "RECOMMENDED ACTIONS",
                "APPENDIX B — FINDING LEDGER (sample"):
    check(f"preflight: section '{section}' present", section in pfo)
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
      "· 1 masked" in pfo and "Mixed" in pfo)
check("preflight: attribution split reconciles",
      "family-attributed" in pfo and "unattributed" in pfo)
check("preflight: tier partition stated explicitly",
      "mutually exclusive" in pfo)
check("preflight: session-timestamp date discipline",
      "from session timestamps" in pfo)
check("preflight: key-name tier defined in the partition note",
      "key-name" in pfo)
check("preflight: why status = redaction status, caveat in action",
      "active status unknown" in pfo and "candidate — active status unknown" not in pfo)
check("preflight: appendix A absent from the main report",
      "APPENDIX A" not in pfo)

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
      "APPENDIX B — FINDING LEDGER (complete" in pffo
      and "APPENDIX B — FINDING LEDGER (sample" not in pffo,
      "expected complete ledger header")
check("preflight --full: telemetry appendix present (forensic mode)",
      "APPENDIX A — DETECTION TELEMETRY" in pffo,
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

# 12c. --version flag
ver = subprocess.run(
    [sys.executable, os.path.join(os.getcwd(), "bin", "info-guard"), "--version"],
    capture_output=True, text=True, timeout=60)
check("--version prints the package version",
      ver.returncode == 0 and ver.stdout.strip() == "info-guard 0.2.5",
      f"rc={ver.returncode} out={ver.stdout.strip()!r}")


print(f"\n[test] {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
PYEOF
