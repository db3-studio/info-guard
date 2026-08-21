#!/usr/bin/env python3
"""Wave A v1.1 same-major consumer probe (Info Guard v0.6.0 contract gate).

Proves the same-major compatibility doctrine (Wave A §2.2/§2.3, A22):
a consumer written against v1.0 must accept a v1.1 payload — parse the
schema surface + major from "info-guard/<surface>/v<major>[.<minor>]",
NEVER compare the full string literally, tolerate unknown minor
versions, tolerate unknown additive fields/row types/enum values, and
preserve/report security-significant unknown values (D85 two-part
contract: syntactic tolerance + semantic handling).

Run against assessment/watch/literals JSON (stdin or --file PATH).
Exit 0 = compatible; 1 = a same-major contract broke.

Usage: python3 v1.1-consumer-probe.py [--file PATH] [--surface assessment|watch|literals]
"""
import json
import re
import sys

SCHEMA_RE = re.compile(r"^info-guard/([a-z-]+)/v(\d+)(?:\.(\d+))?$")


def parse_schema(schema_str):
    m = SCHEMA_RE.match(schema_str or "")
    if not m:
        return None
    return {"surface": m.group(1), "major": int(m.group(2)),
            "minor": int(m.group(3)) if m.group(3) else 0}


def main():
    path = None
    surface = None
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--file" and i + 1 < len(args):
            path = args[i + 1]
            i += 2
        elif args[i] == "--surface" and i + 1 < len(args):
            surface = args[i + 1]
            i += 2
        else:
            print(f"usage: v1.1-consumer-probe.py [--file PATH] "
                  f"[--surface assessment|watch|literals]", file=sys.stderr)
            return 2
    try:
        obj = json.load(open(path) if path else sys.stdin)
    except Exception as e:  # noqa: BLE001 — probe mirrors battery style
        print(f"✗ probe: JSON parse failed: {e}", file=sys.stderr)
        return 1

    fails = []

    def chk(name, cond):
        if not cond:
            fails.append(name)
            print(f"  ✗ {name}", file=sys.stderr)

    # 1. schema surface parsing — major-scoped, minor-tolerant:
    parsed = parse_schema(obj.get("schema"))
    chk("schema parses as info-guard/<surface>/v<major>[.<minor>]",
        parsed is not None)
    if parsed:
        if surface:
            chk(f"surface matches ({surface})", parsed["surface"] == surface)
        chk("schema major is int >= 1", parsed["major"] >= 1)
        # same-major acceptance: consumer knows major 1; unknown minor is
        # FINE (this probe accepts ANY minor under major 1)
        chk("same-major accepted (major 1)", parsed["major"] == 1)
    # 2. envelope — tool block present with name + version:
    tool = obj.get("tool", {})
    chk("tool block present", isinstance(tool, dict) and tool.get("name"))
    chk("tool.version present", isinstance(tool.get("version"), str))

    # 3. syntactic tolerance — unknown additive fields at every level must
    # not break parsing (we simply don't read them; the parse above proves
    # JSON validity). Emit a warning for any unknown top-level key so the
    # "tolerate + preserve/report" posture is visible:
    known_top = {"schema", "tool", "status", "totals", "families",
                 "locations", "patterns", "redaction", "top_values",
                 "affected_files", "recommendations", "appendix", "scan",
                 "watch", "assessment", "exposure", "protection", "engine",
                 "literals"}
    unknown = [k for k in obj.keys() if k not in known_top]
    for k in unknown:
        print(f"  ℹ tolerated unknown top-level field: {k}", file=sys.stderr)

    # 4. semantic handling — security-significant unknown enum values are
    # preserved/reported, never silently dropped: if a finding row carries
    # an unknown `type` value, the row must still reach the findings path.
    rows = []
    if isinstance(obj.get("top_values"), list):
        rows += obj["top_values"]
    if isinstance(obj.get("exposure"), dict):
        for arr in ("new_values", "changed_values", "protected_values",
                    "resolved_values"):
            if isinstance(obj["exposure"].get(arr), list):
                rows += obj["exposure"][arr]
    for row in rows:
        t = row.get("type")
        if t and t not in ("KNOWN", "JWT", "GitHub PAT", "API key",
                           "Discord bot token", "Firecrawl key",
                           "generated key", "Slack token", "AWS key",
                           "webhook secret", "GitLab PAT", "hash-like token",
                           "token-shaped", "KEY-SHAPE", "SUSPICIOUS",
                           "HIGH-CONFIDENCE", "key-name", "placeholder",
                           "already-masked"):
            print(f"  ℹ preserve/report unknown type {t!r} on row "
                  f"(masked={row.get('value_masked')})", file=sys.stderr)

    # 5. masked-only surface discipline holds at v1.1:
    blob = json.dumps(obj)
    chk("no raw-value sentinel leaks",
        not any(k in blob for k in ("your-actual-key-here", "MTQ5MjY4",
                                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")))
    chk("no value_sha256 on public surfaces",
        "value_sha256" not in blob)

    print(f"[probe] v1.1 same-major: {'PASS' if not fails else f'FAIL ({len(fails)})'}"
          f" — {len(fails)} break(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
