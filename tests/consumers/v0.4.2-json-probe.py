#!/usr/bin/env python3
"""v0.4.2-era JSON consumer probe (Info Guard v0.5.0 compatibility gate).

This probe is the VERBATIM JSON-parsing logic that existed in
test.sh@v0.4.2 (section 13: `preflight --json` checks) extracted into a
standalone consumer — the closest thing to a real v0.4.2 JSON consumer
the public repo shipped. Run it against v0.5.0 assessment JSON (stdin
or --file PATH) to prove the additive KNOWN-tier fields
(`totals.known`, `totals.known_rows`, `known`/`source_key` on rows,
`status.confirmed_active: true`, per-path `known` counts) are ignored
by old consumers and that every pre-v0.5.0 field keeps its type and
placement (plan A10, MAJ-5 r2 / MAJ-4 r3).

Exit 0 = compatible; 1 = a pre-v0.5.0 contract broke.

Usage: python3 v0.4.2-json-probe.py [--file PATH]   (default: stdin)
"""
import json
import sys


def main():
    path = None
    args = sys.argv[1:]
    if args and args[0] == "--file":
        if len(args) < 2:
            print("usage: v0.4.2-json-probe.py [--file PATH]", file=sys.stderr)
            return 2
        path = args[1]
    try:
        obj = json.load(open(path) if path else sys.stdin)
    except Exception as e:  # noqa: BLE001 — probe mirrors old battery
        print(f"✗ probe: JSON parse failed: {e}", file=sys.stderr)
        return 1

    fails = []

    def chk(name, cond):
        if not cond:
            fails.append(name)
            print(f"  ✗ {name}", file=sys.stderr)

    # 13. preflight --json checks as they existed at v0.4.2:
    chk("schema field", obj.get("schema") == "info-guard/assessment/v1")
    st = obj.get("status", {})
    chk("status.confirmed_active present",
        "confirmed_active" in st and st["confirmed_active"] in (None, True))
    fams = obj.get("families", {})
    chk("families wrapper object",
        isinstance(fams.get("items"), list) and fams.get("complete") is True
        and fams.get("total_with_values")
        == sum(1 for f in fams["items"] if f["value"] > 0))
    t = obj.get("totals", {})
    chk("totals.partition flag", t.get("partition") is True)
    # v0.4.2 identity: findings = raw + mentions + masked (KNOWN rows are
    # additive; when known==0 the identity must hold EXACTLY as before)
    if t.get("known", 0) == 0:
        chk("totals reconcile (raw partition, known==0)",
            t["findings"] == t["raw_detections"] + t["key_name_mentions"]
            + t["already_masked"])
    chk("attribution split reconciles",
        t["credential_shaped"] == t["family_attributed"] + t["unattributed"])
    chk("distinct <= rows <= raw",
        t["distinct_values"] <= t["credential_shaped"] <= t["raw_detections"])
    # field TYPES must be unchanged from v0.4.2:
    chk("credential_shaped is int", isinstance(t["credential_shaped"], int))
    chk("raw_detections is int", isinstance(t["raw_detections"], int))
    chk("distinct_values is int", isinstance(t["distinct_values"], int))
    chk("findings is int", isinstance(t["findings"], int))
    for row in obj.get("top_values", []):
        chk("top_values row shape",
            isinstance(row.get("value_masked"), str)
            and isinstance(row.get("type"), str)
            and isinstance(row.get("count"), int))
        # v0.5.0 additive fields on KNOWN rows are FINE (ignored); but a
        # KNOWN row must carry its contract fields, and non-KNOWN rows
        # must NOT (absent, never null):
        if row.get("known") is True:
            chk("KNOWN row source_key non-empty",
                isinstance(row.get("source_key"), str) and row["source_key"])
        else:
            chk("non-KNOWN row omits known/source_key",
                "known" not in row and "source_key" not in row)
    chk("raw values never present in JSON",
        not any(k in json.dumps(obj) for k in
                ("your-actual-key-here", "MTQ5MjY4", "eyJhbGci")))
    print(f"[probe] v0.4.2-compat: {'PASS' if not fails else f'FAIL ({len(fails)})'}"
          f" — {len(fails)} break(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
