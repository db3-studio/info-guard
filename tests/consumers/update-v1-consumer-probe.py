#!/usr/bin/env python3
"""info-guard/update/v1 consumer probe (Wave C Phase A, IG D113).

Reads ONE update envelope from stdin and validates the contract invariants
a consumer relies on (proposal self-sustain.md §3.2 / plan
self-sustain-phase-a §3.10). Exit 0 = valid, 1 = invalid.

Contract checks:
- schema is exactly info-guard/update/v1
- status/engine/error_class are exactly the normative enums
- applied/healed are booleans; healed implies engine ACTIVE
- status updated implies applied; status error implies a non-none
  error_class
- current is a version string or null; latest/selected_commit null
  semantics are caller-side (this probe only validates types)
"""
import json
import sys

ENUM_STATUS = {"up_to_date", "updated", "update_available", "heal_failed",
               "error"}
ENUM_ENGINE = {"ACTIVE", "PARTIAL", "MISSING", "DRIFT", "UNKNOWN"}
ENUM_ERR = {"none", "usage", "network", "dirty_tree", "not_git", "lock",
            "checkout", "install", "tag_mismatch", "version_mismatch",
            "verify", "state", "repair"}


def main():
    raw = sys.stdin.read()
    try:
        env = json.loads(raw)
    except ValueError as e:
        print(f"update envelope: not JSON: {e}", file=sys.stderr)
        return 1
    if not isinstance(env, dict):
        print("update envelope: not an object", file=sys.stderr)
        return 1
    errs = []
    if env.get("schema") != "info-guard/update/v1":
        errs.append("schema")
    if env.get("status") not in ENUM_STATUS:
        errs.append(f"status={env.get('status')!r}")
    if env.get("engine") not in ENUM_ENGINE:
        errs.append(f"engine={env.get('engine')!r}")
    if env.get("error_class") not in ENUM_ERR:
        errs.append(f"error_class={env.get('error_class')!r}")
    if not isinstance(env.get("applied"), bool) or not isinstance(
            env.get("healed"), bool):
        errs.append("applied/healed must be booleans")
    if env.get("current") is not None and not isinstance(
            env.get("current"), str):
        errs.append("current must be a version string or null")
    if env.get("latest") is not None and not isinstance(env.get("latest"),
                                                        str):
        errs.append("latest must be a version string or null")
    if env.get("selected_commit") is not None and not isinstance(
            env.get("selected_commit"), str):
        errs.append("selected_commit must be a sha or null")
    if env.get("status") == "updated" and not env.get("applied"):
        errs.append("updated implies applied")
    if env.get("healed") and env.get("engine") != "ACTIVE":
        errs.append("healed implies engine ACTIVE")
    if env.get("status") == "error" and env.get("error_class") == "none":
        errs.append("error implies a non-none error_class")
    if errs:
        print(f"update envelope: INVALID: {', '.join(errs)}", file=sys.stderr)
        return 1
    print("update envelope: VALID (info-guard/update/v1)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
