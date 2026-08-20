# Info Guard — Watch JSON schema (`info-guard/watch/v1`)

The machine-readable result of `info-guard watch` — the **public delta
result** (proposal-review amendment 1, IG D49). Where
[assessment.json](assessment-schema.md) is the preflight point-in-time
snapshot, watch/v1 is the change report: what differs between the
baseline snapshot and the current scan, across three tracks — exposure
(values), protection configuration (fingerprints/counts), and engine
state (transitions).

**Status:** shipped with v0.4.0 (2026-08-20). Independent AI plan review
amended the row shape pre-build (review MAJ A3): exposure rows carry
`value_masked` (2+2) — **`value_sha256` is FORBIDDEN in this object**
(the private 0600 baseline keeps sha256; this is the public surface, and
sha256 of low-entropy values is brute-forceable).

## Architecture

```
scanner
   ↓
watch baseline v2        ← private 0600 state: value sha256s + protection
   ↓                       fingerprints + assessment totals (private by design)
delta object (in memory) ← one object per run, diffed vs baseline
   ↓
terminal blocks / watch/v1 JSON   ← renders of the SAME object
```

Principle (same as assessment): **JSON contains facts. Renderer contains
language.** The terminal output and `--json` are two renders of one
in-memory delta object — never a second implementation.

## The object

```json
{
  "schema": "info-guard/watch/v1",
  "tool": {"name": "info-guard", "version": "0.4.0"},
  "watch": {
    "generated": "2026-08-20T16:53:00Z",
    "baseline_generated": "2026-08-19T16:53:00Z",
    "status": "clean"
  },
  "assessment": {
    "before": {"credential_shaped": 10, "distinct_values": 6,
               "family_attributed": 9, "unattributed": 1},
    "after":  {"credential_shaped": 10, "distinct_values": 6,
               "family_attributed": 9, "unattributed": 1}
  },
  "exposure": {
    "new_values": [],
    "resolved_values": [],
    "changed_values": [],
    "new_families": [],
    "resolved_families": [],
    "changed_files": []
  },
  "protection": {
    "status": "unchanged",
    "custom_literals": {"added": 0, "removed": 0},
    "key_patterns": {"added": 0, "removed": 0},
    "redact_patterns": {"changed": false,
                        "literal_count_before": 18,
                        "literal_count_after": 18,
                        "key_pattern_count_before": 31,
                        "key_pattern_count_after": 31},
    "mask_policy": {"changed": false}
  },
  "engine": {
    "state_before": "active", "state_after": "active",
    "version_before": "0.3.1", "version_after": "0.4.0"
  }
}
```

## Fields

### `schema`
`info-guard/watch/v1` — discriminates the watch object from the
assessment object (`info-guard/assessment/v1`).

### `tool`
`name` = `info-guard`, `version` = package version. No gitleaks field
(the assessment's `tool` carries it; watch reports deltas, not scanner
identity).

### `watch`
- `generated` — ISO-8601 UTC timestamp of THIS scan (renderer owns
  display language).
- `baseline_generated` — timestamp of the baseline this run diffed
  against; `null` on the very first run (no baseline existed).
- `status` — `"clean"` (no deltas on any track) | `"changed"` (any
  exposure/protection/engine delta). Independent of the exit code: a
  config-only change is `"changed"` with exit 0; new values or a
  degraded engine transition are `"changed"` with exit 1.

### `assessment`
Totals snapshot before/after the run (the JSON's "before" = baseline
snapshot; "after" = current scan). `before` is `null` on the first run.
Same totals vocabulary as assessment/v1: `credential_shaped`,
`distinct_values`, `family_attributed`, `unattributed`. The baseline
also stores a per-file count map, but that is **private 0600 state** —
it does not appear here; file-level facts surface only as
`exposure.changed_files`.

### `exposure`

Every value row follows one shape: `{value_masked, type, family, count}`
(2+2 masked value — mirroring the assessment's `top_values`). For
`resolved_values`, `value_masked` is `null`: the value is no longer in
the scan, and only its sha256 was ever persisted (raw values never enter
the baseline) — there is nothing left to mask. `family` is the raw
family name, or `null` for bare tokens (the terminal renders
`(no key context)`; the JSON stays machine-friendly).

- `new_values` — value sha256 not in the baseline → new exposure. **exit 1.**
- `resolved_values` — baseline value absent from the current scan.
  **Informational (exit 0).** Semantics: **"No longer detected in the
  current scan scope. This does not confirm that the credential is dead
  or revoked."** A file deletion, a move outside the scan dirs, or a
  detector-classification change all read as resolved.
- `changed_values` — present on both sides, occurrence count differs.
  Rows carry `count` (now) and `count_before`; the terminal renders
  `+N/-N`. **Informational (exit 0).**
- `new_families` / `resolved_families` — family-name rollups of the
  above (raw names, sorted, bare-token excluded).
- `changed_files` — `{file, before, after}` per file whose
  credential-shaped count changed (baseline `assessment.files` vs
  current; absent = 0).

### `protection`
Counts and fingerprints-derived deltas ONLY — **raw literals never
appear, not even masked** (guidance's explicit don't; IG D45). The
baseline stores sha256 fingerprints; diffs are set differences
(duplicates = one, order-insensitive).

- `status` — `"unchanged"` | `"changed"`.
- `custom_literals` — `{added, removed}` from the hand-edited
  `<state>/custom_literals.json` source file (per-literal fingerprint
  diff).
- `key_patterns` — `{added, removed}` from the enforcement artifact's
  key-pattern set (per-pattern fingerprint diff; baseline v2 stores the
  per-pattern list so exact counts are possible).
- `redact_patterns` — `changed` + literal/key-pattern counts
  before/after (whole-set fingerprint comparison — catches regeneration
  or reordering, which per-pattern diffs would miss).
- `mask_policy` — `{changed}` (structural compare of
  `{head, tail, floor}`).

A custom-literal add followed by `build` fires BOTH `custom_literals`
and `redact_patterns` deltas **by design**: the first confirms the
hand-edit landed in the source, the second that it landed in the
enforcement artifact (IG D50 — the duplication is deliberate).

**Wording contract (IG D50):** watch reports configuration deltas —
never effectiveness. "Protection configuration changed" is the only
claim; whether the change reduced exposure is answered by the next
preflight.

### `engine`
Transition facts: `state_before`/`state_after` (`active` | `partial` |
`none`) and `version_before`/`version_after` (null when no install
manifest). Exit-code contract (IG D47) — transitions that alert:

| Transition / event | Exit |
|---|---|
| engine `none→active` / `partial→active` | 0 |
| engine `active→partial` (degraded) | **1** |
| engine `active→none` (removed) | **1** |
| engine unchanged | 0 |
| NEW credential-shaped values | **1** |
| config-only / resolved / changed values | 0 |
| usage error | 2 |

`partial` is never ambiguous: degraded protection alerts exactly like
removal — watch is a security-monitoring command, and `check` already
exits 1 on a partial engine.

## Exit codes and `--json` modes

- `watch --json` — the object to stdout, **pure JSON, no chatter**
  (informational lines — baseline created, migration notice, version
  change, refreshed — go to stderr). Exit codes unchanged (see table).
- `watch --json-out FILE` — same object written atomically (temp +
  fsync + rename) mode **0600**; implies JSON mode; missing path =
  usage error (exit 2, message to stderr).

## Baseline v2 note

The baseline (`<state>/info-guard/watch-baseline.json`, schema
`info-guard/watch-baseline/v2`, 0600) is PRIVATE state: value sha256s
+ first_seen, the protection fingerprint snapshot, and the assessment
totals (incl. a per-file credential-shaped map, files-with-findings
only). It is migrated in place from v1 (values reconciled against the
current scan — absent values dropped; first v2 run is delta-free), and
rewritten at the end of any run that observed a delta (refresh-on-delta:
every delta alerts exactly once; clean runs leave it untouched). v1
baselines never re-alert after migration.

The baseline is not part of this public contract — consumers read
watch/v1. It lives under `<state>/info-guard/`, which is not in the
default scan set — Info Guard never scans its own artifacts.
