# Info Guard — Watch JSON schema (`info-guard/watch/v1`)

The machine-readable result of `info-guard watch` — the **public delta
result**. Where
[assessment.json](assessment-schema.md) is the preflight point-in-time
snapshot, watch/v1 is the change report: what differs between the
baseline snapshot and the current scan, across three tracks — exposure
(values), protection configuration (fingerprints/counts), and engine
state (transitions).

**Status:** shipped with v0.4.0 (2026-08-20); **`exposure.protected_values`
added v0.4.1 (2026-08-20)** — additive only, schema stays
`watch/v1`. Independent AI plan review
amended the row shape pre-build: exposure rows carry
`value_masked` (2+2) — **`value_sha256` is FORBIDDEN in this object**
(the private 0600 baseline keeps sha256; this is the public surface, and
sha256 of low-entropy values is brute-forceable). **`value_id` added
v0.4.2 (2026-08-20)** — additive opaque registration ids on
protected rows (protected_values + the overlaid new/changed rows), so
consumers can join an alert to the exact `custom_literals.json` entry.
**v0.6.0:** additive — watch runs the `.env` pass;
env-matched rows gain `source` + `source_key`; `value_id` extends to env
rows (present iff registry-registered, absent never null); the full
transition table T1–T8 (incl. T3b detection-loss and T8 config-only) is
normative; schema stays `watch/v1`. See the v0.6.0 section below.

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
  "tool": {"name": "info-guard", "version": "0.6.0"},
  "watch": {
    "generated": "2026-08-20T16:53:00Z",
    "baseline_generated": "2026-08-19T16:53:00Z",
    "status": "changed"
  },
  "assessment": {
    "before": {"credential_shaped": 10, "distinct_values": 6,
               "family_attributed": 9, "unattributed": 1},
    "after":  {"credential_shaped": 10, "distinct_values": 6,
               "family_attributed": 9, "unattributed": 1}
  },
  "exposure": {
    "new_values": [
      {"value_masked": "se...7x", "type": "KNOWN", "family": "UNIFI_SSH",
       "count": 3, "source": "env", "source_key": "UNIFI_SSH"},
      {"value_masked": "eyJh...A5g", "type": "JWT", "family": "HASS_TOKEN",
       "count": 1}
    ],
    "resolved_values": [
      {"value_masked": null, "type": "KNOWN", "family": "UNIFI_SSH",
       "count": 0, "first_seen": "2026-08-19T16:53:00Z"}
    ],
    "changed_values": [
      {"value_masked": "pa...x2", "type": "KNOWN", "family": "AGH_PIN",
       "count": 5, "count_before": 2, "source": "literal",
       "source_key": "AGH_PIN", "value_id": "3f2a91c4e8b6d705"}
    ],
    "new_families": ["HASS_TOKEN"],
    "resolved_families": [],
    "changed_files": [],
    "protected_values": [
      {"value_masked": "pa...x2", "type": "KNOWN", "family": "AGH_PIN",
       "count": 5, "count_before": 2, "delta": "increased",
       "source": "literal", "source_key": "AGH_PIN",
       "value_id": "3f2a91c4e8b6d705"},
      {"value_masked": "ht...0e", "type": "HONEYTOKEN", "family": null,
       "count": 1, "delta": "new", "source": "literal",
       "value_id": "7c1d9e2f3a4b5c6d"}
    ],
    "review_list": [
      {"value_masked": "6f...8c", "type": "SUSPICIOUS",
       "family": "generic-api-key", "count": 1}
    ],
    "review_list_complete": true
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
    "version_before": "0.4.2", "version_after": "0.6.0"
  }
}
```

The `new_values[]` row is a pure env match (`source: "env"` + `source_key`,
no `value_id` — unregistered). The `changed_values[]` / `protected_values[]`
rows show the collision case: the value is in `.env` as `AGH_PIN` AND
registry-registered — `source: "literal"` wins precedence (P-C), yet
`source_key` is still present (present iff env-matched, regardless of who
won precedence), and both rows carry the same `value_id` (one event, one id).

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
the baseline) — there is nothing left to mask. Resolved rows additionally
carry `first_seen` (the baseline's first-seen timestamp for that value —
date-only, no leak surface). `family` is the raw
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
  `+N/-N`. **Informational (exit 0)** — applies to **non-protected**
  changed values; protected rows are overlaid (below).
- `protected_values` — **(v0.4.1, additive)** the
  protected-value overlay: every current-scan value whose exact sha256
  matches a `custom_literals.json` fingerprint (the app's known-value
  registry). Row shape `{value_masked (2+2), type, family, count,
  count_before? (increased/decreased only), delta ∈ {new, increased,
  decreased, unchanged}, value_id (v0.4.2)}` — **never sha256** (same
  surface rule as every exposure row). `new`/`increased` → **exit 1** (or **exit 4** for a `HONEYTOKEN` row —
 canary-touch);
 `decreased`/`unchanged` → informational (exit 0). A value absent from
 the scan never appears here — it surfaces via `resolved_values`
 (which **never carries a `value_id`** — a resolved row is not
 registry-joinable; a consumer cannot build a "protected value stopped
 appearing" join). Present on every run (empty array when the registry
 is empty or nothing matches; first-run and migration emits are empty —
 the next run reports). **Overlay rule:** a protected value also
 appears in `new_values`/`changed_values` — that is ONE event; the
 terminal renders it once (PROTECTED block only).
 Vocabulary: **protected value** = user-declared via the registry ·
 **detection** = appeared in scan · **increased** = more occurrences
 than baseline · **confirmed leak** = never claimed by watch. Matching
 is exact-value and limited to the credential-shaped scan domain (a
 PII-only literal never matches, by design).

 **HONEYTOKEN rows (v0.7.0):** a canary (`kind: honeytoken`)
 in the scan serializes ONLY here in `protected_values[]` — never in
 `new_values[]`/`changed_values[]`/`resolved_values[]` (one event).
 Row shape as above with `type: "HONEYTOKEN"` + `value_id` (the
 canary's registry id — always present, canaries are registered by
 construction). `delta: "new"|"increased"` → **exit 4** (dominates 1);
 baselined-present `delta: "unchanged"` → exit 0; absent → no row
 (absent canaries are absent, never resolved). A canary that is also a
 live `.env` value is still `HONEYTOKEN` and carries `source_key`.

 ### `review_list` (v0.7.0, additive)

 Report-only SUSPICIOUS surface: ALL current-scan gitleaks
 `generic-api-key` rows (the SUSPICIOUS tier), deduped by value with
 `count` = current-scan occurrences. Row shape mirrors `new_values[]`
 (`value_masked` 2+2, `type: "SUSPICIOUS"`, `family`, `count`) — never
 sha256. **Never raises the exit** (findings listed,
 never alerted; the deployment may review/alert at its discretion).
 Values represented by a HONEYTOKEN row are EXCLUDED (one event). Not
 delta-filtered, not baseline-filtered — unchanged rows remain present
 run-to-run.

 ### `review_list_complete` (v0.7.0, additive)

 `true` when the gitleaks engine produced a full SUSPICIOUS result;
 `false` when the engine is unavailable or degraded, so an empty
 `review_list` can never be misread as "no suspicious rows" while the
 engine produced nothing. Consumers MUST gate review-list interpretation
 on this flag + the engine state. Present on every watch run; never
 emitted by preflight.

### `value_id` (v0.4.2, additive)

An opaque 16-hex random identifier assigned to each `custom_literals.json`
entry at registration (registry v2 — `{"version": 2, "literals":
[{"value", "mask"?, "id"}]}`). On machine surfaces it appears on
protected rows only:

- `exposure.protected_values[]` — every row carries the matched entry's
  `value_id`.
- `exposure.new_values[]` / `exposure.changed_values[]` — the overlaid
  protected row carries the **SAME** `value_id` (one event, one id);
  unregistered rows have **no `value_id` key at all** (absent,
  never null).

**Definition:** `value_id` is a stable opaque identifier for a
**registered literal entry**, not for the literal value itself. The
stability contract is *same persisted registry entry → same ID* — across
runs, rebuilds, file moves, and literal reorder. Deleting and re-adding
a value is a NEW registration and gets a NEW id. Duplicates collapse by
value (set semantics — one registration per unique value), so in
practice one value = one id.

**Join path:** `value_id` ↔ the matching entry in
`<state>/info-guard/custom_literals.json` (0600, same user — the
consumer's registry lookup is a plain file read; no pepper, no crypto).

**Not a security token, not a leak verdict:** the id proves *which
registered value matched* — it is not a credential, not a hash of one,
and watch never claims a leak (leak vocabulary unchanged). The terminal,
the baseline, error paths, and debug output never carry `value_id`
(surface rule); raw values and sha256 stay off every surface.

**Env-row rules (v0.6.0):**
- `value_id` appears on env-matched rows (`new_values[]`,
  `changed_values[]`, `protected_values[]`) **iff** the value is
  registry-registered — **unregistered env rows have no `value_id`**
  (absent, never null).
- `resolved_values[]` never carries a `value_id` (v0.4.2 contract,
  unchanged — a resolved row is not registry-joinable).
- On a collision (env-matched AND registered), the overlay row and the
  `protected_values[]` row carry the **same** `value_id` — one event, one
  id; consumers dedup across arrays by `value_id` when present,
  else `value_masked`.
- IDs are CSPRNG-generated and independent of the value (no hash,
  truncation, or keyed derivation) and locally scoped per
  installation; v0.6.0 emits no installation identifier.
- `new_families` / `resolved_families` — family-name rollups of the
  above (raw names, sorted, bare-token excluded).
- `changed_files` — `{file, before, after}` per file whose
  credential-shaped count changed (baseline `assessment.files` vs
  current; absent = 0).

### `protection`
Counts and fingerprints-derived deltas ONLY — **raw literals never
appear, not even masked** (guidance's explicit don't). The
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
enforcement artifact (the duplication is deliberate).

**Wording contract:** watch reports configuration deltas —
never effectiveness. "Protection configuration changed" is the only
claim; whether the change reduced exposure is answered by the next
preflight.

### `engine`
Transition facts: `state_before`/`state_after` (`active` | `partial` |
`none`) and `version_before`/`version_after` (null when no install
manifest). Exit-code contract — transitions that alert:

| Transition / event | Exit |
|---|---|
| engine `none→active` / `partial→active` | 0 |
| engine `active→partial` (degraded) | **1** |
| engine `active→none` (removed) | **1** |
| engine unchanged | 0 |
| NEW credential-shaped values | **1** |
| protected value `new` / `increased` | **1** |
| config-only / resolved / non-protected changed values | 0 |
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

## v0.6.0 — `.env` match source and transitions

Watch runs the same `.env` pass as preflight (v0.6.0). The env set is a
**match source, not tracked state** — classification is per-run; the
baseline keeps `{value_sha256, type, family, count, first_seen}` only and
records **no `source` field** (no historical `.env`-match claim is ever
made). `family` for env-matched rows is derived from the match rule's key
name and IS persisted in baseline rows — that is provenance, not a claim.

### `source`, `source_key`, `value_id` semantics

Additive row fields on `new_values[]`, `changed_values[]`,
`protected_values[]`:

- `source` — the **precedence winner**: `"env"` (per-run `.env` index) or
  `"literal"` (registry); never `"both"`. **Literal wins (P-C)** — the
  registry is the authoritative declaration; on a collision both
  annotations are still carried, so no information is lost.
- `source_key` — the env key of the `known-env` match; **present iff an env
  match exists, regardless of who won precedence** — a `source: "literal"`
  row may still carry `source_key` (both-match rows carry both); consumers
  must not read `source == "literal"` as "no .env match". Alphabetically
  first key when a value maps to several (v0.5.0 A11 semantics). Absent,
  never null.
- `value_id` — present iff registry-registered; absent never null;
  `resolved_values[]` never carries one (see the value_id section).

### Transition table T1–T8

All transitions are per value hash; the counts machine is preserved.

| # | Transition | Definition | Event / exit |
|---|---|---|---|
| T1 | **added** | value not in baseline, detected in scan (any source) | `new_values[]` → **exit 1**; env-matched rows carry `source: "env"` + `source_key` |
| T2 | **removed** (from scan) | in baseline, absent from current scan | `resolved_values[]` (resolved-value wording) → exit 0 |
| T3 | **`.env`-leave** | value has no env match in the CURRENT run's index | current-run reclassification, **no event, no exit change**: row stays (still in scan), carries no `source_key`/env classification → shape (if unregistered) or `literal` (if registered — registry membership is unaffected by `.env` removal). If it also left the scan → T2. Per-run hashing → no `--reset` needed on `.env` edits |
| T3b | **detection loss** | `.env`-leave of a value detectable ONLY via the env pass (no shape qualification, unregistered) — still in scan, but no longer detectable by any pass | `resolved_values[]` with the resolved-value wording applied literally — reads as remediation, but the cause is loss of detection capability, not removal of exposure → exit 0 |
| T4 | **replaced** (same key, new value) | env key K: old value absent from the current index, new value present | old value → T3 current-run path (T4 emits no event for the old value); new value → T1 if detected in scan (exit 1). If the replacing value is ALSO registry-registered → T1 row carrying both `source_key` + `value_id` |
| T5 | **duplicated** | same value under 2+ env keys, or new scan locations | 2+ keys → ONE row, `source_key` = alphabetically-first key; new locations → count increase → `increased` → **exit 1** |
| T6 | **moved** | value moves files, total count unchanged | `unchanged` → exit 0 |
| T7 | **increased / decreased** | count change vs baseline | increased → **exit 1**; decreased → exit 0 |
| T8 | **config-only** | registry-membership change with unchanged scan state — e.g. self-fill registers an already-baselined value; count/scan presence unchanged | `protected_values[]` appearance with `delta: "unchanged"`; **no `new_values[]` row, no exit raise (exit 0)** — the value was already at rest and already in the scan; registration changes only its classification/overlay membership |

**Collision / overlay (one-event rule):** a value that is env-matched
AND registered appears once in `protected_values[]` (delta per the counts machine) and
once in the overlay (`new_values[]`/`changed_values[]`) — same `value_id`
on both, ONE event; `pm_alarm` (delta new/increased) → exit 1 unchanged.
"One row, never two" means one row per array — consumers dedup across
arrays by `value_id` when present, else `value_masked`.

**`.env`-leave wording (informational, exit 0):** "No longer
detected in the current scan scope. This does not confirm that the
credential is dead or revoked." T3 itself emits no event — the wording
applies to T2/T3b `resolved_values[]` rows.

### Watch exit contract (v0.6.0)

Usage or operational failure → **2**; else ANY of `new_values`, increased
exposure count (T5/T7), engine degradation, new/increased protected alarm
→ **1**; else **0**. Non-alarming transitions (resolved, decreased,
unchanged, config-only (T8), T3/T3b reclassification) never raise the exit.
Watch keeps 0/1/2 — the ladder's 3 (KNOWN present, at-rest verdict) is
preflight-only (P-F). Exit 4 is reserved and never emitted. JSON emission:
`--json` stdout stays pure JSON on 0/1; on an operational failure (exit 2)
the delta object is still emitted with the engine state carried in
`engine.state_after` — the exit code, not the absence of JSON, is the
operational signal (v0.5.1 behavior retained). Full doctrine:
`docs/format-spec.md` ("Contract foundation").

### Mandatory first-run upgrade re-baseline (v0.5.x → v0.6.0)

v0.5.x baselines were written with shape-qualified values only; v0.6.0's
env inclusion means previously-excluded env-matched values satisfy T1 on
the first run against an old baseline — a false `new_values` alarm storm
(exit 1 for every existing watch user on upgrade). **The first v0.6.0 watch
run against a v0.5.x baseline MUST re-baseline** — documented remediation:
reset/delete the baseline, then re-run; the pre-rebaseline alarm is
expected, and subsequent runs are quiet. The baseline file schema itself is
unchanged — the population change is the semantic change.

## Consumer obligations (v0.6.0)

Two-part forward-compatibility contract, mandatory for
watch/v1 consumers:

1. **Syntactic tolerance** — unknown fields, row types, and enum values
   MUST NOT cause parsing failure or be treated as malformed input.
2. **Semantic handling** — each enum field and row-type family declares its
   unknown-value behavior below. Security-significant unknown values MUST be
   preserved and reported while remaining masked — at minimum retain the
   complete masked row, the unknown discriminator value, and route the row
   through the normal findings/reporting path.

**Schema-string parsing:** parse the surface and major from
`info-guard/<surface>/v<major>[.<minor>]`; never compare the full string
literally. Unknown major MAY be rejected; unknown minor MUST be accepted.

Unknown-value behavior at v0.6.0:

| Field / family | Required behavior |
|---|---|
| `type` (finding-class tier: KNOWN, JWT, …) | tolerate + **preserve/report** |
| `delta` (watch transition: new/increased/…) | tolerate + **preserve/report** |
| `source` (`env` \| `literal`, future values) | tolerate + ignore |
| registry mask-style names | tolerate + ignore |
| unknown finding-row types (`new_values[]`, `changed_values[]`, `protected_values[]`, `resolved_values[]`, …) | tolerate + **preserve/report** |
| unknown metadata-row types | tolerate + ignore |

Additive-only evolution is the producer side of the same contract — no
field is removed, retyped, made required, or semantically redefined
without a major bump and the packaged-contract-change rule. Cross-surface seams (value_id
monomorphism, tier-enum growth, exit-4 reservation, additive-only schema
evolution) are declared in `docs/format-spec.md`.
