# Rotation schema — `info-guard/rotate/v1`

Applies to Info Guard **v0.9.3** (rotation contract updated with the
verified-activation handshake — the vocabulary and enums below are
locked to the v0.9.1 release that introduced them).

This document defines the machine-readable rotation surface of Info Guard:
the read-only `rotate-candidates` view and the `literals rotate` registry
transaction. Rotation is an identity lifecycle — never string replacement:
retire the old identity, establish a new identity, preserve lineage, and
activate the new identity (the pattern file is rebuilt and read-back
verified — v0.9.3), exposing the resulting candidate explicitly.

All contract timestamps are ISO 8601 UTC, second precision, with a `Z`
suffix and no fractional seconds.

---

## 1. `rotate-candidates`

### 1.1 Command surface

```text
info-guard rotate-candidates [--json]
```

- No positional arguments are accepted. Any positional argument is a
  usage failure (exit 2).
- At most one `--json` is accepted; a repeated `--json` is a usage error
  (exit 2).
- A bare `--` end-of-options marker is accepted only when no token follows
  it.
- Unknown options — including output-file and transport-file options — are
  usage errors (exit 2); no file is opened and none is ever created.
- The view reads the current registry (read-only), the current scan via
  the existing detector and existing scan corpus, and the watch baseline
  (read-only and optional). It writes nothing: no registry, baseline,
  state, matcher artifact, or output file.

Exits:

| Exit | Meaning |
|---:|---|
| 0 | Successful view with no actionable rows. Idle rows may be present. |
| 1 | Successful view with at least one actionable row. |
| 2 | Usage or operational failure (registry, baseline, detector, conflict, serialization, or internal). |

`status` maps to exits identically in text and JSON modes: `clean` → 0,
`candidates` → 1, `error` → 2.

### 1.2 Response envelope

| Field | Type | Required | Meaning |
|---|---|---:|---|
| `schema` | string | yes | Exactly `info-guard/rotate/v1`. |
| `status` | string | yes | `clean`, `candidates`, or `error`. |
| `generated` | string | yes | UTC timestamp at which the response was generated. |
| `count` | integer ≥ 0 | yes | Exactly `len(rows)`. |
| `actionable` | integer ≥ 0 | yes | Number of rows whose priority is not `idle`; never greater than `count`. |
| `rows` | array | yes | Ordered row objects. Empty on an error response. |
| `error_class` | string | only when `status == "error"` | One value from the closed error-class enum. |

`status` is `clean` when `actionable == 0` (including a view containing
only idle rows), `candidates` when `actionable >= 1`, and `error` only for
a failed command.

### 1.3 Row object

| Field | Type | Required | Meaning |
|---|---|---:|---|
| `priority` | string | yes | One of `critical`, `rotate-now`, `review`, `idle`. Derived; never user-set. |
| `value_masked` | string | yes | Masked representation: values of length ≤ 10 render as `***`; longer values render as the first two characters, `...`, and the last two. Never contains the raw value. |
| `type` | string | for detected rows | Detector classification: `KNOWN`, `KEY-SHAPE`, or `TOKEN-SHAPE`. Absent, never `null`, for idle rows. |
| `family` | string | no | Detector family. Absent, never `null`, when the detector has no family attribution. Idle rows have no family. |
| `count` | integer ≥ 0 | yes | Number of exact matching occurrences in the current scan. Registered undetected rows have `0`. |
| `detected` | boolean | yes | `true` exactly when `count > 0`; `false` exactly when `count == 0`. |
| `source` | string | yes | Row origin: `literal` (registry identity), `env` (existing environment match), or `scan` (scan detection). |
| `source_key` | string | no | Alphabetically first matching environment key whenever an environment key matched. Absent, never `null`, otherwise. |
| `value_id` | string | no | Persisted registry entry id, only when the value is registered (16 lowercase hexadecimal characters). Absent, never `null`, for unregistered values. |
| `retired` | boolean | no | Present as `true` only for a retired registered entry. Absent for non-retired entries. |
| `first_seen` | string | no | First-observation timestamp from the read-only baseline. Absent, never `null`, if unavailable. |
| `last_seen` | string | no | Last-observation timestamp from the read-only baseline. Absent, never `null`, if unavailable. |

Optional fields use omission, never JSON `null`. Rows contain no raw
value and no hash.

### 1.4 Row scope and detection

The row set is the union of distinct non-canary exact values detected in
the current scan and registered non-canary entries absent from that scan.
Excluded before row construction:

- honeytoken registry entries and HONEYTOKEN detections (canaries are
  governed by remove + replant, never rotation);
- key-name-only mentions;
- already-masked-only findings;
- any finding without an exact detected value.

A registered value detected in the scan is one row, not two. Duplicate
registry entries with the same exact value and the same retirement state
retain the canonical first-wins identity rule. A value whose registry
entries have conflicting retirement state (an active and a retired entry
for the same exact value) is a `registry_conflict` and the view fails
closed with exit 2 before a row is emitted.

Detection precedence for a value is: HONEYTOKEN (excluded) → KNOWN →
KEY-SHAPE → TOKEN-SHAPE. A `KNOWN` classification, when identity is
verified by the environment detector, takes precedence over shape
classification. Registration never forces `type: "KNOWN"`.

The v0.9.1 `type` vocabulary is closed to `KNOWN`, `KEY-SHAPE`, and
`TOKEN-SHAPE`. If the internal detector returns any other non-HONEYTOKEN
classification, the view fails closed with `detector_error` rather than
emitting an unknown type or silently dropping the finding.

`family` is the family with the maximum occurrence count over ALL
occurrences of the exact value across all detection tiers; on equal
counts, the lexicographically smallest family wins. A value detected only
by the bare token prefix has no family attribution.

`source_key` is the alphabetically first matching environment key whenever
the existing environment detector matched a key, including registered rows
whose `source` remains `literal`.

### 1.5 Priority

| Priority | Condition |
|---|---|
| `critical` | `retired == true` and `detected == true`. |
| `rotate-now` | `detected == true` and identity is established by either an environment-verified `KNOWN` value or a registered non-retired entry. |
| `review` | An unregistered credential-shaped value is detected. |
| `idle` | The value is registered and not detected in the current scan. |

A retired entry that is not detected is `idle`; `critical` requires
detection.

### 1.6 Ordering

Rows are ordered deterministically by: priority rank (`critical`,
`rotate-now`, `review`, `idle`); `count` descending; `family` ascending
with absent family last; `value_masked` ascending; `value_id` ascending
where present; and the internal SHA-256 of the exact value ascending as
the final key (never emitted). Row count and order are part of the
consumer contract.

### 1.7 Text format

Default text mode emits no header and one fixed-column-order,
tab-separated line per row:

```text
priority<TAB>value_masked<TAB>type<TAB>family<TAB>count<TAB>detected<TAB>source<TAB>source_key<TAB>value_id<TAB>retired<TAB>first_seen<TAB>last_seen
```

An inapplicable optional field renders as `-`. A field whose actual value
is the literal `-` renders as `\-`. Every text field is escaped
deterministically: a literal backslash becomes `\\`; tab becomes `\t`;
newline becomes `\n`; carriage return becomes `\r`; other control
characters become `\xNN` with uppercase hexadecimal digits. Escaping is
applied to every field, including `value_masked`. A zero-row view emits
exactly zero bytes.

Text output is masked-only: it contains no raw value and no hash.

### 1.8 Failures

For every usage or operational failure the view emits no partial rows and
never reports a clean result:

- text mode: stderr carries exactly `error: <class>` and stdout is empty;
- JSON mode (when an exact `--json` token is present anywhere in argv):
  stdout carries exactly one error envelope with `status: "error"`,
  `count: 0`, `actionable: 0`, `rows: []`, and the applicable
  `error_class`; stderr is empty.

If serialization of the normal response or of the JSON error envelope
itself fails, the implementation emits no stdout, emits exactly one
fixed value-free stderr diagnostic `error: internal_error`, and exits 2.
The fallback never attempts a second serialization and never exposes
exception text, paths, or values.

### 1.9 Error classes

The v0.9.1 `error_class` enum is closed for emission:

| `error_class` | Meaning |
|---|---|
| `usage` | Invalid command syntax, malformed options, missing or extra positional arguments, or invalid end-of-options use. |
| `registry_unavailable` | Missing, unreadable, malformed, unsupported, or id-less registry that cannot be exposed read-only. |
| `registry_conflict` | Duplicate exact value with conflicting retirement state, duplicate target value, or contradictory/malformed lineage on a rotate target. |
| `baseline_unavailable` | A present baseline is unreadable or malformed. No error is emitted when the baseline is absent. |
| `detector_error` | Detector failure, scan-corpus failure, or an internal detector classification outside the closed vocabulary. |
| `internal_error` | Every other internal failure, including canonical write failure and serialization failure. Always value-free. |

Future additions are additive: consumers must remain syntactically
tolerant and preserve/report unknown security-significant values.

---

## 2. `literals rotate`

### 2.1 Command surface

```text
info-guard literals rotate <value_id> [--json]
```

- Exactly one positional `<value_id>` (16 lowercase hexadecimal
  characters). A positional replacement value is rejected.
- `--json` is accepted before or after `<value_id>`, at most once; a
  repeated `--json` is a usage error.
- `--` is the end-of-options marker; tokens after it are positional data.
- `--mask`, `--kind`, `--file`, `--json-out`, and unknown options are
  usage errors (exit 2) before any file is opened.
- The replacement value is supplied through **stdin only** — never in
  argv, never in an operator-named file.

Exits:

| Exit | Meaning |
|---:|---|
| 0 | Successful atomic rotation (old and new entries plus lineage committed). |
| 2 | Usage error or operational failure. Registry bytes remain unchanged. |

### 2.2 Stdin contract

The logical new value is decoded as strict UTF-8, read as exactly one
logical line, stripped of surrounding whitespace, and validated as
non-empty and free of embedded line terminators and other control
characters. A final LF or CRLF used as the transport line delimiter is
accepted and removed before validation. A second line, a blank line,
empty input, embedded LF/CR, invalid UTF-8, or any remaining control
character causes exit 2.

The deployment driver obtains the replacement value out of band (for
example from a vault) and pipes it to `literals rotate`. The product never
reads an operator-named transport file and never discovers or opens
deployment paths.

### 2.3 Target validation

Before any mutation the command validates, failing closed with exit 2 and
no registry write on any violation:

1. the registry is readable and supported (version 2);
2. the target id has exactly 16 lowercase hexadecimal characters;
3. exactly one target id is given;
4. the target exists and has an id (id-less entries are never rotate
   targets);
5. the target is not retired and is not a honeytoken;
6. the target's exact value is unique across the whole registry —
   no other active or retired entry may hold the same exact value;
7. the target's lineage is non-contradictory: an active target carrying
   `rotated_to`, or a target with malformed retirement metadata or
   contradictory lineage, fails closed with `registry_conflict`. A
   dangling `rotated_from` reference caused by removal of a predecessor is
   tolerated as a severed historical chain;
8. the stdin input is exactly one valid value;
9. the new value differs from the old value and from every existing
   registered value, including retired entries (old identities cannot be
   resurrected).

Rotation validates only its selected target and the target/new-value
uniqueness rules. It does not repair malformed lineage on unrelated
entries; dangling references left by entry removal are tolerated, and
unrelated entries are never rewritten.

### 2.4 The transaction

A successful rotation is one logical registry transaction and one final
canonical registry write:

1. the complete current registry is read and validated;
2. the complete candidate document is constructed in memory (including
   any required lazy id backfill for unrelated legacy id-less entries,
   committed in the same single write);
3. retire + establish + lineage are applied;
4. the candidate is validated (both exact values present, two distinct
   ids, correct bidirectional lineage, exactly one retired target
   transition);
5. the candidate is serialized;
6. the success response is fully serialized before the writer runs;
7. exactly one canonical atomic write commits the registry;
8. success is reported only after the write succeeds.

The new entry: receives a fresh random id (`secrets.token_hex(8)`, never
derived from the value, old id, hash, mask, or timestamp); receives the
supplied new value; preserves the old entry's mask style, its non-
honeytoken `kind`, and all unknown non-lineage fields; receives
`rotated_from: <old-id>` and `rotated_at: <transaction timestamp>`; and
does not inherit the old entry's retirement fields or successor pointer.

The old entry: remains in the registry; receives `retired: true`,
`retired_at`, and `rotated_to: <new-id>`; and retains its existing value,
id, mask, kind, and unknown fields. Old and new timestamps are the same
transaction timestamp.

The product has no registry lock; concurrent writers retain existing
last-writer-wins semantics. **Do not run concurrent `literals rotate`
invocations against the same registry.**

### 2.5 Success output

Text mode:

```text
rotated <old-id> -> <new-id>
```

Only ids appear; the old or new value never appears.

JSON mode (exactly four fields, no schema field, no error envelope):

```json
{
  "rotated": true,
  "old_id": "<old-id>",
  "new_id": "<new-id>",
  "value_masked": "<mask-of-the-new-value>"
}
```

`value_masked` is the only representation of the new value in the
response. In JSON mode stdout carries exactly the success object; text
output is forbidden.

### 2.6 Failures

All failures exit 2 with stdout empty and value-free stderr. Text-mode
failures emit `error: <class>` on stderr. JSON-mode failures emit **no
error envelope** — the literals family convention; the structured
`error_class` surface belongs to the read-only `rotate-candidates` view,
which is what a deployment driver consumes. Registry bytes remain
unchanged on every failure. Serialization failure also exits 2 and
remains value-free.

The `error_class` values used by `literals rotate` are a subset of the
closed enum in §1.9: `usage` (parser/grammar and stdin-shape failures,
including an unknown, retired, or honeytoken target id — invalid target
selection is a usage error, not a data conflict), `registry_unavailable`
(missing, unreadable, malformed, or unsupported registry),
`registry_conflict` (duplicate target value, duplicate target-id matches,
contradictory or malformed lineage on the selected target, or same-value
and duplicate replacement values), and `internal_error` (candidate
serialization or canonical write failure).

Consolidated `literals` exit codes (legacy surfaces unchanged):

| Subcommand | Success | Unreadable/malformed registry | Other failure |
|---|---|---|---|
| `literals add` | 0 | 1 | 1 |
| `literals list` | 0 | 0 (registry skipped) | 1 |
| `literals remove` | 0 | **1** | 1 |
| `literals rotate` | 0 | **2** (`registry_unavailable`) | 2 (`usage` / `registry_conflict` / `internal_error`) |

`literals rotate` is the only literals subcommand whose operational
failures use the closed `error_class` vocabulary on stderr (`error:
<class>`) with exit 2 and an empty stdout — the legacy subcommands retain
their historical exit behavior.

---

## 3. Registry lineage

Registry schema remains version 2:

```json
{
  "version": 2,
  "literals": []
}
```

**Registry ownership.** `custom_literals.json` is product-owned. Entries
are added, rotated, and removed through the CLI only (`literals add`,
`literals rotate`, `literals remove`); directly editing the file is
unsupported. Validation and fail-closed behavior cover the states the
product itself can produce — a hand-edited registry may not be detected
as invalid.

Lineage fields are additive per-entry fields.

| Field | Type | Meaning |
|---|---|---|
| `rotated_from` | 16 lowercase hex chars | Id of the immediately preceding identity. Present on every entry created by rotate. |
| `rotated_at` | ISO 8601 UTC string | Transaction time at which the new identity was established. |
| `retired` | boolean | `true` on entries retired by rotation. Absent (not `false`) on active entries. |
| `retired_at` | ISO 8601 UTC string | Transaction time at which the old identity was retired. |
| `rotated_to` | 16 lowercase hex chars | Id of the immediately established successor. Present on every entry retired by rotate. |

A new id never equals the old id or any active, retired, or candidate id.
Lineage is an entry history record — not a replacement pointer, hash,
external ledger, or second identity mechanism.

Retired entries remain registered, remain masked by the registry after
`info-guard build`, remain included in the next watch run's derived
protection fingerprint set, and remain detectable. They appear in
`literals list` with their masked value, id, and kind, indistinguishable
from active entries there (that list renders masked value, id, and kind
only); lineage and retirement inspection happens through
`rotate-candidates` or the registry JSON.

`literals remove <id>` remains available for retired entries. Removal
deletes only that entry, does not rewrite surviving `rotated_from` or
`rotated_to` references, and never reuses its id. Removal of a lineage
entry severs the chain; surviving references remain as historical
context, not corruption.

Worked example — a two-step rotation chain:

```json
{
  "version": 2,
  "literals": [
    {"value": "…old-value…", "id": "1111222233334444",
     "retired": true, "retired_at": "2026-08-24T00:00:00Z",
     "rotated_to": "2222333344445555"},
    {"value": "…middle-value…", "id": "2222333344445555",
     "rotated_from": "1111222233334444",
     "rotated_at": "2026-08-24T00:00:00Z",
     "retired": true, "retired_at": "2026-08-24T01:00:00Z",
     "rotated_to": "3333444455556666"},
    {"value": "…current-value…", "id": "3333444455556666",
     "rotated_from": "2222333344445555",
     "rotated_at": "2026-08-24T01:00:00Z"}
  ]
}
```

Each rotate retires its predecessor (`retired: true` + `retired_at` +
`rotated_to` = the successor id) and establishes the successor
(`rotated_from` = the retired predecessor's id + `rotated_at`). The
active tail carries no retirement fields. Removing `2222333344445555`
severs the chain: `1111222233334444.rotated_to` and
`3333444455556666.rotated_from` then dangle as historical references.

Honeytokens are never rotation targets and never appear in the rotate
view. A fired canary is an incident; canary lifecycle is remove +
replant. A honeytoken and an ordinary entry with the same exact value are
not a registry conflict: the ordinary non-canary entry supplies the row
identity.

### 3.1 Fingerprints

`custom_literals.fingerprints` is the per-literal SHA-256 list persisted
in the watch baseline's `protection` block, derived from the registry
snapshot at each watch run:

```text
sorted unique SHA-256 digests of the exact unique literal values
```

The registry document itself carries no fingerprint field. `literals
rotate` changes the registry and rebuilds the pattern file (v0.9.3
verified activation — the new value is masked immediately, read-back
verified); it performs no fingerprint or baseline write. On the next
watch run the protection snapshot contains both the retired old value
and the new value, and no stale fingerprint can remain because the list
is derived from the current registry snapshot.

---

## 4. Watch metadata

### 4.1 Protected rows

Existing `watch/v1` protected rows gain one additive field:

| Field | Type | Meaning |
|---|---|---|
| `retired` | boolean | `true` only when the detected protected value belongs to a retired registry entry. Absent, never `null`, for non-retired entries. |

All existing fields, delta rules, and exit codes are unchanged. The
`retired` field is the machine-readable old-FAILS signal; it introduces
no new exit code and no precedence change.

### 4.2 Baseline rows

The private watch baseline (schema v2) value rows gain:

| Field | Type | Meaning |
|---|---|---|
| `last_seen` | ISO 8601 UTC string | Timestamp of the latest watch run in which the exact value was present in the scan. Required for rows refreshed by a watch run; absent for legacy rows until refreshed. |

Watch continues to retain rows only for values present at the last watch
run, drop absent values, union-keep `first_seen`, and refresh `last_seen`
for values present in the current run. The rotate view only reads these
fields; it never refreshes them. An idle row can carry a historical
`last_seen` during the window after the last watch run observed the value
and before the next watch run drops it; after resolution the idle row has
no `last_seen`. If no baseline exists, both fields are omitted.

---

## 5. Deployment driver sequence

Rotation of a deployment credential is the deployment's responsibility;
the product provides the primitives. The documented sequence:

1. Run `info-guard rotate-candidates --json` and consume
   `info-guard/rotate/v1` directly.
2. Select a row by `value_id`; never join on masked values, hashes,
   families, or raw values.
3. If the selected row has no `value_id`, the value is unregistered —
   register the deployment value with `literals add` first, then re-run
   `rotate-candidates` to obtain the `value_id`. An unregistered
   environment value is not rotatable.
4. Obtain a fresh replacement value out of band (for example from a
   vault).
5. Pipe the value to `info-guard literals rotate <value_id>` — never
   place it in argv.
6. Run `info-guard build` as the explicit regeneration step. The
   matcher-regeneration step is performed with `info-guard build`;
   rotation itself does not rebuild matcher artifacts.
7. Update the deployment-owned configuration (for example `.env`)
   outside the product.
8. Verify the new deployment value and the old-value failure using
   product primitives.
9. Re-run `rotate-candidates` and/or `watch` to expose the resulting
   state.

The product does not implement or own this driver. `.env` rotation,
service-specific value replacement, verification drills, alerting, and
digests remain deployment-side.

---

## 6. Consumer obligations

Consumers of `info-guard/rotate/v1`:

1. MUST tolerate unknown object fields without treating the document as
   malformed.
2. MUST tolerate unknown row types and priority values syntactically.
3. MUST preserve/report unknown security-significant row classifications
   rather than silently dropping the row.
4. MUST treat an unknown `priority` as non-clean unless the consumer has
   an explicit safe policy.
5. MUST not reinterpret `value_masked` as an identity.
6. MUST key registry joins on `value_id`, not on masks, hashes, families,
   or values.
7. MUST treat absent optional fields as unavailable, not as `null`, empty
   identity, or a negative assertion.
8. MUST not require a baseline for parsing a valid response.
9. MUST distinguish exit 1 candidates from exit 2 operational failure.

The v0.9.1 view itself emits only the closed `type` vocabulary and the
closed `error_class` enum. An internal detector classification outside
the closed vocabulary is never emitted as a future value and never
silently discarded: the view fails closed with `detector_error`. Consumer
tolerance for unknown future values is a forward-compatibility
obligation; it does not expand v0.9.1 emission.

---

## 7. Safety guidance

- Replacement values are supplied to `literals rotate` through stdin and
  must never be placed in argv.
- Concurrent `literals rotate` invocations against one registry are
  prohibited (no registry lock; concurrent writers are last-writer-wins).
- `.env` and deployment configuration are deployment-side; the product
  never reads or writes them.
- `info-guard build` is the explicit regeneration step after rotation.
- Honeytokens are not rotation candidates.
