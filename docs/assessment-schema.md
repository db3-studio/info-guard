# Info Guard — Assessment JSON schema (`info-guard/assessment/v1`)

The machine-readable twin of the preflight report. `info-guard preflight
--json` serializes the SAME in-memory object the text report renders — the
text report is never a second implementation. `info-guard watch` diffs the
credential-shaped value set over time against a separate baseline file
(see [Preflight report format](format-spec.md)).

**Status:** shipped with v0.3.0 (2026-08-19). Friend-reviewed pre-ship
(architecture: scanner → raw findings → assessment.json → renderers).
Raw values NEVER enter this object — every value field is masked 2+2 via
the scanner's mask, or `***`.

**v0.6.0:** schema id unchanged (`info-guard/assessment/v1`);
every addition is additive per the taxonomy — `value_id` annotation on
registered KNOWN rows, KNOWN-row rules extended for env rows.
The complete envelope/versioning doctrine, exit table (0/1/2/3/4, 4
reserved), and cross-surface seams live in `docs/format-spec.md` ("Contract
foundation"); the two-part consumer obligations are stated below.

## Architecture

```
scanner
   ↓
raw findings            ← in memory; watch persists a signature subset as its baseline
   ↓
assessment.json         ← the semantic layer: facts only, no prose
   ↓
HTML / PDF / CLI        ← renderers own the language
```

Principle: **JSON contains facts. Renderer contains language.** No
generated paragraphs in the scanner beyond fact-statements.

## The object

```json
{
  "schema": "info-guard/assessment/v1",
  "tool": {
    "name": "info-guard", "version": "0.3.0", "gitleaks": "8.30.1",
    "installed": true,
    "engine_state": "active",
    "engine_version": "0.3.0"
  },
  "scan": {
    "generated": "2026-08-18T23:48:00Z",
    "dirs": ["sessions", "logs", "cron"],
    "files_scanned": 7209,
    "read_only": true,
    "gitleaks_ok": true
  },
  "status": {
    "severity": "high",
    "action_required": true,
    "summary": "Credential-shaped values were found at rest.",
    "credential_shaped": 159,
    "confirmed_active": null
  },
  "totals": {
    "findings": 38639,
    "credential_shaped": 159,
    "raw_detections": 168,
    "distinct_values": 42,
    "family_attributed": 56,
    "unattributed": 103,
    "key_name_mentions": 38480,
    "already_masked": 512,
    "partition": true
  },
  "families": {
    "total_with_values": 6,
    "complete": true,
    "items": [
      {
        "family": "HASS_TOKEN",
        "value_findings": 26,
        "masked_findings": 0,
        "key_name_mentions": 390,
        "evidence": ["JWT-shaped"],
        "status": "exposed",
        "priority": "high",
        "distinct_values": 1,
        "example": { "value_masked": "eyJh...A5g", "file": "sessions/…jsonl", "line": 93 }
      },
      {
        "family": "FIRECRAWL_API_KEY",
        "value_findings": 0,
        "masked_findings": 166,
        "key_name_mentions": 166,
        "status": "protected",
        "priority": "protected"
      }
    ]
  },
  "locations": [
    {
      "area": "sessions",
      "credential_shaped": 145,
      "masked": 12,
      "status": "mixed",
      "percentage": 91.2,
      "files_affected": 12,
      "date_range": { "source": "session_timestamp", "start": "2026-04-24", "end": "2026-05-10" }
    }
  ],
  "patterns": [
    {
      "type": "historical_concentration",
      "severity": "info",
      "confidence": "moderate",
      "summary": "Candidates are concentrated in historical session transcripts.",
      "areas": ["sessions"],
      "date_range": { "source": "session_timestamp", "start": "2026-04-24", "end": "2026-05-10" }
    }
  ],
  "redaction": [
    { "scope_type": "family", "scope": "FIRECRAWL_API_KEY", "status": "protected", "note": "Most occurrences were already masked." },
    { "scope_type": "area", "scope": "logs/agent.log", "status": "mostly_masked", "note": "Redactor handled hits in place." },
    { "scope_type": "family", "scope": "HASS_TOKEN", "status": "exposed", "note": "JWT-shaped values remain at rest." }
  ],
  "top_values": [
    { "value_masked": "eyJh...A5g", "type": "JWT", "family": "HASS_TOKEN", "count": 43 }
  ],
  "affected_files": [
    { "file": "sessions/…json", "total_findings": 208, "credential_shaped": 17, "key_name_mentions": 191 }
  ],
  "recommendations": [
    { "priority": "high", "title": "Rotate active credentials",
      "detail": "Verify whether credential-shaped candidates are still active and rotate those that are." }
  ],
  "appendix": { "telemetry": [ { "key": "Authorization", "mentions": 4172 } ] }
}
```

Family items additionally carry `areas`, `dates`, `types` and (when a
value is shared across families) `shared_with` — the renderer's dagger
footnotes. `top_values` items may carry a `families` list (all families
the value appeared under). Extra keys are additive; consumers should
ignore unknown fields.

## Definitions (the exactness contract)

**Taxonomy — a partition, not overlapping categories.** `totals.partition: true`
means every raw hit is classified into exactly one of:

| Key | Meaning | Code bucket |
|---|---|---|
| `raw_detections` | credential-shaped HITS: token-format values + gitleaks HIGH-CONFIDENCE, before dedup | `n_tok + n_gl` |
| `credential_shaped` | the canonical candidate count: one per unique `file:line:value` ROW (duplicate detector fires collapsed) — the headline; family, location and affected-file tables all sum to it | deduped |
| `distinct_values` | the rotate list: distinct credential-shaped values across the scan | value-dedup |
| `known` | distinct KNOWN `.env` values (v0.5.0 — identity-verified, the new tier) | value-dedup |
| `known_rows` | distinct KNOWN rows (v0.5.0 — `file:line:value` level; `known ≤ known_rows`, the partition reconciliation) | deduped |
| `honeytoken` | distinct canary values matched (v0.7.0 — a registered `kind: honeytoken` value found at rest = canary-touch; the TOP tier, wins over every class below) | value-dedup |
| `honeytoken_rows` | distinct HONEYTOKEN rows (v0.7.0 — `file:line:value` level; `honeytoken ≤ honeytoken_rows`) | deduped |
| `key_name_mentions` | everything else that isn't masked — lines that mention a secret-sounding key, including reference/noise rows (code refs `${…}`, paths, markup; future v2 may split a 4th `reference_noise` tier) | `n_key` |
| `already_masked` | values already `***` in the source (prevention layer working) | `n_mask` |

`findings = honeytoken + known + raw_detections + key_name_mentions + already_masked`, exactly
(the partition holds over raw hits at ROW level — each `file:line:value`
row is exactly one tier; `known` is the distinct-value rollup of the KNOWN
rows, so `known ≤ known_rows`; same for `honeytoken ≤ honeytoken_rows`).
`credential_shaped = family_attributed
+ unattributed` in the common case — `family_attributed` = credential-shaped
values tied to a known secret family (key name on the hit line, or a
gitleaks RuleID); `unattributed` = generic token-shaped values with no key
context (the `bare-token` bucket). Verified against live code.

**Per-family counts:** `value_findings` = distinct (file:line:value) rows
carrying a real value at rest; `masked_findings` = distinct rows already
masked; `key_name_mentions` = all hit rows mentioning the family (incl.
duplicates). `status` = the redaction status (`exposed` = real values, none
masked; `mixed` = both; `protected` = masked-only) — the merged report table
sorts by it. `distinct_values` = distinct credential-shaped values attributed
to the family (the report shows "+N more" when > 1). `families.complete`
defaults to `true` — the scan computes exact counts in memory; caps apply at
render time, and renderers must surface them ("top 15 of N").

**`status.severity`:** `none | low | medium | high` (none = clean).
`confirmed_active` is `null` by default (the scanner cannot know
activeness); v0.5.0 activates it in place: `true` when ≥1 KNOWN `.env`
row exists, `null` otherwise. `null` deliberately covers BOTH "KNOWN
pass disabled" (no usable `.env` sources) and "pass active, no match" —
the two are not distinguished (documented; the text report's
disabled line is the human-facing distinction). **v0.6.0 semantics:**
`null` = pass disabled or no identity-verified matches;
`true` = ≥1 identity-verified KNOWN value; **`false` is NOT emitted by
v0.6.0 — no output path produces it, and an unexpected `false` MUST be
handled as `null` under preserve/report behavior**. It is NOT live
credential validation. A future validation step may fill
`{"confirmed_active": n, "confirmed_inactive": n,
"unverified": n}` without a schema change.

**`locations[].percentage`** is a stored derived fact (`credential_shaped / Σ`),
kept for renderer convenience. `locations[].masked` = masked occurrences in
the area; `locations[].status` (`exposed | mixed | mostly_masked |
protected`) — masked is the share of the area's *candidates* already
redacted (all → protected, ≥ half → mostly_masked, some → mixed, none →
exposed; no candidates → protected when any masked rows exist).

**Date discipline:** `date_range.source` is `session_timestamp` (parsed from
`session_YYYYMMDD…` filenames — the honest "when the session ran" evidence)
or `mtime` (filesystem modification time). Never label an mtime-derived
range as an exposure date; renderers may only say "from session timestamps"
when that source is used.

**`patterns`** are fact-structures, not prose, with a `confidence` field
(`low | moderate | high`) so renderers can qualify language. Renderers
compose sentences from `summary + areas + date_range`; the qualified form
("consistent with retained historical exposure rather than a current logging
failure") is renderer language, only permitted at `confidence >= moderate`.
New pattern types can be added without schema churn.

**`redaction[].status`** vocabulary (v1):
`protected | mostly_masked | mixed | exposed`, plus reserved-for-future
`not_detected | unknown`. `scope_type` is `family | area` — a scope may be a
key family or a file/area (e.g. `logs/agent.log`).

**`top_values[].family`** is nullable — only set when the scanner can
attribute the value to a family; `value_masked` is the scanner's actual 2+2
mask, never re-formatted.

**KNOWN rows (v0.5.0; env-row rules v0.6.0):**
a KNOWN row is identity-verified — the value matches a current eligible
`.env` source value. Row rules, enforced across every row-bearing path
(`top_values[]`, `families.items[]`, `locations[]`, `affected_files[]`):
- KNOWN rows REQUIRE `known: true` and a non-empty `source_key` (the
  alphabetically-first env key across sources) and carry
  `type: "KNOWN"` in `top_values`; `count` = occurrences (per-occurrence,
  incl. same-line repeats).
- `known == (type == "KNOWN")` — `type` is the authoritative finding-class
  field; `known` is a derived convenience flag, false for every future tier
  (e.g. a HONEYTOKEN row).
- non-KNOWN rows MUST NOT carry `known`/`source_key` — absent, never null.
- `value_id` (v0.6.0): KNOWN rows carry `value_id` **iff** the
  value is registry-registered (lookup at row-build time) — absent, never
  null. The annotation never affects matching or counts (see the consumer
  obligations below).
- `families.items[].known`, `locations[].known`, `affected_files[].known`
  are additive per-path KNOWN-row counts (0 or more; `known` is a
  distinct-VALUE count at the totals level, a ROW count at path level).
- The KNOWN tier wins a `file:line:value` row over shape detectors
  (identity beats shape-guess; the dropped shape row is never counted as
  credential-shaped).

**HONEYTOKEN rows (v0.7.0 — the top tier):** a canary row is
identity-verified by construction — the value is a registered
`kind: honeytoken` entry matched exactly in the scan (canary-touch
detection fact, never "leak"/"confirmed"). Row rules:
- HONEYTOKEN rows carry `type: "HONEYTOKEN"`, `known: false` (the
  derived flag is false for every future tier — the shipped contract),
  and `value_id` (the canary's registry id — always present, canaries
  are registered by construction); `count` = occurrences; `family` is
  `null` (unattributed, the existing nullable contract).
- `source_key` is present ONLY when the canary is also a live `.env`
  value (both facts reported; the tier still wins).
- The HONEYTOKEN tier wins a `file:line:value` row over KNOWN,
  credential-shaped, key-name-mention, and already-masked classes — one
  row per `file:line:value`, never a second tier row. `totals`
  adds `honeytoken` (distinct values) and `honeytoken_rows` (rows);
  `status.severity` is `high`; exit 4 (see format-spec §Exit contract).
- `families.items[].known`, `locations[].known`, `affected_files[].known`
  include canary rows (registered values share the "known" path column —
  the type field disambiguates); `types` lists `HONEYTOKEN`.

**Masking discipline:** every value in the assessment is masked
(`value_masked`) — raw values never enter the JSON. The watch baseline
(raw-findings layer) stores signatures with `value_sha256` only, 0600 state
file.

## Emit contract

- `info-guard preflight --json [DIR ...]` — assessment object to stdout,
  pretty-printed, deterministic key order. No chatter on stdout (the
  object's `tool` block carries engine state). Exit codes unchanged:
  0 = clean, 1 = findings, 2 = usage error.
- `info-guard preflight --json-out FILE [DIR ...]` — atomic write (temp +
  fsync + rename), mode 0600. Implies JSON mode.
- `info-guard watch [DIR ...]` — same scan, diffs the credential-shaped
  distinct-value set (sha256) against `<state>/info-guard/watch-baseline.json`
  (schema `info-guard/watch-baseline/v1`, 0600). First run (or `--reset`)
  creates the baseline, exit 0; no new values → one-line status, exit 0;
  new values → masked NEW VALUES block + baseline update, exit 1. On
  tool/gitleaks version change the baseline is union-kept (known values
  never re-alert) with a notice.
- `scan.generated` is ISO-8601 UTC; the text renderer reformats for display
  (renderer owns language).

## Consumer obligations (v0.6.0)

Schema `info-guard/assessment/v1` is unchanged in v0.6.0 — every v0.6.0
addition is additive. The complete envelope/versioning doctrine, nullable
field list, exit table, and cross-surface seams live in `docs/format-spec.md`
("Contract foundation").

**Two-part forward-compatibility contract:**

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
| `delta` (watch transition) | tolerate + **preserve/report** |
| `source` (`env` \| `literal`, future values) | tolerate + ignore |
| registry mask-style names | tolerate + ignore |
| unknown finding-row types (`top_values[]`, `families.items[]`, `locations[]`, `affected_files[]`) | tolerate + **preserve/report** |
| unknown metadata-row types (`patterns[]`, `redaction[]`, …) | tolerate + ignore |

**Row-bearing paths:** the KNOWN-row rules are enforced across every
row-bearing path — `top_values[]`, `families.items[]`, `locations[]`,
`affected_files[]`. Every path rejects: KNOWN without a non-empty
`source_key`; non-KNOWN rows carrying `known`/`source_key`; optional
annotation fields set to `null`; any field outside the nullable list
(`family`, `resolved_values[].value_masked`, `status.confirmed_active`)
emitted as `null`.

**`value_id` annotation (v0.6.0):** read-only, annotation-only
lookup at row-build time — it NEVER affects matching, counts, or
classification. `value_id` appears on a KNOWN row iff the value is
registry-registered; absent, never null. Registry membership itself IS a
classification input by design (`literal` source, protected overlay,
collision precedence) — the annotation is the only thing that must not
change behavior. Example KNOWN row (registered value — row excerpt):

```json
{"value_masked": "se...7x", "type": "KNOWN", "family": "UNIFI_SSH",
 "count": 1, "families": ["UNIFI_SSH"], "known": true,
 "source_key": "UNIFI_SSH", "value_id": "a1b2c3d4e5f60718"}
```

## Text ↔ JSON vocabulary

| Text (report) | JSON (v0.3.0) |
|---|---|
| credential-shaped candidates | `credential_shaped` |
| findings (raw total) | `findings` |
| families with value-shaped material | `families.items[]` with `value_findings > 0` |
| already masked | `already_masked` / `masked_findings` |
| key-name mentions (NOT findings) | `key_name_mentions` |
| Pattern: … | rendered from `patterns[]` |

The text report keeps "credential-shaped candidates" / "candidates, not
confirmed leaks" language; the JSON keys are the machine twin of the same
concepts. No divergence — one vocabulary, two surfaces.
