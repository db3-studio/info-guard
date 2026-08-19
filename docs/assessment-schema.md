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
| `key_name_mentions` | everything else that isn't masked — lines that mention a secret-sounding key, including reference/noise rows (code refs `${…}`, paths, markup; future v2 may split a 4th `reference_noise` tier) | `n_key` |
| `already_masked` | values already `***` in the source (prevention layer working) | `n_mask` |

`findings = raw_detections + key_name_mentions + already_masked`, exactly
(the partition holds over raw hits). `credential_shaped = family_attributed
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
`confirmed_active` is `null` in v1 (the scanner cannot know); a future
validation step fills `{"confirmed_active": n, "confirmed_inactive": n,
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
