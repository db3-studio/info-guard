# Info Guard — pattern file format (v1)

The pattern file is the **single interface** between your secrets and Hermes'
redaction engine. Hermes reads it at every message boundary (tool output,
logs, transcripts, file reads) and masks anything it contains. The file is
plain JSON — you can generate it with `bin/info-guard build`, edit it by
hand, or have your agent maintain it.

## Location & precedence

1. `security.redact_patterns` in `~/.hermes/config.yaml` (set by `install.sh`)
2. `$HERMES_REDACT_PATTERNS` environment variable
3. Code default: `$HERMES_HOME/state/info-guard/redact_patterns.json`
   (fallback `~/.hermes/...`) — one file **per Hermes instance**, so every
   profile gets its own redaction set automatically.

Pattern-file *content* changes apply immediately (mtime-cached, proven).
Path *changes* apply at the next process start.

## Top-level shape

```json
{
  "mask": {"head": 2, "tail": 2, "floor": 12},
  "literals": ["exact-value", {"value": "...", "mask": "full"}],
  "key_patterns": {"PIN": true, "MY_CUSTOM_SECRET": true},
  "generated": "2026-08-16T17:40:00+00:00"
}
```

All sections optional. A missing or unreadable file is a **no-op** — the
built-in redactor keeps running; nothing ever crashes because of this file.

## Sections

### `mask` — the default masking style

Length-driven partial masking, applied to every literal without its own
override:

| Field | Default | Meaning |
|---|---|---|
| `head` | `2` | visible leading characters |
| `tail` | `2` | visible trailing characters |
| `floor` | `12` | values shorter than this are fully masked (`***`) |

Rationale for the defaults: keeps the built-in redactor's invariant that at
least 8 characters are always hidden, while values like phone numbers (12
chars) and short emails stay partially visible for troubleshooting. Values
≤ 10 chars (PINs) are fully masked by default.

### `literals` — exact-value masking

Each entry is either a plain string (use the default mask) or an object:

```json
{"value": "super-sensitive-value", "mask": "full"}
```

`mask` accepts `"full"` (nothing visible) or a custom object
`{"head": 3, "tail": 1, "floor": 8}`. Anything unknown falls back to the
safe default — never an unmask, never a crash.

Matching notes:

- Longest literals match first, so overlapping values mask deterministically.
- Built-in keyword families (`KEY=value` with `PASS`/`TOKEN`/`SECRET`/... in
  the key) are masked by Hermes even without this file — Info Guard adds
  **your exact values** and your **custom keys**.
- Values are matched as exact strings (never substring patterns) — this is
  the precision property that keeps over-redaction near zero.

### `key_patterns` — key-aware masking

`{"KEY_NAME": true}` masks the value of that key in `KEY=value`,
`KEY: value`, and JSON `"KEY": "value"` forms — **regardless of value
length**. This covers the class of short secrets (`PIN`, `x_passphrase`)
that exact-value matching can't safely touch.

`info-guard build` populates this from your `.env` files (every secret-shaped
key) plus a curated built-in list (`PIN`, `WEBUI_PIN`,
`HERMES_WEBUI_PASSWORD`, `x_passphrase`, `client_secret`, `refresh_token`,
`access_token`, `dns_provider_credentials`). Non-secret keys — hosts, URLs,
usernames, emails, ports, flags, schedules, model configs — are excluded:
masking those values was pure information loss.

## Safety properties

- **Fail-safe**: missing/broken/unreadable file = no-op; a broken file keeps
  the last-good pattern set active (no unmasked gap) and auto-recovers when
  repaired.
- **Sentinel on file reads**: values redacted from file *content* are
  replaced with a non-reusable sentinel, so a masked value can never be
  written back over the real file. Tool output and logs get partial or full
  masking instead.
- **Display-only**: masking can never modify your `.env` files, vault, or
  config — it is a read-time transform.
- **Per-instance**: the default path resolves under `$HERMES_HOME`, so
  profiles and relocated installs each get their own file (no cross-instance
  leakage, no silent no-op under a remapped home).
- **Boundary (honest)**: the pattern file is *inside* the agent's trust
  envelope — 0600 protects it from other OS users; nothing in-process can
  protect it from the agent itself (OS isolation is the hard boundary per
  Hermes' own model; a SANITIZE-only daemon is the v2 direction).
- **Coverage gap (documented)**: `key_patterns` masks `KEY=`, `KEY:`, and
  JSON key forms. XML-style tags (`<ApiKey>value</ApiKey>`) are NOT covered
  by key patterns — register those values as exact literals instead
  (literals mask anywhere, including inside XML). Note: token-shaped values
  inside XML are still caught by the token-prefix pass and gitleaks;
  identification happens at the source config, where the tag names the
  secret.

## The `.env` grammar (what `info-guard build` parses)

Lines are `KEY=value`; anything after the first `=` is the value:

- keys must match `[A-Za-z_][A-Za-z0-9_]*` (other lines are skipped)
- surrounding single or double quotes are stripped from the value
- trailing `# comments` are stripped only when preceded by whitespace
  (a `#` inside the value is part of the value)
- `export KEY=...` prefixes are not supported
- non-secret keys (hosts, URLs, usernames, flags, schedules, ports, …) are
  excluded via a curated list (the matcher's `_is_non_secret_key`);
  secret-shaped keys become key patterns, and values ≥ 8 chars become
  exact literals
- values shorter than 8 chars are not registered as literals (precision
  floor), but their KEY still becomes a key pattern — so `PIN=1234` masks
  even though the value is unregistered

## Trusted-path assumption

The registry path is **fully trusted**: whatever `security.redact_patterns`
or `HERMES_REDACT_PATTERNS` points at is loaded as-is, symlinks followed,
with no requirement that it live under `$HERMES_HOME/state/info-guard/`.
Configurable external registries are a feature (share one registry across
profiles, mount it read-only, generate it elsewhere) — but the flip side
is that anything able to write that path controls redaction. If that is
unacceptable in your threat model, keep the registry under your own
`$HERMES_HOME` and enforce the permissions there.

## Custom literals (the PII workflow) — registry v2 (v0.4.2)

`<state>/custom_literals.json` — CLI-managed (literals add/rotate/remove), survives rebuilds, masking only
(never part of detection). Registry v2 shape:

```json
{"version": 2, "literals": [
  "someone@example.com",
  {"value": "anything-you-want", "mask": "full", "id": "3f2a91c4e8b6d705"},
  {"value": "ht-3f9c2a1b8e4d5c6a7b8c9d0e", "mask": "full",
   "id": "7c1d9e2f3a4b5c6d", "kind": "honeytoken"}
]}
```

**`id`** — an opaque 16-hex random registration id (v0.4.2). The app
assigns it: plain-string entries and id-less dicts get one on the next
load, and the file is rewritten once (lazy migration, one-time stderr
note). This is the `value_id` that watch/v1 JSON carries on protected
rows — the consumer's join key into this file (see
`docs/watch-schema.md`).

**`kind`** (v0.7.0): optional per-entry
metadata. Absent = a normal literal (never serialized as
`"kind": "literal"`); `"kind": "honeytoken"` marks a **canary** — a
value that must never legitimately appear at rest; any exact scan match
is a canary-touch (tier `HONEYTOKEN`, exit 4; see §Canary-touch
contract). Unknown `kind` values are treated as normal literals with
one stderr warning per load/invocation (never a crash, never an
escalation). `kind` does NOT participate in deduplication (dedup stays
by value) and does not affect matching. literal ↔ honeytoken
transitions are hand-edits (per-entry metadata; next run reclassifies);
removal + re-add = fresh `value_id`.

**File contract (add-only):** the app may normalize the file to add
ids, but it NEVER strips anything — unknown entry fields (e.g. `mask`,
`note`, `kind`), non-string entries, and unknown top-level keys are
preserved verbatim; duplicate values collapse to the first entry (one
registration per unique value, so one value = one id in practice);
duplicate ids are repaired deterministically with a stderr warning.
Unreadable files are never overwritten. Old (v0.4.1–v0.6.1) binaries
still read a v2 file with `kind` present: the unknown field is
preserved verbatim and the value matches as a normal literal (never a
crash, never a canary-touch).

**The sanctioned add path is the CLI** (v0.4.2 — every mutation
goes through the same canonical loader/writer):

```
info-guard literals add VALUE... [--mask STYLE] [--file FILE] [--json]
info-guard literals add --kind honeytoken [VALUE] [--json]
info-guard literals list [--json]
info-guard literals remove <id> [--json]
```

`literals add` prints the assigned id per value; duplicate values return
the existing id (no new entry); `--mask` applies to every value in the
invocation (last flag wins); `--file` reads line-delimited values
(blank lines and `#` comments skipped); explicit registration accepts
any non-empty string (no 8-char floor — short/PIN-class values are
legal; `setup`'s floor is unchanged). **`--kind honeytoken`** (v0.7.0):
plants a canary — with no VALUE, generates `ht-` + 24 CSPRNG
hex chars; with a VALUE, registers that exact value (no prefix
enforced; explicit values are never echoed in full). Rejects `--file`,
`--mask` (mask is forced `full`), control characters, line terminators,
empty/whitespace-only values, and any `--kind` value other than
`honeytoken` — all with usage exit 2 and no registry mutation. A
duplicate normal literal supplied with `--kind honeytoken` fails loudly
(exit 2 — never a silent no-op plant); a duplicate honeytoken is
idempotent success (existing id, no rewrite). The generated full value
is printed once to stderr at plant time (never stdout; escaped
representation). **`literals remove <id>`** (v0.7.0): removes exactly
one entry by id via the canonical atomic 0600-preserving writer;
unknown id → exit 0 with `no entry with id <id>` on stderr and
`{"removed": false}` in JSON (idempotent — the replant prerequisite).
`literals list` may perform the
one-time migration write when the registry is stale — a read command
that normalizes once; `--json` output stays pure (all chatter on
stderr). Exit codes: 0 success, 1 unreadable registry (no write), 2
usage. CLI rules apply (`--help` → usage exit 0 anywhere; unknown
`--*` flags → verbatim warning + continue).

Hand-editing still works: edit the file, then `info-guard build` — live
within seconds, no restarts.

## Preflight report format (v0.2.4+)

`info-guard preflight` prints a structured, fully-masked security assessment.
The format is a contract — tests assert its sections; keep them in sync when
changing it. Every value is masked (head/tail 2+2 via `_mask_value`) or `***`;
raw values never reach the terminal.

The scan builds ONE in-memory assessment object (facts only, no prose);
the report is its render. The object is the contract:
`docs/assessment-schema.md` (schema `info-guard/assessment/v1`). The text
report is never a second implementation.

### `--json` / `--json-out` (v0.3.0) and `watch` (v0.3.0 → v2 in v0.4.0)

- `preflight --json` serializes the SAME object to stdout — no chatter
  (the object's `tool` block carries engine state). `--json-out FILE`
  writes it atomically (temp + fsync + rename, **0600**) and implies JSON
  mode. Exit codes unchanged: 0 = clean, 1 = findings, 2 = usage error.
- `watch` (v2, v0.4.0; protected-value matching v0.4.1) re-runs the scan
  and reports **deltas on four tracks** against
  `<state>/info-guard/watch-baseline.json` (schema
  `info-guard/watch-baseline/v2`, 0600 — **value sha256 only; raw values
  never persisted**; schema v1 baselines are migrated in place, delta-free):
  1. **Exposure** — `new_values` (masked 2+2 · type · family · count,
     exit 1), `resolved_values` (informational — "No longer detected in
     the current scan scope. This does not confirm that the credential
     is dead or revoked"), `changed_values` (±occurrences, informational),
     family rollups, per-file count changes, and **`protected_values`**
     (v0.4.1 — see item 4).
  2. **Protection configuration** — custom literals / key patterns
     added/removed (fingerprint-set diffs), redact_patterns whole-set
     fingerprint change, mask-policy change. Counts + fingerprints ONLY —
     raw literals never appear, not even masked. Wording contract:
     configuration deltas, never effectiveness ("protection configuration
     changed", never "protection improved").
  3. **Engine state** — transitions between `active` / `partial` /
     `none` with explicit blocks (installed / restored / degraded /
     removed).
  4. **Protected values (v0.4.1)** — scan values whose
     exact sha256 matches a `custom_literals.json` entry (the app's
     known-value registry — NOT the house `known_secrets.json`, which is
     HMAC-peppered leak_scan state and stays out of the public product).
     Vocabulary: **protected value** = user-declared via the registry ·
     **detection** = the value appeared in the scan · **increased** =
     more occurrences than baseline · **confirmed leak** = never claimed
     by watch. Wording: "PROTECTED VALUE RE-DETECTED", never "known
     secret detected", never "leak". Matching is **exact-value only**
     (case-sensitive) and operates on the scan's **credential-shaped
     value set** (the same domain as the baseline) — a declared literal
     that is not credential-shaped (e.g. a PII-only email) never matches,
     by design. Count = matching occurrences across the watch scan scope;
     deltas: `new` (not in baseline) / `increased` / `decreased` /
     `unchanged`; a value absent from the scan surfaces only via
     `resolved_values`, never as a protected row. **Overlay rule:** JSON
     keeps the row in `new_values`/`changed_values` AND
     `protected_values` (one event); the terminal renders protected rows
     only in the PROTECTED block. Live-registry semantics: declaring a
     literal takes effect on the next run, no `--reset` needed.
- **Exit codes (contract, v0.4.0; protected row v0.4.1):** NEW values =
  1 · **protected value `new`/`increased` = 1** · `active→partial` = 1
  (degraded) · `active→none` = 1 (engine removed — config remains on
  disk, not applied) · `none→active` / `partial→active` = 0 ·
  config-only / resolved / **non-protected** changed = 0 · usage = 2.
  `partial` is never ambiguous — degraded protection alerts exactly like
  removal (matches `check`).
- **CLI contract (v0.4.1):** every subcommand accepts
  `-h`/`--help` → prints its usage line, exit 0. Unknown `--*` flags are
  tolerated (preflight precedent) but never silent: stderr
  `Warning: unknown option '<flag>'` (flag echoed verbatim), then the run
  proceeds — a typo (`--jason`) is visible in cron logs. Single-dash
  tokens remain scan-dir names (documented limitation).
- **Baseline lifecycle:** first run (or `--reset`) creates it; on
  tool/gitleaks version change it is **union-kept** (known values never
  re-alert) with a notice; a broken/unreadable baseline is rebuilt,
  never a crash. **Refresh-on-delta:** the baseline is rewritten at the
  end of any run that observed a delta (exposure, protection, or engine)
  with current state — every delta alerts exactly once; clean runs leave
  it untouched. `setup` stamps the protection/assessment snapshot into
  an existing baseline (values preserved) so a deliberate config change
  after setup doesn't alarm on the next watch.
- **Baseline v2 note:** the baseline's `assessment` block carries a
  private per-file `credential_shaped` map (files-with-findings only,
  absent = 0 in the diff) in addition to the totals — an internal 0600
  extension of the watch/v1 contract (which exposes file-level facts
  only as `exposure.changed_files`); documented in full in
  `docs/watch-schema.md`.
- `watch --json` / `--json-out FILE` emit the delta object (schema
  `info-guard/watch/v1`, doc `docs/watch-schema.md`) — the PUBLIC delta
  result: exposure rows are masked 2+2 (`value_sha256` is FORBIDDEN
  there; the private baseline keeps sha256), protection rows are counts
  only. JSON mode keeps stdout pure JSON (informational lines go to
  stderr), 0600 atomic writes, missing `--json-out` path = usage error 2.
- The baseline lives under `<state>/info-guard/`, which is not in the
  default scan set (`sessions`, `logs`, `cron/output`) — Info Guard never
  scans its own artifacts. Passing explicit dirs that include it is the
  caller's choice.
- `scan.generated` / `watch.generated` are ISO-8601 UTC; the text
  renderer reformats for display (renderer owns language).

Report sections, in order (each printed only when its data is non-empty):

1. **Header** — `Info Guard v<version> — Preflight Security Assessment` +
   scan metadata (read-only, values masked, generated timestamp) + an
   **Engine** line (install state + installed version from the install
   manifest, or NOT INSTALLED for the decide step) + a **SCOPE** line
   (directories scanned + file count) so a clean result never reads as
   "the entire installation is secure".
2. **STATUS** — 🔴 ACTION REQUIRED + one-line summary (candidates, not
   confirmed leaks) / 🟢 CLEAN + what it means. "No changes were made by this
   scan" is prominent here.
3. **EXECUTIVE SUMMARY** — metric cards: **credential-shaped candidates**
   (the canonical count: one per unique `file:line:value` row — the family,
   location and affected-file tables all sum to it exactly), with the
   **family-attributed · unattributed split**, **distinct values** (the
   rotate list), and **raw detections** (detector fires before dedup; a
   "N duplicate detector hits collapsed" note appears when they exceed the
   candidate count). Plus files scanned, families with value-shaped
   material, already-masked occurrences. And WHAT MATTERS: 2–3 bullets
   generated from the assessment (value shapes, location concentration,
   redaction working).
4. **CREDENTIAL EXPOSURE BY FAMILY** — the merged master table (owner
   refinement 2026-08-19): one row per family with **Family · Type · Qty ·
   Value (masked 2+2) · Status** (🔴 Exposed / 🟡 Mixed / 🟢 Protected
   circles), sorted by status group (exposed → mixed → protected) then
   alphabetically. Qty = value-findings (or "N masked" for protected-only
   families); Value = the top distinct value in 2+2 masked form ("+N more"
   when the family has further distinct values; `--full` lists every
   distinct value). Protected-only families are capped at 10 with a
   "showing top N of M" line. Rows whose masked value also appears under
   another family carry a dagger (†) with a footnote naming the other
   families — one credential caught under multiple key names (e.g. header
   vs env var). Below the table, **DISTINCT VALUES — THE ROTATE LIST**
   lists every distinct value once (mask 2+2 · type · occurrence count ·
   dominant family; top 15, `--full` for all) — the checklist behind
   RECOMMENDED ACTIONS #1. Literal generic key names render quoted
   (`"token"`) so they never read as credential classes; the synthetic
   prefix-only family renders as `(no key context)`. Data/JSON family
   names are unchanged.
5. **EXPOSURE LOCATIONS** — per area (sessions / logs / cron / state /
   other): **credential-shaped candidate counts + masked counts + area
   status** (🔴 Exposed / 🟡 Mixed / 🟢 Mostly masked / 🟢 Protected —
   masked is the share of the area's *candidates* already redacted: all →
   Protected, ≥ half → Mostly masked, some → Mixed, none → Exposed), a
   qualified Pattern observation ("consistent with retained historical
   exposure rather than a current logging failure" — never a definitive
   claim), and SHOW AFFECTED FILES (top 10: "N findings (M candidates)" —
   findings include duplicate detector fires and mentions; the candidate
   column is the deduplicated file:line:value count and sums to the
   headline exactly).
6. **RECOMMENDED ACTIONS** — 4 numbered steps (rotate active candidates →
   choose prevention → clean historical exposure → verify) + the explicit
   tier-partition statement + no-routine-re-run note.
7. **APPENDIX A — FINDING LEDGER** — in the main report: the sample mode,
   with the "(sample — one per family; …)" hint as a smaller subtitle under
   the title (one example per family, ranked by signal; junk-display rows
   count-only; `— your .env key` labels; rows show file:line + the 2+2
   masked value only — no context line). With `--full`: the complete
   deduplicated ledger (same masking, no cap) followed by **APPENDIX B —
   DETECTION TELEMETRY** (key-name mention counts, explicitly NOT findings —
   forensic mode only). Source-masked rows stay count-only in both modes.

Taxonomy — a partition, stated in the report: every raw hit is classified
into exactly one of **KNOWN** (v0.5.0 — your `.env` values, identity-verified),
**credential-shaped** (token-format values + gitleaks
HIGH-CONFIDENCE — the actionable set), **key-name mention** (includes
reference/noise rows; a future tier may split them), or **already-masked**
(the prevention layer working). `findings = known + raw_detections +
key_name_mentions + already_masked`, exactly — the partition holds over
RAW hits at ROW level (each `file:line:value` row is exactly one tier);
`totals.known` is the distinct-VALUE rollup (≤ `totals.known_rows`, the
row-level KNOWN count — both are reported so the reconciliation is
checkable). `credential_shaped` is the deduplicated row count of the
credential-shaped class (≤ `raw_detections`); the headline, family,
location and affected-file tables all sum to it.

The candidate unit is the unique **`file:line:value` row**: when several
detectors flag the same value on the same line (key-shape + token-prefix +
gitleaks can all fire), the row counts once — and when the value is a
KNOWN `.env` match, the KNOWN tier wins the row (identity-verified beats
shape-guess; the shape row is dropped, never counted as credential-shaped).
`totals.raw_detections` keeps the raw detector-fire count and
`totals.distinct_values` the value-level count — the summary line states
all three so every table's sum reconciles.

### The KNOWN tier — `.env` exact-value detection (v0.5.0)

**What it does:** preflight reads your default `.env` sources
(`$HERMES_HOME/.env`, `./.env` — existing files only, the same sources
`build` uses), builds an in-memory `sha256(value) → [keys...]` index of
every **eligible** value (key not in the non-secret list, `len ≥ 8`, not
trivial, ≤ 4 KB), and intersects it with value-like candidate runs found
in the scan (`[A-Za-z0-9_\-./+=:@%?&~#]{8,}`, ≤ 256 candidates per line).
A match is reported as a **KNOWN** row: masked 2+2, `rule
known-env:<KEY>` (alphabetically first key across sources),
`known: true`, `source_key: <KEY>`, `type: "KNOWN"`. The scan's own
`.env` sources are excluded from matching (canonical path + inode
identity — the pass never reports its own input). All other detectors
are untouched. The pass is **preflight-only** in v0.5.0 — `watch` and
`setup` do not run it. **v0.6.0: `watch` and `setup` run
the same env pass** (watch rows gain `source`/`source_key` annotations and
the T1–T8 transitions; setup self-fills KNOWN candidates — see the
Contract foundation section).

**Candidate grammar (exact-match doctrine — published, with exclusions):**

| Construct | Behavior |
|---|---|
| `[A-Za-z0-9_\-./+=:@%?&~#]{8,}` run | candidate; sha256'd and intersected |
| surrounding quotes | delimit runs (quote chars not in the grammar; no strip step) |
| quote char INSIDE a value | the value can never be a candidate (documented exclusion) |
| whitespace, Unicode, commas, brackets, backslashes, shell escapes, multi-line | never candidates (documented exclusions, negative fixtures) |
| `KEY=value`-style line | ONE run including `KEY=` (both `=` and `_` are grammar chars) — matches only if the whole run equals an eligible `.env` value |
| partial fragments | never match — exact token equality only |
| same-line repeats | one row, `count` preserves occurrences |

**Source aggregation:** per-key last-parse-wins WITHIN a file; the same
key in two files contributes BOTH parsed values; the same value under
different keys maps to all keys (`source_key` = alphabetically first).
**Source states:** `absent` (not in the default list — no diagnostic),
`unreadable` (read fails), `malformed` (non-empty, zero valid entries),
`ok`. Each unreadable/malformed source emits **one masked diagnostic
line** in the text report's KNOWN section; JSON is stable
(`confirmed_active` + `totals.known`, never a diagnostics field). The
pass stays active if ≥1 source parses; **disabled only when zero sources
are ok** — the text report then emits exactly one line:
`KNOWN pass: no .env sources — disabled`. Source state never affects
exit status.

**Vocabulary:** KNOWN rows "match a current eligible `.env` value;
review whether it is still live" — never "leak", never "confirmed".
`status.confirmed_active` is `true` when ≥1 KNOWN row, `null` otherwise
(null = pass disabled OR pass active with no matches — deliberately not
distinguished in v0.5.0).

**Exit codes (v0.5.0 — documented extension):** `0` = clean, **`1` iff
`known > 0 OR credential_shaped > 0`**, `2` = usage error. **v0.5.1:**
`2` widens to usage **or operational** — a degraded preflight run (gitleaks
engine unavailable, or an internal scan failure) exits **2, never 0 and never
1**; the assessment JSON continues to carry `engine.installed` so consumers
can distinguish the cause. The severity
ladder (0 clean / 1 shape / 2 usage / 3 KNOWN, KNOWN dominates) was
deferred to a later release and **shipped in v0.6.0 as ONE
packaged contract change** (format-spec + CHANGELOG + release notes +
consumer tests together), adopting this widened `2` unchanged.

Date discipline: historical date ranges come from **session filename
timestamps** (`session_YYYYMMDD…`), never filesystem mtime.

Detection coverage (v0.3.1): the key-shape pass covers secret-family keys
including `Authorization` headers (v0.3.1 — `auth\b` never matched
"Authorization"); the bare-value pass covers token prefixes (`sk-`,
`ghp_`, `key_`, …) plus **dot-structured JWTs** (`eyJ` header ≥8 chars +
`.` + payload ≥2 — the canonical jwt.io header without a dot never
fires, masked-looking short forms never fire). The prefix pass searches
whole lines, so `Authorization: Bearer <jwt>` yields an actionable JWT
row (unattributed when no key context); `Authorization: ***` counts
already-masked.

Exit codes: **0 = clean**, **1 = findings** (any KNOWN `.env` value OR any
credential-shaped value — single-predicate extension, v0.5.0; previously
credential-shaped only),
**2 = usage or operational error** (v0.5.1 — the operational
sub-case: gitleaks engine unavailable or an internal scan failure; preflight
exits 2, never 0). gitleaks is optional: without it the scan runs the
key-shape pass only and says so. The severity ladder (0/1/2/3 with KNOWN
dominating) **shipped in v0.6.0** as one packaged contract
change — see the Contract foundation section.

## Contract foundation (v0.6.0)

Normative contract for every public JSON surface, shipped as ONE packaged
contract change (docs + CHANGELOG + release notes
+ consumer-facing tests together). Later releases build on the declared seams
and may not reinterpret anything below.

### Envelope doctrine

Every **public** machine-readable surface is an envelope:
`{"schema": "info-guard/<surface>/v<major>[.<minor>]", "tool": {...}, ...payload}`.

| Surface | Schema id | Envelope (`schema` + `tool`)? |
|---|---|---|
| preflight assessment | `info-guard/assessment/v1` | yes |
| watch | `info-guard/watch/v1` | yes |
| `literals --json` | `info-guard/literals/v1` | yes (v0.6.0 — first envelope on this surface, additive) |

Exempt from the envelope doctrine:

- `custom_literals.json` — user-owned local configuration (trusted 0600
  state, managed through the CLI, raw values by design).
- `watch-baseline.json` — internal state; versioned independently, not part
  of the envelope doctrine unless explicitly promoted to a public contract.
- The exit-code table — **documentation-only in v0.6.0**; its
  machine-readable JSON form is descoped (no v0.6.0 consumer; publish the
  JSON surface in the release that first has a consumer for it, plausibly
  when exit 4 becomes normative). No standalone `exit-codes` JSON file or
  endpoint is published.

### Versioning policy

- **Major = compatibility generation; minor = optional additive revision.**
- Same-major consumers MUST tolerate additive revisions.
- Producers do not bump the minor merely because additive fields were
  added — a release performs additive work under its current major; creating
  `v1.1` just to advertise additions is prohibited (the additive contract +
  consumer obligations already cover it).
- Minor-bump timing is producer policy per release, announced in the release
  notes; consumers MUST NOT depend on bump frequency or timing.
- Breaking = requiredness change, type change, identity change, field
  removal, semantic change.
- CLI exit-code semantics are versioned **independently** of JSON schemas:
  changing an exit code's meaning is a CLI contract change requiring the
  packaged-contract-change rule — it is NOT automatically a JSON schema major bump.

v0.6.0 keeps `info-guard/assessment/v1`, `info-guard/watch/v1`, and
`info-guard/literals/v1` — identifiers unchanged; every v0.6.0 field
addition is additive per the taxonomy below.

### Additive/breaking taxonomy

| Additive (no major bump) | Breaking (major bump + packaged-contract-change rule) |
|---|---|
| new object field | changing the meaning of an existing field |
| new optional metadata | changing required/optional status |
| new output row type (consumers MUST tolerate) | changing field type |
| new enum value (consumers MUST tolerate) | removing a field |
| | changing identity semantics |
| | changing the meaning of an existing exit code (CLI contract — listed for completeness; NOT a JSON schema trigger) |

Enum expansion is NOT automatically additive — `if tier == "KNOWN": … else:
fail` breaks on any new tier unless consumers are obligated to tolerate
unknown values. That is why the consumer obligations below are a contract,
not advice.

### Consumer obligations (two-part)

1. **Syntactic tolerance** — unknown fields, row types, and enum values MUST
   NOT cause parsing failure or be treated as malformed input.
2. **Semantic handling** — each enum field and row-type family declares its
   unknown-value behavior in the schema docs. Security-significant unknown
   values MUST be preserved and reported, while remaining masked. At minimum
   a compliant consumer must retain:
   - the complete masked row,
   - the unknown discriminator value (e.g. an unknown `type` string),
   - the row through its normal findings/reporting path.

Unknown-value behavior at v0.6.0:

| Field / family | Required behavior |
|---|---|
| `type` (finding-class tier: KNOWN, JWT, …) | tolerate + **preserve/report** |
| `delta` (watch transition: new/increased/…) | tolerate + **preserve/report** |
| `source` (`env` \| `literal`, future values) | tolerate + ignore (actionability rides on `type`/`delta`) |
| registry mask-style names | tolerate + ignore |
| unknown finding-row types (`top_values[]`, `protected_values[]`, …) | tolerate + **preserve/report** |
| unknown metadata-row types | tolerate + ignore |

Preserve/report stays inside the masked-only surface discipline — unknown
values are surfaced masked, never raw. The failure mode this closes:
"MUST ignore" would let a compliant consumer silently drop a future
HONEYTOKEN row — the tier enum IS the severity signal.

### Schema-string parsing

Consumers MUST parse the **surface** and **major** from the `schema` string:

```text
info-guard/<surface>/v<major>[.<minor>]
```

They MUST NOT compare the complete string literally (a literal
`schema == "info-guard/watch/v1"` check breaks the day v1.1 ships). Unknown
**major** versions MAY be rejected; unknown **minor** versions MUST be
accepted — the same-major tolerance guarantee is enforceable only under
this rule.

### Nullable and optional fields

Optional annotation fields are **absent when unavailable and never emitted
as `null`**:

- `value_id`
- `source_key`
- `source`

Across `assessment/v1` and `watch/v1`, the ONLY nullable fields are:

- `family` (genuinely nullable for unattributed values)
- `resolved_values[].value_masked` (value gone from the scan — null by design)
- `status.confirmed_active`

Any field not listed is non-nullable by contract. `status.confirmed_active`:

- `null` — pass disabled or no identity-verified matches
- `true` — at least one identity-verified KNOWN value
- `false` — NOT emitted by v0.6.0; an unexpected `false` MUST be handled as
  `null` under preserve/report behavior

### Exit contract (0/1/2/3/4)

| Code | Meaning | Emission |
|---:|---|---|
| 0 | clean — no findings or delta | all applicable commands |
| 1 | credential-shaped findings or watch delta alarm | preflight and watch |
| 2 | usage or operational error | all commands |
| 3 | identity-verified KNOWN value present; dominates | preflight only |
| 4 | **honeytoken-grade escalation (NORMATIVE since v0.7.0)** — a registered canary value was found at rest (canary-touch detection fact) | preflight and watch |

**Preflight reduction (v0.7.0 — 4 normative):**

1. Usage or operational failure → `2` (never overridden — an incomplete
   scan asserts no complete verdict; independently detected facts MAY
   still be serialized as partial rows, §Canary-touch below).
2. Otherwise, `honeytoken > 0` → `4` (dominates 3 and 1).
3. Otherwise, `known > 0` → `3` (dominates 1).
4. Otherwise, credential-shaped findings → `1`.
5. Otherwise → `0`.

**Watch reduction (v0.7.0 — watch-side 4 normative):**

1. Usage or operational failure → `2` (same partial-row doctrine).
2. Otherwise, honeytoken new/increased (canary-touch) → `4` (dominates 1).
3. Otherwise, ANY of `new_values`, increased exposure count, engine
   degradation, new/increased protected alarm → `1`.
4. Otherwise → `0`.

Non-alarming transitions (resolved, decreased, unchanged, config-only (T8),
T3/T3b reclassification, baselined-canary-present (`delta: "unchanged"`))
never raise the exit.

**JSON emission:**

- Exit `0`, `1`, `3`, and `4`: emit parseable JSON where the command has a
  JSON surface.
- Exit `2` (usage): print the error to stderr and emit no JSON (usage errors
  happen before any scan output exists).
- **Exit `2` (operational failure): the assessment IS still emitted in
  `--json` mode — stdout stays pure JSON carrying the engine state
  (`tool.installed` / `tool.engine_state` / `scan.gitleaks_ok`), advisory to
  stderr; v0.5.1 behavior retained unchanged.** The exit code, not
  the absence of JSON, is the operational signal.
- Exit codes `> 4` and unknown nonzero codes: consumers MUST treat them as
  unexpected failures, capture diagnostics, and assign no fixed semantics.

### Canary-touch contract (v0.7.0)

A **honeytoken** is a registry entry with `"kind": "honeytoken"` planted via
the sanctioned `literals add --kind honeytoken` path (a canary value is
`ht-` + 24 CSPRNG hex chars when generated; explicit values allowed). The
value must never legitimately appear at rest — any exact match in the scan
is a **canary-touch detection fact** (never "leak"/"confirmed").

- **Detection:** registry-exact value pass (independent of gitleaks) on
  preflight AND watch. Tier `HONEYTOKEN` wins over every existing class
  (KNOWN, credential-shaped, key-name mention, already-masked) — one row per
  `file:line:value`; a canary that is also a live `.env` value is still
  `HONEYTOKEN` and carries `source_key` + `value_id`.
- **Escalation:** exit `4` on preflight presence; exit `4` on watch
  new/increased. A baselined canary (`delta: "unchanged"`) never raises the
  exit (value-level appearance semantics).
- **Partial-result doctrine:** when the engine is unavailable/degraded, exit
  `2` is authoritative; independently detected HONEYTOKEN rows MAY still be
  serialized in the JSON (partial rows are never a complete assessment).
- **Lifecycle:** sticky — a touched canary keeps matching until removed
  (`literals remove <id>`) or replanted (fresh `value_id`). No
  auto-deactivation (silent mutation, invariant 5).
- **Scan boundary:** default scan dirs never include the product state dir;
  explicitly-specified dirs are operator-chosen targets (a canary match
  there is a genuine finding).

### Cross-surface seams

| Seam | Contract |
|---|---|
| `value_id` identity monomorphism | `value_id` is the ONLY cross-surface identity mechanism. Same persisted registry entry retains the same ID across runs, rebuilds, reorders, and self-fill merges; an ID is assigned exactly once and persisted; delete + re-add produces a fresh ID, never reused; IDs are locally scoped to one installation (v0.6.0 emits no installation identifier); IDs are CSPRNG-generated and independent of the value — no hash, truncation, or keyed derivation. v0.7.0: canary identity = the registry entry id; replant = fresh id |
| tier-enum growth | unknown tiers are not fatal to v0.6.0 code; consumers preserve/report unknown security-significant tiers. **v0.7.0: `HONEYTOKEN` tier ADDED (additive); old consumers preserve/report the row, never drop it** |
| exit-4 reservation | **FULFILLED by v0.7.0:** exit 4 is now normative and emitted on canary-touch (preflight + watch); the reservation wording is superseded |
| additive-only schema evolution | all v0.6.0 output additions are optional and additive; no field is removed, retyped, made required, or semantically redefined. v0.7.0 additions are additive: registry `kind`, tier `HONEYTOKEN`, watch `review_list` + `review_list_complete`; honeytoken rows carry `known: false` per the shipped derived-flag contract |

### Watch source and transition contracts (T1–T8)

The `.env` set is a **match source, not tracked state** — classification is
per-run (per-run hashing); the baseline keeps
`{value_sha256, type, family, count, first_seen}` only, with no `source`
field. All transitions below are per value hash. `family` for env-matched
rows is derived from the match rule's key name and IS persisted in baseline
rows — that is provenance, not a claim: the baseline records no `source`
classification.

| # | Transition | Definition | Event / exit |
|---|---|---|---|
| T1 | **added** | value not in baseline, detected in scan (any source) | `new_values[]` → **exit 1**; env-matched rows carry `source: "env"` + `source_key` |
| T2 | **removed** (from scan) | in baseline, absent from current scan | `resolved_values[]` → exit 0 |
| T3 | **`.env`-leave** | value has no env match in the CURRENT run's index (the baseline stores no source — no historical `.env`-match claim is made) | current-run reclassification, **no event, no exit change**: row stays (still in scan), carries no `source_key`/env classification → shape (if unregistered) or `literal` (if registered — registry membership is unaffected by `.env` removal). If it also left the scan → T2. Per-run hashing → no `--reset` needed on `.env` edits |
| T3b | **detection loss** | `.env`-leave of a value detectable ONLY via the env pass (no shape qualification, unregistered) — still in scan, but no longer detectable by any pass | `resolved_values[]` with the D46 wording applied literally — reads as remediation, but the cause is loss of detection capability, not removal of exposure → exit 0 |
| T4 | **replaced** (same key, new value) | env key K: old value absent from the current index, new value present | old value → T3 current-run path (T4 emits no event for the old value); new value → T1 if detected in scan (exit 1 — the alert is "new value at rest"). If the replacing value is ALSO registry-registered → T1 row carrying both `source_key` + `value_id` |
| T5 | **duplicated** | same value under 2+ env keys, or new scan locations | 2+ keys → ONE row, `source_key` = alphabetically-first key (v0.5.0 A11 semantics); new locations → count increase → `increased` → **exit 1** |
| T6 | **moved** | value moves files, total count unchanged | `unchanged` → exit 0 |
| T7 | **increased / decreased** | count change vs baseline | increased → **exit 1**; decreased → exit 0 |
| T8 | **config-only** | registry-membership change with unchanged scan state — e.g. self-fill registers an already-baselined value; count/scan presence unchanged | `protected_values[]` appearance with `delta: "unchanged"`; **no `new_values[]` row, no exit raise (exit 0)** — registration changes only classification/overlay membership |

**Precedence (P-C):** `source` = the precedence winner — `env` or `literal`,
never "both". **Literal wins**: the registry is the authoritative
declaration; `source_key` + `value_id` are still both carried when a
collision exists, so no information is lost. `source_key` is present iff an
env match exists **regardless of who won precedence** — a `source:
"literal"` row may still carry `source_key`; consumers must not read
`source == "literal"` as "no .env match".

**Collision / overlay (one-event rule):** a value that is env-matched
AND registered appears once in `protected_values[]` (delta per the counts machine) and
once in the overlay (`new_values[]`/`changed_values[]`) — same `value_id`
on both, ONE event; `pm_alarm` (delta new/increased) → exit 1. "One row,
never two" means one row per array — consumers dedup across arrays by
`value_id` when present, else `value_masked`.

**`.env`-leave wording (informational, exit 0):** "No longer
detected in the current scan scope. This does not confirm that the
credential is dead or revoked."

**Env index source states:** `absent` (not in the default list — no
diagnostic), `unreadable` (read fails), `malformed` (non-empty, zero valid
entries), `ok`. Each unreadable/malformed source emits exactly ONE masked
diagnostic line; a source whose LINES are mixed valid/malformed parses its
valid lines and silently skips the malformed ones (no diagnostic —
malformed refers to whole-file states only). Diagnostics are text-only; JSON
stays stable (`confirmed_active` + totals). Eligibility limits: values > 4 KB
are excluded from the index (skipped, no diagnostic); sources > 2 MB are
excluded from the source set (one diagnostic per excluded source); > 256
candidates on a line → first 256 considered, rest of the line ignored.

### Setup self-fill disclosure

`setup` (v0.6.0) runs the env pass and group-prompts identity-verified
KNOWN candidates, **default yes**:

```text
N known .env value(s) found in the scanned files — register as protected literal(s)? [Y/n]
```

- The prompt names the leak location — the values were FOUND in the scanned
  files, not "found in your .env". Each candidate is listed **masked**:
  value 2+2 + `source_key` + proposed mask style. Declining the group skips
  all KNOWN candidates (they remain detectable as env rows, just
  unregistered); non-KNOWN candidates keep the existing per-item y/n walk;
  `--all` (agent path) accepts everything.
- Mask style (P-D): shape-based — token-format values → `mask: "full"`,
  others → default 2+2; values under 12 chars → `full` regardless of shape.
- **Plaintext persistence disclosure:** the group prompt explicitly states
  that a PLAINTEXT copy of each accepted value is written to
  `<state>/info-guard/custom_literals.json` (path + 0600 trust boundary).
  Values are shown masked only, never echoed — including confirmation and
  error messages; nothing is written before the confirmation phase
  completes; the reject path writes nothing.
- Writes go through the canonical registry path (load → dedup → normalize →
  atomic write 0600); merge-only, never clobber; duplicates
  collapse by value, first entry's id wins; `id` assigned at write
  time. A failed atomic write leaves the ORIGINAL registry intact — no
  partial registration, no data loss.
- Abort/decline (EOF / invalid input / interruption before confirmation) →
  NO registration, exit 2.
- The registry path is OUTSIDE the default scan scope (sessions / logs /
  cron/output) — registering literals cannot seed a self-detection loop
  (the registry file never becomes a location hit).
- Self-fill sources are the `.env` set only (the same sources `build`
  uses); other inventory sources are out of v0.6.0 scope.

### `literals --json` envelope

`literals list --json` is a public JSON surface (schema
`info-guard/literals/v1`, v0.6.0 — first envelope on this surface,
additive; the top level was already an object `{"literals": [...]}`).
Masked values + mask-style metadata + IDs only — raw values never appear.

```json
{
  "schema": "info-guard/literals/v1",
  "tool": {"name": "info-guard", "version": "0.6.0"},
  "literals": [
    {"value_masked": "se...7x", "mask": "full", "id": "3f9c2a1b8e4d5c6a"}
  ]
}
```

The registry file itself stays exempt from the envelope doctrine
(user-owned local configuration).

### First-run upgrade re-baseline (v0.5.x → v0.6.0)

v0.5.x watch baselines were written with shape-qualified values only;
v0.6.0's env inclusion means previously-excluded env-matched values satisfy
T1 on the first run against an old baseline — a false `new_values` alarm
storm (exit 1 for every existing watch user on upgrade). **The first v0.6.0
watch run against a v0.5.x baseline MUST re-baseline** — documented
remediation: reset/delete the baseline and re-run; subsequently the
baseline is correct and runs are quiet. The pre-rebaseline alarm is
expected and documented; the baseline file schema itself is unchanged (no
baseline schema bump — the population change is the semantic change).

## v0.8.0 — `update`, `check --heal`/`--battery`, and cron

The preflight/watch 0–4 ladder is **untouched**; `check` keeps its 0/1/2
meanings (0 healthy · 1 completed broken verdict · 2 usage OR operational).
This section adds only the declared new contracts.

### `info-guard update` — surface and exit table

```
info-guard update [--check] [--json] [--rollback]
```

- The package is the git checkout containing the running binary (resolved
  via `__file__`; `~/.info-guard` is the documented canonical location, not
  a logic-level assumption). A non-git package is refused (exit 2,
  `error_class: not_git`).
- The configured origin is the **trust anchor** (HTTPS git only — a
  non-HTTPS origin is refused before any fetch, exit 2). Release
  candidates are exactly the origin's `vX.Y.Z` tags (strict grammar, no
  suffixes; annotated tags peeled); local tags are never a selection
  source.
- **`--check`** is read-only in every state: `git ls-remote --tags origin`
  only — no fetch, no refs/index/worktree/`FETCH_HEAD` mutation, no
  repair. A newer matching release exists → **exit 1 regardless of
  `--json`** (report-only). Up to date → exit 0 (a broken engine is
  informational in `--check`).
- **Default mode** is the explicit mutation: stale-`pending` recovery
  first → dirty-tree refusal (never auto-stash) → discovery → transaction
  (`pending` written pre-checkout) → fetch `refs/tags/<t>` (FETCH_HEAD
  only, no local tag) → verify FETCH_HEAD == selected commit → checkout by
  **commit id** (detached HEAD — install.sh/uninstall.sh use `$HERE`,
  never a branch) → `install.sh --no-config --no-cron` → verification →
  durable `refs/info-guard/previous` → atomic manifest commit. Current tag
  with a broken engine → heal-only install (no tag change).
- **`--rollback`** (mutually exclusive with `--check`, usage exit 2):
  resolves the previous commit from `refs/info-guard/previous` (fallback
  `install.json.previous_commit`), checks out **by commit id** (no local
  tag required), re-runs install.sh, verifies against the recorded
  `previous_version`, and commits a coherent post-rollback manifest. If
  the recorded commit is unavailable: exit 2, `previous release commit no
  longer available locally — cannot roll back`.

| Exit | Meaning |
|---:|---|
| 0 | up to date · updated and verified · heal-only path healed · rollback complete |
| 1 | newer version available (`--check` only) · heal attempted-and-failed leaving the engine detected-broken |
| 2 | usage OR operational failure (not a git checkout · dirty package tree · lock held · fetch/verify/version-source disagreement · state inaccessible during verification · heal could not be attempted) |

Never exits 3/4. **Version-source agreement** (three sources must agree
after apply): the checked-out origin commit (verified via FETCH_HEAD), the
checked-out `bin/info-guard` `_PACKAGE_VERSION`, and
`install.json.version`. Disagreement → exit 2 `version_mismatch`, never an
"updated"/"verified" claim.

### The `update --json` envelope (`info-guard/update/v1`)

One shape for every reachable outcome; in `--json` mode stdout carries
ONLY this object (all diagnostics, including delegated install/test
output, go to stderr):

```json
{"schema": "info-guard/update/v1", "status": "up_to_date|updated|update_available|heal_failed|error",
 "current": "<version|null>", "latest": "<version|null>", "selected_commit": "<sha|null>",
 "engine": "ACTIVE|PARTIAL|MISSING|DRIFT|UNKNOWN", "applied": false, "healed": false,
 "error_class": "none|usage|network|dirty_tree|not_git|lock|checkout|install|tag_mismatch|version_mismatch|verify|state|repair"}
```

- `current` = the running binary's `_PACKAGE_VERSION` (on `updated`
  outcomes it is the INVOKING version — the next invocation reports the
  new one; consumers comparing `current` vs `latest` expect
  `current < latest` on the run that performed the update).
- `applied: true, healed: false` is the required partial-outcome
  representation whenever the selected commit was checked out but install
  or verification did not complete (consumers key on `engine` + `status` +
  `error_class` + exit together).
- `update --check` can never produce checkout/install/verify/state rows —
  it performs none of those operations.

### `check --heal` — the explicit mutation boundary

- `check` stays report-only by default; `check --heal` (explicit flag
  only, never automatic from a scheduler) repairs a PARTIAL/MISSING/DRIFT
  engine through the canonical `install.sh --no-config --no-cron`.
- Exit: 0 healed · 1 repair attempted but the engine is still broken
  (completed verdict) · 2 the repair could not be attempted (operational:
  lock held, dirty patched target file refusal, unwritable target,
  invalid/unreadable target version, no target checkout).
- **ACTIVE artifact-mismatch replace-by-design caveat:** in the ACTIVE
  artifact-mismatch state (markers complete, working-tree patch differs
  from the package's artifact), heal replaces the stale applied patch in
  place. Content attribution cannot distinguish a stale product patch from
  a pre-existing operator edit in that state (current bytes cannot
  reconstruct history), so an operator edit present in that state before
  the heal is **replaced by design** — documented here and in the README.
  Operator protection in the attribution-exact MISSING/PARTIAL states is
  fail-closed refusal (exit 2, file preserved); in every branch an
  external modification between snapshot and final revalidation is
  detected and aborts (exit 2). The residual sub-second window between the
  final revalidation and the restore is documented: no external-race
  guarantee extends across it.

### The seven-check smoke and `check --battery`

- Default `check` runs an in-process, read-only, ≤10s **smoke** proving the
  engine actually masks (not just that markers exist): exact-value partial
  masking (head/tail/floor) · `mask: "full"` → `***` · short-value floor
  (≤10 chars fully masked) · key-pattern `KEY=value` · broken pattern file
  fail-safe fallback (no unmasked gap, no repair) · missing pattern file
  no-op with built-in redaction intact · file_read sentinel (a masked
  value can never be written back). Smoke failure → exit 1 with the
  failing check named.
- `check --battery` runs the full committed `test.sh` in a sandbox
  (scratch `HERMES_HOME` + scratch target checkout), bounded by a 30-minute
  timeout (timeout → exit 2, distinct message), asserts the real
  package/target/registry/state/git metadata are byte-unchanged and that
  the battery never recursively invokes `check --battery`. Exit: 0 all
  green · 1 battery verdict broken · 2 operational.

### Cron — `install.sh --cron [SCHEDULE]` / `--no-cron`

- Opt-in only: `--cron` installs one managed line running the package's
  `check` on the default `0 6 * * *` unless SCHEDULE is given. When neither
  flag is given, an interactive TTY is prompted; **non-interactive default
  installs nothing**. Every internal invocation (`check --heal`, all
  `update` paths, recovery, rollback) passes `--no-cron` — internal
  installs never surface the prompt (A14).
- **Schedule grammar:** exactly 5 whitespace-separated fields; each field
  `*` OR one integer OR one inclusive range `lo-hi` (min ≤ max) OR a
  comma list of integers within bounds — minute 0–59 · hour 0–23 ·
  day-of-month 1–31 · month 1–12 · weekday 0–7 (7 ≡ 0). Steps (`*/5`),
  named fields, wrong field counts, newlines, and `%` are **rejected →
  exit 2, nothing written**.
- **Managed line** (canonical quoted form, always emitted):
  `0 6 * * * HERMES_HOME='…' '<pkg>/bin/info-guard' check  # info-guard-managed:'<pkg>'`
  — every interpolated value single-quote wrapped with `'\''` escaping; the
  schedule prefix is required (a schedule-less line is invalid cron).
  `%` in the executable path, any state path, or the ownership-marker
  value is **rejected at serialization** (cron's daemon layer parses `%`
  before the shell — quoting does not protect it) → exit 2, nothing
  written, no ownership marker. Control characters and newlines are
  rejected likewise.
- Re-runs replace ONLY this package's exact managed lines; unrelated
  entries are preserved byte-for-byte. All crontab read-modify-write
  operations hold `<state>/cron-install.lock` (flock). `uninstall.sh`
  removes only this package's managed lines.
- `crontab` unavailable/unwritable → `install.sh --cron` exits 2 (never a
  silent no-op).
- **Stale-cron probe (`check`, read-only):** scans the operator's crontab
  for `info-guard-managed` lines with a quoted-string tokenizer, rejects
  `%`/control-character-bearing lines (never executed), and warns when the
  resolved absolute binary is missing or its `--version` differs from the
  running binary. **Warning ≠ health verdict: stale-cron warnings return
  exit 0 — exit-code-only automation cannot see them** (documented
  limitation). The probe never mutates the crontab and never executes
  arbitrary crontab text. When `crontab` is unavailable, `check` prints a
  fixed `cron probe unavailable` warning and still exits per its health
  verdict (exit 0 unless another problem exists).

### D42 ordering contract

Run `info-guard update` BEFORE `hermes update` — an untested Hermes
release may not accept the patch. After `hermes update` (which rewrites
the checkout), run `info-guard check --heal` (or `info-guard update`) to
restore the engine. `check`'s supported-range floor remains the
enforcement guard.


## v0.8.0 — masked viewers

The three viewer commands (`pipe`, `view`, `env`) implement the
sanctioned no-dump doctrine: **prefer masked viewers over raw dumps —
`info-guard view`, `info-guard env`, and `info-guard pipe` are the
sanctioned way to inspect configuration surfaces.** They are read-only
display surfaces: they read only what the operator names explicitly on
the command line, never a defaulted deployment path; their output feeds
nothing in the product (no detection, no registration, no state).

### Viewer output boundary (binding, all three commands)

1. **Argument-vector execution.** Every child-process surface invokes
   the child with a subprocess argument vector. No operator-supplied
   unit name, container name, compose path, or file path is ever
   interpolated into a shell string. (`view file` opens its explicit
   path as a path value — never evaluated as shell syntax.)
2. **Capture, mask, then emit.** Child stdout is captured in memory,
   passed through the registry masking engine, and emitted only after
   masking succeeds. **Child stderr is never forwarded raw** — it is
   suppressed and replaced by the fixed value-free categories below.
3. **Explicit child-status handling.** The viewer checks the child's
   actual status; it never uses a pipeline whose status is determined by
   the last command. A nonzero child status maps to the fixed source
   category and product exit 2.
4. **Separate source and masking failures** — see the diagnostics table.
   Neither failure path emits the captured source bytes.
5. **CLI rules:** `--help`/`-h` anywhere prints the command's usage and
   exits 0 (no source is read on the help path); an unknown `--*` flag
   prints only the fixed `warning: unknown option` and exits 2 (the
   option text and its value are NEVER echoed — a `--bad=<registered
   secret>` option must not appear in stderr); usage errors exit 2;
   flag combinations are explicit (`env --check --keys` → usage exit 2).
6. **Non-disclosure.** No raw registry value, source value, or
   operator-supplied argument containing a registry value appears on
   stdout or stderr on any path. Successful viewer output is masked
   before emission; `env` never emits values at all.

### `info-guard pipe` — mask stdin

```
info-guard pipe
```

- Reads stdin as UTF-8 with replacement (invalid byte sequences become
  U+FFFD — never an exception, never a disclosure).
- Masks exact literals (longest-first, honoring each entry's `mask`
  style and the file's `mask` default head/tail/floor; full-mask
  literals → `***`; values at or below the configured floor are fully
  masked) and `key_patterns` values in `KEY=value`, `KEY: value`, and
  JSON key/value forms (empty values pass through unchanged).
- **Fail-closed:** masking availability is established BEFORE stdin is
  read. A missing/unreadable pattern file → exit 2 with the fixed
  diagnostic and NO stdout passthrough; a pattern file present but
  unloadable → exit 2 with the fixed short masking diagnostic. A
  present, readable pattern file with an empty registry is masking
  established (nothing to mask) → exit 0 with input preserved.
- Help path (`pipe --help`) exits 0 without reading stdin or the
  matcher. Unknown options exit 2 with the fixed warning.

| `pipe` exit | Meaning |
|---|---|
| 0 | input masked and emitted |
| 2 | usage error, or masking unavailable (fail-closed, no passthrough) |

### `info-guard view <surface> <arg>` — masked surface viewers

```
info-guard view systemd-unit <name>
info-guard view docker-env <container>
info-guard view compose-config <path>
info-guard view file <path>
```

| Surface | Invocation (argv exec) | Successful output | Source-failure classification |
|---|---|---|---|
| `systemd-unit` | `systemctl cat <name>`; on failure `systemctl --user cat <name>` (system-then-user fallback) | the successful command's stdout, masked before emission | `systemctl` exit 4 or stderr matching `not be found|No such` → `source: not found`; tool missing from PATH → `source: not found`; any other nonzero → `source: failed` |
| `docker-env` | `docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' <container>` (format string is one argv element, never shell-composed) | one environment record per line (`KEY=value`), masked before emission | stderr matching `No such object|not found` → `source: not found`; tool missing → `source: not found`; any other nonzero → `source: failed` |
| `compose-config` | `docker compose -f <path> config` (`-f`, path, and `config` are separate argv elements) | rendered compose configuration, masked before emission | stderr matching `no such file|not found` → `source: not found`; tool missing → `source: not found`; any other nonzero → `source: failed` |
| `file` | explicit path opened as a path value (no child process) | file content, masked before emission; no wrapper label is added | path does not exist → `source: not found`; unreadable → `source: failed` |

The absence-pattern lists above are the single byte-level source: the
pattern is matched INTERNALLY to select the
category and is never emitted. Child stdout from a failed attempt is
discarded (a failed system attempt's stdout is never emitted when the
user fallback succeeds). A source that was read successfully but cannot
be masked (pattern file unavailable/unreadable) → `masking: unavailable`,
exit 2, captured source discarded.

| `view` exit | Meaning |
|---|---|
| 0 | source read, masked, and emitted |
| 2 | usage error, source failure (fixed category), or masking failure |

### `info-guard env [FILE] [--check|--keys]` — keys + lengths only

FILE is explicit and positional — there is no default deployment path.
The product never consults `$HERMES_HOME`, a deployment directory, or
any hard-coded house path for `env`.

- **`env FILE`** — one line per valid assignment:
  `KEY = <N chars>` where N is the number of decoded Unicode **code
  points** of the parsed value (not bytes — deliberately diverges from
  the house wrapper's `wc -c` byte count). Blank lines (empty or
  whitespace-only) pass through as blank output lines. Comments and
  malformed lines are DROPPED, never echoed (they may contain literal
  secrets). The value is never emitted.
- **`env FILE --check`** — NON-EXECUTING grammar validation. It shares
  the `.env` grammar parser that feeds `build`/`matcher build` (one
  grammar, single-sourced; the shared parser gains a reporting channel,
  never a second parser). Nothing is sourced, captured, or evaluated —
  the parser reads lines as data, so no shell, child process, command
  substitution, redirection, or capture mechanism exists to leak.
  Report format: one line per violating line, `LINENO: KEY` when the
  key is safe (matches the key grammar AND is not itself a registered
  literal AND contains no registered value), otherwise `LINENO:`
  (line number only). Line numbers are 1-based and correspond to the
  file's lines as written. Supported malformed categories:
  bad key form (no `=`, invalid key token) · unterminated quote
  (value starts with a quote char that never closes) · control
  characters (C0/C1) · shell payload (values carrying a shell-execution
  construct: `$(`, backtick, `;`, `|`, `>`, `<`, `&`, or a
  `source`/`. ` attempt — the A17 hostile class; classified as a
  grammar violation, never executed). A file containing no violations
  exits 0; any violation exits 1. An unreadable file exits 2 with
  `file: unreadable`.
- **`env FILE --keys`** — bare key names only: one per line, sorted
  deterministically, unique; no `=`, length annotation, quotes,
  comments, or values. Comments and malformed lines contribute no keys.
- `--check` and `--keys` are mutually exclusive → usage exit 2.
- `--help`/`-h` anywhere prints usage and exits 0 without reading FILE.

| `env` exit | Meaning |
|---|---|
| 0 | file read/rendered successfully, or `--check` found no violations |
| 1 | `--check` found malformed lines (completed verdict) |
| 2 | usage error or file-read failure |

### New-command exit-contract table (additive — the preflight/watch ladder 0–4 is untouched)

| Command / mode | Exit | Meaning |
|---|---|---|
| `pipe` | 0 · 2 | masked · usage/masking-unavailable (fail-closed) |
| `view` | 0 · 2 | masked · usage/source/masking failure (categorized) |
| `env` | 0 · 1 · 2 | ok · `--check` found malformed lines · usage |

### Authoritative diagnostics table (one byte-level source)

Every diagnostic below is a FIXED string — none interpolates an
operator-supplied argument, child output, or source path:

| Fixed string | Used for | Exit |
|---|---|---|
| `masking: unavailable (no pattern file — run install.sh + build)` | `pipe` with missing/unreadable pattern file (fail-closed) | 2 |
| `masking: unavailable` | unloadable pattern file (`pipe`) · masking failure after a successful source read (`view`) | 2 |
| `source: not found` | missing tool, missing/unidentified unit/container/file (absence pattern matched internally) | 2 |
| `source: failed` | source child exists but failed for any other reason | 2 |
| `warning: unknown option` | any unknown `--*` flag on any viewer command (option text/value never echoed) | 2 |
| `file: unreadable` | `env` file-read failure | 2 |


## Version notes

- Requires Hermes Agent **v0.20.0+**. One version-tolerant patch: apply-checked
  and 15/15 test suite against v0.20.0 (2026.8.3), v0.20.1 (2026.8.13),
  v0.20.2 (2026.8.16), v0.20.3 (2026.8.16.2), v0.20.4 (2026.8.18), and
  v0.20.5 (2026.8.19) —
  v0.20.2 drifted `hermes_cli/main.py` (dotenv loading rework) and v0.20.4
  drifted `gateway/run.py` (media-policy module extraction); the hunk
  contexts were rebased/trimmed to anchor on lines identical across all six.
- `install.sh` / `uninstall.sh` fail loudly if the patch doesn't apply after
  a `hermes update` — never silently. `install.sh` also replaces an older
  applied patch in place (update Info Guard before Hermes — see README).
- `info-guard check` verifies the applied patch matches the package's
  artifact and that the live Hermes is within the tested range (newer =
  exit 1 with "update Info Guard first").
- `security.redact_patterns` may print "not a recognized config key" on the
  CLI — it is read by the entry-point bridge anyway; the warning is cosmetic.
- The `patterns` (regex) section is v2 (planned) — format-based redaction
  (any email/phone/SSN shape) on top of the exact-value engine. See
  `docs/full-stack.md`.

## Discover output format (v0.9.0)

`info-guard discover [PATH ...] [--json]` scans operator-named source
paths (or the `discover.dirs` list in `custom_literals.json`; CLI paths
completely override configuration) and reports key-shaped values that are
not yet registered. It is read-only: the registry is never written, no
candidate state is persisted, and no implicit path is scanned. Traversal
is anchored (directory handles, no-follow opens at every component — any
symlink fails closed), bounded (depth 32 excluding the named root, 10,000
regular files total across all roots, 10 MiB per file inclusive; a file
larger than the bound is `scan_limit` regardless of binary status), and
skips NUL-byte files (UTF-16 sources are skipped as binary). Binary and
non-enrollable constructs are never candidates.

### Text mode

- exit 0 (clean): empty stdout, empty stderr
- exit 1 (candidates): one line per pointer, five tab-separated fields in
  order: `key`, `source`, `line`, `shape_class`, `matched_pattern`
- exit 2 (error): stdout empty, one value-free stderr diagnostic

Fields are escaped deterministically: `\` → `\\`, tab/CR/LF → `\t`/`\r`/`\n`,
C0/C1 control bytes and invalid UTF-8 bytes → uppercase `\xNN`, other
Unicode control/format/separator scalars → `\u{NNNN}`.

### JSON mode

One envelope on stdout, stderr always empty:

```json
{"schema": "info-guard/discover/v1", "status": "clean|candidates|error",
 "count": 0, "candidates": [], "error_class": null}
```

- `clean` → exit 0 · `candidates` → exit 1 · `error` → exit 2
- `count == len(candidates)` is a normative invariant
- candidates are exactly five fields (`key`, `source`, `line`,
  `shape_class`, `matched_pattern`) — pointers only, values never appear;
  registered values are suppressed by internal digest comparison
- `error_class` is `null` unless `status == "error"`

### Error classes (exit 2)

`usage` (unknown flag, no sources, invalid selector) ·
`registry_unavailable` (absent/unreadable/old-schema registry) ·
`invalid_config` (malformed `discover.dirs`) · `invalid_source` (empty or
NUL CLI path) · `source_unreadable` (missing, inaccessible, symlink,
special file, race) · `scan_limit` (depth/file-count/size bound) ·
`detector_error` (operational detector/parser failure — accumulated
candidates are discarded).

Unknown `--*` flags are usage errors (not warnings) so clean and candidate
results have exactly empty stderr.

## Enrollment: `literals add --from` (v0.9.0)

`info-guard literals add --from SOURCE:KEY [--json]` is the sole
enrollment bridge for discovered candidates. The selector splits at the
**last colon** (colon-containing paths work; POSIX paths only). Accepted
forms: `--from SOURCE:KEY`, `--from=SOURCE:KEY`, and
`--from -- SOURCE:KEY` (a source beginning with `-` requires the latter
two). `--from` is mutually exclusive with positional values, `--file`,
`--mask`, and `--kind`. The key must match the `.env` grammar key token.

Enrollment opens the source exactly once (anchored, no-follow), parses it
with the shared `.env` grammar, fingerprints the complete file, then
revalidates the opened handle and the original path binding — a rename or
symlink substitution after the open fails closed (exit 2) with the
registry untouched. Same-file duplicate records for the key are ambiguous
and fail closed. The registry is read non-mutating before commit and
re-verified at the commit boundary; the write is the canonical atomic
write.

Output:

- text success: the assigned `value_id` only (never the value)
- `--json` success: the existing add envelope —
  `{"added": [{"value_masked": "...", "id": "..."}], "duplicates": []}`;
  an already-registered value returns the existing id in `duplicates`
  with no rewrite
- any failure: empty stdout, value-free stderr, exit 2 (no JSON error
  envelope — the existing literals convention)

## Consumer obligations — discover JSON (v0.9.0)

Consumers of the `info-guard/discover/v1` envelope must:

1. **Tolerate unknown fields** — additive fields may appear in any
   object; unknown fields must never break parsing.
2. **Tolerate additive candidate fields** — candidate pointers carry
   exactly five fields today (`key`, `source`, `line`, `shape_class`,
   `matched_pattern`); future releases may add fields. Consumers must
   not reject candidates for unknown fields.
3. **Preserve and report unknown `status` values** — a status other
   than `clean`/`candidates`/`error` must never be silently treated as
   `clean`; forward it as received.
4. **Preserve and report unknown `error_class` values** — an unknown
   class must never be silently mapped to a known one; forward it as
   received.
5. **Treat an unrecognized security-significant `status` or `error_class` as unhandled** — never downgrade an unknown status to `clean` or map an unknown class to a known one; surface it to the operator.
6. **Do not assume the five candidate fields are the complete set** — treat `key`, `source`, `line`, `shape_class`, `matched_pattern` as the guaranteed minimum; future fields may be added.
7. **Continue applying the non-disclosure invariant to future fields** — any field added later must also never expose raw secret values.
