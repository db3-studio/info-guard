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

## Custom literals (the PII workflow)

`<state>/custom_literals.json` — hand-edited, survives rebuilds, masking only
(never part of detection):

```json
{"literals": ["someone@example.com", {"value": "anything-you-want", "mask": "full"}]}
```

Edit it, then run `info-guard build` — live within seconds, no restarts.

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
- `watch` (v2, v0.4.0) re-runs the scan and reports **deltas on three
  tracks** against `<state>/info-guard/watch-baseline.json` (schema
  `info-guard/watch-baseline/v2`, 0600 — **value sha256 only; raw values
  never persisted**; schema v1 baselines are migrated in place, delta-free):
  1. **Exposure** — `new_values` (masked 2+2 · type · family · count,
     exit 1), `resolved_values` (informational — "No longer detected in
     the current scan scope. This does not confirm that the credential
     is dead or revoked"), `changed_values` (±occurrences, informational),
     family rollups, per-file count changes.
  2. **Protection configuration** — custom literals / key patterns
     added/removed (fingerprint-set diffs), redact_patterns whole-set
     fingerprint change, mask-policy change. Counts + fingerprints ONLY —
     raw literals never appear, not even masked. Wording contract:
     configuration deltas, never effectiveness ("protection configuration
     changed", never "protection improved").
  3. **Engine state** — transitions between `active` / `partial` /
     `none` with explicit blocks (installed / restored / degraded /
     removed).
- **Exit codes (contract, v0.4.0):** NEW values = 1 · `active→partial`
  = 1 (degraded) · `active→none` = 1 (engine removed — config remains on
  disk, not applied) · `none→active` / `partial→active` = 0 ·
  config-only / resolved / changed = 0 · usage = 2. `partial` is never
  ambiguous — degraded protection alerts exactly like removal (matches
  `check`).
- **Baseline lifecycle:** first run (or `--reset`) creates it; on
  tool/gitleaks version change it is **union-kept** (known values never
  re-alert) with a notice; a broken/unreadable baseline is rebuilt,
  never a crash. **Refresh-on-delta:** the baseline is rewritten at the
  end of any run that observed a delta (exposure, protection, or engine)
  with current state — every delta alerts exactly once; clean runs leave
  it untouched. `setup` stamps the protection/assessment snapshot into
  an existing baseline (values preserved) so a deliberate config change
  after setup doesn't alarm on the next watch.
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
into exactly one of **credential-shaped** (token-format values + gitleaks
HIGH-CONFIDENCE — the actionable set), **key-name mention** (includes
reference/noise rows; a future tier may split them), or **already-masked**
(the prevention layer working). `findings = raw_detections +
key_name_mentions + already_masked`, exactly — the partition holds over
RAW hits. `credential_shaped` is the deduplicated row count of the
credential-shaped class (≤ `raw_detections`); the headline, family,
location and affected-file tables all sum to it.

The candidate unit is the unique **`file:line:value` row**: when several
detectors flag the same value on the same line (key-shape + token-prefix +
gitleaks can all fire), the row counts once. `totals.raw_detections` keeps
the raw detector-fire count and `totals.distinct_values` the value-level
count — the summary line states all three so every table's sum reconciles.

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

Exit codes: **0 = clean**, **1 = findings** (any credential-shaped value),
**2 = usage error**. gitleaks is optional: without it the scan runs the
key-shape pass only and says so.

## Version notes

- Requires Hermes Agent **v0.20.0+**. One version-tolerant patch: apply-checked
  and 15/15 test suite against v0.20.0 (2026.8.3), v0.20.1 (2026.8.13),
  v0.20.2 (2026.8.16), v0.20.3 (2026.8.16.2), and v0.20.4 (2026.8.18) —
  v0.20.2 drifted `hermes_cli/main.py` (dotenv loading rework) and v0.20.4
  drifted `gateway/run.py` (media-policy module extraction); the hunk
  contexts were rebased/trimmed to anchor on lines identical across all five.
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
