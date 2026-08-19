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

The scan builds ONE in-memory assessment object (facts only, no prose); the
report is its render. v0.3.0 serializes the same object as JSON and diffs it
(`watch`) — the text report is never a second implementation.

Report sections, in order (each printed only when its data is non-empty):

1. **Header** — `Info Guard v<version> — Preflight Security Assessment` +
   scan metadata (read-only, values masked, generated timestamp) + a **SCOPE**
   line (directories scanned + file count) so a clean result never reads as
   "the entire installation is secure".
2. **STATUS** — 🔴 ACTION REQUIRED + one-line summary (candidates, not
   confirmed leaks) / 🟢 CLEAN + what it means. "No changes were made by this
   scan" is prominent here.
3. **EXECUTIVE SUMMARY** — metric cards: credential-shaped candidates with
   the **family-attributed · unattributed split** (the family table's sum
   always reconciles; a note appears when duplicated rows make the split
   differ from the candidate-row total), files scanned, families with
   value-shaped material, already-masked occurrences. Plus WHAT MATTERS:
   2–3 bullets generated from the assessment (value shapes, location
   concentration, redaction working).
4. **CREDENTIAL EXPOSURE BY FAMILY** — per family: value-findings count,
   evidence (value shapes), priority (🔴 High = any real value at rest;
   🟢 Protected = masked-only). Protected-only families are capped at 10 with
   a "showing top N of M" line. Followed by **VALUES — MATCH AGAINST YOUR
   CURRENT CREDENTIALS**: the distinct credential-shaped values as 2+2 masked
   forms (head/tail two chars) with occurrence counts, type, and family when
   attributable — the matching aid for "is this still my credential?" Top 15
   by count; `--full` lists all.
5. **EXPOSURE LOCATIONS** — credential-shaped candidates bucketed by area
   (sessions / logs / cron / state / other) as **absolute counts** (no
   percentages), a qualified Pattern observation ("consistent with retained
   historical exposure rather than a current logging failure" — never a
   definitive claim), and SHOW AFFECTED FILES (top 10, with credential-shaped
   breakdown when > 0).
6. **REDACTION EFFECTIVENESS** — per scope (family OR area, e.g.
   `logs/agent.log`): 🟢 Protected / 🟢 Mostly masked / 🟡 Mixed / 🔴 Exposed.
7. **WHY AM I SEEING THIS** — top families: why flagged, where (area +
   session-timestamp date range when available), status (candidate — active
   status unknown), recommended action.
8. **RECOMMENDED ACTIONS** — 4 numbered steps (rotate active candidates →
   choose prevention → clean historical exposure → verify) + the explicit
   tier-partition statement + no-routine-re-run note.
9. **APPENDIX A — DETECTION TELEMETRY** — key-name mention counts,
   explicitly NOT findings (moved here so the main report stays risk-focused).
10. **APPENDIX B — FINDING LEDGER** — a sample (one example per family,
    ranked by signal; junk-display rows count-only; `— your .env key` labels)
    or, with `--full`, the complete deduplicated ledger (same masking, no
    cap). Source-masked rows stay count-only in both modes.

Taxonomy — a partition, stated in the report: every finding is classified
into exactly one of **credential-shaped** (token-format values + gitleaks
HIGH-CONFIDENCE — the actionable set), **key-name mention** (includes
reference/noise rows; a future tier may split them), or **already-masked**
(the prevention layer working). `findings = credential_shaped +
key_name_mentions + already_masked`, exactly.

Date discipline: historical date ranges come from **session filename
timestamps** (`session_YYYYMMDD…`), never filesystem mtime.

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
